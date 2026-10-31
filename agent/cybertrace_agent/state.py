"""Durable local agent state: identity, cursors, spool queue and error reports."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

TOKEN_PREFIX = "ct_agent_"
_SCHEMA_VERSION = "1"


class AgentStateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Cursor:
    source_key: str
    path: str
    device: int | None
    inode: int | None
    offset: int
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PendingBatch:
    batch_id: str
    manifest: dict[str, Any]
    total_bytes: int
    created_at: datetime
    attempts: int
    next_attempt_at: datetime | None
    last_error: str | None


@dataclass(frozen=True, slots=True)
class LocalError:
    id: int
    source_key: str | None
    code: str
    message: str
    occurred_at: datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        pass


class AgentState:
    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        _chmod(self.state_dir, 0o700)
        self.db_path = self.state_dir / "agent-state.sqlite3"
        self.token_path = self.state_dir / "agent-token"
        self.spool_root = self.state_dir / "spool"
        self.quarantine_root = self.state_dir / "quarantine"
        self.spool_root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)
        _chmod(self.spool_root, 0o700)
        _chmod(self.quarantine_root, 0o700)

        self._conn = sqlite3.connect(str(self.db_path), timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        _chmod(self.db_path, 0o600)

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cursors (
                    source_key TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    device TEXT,
                    inode TEXT,
                    offset INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS batches (
                    batch_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT,
                    last_error TEXT
                );
                CREATE TABLE IF NOT EXISTS errors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_key TEXT,
                    code TEXT NOT NULL,
                    message TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    reported INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS ix_errors_unreported
                    ON errors (reported, id);
                """
            )
            current = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            if current is None:
                self._conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                    (_SCHEMA_VERSION,),
                )

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def get_or_create_agent_uid(self, configured: str | None) -> str:
        existing = self.get_meta("agent_uid")
        if configured and existing and configured != existing:
            raise AgentStateError(
                "config agent_uid does not match the identity stored in state_dir; "
                "refusing to silently change endpoint identity"
            )
        if configured:
            self.set_meta("agent_uid", configured)
            return configured
        if existing:
            return existing
        uid = self._derive_machine_uid()
        self.set_meta("agent_uid", uid)
        return uid

    def _derive_machine_uid(self) -> str:
        for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
            try:
                machine_id = candidate.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if machine_id:
                import hashlib

                digest = hashlib.sha256(f"cybertrace:{machine_id}".encode()).hexdigest()
                return f"linux-{digest[:32]}"
        return f"agent-{uuid.uuid4().hex}"

    # ----------------------------------------------------------------- token
    def load_token(self) -> str | None:
        try:
            token = self.token_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not token:
            return None
        if not token.startswith(TOKEN_PREFIX) or len(token) < 20:
            raise AgentStateError("stored agent token is malformed")
        return token

    def save_token(self, token: str) -> None:
        if not token.startswith(TOKEN_PREFIX):
            raise AgentStateError("refusing to store a malformed agent token")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.token_path, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(token)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            _chmod(self.token_path, 0o600)

    def delete_token(self) -> None:
        self.token_path.unlink(missing_ok=True)

    # --------------------------------------------------------------- cursors
    def get_cursor(self, source_key: str) -> Cursor | None:
        row = self._conn.execute(
            "SELECT * FROM cursors WHERE source_key = ?", (source_key,)
        ).fetchone()
        if row is None:
            return None
        return Cursor(
            source_key=row["source_key"],
            path=row["path"],
            device=int(row["device"]) if row["device"] is not None else None,
            inode=int(row["inode"]) if row["inode"] is not None else None,
            offset=int(row["offset"]),
            updated_at=_parse_dt(row["updated_at"]) or _utcnow(),
        )

    def set_cursor(
        self,
        source_key: str,
        *,
        path: str,
        device: int | None,
        inode: int | None,
        offset: int,
        updated_at: datetime | None = None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO cursors "
                "(source_key, path, device, inode, offset, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(source_key) DO UPDATE SET "
                "path = excluded.path, device = excluded.device, inode = excluded.inode, "
                "offset = excluded.offset, updated_at = excluded.updated_at",
                (
                    source_key,
                    path,
                    str(device) if device is not None else None,
                    str(inode) if inode is not None else None,
                    offset,
                    _iso(updated_at or _utcnow()),
                ),
            )

    # ---------------------------------------------------------------- batches
    def enqueue_batch(self, manifest: dict[str, Any], total_bytes: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO batches "
                "(batch_id, manifest_json, total_bytes, created_at, attempts, "
                "next_attempt_at, last_error) VALUES (?, ?, ?, ?, 0, NULL, NULL)",
                (
                    manifest["batch_id"],
                    json.dumps(manifest, separators=(",", ":"), ensure_ascii=True),
                    total_bytes,
                    _iso(_utcnow()),
                ),
            )

    def pending_batches(self, *, now: datetime | None = None) -> list[PendingBatch]:
        now = now or _utcnow()
        rows = self._conn.execute(
            "SELECT * FROM batches WHERE next_attempt_at IS NULL OR next_attempt_at <= ? "
            "ORDER BY created_at ASC",
            (_iso(now),),
        ).fetchall()
        result: list[PendingBatch] = []
        for row in rows:
            result.append(
                PendingBatch(
                    batch_id=row["batch_id"],
                    manifest=json.loads(row["manifest_json"]),
                    total_bytes=int(row["total_bytes"]),
                    created_at=_parse_dt(row["created_at"]) or _utcnow(),
                    attempts=int(row["attempts"]),
                    next_attempt_at=_parse_dt(row["next_attempt_at"]),
                    last_error=row["last_error"],
                )
            )
        return result

    def all_batch_ids(self) -> set[str]:
        return {
            row["batch_id"]
            for row in self._conn.execute("SELECT batch_id FROM batches").fetchall()
        }

    def batch_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM batches").fetchone()
        return int(row["n"])

    def pending_bytes(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(total_bytes), 0) AS total FROM batches"
        ).fetchone()
        return int(row["total"])

    def update_batch_attempt(
        self,
        batch_id: str,
        *,
        error: str,
        next_attempt_at: datetime | None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE batches SET attempts = attempts + 1, last_error = ?, "
                "next_attempt_at = ? WHERE batch_id = ?",
                (error[:4000], _iso(next_attempt_at) if next_attempt_at else None, batch_id),
            )

    def remove_batch(self, batch_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM batches WHERE batch_id = ?", (batch_id,))

    def get_batch(self, batch_id: str) -> PendingBatch | None:
        row = self._conn.execute(
            "SELECT * FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        if row is None:
            return None
        return PendingBatch(
            batch_id=row["batch_id"],
            manifest=json.loads(row["manifest_json"]),
            total_bytes=int(row["total_bytes"]),
            created_at=_parse_dt(row["created_at"]) or _utcnow(),
            attempts=int(row["attempts"]),
            next_attempt_at=_parse_dt(row["next_attempt_at"]),
            last_error=row["last_error"],
        )

    # ----------------------------------------------------------------- errors
    def add_error(
        self,
        *,
        code: str,
        message: str,
        source_key: str | None = None,
        occurred_at: datetime | None = None,
    ) -> int:
        existing = self._conn.execute(
            "SELECT id FROM errors WHERE reported = 0 AND code = ? "
            "AND message = ? AND COALESCE(source_key, '') = ? "
            "ORDER BY id DESC LIMIT 1",
            (code[:64], message[:4000], source_key or ""),
        ).fetchone()
        if existing is not None:
            return int(existing["id"])
        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO errors (source_key, code, message, occurred_at, reported) "
                "VALUES (?, ?, ?, ?, 0)",
                (
                    source_key,
                    code[:64],
                    message[:4000],
                    _iso(occurred_at or _utcnow()),
                ),
            )
        self._trim_errors()
        return int(cursor.lastrowid)

    def _trim_errors(self) -> None:
        cutoff = _iso(_utcnow() - timedelta(days=30))
        with self._conn:
            self._conn.execute(
                "DELETE FROM errors WHERE reported = 1 AND occurred_at < ?", (cutoff,)
            )

    def unreported_errors(self, limit: int = 50) -> list[LocalError]:
        rows = self._conn.execute(
            "SELECT * FROM errors WHERE reported = 0 ORDER BY id ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            LocalError(
                id=int(row["id"]),
                source_key=row["source_key"],
                code=row["code"],
                message=row["message"],
                occurred_at=_parse_dt(row["occurred_at"]) or _utcnow(),
            )
            for row in rows
        ]

    def mark_errors_reported(self, ids: list[int]) -> None:
        if not ids:
            return
        placeholders = ", ".join("?" for _ in ids)
        with self._conn:
            self._conn.execute(
                f"UPDATE errors SET reported = 1 WHERE id IN ({placeholders})",
                tuple(ids),
            )

    def error_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS n FROM errors").fetchone()
        return int(row["n"])
