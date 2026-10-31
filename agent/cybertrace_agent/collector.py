"""Incremental, bounded, read-only log collection."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat as stat_module
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cybertrace_agent.config import AgentConfig, SourceConfig
from cybertrace_agent.state import AgentState, Cursor

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SourceCollectionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Segment:
    item_id: str
    source_key: str
    source_type: str
    source_path: str
    spool_file: str
    filename: str
    sha256: str
    size_bytes: int
    range_start: int
    range_end: int
    collected_at: datetime
    device: int | None
    inode: int | None
    collection_started_at: datetime | None = None
    collection_ended_at: datetime | None = None
    lines_collected: int | None = None
    expected_bytes: int | None = None


@dataclass(slots=True)
class SourceStatus:
    key: str
    name: str
    enabled: bool
    readable: bool | None
    status: str
    last_error: str | None
    last_collected_at: datetime | None
    cursor_bytes: int | None
    last_success_at: datetime | None = None
    collection_available: bool | None = None
    collection_started_at: datetime | None = None
    collection_ended_at: datetime | None = None
    bytes_collected_last_cycle: int | None = None
    lines_collected_last_cycle: int | None = None
    observed_size_bytes: int | None = None


@dataclass(slots=True)
class CollectionResult:
    batch_id: str
    segments: list[Segment] = field(default_factory=list)
    statuses: list[SourceStatus] = field(default_factory=list)
    total_bytes: int = 0

    @property
    def has_segments(self) -> bool:
        return bool(self.segments)


class Collector:
    def __init__(
        self,
        config: AgentConfig,
        state: AgentState,
        *,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.config = config
        self.state = state
        self.clock = clock

    def collect_all(self) -> CollectionResult:
        batch_id = f"batch-{uuid.uuid4().hex}"
        batch_dir = self.state.spool_root / batch_id
        result = CollectionResult(batch_id=batch_id)

        pending_bytes = self.state.pending_bytes()
        buffer_remaining = max(0, self.config.max_buffer_bytes - pending_bytes)

        for source in self.config.sources:
            if not source.enabled:
                result.statuses.append(
                    SourceStatus(
                        key=source.key,
                        name=source.name,
                        enabled=False,
                        readable=None,
                        status="disabled",
                        last_error=None,
                        last_collected_at=self._cursor_time(source.key),
                        cursor_bytes=self._cursor_offset(source.key),
                        collection_available=False,
                    )
                )
                continue

            try:
                self._collect_source(
                    source,
                    result,
                    batch_dir,
                    buffer_remaining - result.total_bytes,
                )
            except SourceCollectionError as exc:
                logger.warning("Source %s collection failed: %s", source.key, exc.message)
                self.state.add_error(
                    source_key=source.key,
                    code=exc.code,
                    message=exc.message,
                )
                result.statuses.append(
                    SourceStatus(
                        key=source.key,
                        name=source.name,
                        enabled=True,
                        readable=False,
                        status="error",
                        last_error=exc.message,
                        last_collected_at=self._cursor_time(source.key),
                        cursor_bytes=self._cursor_offset(source.key),
                        collection_available=False,
                    )
                )
            except OSError as exc:
                message = f"Could not read configured log source: {exc}"
                logger.warning("Source %s collection failed: %s", source.key, message)
                self.state.add_error(
                    source_key=source.key,
                    code="source_read_error",
                    message=message,
                )
                result.statuses.append(
                    SourceStatus(
                        key=source.key,
                        name=source.name,
                        enabled=True,
                        readable=False,
                        status="error",
                        last_error=message,
                        last_collected_at=self._cursor_time(source.key),
                        cursor_bytes=self._cursor_offset(source.key),
                        collection_available=False,
                    )
                )

        if not result.has_segments and batch_dir.exists():
            shutil.rmtree(batch_dir, ignore_errors=True)
        return result

    def _cursor_time(self, source_key: str) -> datetime | None:
        cursor = self.state.get_cursor(source_key)
        return cursor.updated_at if cursor else None

    def _cursor_offset(self, source_key: str) -> int | None:
        cursor = self.state.get_cursor(source_key)
        return cursor.offset if cursor else None

    def _collect_source(
        self,
        source: SourceConfig,
        result: CollectionResult,
        batch_dir: Path,
        buffer_remaining: int,
    ) -> None:
        cycle_started_at = self.clock()
        try:
            initial_stat = source.path.stat()
        except FileNotFoundError as exc:
            raise SourceCollectionError(
                "source_missing", f"Configured log path does not exist: {source.path}"
            ) from exc
        except PermissionError as exc:
            raise SourceCollectionError(
                "permission_denied",
                f"Agent cannot stat the configured log path: {source.path}",
            ) from exc
        if not stat_module.S_ISREG(initial_stat.st_mode):
            raise SourceCollectionError(
                "not_regular_file", f"Configured log path is not a regular file: {source.path}"
            )

        cursor = self.state.get_cursor(source.key)
        start = self._resolve_start(source, cursor, initial_stat)
        if start is None:
            ended_at = self.clock()
            result.statuses.append(
                SourceStatus(
                    key=source.key,
                    name=source.name,
                    enabled=True,
                    readable=True,
                    status="healthy",
                    last_error=None,
                    last_collected_at=cursor.updated_at if cursor else None,
                    cursor_bytes=self._cursor_offset(source.key),
                    last_success_at=ended_at,
                    collection_available=True,
                    collection_started_at=cycle_started_at,
                    collection_ended_at=ended_at,
                    bytes_collected_last_cycle=0,
                    lines_collected_last_cycle=0,
                    observed_size_bytes=initial_stat.st_size,
                )
            )
            return

        if buffer_remaining <= 0:
            message = (
                f"Local buffer limit of {self.config.max_buffer_bytes} bytes is reached; "
                "no new data was collected."
            )
            self.state.add_error(source_key=source.key, code="buffer_full", message=message)
            result.statuses.append(
                SourceStatus(
                    key=source.key,
                    name=source.name,
                    enabled=True,
                    readable=True,
                    status="error",
                    last_error=message,
                    last_collected_at=cursor.updated_at if cursor else None,
                    cursor_bytes=start,
                    collection_available=False,
                    collection_started_at=cycle_started_at,
                    collection_ended_at=self.clock(),
                    bytes_collected_last_cycle=0,
                    lines_collected_last_cycle=0,
                    observed_size_bytes=initial_stat.st_size,
                )
            )
            return

        last_collected_at: datetime | None = None
        last_offset = start
        segments_for_source = 0
        lines_collected = 0

        with source.path.open("rb") as handle:
            read_stat = os.fstat(handle.fileno())
            if (
                read_stat.st_dev != initial_stat.st_dev
                or (read_stat.st_ino and read_stat.st_ino != initial_stat.st_ino)
            ):
                raise SourceCollectionError(
                    "source_changed",
                    "The configured log file was replaced during collection; no bytes were read.",
                )
            handle.seek(start)
            offset = start
            while True:
                file_remaining = max(0, read_stat.st_size - offset)
                if file_remaining == 0:
                    break
                if len(result.segments) >= self.config.max_batch_files:
                    break
                batch_remaining = self.config.max_batch_bytes - result.total_bytes
                capacity = min(
                    self.config.max_segment_bytes,
                    file_remaining,
                    batch_remaining,
                    buffer_remaining - (offset - start),
                )
                if capacity < 1:
                    if batch_remaining < self.config.max_segment_bytes:
                        break
                    message = (
                        f"Local buffer limit of {self.config.max_buffer_bytes} bytes is "
                        "reached; no additional data was collected."
                    )
                    self.state.add_error(
                        source_key=source.key, code="buffer_full", message=message
                    )
                    break

                data = handle.read(capacity)
                if not data:
                    break

                if (
                    len(data) == capacity
                    and offset + len(data) < read_stat.st_size
                    and not data.endswith(b"\n")
                ):
                    newline = data.rfind(b"\n")
                    if newline >= 0:
                        data = data[: newline + 1]
                    if not data:
                        break

                now = self.clock()
                end_offset = offset + len(data)
                item_id = uuid.uuid4().hex
                batch_dir.mkdir(parents=True, exist_ok=True)
                spool_path = batch_dir / f"{item_id}.log"
                with spool_path.open("xb") as target:
                    target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
                try:
                    os.chmod(spool_path, 0o600)
                except OSError:
                    pass

                filename = f"{source.key}-{result.batch_id[-12:]}-{segments_for_source:03d}.log"
                result.segments.append(
                    Segment(
                        item_id=item_id,
                        source_key=source.key,
                        source_type=source.source_type,
                        source_path=str(source.path),
                        spool_file=f"spool/{result.batch_id}/{item_id}.log",
                        filename=filename,
                        sha256=hashlib.sha256(data).hexdigest(),
                        size_bytes=len(data),
                        range_start=offset,
                        range_end=end_offset,
                        collected_at=now,
                        device=read_stat.st_dev,
                        inode=read_stat.st_ino,
                        collection_started_at=cycle_started_at,
                        collection_ended_at=now,
                        lines_collected=data.count(b"\n"),
                        expected_bytes=len(data),
                    )
                )
                result.total_bytes += len(data)
                offset = end_offset
                last_offset = end_offset
                last_collected_at = now
                lines_collected += data.count(b"\n")
                segments_for_source += 1

                if len(data) < capacity:
                    break

        cycle_ended_at = self.clock()
        result.statuses.append(
            SourceStatus(
                key=source.key,
                name=source.name,
                enabled=True,
                readable=True,
                status="healthy",
                last_error=None,
                last_collected_at=last_collected_at
                or (cursor.updated_at if cursor else None),
                cursor_bytes=last_offset,
                last_success_at=cycle_ended_at,
                collection_available=True,
                collection_started_at=cycle_started_at,
                collection_ended_at=cycle_ended_at,
                bytes_collected_last_cycle=last_offset - start,
                lines_collected_last_cycle=lines_collected,
                observed_size_bytes=initial_stat.st_size,
            )
        )

    def _resolve_start(
        self,
        source: SourceConfig,
        cursor: Cursor | None,
        initial_stat: os.stat_result,
    ) -> int | None:
        size = initial_stat.st_size
        if cursor is None:
            if self.config.start_position == "end":
                now = self.clock()
                self.state.set_cursor(
                    source.key,
                    path=str(source.path),
                    device=initial_stat.st_dev,
                    inode=initial_stat.st_ino,
                    offset=size,
                    updated_at=now,
                )
                logger.info(
                    "Initialized %s at end of file (%s bytes); set start_position=beginning "
                    "to collect existing content.",
                    source.key,
                    size,
                )
                return None
            return 0

        rotated = False
        if cursor.device is not None and cursor.device != initial_stat.st_dev:
            rotated = True
        if (
            cursor.inode is not None
            and initial_stat.st_ino
            and cursor.inode != initial_stat.st_ino
        ):
            rotated = True
        if size < cursor.offset:
            rotated = True
        if rotated:
            logger.info(
                "Log rotation or truncation detected for %s; reading from start.", source.key
            )
            return 0
        return cursor.offset
