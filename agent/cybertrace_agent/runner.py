"""Agent supervisor: enrollment, collection, durable buffering and delivery."""

from __future__ import annotations

import logging
import os
import platform as platform_module
import shutil
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - the agent targets Linux
    fcntl = None  # type: ignore[assignment]

from cybertrace_agent import AGENT_VERSION
from cybertrace_agent.client import (
    AgentClient,
    AgentClientError,
    AuthenticationRejected,
    EnrollmentRejected,
    PayloadTooLarge,
    ProtocolError,
    RegistrationResult,
    RequestRejected,
    SpoolFileError,
    TransientClientError,
    UploadFilePart,
)
from cybertrace_agent.collector import CollectionResult, Collector, SourceStatus
from cybertrace_agent.config import AgentConfig, SourceConfig
from cybertrace_agent.state import AgentState, AgentStateError, PendingBatch

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


class AgentRuntimeError(RuntimeError):
    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class InstanceLock:
    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / "agent.lock"
        self._handle = None

    def acquire(self) -> None:
        self._handle = self.path.open("a+", encoding="utf-8")
        if fcntl is not None:
            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                self._handle.close()
                self._handle = None
                raise AgentRuntimeError(
                    "Another CyberTrace agent is already using this state directory.",
                    code="instance_already_running",
                ) from exc
        self._handle.seek(0)
        self._handle.truncate()
        self._handle.write(f"{os.getpid()}\n")
        self._handle.flush()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def release(self) -> None:
        if self._handle is None:
            return
        if fcntl is not None:
            try:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        self._handle.close()
        self._handle = None


@dataclass(slots=True)
class _LoopSchedule:
    collect_at: datetime
    flush_at: datetime
    heartbeat_at: datetime


class AgentRunner:
    def __init__(
        self,
        config: AgentConfig,
        *,
        state: AgentState | None = None,
        client: AgentClient | None = None,
        collector: Collector | None = None,
        stop_event: threading.Event | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.config = config
        self.clock = clock
        self.state = state or AgentState(config.state_dir)
        self.client = client or AgentClient(config)
        self.collector = collector or Collector(config, self.state, clock=clock)
        self.stop_event = stop_event or threading.Event()

        self.agent_uid: str | None = None
        self.token: str | None = None
        self._token_needs_check = True
        self._auth_blocked = False
        self._auth_failures = 0
        self._next_auth_attempt: datetime | None = None
        self._network_failing = False
        self._source_sync_pending = True
        self._next_source_sync: datetime | None = None
        self._statuses: dict[str, SourceStatus] = {}
        self._last_heartbeat_at: datetime | None = None
        self._last_collection_at: datetime | None = None
        self._measured_clock_offset_seconds: int | None = None

    # --------------------------------------------------------------- lifecycle
    def run(self) -> None:
        lock = InstanceLock(self.config.state_dir)
        try:
            lock.acquire()
        except Exception:
            self.state.close()
            raise
        try:
            self._cleanup_orphan_spools()
            self._initialize_statuses()
            self._bootstrap()
            self._loop()
        finally:
            self.stop_event.set()
            lock.release()
            self.state.close()

    def stop(self) -> None:
        self.stop_event.set()

    def _cleanup_orphan_spools(self) -> None:
        known = self.state.all_batch_ids()
        try:
            children = list(self.state.spool_root.iterdir())
        except OSError as exc:
            logger.warning("Could not inspect the spool directory: %s", exc)
            return
        for child in children:
            if child.is_dir() and child.name not in known:
                logger.warning("Removing unreferenced spool directory %s", child.name)
                shutil.rmtree(child, ignore_errors=True)

    def _initialize_statuses(self) -> None:
        self._statuses = {}
        for source in self.config.sources:
            cursor = self.state.get_cursor(source.key)
            if not source.enabled:
                status = "disabled"
            else:
                status = "unknown"
            self._statuses[source.key] = SourceStatus(
                key=source.key,
                name=source.name,
                enabled=source.enabled,
                readable=None,
                status=status,
                last_error=None,
                last_collected_at=cursor.updated_at if cursor else None,
                cursor_bytes=cursor.offset if cursor else None,
            )

    def _bootstrap(self) -> None:
        try:
            self.agent_uid = self.state.get_or_create_agent_uid(self.config.agent_uid)
        except AgentStateError as exc:
            raise AgentRuntimeError(str(exc), code="state_identity_conflict") from exc
        stored_investigation = self.state.get_meta("investigation_id")
        if (
            stored_investigation
            and stored_investigation.lower() != self.config.investigation_id.lower()
        ):
            raise AgentRuntimeError(
                "state_dir belongs to a different investigation; use a fresh state directory.",
                code="state_investigation_conflict",
            )
        self.token = self.state.load_token()

        token = self._acquire_token()
        if token is not None:
            self._sync_sources_once()

    def _loop(self) -> None:
        now = self.clock()
        schedule = _LoopSchedule(
            collect_at=now,
            flush_at=now,
            heartbeat_at=now,
        )
        while not self.stop_event.is_set():
            now = self.clock()
            if self._source_sync_pending and (
                self._next_source_sync is None or now >= self._next_source_sync
            ):
                self._sync_sources_once()

            if now >= schedule.collect_at:
                self.collect_once()
                schedule.collect_at = self.clock() + timedelta(
                    seconds=self.config.collection_interval_seconds
                )

            if now >= schedule.flush_at:
                self.flush_once()
                schedule.flush_at = self.clock() + timedelta(
                    seconds=self.config.flush_interval_seconds
                )

            if now >= schedule.heartbeat_at:
                self.heartbeat_once()
                schedule.heartbeat_at = self.clock() + timedelta(
                    seconds=self.config.heartbeat_interval_seconds
                )

            now = self.clock()
            nearest = min(schedule.collect_at, schedule.flush_at, schedule.heartbeat_at)
            wait_seconds = max(0.0, (nearest - now).total_seconds())
            if self._next_source_sync is not None:
                wait_seconds = min(wait_seconds, max(0.0, (self._next_source_sync - now).total_seconds()))
            if self._next_auth_attempt is not None:
                wait_seconds = min(
                    wait_seconds, max(0.0, (self._next_auth_attempt - now).total_seconds())
                )
            self.stop_event.wait(min(1.0, wait_seconds))

    # ---------------------------------------------------------------- identity
    def _read_enrollment_token(self) -> str:
        path = self.config.enrollment_token_file
        if path is None:
            raise AgentRuntimeError(
                "enrollment_token_file is required to register this agent.",
                code="missing_enrollment_token_file",
            )
        try:
            token = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AgentRuntimeError(
                f"Cannot read enrollment token file {path}: {exc}",
                code="enrollment_token_unreadable",
            ) from exc
        if not token:
            raise AgentRuntimeError(
                "The enrollment token file is empty.",
                code="empty_enrollment_token",
            )
        try:
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                logger.warning(
                    "Enrollment token file %s is readable by group/others; use chmod 600.",
                    path,
                )
        except OSError:
            pass
        return token

    def _source_registration(self, source: SourceConfig) -> dict[str, Any]:
        return {
            "key": source.key,
            "name": source.name,
            "source_type": source.source_type,
            "path_hint": str(source.path)[:512],
            "timezone_hint": source.timezone_hint,
            "default_year": source.default_year,
            "enabled": source.enabled,
            "clock_offset_seconds": source.clock_offset_seconds,
            "expected_collection_interval_seconds": (
                source.expected_collection_interval_seconds
            ),
        }

    def _source_registrations(self) -> list[dict[str, Any]]:
        return [self._source_registration(source) for source in self.config.sources]

    def _register_once(self) -> str | None:
        enrollment_token = self._read_enrollment_token()
        try:
            result = self.client.register(
                enrollment_token=enrollment_token,
                agent_uid=self.agent_uid or "",
                display_name=self.config.display_name,
                hostname=socket.gethostname()[:255],
                platform=platform_module.platform()[:120],
                investigation_id=self.config.investigation_id,
                sources=self._source_registrations(),
            )
        except EnrollmentRejected as exc:
            if exc.status_code == 401:
                raise AgentRuntimeError(
                    "The server rejected the enrollment token. Check AGENT_ENROLLMENT_TOKEN "
                    "and the local enrollment token file.",
                    code="invalid_enrollment_token",
                ) from exc
            self._record_local_error(
                "enrollment_rejected",
                "Agent enrollment was refused by the server; the agent may be disabled.",
            )
            self._auth_blocked = True
            self._token_needs_check = False
            self._set_auth_backoff(maximum=True)
            return None
        except RequestRejected as exc:
            if exc.status_code == 404 or exc.code in {
                "investigation_not_found",
                "investigation_missing",
            }:
                raise AgentRuntimeError(
                    "The configured investigation_id does not exist on the server.",
                    code="investigation_not_found",
                ) from exc
            if exc.code == "agent_investigation_conflict":
                raise AgentRuntimeError(
                    "This agent UID is registered to a different investigation.",
                    code="agent_investigation_conflict",
                ) from exc
            raise AgentRuntimeError(
                f"Agent registration was rejected: {exc.detail or exc}",
                code="agent_registration_rejected",
            ) from exc
        except TransientClientError as exc:
            logger.warning("Agent registration will be retried: %s", exc)
            self._record_local_error("registration_unavailable", str(exc))
            self._set_auth_backoff()
            return None
        except AgentClientError as exc:
            raise AgentRuntimeError(
                f"Agent registration failed: {exc.detail or exc}",
                code=exc.code,
            ) from exc

        self._accept_registration(result)
        return self.token

    def _accept_registration(self, result: RegistrationResult) -> None:
        if result.investigation_id.lower() != self.config.investigation_id.lower():
            raise AgentRuntimeError(
                "The server assigned this agent to a different investigation than configured.",
                code="investigation_mismatch",
            )
        if self.agent_uid and result.agent_uid != self.agent_uid:
            raise AgentRuntimeError(
                "The server returned an unexpected agent identity.",
                code="agent_identity_mismatch",
            )
        try:
            self.state.save_token(result.agent_token)
            self.state.set_meta("agent_id", result.agent_id)
            self.state.set_meta("investigation_id", result.investigation_id)
            self.state.set_meta("agent_uid", result.agent_uid)
        except (OSError, AgentStateError) as exc:
            raise AgentRuntimeError(
                f"Could not persist the new agent token: {exc}",
                code="token_persistence_failed",
            ) from exc

        self.token = result.agent_token
        self._token_needs_check = False
        self._auth_blocked = False
        self._auth_failures = 0
        self._next_auth_attempt = None
        self._source_sync_pending = True
        self._next_source_sync = None
        if result.rotated:
            logger.warning("Agent re-registered and its previous token was rotated.")
        logger.info(
            "Registered agent %s (%s) for investigation %s",
            result.agent_uid,
            result.token_prefix,
            result.investigation_id,
        )

    def _validate_me(self, payload: dict[str, Any]) -> None:
        investigation = str(payload.get("investigation_id") or "")
        if investigation.lower() != self.config.investigation_id.lower():
            raise AgentRuntimeError(
                "The server token belongs to a different investigation than configured.",
                code="token_investigation_mismatch",
            )
        agent_uid = payload.get("agent_uid")
        if self.agent_uid and agent_uid and str(agent_uid) != self.agent_uid:
            raise AgentRuntimeError(
                "The server token belongs to a different agent identity.",
                code="token_identity_mismatch",
            )

    def _acquire_token(self) -> str | None:
        now = self.clock()
        if self._next_auth_attempt is not None and now < self._next_auth_attempt:
            return None
        if self.token is not None and not self._token_needs_check:
            return self.token

        token = self.token or self.state.load_token()
        if token is not None:
            try:
                payload = self.client.me(token)
            except AuthenticationRejected as exc:
                if exc.status_code == 403:
                    self._handle_auth_failure(exc)
                    return None
                self._discard_token()
                logger.warning("Stored agent token was rejected; attempting re-enrollment.")
            except TransientClientError as exc:
                logger.warning("Could not verify the stored agent token yet: %s", exc)
                self.token = token
                self._token_needs_check = False
                self._network_failing = True
                return token
            except AgentClientError as exc:
                logger.warning("Could not verify the stored agent token: %s", exc)
                self._token_needs_check = False
                return token
            else:
                self._validate_me(payload)
                self.token = token
                self._token_needs_check = False
                self._auth_blocked = False
                self._network_failing = False
                return token

        return self._register_once()

    def _discard_token(self) -> None:
        self.token = None
        self._token_needs_check = False
        try:
            self.state.delete_token()
        except OSError as exc:
            logger.warning("Could not remove the invalid token file: %s", exc)

    def _handle_auth_failure(self, exc: AgentClientError) -> None:
        if exc.status_code == 403:
            self._auth_blocked = True
            self._token_needs_check = True
            self._record_local_error(
                "agent_auth_blocked",
                "The server refused this agent token; the agent may be disabled.",
            )
            self._set_auth_backoff(maximum=True)
        else:
            self._auth_blocked = False
            self._record_local_error(
                "agent_auth_rejected",
                "The server rejected the stored agent token; re-enrollment is required.",
            )
            self._discard_token()
            self._set_auth_backoff()
        logger.warning("Agent authentication failed: %s", exc.detail or exc)

    def _set_auth_backoff(self, *, maximum: bool = False) -> None:
        self._auth_failures += 1
        if maximum:
            delay = self.config.max_backoff_seconds
        else:
            delay = min(
                self.config.max_backoff_seconds,
                5 * (2 ** min(self._auth_failures - 1, 8)),
            )
        self._next_auth_attempt = self.clock() + timedelta(seconds=delay)

    def _record_local_error(self, code: str, message: str) -> None:
        try:
            self.state.add_error(code=code, message=message)
        except Exception:
            logger.exception("Could not write a local agent error report")

    # --------------------------------------------------------------- inventory
    def _sync_sources_once(self) -> bool:
        token = self._acquire_token()
        if token is None:
            return False
        try:
            response = self.client.sync_sources(token, self._source_registrations())
        except AuthenticationRejected as exc:
            self._handle_auth_failure(exc)
            return False
        except TransientClientError as exc:
            self._network_failing = True
            logger.warning("Source inventory sync will be retried: %s", exc)
            self._record_local_error("source_sync_unavailable", str(exc))
            self._next_source_sync = self.clock() + timedelta(
                seconds=min(60, self.config.max_backoff_seconds)
            )
            return False
        except RequestRejected as exc:
            raise AgentRuntimeError(
                f"Source inventory was rejected: {exc.detail or exc}",
                code=exc.code,
            ) from exc
        except AgentClientError as exc:
            logger.warning("Source inventory sync failed: %s", exc)
            self._next_source_sync = self.clock() + timedelta(
                seconds=min(60, self.config.max_backoff_seconds)
            )
            return False

        self._source_sync_pending = False
        self._next_source_sync = None
        self._network_failing = False
        created = response.get("created", 0)
        updated = response.get("updated", 0)
        logger.info("Source inventory synchronized (created=%s, updated=%s).", created, updated)
        return True

    # --------------------------------------------------------------- collection
    def collect_once(self) -> CollectionResult | None:
        try:
            result = self.collector.collect_all()
        except Exception as exc:
            logger.exception("Unexpected collection failure")
            self._record_local_error(
                "collection_failed",
                f"Unexpected collection failure: {type(exc).__name__}",
            )
            return None

        self._statuses = {status.key: status for status in result.statuses}
        if not result.has_segments:
            return result

        manifest = self._build_manifest(result)
        try:
            self.state.enqueue_batch(manifest, result.total_bytes)
        except Exception as exc:
            logger.exception("Could not enqueue collected batch %s", result.batch_id)
            shutil.rmtree(self.state.spool_root / result.batch_id, ignore_errors=True)
            self._record_local_error(
                "queue_write_failed",
                f"Could not persist a collected batch: {type(exc).__name__}",
            )
            return None

        self._advance_cursors(result)
        self._last_collection_at = max(
            (segment.collected_at for segment in result.segments), default=self.clock()
        )
        logger.info(
            "Queued batch %s with %s file(s), %s bytes.",
            result.batch_id,
            len(result.segments),
            result.total_bytes,
        )
        return result

    def _build_manifest(self, result: CollectionResult) -> dict[str, Any]:
        return {
            "batch_id": result.batch_id,
            "investigation_id": self.config.investigation_id,
            "created_at": _iso(self.clock()),
            "agent_version": AGENT_VERSION,
            "items": [
                {
                    "item_id": segment.item_id,
                    "source_key": segment.source_key,
                    "source_type": segment.source_type,
                    "filename": segment.filename,
                    "sha256": segment.sha256,
                    "size_bytes": segment.size_bytes,
                    "collected_at": _iso(segment.collected_at),
                    "collection_started_at": _iso(segment.collection_started_at),
                    "collection_ended_at": _iso(segment.collection_ended_at),
                    "lines_collected": segment.lines_collected,
                    "range_start": segment.range_start,
                    "range_end": segment.range_end,
                }
                for segment in result.segments
            ],
            "errors": [],
        }

    def _advance_cursors(self, result: CollectionResult) -> None:
        latest: dict[str, Any] = {}
        for segment in result.segments:
            latest[segment.source_key] = segment
        for segment in latest.values():
            try:
                self.state.set_cursor(
                    segment.source_key,
                    path=segment.source_path,
                    device=segment.device,
                    inode=segment.inode,
                    offset=segment.range_end,
                    updated_at=segment.collected_at,
                )
            except Exception:
                logger.exception(
                    "Could not persist cursor for %s; a duplicate may be uploaded next cycle.",
                    segment.source_key,
                )

    # ----------------------------------------------------------------- delivery
    def flush_once(self) -> int:
        batches = self.state.pending_batches(now=self.clock())
        if not batches:
            return 0
        token = self._acquire_token()
        if token is None:
            return 0

        delivered = 0
        for batch in batches[:10]:
            if self.stop_event.is_set():
                break
            try:
                parts = self._parts_for_batch(batch)
                response = self.client.upload_batch(token, batch.manifest, parts)
            except SpoolFileError as exc:
                self._quarantine_batch(batch, code=exc.code, message=str(exc))
                continue
            except AuthenticationRejected as exc:
                self._handle_auth_failure(exc)
                self._backoff_batch(batch, str(exc), exc)
                return delivered
            except PayloadTooLarge as exc:
                self._quarantine_batch(batch, code=exc.code, message=str(exc))
                continue
            except RequestRejected as exc:
                if exc.code == "unknown_agent_source":
                    self._record_local_error(
                        "unknown_agent_source",
                        "The server does not know a source in the queued batch; "
                        "synchronizing inventory before retrying.",
                    )
                    self._source_sync_pending = True
                    self._next_source_sync = self.clock()
                    self._backoff_batch(batch, str(exc), exc, minimum_delay=5)
                    return delivered
                if exc.code == "agent_source_disabled":
                    self._record_local_error(
                        "agent_source_disabled",
                        "A configured source is disabled on the server; its queued batch "
                        "will be retried after the source is enabled.",
                    )
                    self._backoff_batch(batch, str(exc), exc)
                    return delivered
                if exc.code == "investigation_mismatch":
                    raise AgentRuntimeError(
                        "The queued batch belongs to a different investigation.",
                        code="batch_investigation_mismatch",
                    ) from exc
                self._quarantine_batch(batch, code=exc.code, message=str(exc))
                continue
            except (TransientClientError, ProtocolError) as exc:
                self._network_failing = True
                self._backoff_batch(batch, str(exc), exc)
                logger.warning("Batch %s upload will be retried: %s", batch.batch_id, exc)
                return delivered
            except AgentClientError as exc:
                if exc.retryable:
                    self._network_failing = True
                    self._backoff_batch(batch, str(exc), exc)
                    return delivered
                self._quarantine_batch(batch, code=exc.code, message=str(exc))
                continue

            self._network_failing = False
            server_batch_id = response.get("batch_id")
            if server_batch_id and server_batch_id != batch.batch_id:
                self._backoff_batch(
                    batch,
                    "Server returned a different batch_id.",
                    ProtocolError("Server returned a different batch_id."),
                )
                return delivered
            retryable_items = [
                item
                for item in (response.get("items") or [])
                if isinstance(item, dict) and item.get("retryable") is True
            ]
            if retryable_items:
                self._record_local_error(
                    "batch_item_retryable",
                    "The server reported retryable item failures; the batch is retained.",
                )
                self._backoff_batch(
                    batch,
                    "Server reported retryable item failures.",
                    TransientClientError(
                        "retryable batch items", code="retryable_batch_items"
                    ),
                )
                return delivered

            try:
                self.state.remove_batch(batch.batch_id)
                shutil.rmtree(self.state.spool_root / batch.batch_id, ignore_errors=True)
            except Exception:
                logger.exception("Uploaded batch %s could not be removed from local state.", batch.batch_id)
                return delivered
            delivered += 1
            logger.info(
                "Delivered batch %s: status=%s accepted=%s duplicates=%s failed=%s.",
                batch.batch_id,
                response.get("status"),
                response.get("accepted_items", 0),
                response.get("duplicate_items", 0),
                response.get("failed_items", 0),
            )
        return delivered

    def _parts_for_batch(self, batch: PendingBatch) -> list[UploadFilePart]:
        items = batch.manifest.get("items")
        if not isinstance(items, list) or not items:
            raise SpoolFileError("Queued batch has no items.")
        parts: list[UploadFilePart] = []
        batch_dir = self.state.spool_root / batch.batch_id
        for item in items:
            if not isinstance(item, dict):
                raise SpoolFileError("Queued batch manifest is malformed.")
            try:
                item_id = str(item["item_id"])
                filename = str(item["filename"])
                sha256 = str(item["sha256"])
                size_bytes = int(item["size_bytes"])
            except (KeyError, TypeError, ValueError) as exc:
                raise SpoolFileError("Queued batch item manifest is malformed.") from exc
            parts.append(
                UploadFilePart(
                    filename=filename,
                    path=batch_dir / f"{item_id}.log",
                    sha256=sha256,
                    size_bytes=size_bytes,
                )
            )
        return parts

    def _backoff_batch(
        self,
        batch: PendingBatch,
        error: str,
        exc: AgentClientError,
        *,
        minimum_delay: int = 1,
    ) -> None:
        attempts = batch.attempts + 1
        delay = max(
            minimum_delay,
            min(self.config.max_backoff_seconds, 2 ** min(attempts, 10)),
        )
        if exc.retry_after is not None:
            delay = max(delay, min(exc.retry_after, self.config.max_backoff_seconds))
        try:
            self.state.update_batch_attempt(
                batch.batch_id,
                error=error,
                next_attempt_at=self.clock() + timedelta(seconds=delay),
            )
        except Exception:
            logger.exception("Could not schedule retry for batch %s", batch.batch_id)

    def _quarantine_batch(self, batch: PendingBatch, *, code: str, message: str) -> None:
        source_dir = self.state.spool_root / batch.batch_id
        target_dir = self.state.quarantine_root / batch.batch_id
        try:
            if target_dir.exists():
                shutil.rmtree(target_dir)
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            if source_dir.exists():
                shutil.move(str(source_dir), str(target_dir))
            else:
                target_dir.mkdir(parents=True, exist_ok=True)
            reason = (
                f"code: {code}\n"
                f"time: {_iso(self.clock())}\n"
                f"message: {message[:4000]}\n"
            )
            reason_path = target_dir / "QUARANTINE.txt"
            reason_path.write_text(reason, encoding="utf-8")
            try:
                os.chmod(reason_path, 0o600)
            except OSError:
                pass
            self.state.remove_batch(batch.batch_id)
        except Exception as exc:
            logger.exception("Could not quarantine batch %s", batch.batch_id)
            self._record_local_error(
                "quarantine_failed",
                f"Batch {batch.batch_id} could not be quarantined: {type(exc).__name__}",
            )
            return

        logger.error("Quarantined batch %s (%s): %s", batch.batch_id, code, message)
        self._record_local_error(
            "batch_quarantined",
            f"Batch {batch.batch_id} was quarantined ({code}): {message[:1500]}",
        )

    # ------------------------------------------------------------------ status
    def _source_report(self, source: SourceConfig) -> dict[str, Any]:
        status = self._statuses.get(source.key)
        if status is None:
            cursor = self.state.get_cursor(source.key)
            status = SourceStatus(
                key=source.key,
                name=source.name,
                enabled=source.enabled,
                readable=None,
                status="disabled" if not source.enabled else "unknown",
                last_error=None,
                last_collected_at=cursor.updated_at if cursor else None,
                cursor_bytes=cursor.offset if cursor else None,
            )
        return {
            "key": source.key,
            "status": status.status,
            "path_readable": status.readable,
            "last_collected_at": _iso(status.last_collected_at),
            "last_success_at": _iso(status.last_success_at),
            "collection_started_at": _iso(status.collection_started_at),
            "collection_ended_at": _iso(status.collection_ended_at),
            "cursor_bytes": status.cursor_bytes,
            "observed_size_bytes": status.observed_size_bytes,
            "bytes_collected_last_cycle": status.bytes_collected_last_cycle,
            "lines_collected_last_cycle": status.lines_collected_last_cycle,
            "collection_available": status.collection_available,
            "last_error": (status.last_error or "")[:2000] or None,
        }

    def _heartbeat_payload(self) -> dict[str, Any]:
        errors = self.state.unreported_errors(50)
        return {
            "agent_version": AGENT_VERSION,
            "runtime_status": self._runtime_status(),
            "queue_pending_batches": self.state.batch_count(),
            "queue_pending_bytes": self.state.pending_bytes(),
            "heartbeat_interval_seconds": self.config.heartbeat_interval_seconds,
            "collection_interval_seconds": self.config.collection_interval_seconds,
            "clock_offset_seconds": self._measured_clock_offset_seconds,
            "clock_offset_source": (
                "measured" if self._measured_clock_offset_seconds is not None else None
            ),
            "reported_at": _iso(self.clock()),
            "sources": [self._source_report(source) for source in self.config.sources],
            "errors": [
                {
                    "source_key": error.source_key,
                    "code": error.code,
                    "message": error.message[:2000],
                    "occurred_at": _iso(error.occurred_at),
                }
                for error in errors
            ],
        }

    def _runtime_status(self) -> str:
        if self._auth_blocked or self._network_failing:
            return "degraded"
        if any(status.status == "error" for status in self._statuses.values()):
            return "degraded"
        return "running"

    def heartbeat_once(self) -> bool:
        token = self._acquire_token()
        if token is None:
            return False
        payload = self._heartbeat_payload()
        sent_error_ids = [
            error.id
            for error in self.state.unreported_errors(50)
        ]
        try:
            response = self.client.heartbeat(token, payload)
        except AuthenticationRejected as exc:
            self._handle_auth_failure(exc)
            return False
        except TransientClientError as exc:
            self._network_failing = True
            logger.warning("Heartbeat will be retried: %s", exc)
            return False
        except RequestRejected as exc:
            raise AgentRuntimeError(
                f"Heartbeat was rejected: {exc.detail or exc}",
                code="heartbeat_rejected",
            ) from exc
        except AgentClientError as exc:
            logger.warning("Heartbeat failed: %s", exc)
            return False

        self._network_failing = False
        self._auth_failures = 0
        self._next_auth_attempt = None
        self._last_heartbeat_at = self.clock()
        server_time = _parse_iso(response.get("server_time"))
        if server_time is not None:
            measured = int(round((server_time - self.clock()).total_seconds()))
            if -86400 <= measured <= 86400:
                self._measured_clock_offset_seconds = measured
        acknowledged = bool(response.get("acknowledged"))
        recorded = int(response.get("errors_recorded") or 0)
        if acknowledged and recorded >= len(sent_error_ids):
            self.state.mark_errors_reported(sent_error_ids)
        ignored = response.get("ignored_sources") or []
        if ignored:
            self._record_local_error(
                "source_inventory_mismatch",
                "The server ignored source keys in the heartbeat: "
                + ", ".join(str(item)[:64] for item in ignored[:10]),
            )
            self._source_sync_pending = True
            self._next_source_sync = self.clock()
        logger.debug("Heartbeat acknowledged; agent health is %s.", response.get("agent_health"))
        return acknowledged
