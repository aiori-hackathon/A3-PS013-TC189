"""Idempotent ingestion of agent collection batches."""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agent_schemas import (
    AgentBatchItemManifest,
    AgentBatchItemResult,
    AgentBatchManifest,
    AgentBatchResult,
)
from app.config import Settings
from app.constants import (
    AgentBatchItemStatus,
    AgentBatchStatus,
    AgentSourceStatus,
    CollectionGapReason,
    CollectionGapStatus,
    CollectionWindowStatus,
    GapBasis,
    RequestedSourceType,
    SourceType,
)
from app.models import (
    Agent,
    AgentBatch,
    AgentBatchItem,
    AgentError,
    AgentSource,
    CollectionGap,
    EvidenceFile,
    EvidenceSource,
    Investigation,
    SourceCollectionWindow,
    utcnow,
)
from app.services.agent_service import _max_time, record_agent_error
from app.services.coverage import (
    close_open_gaps,
    ensure_open_gap,
    record_collection_window,
)
from app.services.errors import IngestError
from app.services.ingest import IngestOptions, IngestService

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 1024 * 1024
_MAX_FUTURE_SKEW = timedelta(hours=24)


@dataclass(slots=True)
class StagedUpload:
    item: AgentBatchItemManifest
    path: Path
    sha256: str
    size_bytes: int


def _cleanup(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Could not remove staged agent upload %s", path)


def _stage_uploads(
    settings: Settings,
    items: list[AgentBatchItemManifest],
    files: list[UploadFile],
) -> list[StagedUpload]:
    if len(files) != len(items):
        raise IngestError(
            422,
            "batch_file_count_mismatch",
            "The number of uploaded files does not match the manifest item count.",
            expected=len(items),
            received=len(files),
        )

    settings.temp_root.mkdir(parents=True, exist_ok=True)
    staged: list[StagedUpload] = []
    total = 0
    try:
        for item, upload in zip(items, files, strict=True):
            temp_path = settings.temp_root / f"agent-{uuid.uuid4().hex}.upload"
            digest = hashlib.sha256()
            size = 0
            upload.file.seek(0)
            with temp_path.open("wb") as target:
                while True:
                    chunk = upload.file.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    total += len(chunk)
                    if total > settings.agent_batch_max_bytes:
                        raise IngestError(
                            413,
                            "agent_batch_too_large",
                            f"Batch exceeds the {settings.agent_batch_max_bytes} byte limit.",
                        )
                    if size > settings.max_upload_size_bytes:
                        raise IngestError(
                            413,
                            "file_too_large",
                            (
                                f"Batch item {item.item_id!r} exceeds the "
                                f"{settings.max_upload_size_bytes} byte upload limit."
                            ),
                            item_id=item.item_id,
                        )
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
            if size == 0:
                raise IngestError(
                    422,
                    "empty_file",
                    "Empty batch items are not accepted as evidence.",
                    item_id=item.item_id,
                )
            actual_sha = digest.hexdigest()
            if size != item.size_bytes or actual_sha != item.sha256:
                raise IngestError(
                    422,
                    "item_integrity_mismatch",
                    (
                        f"Batch item {item.item_id!r} did not match its manifest size or "
                        "SHA-256. No files from this batch were ingested."
                    ),
                    item_id=item.item_id,
                    expected_sha256=item.sha256,
                    actual_sha256=actual_sha,
                    expected_size_bytes=item.size_bytes,
                    actual_size_bytes=size,
                )
            staged.append(
                StagedUpload(item=item, path=temp_path, sha256=actual_sha, size_bytes=size)
            )
    except Exception:
        _cleanup([entry.path for entry in staged])
        raise

    return staged


def _validate_manifest(
    session: Session,
    settings: Settings,
    agent: Agent,
    manifest: AgentBatchManifest,
) -> dict[str, AgentSource]:
    if not manifest.items and not manifest.errors:
        raise IngestError(422, "empty_batch", "A batch must contain items or errors.")
    if len(manifest.items) > settings.agent_batch_max_files:
        raise IngestError(
            413,
            "too_many_batch_items",
            f"A batch may contain at most {settings.agent_batch_max_files} files.",
            item_count=len(manifest.items),
        )
    if sum(item.size_bytes for item in manifest.items) > settings.agent_batch_max_bytes:
        raise IngestError(
            413,
            "agent_batch_too_large",
            f"Batch exceeds the {settings.agent_batch_max_bytes} byte limit.",
        )
    if manifest.investigation_id != agent.investigation_id:
        raise IngestError(
            409,
            "investigation_mismatch",
            "Batch investigation does not match the investigation assigned to this agent.",
        )

    now = utcnow()
    sources = {
        source.source_key: source
        for source in session.scalars(
            select(AgentSource).where(AgentSource.agent_id == agent.id)
        ).all()
    }
    for item in manifest.items:
        source = sources.get(item.source_key)
        if source is None:
            raise IngestError(
                422,
                "unknown_agent_source",
                f"Agent source {item.source_key!r} is not registered on the server.",
                source_key=item.source_key,
            )
        if not source.enabled:
            raise IngestError(
                409,
                "agent_source_disabled",
                f"Agent source {item.source_key!r} is disabled.",
                source_key=item.source_key,
            )
        if source.source_type.value != item.source_type:
            raise IngestError(
                422,
                "source_type_mismatch",
                (
                    f"Manifest item source type {item.source_type!r} does not match "
                    f"registered source type {source.source_type.value!r}."
                ),
                source_key=item.source_key,
            )
        if Path(item.filename).suffix.lower() not in settings.allowed_extension_set:
            raise IngestError(
                415,
                "unsupported_file_type",
                (
                    f"Batch item filename {item.filename!r} has an extension that is not "
                    "accepted as text evidence."
                ),
                item_id=item.item_id,
            )
        if item.collected_at > now + _MAX_FUTURE_SKEW:
            raise IngestError(
                422,
                "invalid_collected_at",
                "Batch item collected_at is unreasonably far in the future.",
                item_id=item.item_id,
            )
    return sources


def _get_or_create_evidence_source(
    session: Session,
    agent: Agent,
    agent_source: AgentSource,
) -> EvidenceSource:
    if agent_source.evidence_source_id is not None:
        existing = session.get(EvidenceSource, agent_source.evidence_source_id)
        if existing is not None and existing.investigation_id == agent.investigation_id:
            if existing.source_type.value == agent_source.source_type.value:
                return existing

    name = f"agent:{agent.agent_uid[:16]}:{agent_source.source_key}"
    source = session.scalar(
        select(EvidenceSource).where(
            EvidenceSource.investigation_id == agent.investigation_id,
            EvidenceSource.name == name,
        )
    )
    if source is None:
        source = EvidenceSource(
            investigation_id=agent.investigation_id,
            name=name,
            source_type=SourceType(agent_source.source_type),
            hostname=agent.hostname,
            description=f"Collected automatically by CyberTrace agent {agent.display_name}.",
            metadata_json={
                "managed_by": "agent",
                "agent_id": str(agent.id),
                "agent_uid": agent.agent_uid,
                "source_key": agent_source.source_key,
            },
        )
        try:
            session.add(source)
            session.flush()
        except IntegrityError:
            session.rollback()
            source = session.scalar(
                select(EvidenceSource).where(
                    EvidenceSource.investigation_id == agent.investigation_id,
                    EvidenceSource.name == name,
                )
            )
            if source is None:
                raise
    if source.source_type.value != agent_source.source_type.value:
        raise IngestError(
            409,
            "source_type_conflict",
            "The evidence source already exists with a different log type.",
            source_key=agent_source.source_key,
        )
    agent_source.evidence_source_id = source.id
    session.flush()
    return source


def _find_duplicate(
    session: Session, investigation_id: uuid.UUID, sha256: str
) -> EvidenceFile | None:
    return session.scalar(
        select(EvidenceFile)
        .where(
            EvidenceFile.investigation_id == investigation_id,
            EvidenceFile.sha256 == sha256,
        )
        .order_by(EvidenceFile.received_at.asc())
        .limit(1)
    )


def _mark_source_success(
    session: Session,
    agent: Agent,
    agent_source: AgentSource,
    item: AgentBatchItemManifest,
    now: datetime,
    *,
    status: CollectionWindowStatus,
    evidence_file_id: uuid.UUID | None,
    batch: AgentBatch,
    batch_item_id: int | None,
    size_bytes: int | None,
    overlap_bytes: int | None = None,
) -> None:
    agent.last_seen_at = now
    agent.last_collection_at = _max_time(agent.last_collection_at, item.collected_at)
    agent_source.last_seen_at = now
    agent_source.last_collected_at = _max_time(
        agent_source.last_collected_at, item.collected_at
    )
    agent_source.last_success_at = _max_time(
        agent_source.last_success_at, item.collected_at
    )
    agent_source.status = AgentSourceStatus.HEALTHY
    agent_source.last_error = None
    agent_source.last_error_at = None
    agent_source.collection_available = True
    if item.collection_started_at is not None:
        agent_source.last_collection_started_at = _max_time(
            agent_source.last_collection_started_at, item.collection_started_at
        )
    if item.collection_ended_at is not None:
        agent_source.last_collection_ended_at = _max_time(
            agent_source.last_collection_ended_at, item.collection_ended_at
        )
    if size_bytes is not None:
        agent_source.last_cycle_bytes = size_bytes
        agent_source.last_cycle_lines = item.lines_collected
        agent_source.last_cycle_at = now
    if item.range_end is not None:
        agent_source.cursor_bytes = item.range_end

    closed_gaps = close_open_gaps(
        session,
        investigation_id=agent.investigation_id,
        end=now,
        agent_source_id=agent_source.id,
        note="Batch item was accepted or identified as an exact duplicate; collection coverage resumed.",
    )
    if closed_gaps:
        agent_source.recovery_count = (agent_source.recovery_count or 0) + 1
        agent_source.last_recovery_at = now

    expected_bytes = (
        max(item.range_end - item.range_start, 0)
        if item.range_start is not None and item.range_end is not None
        else size_bytes
    )
    record_collection_window(
        session,
        investigation_id=agent.investigation_id,
        agent=agent,
        source=agent_source,
        origin="batch",
        status=status,
        observed_at=now,
        started_at=item.collection_started_at,
        ended_at=item.collection_ended_at or item.collected_at,
        bytes_collected=size_bytes,
        lines_collected=item.lines_collected,
        expected_bytes=expected_bytes,
        range_start=item.range_start,
        range_end=item.range_end,
        evidence_file_id=evidence_file_id,
        agent_batch_id=batch.id,
        agent_batch_item_id=batch_item_id,
        detail={
            "batch_id": batch.batch_id,
            "item_id": item.item_id,
            "overlap_bytes": overlap_bytes,
        },
    )


def _upsert_item(
    session: Session,
    existing: AgentBatchItem | None,
    *,
    batch: AgentBatch,
    agent_source: AgentSource,
    item: AgentBatchItemManifest,
    status: AgentBatchItemStatus,
    evidence_id: uuid.UUID | None,
    message: str | None,
    error_code: str | None = None,
    retryable: bool = False,
) -> AgentBatchItem:
    if existing is None:
        existing = AgentBatchItem(
            agent_batch_id=batch.id,
            item_id=item.item_id,
            source_id=agent_source.id,
            source_key=item.source_key,
            source_type=SourceType(item.source_type),
            original_filename=item.filename,
            sha256=item.sha256,
            size_bytes=item.size_bytes,
            collected_at=item.collected_at,
            collection_started_at=item.collection_started_at,
            collection_ended_at=item.collection_ended_at,
            range_start=item.range_start,
            range_end=item.range_end,
            expected_bytes=(
                max(item.range_end - item.range_start, 0)
                if item.range_start is not None and item.range_end is not None
                else item.size_bytes
            ),
            lines_collected=item.lines_collected,
            status=status,
        )
        session.add(existing)
    existing.source_id = agent_source.id
    existing.evidence_file_id = evidence_id
    existing.original_filename = item.filename
    existing.sha256 = item.sha256
    existing.size_bytes = item.size_bytes
    existing.collected_at = item.collected_at
    existing.collection_started_at = item.collection_started_at
    existing.collection_ended_at = item.collection_ended_at
    existing.range_start = item.range_start
    existing.range_end = item.range_end
    existing.expected_bytes = (
        max(item.range_end - item.range_start, 0)
        if item.range_start is not None and item.range_end is not None
        else item.size_bytes
    )
    existing.lines_collected = item.lines_collected
    existing.status = status
    existing.error_code = error_code
    existing.message = message
    existing.retryable = retryable
    return existing


def _range_relation(
    agent_source: AgentSource, item: AgentBatchItemManifest
) -> tuple[int | None, int | None]:
    previous_cursor = agent_source.cursor_bytes
    if previous_cursor is None or item.range_start is None:
        return previous_cursor, None
    if item.range_start > previous_cursor:
        return previous_cursor, 0
    if item.range_start < previous_cursor:
        return previous_cursor, previous_cursor - item.range_start
    return previous_cursor, None


def _record_byte_range_gap(
    session: Session,
    *,
    agent: Agent,
    agent_source: AgentSource,
    item: AgentBatchItemManifest,
    previous_cursor: int | None,
) -> None:
    if (
        previous_cursor is None
        or item.range_start is None
        or item.range_start <= previous_cursor
    ):
        return
    already_recorded = session.scalar(
        select(SourceCollectionWindow.id)
        .where(
            SourceCollectionWindow.agent_source_id == agent_source.id,
            SourceCollectionWindow.range_start == item.range_start,
        )
        .limit(1)
    )
    if already_recorded is not None:
        return
    start_time = (
        agent_source.last_collection_ended_at
        or item.collection_started_at
        or item.collected_at
    )
    end_time = item.collection_started_at or item.collected_at
    session.add(
        CollectionGap(
            investigation_id=agent.investigation_id,
            agent_id=agent.id,
            agent_source_id=agent_source.id,
            gap_start=start_time,
            gap_end=end_time,
            status=CollectionGapStatus.CLOSED,
            reason=CollectionGapReason.BYTE_RANGE_GAP,
            basis=GapBasis.OBSERVED,
            expected_interval_seconds=agent_source.expected_collection_interval_seconds,
            detail={
                "previous_cursor_bytes": previous_cursor,
                "range_start": item.range_start,
                "missing_bytes": item.range_start - previous_cursor,
                "item_id": item.item_id,
                "note": (
                    "The byte range is observed from the agent cursor. The gap start/end "
                    "times are the nearest observed collection timestamps, not measured "
                    "failure instants."
                ),
            },
        )
    )


def _mark_source_failure(
    session: Session,
    *,
    agent: Agent,
    agent_source: AgentSource,
    item: AgentBatchItemManifest,
    now: datetime,
    batch: AgentBatch,
    batch_item_id: int | None,
    error_code: str,
    message: str,
    size_bytes: int | None,
) -> None:
    if item.collection_started_at is not None:
        agent_source.last_collection_started_at = _max_time(
            agent_source.last_collection_started_at, item.collection_started_at
        )
    if item.collection_ended_at is not None:
        agent_source.last_collection_ended_at = _max_time(
            agent_source.last_collection_ended_at, item.collection_ended_at
        )
    ensure_open_gap(
        session,
        investigation_id=agent.investigation_id,
        agent=agent,
        source=agent_source,
        gap_start=item.collection_started_at
        or agent_source.last_success_at
        or item.collected_at,
        reason=CollectionGapReason.BATCH_MISSING,
        basis=(
            GapBasis.OBSERVED
            if item.collection_started_at is not None
            else GapBasis.INFERRED
        ),
        expected_interval_seconds=(
            agent_source.expected_collection_interval_seconds
            or agent.collection_interval_seconds
        ),
        detail={
            "item_id": item.item_id,
            "batch_id": batch.batch_id,
            "error_code": error_code,
            "error": message,
            "note": (
                "The batch item did not preserve this collection interval. Coverage "
                "remains open until a later success closes it."
            ),
        },
    )
    record_collection_window(
        session,
        investigation_id=agent.investigation_id,
        agent=agent,
        source=agent_source,
        origin="batch",
        status=CollectionWindowStatus.FAILED,
        observed_at=now,
        started_at=item.collection_started_at,
        ended_at=item.collection_ended_at or item.collected_at,
        bytes_collected=size_bytes,
        lines_collected=item.lines_collected,
        expected_bytes=(
            max(item.range_end - item.range_start, 0)
            if item.range_start is not None and item.range_end is not None
            else size_bytes
        ),
        range_start=item.range_start,
        range_end=item.range_end,
        agent_batch_id=batch.id,
        agent_batch_item_id=batch_item_id,
        detail={
            "batch_id": batch.batch_id,
            "item_id": item.item_id,
            "error_code": error_code,
        },
    )


def _process_item(
    session: Session,
    settings: Settings,
    agent: Agent,
    batch: AgentBatch,
    agent_source: AgentSource,
    staged: StagedUpload,
    existing_item: AgentBatchItem | None,
) -> AgentBatchItem:
    item = staged.item
    now = utcnow()
    previous_cursor, overlap_bytes = _range_relation(agent_source, item)
    _record_byte_range_gap(
        session,
        agent=agent,
        agent_source=agent_source,
        item=item,
        previous_cursor=previous_cursor,
    )

    duplicate = _find_duplicate(session, agent.investigation_id, staged.sha256)
    if duplicate is not None:
        row = _upsert_item(
            session,
            existing_item,
            batch=batch,
            agent_source=agent_source,
            item=item,
            status=AgentBatchItemStatus.DUPLICATE,
            evidence_id=duplicate.id,
            message=(
                "Identical evidence already exists in this investigation; "
                "no additional copy was stored."
            ),
        )
        session.flush()
        _mark_source_success(
            session,
            agent,
            agent_source,
            item,
            now,
            status=CollectionWindowStatus.DUPLICATE,
            evidence_file_id=duplicate.id,
            batch=batch,
            batch_item_id=row.id,
            size_bytes=staged.size_bytes,
            overlap_bytes=overlap_bytes,
        )
        session.commit()
        return row

    investigation = session.get(Investigation, agent.investigation_id)
    if investigation is None:
        raise IngestError(409, "investigation_missing", "The investigation no longer exists.")

    evidence_source = _get_or_create_evidence_source(session, agent, agent_source)
    session.commit()

    options = IngestOptions(
        requested_source_type=RequestedSourceType(item.source_type),
        source_id=evidence_source.id,
        hostname=agent.hostname,
        timezone_hint=agent_source.timezone_hint,
        default_year=agent_source.default_year,
        clock_offset_seconds=agent_source.clock_offset_seconds,
        collected_at=item.collected_at,
        notes=(
            f"Automatically collected by agent {agent.display_name} "
            f"({agent.agent_uid}), batch {batch.batch_id}."
        ),
        allow_duplicate=False,
        content_type="text/plain",
        actor_type="agent",
        actor_detail=agent.agent_uid,
    )
    service = IngestService(session, settings)

    try:
        with staged.path.open("rb") as handle:
            evidence = service.ingest(investigation, handle, item.filename, options)
    except IngestError as exc:
        if exc.code == "duplicate_evidence":
            existing_id = exc.extra.get("existing_evidence_id")
            duplicate = (
                session.get(EvidenceFile, uuid.UUID(existing_id)) if existing_id else None
            )
            if duplicate is not None:
                row = _upsert_item(
                    session,
                    existing_item,
                    batch=batch,
                    agent_source=agent_source,
                    item=item,
                    status=AgentBatchItemStatus.DUPLICATE,
                    evidence_id=duplicate.id,
                    message="Identical evidence already exists in this investigation.",
                )
                session.flush()
                _mark_source_success(
                    session,
                    agent,
                    agent_source,
                    item,
                    now,
                    status=CollectionWindowStatus.DUPLICATE,
                    evidence_file_id=duplicate.id,
                    batch=batch,
                    batch_item_id=row.id,
                    size_bytes=staged.size_bytes,
                    overlap_bytes=overlap_bytes,
                )
                session.commit()
                return row
        session.rollback()
        batch = session.get(AgentBatch, batch.id)
        agent = session.get(Agent, agent.id)
        agent_source = session.get(AgentSource, agent_source.id)
        if batch is None or agent is None or agent_source is None:
            raise
        row = _upsert_item(
            session,
            existing_item,
            batch=batch,
            agent_source=agent_source,
            item=item,
            status=AgentBatchItemStatus.FAILED,
            evidence_id=None,
            error_code=exc.code,
            message=exc.message,
            retryable=exc.status_code >= 500,
        )
        record_agent_error(
            session,
            agent,
            code=exc.code,
            message=exc.message,
            source=agent_source,
            batch=batch,
        )
        if exc.status_code >= 500:
            agent_source.status = AgentSourceStatus.ERROR
        session.flush()
        _mark_source_failure(
            session,
            agent=agent,
            agent_source=agent_source,
            item=item,
            now=now,
            batch=batch,
            batch_item_id=row.id,
            error_code=exc.code,
            message=exc.message,
            size_bytes=staged.size_bytes,
        )
        session.commit()
        return row
    except Exception as exc:  # defensive: one item must not abort a batch
        session.rollback()
        logger.exception("Unexpected agent batch item failure for %s", item.item_id)
        batch = session.get(AgentBatch, batch.id)
        agent = session.get(Agent, agent.id)
        agent_source = session.get(AgentSource, agent_source.id)
        if batch is None or agent is None or agent_source is None:
            raise
        row = _upsert_item(
            session,
            existing_item,
            batch=batch,
            agent_source=agent_source,
            item=item,
            status=AgentBatchItemStatus.FAILED,
            evidence_id=None,
            error_code="agent_batch_item_error",
            message=f"Unexpected ingestion failure: {type(exc).__name__}",
            retryable=True,
        )
        record_agent_error(
            session,
            agent,
            code="agent_batch_item_error",
            message=f"Unexpected ingestion failure for item {item.item_id}: {type(exc).__name__}",
            source=agent_source,
            batch=batch,
        )
        session.flush()
        _mark_source_failure(
            session,
            agent=agent,
            agent_source=agent_source,
            item=item,
            now=now,
            batch=batch,
            batch_item_id=row.id,
            error_code="agent_batch_item_error",
            message=f"Unexpected ingestion failure: {type(exc).__name__}",
            size_bytes=staged.size_bytes,
        )
        session.commit()
        return row

    evidence.metadata_json = {
        **(evidence.metadata_json or {}),
        "agent": {
            "agent_id": str(agent.id),
            "agent_uid": agent.agent_uid,
            "display_name": agent.display_name,
            "batch_id": batch.batch_id,
            "item_id": item.item_id,
            "source_key": agent_source.source_key,
            "agent_version": batch.agent_version,
        },
        "agent_collection": {
            "collected_at": item.collected_at.isoformat(),
            "collection_started_at": (
                item.collection_started_at.isoformat()
                if item.collection_started_at
                else None
            ),
            "collection_ended_at": (
                item.collection_ended_at.isoformat()
                if item.collection_ended_at
                else None
            ),
            "range_start": item.range_start,
            "range_end": item.range_end,
            "lines_collected": item.lines_collected,
            "transport_sha256": staged.sha256,
            "overlap_bytes": overlap_bytes,
        },
    }
    row = _upsert_item(
        session,
        existing_item,
        batch=batch,
        agent_source=agent_source,
        item=item,
        status=AgentBatchItemStatus.ACCEPTED,
        evidence_id=evidence.id,
        message="Evidence stored, hashed and parsed.",
    )
    session.flush()
    _mark_source_success(
        session,
        agent,
        agent_source,
        item,
        now,
        status=CollectionWindowStatus.COMPLETED,
        evidence_file_id=evidence.id,
        batch=batch,
        batch_item_id=row.id,
        size_bytes=staged.size_bytes,
        overlap_bytes=overlap_bytes,
    )
    session.commit()
    return row


def _record_manifest_errors(
    session: Session,
    agent: Agent,
    batch: AgentBatch,
    manifest: AgentBatchManifest,
    sources: dict[str, AgentSource],
) -> int:
    if not manifest.errors:
        return 0
    existing = {
        (error.error_code, error.message, error.occurred_at)
        for error in session.scalars(
            select(AgentError).where(AgentError.agent_batch_id == batch.id)
        ).all()
    }
    recorded = 0
    for reported in manifest.errors:
        source = sources.get(reported.source_key) if reported.source_key else None
        occurred_at = reported.occurred_at or utcnow()
        key = (reported.code, reported.message, occurred_at)
        if key in existing:
            continue
        record_agent_error(
            session,
            agent,
            code=reported.code,
            message=reported.message,
            occurred_at=occurred_at,
            source=source,
            batch=batch,
        )
        existing.add(key)
        recorded += 1
    return recorded


def _finalize_batch(
    session: Session, batch: AgentBatch, manifest_error_count: int
) -> AgentBatch:
    counts = {
        status: int(count)
        for status, count in session.execute(
            select(AgentBatchItem.status, func.count(AgentBatchItem.id))
            .where(AgentBatchItem.agent_batch_id == batch.id)
            .group_by(AgentBatchItem.status)
        ).all()
    }
    accepted = counts.get(AgentBatchItemStatus.ACCEPTED, 0)
    duplicates = counts.get(AgentBatchItemStatus.DUPLICATE, 0)
    failed = counts.get(AgentBatchItemStatus.FAILED, 0)

    if batch.file_count == 0:
        status = AgentBatchStatus.PROCESSED
    elif failed == batch.file_count:
        status = AgentBatchStatus.FAILED
    elif failed > 0:
        status = AgentBatchStatus.PARTIAL
    else:
        status = AgentBatchStatus.PROCESSED

    first_failure = session.scalar(
        select(AgentBatchItem)
        .where(
            AgentBatchItem.agent_batch_id == batch.id,
            AgentBatchItem.status == AgentBatchItemStatus.FAILED,
        )
        .order_by(AgentBatchItem.id.asc())
        .limit(1)
    )
    batch.status = status
    batch.accepted_items = accepted
    batch.duplicate_items = duplicates
    batch.failed_items = failed
    batch.error_count = manifest_error_count + failed
    batch.error_message = (
        first_failure.message[:4000]
        if first_failure is not None and first_failure.message
        else None
    )
    batch.processed_at = utcnow()
    session.commit()
    return batch


def _batch_result(
    session: Session, batch: AgentBatch, *, replayed: bool
) -> AgentBatchResult:
    items = session.scalars(
        select(AgentBatchItem)
        .where(AgentBatchItem.agent_batch_id == batch.id)
        .order_by(AgentBatchItem.id.asc())
    ).all()
    return AgentBatchResult(
        batch_id=batch.batch_id,
        agent_id=batch.agent_id,
        investigation_id=batch.investigation_id,
        status=batch.status,
        replayed=replayed,
        received_at=batch.received_at,
        processed_at=batch.processed_at,
        file_count=batch.file_count,
        byte_count=batch.byte_count,
        accepted_items=batch.accepted_items,
        duplicate_items=batch.duplicate_items,
        failed_items=batch.failed_items,
        error_count=batch.error_count,
        items=[
            AgentBatchItemResult(
                item_id=row.item_id,
                source_key=row.source_key,
                status=row.status,
                evidence_id=row.evidence_file_id,
                sha256=row.sha256,
                size_bytes=row.size_bytes,
                error_code=row.error_code,
                message=row.message,
                retryable=row.retryable,
            )
            for row in items
        ],
        errors_recorded=batch.error_count,
    )


def process_batch(
    session: Session,
    settings: Settings,
    agent: Agent,
    manifest_raw: str,
    manifest: AgentBatchManifest,
    files: list[UploadFile],
) -> AgentBatchResult:
    request_digest = hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest()
    existing = session.scalar(
        select(AgentBatch).where(
            AgentBatch.agent_id == agent.id,
            AgentBatch.batch_id == manifest.batch_id,
        )
    )
    replayed = existing is not None

    if existing is not None:
        if existing.request_digest != request_digest:
            raise IngestError(
                409,
                "batch_conflict",
                "This batch_id was already used with a different manifest.",
                batch_id=manifest.batch_id,
            )
        agent.last_seen_at = utcnow()
        session.commit()
        if existing.status is AgentBatchStatus.PROCESSED:
            return _batch_result(session, existing, replayed=True)

    sources = _validate_manifest(session, settings, agent, manifest)
    if manifest.items:
        staged = _stage_uploads(settings, manifest.items, files)
    else:
        if files:
            raise IngestError(
                422,
                "batch_file_count_mismatch",
                "The manifest has no items but files were uploaded.",
                received=len(files),
            )
        staged = []

    try:
        if existing is None:
            existing = AgentBatch(
                agent_id=agent.id,
                investigation_id=agent.investigation_id,
                batch_id=manifest.batch_id,
                request_digest=request_digest,
                agent_version=manifest.agent_version,
                client_created_at=manifest.created_at,
                status=AgentBatchStatus.RECEIVED,
                file_count=len(manifest.items),
                byte_count=sum(item.size_bytes for item in manifest.items),
                metadata_json={},
            )
            session.add(existing)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = session.scalar(
                    select(AgentBatch).where(
                        AgentBatch.agent_id == agent.id,
                        AgentBatch.batch_id == manifest.batch_id,
                    )
                )
                if existing is None:
                    raise
                if existing.request_digest != request_digest:
                    raise IngestError(
                        409,
                        "batch_conflict",
                        "This batch_id was already used with a different manifest.",
                        batch_id=manifest.batch_id,
                    ) from None
                if existing.status is AgentBatchStatus.PROCESSED:
                    return _batch_result(session, existing, replayed=True)
                replayed = True
        agent = session.get(Agent, agent.id)
        if agent is None:
            raise IngestError(409, "agent_missing", "The agent record no longer exists.")

        existing_rows = {
            row.item_id: row
            for row in session.scalars(
                select(AgentBatchItem).where(AgentBatchItem.agent_batch_id == existing.id)
            ).all()
        }
        for staged_item in staged:
            row = existing_rows.get(staged_item.item.item_id)
            if row is not None and row.status in (
                AgentBatchItemStatus.ACCEPTED,
                AgentBatchItemStatus.DUPLICATE,
            ):
                continue
            agent_source = session.get(AgentSource, sources[staged_item.item.source_key].id)
            if agent_source is None:
                raise IngestError(
                    409,
                    "agent_source_missing",
                    "The agent source disappeared during batch processing.",
                )
            try:
                _process_item(
                    session,
                    settings,
                    agent,
                    existing,
                    agent_source,
                    staged_item,
                    row,
                )
            finally:
                try:
                    staged_item.path.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Could not remove staged upload %s", staged_item.path)

        manifest_errors = _record_manifest_errors(
            session, agent, existing, manifest, sources
        )
        existing = _finalize_batch(session, existing, manifest_errors)
        return _batch_result(session, existing, replayed=replayed)
    except Exception:
        _cleanup([entry.path for entry in staged])
        raise
    finally:
        _cleanup([entry.path for entry in staged])
