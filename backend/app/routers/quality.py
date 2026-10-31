"""Evidence quality APIs: coverage, parsing, timestamps, integrity, duplicates, audit."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.constants import (
    AuditEventType,
    CoverageState,
    DuplicateStatus,
    IntegrityStatus,
    ReconciliationStatus,
    TimestampStatus,
)
from app.database import get_db
from app.models import (
    EvidenceAuditEvent,
    EvidenceFile,
    EvidenceSource,
    Investigation,
    ParsedEvent,
    ParsingResult,
    ReconciliationRun,
    utcnow,
)
from app.routers.timeline import ORDERING_RULE
from app.schemas import (
    AuditPage,
    CoverageRead,
    DuplicateEventRead,
    DuplicateGroupRead,
    DuplicateQualityRead,
    EvidenceAuditEventRead,
    GapPage,
    IntegrityEvidenceRead,
    IntegrityQualityRead,
    ManifestItemRead,
    ManifestRead,
    ParsingQualityItemRead,
    ParsingQualityRead,
    ParsingResultRead,
    QualityOverviewInvestigationRead,
    QualityOverviewRead,
    ReconcileResponse,
    ReconciliationRunRead,
    TimestampEventRead,
    TimestampQualityRead,
)
from app.services.coverage import (
    build_investigation_coverage,
    default_coverage_window,
)
from app.services.quality import (
    build_manifest,
    reconcile_duplicates,
    record_audit,
)

router = APIRouter(prefix="/quality", tags=["quality"])

TIMESTAMP_RULE = (
    "Original timestamp strings are preserved verbatim. A UTC value is produced only "
    "when the record has an explicit offset or a supplied timezone hint, and the year "
    "is known. A configured source clock offset is applied only when supplied; measured "
    "clock offsets are recorded but never silently applied. Unresolved timestamps are "
    "retained and shown separately, never dropped."
)


def _aware(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"{name} must include a UTC offset or timezone "
                "(for example 2026-10-31T10:00:00Z)."
            ),
        )
    return value.astimezone(UTC)


def _require_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation:
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


def _coverage_window(
    settings: Settings,
    start: datetime | None,
    end: datetime | None,
) -> tuple[datetime, datetime, datetime]:
    now = utcnow()
    start_utc = _aware(start, "start")
    end_utc = _aware(end, "end")
    if start_utc is None or end_utc is None:
        default_start, default_end = default_coverage_window(settings, now)
        start_utc = start_utc or default_start
        end_utc = end_utc or default_end
    if start_utc > end_utc:
        raise HTTPException(status_code=422, detail="start must be before or equal to end.")
    return start_utc, end_utc, now


@router.get("/overview", response_model=QualityOverviewRead)
def quality_overview(
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> QualityOverviewRead:
    now = utcnow()
    window_start, window_end = default_coverage_window(settings, now)
    investigations = session.scalars(
        select(Investigation).order_by(Investigation.created_at.asc())
    ).all()
    items: list[QualityOverviewInvestigationRead] = []
    totals = Counter()
    for investigation in investigations:
        coverage = build_investigation_coverage(
            session,
            settings,
            investigation_id=investigation.id,
            window_start=window_start,
            window_end=window_end,
            now=now,
        )
        duplicate_events = int(
            session.scalar(
                select(func.count(ParsedEvent.id)).where(
                    ParsedEvent.investigation_id == investigation.id,
                    ParsedEvent.dedup_status == DuplicateStatus.DUPLICATE,
                )
            )
            or 0
        )
        total_events = int(
            session.scalar(
                select(func.count(ParsedEvent.id)).where(
                    ParsedEvent.investigation_id == investigation.id
                )
            )
            or 0
        )
        normalized = int(
            session.scalar(
                select(func.count(ParsedEvent.id)).where(
                    ParsedEvent.investigation_id == investigation.id,
                    ParsedEvent.timestamp_status == TimestampStatus.NORMALIZED,
                )
            )
            or 0
        )
        integrity_counts = {
            status: int(count)
            for status, count in session.execute(
                select(EvidenceFile.integrity_status, func.count(EvidenceFile.id))
                .where(EvidenceFile.investigation_id == investigation.id)
                .group_by(EvidenceFile.integrity_status)
            ).all()
        }
        audit_events = int(
            session.scalar(
                select(func.count(EvidenceAuditEvent.id)).where(
                    EvidenceAuditEvent.investigation_id == investigation.id
                )
            )
            or 0
        )
        summary = coverage.summary
        state_counts = {
            CoverageState.REPORTING: summary.reporting_sources,
            CoverageState.IDLE: summary.idle_sources,
            CoverageState.NOT_REPORTING: summary.not_reporting_sources,
            CoverageState.ERROR: summary.error_sources,
            CoverageState.DISABLED: summary.disabled_sources,
            CoverageState.UNKNOWN: summary.unknown_sources,
        }
        if state_counts[CoverageState.ERROR] or state_counts[CoverageState.NOT_REPORTING]:
            aggregate_state = (
                CoverageState.ERROR
                if state_counts[CoverageState.ERROR]
                else CoverageState.NOT_REPORTING
            )
        elif state_counts[CoverageState.REPORTING] or state_counts[CoverageState.IDLE]:
            aggregate_state = CoverageState.REPORTING
        elif state_counts[CoverageState.DISABLED] and not state_counts[CoverageState.UNKNOWN]:
            aggregate_state = CoverageState.DISABLED
        else:
            aggregate_state = CoverageState.UNKNOWN

        item = QualityOverviewInvestigationRead(
            investigation_id=investigation.id,
            name=investigation.name,
            source_count=int(
                session.scalar(
                    select(func.count(EvidenceSource.id)).where(
                        EvidenceSource.investigation_id == investigation.id
                    )
                )
                or 0
            ),
            registered_sources=summary.registered_sources,
            reporting_sources=summary.reporting_sources,
            idle_sources=summary.idle_sources,
            not_reporting_sources=summary.not_reporting_sources,
            error_sources=summary.error_sources,
            disabled_sources=summary.disabled_sources,
            unknown_sources=summary.unknown_sources,
            coverage_state=aggregate_state,
            open_gaps=summary.open_gaps,
            duplicate_events=duplicate_events,
            timestamp_uncertain_events=max(total_events - normalized, 0),
            integrity_mismatched=integrity_counts.get(IntegrityStatus.MISMATCH, 0),
            integrity_unverified=integrity_counts.get(IntegrityStatus.UNVERIFIED, 0),
            audit_events=audit_events,
        )
        items.append(item)
        totals["investigations"] += 1
        totals["sources"] += item.source_count
        totals["registered_sources"] += item.registered_sources
        totals["reporting_sources"] += item.reporting_sources
        totals["open_gaps"] += item.open_gaps
        totals["duplicate_events"] += item.duplicate_events
        totals["timestamp_uncertain_events"] += item.timestamp_uncertain_events
        totals["integrity_mismatched"] += item.integrity_mismatched
        totals["audit_events"] += item.audit_events
    return QualityOverviewRead(
        generated_at=now,
        investigations=items,
        totals=dict(totals),
        note=(
            "Investigation-level coverage aggregates reported agent cycles. "
            "Unknown/manual sources are not counted as healthy, and zero collected bytes "
            "does not imply zero activity."
        ),
    )


@router.get(
    "/investigations/{investigation_id}/coverage",
    response_model=CoverageRead,
)
def investigation_coverage(
    investigation_id: uuid.UUID,
    start: datetime | None = Query(None),
    end: datetime | None = Query(None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CoverageRead:
    _require_investigation(session, investigation_id)
    window_start, window_end, now = _coverage_window(settings, start, end)
    return build_investigation_coverage(
        session,
        settings,
        investigation_id=investigation_id,
        window_start=window_start,
        window_end=window_end,
        now=now,
    )


@router.get("/investigations/{investigation_id}/gaps", response_model=GapPage)
def investigation_gaps(
    investigation_id: uuid.UUID,
    start: datetime | None = Query(None),
    end: datetime | None = Query(None),
    include_closed: bool = Query(True),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> GapPage:
    _require_investigation(session, investigation_id)
    window_start, window_end, now = _coverage_window(settings, start, end)
    coverage = build_investigation_coverage(
        session,
        settings,
        investigation_id=investigation_id,
        window_start=window_start,
        window_end=window_end,
        now=now,
    )
    gaps = [
        gap
        for gap in coverage.gaps
        if include_closed or gap.status.value == "open"
    ]
    total = len(gaps)
    return GapPage(
        investigation_id=investigation_id,
        generated_at=now,
        items=gaps[offset : offset + limit],
        total=total,
    )


@router.get(
    "/investigations/{investigation_id}/parsing",
    response_model=ParsingQualityRead,
)
def investigation_parsing(
    investigation_id: uuid.UUID,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> ParsingQualityRead:
    _require_investigation(session, investigation_id)
    rows = session.execute(
        select(EvidenceFile, EvidenceSource, ParsingResult)
        .join(EvidenceSource, EvidenceSource.id == EvidenceFile.source_id)
        .outerjoin(ParsingResult, ParsingResult.evidence_file_id == EvidenceFile.id)
        .where(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.received_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    items = [
        ParsingQualityItemRead(
            evidence_id=evidence.id,
            filename=evidence.original_filename,
            source_id=source.id,
            source_name=source.name,
            received_at=evidence.received_at,
            clock_offset_seconds=evidence.clock_offset_seconds,
            parsing_result=(
                ParsingResultRead.model_validate(result) if result is not None else None
            ),
        )
        for evidence, source, result in rows
    ]
    results = session.scalars(
        select(ParsingResult)
        .join(EvidenceFile, EvidenceFile.id == ParsingResult.evidence_file_id)
        .where(EvidenceFile.investigation_id == investigation_id)
    ).all()
    totals = {
        "evidence_files": len(results),
        "records_received": sum(item.records_received for item in results),
        "parsed_records": sum(item.parsed_records for item in results),
        "records_rejected": sum(item.records_rejected for item in results),
        "malformed_records": sum(item.malformed_records for item in results),
        "unsupported_records": sum(item.unsupported_records for item in results),
        "unsupported_formats": sum(item.unsupported_formats for item in results),
        "missing_required_fields": sum(item.missing_required_fields for item in results),
        "missing_optional_fields": sum(item.missing_optional_fields for item in results),
        "parser_errors": sum(item.parser_errors for item in results),
        "duplicate_records": sum(item.duplicate_records for item in results),
        "timestamp_flagged_records": sum(item.timestamp_flagged_records for item in results),
        "ordering_tied_records": sum(item.ordering_tied_records for item in results),
        "ordering_unresolved_records": sum(
            item.ordering_unresolved_records for item in results
        ),
        "issues_recorded": sum(item.issues_recorded for item in results),
        "issues_suppressed": sum(item.issues_suppressed for item in results),
    }
    evidence_without_parser = int(
        session.scalar(
            select(func.count(EvidenceFile.id))
            .outerjoin(ParsingResult, ParsingResult.evidence_file_id == EvidenceFile.id)
            .where(
                EvidenceFile.investigation_id == investigation_id,
                ParsingResult.id.is_(None),
            )
        )
        or 0
    )
    evidence_with_issues = sum(
        1
        for item in results
        if item.records_rejected
        or item.issues_recorded
        or item.parser_errors
        or item.ordering_tied_records
        or item.ordering_unresolved_records
    )
    return ParsingQualityRead(
        investigation_id=investigation_id,
        generated_at=utcnow(),
        items=items,
        totals=totals,
        evidence_with_issues=evidence_with_issues,
        evidence_without_parser=evidence_without_parser,
    )


@router.get(
    "/investigations/{investigation_id}/timestamps",
    response_model=TimestampQualityRead,
)
def investigation_timestamps(
    investigation_id: uuid.UUID,
    sample_limit: int = Query(50, ge=0, le=500),
    session: Session = Depends(get_db),
) -> TimestampQualityRead:
    _require_investigation(session, investigation_id)
    status_counts = {
        getattr(status, "value", status): int(count)
        for status, count in session.execute(
            select(ParsedEvent.timestamp_status, func.count(ParsedEvent.id))
            .where(ParsedEvent.investigation_id == investigation_id)
            .group_by(ParsedEvent.timestamp_status)
        ).all()
    }
    ordering_counts = {
        getattr(status, "value", status): int(count)
        for status, count in session.execute(
            select(ParsedEvent.ordering_status, func.count(ParsedEvent.id))
            .where(ParsedEvent.investigation_id == investigation_id)
            .group_by(ParsedEvent.ordering_status)
        ).all()
    }
    total_events = sum(status_counts.values())
    normalized = status_counts.get(TimestampStatus.NORMALIZED.value, 0)
    clock_offset_events = int(
        session.scalar(
            select(func.count(ParsedEvent.id)).where(
                ParsedEvent.investigation_id == investigation_id,
                ParsedEvent.clock_offset_seconds.is_not(None),
            )
        )
        or 0
    )
    samples: list[TimestampEventRead] = []
    if sample_limit:
        rows = session.execute(
            select(ParsedEvent, EvidenceFile, EvidenceSource)
            .join(EvidenceFile, EvidenceFile.id == ParsedEvent.evidence_file_id)
            .join(EvidenceSource, EvidenceSource.id == ParsedEvent.source_id)
            .where(
                ParsedEvent.investigation_id == investigation_id,
                ParsedEvent.timestamp_status != TimestampStatus.NORMALIZED,
            )
            .order_by(ParsedEvent.id.desc())
            .limit(sample_limit)
        ).all()
        samples = [
            TimestampEventRead(
                event_id=event.id,
                evidence_id=evidence.id,
                evidence_filename=evidence.original_filename,
                line_number=event.line_number,
                source_name=source.name,
                event_type=event.event_type,
                timestamp_utc=event.timestamp_utc,
                original_timestamp_string=event.original_timestamp_string,
                timestamp_status=event.timestamp_status,
                timestamp_detail=event.timestamp_detail,
                timestamp_precision=event.timestamp_precision,
                clock_offset_seconds=event.clock_offset_seconds,
                clock_offset_applied=event.clock_offset_applied,
                ordering_status=event.ordering_status,
            )
            for event, evidence, source in rows
        ]
    return TimestampQualityRead(
        investigation_id=investigation_id,
        generated_at=utcnow(),
        total_events=total_events,
        normalized_events=normalized,
        uncertain_events=max(total_events - normalized, 0),
        timestamp_status_counts=status_counts,
        ordering_status_counts=ordering_counts,
        timestamp_rule=TIMESTAMP_RULE,
        ordering_rule=ORDERING_RULE,
        clock_offset_events=clock_offset_events,
        uncertain_samples=samples,
    )


@router.get(
    "/investigations/{investigation_id}/integrity",
    response_model=IntegrityQualityRead,
)
def investigation_integrity(
    investigation_id: uuid.UUID,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IntegrityQualityRead:
    _require_investigation(session, investigation_id)
    evidence_files = session.scalars(
        select(EvidenceFile)
        .where(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.received_at.desc())
    ).all()
    counts = {
        status: int(count)
        for status, count in session.execute(
            select(EvidenceFile.integrity_status, func.count(EvidenceFile.id))
            .where(EvidenceFile.investigation_id == investigation_id)
            .group_by(EvidenceFile.integrity_status)
        ).all()
    }
    status_counts = {status.value: counts.get(status, 0) for status in IntegrityStatus}
    items = [
        IntegrityEvidenceRead(
            evidence_id=evidence.id,
            filename=evidence.original_filename,
            sha256=evidence.sha256,
            size_bytes=evidence.size_bytes,
            integrity_status=evidence.integrity_status,
            verification_count=evidence.verification_count,
            last_verified_at=evidence.last_verified_at,
            last_verification_source=evidence.last_verification_source,
            download_url=f"{settings.api_prefix}/evidence/{evidence.id}/download",
            verify_url=f"{settings.api_prefix}/evidence/{evidence.id}/verify",
            manifest_url=f"{settings.api_prefix}/evidence/{evidence.id}/manifest",
            verifications_url=f"{settings.api_prefix}/evidence/{evidence.id}/verifications",
            audit_url=f"{settings.api_prefix}/quality/evidence/{evidence.id}/audit",
        )
        for evidence in evidence_files
    ]
    return IntegrityQualityRead(
        investigation_id=investigation_id,
        generated_at=utcnow(),
        integrity_status_counts=status_counts,
        evidence_count=len(evidence_files),
        verified_evidence=status_counts[IntegrityStatus.VERIFIED.value],
        unverified_evidence=status_counts[IntegrityStatus.UNVERIFIED.value],
        mismatched_evidence=status_counts[IntegrityStatus.MISMATCH.value],
        missing_evidence=status_counts[IntegrityStatus.MISSING.value],
        items=items,
        note=(
            "Verification checks that stored bytes are consistent with the hash recorded "
            "at preservation time. It does not independently prove that the bytes were "
            "authentic before collection."
        ),
    )


def _duplicate_event_read(
    event: ParsedEvent, evidence: EvidenceFile, source: EvidenceSource
) -> DuplicateEventRead:
    return DuplicateEventRead(
        event_id=event.id,
        evidence_id=evidence.id,
        evidence_filename=evidence.original_filename,
        line_number=event.line_number,
        source_id=source.id,
        source_name=source.name,
        event_type=event.event_type,
        timestamp_utc=event.timestamp_utc,
        timestamp_status=event.timestamp_status,
        dedup_status=event.dedup_status,
        duplicate_of_event_id=event.duplicate_of_event_id,
    )


@router.get(
    "/investigations/{investigation_id}/duplicates",
    response_model=DuplicateQualityRead,
)
def investigation_duplicates(
    investigation_id: uuid.UUID,
    group_limit: int = Query(200, ge=0, le=1000),
    session: Session = Depends(get_db),
) -> DuplicateQualityRead:
    _require_investigation(session, investigation_id)
    total_events = int(
        session.scalar(
            select(func.count(ParsedEvent.id)).where(
                ParsedEvent.investigation_id == investigation_id
            )
        )
        or 0
    )
    duplicate_events = int(
        session.scalar(
            select(func.count(ParsedEvent.id)).where(
                ParsedEvent.investigation_id == investigation_id,
                ParsedEvent.dedup_status == DuplicateStatus.DUPLICATE,
            )
        )
        or 0
    )
    duplicate_group_count = int(
        session.scalar(
            select(func.count())
            .select_from(
                select(ParsedEvent.fingerprint_sha256)
                .where(
                    ParsedEvent.investigation_id == investigation_id,
                    ParsedEvent.fingerprint_sha256.is_not(None),
                )
                .group_by(ParsedEvent.fingerprint_sha256)
                .having(func.count(ParsedEvent.id) > 1)
                .subquery()
            )
        )
        or 0
    )
    group_rows = session.execute(
        select(ParsedEvent.fingerprint_sha256, func.count(ParsedEvent.id))
        .where(
            ParsedEvent.investigation_id == investigation_id,
            ParsedEvent.fingerprint_sha256.is_not(None),
        )
        .group_by(ParsedEvent.fingerprint_sha256)
        .having(func.count(ParsedEvent.id) > 1)
        .order_by(func.count(ParsedEvent.id).desc())
        .limit(group_limit)
    ).all()
    groups: list[DuplicateGroupRead] = []
    for fingerprint, count in group_rows:
        rows = session.execute(
            select(ParsedEvent, EvidenceFile, EvidenceSource)
            .join(EvidenceFile, EvidenceFile.id == ParsedEvent.evidence_file_id)
            .join(EvidenceSource, EvidenceSource.id == ParsedEvent.source_id)
            .where(
                ParsedEvent.investigation_id == investigation_id,
                ParsedEvent.fingerprint_sha256 == fingerprint,
            )
            .order_by(ParsedEvent.id.asc())
        ).all()
        if not rows:
            continue
        canonical_event, canonical_evidence, canonical_source = rows[0]
        groups.append(
            DuplicateGroupRead(
                fingerprint_sha256=fingerprint,
                event_count=int(count),
                canonical_event=_duplicate_event_read(
                    canonical_event, canonical_evidence, canonical_source
                ),
                duplicate_events=[
                    _duplicate_event_read(event, evidence, source)
                    for event, evidence, source in rows[1:]
                ],
            )
        )
    last_run = session.scalar(
        select(ReconciliationRun)
        .where(ReconciliationRun.investigation_id == investigation_id)
        .order_by(ReconciliationRun.started_at.desc())
        .limit(1)
    )
    return DuplicateQualityRead(
        investigation_id=investigation_id,
        generated_at=utcnow(),
        total_events=total_events,
        unique_events=total_events - duplicate_events,
        duplicate_events=duplicate_events,
        duplicate_groups=duplicate_group_count,
        groups=groups,
        last_reconciliation=(
            ReconciliationRunRead.model_validate(last_run) if last_run else None
        ),
        note=(
            "Fingerprints include source, event type, normalized timestamp, original "
            "timestamp and a hash of the raw line. Duplicate rows are linked and flagged; "
            "they are never deleted. Identical legitimate lines may need analyst review."
        ),
    )


@router.post(
    "/investigations/{investigation_id}/reconcile",
    response_model=ReconcileResponse,
)
def reconcile_investigation_duplicates(
    investigation_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
) -> ReconcileResponse:
    _require_investigation(session, investigation_id)
    actor = request.client.host if request.client else None
    run = ReconciliationRun(
        investigation_id=investigation_id,
        status=ReconciliationStatus.COMPLETED,
        scope="investigation",
        actor_type="api",
        actor_detail=actor,
        started_at=utcnow(),
    )
    session.add(run)
    session.flush()
    events_scanned, duplicate_events, duplicate_groups = reconcile_duplicates(
        session, investigation_id
    )
    total_events = int(
        session.scalar(
            select(func.count(ParsedEvent.id)).where(
                ParsedEvent.investigation_id == investigation_id
            )
        )
        or 0
    )
    run.events_scanned = events_scanned
    run.duplicate_events = duplicate_events
    run.duplicate_groups = duplicate_groups
    run.completed_at = utcnow()
    record_audit(
        session,
        investigation_id=investigation_id,
        event_type=AuditEventType.DUPLICATES_RECONCILED,
        actor_type="api",
        actor_detail=actor,
        request_id=request.headers.get("x-request-id"),
        detail={
            "run_id": str(run.id),
            "events_scanned": events_scanned,
            "duplicate_events": duplicate_events,
            "duplicate_groups": duplicate_groups,
        },
    )
    session.commit()
    session.refresh(run)
    return ReconcileResponse(
        run=ReconciliationRunRead.model_validate(run),
        total_events=total_events,
        unique_events=total_events - duplicate_events,
        duplicate_events=duplicate_events,
        duplicate_groups=duplicate_groups,
    )


def _audit_page(
    session: Session,
    *,
    investigation_id: uuid.UUID | None = None,
    evidence_id: uuid.UUID | None = None,
    event_type: str | None = None,
    actor_type: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> AuditPage:
    conditions = []
    if investigation_id is not None:
        conditions.append(EvidenceAuditEvent.investigation_id == investigation_id)
    if evidence_id is not None:
        conditions.append(EvidenceAuditEvent.evidence_file_id == evidence_id)
    if event_type:
        conditions.append(EvidenceAuditEvent.event_type == event_type)
    if actor_type:
        conditions.append(EvidenceAuditEvent.actor_type == actor_type)
    if start is not None:
        conditions.append(EvidenceAuditEvent.occurred_at >= start)
    if end is not None:
        conditions.append(EvidenceAuditEvent.occurred_at <= end)
    total = int(
        session.scalar(
            select(func.count(EvidenceAuditEvent.id)).where(*conditions)
        )
        or 0
    )
    events = session.scalars(
        select(EvidenceAuditEvent)
        .where(*conditions)
        .order_by(EvidenceAuditEvent.occurred_at.desc(), EvidenceAuditEvent.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditPage(
        items=[EvidenceAuditEventRead.model_validate(event) for event in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/investigations/{investigation_id}/audit",
    response_model=AuditPage,
)
def investigation_audit(
    investigation_id: uuid.UUID,
    event_type: str | None = Query(None, max_length=64),
    actor_type: str | None = Query(None, max_length=16),
    start: datetime | None = Query(None),
    end: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> AuditPage:
    _require_investigation(session, investigation_id)
    return _audit_page(
        session,
        investigation_id=investigation_id,
        event_type=event_type,
        actor_type=actor_type,
        start=_aware(start, "start"),
        end=_aware(end, "end"),
        limit=limit,
        offset=offset,
    )


@router.get("/evidence/{evidence_id}/audit", response_model=AuditPage)
def evidence_audit(
    evidence_id: uuid.UUID,
    event_type: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> AuditPage:
    if session.get(EvidenceFile, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    return _audit_page(
        session,
        evidence_id=evidence_id,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/investigations/{investigation_id}/manifest",
    response_model=ManifestRead,
)
def investigation_manifest(
    investigation_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
) -> ManifestRead:
    _require_investigation(session, investigation_id)
    evidence_files = session.scalars(
        select(EvidenceFile)
        .where(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.received_at.asc(), EvidenceFile.id.asc())
    ).all()
    body, digest = build_manifest(
        list(evidence_files),
        scope="investigation",
        investigation_id=investigation_id,
    )
    record_audit(
        session,
        investigation_id=investigation_id,
        event_type=AuditEventType.MANIFEST_EXPORTED,
        actor_type="api",
        actor_detail=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail={"scope": "investigation", "manifest_sha256": digest},
    )
    session.commit()
    return ManifestRead(
        scope=body["scope"],
        investigation_id=investigation_id,
        generated_at=utcnow(),
        manifest_sha256=digest,
        item_count=body["item_count"],
        items=[ManifestItemRead(**item) for item in body["items"]],
        note=(
            "The manifest hash covers the canonical scope/investigation/items body. "
            "It records hashes and verification state; it does not prove pre-collection "
            "authenticity."
        ),
    )
