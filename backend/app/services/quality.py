"""Evidence quality helpers: audit, ordering, deduplication and manifests."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.constants import (
    AuditEventType,
    DuplicateStatus,
    OrderingStatus,
    ParsingStatus,
)
from app.models import (
    EvidenceAuditEvent,
    EvidenceFile,
    ParsedEvent,
    ParsingResult,
    utcnow,
)

ORDERING_NOTE_TIED = (
    "Another event shares this exact UTC timestamp. The API orders ties by evidence "
    "receipt time, evidence id and line number; this is deterministic, not proof of "
    "real-world order."
)
ORDERING_NOTE_UNRESOLVED = (
    "No UTC timestamp is available. The API places the event using evidence receipt "
    "time, evidence id and line number only."
)


def event_fingerprint(
    *,
    source_id: Any,
    event_category: Any,
    event_type: str,
    timestamp_utc: datetime | None,
    original_timestamp_string: str | None,
    line_sha256: str,
) -> str:
    """A source-aware content fingerprint for non-destructive deduplication.

    The raw line hash is included, so two genuinely identical lines in the same
    source and at the same resolved time are flagged for review. Nothing is ever
    deleted; only a duplicate link and status are recorded.
    """

    category = getattr(event_category, "value", event_category)
    payload = "|".join(
        [
            str(source_id),
            str(category),
            str(event_type),
            timestamp_utc.isoformat() if timestamp_utc else "",
            original_timestamp_string or "",
            line_sha256,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_audit(
    session: Session,
    *,
    investigation_id: Any,
    event_type: AuditEventType | str,
    evidence: EvidenceFile | None = None,
    actor_type: str = "api",
    actor_detail: str | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> EvidenceAuditEvent:
    event = EvidenceAuditEvent(
        investigation_id=investigation_id,
        evidence_file_id=evidence.id if evidence else None,
        event_type=event_type.value if isinstance(event_type, AuditEventType) else event_type,
        actor_type=actor_type,
        actor_detail=actor_detail,
        request_id=request_id,
        evidence_filename=evidence.original_filename if evidence else None,
        evidence_sha256=evidence.sha256 if evidence else None,
        detail=detail or {},
        occurred_at=occurred_at or utcnow(),
    )
    session.add(event)
    return event


def mark_ordering(session: Session, investigation_id: Any) -> tuple[int, int]:
    """Set conservative ordering status for every event in an investigation.

    Returns ``(tied_count, unresolved_count)``. The operation is idempotent and
    can be re-run after new evidence arrives.
    """

    rows = session.execute(
        select(ParsedEvent.id, ParsedEvent.timestamp_utc).where(
            ParsedEvent.investigation_id == investigation_id
        )
    ).all()
    timestamp_counts = Counter(ts for _id, ts in rows if ts is not None)

    ordered_ids: list[int] = []
    tied_ids: list[int] = []
    unresolved_ids: list[int] = []
    for event_id, timestamp in rows:
        if timestamp is None:
            unresolved_ids.append(event_id)
        elif timestamp_counts[timestamp] > 1:
            tied_ids.append(event_id)
        else:
            ordered_ids.append(event_id)

    if unresolved_ids:
        session.execute(
            update(ParsedEvent)
            .where(ParsedEvent.id.in_(unresolved_ids))
            .values(
                ordering_status=OrderingStatus.UNRESOLVED,
                ordering_note=ORDERING_NOTE_UNRESOLVED,
            )
        )
    if tied_ids:
        session.execute(
            update(ParsedEvent)
            .where(ParsedEvent.id.in_(tied_ids))
            .values(ordering_status=OrderingStatus.TIED, ordering_note=ORDERING_NOTE_TIED)
        )
    if ordered_ids:
        session.execute(
            update(ParsedEvent)
            .where(ParsedEvent.id.in_(ordered_ids))
            .values(ordering_status=OrderingStatus.ORDERED, ordering_note=None)
        )
    return len(tied_ids), len(unresolved_ids)


def refresh_parsing_ordering_counts(session: Session, investigation_id: Any) -> None:
    """Refresh stored tied/unresolved counters for all parsing results in scope."""

    counts_by_evidence = {
        (evidence_id, status): count
        for evidence_id, status, count in session.execute(
            select(
                ParsedEvent.evidence_file_id,
                ParsedEvent.ordering_status,
                func.count(ParsedEvent.id),
            )
            .where(ParsedEvent.investigation_id == investigation_id)
            .group_by(ParsedEvent.evidence_file_id, ParsedEvent.ordering_status)
        ).all()
    }
    results = session.scalars(
        select(ParsingResult)
        .join(EvidenceFile, EvidenceFile.id == ParsingResult.evidence_file_id)
        .where(EvidenceFile.investigation_id == investigation_id)
    ).all()
    for result in results:
        result.ordering_tied_records = counts_by_evidence.get(
            (result.evidence_file_id, OrderingStatus.TIED), 0
        )
        result.ordering_unresolved_records = counts_by_evidence.get(
            (result.evidence_file_id, OrderingStatus.UNRESOLVED), 0
        )


def reconcile_duplicates(
    session: Session, investigation_id: Any, *, scope: str = "investigation"
) -> tuple[int, int, int]:
    """Recompute duplicate links across an investigation without deleting events.

    Returns ``(events_scanned, duplicate_events, duplicate_groups)``.
    """

    events_scanned = session.scalar(
        select(func.count(ParsedEvent.id)).where(
            ParsedEvent.investigation_id == investigation_id
        )
    ) or 0

    session.execute(
        update(ParsedEvent)
        .where(
            ParsedEvent.investigation_id == investigation_id,
            ParsedEvent.dedup_status != DuplicateStatus.UNIQUE,
        )
        .values(dedup_status=DuplicateStatus.UNIQUE, duplicate_of_event_id=None)
    )

    groups = session.execute(
        select(
            ParsedEvent.fingerprint_sha256,
            func.min(ParsedEvent.id),
        )
        .where(
            ParsedEvent.investigation_id == investigation_id,
            ParsedEvent.fingerprint_sha256.is_not(None),
        )
        .group_by(ParsedEvent.fingerprint_sha256)
        .having(func.count(ParsedEvent.id) > 1)
    ).all()

    duplicate_events = 0
    for fingerprint, canonical_id in groups:
        duplicate_ids = session.scalars(
            select(ParsedEvent.id).where(
                ParsedEvent.investigation_id == investigation_id,
                ParsedEvent.fingerprint_sha256 == fingerprint,
                ParsedEvent.id != canonical_id,
            )
        ).all()
        if not duplicate_ids:
            continue
        session.execute(
            update(ParsedEvent)
            .where(ParsedEvent.id.in_(duplicate_ids))
            .values(
                dedup_status=DuplicateStatus.DUPLICATE,
                duplicate_of_event_id=canonical_id,
            )
        )
        duplicate_events += len(duplicate_ids)

    refresh_parsing_duplicate_counts(session, investigation_id)
    return events_scanned, duplicate_events, len(groups)


def refresh_parsing_duplicate_counts(session: Session, investigation_id: Any) -> None:
    counts_by_evidence = dict(
        session.execute(
            select(ParsedEvent.evidence_file_id, func.count(ParsedEvent.id))
            .where(
                ParsedEvent.investigation_id == investigation_id,
                ParsedEvent.dedup_status == DuplicateStatus.DUPLICATE,
            )
            .group_by(ParsedEvent.evidence_file_id)
        ).all()
    )
    results = session.scalars(
        select(ParsingResult)
        .join(EvidenceFile, EvidenceFile.id == ParsingResult.evidence_file_id)
        .where(EvidenceFile.investigation_id == investigation_id)
    ).all()
    for result in results:
        result.duplicate_records = counts_by_evidence.get(result.evidence_file_id, 0)


def evidence_manifest_item(evidence: EvidenceFile, *, verified_source: str | None = None) -> dict:
    return {
        "evidence_id": str(evidence.id),
        "filename": evidence.original_filename,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "stored_relative_path": evidence.stored_relative_path,
        "source_id": str(evidence.source_id),
        "source_type": evidence.source_type.value,
        "collected_at": evidence.collected_at.isoformat() if evidence.collected_at else None,
        "received_at": evidence.received_at.isoformat() if evidence.received_at else None,
        "integrity_status": evidence.integrity_status.value,
        "verification_count": evidence.verification_count,
        "last_verified_at": (
            evidence.last_verified_at.isoformat() if evidence.last_verified_at else None
        ),
        "last_verification_source": verified_source or evidence.last_verification_source,
        "duplicate_of_evidence_id": (
            str(evidence.duplicate_of_evidence_id)
            if evidence.duplicate_of_evidence_id
            else None
        ),
    }


def build_manifest(
    evidence_items: list[EvidenceFile],
    *,
    scope: str,
    investigation_id: Any,
) -> tuple[dict[str, Any], str]:
    items = [evidence_manifest_item(item) for item in evidence_items]
    body = {
        "scope": scope,
        "investigation_id": str(investigation_id) if investigation_id else None,
        "item_count": len(items),
        "items": items,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return body, digest


def parsing_quality(result: ParsingResult) -> dict[str, Any]:
    return {
        "status": result.status.value if isinstance(result.status, ParsingStatus) else result.status,
        "records_received": result.records_received,
        "records_parsed": result.parsed_records,
        "records_rejected": result.records_rejected,
        "malformed_records": result.malformed_records,
        "unsupported_records": result.unsupported_records,
        "unsupported_formats": result.unsupported_formats,
        "missing_required_fields": result.missing_required_fields,
        "missing_optional_fields": result.missing_optional_fields,
        "parser_errors": result.parser_errors,
        "duplicate_records": result.duplicate_records,
        "timestamp_flagged_records": result.timestamp_flagged_records,
        "ordering_tied_records": result.ordering_tied_records,
        "ordering_unresolved_records": result.ordering_unresolved_records,
        "encoding_error_lines": result.encoding_error_lines,
        "issues_recorded": result.issues_recorded,
        "issues_suppressed": result.issues_suppressed,
    }
