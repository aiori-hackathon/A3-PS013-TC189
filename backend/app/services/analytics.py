"""Aggregate investigation telemetry for the dashboard and status endpoint."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.constants import TimestampStatus
from app.models import (
    EvidenceFile,
    EvidenceHash,
    EvidenceSource,
    ParsedEvent,
    ParsingIssue,
    ParsingResult,
)
from app.schemas import InvestigationSummaryRead


def _count(session: Session, stmt) -> int:
    return int(session.scalar(stmt) or 0)


def _group_counts(session: Session, key_column, statement) -> dict[str, int]:
    rows = session.execute(statement).all()
    result: dict[str, int] = {}
    for key, count in rows:
        result[str(getattr(key, "value", key))] = int(count)
    return result


def build_summary(session: Session, investigation_id: uuid.UUID) -> InvestigationSummaryRead:
    source_count = _count(
        session,
        select(func.count(EvidenceSource.id)).where(
            EvidenceSource.investigation_id == investigation_id
        ),
    )
    evidence_count = _count(
        session,
        select(func.count(EvidenceFile.id)).where(
            EvidenceFile.investigation_id == investigation_id
        ),
    )
    event_count = _count(
        session,
        select(func.count(ParsedEvent.id)).where(
            ParsedEvent.investigation_id == investigation_id
        ),
    )
    earliest_collected_at, latest_collected_at = session.execute(
        select(
            func.min(EvidenceFile.collected_at),
            func.max(EvidenceFile.collected_at),
        ).where(EvidenceFile.investigation_id == investigation_id)
    ).one()

    parsing_totals = session.execute(
        select(
            func.coalesce(func.sum(ParsingResult.total_lines), 0),
            func.coalesce(func.sum(ParsingResult.parsed_records), 0),
            func.coalesce(func.sum(ParsingResult.malformed_records), 0),
            func.coalesce(func.sum(ParsingResult.unsupported_records), 0),
            func.coalesce(func.sum(ParsingResult.blank_lines), 0),
            func.coalesce(func.sum(ParsingResult.timestamp_flagged_records), 0),
        )
        .join(EvidenceFile, ParsingResult.evidence_file_id == EvidenceFile.id)
        .where(EvidenceFile.investigation_id == investigation_id)
    ).one()

    events_by_source_type = _group_counts(
        session,
        EvidenceSource.source_type,
        select(EvidenceSource.source_type, func.count(ParsedEvent.id))
        .join(ParsedEvent, ParsedEvent.source_id == EvidenceSource.id)
        .where(ParsedEvent.investigation_id == investigation_id)
        .group_by(EvidenceSource.source_type),
    )
    events_by_event_type = _group_counts(
        session,
        ParsedEvent.event_type,
        select(ParsedEvent.event_type, func.count(ParsedEvent.id))
        .where(ParsedEvent.investigation_id == investigation_id)
        .group_by(ParsedEvent.event_type),
    )
    timestamp_status_counts = _group_counts(
        session,
        ParsedEvent.timestamp_status,
        select(ParsedEvent.timestamp_status, func.count(ParsedEvent.id))
        .where(ParsedEvent.investigation_id == investigation_id)
        .group_by(ParsedEvent.timestamp_status),
    )
    evidence_status_counts = _group_counts(
        session,
        EvidenceFile.status,
        select(EvidenceFile.status, func.count(EvidenceFile.id))
        .where(EvidenceFile.investigation_id == investigation_id)
        .group_by(EvidenceFile.status),
    )
    parsing_status_counts = _group_counts(
        session,
        ParsingResult.status,
        select(ParsingResult.status, func.count(ParsingResult.id))
        .join(EvidenceFile, ParsingResult.evidence_file_id == EvidenceFile.id)
        .where(EvidenceFile.investigation_id == investigation_id)
        .group_by(ParsingResult.status),
    )
    issue_counts_by_type = _group_counts(
        session,
        ParsingIssue.issue_type,
        select(ParsingIssue.issue_type, func.count(ParsingIssue.id))
        .join(EvidenceFile, ParsingIssue.evidence_file_id == EvidenceFile.id)
        .where(EvidenceFile.investigation_id == investigation_id)
        .group_by(ParsingIssue.issue_type),
    )

    verified = _count(
        session,
        select(func.count(EvidenceHash.id))
        .join(EvidenceFile, EvidenceHash.evidence_file_id == EvidenceFile.id)
        .where(
            EvidenceFile.investigation_id == investigation_id,
            EvidenceHash.verified.is_(True),
        ),
    )
    mismatched = _count(
        session,
        select(func.count(EvidenceHash.id))
        .join(EvidenceFile, EvidenceHash.evidence_file_id == EvidenceFile.id)
        .where(
            EvidenceFile.investigation_id == investigation_id,
            EvidenceHash.verified.is_(False),
        ),
    )
    unverified = _count(
        session,
        select(func.count(EvidenceHash.id))
        .join(EvidenceFile, EvidenceHash.evidence_file_id == EvidenceFile.id)
        .where(
            EvidenceFile.investigation_id == investigation_id,
            EvidenceHash.verified.is_(None),
        ),
    )

    return InvestigationSummaryRead(
        investigation_id=investigation_id,
        sources=source_count,
        evidence_files=evidence_count,
        events=event_count,
        earliest_collected_at=earliest_collected_at,
        latest_collected_at=latest_collected_at,
        total_lines=int(parsing_totals[0]),
        parsed_records=int(parsing_totals[1]),
        malformed_records=int(parsing_totals[2]),
        unsupported_records=int(parsing_totals[3]),
        blank_lines=int(parsing_totals[4]),
        timestamp_flagged_records=int(parsing_totals[5]),
        events_by_source_type=events_by_source_type,
        events_by_event_type=events_by_event_type,
        timestamp_status_counts=timestamp_status_counts,
        evidence_status_counts=evidence_status_counts,
        parsing_status_counts=parsing_status_counts,
        issue_counts_by_type=issue_counts_by_type,
        issues_total=sum(issue_counts_by_type.values()),
        hashes_verified=verified,
        hashes_mismatched=mismatched,
        hashes_unverified=unverified,
    )


def timestamp_uncertain_count(summary: InvestigationSummaryRead) -> int:
    return sum(
        count
        for status, count in summary.timestamp_status_counts.items()
        if status != TimestampStatus.NORMALIZED.value
    )
