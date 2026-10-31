"""Unified searchable timeline endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.constants import (
    DuplicateStatus,
    EventType,
    OrderingStatus,
    SourceType,
    TimestampStatus,
)
from app.database import get_db
from app.models import EvidenceFile, EvidenceSource, Investigation, ParsedEvent
from app.schemas import TimelineEventRead, TimelinePage
from app.serializers import timeline_event_read

router = APIRouter(tags=["timeline"])

ORDERING_RULE = (
    "Events are ordered by normalized UTC time (NULLS LAST). Ties are broken "
    "deterministically by evidence received_at, evidence id, line number and event id. "
    "A tie does not establish real-world order; unresolved timestamps are placed at the end."
)


def _require_aware(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=f"{name} must include a UTC offset or timezone (for example 2026-10-31T10:00:00Z).",
        )
    return value.astimezone(UTC)


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/timeline", response_model=TimelinePage)
def get_timeline(
    investigation_id: uuid.UUID = Query(...),
    start: datetime | None = Query(None),
    end: datetime | None = Query(None),
    source_type: SourceType | None = Query(None),
    event_type: EventType | None = Query(None),
    source_id: uuid.UUID | None = Query(None),
    evidence_id: uuid.UUID | None = Query(None),
    hostname: str | None = Query(None, max_length=255),
    username: str | None = Query(None, max_length=255),
    source_ip: str | None = Query(None, max_length=64),
    http_status: int | None = Query(None),
    timestamp_status: TimestampStatus | None = Query(None),
    ordering_status: OrderingStatus | None = Query(None),
    dedup_status: DuplicateStatus | None = Query(None),
    include_duplicates: bool = Query(True),
    q: str | None = Query(None, max_length=500),
    include_unknown_time: bool = Query(True),
    sort: Literal["asc", "desc"] = Query("asc"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TimelinePage:
    if session.get(Investigation, investigation_id) is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    start_utc = _require_aware(start, "start")
    end_utc = _require_aware(end, "end")
    if start_utc and end_utc and start_utc > end_utc:
        raise HTTPException(status_code=422, detail="start must be before or equal to end.")

    conditions = [ParsedEvent.investigation_id == investigation_id]
    if start_utc is not None:
        conditions.append(ParsedEvent.timestamp_utc >= start_utc)
    if end_utc is not None:
        conditions.append(ParsedEvent.timestamp_utc <= end_utc)
    if source_type is not None:
        conditions.append(EvidenceSource.source_type == source_type)
    if event_type is not None:
        conditions.append(ParsedEvent.event_type == event_type.value)
    if source_id is not None:
        conditions.append(ParsedEvent.source_id == source_id)
    if evidence_id is not None:
        conditions.append(ParsedEvent.evidence_file_id == evidence_id)
    if hostname:
        conditions.append(func.lower(ParsedEvent.hostname) == hostname.strip().lower())
    if username:
        conditions.append(func.lower(ParsedEvent.username) == username.strip().lower())
    if source_ip:
        conditions.append(ParsedEvent.source_ip == source_ip.strip())
    if http_status is not None:
        conditions.append(ParsedEvent.http_status == http_status)
    if timestamp_status is not None:
        conditions.append(ParsedEvent.timestamp_status == timestamp_status)
    if ordering_status is not None:
        conditions.append(ParsedEvent.ordering_status == ordering_status)
    if dedup_status is not None:
        conditions.append(ParsedEvent.dedup_status == dedup_status)
    if not include_duplicates:
        conditions.append(ParsedEvent.dedup_status != DuplicateStatus.DUPLICATE)
    if not include_unknown_time:
        conditions.append(ParsedEvent.timestamp_utc.is_not(None))
    if q and q.strip():
        pattern = f"%{_escape_like(q.strip())}%"
        conditions.append(
            ParsedEvent.message.ilike(pattern, escape="\\")
            | ParsedEvent.raw_line.ilike(pattern, escape="\\")
            | ParsedEvent.username.ilike(pattern, escape="\\")
            | ParsedEvent.source_ip.ilike(pattern, escape="\\")
            | ParsedEvent.hostname.ilike(pattern, escape="\\")
            | ParsedEvent.http_path.ilike(pattern, escape="\\")
            | ParsedEvent.http_user_agent.ilike(pattern, escape="\\")
            | ParsedEvent.process.ilike(pattern, escape="\\")
        )

    count_stmt = (
        select(func.count(ParsedEvent.id))
        .join(EvidenceSource, ParsedEvent.source_id == EvidenceSource.id)
        .where(*conditions)
    )
    total = int(session.scalar(count_stmt) or 0)

    if sort == "asc":
        order_by = (
            ParsedEvent.timestamp_utc.asc().nulls_last(),
            EvidenceFile.received_at.asc(),
            EvidenceFile.id.asc(),
            ParsedEvent.line_number.asc(),
            ParsedEvent.id.asc(),
        )
    else:
        order_by = (
            ParsedEvent.timestamp_utc.desc().nulls_last(),
            EvidenceFile.received_at.desc(),
            EvidenceFile.id.desc(),
            ParsedEvent.line_number.desc(),
            ParsedEvent.id.desc(),
        )
    statement = (
        select(ParsedEvent, EvidenceSource, EvidenceFile)
        .join(EvidenceSource, ParsedEvent.source_id == EvidenceSource.id)
        .join(EvidenceFile, ParsedEvent.evidence_file_id == EvidenceFile.id)
        .where(*conditions)
        .order_by(*order_by)
        .limit(limit)
        .offset(offset)
    )
    rows = session.execute(statement).all()
    items = [
        timeline_event_read(event, source, evidence, settings)
        for event, source, evidence in rows
    ]
    return TimelinePage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        sort=sort,
        ordering_rule=ORDERING_RULE,
    )


@router.get("/events/{event_id}", response_model=TimelineEventRead)
def get_event(
    event_id: int,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TimelineEventRead:
    row = session.execute(
        select(ParsedEvent, EvidenceSource, EvidenceFile)
        .join(EvidenceSource, ParsedEvent.source_id == EvidenceSource.id)
        .join(EvidenceFile, ParsedEvent.evidence_file_id == EvidenceFile.id)
        .where(ParsedEvent.id == event_id)
    ).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Event not found.")
    event, source, evidence = row
    return timeline_event_read(event, source, evidence, settings)
