"""Cross-source event correlation APIs."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.constants import CorrelationStatus
from app.database import get_db
from app.models import (
    EventCorrelation,
    EventCorrelationMember,
    Investigation,
)
from app.schemas import (
    CorrelationDismissRequest,
    CorrelationRead,
    CorrelationRunResponse,
)
from app.services.correlation import (
    DEFAULT_TIME_WINDOW_SECONDS,
    dismiss_correlation,
    get_correlation,
    list_correlations,
    run_investigation_correlations,
)

router = APIRouter(tags=["correlations"])


def _require_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation:
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


def _member_read(member: EventCorrelationMember) -> Any:
    from app.schemas import CorrelationMemberRead

    event = member.event
    evidence = event.evidence_file
    source = event.source
    return CorrelationMemberRead(
        correlation_id=member.correlation_id,
        event_id=event.id,
        role=member.role,
        evidence_file_id=evidence.id,
        evidence_filename=evidence.original_filename,
        source_id=source.id,
        source_name=source.name,
        source_type=source.source_type,
        event_type=event.event_type,
        event_category=event.event_category,
        timestamp_utc=event.timestamp_utc,
        timestamp_status=event.timestamp_status,
        timestamp_detail=event.timestamp_detail,
        hostname=event.hostname,
        source_ip=event.source_ip,
        username=event.username,
        original_timestamp_string=event.original_timestamp_string,
        raw_line=event.raw_line,
        evidence_sha256=evidence.sha256,
    )


def _correlation_read(correlation: EventCorrelation) -> CorrelationRead:
    from app.schemas import CorrelationRead

    members = [_member_read(member) for member in correlation.members]
    source_systems = sorted({member.event.source.name for member in correlation.members})
    return CorrelationRead(
        id=correlation.id,
        investigation_id=correlation.investigation_id,
        rule_id=correlation.rule_id,
        rule_name=correlation.rule_name,
        rule_description=correlation.rule_description,
        correlation_type=correlation.correlation_type,
        confidence=getattr(correlation.confidence, "value", correlation.confidence),
        title=correlation.title,
        explanation=correlation.explanation,
        matching_fields=list(correlation.matching_fields or []),
        time_relationship=correlation.time_relationship,
        timestamp_uncertainty=correlation.timestamp_uncertainty,
        status=getattr(correlation.status, "value", correlation.status),
        dismissed_at=correlation.dismissed_at,
        dismissed_by=correlation.dismissed_by,
        dismissal_reason=correlation.dismissal_reason,
        created_at=correlation.created_at,
        updated_at=correlation.updated_at,
        source_systems=source_systems,
        event_ids=[member.event_id for member in correlation.members],
        events=members,
    )


def _list_for_investigation(
    session: Session,
    investigation_id: uuid.UUID,
    *,
    include_dismissed: bool = True,
    status_filter: str | None = None,
) -> list[EventCorrelation]:
    _require_investigation(session, investigation_id)
    correlations = list_correlations(session, investigation_id)
    if status_filter:
        correlations = [
            item
            for item in correlations
            if getattr(item.status, "value", item.status) == status_filter
        ]
    if not include_dismissed:
        correlations = [
            item
            for item in correlations
            if getattr(item.status, "value", item.status) != CorrelationStatus.DISMISSED.value
        ]
    return correlations


@router.get(
    "/investigations/{investigation_id}/correlations",
    response_model=list[CorrelationRead],
)
def get_investigation_correlations(
    investigation_id: uuid.UUID,
    include_dismissed: bool = Query(True),
    status: str | None = Query(None, max_length=16),
    session: Session = Depends(get_db),
) -> list[CorrelationRead]:
    correlations = _list_for_investigation(
        session, investigation_id, include_dismissed=include_dismissed, status_filter=status
    )
    return [_correlation_read(item) for item in correlations]


@router.post(
    "/investigations/{investigation_id}/correlations",
    response_model=CorrelationRunResponse,
)
def run_correlations(
    investigation_id: uuid.UUID,
    request: Request,
    time_window_seconds: int | None = Query(None, ge=60, le=86400),
    session: Session = Depends(get_db),
) -> CorrelationRunResponse:
    _require_investigation(session, investigation_id)
    window = time_window_seconds or DEFAULT_TIME_WINDOW_SECONDS
    created, updated, preserved, items = run_investigation_correlations(
        session,
        investigation_id,
        time_window_seconds=window,
        actor_type="api",
        actor_detail=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
    )
    session.commit()
    correlations = list_correlations(session, investigation_id)
    return CorrelationRunResponse(
        investigation_id=investigation_id,
        created=created,
        updated=updated,
        preserved_dismissed=preserved,
        total=len(correlations),
        time_window_seconds=window,
        items=[_correlation_read(item) for item in correlations],
    )


@router.get("/correlations/{correlation_id}", response_model=CorrelationRead)
def get_correlation_detail(
    correlation_id: uuid.UUID, session: Session = Depends(get_db)
) -> CorrelationRead:
    correlation = get_correlation(session, correlation_id)
    if correlation is None:
        raise HTTPException(status_code=404, detail="Correlation not found.")
    return _correlation_read(correlation)


@router.post(
    "/correlations/{correlation_id}/dismiss",
    response_model=CorrelationRead,
)
def dismiss_correlation_endpoint(
    correlation_id: uuid.UUID,
    payload: CorrelationDismissRequest,
    request: Request,
    session: Session = Depends(get_db),
) -> CorrelationRead:
    correlation = get_correlation(session, correlation_id)
    if correlation is None:
        raise HTTPException(status_code=404, detail="Correlation not found.")
    dismiss_correlation(
        session,
        correlation,
        reason=payload.reason,
        actor_type="api",
        actor_detail=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
    )
    session.commit()
    session.refresh(correlation)
    return _correlation_read(correlation)


@router.get(
    "/events/{event_id}/correlations",
    response_model=list[CorrelationRead],
)
def get_event_correlations(
    event_id: int, session: Session = Depends(get_db)
) -> list[CorrelationRead]:
    member_rows = session.scalars(
        select(EventCorrelationMember).where(EventCorrelationMember.event_id == event_id)
    ).all()
    correlation_ids = {row.correlation_id for row in member_rows}
    correlations: list[EventCorrelation] = []
    for correlation_id in correlation_ids:
        correlation = get_correlation(session, correlation_id)
        if correlation is not None:
            correlations.append(correlation)
    correlations.sort(key=lambda item: item.created_at, reverse=True)
    return [_correlation_read(item) for item in correlations]


# Aliases for quality-style paths.
@router.get(
    "/quality/investigations/{investigation_id}/correlations",
    response_model=list[CorrelationRead],
)
def quality_list_correlations(
    investigation_id: uuid.UUID,
    include_dismissed: bool = Query(True),
    status: str | None = Query(None, max_length=16),
    session: Session = Depends(get_db),
) -> list[CorrelationRead]:
    return get_investigation_correlations(
        investigation_id, include_dismissed=include_dismissed, status=status, session=session
    )


@router.post(
    "/quality/investigations/{investigation_id}/correlations",
    response_model=CorrelationRunResponse,
)
def quality_run_correlations(
    investigation_id: uuid.UUID,
    request: Request,
    time_window_seconds: int | None = Query(None, ge=60, le=86400),
    session: Session = Depends(get_db),
) -> CorrelationRunResponse:
    return run_correlations(
        investigation_id, request=request, time_window_seconds=time_window_seconds, session=session
    )
