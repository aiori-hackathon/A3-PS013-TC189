"""Investigation and summary endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import EvidenceFile, EvidenceSource, Investigation, ParsedEvent
from app.schemas import (
    EvidenceSourceRead,
    InvestigationCreate,
    InvestigationRead,
    InvestigationSummaryRead,
)
from app.services.analytics import build_summary

router = APIRouter(prefix="/investigations", tags=["investigations"])


def _get_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation:
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


def _counts(
    session: Session, investigation_id: uuid.UUID
) -> tuple[int, int, int]:
    source_count = session.scalar(
        select(func.count(EvidenceSource.id)).where(
            EvidenceSource.investigation_id == investigation_id
        )
    )
    evidence_count = session.scalar(
        select(func.count(EvidenceFile.id)).where(
            EvidenceFile.investigation_id == investigation_id
        )
    )
    event_count = session.scalar(
        select(func.count(ParsedEvent.id)).where(
            ParsedEvent.investigation_id == investigation_id
        )
    )
    return int(source_count or 0), int(evidence_count or 0), int(event_count or 0)


def _to_read(
    session: Session, investigation: Investigation, counts: tuple[int, int, int]
) -> InvestigationRead:
    source_count, evidence_count, event_count = counts
    return InvestigationRead(
        id=investigation.id,
        name=investigation.name,
        description=investigation.description,
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
        source_count=source_count,
        evidence_count=evidence_count,
        event_count=event_count,
    )


@router.post("", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
def create_investigation(
    payload: InvestigationCreate, session: Session = Depends(get_db)
) -> InvestigationRead:
    investigation = Investigation(name=payload.name, description=payload.description)
    session.add(investigation)
    session.commit()
    session.refresh(investigation)
    return _to_read(session, investigation, (0, 0, 0))


@router.get("", response_model=list[InvestigationRead])
def list_investigations(session: Session = Depends(get_db)) -> list[InvestigationRead]:
    investigations = session.scalars(
        select(Investigation).order_by(Investigation.created_at.desc())
    ).all()

    source_counts = dict(
        session.execute(
            select(EvidenceSource.investigation_id, func.count(EvidenceSource.id)).group_by(
                EvidenceSource.investigation_id
            )
        ).all()
    )
    evidence_counts = dict(
        session.execute(
            select(EvidenceFile.investigation_id, func.count(EvidenceFile.id)).group_by(
                EvidenceFile.investigation_id
            )
        ).all()
    )
    event_counts = dict(
        session.execute(
            select(ParsedEvent.investigation_id, func.count(ParsedEvent.id)).group_by(
                ParsedEvent.investigation_id
            )
        ).all()
    )

    return [
        _to_read(
            session,
            investigation,
            (
                int(source_counts.get(investigation.id, 0)),
                int(evidence_counts.get(investigation.id, 0)),
                int(event_counts.get(investigation.id, 0)),
            ),
        )
        for investigation in investigations
    ]


@router.get("/{investigation_id}", response_model=InvestigationRead)
def get_investigation(
    investigation_id: uuid.UUID, session: Session = Depends(get_db)
) -> InvestigationRead:
    investigation = _get_investigation(session, investigation_id)
    return _to_read(session, investigation, _counts(session, investigation_id))


@router.get("/{investigation_id}/summary", response_model=InvestigationSummaryRead)
def get_summary(
    investigation_id: uuid.UUID, session: Session = Depends(get_db)
) -> InvestigationSummaryRead:
    _get_investigation(session, investigation_id)
    return build_summary(session, investigation_id)


@router.get(
    "/{investigation_id}/sources",
    response_model=list[EvidenceSourceRead],
)
def list_evidence_sources(
    investigation_id: uuid.UUID, session: Session = Depends(get_db)
) -> list[EvidenceSourceRead]:
    _get_investigation(session, investigation_id)
    sources = session.scalars(
        select(EvidenceSource)
        .where(EvidenceSource.investigation_id == investigation_id)
        .order_by(EvidenceSource.name.asc())
    ).all()
    return [EvidenceSourceRead.model_validate(source) for source in sources]
