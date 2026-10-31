"""Investigation report and CSV export endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_db
from app.models import Investigation
from app.services.reporting import build_csv, build_pdf, gather_report_data

router = APIRouter(tags=["reports"])


def _require_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation:
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return investigation


def _parse_dt(value: str | None, name: str) -> datetime | None:
    if not value:
        return None
    try:
        # Accept ISO-8601 with or without timezone; naive values are treated as UTC.
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {name} timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


@router.get("/investigations/{investigation_id}/report.pdf")
def download_pdf_report(
    investigation_id: uuid.UUID,
    start: str | None = Query(None),
    end: str | None = Query(None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    _require_investigation(session, investigation_id)
    start_dt = _parse_dt(start, "start")
    end_dt = _parse_dt(end, "end")
    if start_dt and end_dt and start_dt > end_dt:
        raise HTTPException(status_code=422, detail="start must be before or equal to end.")
    data = gather_report_data(session, settings, investigation_id, start=start_dt, end=end_dt)
    pdf_bytes = build_pdf(data)
    filename = f"cybertrace-investigation-{investigation_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/investigations/{investigation_id}/report")
def download_report_alias(
    investigation_id: uuid.UUID,
    start: str | None = Query(None),
    end: str | None = Query(None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    return download_pdf_report(investigation_id, start=start, end=end, session=session, settings=settings)


@router.get("/investigations/{investigation_id}/export/{dataset}.csv")
def download_csv_report(
    investigation_id: uuid.UUID,
    dataset: str,
    start: str | None = Query(None),
    end: str | None = Query(None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    _require_investigation(session, investigation_id)
    valid = {"timeline", "evidence", "coverage", "gaps", "parsing", "correlations", "events", "inventory"}
    if dataset not in valid:
        raise HTTPException(status_code=404, detail="Unsupported CSV dataset.")
    normalized = {
        "events": "timeline",
        "inventory": "evidence",
    }.get(dataset, dataset)
    start_dt = _parse_dt(start, "start")
    end_dt = _parse_dt(end, "end")
    if start_dt and end_dt and start_dt > end_dt:
        raise HTTPException(status_code=422, detail="start must be before or equal to end.")
    data = gather_report_data(session, settings, investigation_id, start=start_dt, end=end_dt)
    csv_text = build_csv(normalized, data)
    filename = f"cybertrace-{normalized}-{investigation_id}.csv"
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/investigations/{investigation_id}/exports/{dataset}")
def download_csv_alias(
    investigation_id: uuid.UUID,
    dataset: str,
    start: str | None = Query(None),
    end: str | None = Query(None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    return download_csv_report(investigation_id, dataset, start=start, end=end, session=session, settings=settings)


@router.get("/investigations/{investigation_id}/export/{dataset}")
def download_csv_alias2(
    investigation_id: uuid.UUID,
    dataset: str,
    start: str | None = Query(None),
    end: str | None = Query(None),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    return download_csv_report(investigation_id, dataset, start=start, end=end, session=session, settings=settings)
