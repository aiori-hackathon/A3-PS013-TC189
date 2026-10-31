"""Health and readiness endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.constants import CYBERTRACE_VERSION
from app.database import get_db
from app.schemas import HealthRead
from app.services.storage import check_storage_writable

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthRead)
def health(
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    database = "ok"
    schema = "ok"
    try:
        session.execute(text("SELECT 1"))
        inspector = inspect(session.get_bind())
        if not inspector.has_table("investigations") or not inspector.has_table("agents"):
            schema = "missing"
    except SQLAlchemyError:
        database = "unavailable"
        schema = "unknown"

    storage_ok, _storage_detail = check_storage_writable(settings)
    storage = "ok" if storage_ok else "unwritable"
    overall = "ok" if database == "ok" and schema == "ok" and storage == "ok" else "degraded"
    payload = HealthRead(
        status=overall,
        database=database,
        schema_status=schema,
        storage=storage,
        version=CYBERTRACE_VERSION,
    )
    if overall != "ok":
        return JSONResponse(status_code=503, content=payload.model_dump())
    return payload
