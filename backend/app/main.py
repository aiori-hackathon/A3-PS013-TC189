"""FastAPI application entrypoint for CyberTrace."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.config import Settings, get_settings
from app.constants import CYBERTRACE_VERSION
from app.database import engine
from app.routers import (
    agents,
    correlations,
    evidence,
    health,
    investigations,
    quality,
    reports,
    timeline,
)
from app.services.storage import check_storage_writable

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )
    settings.evidence_root.mkdir(parents=True, exist_ok=True)
    settings.temp_root.mkdir(parents=True, exist_ok=True)
    storage_ok, detail = check_storage_writable(settings)
    if not storage_ok:
        logger.error("Evidence storage is not writable: %s", detail)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        logger.info("Database connection established")
    except SQLAlchemyError as exc:
        logger.error("Database is not reachable at startup: %s", exc)
    logger.info(
        "CyberTrace %s started (api prefix %s, storage %s)",
        CYBERTRACE_VERSION,
        settings.api_prefix,
        settings.storage_root,
    )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CyberTrace API",
        version=CYBERTRACE_VERSION,
        description=(
            "Digital forensics timeline analyzer for small teams. Phase 1 imports "
            "Linux authentication and web access logs, preserves and hashes original "
            "evidence, normalizes only known timestamps to UTC, and exposes a "
            "searchable timeline with explicit parsing gaps. Phase 2 adds per-host "
            "Linux agents with authenticated TLS upload, local buffering and retry, "
            "heartbeats, source inventory and idempotent batch ingestion. Phase 3 adds "
            "collection coverage and gap tracking, timestamp uncertainty and clock "
            "offsets, parser transparency, evidence verification manifests, "
            "non-destructive deduplication and an evidence audit trail. Phase 4.1 "
            "adds an investigation dashboard and unified timeline at /, while "
            "keeping the evidence workspace at /workspace."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(investigations.router, prefix=settings.api_prefix)
    app.include_router(evidence.router, prefix=settings.api_prefix)
    app.include_router(timeline.router, prefix=settings.api_prefix)
    app.include_router(agents.router, prefix=settings.api_prefix)
    app.include_router(quality.router, prefix=settings.api_prefix)
    app.include_router(correlations.router, prefix=settings.api_prefix)
    app.include_router(reports.router, prefix=settings.api_prefix)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "dashboard.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard_alias() -> FileResponse:
        return FileResponse(STATIC_DIR / "dashboard.html")

    @app.get("/workspace", include_in_schema=False)
    def workspace_dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/agents", include_in_schema=False)
    def agents_dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "agents.html")

    @app.get("/quality", include_in_schema=False)
    def quality_dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "quality.html")

    return app


app = create_app()
