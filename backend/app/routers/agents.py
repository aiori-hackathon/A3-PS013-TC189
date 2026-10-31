"""Endpoint agent registration, collection, heartbeat and health APIs."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.agent_schemas import (
    AgentBatchListPage,
    AgentBatchManifest,
    AgentBatchResult,
    AgentBatchSummary,
    AgentDetailRead,
    AgentErrorRead,
    AgentHealthSummary,
    AgentHeartbeatRead,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentListPage,
    AgentMeResponse,
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentSourceListResponse,
    AgentSourceRead,
    AgentSourceSyncRequest,
    AgentSourceSyncResponse,
)
from app.config import Settings, get_settings
from app.constants import AgentStatus
from app.database import get_db
from app.models import Agent, AgentBatch, AgentSource
from app.schemas import OperationMessage
from app.services import agent_batch, agent_service
from app.services.agent_auth import get_current_agent, require_enrollment_token
from app.services.errors import IngestError

router = APIRouter(tags=["agents"])


def _raise_ingest(exc: IngestError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.as_detail()) from exc


def _validation_detail(exc: ValidationError) -> dict:
    return {
        "code": "invalid_payload",
        "message": "Request payload validation failed.",
        "errors": [
            {
                "loc": list(item.get("loc", [])),
                "msg": item.get("msg", ""),
                "type": item.get("type", ""),
            }
            for item in exc.errors()
        ],
    }


def _get_agent(session: Session, agent_id: uuid.UUID, *, with_sources: bool = False) -> Agent:
    statement = select(Agent).where(Agent.id == agent_id)
    if with_sources:
        statement = statement.options(selectinload(Agent.sources))
    agent = session.scalar(statement)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return agent


def _counts_by_agent(
    session: Session, column, model
) -> dict[uuid.UUID, int]:
    return {
        row[0]: int(row[1])
        for row in session.execute(select(column, func.count(model.id)).group_by(column)).all()
    }


@router.post(
    "/agents/register",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_agent(
    payload: AgentRegisterRequest,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _enrollment: None = Depends(require_enrollment_token),
) -> AgentRegisterResponse:
    try:
        agent, token, rotated = agent_service.register_agent(session, settings, payload)
    except IngestError as exc:
        _raise_ingest(exc)

    return AgentRegisterResponse(
        agent_id=agent.id,
        agent_uid=agent.agent_uid,
        investigation_id=agent.investigation_id,
        agent_token=token,
        token_prefix=agent.token_prefix,
        rotated=rotated,
        stale_after_seconds=settings.agent_stale_after_seconds,
        server_time=datetime.now(UTC),
    )


@router.get("/agents/health", response_model=AgentHealthSummary)
def agent_health(
    session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
) -> AgentHealthSummary:
    return agent_service.agent_health_summary(session, settings)


@router.get("/agents/me", response_model=AgentMeResponse)
def agent_me(
    agent: Agent = Depends(get_current_agent),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AgentMeResponse:
    return agent_service.agent_me(session, settings, agent)


@router.put("/agents/sources", response_model=AgentSourceSyncResponse)
def sync_agent_sources(
    payload: AgentSourceSyncRequest,
    agent: Agent = Depends(get_current_agent),
    session: Session = Depends(get_db),
) -> AgentSourceSyncResponse:
    try:
        return agent_service.sync_sources(session, agent, payload.sources)
    except IngestError as exc:
        _raise_ingest(exc)


@router.post("/agents/heartbeat", response_model=AgentHeartbeatResponse)
def heartbeat(
    payload: AgentHeartbeatRequest,
    agent: Agent = Depends(get_current_agent),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AgentHeartbeatResponse:
    return agent_service.apply_heartbeat(session, settings, agent, payload)


@router.post("/agents/batches", response_model=AgentBatchResult)
def upload_agent_batch(
    request: Request,
    manifest: str = Form(..., description="JSON collection manifest"),
    files: list[UploadFile] = File(default=[]),
    agent: Agent = Depends(get_current_agent),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AgentBatchResult:
    raw_manifest = manifest.encode("utf-8")
    if not raw_manifest:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_manifest", "message": "Manifest must not be empty."},
        )
    if len(raw_manifest) > settings.agent_manifest_max_bytes:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "manifest_too_large",
                "message": (
                    f"Manifest exceeds the {settings.agent_manifest_max_bytes} byte limit."
                ),
            },
        )

    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit():
        overhead = settings.agent_manifest_max_bytes + 2 * 1024 * 1024
        if int(content_length) > settings.agent_batch_max_bytes + overhead:
            raise HTTPException(
                status_code=413,
                detail={
                    "code": "agent_batch_too_large",
                    "message": "Uploaded batch exceeds the configured size limit.",
                },
            )

    try:
        payload_data = json.loads(manifest)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_manifest",
                "message": f"Manifest is not valid JSON: {exc.msg}.",
            },
        ) from exc

    try:
        parsed = AgentBatchManifest.model_validate(payload_data)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=_validation_detail(exc)) from exc

    try:
        return agent_batch.process_batch(session, settings, agent, manifest, parsed, files)
    except IngestError as exc:
        _raise_ingest(exc)


@router.get("/agents", response_model=AgentListPage)
def list_agents(
    investigation_id: uuid.UUID | None = Query(None),
    health: str | None = Query(None, pattern="^(online|stale|never_seen|disabled)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AgentListPage:
    conditions = []
    if investigation_id is not None:
        conditions.append(Agent.investigation_id == investigation_id)
    agents = session.scalars(
        select(Agent).where(*conditions).order_by(Agent.last_seen_at.desc().nulls_last())
    ).all()
    source_counts = _counts_by_agent(session, AgentSource.agent_id, AgentSource)
    batch_counts = _counts_by_agent(session, AgentBatch.agent_id, AgentBatch)
    now = datetime.now(UTC)

    summaries = [
        agent_service.agent_summary(
            agent,
            settings,
            now=now,
            source_count=source_counts.get(agent.id, 0),
            batch_count=batch_counts.get(agent.id, 0),
        )
        for agent in agents
    ]
    if health is not None:
        summaries = [item for item in summaries if item.health.value == health]
    total = len(summaries)
    return AgentListPage(
        items=summaries[offset : offset + limit], total=total, limit=limit, offset=offset
    )


@router.get("/agents/{agent_id}", response_model=AgentDetailRead)
def get_agent(
    agent_id: uuid.UUID,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AgentDetailRead:
    agent = _get_agent(session, agent_id, with_sources=True)
    source_count = len(agent.sources)
    batch_count = int(
        session.scalar(
            select(func.count(AgentBatch.id)).where(AgentBatch.agent_id == agent.id)
        )
        or 0
    )
    summary = agent_service.agent_summary(
        agent,
        settings,
        now=datetime.now(UTC),
        source_count=source_count,
        batch_count=batch_count,
    )
    recent_errors = agent_service.load_recent_errors(session, agent.id)
    recent_batches = agent_service.load_recent_batches(session, agent.id)
    recent_heartbeats = agent_service.load_recent_heartbeats(session, agent.id)
    return AgentDetailRead(
        **summary.model_dump(),
        sources=[AgentSourceRead.model_validate(source) for source in agent.sources],
        recent_errors=[AgentErrorRead.model_validate(error) for error in recent_errors],
        recent_batches=[AgentBatchSummary.model_validate(batch) for batch in recent_batches],
        recent_heartbeats=[
            AgentHeartbeatRead.model_validate(heartbeat)
            for heartbeat in recent_heartbeats
        ],
    )


@router.get("/agents/{agent_id}/sources", response_model=AgentSourceListResponse)
def list_agent_sources(
    agent_id: uuid.UUID,
    session: Session = Depends(get_db),
) -> AgentSourceListResponse:
    _get_agent(session, agent_id)
    sources = session.scalars(
        select(AgentSource)
        .where(AgentSource.agent_id == agent_id)
        .order_by(AgentSource.source_key.asc())
    ).all()
    return AgentSourceListResponse(
        items=[AgentSourceRead.model_validate(source) for source in sources]
    )


@router.get("/agents/{agent_id}/batches", response_model=AgentBatchListPage)
def list_agent_batches(
    agent_id: uuid.UUID,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> AgentBatchListPage:
    _get_agent(session, agent_id)
    total = int(
        session.scalar(
            select(func.count(AgentBatch.id)).where(AgentBatch.agent_id == agent_id)
        )
        or 0
    )
    batches = session.scalars(
        select(AgentBatch)
        .where(AgentBatch.agent_id == agent_id)
        .order_by(AgentBatch.received_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AgentBatchListPage(
        items=[AgentBatchSummary.model_validate(batch) for batch in batches],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/agents/{agent_id}/disable", response_model=OperationMessage)
def disable_agent(
    agent_id: uuid.UUID,
    session: Session = Depends(get_db),
    _enrollment: None = Depends(require_enrollment_token),
) -> OperationMessage:
    agent = _get_agent(session, agent_id)
    agent.status = AgentStatus.DISABLED
    session.commit()
    return OperationMessage(
        message="Agent disabled. Existing tokens will be rejected and buffered data can no longer upload."
    )


@router.post("/agents/{agent_id}/enable", response_model=OperationMessage)
def enable_agent(
    agent_id: uuid.UUID,
    session: Session = Depends(get_db),
    _enrollment: None = Depends(require_enrollment_token),
) -> OperationMessage:
    agent = _get_agent(session, agent_id)
    agent.status = AgentStatus.ACTIVE
    session.commit()
    return OperationMessage(message="Agent enabled.")


@router.delete("/agents/{agent_id}", response_model=OperationMessage)
def delete_agent(
    agent_id: uuid.UUID,
    session: Session = Depends(get_db),
    _enrollment: None = Depends(require_enrollment_token),
) -> OperationMessage:
    agent = _get_agent(session, agent_id)
    session.delete(agent)
    session.commit()
    return OperationMessage(
        message=(
            "Agent registration, inventory and delivery history deleted. "
            "Preserved evidence files and timeline events were retained."
        )
    )
