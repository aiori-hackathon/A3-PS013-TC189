"""Agent registration, inventory synchronization, heartbeat and health logic."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent_schemas import (
    AgentBatchSummary,
    AgentDetailRead,
    AgentErrorRead,
    AgentHealthSummary,
    AgentHeartbeatRead,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentMeResponse,
    AgentRegisterRequest,
    AgentSourceRead,
    AgentSourceRegistration,
    AgentSourceSyncResponse,
    AgentSummaryRead,
)
from app.config import Settings
from app.constants import (
    AgentHealth,
    AgentRuntimeStatus,
    AgentSourceStatus,
    AgentStatus,
    CollectionGapReason,
    CollectionGapStatus,
    CollectionWindowStatus,
    GapBasis,
    SourceType,
)
from app.models import (
    Agent,
    AgentBatch,
    AgentError,
    AgentHeartbeat,
    AgentSource,
    CollectionGap,
    Investigation,
    utcnow,
)
from app.services.agent_auth import generate_agent_token, hash_agent_token, token_prefix
from app.services.coverage import (
    close_open_gaps,
    ensure_open_gap,
    record_collection_window,
)
from app.services.errors import IngestError


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _max_time(current: datetime | None, candidate: datetime | None) -> datetime | None:
    if candidate is None:
        return current
    candidate = _utc(candidate)
    if current is None:
        return candidate
    return max(_utc(current), candidate)


def get_agent_health(agent: Agent, now: datetime, stale_after_seconds: int) -> AgentHealth:
    if agent.status is AgentStatus.DISABLED:
        return AgentHealth.DISABLED
    if agent.last_seen_at is None:
        return AgentHealth.NEVER_SEEN
    age = (now - _utc(agent.last_seen_at)).total_seconds()
    if age > stale_after_seconds:
        return AgentHealth.STALE
    return AgentHealth.ONLINE


def agent_summary(
    agent: Agent,
    settings: Settings,
    *,
    now: datetime,
    source_count: int | None = None,
    batch_count: int | None = None,
) -> AgentSummaryRead:
    return AgentSummaryRead(
        id=agent.id,
        agent_uid=agent.agent_uid,
        display_name=agent.display_name,
        hostname=agent.hostname,
        platform=agent.platform,
        agent_version=agent.agent_version,
        investigation_id=agent.investigation_id,
        status=agent.status,
        runtime_status=agent.runtime_status,
        health=get_agent_health(agent, now, settings.agent_stale_after_seconds),
        last_seen_at=agent.last_seen_at,
        last_heartbeat_at=agent.last_heartbeat_at,
        last_collection_at=agent.last_collection_at,
        last_error_at=agent.last_error_at,
        last_error=agent.last_error,
        queue_pending_batches=agent.queue_pending_batches,
        queue_pending_bytes=agent.queue_pending_bytes,
        heartbeat_interval_seconds=agent.heartbeat_interval_seconds,
        collection_interval_seconds=agent.collection_interval_seconds,
        measured_clock_offset_seconds=agent.measured_clock_offset_seconds,
        clock_offset_source=agent.clock_offset_source,
        last_recovery_at=agent.last_recovery_at,
        reconnection_count=agent.reconnection_count,
        registered_at=agent.registered_at,
        source_count=source_count if source_count is not None else len(agent.sources),
        batch_count=batch_count if batch_count is not None else len(agent.batches),
    )


def agent_detail(
    agent: Agent,
    settings: Settings,
    *,
    now: datetime,
    recent_errors: list[AgentError],
    recent_batches: list[AgentBatch],
    recent_heartbeats: list[AgentHeartbeat] | None = None,
) -> AgentDetailRead:
    summary = agent_summary(agent, settings, now=now)
    return AgentDetailRead(
        **summary.model_dump(),
        sources=[AgentSourceRead.model_validate(source) for source in agent.sources],
        recent_errors=[AgentErrorRead.model_validate(error) for error in recent_errors],
        recent_batches=[AgentBatchSummary.model_validate(batch) for batch in recent_batches],
        recent_heartbeats=[
            AgentHeartbeatRead.model_validate(heartbeat)
            for heartbeat in (recent_heartbeats or [])
        ],
    )


def _upsert_sources(
    session: Session,
    agent: Agent,
    registrations: list[AgentSourceRegistration],
) -> tuple[int, int]:
    existing = {
        source.source_key: source
        for source in session.scalars(
            select(AgentSource).where(AgentSource.agent_id == agent.id)
        ).all()
    }

    # Validate all changes before mutating anything so registration is atomic.
    for registration in registrations:
        current = existing.get(registration.key)
        if current is None:
            continue
        if current.source_type.value != registration.source_type:
            if current.evidence_source_id is not None:
                raise IngestError(
                    409,
                    "source_type_conflict",
                    (
                        f"Source {registration.key!r} already has stored evidence under "
                        f"{current.source_type.value!r}; it cannot change to "
                        f"{registration.source_type!r}."
                    ),
                    source_key=registration.key,
                )

    created = 0
    updated = 0
    for registration in registrations:
        current = existing.get(registration.key)
        if current is None:
            current = AgentSource(
                agent_id=agent.id,
                source_key=registration.key,
                name=registration.name,
                source_type=SourceType(registration.source_type),
                status=(
                    AgentSourceStatus.UNKNOWN
                    if registration.enabled
                    else AgentSourceStatus.DISABLED
                ),
                enabled=registration.enabled,
                metadata_json={"created_by": "agent_registration"},
            )
            session.add(current)
            existing[registration.key] = current
            created += 1
        else:
            if current.source_type.value != registration.source_type:
                current.source_type = SourceType(registration.source_type)
            if not registration.enabled:
                current.status = AgentSourceStatus.DISABLED
            elif current.status is AgentSourceStatus.DISABLED:
                current.status = AgentSourceStatus.UNKNOWN
            updated += 1
        current.name = registration.name
        current.path_hint = registration.path_hint
        current.timezone_hint = registration.timezone_hint
        current.default_year = registration.default_year
        current.enabled = registration.enabled
        current.clock_offset_seconds = registration.clock_offset_seconds
        current.expected_collection_interval_seconds = (
            registration.expected_collection_interval_seconds
        )

    session.flush()
    return created, updated


def register_agent(
    session: Session,
    settings: Settings,
    payload: AgentRegisterRequest,
) -> tuple[Agent, str, bool]:
    investigation = session.get(Investigation, payload.investigation_id)
    if investigation is None:
        raise IngestError(404, "investigation_not_found", "Investigation was not found.")

    now = utcnow()
    agent = session.scalar(select(Agent).where(Agent.agent_uid == payload.agent_uid))
    rotated = agent is not None

    if agent is not None:
        if agent.investigation_id != payload.investigation_id:
            raise IngestError(
                409,
                "agent_investigation_conflict",
                "This agent identifier is already registered to a different investigation.",
                agent_id=str(agent.id),
            )
        if agent.status is AgentStatus.DISABLED:
            raise IngestError(
                403,
                "agent_disabled",
                "This agent has been disabled by an administrator.",
                agent_id=str(agent.id),
            )
        token = generate_agent_token()
        agent.token_hash = hash_agent_token(token)
        agent.token_prefix = token_prefix(token)
        agent.display_name = payload.display_name
        agent.hostname = payload.hostname
        agent.platform = payload.platform
        agent.agent_version = payload.agent_version
        agent.last_seen_at = now
        agent.metadata_json = {
            **(agent.metadata_json or {}),
            "re_registered_at": now.isoformat(),
        }
    else:
        token = generate_agent_token()
        agent = Agent(
            agent_uid=payload.agent_uid,
            display_name=payload.display_name,
            hostname=payload.hostname,
            platform=payload.platform,
            agent_version=payload.agent_version,
            investigation_id=payload.investigation_id,
            token_hash=hash_agent_token(token),
            token_prefix=token_prefix(token),
            status=AgentStatus.ACTIVE,
            runtime_status=AgentRuntimeStatus.UNKNOWN,
            last_seen_at=now,
            metadata_json={"registered_by": "agent_enrollment"},
        )
        session.add(agent)
        session.flush()

    _upsert_sources(session, agent, payload.sources)
    session.commit()
    session.refresh(agent)
    return agent, token, rotated


def sync_sources(
    session: Session,
    agent: Agent,
    registrations: list[AgentSourceRegistration],
) -> AgentSourceSyncResponse:
    created, updated = _upsert_sources(session, agent, registrations)
    agent.last_seen_at = utcnow()
    session.commit()
    session.refresh(agent)
    sources = session.scalars(
        select(AgentSource)
        .where(AgentSource.agent_id == agent.id)
        .order_by(AgentSource.source_key.asc())
    ).all()
    return AgentSourceSyncResponse(
        items=[AgentSourceRead.model_validate(source) for source in sources],
        created=created,
        updated=updated,
    )


def record_agent_error(
    session: Session,
    agent: Agent,
    *,
    code: str,
    message: str,
    occurred_at: datetime | None = None,
    source: AgentSource | None = None,
    batch: AgentBatch | None = None,
) -> AgentError:
    when = _utc(occurred_at) if occurred_at is not None else utcnow()
    error = AgentError(
        agent_id=agent.id,
        source_id=source.id if source else None,
        agent_batch_id=batch.id if batch else None,
        error_code=code[:64],
        message=message[:4000],
        occurred_at=when,
        metadata_json={},
    )
    session.add(error)
    agent.last_error_at = when
    agent.last_error = message[:4000]
    if source is not None and source.enabled:
        source.status = AgentSourceStatus.ERROR
        source.last_error = message[:4000]
        source.last_error_at = when
    return error


def apply_heartbeat(
    session: Session,
    settings: Settings,
    agent: Agent,
    payload: AgentHeartbeatRequest,
) -> AgentHeartbeatResponse:
    now = utcnow()
    previous_heartbeat = (
        _utc(agent.last_heartbeat_at) if agent.last_heartbeat_at else None
    )
    previous_seen = _utc(agent.last_seen_at) if agent.last_seen_at else None
    previous_was_stale = bool(
        previous_seen
        and (now - previous_seen).total_seconds() > settings.agent_stale_after_seconds
    )

    agent.last_seen_at = now
    agent.last_heartbeat_at = now
    agent.runtime_status = AgentRuntimeStatus(payload.runtime_status)
    if payload.agent_version:
        agent.agent_version = payload.agent_version
    agent.queue_pending_batches = payload.queue_pending_batches
    agent.queue_pending_bytes = payload.queue_pending_bytes
    if payload.heartbeat_interval_seconds is not None:
        agent.heartbeat_interval_seconds = payload.heartbeat_interval_seconds
    if payload.collection_interval_seconds is not None:
        agent.collection_interval_seconds = payload.collection_interval_seconds
    if payload.clock_offset_seconds is not None:
        agent.measured_clock_offset_seconds = payload.clock_offset_seconds
        agent.clock_offset_source = payload.clock_offset_source or "measured"
        agent.clock_offset_observed_at = now

    expected_heartbeat = (
        agent.heartbeat_interval_seconds
        or settings.agent_default_heartbeat_interval_seconds
    )
    gap_threshold = max(settings.agent_stale_after_seconds, expected_heartbeat * 2)

    closed_agent_gaps = close_open_gaps(
        session,
        investigation_id=agent.investigation_id,
        agent_id=agent.id,
        agent_level_only=True,
        end=now,
        note="Agent resumed heartbeats and reported its current state.",
    )
    recovered = bool(closed_agent_gaps)
    if (
        previous_heartbeat is not None
        and (now - previous_heartbeat).total_seconds() > gap_threshold
    ):
        session.add(
            CollectionGap(
                investigation_id=agent.investigation_id,
                agent_id=agent.id,
                agent_source_id=None,
                gap_start=previous_heartbeat,
                gap_end=now,
                status=CollectionGapStatus.CLOSED,
                reason=CollectionGapReason.AGENT_OFFLINE,
                basis=GapBasis.OBSERVED,
                expected_interval_seconds=expected_heartbeat,
                detail={
                    "previous_heartbeat_at": previous_heartbeat.isoformat(),
                    "resumed_at": now.isoformat(),
                    "gap_threshold_seconds": gap_threshold,
                    "previous_health": (
                        AgentHealth.STALE.value if previous_was_stale else "online"
                    ),
                    "note": (
                        "The interval between the previous and current heartbeat exceeded "
                        "the stale/gap threshold. Start and end are observed heartbeat times."
                    ),
                },
            )
        )
        recovered = True
    if recovered:
        agent.reconnection_count = (agent.reconnection_count or 0) + 1
        agent.last_recovery_at = now

    sources = {
        source.source_key: source
        for source in session.scalars(
            select(AgentSource).where(AgentSource.agent_id == agent.id)
        ).all()
    }
    ignored: list[str] = []

    for report in payload.sources:
        source = sources.get(report.key)
        if source is None:
            ignored.append(report.key)
            continue
        source.last_seen_at = now
        if report.last_collected_at is not None:
            source.last_collected_at = _max_time(
                source.last_collected_at, report.last_collected_at
            )
        if report.last_success_at is not None:
            source.last_success_at = _max_time(
                source.last_success_at, report.last_success_at
            )
        if report.collection_started_at is not None:
            source.last_collection_started_at = _max_time(
                source.last_collection_started_at, report.collection_started_at
            )
        if report.collection_ended_at is not None:
            source.last_collection_ended_at = _max_time(
                source.last_collection_ended_at, report.collection_ended_at
            )
        if report.cursor_bytes is not None:
            source.cursor_bytes = report.cursor_bytes
        if report.observed_size_bytes is not None:
            source.observed_size_bytes = report.observed_size_bytes
        if (
            report.bytes_collected_last_cycle is not None
            or report.lines_collected_last_cycle is not None
        ):
            source.last_cycle_at = now
            if report.bytes_collected_last_cycle is not None:
                source.last_cycle_bytes = report.bytes_collected_last_cycle
            if report.lines_collected_last_cycle is not None:
                source.last_cycle_lines = report.lines_collected_last_cycle
        if report.collection_available is not None:
            source.collection_available = report.collection_available

        if not source.enabled:
            source.status = AgentSourceStatus.DISABLED
            close_open_gaps(
                session,
                investigation_id=agent.investigation_id,
                end=now,
                agent_source_id=source.id,
                note="Source was disabled; the open gap was closed administratively.",
            )
            continue

        failure = report.last_error
        if report.path_readable is False and not failure:
            failure = "The configured log path is not readable by the agent."
        if failure:
            source.status = AgentSourceStatus.ERROR
            source.last_error = failure
            source.last_error_at = now
        elif report.status == "disabled":
            source.status = AgentSourceStatus.DISABLED
        elif report.status == "error":
            source.status = AgentSourceStatus.ERROR
            if not source.last_error:
                source.last_error = "The agent reported an unspecified collection error."
                source.last_error_at = now
        elif report.status == "healthy":
            source.status = AgentSourceStatus.HEALTHY
            source.last_error = None
            if report.last_success_at is None and source.last_success_at is None:
                source.last_success_at = report.last_collected_at or now
        elif source.last_success_at is not None:
            source.status = AgentSourceStatus.HEALTHY
        else:
            source.status = AgentSourceStatus.UNKNOWN

        if source.status is AgentSourceStatus.HEALTHY:
            closed_source_gaps = close_open_gaps(
                session,
                investigation_id=agent.investigation_id,
                end=now,
                agent_source_id=source.id,
                note="Source reported healthy collection; the open source gap is closed.",
            )
            if closed_source_gaps:
                source.recovery_count = (source.recovery_count or 0) + 1
                source.last_recovery_at = now
            if report.collection_started_at or report.collection_ended_at or (
                report.bytes_collected_last_cycle is not None
            ):
                if (report.bytes_collected_last_cycle or 0) == 0:
                    window_status = CollectionWindowStatus.EMPTY
                else:
                    window_status = CollectionWindowStatus.COMPLETED
                record_collection_window(
                    session,
                    investigation_id=agent.investigation_id,
                    agent=agent,
                    source=source,
                    origin="heartbeat",
                    status=window_status,
                    observed_at=now,
                    started_at=report.collection_started_at,
                    ended_at=report.collection_ended_at,
                    bytes_collected=report.bytes_collected_last_cycle,
                    lines_collected=report.lines_collected_last_cycle,
                    detail={"reported_via": "heartbeat"},
                )
        elif source.status is AgentSourceStatus.ERROR:
            estimated_start = (
                source.last_success_at
                or previous_heartbeat
                or source.last_error_at
                or now
            )
            ensure_open_gap(
                session,
                investigation_id=agent.investigation_id,
                agent=agent,
                source=source,
                gap_start=estimated_start,
                reason=CollectionGapReason.SOURCE_ERROR,
                basis=(
                    GapBasis.INFERRED
                    if source.last_success_at is not None
                    else GapBasis.OBSERVED
                ),
                expected_interval_seconds=(
                    source.expected_collection_interval_seconds
                    or agent.collection_interval_seconds
                    or settings.agent_default_collection_interval_seconds
                ),
                detail={
                    "last_success_at": (
                        source.last_success_at.isoformat()
                        if source.last_success_at
                        else None
                    ),
                    "last_error": source.last_error,
                    "note": (
                        "Gap start is the last known success/heartbeat, not a measured "
                        "failure instant."
                    ),
                },
            )
            if report.collection_started_at or report.collection_ended_at:
                record_collection_window(
                    session,
                    investigation_id=agent.investigation_id,
                    agent=agent,
                    source=source,
                    origin="heartbeat",
                    status=CollectionWindowStatus.FAILED,
                    observed_at=now,
                    started_at=report.collection_started_at,
                    ended_at=report.collection_ended_at,
                    bytes_collected=report.bytes_collected_last_cycle,
                    lines_collected=report.lines_collected_last_cycle,
                    detail={"reported_via": "heartbeat", "error": source.last_error},
                )
        elif source.status is AgentSourceStatus.DISABLED:
            close_open_gaps(
                session,
                investigation_id=agent.investigation_id,
                end=now,
                agent_source_id=source.id,
                note="Source reported disabled; the open gap was closed administratively.",
            )

    for reported_error in payload.errors:
        source = sources.get(reported_error.source_key) if reported_error.source_key else None
        record_agent_error(
            session,
            agent,
            code=reported_error.code,
            message=reported_error.message,
            occurred_at=reported_error.occurred_at,
            source=source,
        )
        if source is not None and source.enabled:
            ensure_open_gap(
                session,
                investigation_id=agent.investigation_id,
                agent=agent,
                source=source,
                gap_start=source.last_success_at or previous_heartbeat or now,
                reason=CollectionGapReason.SOURCE_ERROR,
                basis=(
                    GapBasis.INFERRED
                    if source.last_success_at is not None
                    else GapBasis.OBSERVED
                ),
                expected_interval_seconds=(
                    source.expected_collection_interval_seconds
                    or agent.collection_interval_seconds
                    or settings.agent_default_collection_interval_seconds
                ),
                detail={
                    "last_error": reported_error.message,
                    "error_code": reported_error.code,
                    "reported_via": "heartbeat_error",
                },
            )

    collection_times = [
        source.last_collected_at
        for source in sources.values()
        if source.last_collected_at is not None
    ]
    if collection_times:
        agent.last_collection_at = max(_utc(item) for item in collection_times if item)

    active_source_error = any(
        source.status is AgentSourceStatus.ERROR for source in sources.values() if source.enabled
    )
    if not payload.errors and not active_source_error:
        agent.last_error = None
        agent.last_error_at = None

    session.add(
        AgentHeartbeat(
            agent_id=agent.id,
            investigation_id=agent.investigation_id,
            agent_reported_at=payload.reported_at,
            received_at=now,
            runtime_status=AgentRuntimeStatus(payload.runtime_status),
            heartbeat_interval_seconds=agent.heartbeat_interval_seconds,
            collection_interval_seconds=agent.collection_interval_seconds,
            measured_clock_offset_seconds=agent.measured_clock_offset_seconds,
            queue_pending_batches=payload.queue_pending_batches,
            queue_pending_bytes=payload.queue_pending_bytes,
            source_count=len(payload.sources),
            sources_json=[report.model_dump(mode="json") for report in payload.sources],
            metadata_json={
                "ignored_sources": ignored,
                "errors_reported": len(payload.errors),
                "previous_heartbeat_at": (
                    previous_heartbeat.isoformat() if previous_heartbeat else None
                ),
                "recovered": recovered,
            },
        )
    )

    session.commit()
    session.refresh(agent)
    return AgentHeartbeatResponse(
        acknowledged=True,
        agent_health=get_agent_health(agent, now, settings.agent_stale_after_seconds),
        server_time=now,
        stale_after_seconds=settings.agent_stale_after_seconds,
        ignored_sources=ignored,
        errors_recorded=len(payload.errors),
    )


def agent_health_summary(
    session: Session, settings: Settings
) -> AgentHealthSummary:
    now = utcnow()
    agents = session.scalars(select(Agent)).all()
    counts = {
        AgentHealth.ONLINE: 0,
        AgentHealth.STALE: 0,
        AgentHealth.NEVER_SEEN: 0,
        AgentHealth.DISABLED: 0,
    }
    for agent in agents:
        counts[get_agent_health(agent, now, settings.agent_stale_after_seconds)] += 1

    agents_with_errors = sum(1 for agent in agents if agent.last_error is not None)
    pending_batches = sum(agent.queue_pending_batches for agent in agents)
    pending_bytes = sum(agent.queue_pending_bytes for agent in agents)

    if not agents:
        overall = "empty"
    elif counts[AgentHealth.STALE] or counts[AgentHealth.NEVER_SEEN] or agents_with_errors:
        overall = "degraded"
    else:
        overall = "ok"

    return AgentHealthSummary(
        status=overall,
        stale_after_seconds=settings.agent_stale_after_seconds,
        server_time=now,
        total_agents=len(agents),
        online=counts[AgentHealth.ONLINE],
        stale=counts[AgentHealth.STALE],
        never_seen=counts[AgentHealth.NEVER_SEEN],
        disabled=counts[AgentHealth.DISABLED],
        agents_with_errors=agents_with_errors,
        pending_batches=pending_batches,
        pending_bytes=pending_bytes,
    )


def agent_me(session: Session, settings: Settings, agent: Agent) -> AgentMeResponse:
    now = utcnow()
    sources = session.scalars(
        select(AgentSource)
        .where(AgentSource.agent_id == agent.id)
        .order_by(AgentSource.source_key.asc())
    ).all()
    return AgentMeResponse(
        agent_id=agent.id,
        agent_uid=agent.agent_uid,
        display_name=agent.display_name,
        investigation_id=agent.investigation_id,
        status=agent.status,
        health=get_agent_health(agent, now, settings.agent_stale_after_seconds),
        stale_after_seconds=settings.agent_stale_after_seconds,
        server_time=now,
        sources=[AgentSourceRead.model_validate(source) for source in sources],
        metadata=agent.metadata_json or {},
    )


def load_recent_errors(
    session: Session, agent_id: uuid.UUID, limit: int = 10
) -> list[AgentError]:
    return list(
        session.scalars(
            select(AgentError)
            .where(AgentError.agent_id == agent_id)
            .order_by(AgentError.reported_at.desc(), AgentError.id.desc())
            .limit(limit)
        ).all()
    )


def load_recent_batches(
    session: Session, agent_id: uuid.UUID, limit: int = 10
) -> list[AgentBatch]:
    return list(
        session.scalars(
            select(AgentBatch)
            .where(AgentBatch.agent_id == agent_id)
            .order_by(AgentBatch.received_at.desc())
            .limit(limit)
        ).all()
    )


def load_recent_heartbeats(
    session: Session, agent_id: uuid.UUID, limit: int = 20
) -> list[AgentHeartbeat]:
    return list(
        session.scalars(
            select(AgentHeartbeat)
            .where(AgentHeartbeat.agent_id == agent_id)
            .order_by(AgentHeartbeat.received_at.desc(), AgentHeartbeat.id.desc())
            .limit(limit)
        ).all()
    )
