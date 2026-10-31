"""Collection coverage, heartbeat history and gap accounting."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.constants import (
    AgentHealth,
    AgentSourceStatus,
    AgentStatus,
    CollectionGapReason,
    CollectionGapStatus,
    CollectionWindowStatus,
    CoverageState,
    GapBasis,
)
from app.models import (
    Agent,
    AgentSource,
    CollectionGap,
    EvidenceFile,
    EvidenceSource,
    ParsedEvent,
    SourceCollectionWindow,
)
from app.schemas import (
    CoverageAgentRead,
    CoverageGapRead,
    CoverageRead,
    CoverageSourceRead,
    CoverageSummaryRead,
)


def utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _max_time(current: datetime | None, candidate: datetime | None) -> datetime | None:
    current = utc(current)
    candidate = utc(candidate)
    if candidate is None:
        return current
    if current is None:
        return candidate
    return max(current, candidate)


def _min_time(current: datetime | None, candidate: datetime) -> datetime:
    current = utc(current)
    return candidate if current is None else min(current, candidate)


def ensure_open_gap(
    session: Session,
    *,
    investigation_id: uuid.UUID,
    agent: Agent | None,
    source: AgentSource | None,
    gap_start: datetime,
    reason: CollectionGapReason,
    basis: GapBasis,
    expected_interval_seconds: int | None,
    detail: dict[str, Any] | None = None,
) -> CollectionGap:
    """Create one open gap per agent/source scope, widening it if necessary."""

    conditions = [
        CollectionGap.investigation_id == investigation_id,
        CollectionGap.status == CollectionGapStatus.OPEN,
        CollectionGap.agent_id == (agent.id if agent else None),
    ]
    if source is not None:
        conditions.append(CollectionGap.agent_source_id == source.id)
    else:
        conditions.append(CollectionGap.agent_source_id.is_(None))
    existing = session.scalar(select(CollectionGap).where(*conditions).limit(1))
    gap_start = utc(gap_start) or gap_start
    if existing is not None:
        existing.gap_start = _min_time(existing.gap_start, gap_start)
        if detail:
            existing.detail = {**(existing.detail or {}), **detail}
        return existing

    gap = CollectionGap(
        investigation_id=investigation_id,
        agent_id=agent.id if agent else None,
        agent_source_id=source.id if source else None,
        gap_start=gap_start,
        gap_end=None,
        status=CollectionGapStatus.OPEN,
        reason=reason,
        basis=basis,
        expected_interval_seconds=expected_interval_seconds,
        detail=detail or {},
    )
    session.add(gap)
    session.flush()
    return gap


def close_open_gaps(
    session: Session,
    *,
    investigation_id: uuid.UUID,
    end: datetime,
    agent_id: uuid.UUID | None = None,
    agent_source_id: uuid.UUID | None = None,
    agent_level_only: bool = False,
    note: str | None = None,
) -> list[CollectionGap]:
    """Close matching open gaps and return them for recovery accounting."""

    conditions = [
        CollectionGap.investigation_id == investigation_id,
        CollectionGap.status == CollectionGapStatus.OPEN,
    ]
    if agent_id is not None:
        conditions.append(CollectionGap.agent_id == agent_id)
    if agent_source_id is not None:
        conditions.append(CollectionGap.agent_source_id == agent_source_id)
    if agent_level_only:
        conditions.append(CollectionGap.agent_source_id.is_(None))
    gaps = session.scalars(select(CollectionGap).where(*conditions)).all()
    end = utc(end) or end
    for gap in gaps:
        gap.status = CollectionGapStatus.CLOSED
        gap.gap_end = end
        gap.detail = {
            **(gap.detail or {}),
            "closed_at": end.isoformat(),
            "closed_note": note
            or "Collection resumed; this closes the observed/inferred gap interval.",
        }
    return list(gaps)


def record_collection_window(
    session: Session,
    *,
    investigation_id: uuid.UUID,
    agent: Agent,
    source: AgentSource,
    origin: str,
    status: CollectionWindowStatus,
    observed_at: datetime,
    started_at: datetime | None = None,
    ended_at: datetime | None = None,
    bytes_collected: int | None = None,
    lines_collected: int | None = None,
    expected_bytes: int | None = None,
    range_start: int | None = None,
    range_end: int | None = None,
    evidence_file_id: uuid.UUID | None = None,
    agent_batch_id: uuid.UUID | None = None,
    agent_batch_item_id: int | None = None,
    detail: dict[str, Any] | None = None,
) -> SourceCollectionWindow | None:
    """Record a collection attempt. Heartbeat repeats are deduplicated."""

    observed_at = utc(observed_at) or observed_at
    started_at = utc(started_at)
    ended_at = utc(ended_at)

    if origin == "heartbeat":
        if started_at is None and ended_at is None:
            return None
        conditions = [
            SourceCollectionWindow.agent_source_id == source.id,
            SourceCollectionWindow.origin == "heartbeat",
            SourceCollectionWindow.started_at == started_at,
            SourceCollectionWindow.ended_at == ended_at,
        ]
        existing = session.scalar(select(SourceCollectionWindow).where(*conditions).limit(1))
        if existing is not None:
            existing.observed_at = observed_at
            existing.bytes_collected = bytes_collected
            existing.lines_collected = lines_collected
            existing.expected_bytes = expected_bytes
            existing.detail = {**(existing.detail or {}), **(detail or {})}
            return existing

    window = SourceCollectionWindow(
        investigation_id=investigation_id,
        agent_id=agent.id,
        agent_source_id=source.id,
        evidence_file_id=evidence_file_id,
        agent_batch_id=agent_batch_id,
        agent_batch_item_id=agent_batch_item_id,
        origin=origin,
        status=status,
        started_at=started_at,
        ended_at=ended_at,
        observed_at=observed_at,
        bytes_collected=bytes_collected,
        lines_collected=lines_collected,
        expected_bytes=expected_bytes,
        range_start=range_start,
        range_end=range_end,
        detail=detail or {},
    )
    session.add(window)
    return window


def agent_health(agent: Agent, now: datetime, stale_after_seconds: int) -> AgentHealth:
    if agent.status is AgentStatus.DISABLED:
        return AgentHealth.DISABLED
    if agent.last_seen_at is None:
        return AgentHealth.NEVER_SEEN
    last_seen = utc(agent.last_seen_at) or agent.last_seen_at
    if (now - last_seen).total_seconds() > stale_after_seconds:
        return AgentHealth.STALE
    return AgentHealth.ONLINE


def _gap_read(
    gap: CollectionGap | None,
    *,
    agent_name: str | None,
    source_name: str | None,
    now: datetime,
    derived: bool = False,
    derived_detail: dict[str, Any] | None = None,
) -> CoverageGapRead | None:
    if gap is None:
        return None
    end = utc(gap.gap_end)
    duration = int(((end or now) - (utc(gap.gap_start) or gap.gap_start)).total_seconds())
    return CoverageGapRead(
        id=gap.id,
        derived=derived,
        scope="source" if gap.agent_source_id else "agent",
        agent_id=gap.agent_id,
        agent_name=agent_name,
        agent_source_id=gap.agent_source_id,
        source_key=None,
        source_name=source_name,
        gap_start=gap.gap_start,
        gap_end=gap.gap_end,
        status=gap.status,
        reason=gap.reason,
        basis=gap.basis,
        expected_interval_seconds=gap.expected_interval_seconds,
        duration_seconds=max(duration, 0),
        detail={**(gap.detail or {}), **(derived_detail or {})},
    )


def _derived_gap_read(
    *,
    investigation_id: uuid.UUID,
    agent: Agent,
    source: AgentSource | None,
    gap_start: datetime,
    reason: CollectionGapReason,
    basis: GapBasis,
    now: datetime,
    expected_interval_seconds: int | None,
    detail: dict[str, Any],
) -> CoverageGapRead:
    return CoverageGapRead(
        id=None,
        derived=True,
        scope="source" if source is not None else "agent",
        agent_id=agent.id,
        agent_name=agent.display_name,
        agent_source_id=source.id if source else None,
        source_key=source.source_key if source else None,
        source_name=source.name if source else None,
        gap_start=gap_start,
        gap_end=now,
        status=CollectionGapStatus.OPEN,
        reason=reason,
        basis=basis,
        expected_interval_seconds=expected_interval_seconds,
        duration_seconds=max(int((now - gap_start).total_seconds()), 0),
        detail={
            "investigation_id": str(investigation_id),
            "derived": True,
            "note": (
                "This open interval is synthesized from the last observed state and is "
                "not a persisted gap row. Its start is the last known evidence of "
                "collection, not a measured failure instant."
            ),
            **detail,
        },
    )


def build_investigation_coverage(
    session: Session,
    settings: Settings,
    *,
    investigation_id: uuid.UUID,
    window_start: datetime,
    window_end: datetime,
    now: datetime | None = None,
) -> CoverageRead:
    now = utc(now) or datetime.now(UTC)
    window_start = utc(window_start) or window_start
    window_end = utc(window_end) or window_end

    agents = list(
        session.scalars(
            select(Agent)
            .where(Agent.investigation_id == investigation_id)
            .order_by(Agent.display_name.asc(), Agent.id.asc())
        ).all()
    )
    agent_by_id = {agent.id: agent for agent in agents}
    agent_sources = list(
        session.scalars(
            select(AgentSource)
            .where(AgentSource.agent_id.in_([agent.id for agent in agents]))
            .order_by(AgentSource.name.asc())
        ).all()
        if agents
        else []
    )
    evidence_sources = list(
        session.scalars(
            select(EvidenceSource)
            .where(EvidenceSource.investigation_id == investigation_id)
            .order_by(EvidenceSource.name.asc())
        ).all()
    )


    windows = list(
        session.scalars(
            select(SourceCollectionWindow)
            .where(
                SourceCollectionWindow.investigation_id == investigation_id,
                SourceCollectionWindow.observed_at >= window_start,
                SourceCollectionWindow.observed_at <= window_end,
            )
            .order_by(SourceCollectionWindow.observed_at.asc())
        ).all()
    )
    windows_by_source: dict[uuid.UUID, list[SourceCollectionWindow]] = {}
    for window in windows:
        windows_by_source.setdefault(window.agent_source_id, []).append(window)

    gaps = list(
        session.scalars(
            select(CollectionGap)
            .where(CollectionGap.investigation_id == investigation_id)
            .order_by(CollectionGap.gap_start.desc(), CollectionGap.id.desc())
        ).all()
    )
    gaps_by_source: dict[uuid.UUID, list[CollectionGap]] = {}
    gaps_by_agent: dict[uuid.UUID, list[CollectionGap]] = {}
    for gap in gaps:
        if gap.agent_source_id:
            gaps_by_source.setdefault(gap.agent_source_id, []).append(gap)
        elif gap.agent_id:
            gaps_by_agent.setdefault(gap.agent_id, []).append(gap)

    event_counts = {
        source_id: int(count)
        for source_id, count in session.execute(
            select(EvidenceFile.source_id, func.count(ParsedEvent.id))
            .join(EvidenceFile, EvidenceFile.id == ParsedEvent.evidence_file_id)
            .where(
                ParsedEvent.investigation_id == investigation_id,
                EvidenceFile.collected_at >= window_start,
                EvidenceFile.collected_at <= window_end,
            )
            .group_by(EvidenceFile.source_id)
        ).all()
    }

    agent_reads: list[CoverageAgentRead] = []
    derived_gaps: list[CoverageGapRead] = []
    agent_open_gap: dict[uuid.UUID, CoverageGapRead] = {}
    health_by_agent: dict[uuid.UUID, AgentHealth] = {}
    for agent in agents:
        health = agent_health(agent, now, settings.agent_stale_after_seconds)
        health_by_agent[agent.id] = health
        expected_heartbeat = (
            agent.heartbeat_interval_seconds
            or settings.agent_default_heartbeat_interval_seconds
        )
        persisted_open = next(
            (
                gap
                for gap in gaps_by_agent.get(agent.id, [])
                if gap.status is CollectionGapStatus.OPEN
            ),
            None,
        )
        open_gap = _gap_read(
            persisted_open,
            agent_name=agent.display_name,
            source_name=None,
            now=now,
        )
        if (
            open_gap is None
            and health is AgentHealth.STALE
            and agent.last_heartbeat_at is not None
        ):
            open_gap = _derived_gap_read(
                investigation_id=investigation_id,
                agent=agent,
                source=None,
                gap_start=utc(agent.last_heartbeat_at) or agent.last_heartbeat_at,
                reason=CollectionGapReason.AGENT_OFFLINE,
                basis=GapBasis.OBSERVED,
                now=now,
                expected_interval_seconds=expected_heartbeat,
                detail={
                    "agent_health": health.value,
                    "last_heartbeat_at": agent.last_heartbeat_at.isoformat(),
                    "stale_after_seconds": settings.agent_stale_after_seconds,
                },
            )
            derived_gaps.append(open_gap)
        agent_open_gap[agent.id] = open_gap
        agent_reads.append(
            CoverageAgentRead(
                agent_id=agent.id,
                name=agent.display_name,
                hostname=agent.hostname,
                status=agent.status.value,
                health=health.value,
                last_heartbeat_at=agent.last_heartbeat_at,
                heartbeat_interval_seconds=agent.heartbeat_interval_seconds,
                collection_interval_seconds=agent.collection_interval_seconds,
                clock_offset_seconds=agent.measured_clock_offset_seconds,
                clock_offset_source=agent.clock_offset_source,
                reconnection_count=agent.reconnection_count,
                last_recovery_at=agent.last_recovery_at,
                source_count=sum(1 for source in agent_sources if source.agent_id == agent.id),
                open_gap=open_gap,
            )
        )

    source_reads: list[CoverageSourceRead] = []
    all_gap_reads: list[CoverageGapRead] = list(derived_gaps)
    for gap in gaps:
        agent = agent_by_id.get(gap.agent_id) if gap.agent_id else None
        source = next(
            (item for item in agent_sources if item.id == gap.agent_source_id), None
        )
        read = _gap_read(
            gap,
            agent_name=agent.display_name if agent else None,
            source_name=source.name if source else None,
            now=now,
        )
        if read is not None:
            all_gap_reads.append(read)

    for source in agent_sources:
        agent = agent_by_id.get(source.agent_id)
        if agent is None:
            continue
        health = health_by_agent.get(agent.id, AgentHealth.NEVER_SEEN)
        expected_interval = (
            source.expected_collection_interval_seconds
            or source.metadata_json.get("expected_collection_interval_seconds")
            or agent.collection_interval_seconds
            or settings.agent_default_collection_interval_seconds
        )
        source_windows = windows_by_source.get(source.id, [])
        observed_cycles = sum(
            1
            for window in source_windows
            if window.status
            in {
                CollectionWindowStatus.COMPLETED,
                CollectionWindowStatus.EMPTY,
                CollectionWindowStatus.DUPLICATE,
            }
        )
        expected_cycles = 0
        if source.enabled and expected_interval:
            effective_start = max(window_start, utc(source.created_at) or window_start)
            effective_end = min(window_end, now)
            if effective_end > effective_start:
                expected_cycles = int(
                    (effective_end - effective_start).total_seconds() // expected_interval
                )
        missing_cycles = max(expected_cycles - observed_cycles, 0)

        bytes_expected = sum(
            int(window.expected_bytes or 0) for window in source_windows
        )
        bytes_received = sum(
            int(window.bytes_collected or 0) for window in source_windows
        )
        no_events_observed = bool(
            source.last_cycle_bytes == 0
            and source.collection_available is not False
            and health is AgentHealth.ONLINE
        )
        clock_source = None
        clock_offset = source.clock_offset_seconds
        if source.clock_offset_seconds is not None:
            clock_source = "configured"
        elif agent.measured_clock_offset_seconds is not None:
            clock_offset = agent.measured_clock_offset_seconds
            clock_source = agent.clock_offset_source or "measured"

        persisted_source_gap = next(
            (
                gap
                for gap in gaps_by_source.get(source.id, [])
                if gap.status is CollectionGapStatus.OPEN
            ),
            None,
        )
        open_gap = _gap_read(
            persisted_source_gap,
            agent_name=agent.display_name,
            source_name=source.name,
            now=now,
        )
        recent_gaps = [
            gap_read
            for gap_read in (
                _gap_read(
                    gap,
                    agent_name=agent.display_name,
                    source_name=source.name,
                    now=now,
                )
                for gap in gaps_by_source.get(source.id, [])[:10]
            )
            if gap_read is not None
        ]

        if not source.enabled or source.status is AgentSourceStatus.DISABLED:
            state = CoverageState.DISABLED
            available: bool | None = False
            reason = "Collection is intentionally disabled for this source."
        elif agent.status is AgentStatus.DISABLED:
            state = CoverageState.DISABLED
            available = False
            reason = "The agent is administratively disabled."
        elif health is AgentHealth.NEVER_SEEN:
            state = CoverageState.NOT_REPORTING
            available = False
            reason = (
                "The agent has never checked in, so collection coverage cannot be "
                "established. This is not evidence that no activity occurred."
            )
        elif health is AgentHealth.STALE:
            state = CoverageState.NOT_REPORTING
            available = False
            reason = (
                f"The agent has not checked in within {settings.agent_stale_after_seconds} "
                "seconds. Coverage is unknown, not proven absent."
            )
        elif source.status is AgentSourceStatus.ERROR or source.collection_available is False:
            state = CoverageState.ERROR
            available = False
            reason = (
                source.last_error
                or "The agent reported that collection is unavailable."
            )
        elif source.status is AgentSourceStatus.UNKNOWN:
            state = CoverageState.UNKNOWN
            available = None
            reason = (
                "The agent is online but has not reported a completed collection cycle yet."
            )
        elif no_events_observed:
            state = CoverageState.IDLE
            available = True
            reason = (
                "Collection ran and observed zero bytes. No events were reported for this "
                "cycle; this is not a claim about network or host activity."
            )
        else:
            state = CoverageState.REPORTING
            available = True
            reason = None

        if open_gap is None and state is CoverageState.ERROR:
            start = (
                utc(source.last_success_at)
                or utc(source.last_seen_at)
                or utc(source.last_error_at)
                or now
            )
            open_gap = _derived_gap_read(
                investigation_id=investigation_id,
                agent=agent,
                source=source,
                gap_start=start,
                reason=CollectionGapReason.SOURCE_ERROR,
                basis=GapBasis.INFERRED,
                now=now,
                expected_interval_seconds=expected_interval,
                detail={
                    "last_success_at": (
                        source.last_success_at.isoformat()
                        if source.last_success_at
                        else None
                    ),
                    "last_error": source.last_error,
                },
            )
            all_gap_reads.append(open_gap)
        source_open_gap = open_gap or agent_open_gap.get(agent.id)

        source_reads.append(
            CoverageSourceRead(
                agent_source_id=source.id,
                inventory_origin="agent",
                agent_id=agent.id,
                agent_name=agent.display_name,
                agent_health=health.value,
                source_key=source.source_key,
                name=source.name,
                source_type=source.source_type,
                enabled=source.enabled,
                status=source.status.value,
                coverage_state=state,
                collection_available=available,
                collection_unavailable_reason=reason,
                last_heartbeat_at=agent.last_heartbeat_at,
                last_success_at=source.last_success_at,
                last_collection_started_at=source.last_collection_started_at,
                last_collection_ended_at=source.last_collection_ended_at,
                last_cycle_bytes=source.last_cycle_bytes,
                last_cycle_lines=source.last_cycle_lines,
                clock_offset_seconds=clock_offset,
                clock_offset_source=clock_source,
                expected_interval_seconds=expected_interval,
                expected_cycles=expected_cycles,
                observed_cycles=observed_cycles,
                missing_cycles=missing_cycles,
                bytes_expected=bytes_expected,
                bytes_received=bytes_received,
                bytes_missing=max(bytes_expected - bytes_received, 0),
                events_observed=event_counts.get(source.evidence_source_id, 0),
                no_events_observed=no_events_observed,
                recovery_count=source.recovery_count,
                last_recovery_at=source.last_recovery_at,
                open_gap=source_open_gap,
                recent_gaps=recent_gaps,
            )
        )

    mapped_evidence_source_ids = {
        source.evidence_source_id for source in agent_sources if source.evidence_source_id
    }
    for evidence_source in evidence_sources:
        if evidence_source.id in mapped_evidence_source_ids:
            continue
        source_reads.append(
            CoverageSourceRead(
                agent_source_id=None,
                inventory_origin="manual_upload",
                agent_id=None,
                agent_name=None,
                agent_health=None,
                source_key=None,
                name=evidence_source.name,
                source_type=evidence_source.source_type,
                enabled=True,
                status="unknown",
                coverage_state=CoverageState.UNKNOWN,
                collection_available=None,
                collection_unavailable_reason=(
                    "No agent collection schedule is registered for this source; "
                    "coverage cannot be inferred from manual uploads."
                ),
                last_heartbeat_at=None,
                last_success_at=None,
                last_collection_started_at=None,
                last_collection_ended_at=None,
                last_cycle_bytes=None,
                last_cycle_lines=None,
                clock_offset_seconds=None,
                clock_offset_source=None,
                expected_interval_seconds=None,
                expected_cycles=0,
                observed_cycles=0,
                missing_cycles=0,
                bytes_expected=0,
                bytes_received=0,
                bytes_missing=0,
                events_observed=event_counts.get(evidence_source.id, 0),
                no_events_observed=False,
                recovery_count=0,
                last_recovery_at=None,
                open_gap=None,
                recent_gaps=[],
            )
        )

    state_counts = {state: 0 for state in CoverageState}
    for read in source_reads:
        state_counts[read.coverage_state] += 1
    open_gaps = sum(
        1 for gap in all_gap_reads if gap.status is CollectionGapStatus.OPEN
    )
    closed_gaps = sum(
        1 for gap in all_gap_reads if gap.status is CollectionGapStatus.CLOSED
    )
    evaluable = state_counts[CoverageState.REPORTING] + state_counts[CoverageState.IDLE]
    coverage_available = state_counts[CoverageState.NOT_REPORTING] == 0 and (
        state_counts[CoverageState.ERROR] == 0
    )

    all_gap_reads.sort(key=lambda item: item.gap_start, reverse=True)
    return CoverageRead(
        investigation_id=investigation_id,
        generated_at=now,
        window_start=window_start,
        window_end=window_end,
        summary=CoverageSummaryRead(
            registered_sources=len(source_reads),
            reporting_sources=state_counts[CoverageState.REPORTING],
            idle_sources=state_counts[CoverageState.IDLE],
            not_reporting_sources=state_counts[CoverageState.NOT_REPORTING],
            error_sources=state_counts[CoverageState.ERROR],
            disabled_sources=state_counts[CoverageState.DISABLED],
            unknown_sources=state_counts[CoverageState.UNKNOWN],
            open_gaps=open_gaps,
            closed_gaps=closed_gaps,
            no_events_observed_sources=sum(
                1 for read in source_reads if read.no_events_observed
            ),
            coverage_available=coverage_available,
            coverage_evaluable_sources=evaluable,
        ),
        agents=agent_reads,
        sources=source_reads,
        gaps=all_gap_reads,
        note=(
            "Coverage reflects reported collection cycles and byte ranges. "
            "'no events observed' means a completed collection cycle reported zero new "
            "bytes; it is not evidence that no host activity occurred. Sources without "
            "a registered agent schedule are marked unknown rather than healthy."
        ),
    )


def default_coverage_window(settings: Settings, now: datetime) -> tuple[datetime, datetime]:
    return now - timedelta(hours=settings.quality_default_window_hours), now
