"""Transparent, rule-based cross-source event correlation.

This module deliberately avoids machine learning. Correlations are derived
suggestions: they link to the original parsed events but never modify them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.constants import (
    AuditEventType,
    CorrelationConfidence,
    CorrelationStatus,
    EventCategory,
)
from app.models import (
    EventCorrelation,
    EventCorrelationMember,
    EvidenceFile,
    EvidenceSource,
    ParsedEvent,
)
from app.services.quality import record_audit

DEFAULT_TIME_WINDOW_SECONDS = 1800
MIN_TIME_WINDOW_SECONDS = 60
MAX_TIME_WINDOW_SECONDS = 86400


RULES: list[dict[str, str]] = [
    {
        "rule_id": "auth_web_shared_identifier",
        "rule_name": "Authentication and web activity share an identifier",
        "correlation_type": "authentication_to_web",
        "description": (
            "An authentication event and a web-access event from different sources "
            "share a source IP address or username. Timestamps, when reliable, must "
            "fall within the configured window."
        ),
    },
    {
        "rule_id": "cross_source_shared_identifier",
        "rule_name": "Cross-source shared identifier",
        "correlation_type": "shared_identifier",
        "description": (
            "Events from different sources share a source IP address or username. "
            "This is a possible relationship only; it does not prove a common actor."
        ),
    },
    {
        "rule_id": "cross_source_shared_hostname",
        "rule_name": "Cross-source shared hostname",
        "correlation_type": "shared_hostname",
        "description": (
            "Events from different sources share a hostname. Hostname matches are "
            "weaker than IP or username matches and are reported as low confidence."
        ),
    },
]


def _norm(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().lower()
    return value or None


def _source_type_value(source: EvidenceSource) -> str:
    return getattr(source.source_type, "value", source.source_type)


def _load_events(session: Session, investigation_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = session.execute(
        select(ParsedEvent, EvidenceSource, EvidenceFile)
        .join(EvidenceSource, ParsedEvent.source_id == EvidenceSource.id)
        .join(EvidenceFile, ParsedEvent.evidence_file_id == EvidenceFile.id)
        .where(ParsedEvent.investigation_id == investigation_id)
    ).all()
    events: list[dict[str, Any]] = []
    for event, source, evidence in rows:
        events.append(
            {
                "event": event,
                "source": source,
                "evidence": evidence,
                "source_id": source.id,
                "source_type": _source_type_value(source),
                "source_name": source.name,
                "timestamp": event.timestamp_utc,
                "timestamp_status": getattr(event.timestamp_status, "value", event.timestamp_status),
                "timestamp_detail": event.timestamp_detail,
                "clock_offset_applied": event.clock_offset_applied,
                "clock_offset_seconds": event.clock_offset_seconds,
                "ip": _norm(event.source_ip),
                "username": _norm(event.username),
                "hostname": _norm(event.hostname),
            }
        )
    return events


def _shared_fields(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    if left["ip"] and left["ip"] == right["ip"]:
        fields.append("source_ip")
    if left["username"] and left["username"] == right["username"]:
        fields.append("username")
    if left["hostname"] and left["hostname"] == right["hostname"]:
        fields.append("hostname")
    return fields


def _time_delta_seconds(left: dict[str, Any], right: dict[str, Any]) -> int | None:
    if left["timestamp"] is None or right["timestamp"] is None:
        return None
    return int((right["timestamp"] - left["timestamp"]).total_seconds())


def _choose_rule(shared: list[str], left: dict[str, Any], right: dict[str, Any]) -> str:
    strong = [field for field in shared if field in {"source_ip", "username"}]
    if not strong:
        return "cross_source_shared_hostname"
    left_cat = getattr(left["event"].event_category, "value", left["event"].event_category)
    right_cat = getattr(right["event"].event_category, "value", right["event"].event_category)
    if {left_cat, right_cat} == {EventCategory.AUTHENTICATION.value, EventCategory.WEB_ACCESS.value}:
        return "auth_web_shared_identifier"
    return "cross_source_shared_identifier"


def _confidence(shared: list[str], left: dict[str, Any], right: dict[str, Any], delta: int | None, window: int) -> CorrelationConfidence:
    strong = [field for field in shared if field in {"source_ip", "username"}]
    cross_type = left["source_type"] != right["source_type"]
    if not strong:
        return CorrelationConfidence.LOW
    if left["timestamp"] is None or right["timestamp"] is None:
        return CorrelationConfidence.LOW
    if abs(delta or 0) <= 300 and cross_type:
        return CorrelationConfidence.HIGH
    if abs(delta or 0) <= window:
        return CorrelationConfidence.MEDIUM
    return CorrelationConfidence.LOW


def _time_relationship(left: dict[str, Any], right: dict[str, Any], delta: int | None) -> str:
    left_label = f"event {left['event'].id}"
    right_label = f"event {right['event'].id}"
    if delta is None:
        if left["timestamp"] is None and right["timestamp"] is None:
            return (
                "Neither event has a reliable UTC timestamp, so no time ordering is claimed."
            )
        return (
            "One event has no reliable UTC timestamp, so precise time ordering is not claimed."
        )
    if delta == 0:
        return f"{left_label} and {right_label} have the same normalized UTC timestamp."
    if delta > 0:
        return (
            f"{left_label} occurred {delta} second(s) before {right_label} "
            f"(within the configured time window)."
        )
    return (
        f"{right_label} occurred {abs(delta)} second(s) before {left_label} "
        f"(within the configured time window)."
    )


def _timestamp_uncertainty(left: dict[str, Any], right: dict[str, Any]) -> str:
    notes: list[str] = []
    for item in (left, right):
        status = item["timestamp_status"]
        if status != "normalized":
            detail = item["timestamp_detail"] or "no UTC timestamp available"
            notes.append(f"event {item['event'].id}: {status} ({detail})")
        if item["clock_offset_applied"]:
            notes.append(
                f"event {item['event'].id}: a configured clock offset of "
                f"{item['clock_offset_seconds']} seconds was applied to its UTC time"
            )
        elif item["clock_offset_seconds"] is not None:
            notes.append(
                f"event {item['event'].id}: a clock offset of "
                f"{item['clock_offset_seconds']} seconds was recorded but not applied"
            )
    if not notes:
        return "Both events have normalized UTC timestamps; no timestamp uncertainty recorded."
    notes.append("Missing or uncertain timestamps are not used as precise ordering evidence.")
    return " ".join(notes)


def _rule_lookup(rule_id: str) -> dict[str, str]:
    for rule in RULES:
        if rule["rule_id"] == rule_id:
            return rule
    return {"rule_id": rule_id, "rule_name": rule_id, "correlation_type": "unknown", "description": None}


def run_investigation_correlations(
    session: Session,
    investigation_id: uuid.UUID,
    *,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
    actor_type: str = "system",
    actor_detail: str | None = None,
    request_id: str | None = None,
) -> tuple[int, int, int, list[EventCorrelation]]:
    """Generate and persist suggested correlations. Returns counts and items."""

    window = max(MIN_TIME_WINDOW_SECONDS, min(MAX_TIME_WINDOW_SECONDS, int(time_window_seconds)))
    events = _load_events(session, investigation_id)
    existing = session.scalars(
        select(EventCorrelation).where(EventCorrelation.investigation_id == investigation_id)
    ).all()
    existing_by_pair: dict[frozenset[int], list[EventCorrelation]] = {}
    for correlation in existing:
        ids = frozenset(member.event_id for member in correlation.members)
        existing_by_pair.setdefault(ids, []).append(correlation)

    created = 0
    updated = 0
    preserved_dismissed = 0
    created_items: list[EventCorrelation] = []

    for left_index in range(len(events)):
        for right_index in range(left_index + 1, len(events)):
            left = events[left_index]
            right = events[right_index]
            if left["source_id"] == right["source_id"]:
                continue
            shared = _shared_fields(left, right)
            if not shared:
                continue
            strong = [field for field in shared if field in {"source_ip", "username"}]
            if not strong and "hostname" not in shared:
                continue
            delta = _time_delta_seconds(left, right)
            if delta is not None and abs(delta) > window:
                continue
            if delta is None and not strong:
                continue

            rule_id = _choose_rule(shared, left, right)
            rule = _rule_lookup(rule_id)
            confidence = _confidence(shared, left, right, delta, window)
            pair_ids = frozenset({left["event"].id, right["event"].id})
            dismissed_existing = [
                correlation
                for correlation in existing_by_pair.get(pair_ids, [])
                if correlation.rule_id == rule_id
                and correlation.status == CorrelationStatus.DISMISSED
            ]
            if dismissed_existing:
                preserved_dismissed += len(dismissed_existing)
                continue

            suggested_existing = [
                correlation
                for correlation in existing_by_pair.get(pair_ids, [])
                if correlation.rule_id == rule_id
                and correlation.status == CorrelationStatus.SUGGESTED
            ]

            time_relationship = _time_relationship(left, right, delta)
            uncertainty = _timestamp_uncertainty(left, right)
            title = (
                f"{rule['rule_name']}: {left['source_name']} "
                f"event {left['event'].id} and {right['source_name']} event {right['event'].id}"
            )
            explanation = (
                f"Possible correlation: events from {left['source_name']} and "
                f"{right['source_name']} share {', '.join(shared)}. "
                f"{time_relationship} {uncertainty} "
                "This is an inferred relationship based on matching fields; it does not "
                "prove a common actor or an attack."
            )
            matching_fields = shared

            if suggested_existing:
                correlation = suggested_existing[0]
                correlation.confidence = confidence
                correlation.title = title
                correlation.explanation = explanation
                correlation.matching_fields = matching_fields
                correlation.time_relationship = time_relationship
                correlation.timestamp_uncertainty = uncertainty
                correlation.parameters = {"time_window_seconds": window}
                updated += 1
            else:
                correlation = EventCorrelation(
                    investigation_id=investigation_id,
                    rule_id=rule_id,
                    rule_name=rule["rule_name"],
                    rule_description=rule.get("description"),
                    correlation_type=rule["correlation_type"],
                    confidence=confidence,
                    title=title,
                    explanation=explanation,
                    matching_fields=matching_fields,
                    time_relationship=time_relationship,
                    timestamp_uncertainty=uncertainty,
                    status=CorrelationStatus.SUGGESTED,
                    parameters={"time_window_seconds": window},
                )
                session.add(correlation)
                session.flush()
                session.add(
                    EventCorrelationMember(
                        correlation_id=correlation.id,
                        event_id=left["event"].id,
                        role="source_event",
                    )
                )
                session.add(
                    EventCorrelationMember(
                        correlation_id=correlation.id,
                        event_id=right["event"].id,
                        role="related_event",
                    )
                )
                created += 1
                created_items.append(correlation)

    session.flush()
    record_audit(
        session,
        investigation_id=investigation_id,
        event_type=AuditEventType.CORRELATIONS_GENERATED,
        actor_type=actor_type,
        actor_detail=actor_detail,
        request_id=request_id,
        detail={
            "time_window_seconds": window,
            "events_scanned": len(events),
            "created": created,
            "updated": updated,
            "preserved_dismissed": preserved_dismissed,
        },
    )
    return created, updated, preserved_dismissed, created_items


def list_correlations(session: Session, investigation_id: uuid.UUID) -> list[EventCorrelation]:
    return list(
        session.scalars(
            select(EventCorrelation)
            .where(EventCorrelation.investigation_id == investigation_id)
            .order_by(EventCorrelation.created_at.desc(), EventCorrelation.id.desc())
        ).all()
    )


def get_correlation(session: Session, correlation_id: uuid.UUID) -> EventCorrelation | None:
    return session.get(EventCorrelation, correlation_id)


def dismiss_correlation(
    session: Session,
    correlation: EventCorrelation,
    *,
    reason: str,
    actor_type: str = "api",
    actor_detail: str | None = None,
    request_id: str | None = None,
) -> EventCorrelation:
    correlation.status = CorrelationStatus.DISMISSED
    correlation.dismissed_at = datetime.now(UTC)
    correlation.dismissed_by = actor_detail or actor_type
    correlation.dismissal_reason = reason
    session.flush()
    record_audit(
        session,
        investigation_id=correlation.investigation_id,
        event_type=AuditEventType.CORRELATION_DISMISSED,
        actor_type=actor_type,
        actor_detail=actor_detail,
        request_id=request_id,
        detail={
            "correlation_id": str(correlation.id),
            "rule_id": correlation.rule_id,
            "reason": reason,
        },
    )
    return correlation
