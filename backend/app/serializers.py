"""ORM-to-schema serialization helpers."""

from __future__ import annotations

from app.config import Settings
from app.models import EvidenceFile, EvidenceSource, ParsedEvent
from app.schemas import EvidenceRead, TimelineEventRead


def evidence_read(evidence: EvidenceFile, settings: Settings, *, event_count: int = 0) -> EvidenceRead:
    payload = EvidenceRead.model_validate(evidence)
    return payload.model_copy(
        update={
            "event_count": event_count,
            "download_url": f"{settings.api_prefix}/evidence/{evidence.id}/download",
            "verify_url": f"{settings.api_prefix}/evidence/{evidence.id}/verify",
            "issues_url": f"{settings.api_prefix}/evidence/{evidence.id}/issues",
            "manifest_url": f"{settings.api_prefix}/evidence/{evidence.id}/manifest",
            "audit_url": f"{settings.api_prefix}/quality/evidence/{evidence.id}/audit",
            "verifications_url": f"{settings.api_prefix}/evidence/{evidence.id}/verifications",
        }
    )


def timeline_event_read(
    event: ParsedEvent,
    source: EvidenceSource,
    evidence: EvidenceFile,
    settings: Settings,
) -> TimelineEventRead:
    return TimelineEventRead(
        id=event.id,
        evidence_file_id=evidence.id,
        evidence_filename=evidence.original_filename,
        evidence_download_url=f"{settings.api_prefix}/evidence/{evidence.id}/download",
        evidence_collected_at=evidence.collected_at,
        evidence_received_at=evidence.received_at,
        evidence_sha256=evidence.sha256,
        evidence_size_bytes=evidence.size_bytes,
        evidence_status=evidence.status,
        evidence_integrity_status=evidence.integrity_status,
        evidence_last_verified_at=evidence.last_verified_at,
        source_id=source.id,
        source_name=source.name,
        source_type=source.source_type,
        source_hostname=source.hostname,
        investigation_id=event.investigation_id,
        line_number=event.line_number,
        byte_offset=event.byte_offset,
        raw_line=event.raw_line,
        event_category=event.event_category,
        event_type=event.event_type,
        hostname=event.hostname,
        source_ip=event.source_ip,
        username=event.username,
        process=event.process,
        pid=event.pid,
        message=event.message,
        http_method=event.http_method,
        http_path=event.http_path,
        http_status=event.http_status,
        http_bytes=event.http_bytes,
        http_referer=event.http_referer,
        http_user_agent=event.http_user_agent,
        original_timestamp_string=event.original_timestamp_string,
        original_timezone=event.original_timezone,
        timestamp_utc=event.timestamp_utc,
        timestamp_status=event.timestamp_status,
        timestamp_detail=event.timestamp_detail,
        timestamp_precision=event.timestamp_precision,
        clock_offset_seconds=event.clock_offset_seconds,
        clock_offset_applied=event.clock_offset_applied,
        ordering_status=event.ordering_status,
        ordering_note=event.ordering_note,
        fingerprint_sha256=event.fingerprint_sha256,
        dedup_status=event.dedup_status,
        duplicate_of_event_id=event.duplicate_of_event_id,
        extra=event.extra,
    )
