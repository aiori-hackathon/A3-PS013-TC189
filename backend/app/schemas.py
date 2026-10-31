"""Pydantic API schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.constants import (
    CollectionGapReason,
    CollectionGapStatus,
    CoverageState,
    DuplicateStatus,
    EventCategory,
    EventType,
    EvidenceStatus,
    GapBasis,
    IntegrityStatus,
    IssueSeverity,
    OrderingStatus,
    ParsingStatus,
    SourceType,
    TimestampStatus,
)


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class InvestigationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("description")
    @classmethod
    def _strip_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class InvestigationRead(APIModel):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime
    updated_at: datetime
    source_count: int = 0
    evidence_count: int = 0
    event_count: int = 0


class EvidenceSourceRead(APIModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    name: str
    source_type: SourceType
    hostname: str | None
    ip_address: str | None
    description: str | None
    created_at: datetime


class EvidenceHashRead(APIModel):
    id: uuid.UUID
    algorithm: str
    hash_value: str
    computed_at: datetime
    verified: bool | None
    verified_at: datetime | None
    verification_note: str | None


class ParsingResultRead(APIModel):
    id: uuid.UUID
    parser_name: str | None
    parser_version: str | None
    status: ParsingStatus
    total_lines: int
    blank_lines: int
    records_received: int = 0
    parsed_records: int
    records_rejected: int = 0
    malformed_records: int
    unsupported_records: int
    unsupported_formats: int = 0
    missing_required_fields: int = 0
    missing_optional_fields: int = 0
    parser_errors: int = 0
    duplicate_records: int = 0
    timestamp_flagged_records: int
    encoding_error_lines: int
    ordering_tied_records: int = 0
    ordering_unresolved_records: int = 0
    issues_recorded: int
    issues_suppressed: int
    fatal_error: str | None
    started_at: datetime
    completed_at: datetime | None
    duration_ms: int | None


class EvidenceRead(APIModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    source_id: uuid.UUID
    original_filename: str
    sha256: str
    size_bytes: int
    content_type: str | None
    source_type: SourceType
    status: EvidenceStatus
    collected_at: datetime
    received_at: datetime
    timezone_hint: str | None
    default_year: int | None
    clock_offset_seconds: int | None
    notes: str | None
    parser_name: str | None
    duplicate_of_evidence_id: uuid.UUID | None
    integrity_status: IntegrityStatus
    last_verified_at: datetime | None
    last_verification_source: str | None
    verification_count: int
    source: EvidenceSourceRead
    hashes: list[EvidenceHashRead]
    parsing_result: ParsingResultRead | None = None
    event_count: int = 0
    download_url: str | None = None
    verify_url: str | None = None
    issues_url: str | None = None
    manifest_url: str | None = None
    audit_url: str | None = None
    verifications_url: str | None = None


class EvidenceListPage(BaseModel):
    items: list[EvidenceRead]
    total: int
    limit: int
    offset: int


class ParsingIssueRead(APIModel):
    id: int
    evidence_file_id: uuid.UUID
    line_number: int | None
    byte_offset: int | None
    raw_line: str | None
    issue_type: str
    severity: IssueSeverity
    message: str
    created_at: datetime


class ParsingIssuePage(BaseModel):
    items: list[ParsingIssueRead]
    total: int
    limit: int
    offset: int


class EvidenceStatusRead(BaseModel):
    evidence_id: uuid.UUID
    status: EvidenceStatus
    parser_name: str | None
    parsing_result: ParsingResultRead | None
    event_count: int
    issue_counts_by_type: dict[str, int]
    issue_counts_by_severity: dict[str, int]
    timestamp_status_counts: dict[str, int]


class VerifyHashResponse(BaseModel):
    evidence_id: uuid.UUID
    algorithm: str
    expected_sha256: str
    actual_sha256: str
    match: bool
    outcome: IntegrityStatus
    source: str
    verified_at: datetime
    note: str


class TimelineEventRead(BaseModel):
    id: int
    evidence_file_id: uuid.UUID
    evidence_filename: str
    evidence_download_url: str
    evidence_collected_at: datetime
    evidence_received_at: datetime
    evidence_sha256: str
    evidence_size_bytes: int
    evidence_status: EvidenceStatus
    evidence_integrity_status: IntegrityStatus
    evidence_last_verified_at: datetime | None
    source_id: uuid.UUID
    source_name: str
    source_type: SourceType
    source_hostname: str | None
    investigation_id: uuid.UUID
    line_number: int
    byte_offset: int
    raw_line: str
    event_category: EventCategory
    event_type: str
    hostname: str | None
    source_ip: str | None
    username: str | None
    process: str | None
    pid: int | None
    message: str | None
    http_method: str | None
    http_path: str | None
    http_status: int | None
    http_bytes: int | None
    http_referer: str | None
    http_user_agent: str | None
    original_timestamp_string: str | None
    original_timezone: str | None
    timestamp_utc: datetime | None
    timestamp_status: TimestampStatus
    timestamp_detail: str | None
    timestamp_precision: str | None
    clock_offset_seconds: int | None
    clock_offset_applied: bool
    ordering_status: OrderingStatus
    ordering_note: str | None
    fingerprint_sha256: str | None
    dedup_status: DuplicateStatus
    duplicate_of_event_id: int | None
    extra: dict[str, Any]


class TimelinePage(BaseModel):
    items: list[TimelineEventRead]
    total: int
    limit: int
    offset: int
    sort: Literal["asc", "desc"]
    ordering_rule: str


class InvestigationSummaryRead(BaseModel):
    investigation_id: uuid.UUID
    sources: int
    evidence_files: int
    events: int
    earliest_collected_at: datetime | None = None
    latest_collected_at: datetime | None = None
    total_lines: int
    records_received: int = 0
    parsed_records: int
    records_rejected: int = 0
    malformed_records: int
    unsupported_records: int
    unsupported_formats: int = 0
    missing_required_fields: int = 0
    missing_optional_fields: int = 0
    parser_errors: int = 0
    duplicate_records: int = 0
    unique_events: int = 0
    blank_lines: int
    timestamp_flagged_records: int
    ordering_tied_records: int = 0
    ordering_unresolved_records: int = 0
    integrity_verified: int = 0
    integrity_mismatched: int = 0
    integrity_missing: int = 0
    integrity_unverified: int = 0
    audit_events: int = 0
    events_by_source_type: dict[str, int]
    events_by_event_type: dict[str, int]
    timestamp_status_counts: dict[str, int]
    evidence_status_counts: dict[str, int]
    parsing_status_counts: dict[str, int]
    issue_counts_by_type: dict[str, int]
    issues_total: int
    hashes_verified: int
    hashes_mismatched: int
    hashes_unverified: int


class EventTypeOption(BaseModel):
    event_type: str
    count: int


class HealthRead(BaseModel):
    status: str
    database: str
    schema_status: str
    storage: str
    version: str


class ReparseResponse(BaseModel):
    evidence: EvidenceRead
    message: str


class OperationMessage(BaseModel):
    message: str


class EvidenceVerificationRead(APIModel):
    id: int
    evidence_file_id: uuid.UUID
    algorithm: str
    expected_sha256: str
    actual_sha256: str | None
    outcome: IntegrityStatus
    source: str
    actor_type: str
    actor_detail: str | None
    note: str | None
    duration_ms: int | None
    verified_at: datetime


class VerificationPage(BaseModel):
    items: list[EvidenceVerificationRead]
    total: int
    limit: int
    offset: int


class EvidenceAuditEventRead(APIModel):
    id: int
    investigation_id: uuid.UUID
    evidence_file_id: uuid.UUID | None
    event_type: str
    actor_type: str
    actor_detail: str | None
    request_id: str | None
    evidence_filename: str | None
    evidence_sha256: str | None
    occurred_at: datetime
    detail: dict[str, Any]


class AuditPage(BaseModel):
    items: list[EvidenceAuditEventRead]
    total: int
    limit: int
    offset: int


class ManifestItemRead(BaseModel):
    evidence_id: str
    filename: str
    sha256: str
    size_bytes: int
    stored_relative_path: str
    source_id: str
    source_type: str
    collected_at: str | None
    received_at: str | None
    integrity_status: str
    verification_count: int
    last_verified_at: str | None
    last_verification_source: str | None
    duplicate_of_evidence_id: str | None


class ManifestRead(BaseModel):
    scope: str
    investigation_id: uuid.UUID | None
    generated_at: datetime
    manifest_sha256: str
    item_count: int
    items: list[ManifestItemRead]
    note: str


class CoverageGapRead(BaseModel):
    id: int | None
    derived: bool = False
    scope: str
    agent_id: uuid.UUID | None
    agent_name: str | None
    agent_source_id: uuid.UUID | None
    source_key: str | None
    source_name: str | None
    gap_start: datetime
    gap_end: datetime | None
    status: CollectionGapStatus
    reason: CollectionGapReason
    basis: GapBasis
    expected_interval_seconds: int | None
    duration_seconds: int | None
    detail: dict[str, Any]


class CoverageSourceRead(BaseModel):
    agent_source_id: uuid.UUID | None
    inventory_origin: str
    agent_id: uuid.UUID | None
    agent_name: str | None
    agent_health: str | None
    source_key: str | None
    name: str
    source_type: SourceType
    enabled: bool
    status: str
    coverage_state: CoverageState
    collection_available: bool | None
    collection_unavailable_reason: str | None
    last_heartbeat_at: datetime | None
    last_success_at: datetime | None
    last_collection_started_at: datetime | None
    last_collection_ended_at: datetime | None
    last_cycle_bytes: int | None
    last_cycle_lines: int | None
    clock_offset_seconds: int | None
    clock_offset_source: str | None
    expected_interval_seconds: int | None
    expected_cycles: int
    observed_cycles: int
    missing_cycles: int
    bytes_expected: int
    bytes_received: int
    bytes_missing: int
    events_observed: int
    no_events_observed: bool
    recovery_count: int
    last_recovery_at: datetime | None
    open_gap: CoverageGapRead | None
    recent_gaps: list[CoverageGapRead]


class CoverageAgentRead(BaseModel):
    agent_id: uuid.UUID
    name: str
    hostname: str
    status: str
    health: str
    last_heartbeat_at: datetime | None
    heartbeat_interval_seconds: int | None
    collection_interval_seconds: int | None
    clock_offset_seconds: int | None
    clock_offset_source: str | None
    reconnection_count: int
    last_recovery_at: datetime | None
    source_count: int
    open_gap: CoverageGapRead | None


class CoverageSummaryRead(BaseModel):
    registered_sources: int
    reporting_sources: int
    idle_sources: int
    not_reporting_sources: int
    error_sources: int
    disabled_sources: int
    unknown_sources: int
    open_gaps: int
    closed_gaps: int
    no_events_observed_sources: int
    coverage_available: bool
    coverage_evaluable_sources: int


class CoverageRead(BaseModel):
    investigation_id: uuid.UUID
    generated_at: datetime
    window_start: datetime
    window_end: datetime
    summary: CoverageSummaryRead
    agents: list[CoverageAgentRead]
    sources: list[CoverageSourceRead]
    gaps: list[CoverageGapRead]
    note: str


class GapPage(BaseModel):
    investigation_id: uuid.UUID
    generated_at: datetime
    items: list[CoverageGapRead]
    total: int


class ParsingQualityItemRead(BaseModel):
    evidence_id: uuid.UUID
    filename: str
    source_id: uuid.UUID
    source_name: str
    received_at: datetime
    clock_offset_seconds: int | None
    parsing_result: ParsingResultRead | None


class ParsingQualityRead(BaseModel):
    investigation_id: uuid.UUID
    generated_at: datetime
    items: list[ParsingQualityItemRead]
    totals: dict[str, int]
    evidence_with_issues: int
    evidence_without_parser: int


class TimestampEventRead(BaseModel):
    event_id: int
    evidence_id: uuid.UUID
    evidence_filename: str
    line_number: int
    source_name: str
    event_type: str
    timestamp_utc: datetime | None
    original_timestamp_string: str | None
    timestamp_status: TimestampStatus
    timestamp_detail: str | None
    timestamp_precision: str | None
    clock_offset_seconds: int | None
    clock_offset_applied: bool
    ordering_status: OrderingStatus


class TimestampQualityRead(BaseModel):
    investigation_id: uuid.UUID
    generated_at: datetime
    total_events: int
    normalized_events: int
    uncertain_events: int
    timestamp_status_counts: dict[str, int]
    ordering_status_counts: dict[str, int]
    timestamp_rule: str
    ordering_rule: str
    clock_offset_events: int
    uncertain_samples: list[TimestampEventRead]


class IntegrityEvidenceRead(BaseModel):
    evidence_id: uuid.UUID
    filename: str
    sha256: str
    size_bytes: int
    integrity_status: IntegrityStatus
    verification_count: int
    last_verified_at: datetime | None
    last_verification_source: str | None
    download_url: str
    verify_url: str
    manifest_url: str
    verifications_url: str
    audit_url: str


class IntegrityQualityRead(BaseModel):
    investigation_id: uuid.UUID
    generated_at: datetime
    integrity_status_counts: dict[str, int]
    evidence_count: int
    verified_evidence: int
    unverified_evidence: int
    mismatched_evidence: int
    missing_evidence: int
    items: list[IntegrityEvidenceRead]
    note: str


class DuplicateEventRead(BaseModel):
    event_id: int
    evidence_id: uuid.UUID
    evidence_filename: str
    line_number: int
    source_id: uuid.UUID
    source_name: str
    event_type: str
    timestamp_utc: datetime | None
    timestamp_status: TimestampStatus
    dedup_status: DuplicateStatus
    duplicate_of_event_id: int | None


class DuplicateGroupRead(BaseModel):
    fingerprint_sha256: str
    event_count: int
    canonical_event: DuplicateEventRead
    duplicate_events: list[DuplicateEventRead]


class ReconciliationRunRead(APIModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    status: str
    scope: str
    events_scanned: int
    duplicate_events: int
    duplicate_groups: int
    actor_type: str
    actor_detail: str | None
    started_at: datetime
    completed_at: datetime | None
    detail: dict[str, Any]


class DuplicateQualityRead(BaseModel):
    investigation_id: uuid.UUID
    generated_at: datetime
    total_events: int
    unique_events: int
    duplicate_events: int
    duplicate_groups: int
    groups: list[DuplicateGroupRead]
    last_reconciliation: ReconciliationRunRead | None
    note: str


class ReconcileResponse(BaseModel):
    run: ReconciliationRunRead
    total_events: int
    unique_events: int
    duplicate_events: int
    duplicate_groups: int


class QualityOverviewInvestigationRead(BaseModel):
    investigation_id: uuid.UUID
    name: str
    source_count: int
    registered_sources: int
    reporting_sources: int
    idle_sources: int
    not_reporting_sources: int
    error_sources: int
    disabled_sources: int
    unknown_sources: int
    coverage_state: CoverageState
    open_gaps: int
    duplicate_events: int
    timestamp_uncertain_events: int
    integrity_mismatched: int
    integrity_unverified: int
    audit_events: int


class QualityOverviewRead(BaseModel):
    generated_at: datetime
    investigations: list[QualityOverviewInvestigationRead]
    totals: dict[str, int]
    note: str


class CorrelationMemberRead(BaseModel):
    correlation_id: uuid.UUID
    event_id: int
    role: str
    evidence_file_id: uuid.UUID
    evidence_filename: str
    source_id: uuid.UUID
    source_name: str
    source_type: SourceType
    event_type: str
    event_category: EventCategory
    timestamp_utc: datetime | None
    timestamp_status: TimestampStatus
    timestamp_detail: str | None
    hostname: str | None
    source_ip: str | None
    username: str | None
    original_timestamp_string: str | None
    raw_line: str
    evidence_sha256: str


class CorrelationRead(BaseModel):
    id: uuid.UUID
    investigation_id: uuid.UUID
    rule_id: str
    rule_name: str
    rule_description: str | None
    correlation_type: str
    confidence: str
    title: str
    explanation: str
    matching_fields: list[str]
    time_relationship: str | None
    timestamp_uncertainty: str | None
    status: str
    dismissed_at: datetime | None
    dismissed_by: str | None
    dismissal_reason: str | None
    created_at: datetime
    updated_at: datetime
    source_systems: list[str]
    event_ids: list[int]
    events: list[CorrelationMemberRead]


class CorrelationRunResponse(BaseModel):
    investigation_id: uuid.UUID
    created: int
    updated: int
    preserved_dismissed: int
    total: int
    time_window_seconds: int
    items: list[CorrelationRead]


class CorrelationDismissRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason must not be blank")
        return value


def event_type_values() -> list[str]:
    return [item.value for item in EventType]
