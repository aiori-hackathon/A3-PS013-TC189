"""Pydantic schemas for endpoint agents, heartbeats and collection batches."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.constants import (
    AgentBatchItemStatus,
    AgentBatchStatus,
    AgentHealth,
    AgentRuntimeStatus,
    AgentSourceStatus,
    AgentStatus,
    SourceType,
)

AGENT_UID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"
SOURCE_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
BATCH_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
ITEM_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
ERROR_CODE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"
SAFE_FILENAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$"
SHA256_PATTERN = r"^[a-fA-F0-9]{64}$"

_CONTROL_RE = str.maketrans({chr(code): " " for code in range(32) if chr(code) not in "\t"})


class AgentAPIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


def _clean_text(value: str | None, *, max_length: int) -> str | None:
    if value is None:
        return None
    value = value.translate(_CONTROL_RE).strip()
    if not value:
        return None
    if len(value) > max_length:
        raise ValueError(f"value must be at most {max_length} characters")
    return value


def _require_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset or timezone")
    return value.astimezone(UTC)


class AgentSourceRegistration(BaseModel):
    key: str = Field(pattern=SOURCE_KEY_PATTERN)
    name: str = Field(min_length=1, max_length=200)
    source_type: Literal["linux_auth", "web_access"]
    path_hint: str | None = Field(default=None, max_length=512)
    timezone_hint: str | None = Field(default=None, max_length=64)
    default_year: int | None = Field(default=None, ge=1970, le=2100)
    enabled: bool = True
    clock_offset_seconds: int | None = Field(default=None, ge=-86400, le=86400)
    expected_collection_interval_seconds: int | None = Field(
        default=None, ge=5, le=86400
    )

    @field_validator("name")
    @classmethod
    def _clean_name(cls, value: str) -> str:
        cleaned = _clean_text(value, max_length=200)
        if not cleaned:
            raise ValueError("name must not be blank")
        return cleaned

    @field_validator("path_hint")
    @classmethod
    def _clean_path_hint(cls, value: str | None) -> str | None:
        return _clean_text(value, max_length=512)

    @field_validator("timezone_hint")
    @classmethod
    def _check_timezone(cls, value: str | None) -> str | None:
        value = _clean_text(value, max_length=64)
        if not value:
            return None
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("timezone_hint must be a valid IANA timezone name") from exc
        return value


class AgentRegisterRequest(BaseModel):
    agent_uid: str = Field(pattern=AGENT_UID_PATTERN)
    display_name: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=120)
    agent_version: str = Field(min_length=1, max_length=32)
    investigation_id: uuid.UUID
    sources: list[AgentSourceRegistration] = Field(default_factory=list, max_length=100)

    @field_validator("display_name", "hostname", "platform", "agent_version")
    @classmethod
    def _clean_registration_text(cls, value: str) -> str:
        cleaned = _clean_text(value, max_length=255)
        if not cleaned:
            raise ValueError("value must not be blank")
        return cleaned


class AgentRegisterResponse(BaseModel):
    agent_id: uuid.UUID
    agent_uid: str
    investigation_id: uuid.UUID
    agent_token: str
    token_prefix: str
    rotated: bool = False
    stale_after_seconds: int
    server_time: datetime


class AgentSourceSyncRequest(BaseModel):
    sources: list[AgentSourceRegistration] = Field(default_factory=list, max_length=100)

    @field_validator("sources")
    @classmethod
    def _unique_keys(cls, value: list[AgentSourceRegistration]) -> list[AgentSourceRegistration]:
        keys = [item.key for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("source keys must be unique")
        return value


class AgentSourceRead(AgentAPIModel):
    id: uuid.UUID
    source_key: str
    name: str
    source_type: SourceType
    path_hint: str | None
    timezone_hint: str | None
    default_year: int | None
    enabled: bool
    status: AgentSourceStatus
    evidence_source_id: uuid.UUID | None
    last_seen_at: datetime | None
    last_collected_at: datetime | None
    last_success_at: datetime | None
    last_error_at: datetime | None
    last_error: str | None
    cursor_bytes: int | None
    clock_offset_seconds: int | None
    expected_collection_interval_seconds: int | None
    collection_available: bool | None
    last_collection_started_at: datetime | None
    last_collection_ended_at: datetime | None
    last_cycle_bytes: int | None
    last_cycle_lines: int | None
    last_cycle_at: datetime | None
    observed_size_bytes: int | None
    last_recovery_at: datetime | None
    recovery_count: int


class AgentSourceListResponse(BaseModel):
    items: list[AgentSourceRead]


class AgentHeartbeatSource(BaseModel):
    key: str = Field(pattern=SOURCE_KEY_PATTERN)
    status: Literal["healthy", "error", "disabled", "unknown"] = "unknown"
    path_readable: bool | None = None
    last_collected_at: datetime | None = None
    last_success_at: datetime | None = None
    collection_started_at: datetime | None = None
    collection_ended_at: datetime | None = None
    cursor_bytes: int | None = Field(default=None, ge=0)
    observed_size_bytes: int | None = Field(default=None, ge=0)
    bytes_collected_last_cycle: int | None = Field(default=None, ge=0)
    lines_collected_last_cycle: int | None = Field(default=None, ge=0)
    collection_available: bool | None = None
    last_error: str | None = Field(default=None, max_length=2000)

    @field_validator(
        "last_collected_at",
        "last_success_at",
        "collection_started_at",
        "collection_ended_at",
    )
    @classmethod
    def _aware_collected_at(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)

    @field_validator("last_error")
    @classmethod
    def _clean_error(cls, value: str | None) -> str | None:
        return _clean_text(value, max_length=2000)


class AgentHeartbeatError(BaseModel):
    source_key: str | None = Field(default=None, pattern=SOURCE_KEY_PATTERN)
    code: str = Field(pattern=ERROR_CODE_PATTERN)
    message: str = Field(min_length=1, max_length=2000)
    occurred_at: datetime | None = None

    @field_validator("message")
    @classmethod
    def _clean_message(cls, value: str) -> str:
        cleaned = _clean_text(value, max_length=2000)
        if not cleaned:
            raise ValueError("message must not be blank")
        return cleaned

    @field_validator("occurred_at")
    @classmethod
    def _aware_occurred_at(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)


class AgentHeartbeatRequest(BaseModel):
    agent_version: str | None = Field(default=None, max_length=32)
    runtime_status: Literal["running", "degraded", "stopped", "unknown"] = "unknown"
    queue_pending_batches: int = Field(default=0, ge=0, le=1_000_000)
    queue_pending_bytes: int = Field(default=0, ge=0, le=1_000_000_000_000_000)
    heartbeat_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    collection_interval_seconds: int | None = Field(default=None, ge=5, le=86400)
    clock_offset_seconds: int | None = Field(default=None, ge=-86400, le=86400)
    clock_offset_source: Literal["measured", "configured", "unknown"] | None = None
    reported_at: datetime | None = None
    sources: list[AgentHeartbeatSource] = Field(default_factory=list, max_length=100)
    errors: list[AgentHeartbeatError] = Field(default_factory=list, max_length=100)

    @field_validator("agent_version")
    @classmethod
    def _clean_version(cls, value: str | None) -> str | None:
        return _clean_text(value, max_length=32)

    @field_validator("reported_at")
    @classmethod
    def _aware_reported_at(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)

    @field_validator("sources")
    @classmethod
    def _unique_source_keys(cls, value: list[AgentHeartbeatSource]) -> list[AgentHeartbeatSource]:
        keys = [item.key for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("source keys must be unique")
        return value


class AgentHeartbeatResponse(BaseModel):
    acknowledged: bool
    agent_health: AgentHealth
    server_time: datetime
    stale_after_seconds: int
    ignored_sources: list[str] = Field(default_factory=list)
    errors_recorded: int = 0


class AgentBatchItemManifest(BaseModel):
    item_id: str = Field(pattern=ITEM_ID_PATTERN)
    source_key: str = Field(pattern=SOURCE_KEY_PATTERN)
    source_type: Literal["linux_auth", "web_access"]
    filename: str = Field(pattern=SAFE_FILENAME_PATTERN)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(ge=0, le=1024 * 1024 * 1024)
    collected_at: datetime
    collection_started_at: datetime | None = None
    collection_ended_at: datetime | None = None
    lines_collected: int | None = Field(default=None, ge=0)
    range_start: int | None = Field(default=None, ge=0)
    range_end: int | None = Field(default=None, ge=0)

    @field_validator("sha256")
    @classmethod
    def _lower_sha(cls, value: str) -> str:
        return value.lower()

    @field_validator("collected_at")
    @classmethod
    def _aware_collected_at(cls, value: datetime) -> datetime:
        resolved = _require_aware(value)
        if resolved is None:
            raise ValueError("collected_at is required")
        if not 1970 <= resolved.year <= 2100:
            raise ValueError("collected_at is outside the supported range")
        return resolved

    @field_validator("collection_started_at", "collection_ended_at")
    @classmethod
    def _aware_collection_bounds(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)

    @model_validator(mode="after")
    def _valid_range(self) -> AgentBatchItemManifest:
        if (
            self.range_start is not None
            and self.range_end is not None
            and self.range_end < self.range_start
        ):
            raise ValueError("range_end must be greater than or equal to range_start")
        return self


class AgentBatchError(BaseModel):
    source_key: str | None = Field(default=None, pattern=SOURCE_KEY_PATTERN)
    code: str = Field(pattern=ERROR_CODE_PATTERN)
    message: str = Field(min_length=1, max_length=2000)
    occurred_at: datetime | None = None

    @field_validator("message")
    @classmethod
    def _clean_message(cls, value: str) -> str:
        cleaned = _clean_text(value, max_length=2000)
        if not cleaned:
            raise ValueError("message must not be blank")
        return cleaned

    @field_validator("occurred_at")
    @classmethod
    def _aware_occurred_at(cls, value: datetime | None) -> datetime | None:
        return _require_aware(value)


class AgentBatchManifest(BaseModel):
    batch_id: str = Field(pattern=BATCH_ID_PATTERN)
    investigation_id: uuid.UUID
    created_at: datetime
    agent_version: str | None = Field(default=None, max_length=32)
    items: list[AgentBatchItemManifest] = Field(default_factory=list, max_length=200)
    errors: list[AgentBatchError] = Field(default_factory=list, max_length=100)

    @field_validator("created_at")
    @classmethod
    def _aware_created_at(cls, value: datetime) -> datetime:
        resolved = _require_aware(value)
        if resolved is None:
            raise ValueError("created_at is required")
        return resolved

    @field_validator("agent_version")
    @classmethod
    def _clean_version(cls, value: str | None) -> str | None:
        return _clean_text(value, max_length=32)

    @model_validator(mode="after")
    def _unique_items(self) -> AgentBatchManifest:
        item_ids = [item.item_id for item in self.items]
        if len(item_ids) != len(set(item_ids)):
            raise ValueError("item_id values must be unique within a batch")
        return self


class AgentBatchItemResult(BaseModel):
    item_id: str
    source_key: str
    status: AgentBatchItemStatus
    evidence_id: uuid.UUID | None
    sha256: str
    size_bytes: int
    error_code: str | None = None
    message: str | None = None
    retryable: bool = False


class AgentBatchResult(BaseModel):
    batch_id: str
    agent_id: uuid.UUID
    investigation_id: uuid.UUID
    status: AgentBatchStatus
    replayed: bool = False
    received_at: datetime
    processed_at: datetime | None
    file_count: int
    byte_count: int
    accepted_items: int
    duplicate_items: int
    failed_items: int
    error_count: int
    items: list[AgentBatchItemResult] = Field(default_factory=list)
    errors_recorded: int = 0


class AgentErrorRead(AgentAPIModel):
    id: int
    source_id: uuid.UUID | None
    agent_batch_id: uuid.UUID | None
    error_code: str
    message: str
    occurred_at: datetime
    reported_at: datetime


class AgentBatchSummary(AgentAPIModel):
    id: uuid.UUID
    batch_id: str
    status: AgentBatchStatus
    file_count: int
    byte_count: int
    accepted_items: int
    duplicate_items: int
    failed_items: int
    error_count: int
    received_at: datetime
    processed_at: datetime | None


class AgentHeartbeatRead(AgentAPIModel):
    id: int
    received_at: datetime
    agent_reported_at: datetime | None
    runtime_status: AgentRuntimeStatus
    heartbeat_interval_seconds: int | None
    collection_interval_seconds: int | None
    measured_clock_offset_seconds: int | None
    queue_pending_batches: int
    queue_pending_bytes: int
    source_count: int


class AgentSummaryRead(AgentAPIModel):
    id: uuid.UUID
    agent_uid: str
    display_name: str
    hostname: str
    platform: str
    agent_version: str
    investigation_id: uuid.UUID
    status: AgentStatus
    runtime_status: AgentRuntimeStatus
    health: AgentHealth
    last_seen_at: datetime | None
    last_heartbeat_at: datetime | None
    last_collection_at: datetime | None
    last_error_at: datetime | None
    last_error: str | None
    queue_pending_batches: int
    queue_pending_bytes: int
    heartbeat_interval_seconds: int | None = None
    collection_interval_seconds: int | None = None
    measured_clock_offset_seconds: int | None = None
    clock_offset_source: str | None = None
    last_recovery_at: datetime | None = None
    reconnection_count: int = 0
    registered_at: datetime
    source_count: int = 0
    batch_count: int = 0


class AgentDetailRead(AgentSummaryRead):
    sources: list[AgentSourceRead] = Field(default_factory=list)
    recent_errors: list[AgentErrorRead] = Field(default_factory=list)
    recent_batches: list[AgentBatchSummary] = Field(default_factory=list)
    recent_heartbeats: list[AgentHeartbeatRead] = Field(default_factory=list)


class AgentListPage(BaseModel):
    items: list[AgentSummaryRead]
    total: int
    limit: int
    offset: int


class AgentHealthSummary(BaseModel):
    status: str
    stale_after_seconds: int
    server_time: datetime
    total_agents: int
    online: int
    stale: int
    never_seen: int
    disabled: int
    agents_with_errors: int
    pending_batches: int
    pending_bytes: int


class AgentMeResponse(BaseModel):
    agent_id: uuid.UUID
    agent_uid: str
    display_name: str
    investigation_id: uuid.UUID
    status: AgentStatus
    health: AgentHealth
    stale_after_seconds: int
    server_time: datetime
    heartbeat_interval_seconds: int | None = None
    collection_interval_seconds: int | None = None
    measured_clock_offset_seconds: int | None = None
    clock_offset_source: str | None = None
    sources: list[AgentSourceRead] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentSourceSyncResponse(BaseModel):
    items: list[AgentSourceRead]
    created: int
    updated: int


class AgentBatchListPage(BaseModel):
    items: list[AgentBatchSummary]
    total: int
    limit: int
    offset: int
