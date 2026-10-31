"""ORM models for CyberTrace Phase 1.

Design rules:
* ``evidence_files`` points at immutable original bytes stored on disk.
* All parsed/derived material lives in separate tables and can be deleted and
  regenerated without touching the original evidence.
* Original timestamp strings, normalized UTC values and an explicit uncertainty
  status are kept side by side.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.constants import (
    AgentBatchItemStatus,
    AgentBatchStatus,
    AgentRuntimeStatus,
    AgentSourceStatus,
    AgentStatus,
    CollectionGapReason,
    CollectionGapStatus,
    CollectionWindowStatus,
    CorrelationConfidence,
    CorrelationStatus,
    DuplicateStatus,
    EventCategory,
    EvidenceStatus,
    GapBasis,
    IntegrityStatus,
    IssueSeverity,
    OrderingStatus,
    ParsingStatus,
    ReconciliationStatus,
    SourceType,
    TimestampStatus,
    VerificationSource,
)
from app.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def enum_type(enum_class: type, name: str, length: int = 32) -> Enum:
    """Store enum *values* in a varchar column (no PostgreSQL enum migration pain)."""

    return Enum(
        enum_class,
        name=name,
        native_enum=False,
        length=length,
        values_callable=lambda cls: [member.value for member in cls],
        validate_strings=True,
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=utcnow
    )

    sources: Mapped[list[EvidenceSource]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", passive_deletes=True
    )
    evidence_files: Mapped[list[EvidenceFile]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", passive_deletes=True
    )


class EvidenceSource(Base):
    """A logical source (host / application) that submitted evidence."""

    __tablename__ = "evidence_sources"
    __table_args__ = (
        UniqueConstraint("investigation_id", "name", name="uq_evidence_sources_investigation_name"),
        Index("ix_evidence_sources_investigation", "investigation_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(
        enum_type(SourceType, "source_type", 32), nullable=False, default=SourceType.UNKNOWN
    )
    hostname: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    investigation: Mapped[Investigation] = relationship(back_populates="sources")
    evidence_files: Mapped[list[EvidenceFile]] = relationship(
        back_populates="source", passive_deletes=True
    )
    events: Mapped[list[ParsedEvent]] = relationship(
        back_populates="source", passive_deletes=True
    )


class EvidenceFile(Base):
    """An immutable original file plus collection metadata (hash lives in EvidenceHash)."""

    __tablename__ = "evidence_files"
    __table_args__ = (
        CheckConstraint("size_bytes >= 0", name="ck_evidence_files_size_nonnegative"),
        CheckConstraint("char_length(sha256) = 64", name="ck_evidence_files_sha256_length"),
        Index("ix_evidence_files_investigation", "investigation_id"),
        Index("ix_evidence_files_sha256", "sha256"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_relative_path: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(120))
    source_type: Mapped[SourceType] = mapped_column(
        enum_type(SourceType, "evidence_source_type", 32), nullable=False
    )
    status: Mapped[EvidenceStatus] = mapped_column(
        enum_type(EvidenceStatus, "evidence_status", 32),
        nullable=False,
        default=EvidenceStatus.RECEIVED,
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    timezone_hint: Mapped[str | None] = mapped_column(String(64))
    default_year: Mapped[int | None] = mapped_column(Integer)
    notes: Mapped[str | None] = mapped_column(Text)
    parser_name: Mapped[str | None] = mapped_column(String(100))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    duplicate_of_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_files.id", ondelete="SET NULL")
    )
    clock_offset_seconds: Mapped[int | None] = mapped_column(Integer)
    integrity_status: Mapped[IntegrityStatus] = mapped_column(
        enum_type(IntegrityStatus, "evidence_integrity_status", 16),
        nullable=False,
        default=IntegrityStatus.UNVERIFIED,
        server_default=text("'unverified'"),
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verification_source: Mapped[str | None] = mapped_column(String(16))
    verification_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    investigation: Mapped[Investigation] = relationship(back_populates="evidence_files")
    source: Mapped[EvidenceSource] = relationship(back_populates="evidence_files")
    hashes: Mapped[list[EvidenceHash]] = relationship(
        back_populates="evidence_file",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="EvidenceHash.computed_at",
    )
    parsing_result: Mapped[ParsingResult | None] = relationship(
        back_populates="evidence_file",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
    events: Mapped[list[ParsedEvent]] = relationship(
        back_populates="evidence_file", cascade="all, delete-orphan", passive_deletes=True
    )
    duplicate_of: Mapped[EvidenceFile | None] = relationship(
        remote_side="EvidenceFile.id",
        back_populates="duplicates",
        foreign_keys=[duplicate_of_evidence_id],
    )
    duplicates: Mapped[list[EvidenceFile]] = relationship(
        back_populates="duplicate_of", foreign_keys=[duplicate_of_evidence_id]
    )
    verifications: Mapped[list[EvidenceVerification]] = relationship(
        back_populates="evidence_file",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="EvidenceVerification.verified_at",
    )
    audit_events: Mapped[list[EvidenceAuditEvent]] = relationship(
        back_populates="evidence_file",
        passive_deletes=True,
        order_by="EvidenceAuditEvent.occurred_at",
    )


class EvidenceHash(Base):
    __tablename__ = "evidence_hashes"
    __table_args__ = (
        UniqueConstraint("evidence_file_id", "algorithm", name="uq_evidence_hashes_file_algorithm"),
        CheckConstraint("char_length(hash_value) = 64", name="ck_evidence_hashes_length"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="sha256")
    hash_value: Mapped[str] = mapped_column(String(64), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    verified: Mapped[bool | None] = mapped_column(Boolean)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_note: Mapped[str | None] = mapped_column(String(255))

    evidence_file: Mapped[EvidenceFile] = relationship(back_populates="hashes")


class EvidenceVerification(Base):
    """One immutable hash-verification attempt (history is never overwritten)."""

    __tablename__ = "evidence_verifications"
    __table_args__ = (
        Index("ix_evidence_verifications_evidence_time", "evidence_file_id", "verified_at"),
        CheckConstraint("char_length(expected_sha256) = 64", name="ck_ev_ver_expected_len"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    evidence_file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="sha256")
    expected_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_sha256: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[IntegrityStatus] = mapped_column(
        enum_type(IntegrityStatus, "verification_outcome", 16), nullable=False
    )
    source: Mapped[VerificationSource] = mapped_column(
        enum_type(VerificationSource, "verification_source", 16), nullable=False
    )
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="api")
    actor_detail: Mapped[str | None] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    evidence_file: Mapped[EvidenceFile] = relationship(back_populates="verifications")


class EvidenceAuditEvent(Base):
    """Append-only chain-of-custody and quality audit record."""

    __tablename__ = "evidence_audit_events"
    __table_args__ = (
        Index("ix_evidence_audit_investigation_time", "investigation_id", "occurred_at"),
        Index("ix_evidence_audit_evidence_time", "evidence_file_id", "occurred_at"),
        Index("ix_evidence_audit_type", "event_type"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    evidence_file_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_files.id", ondelete="SET NULL")
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="api")
    actor_detail: Mapped[str | None] = mapped_column(String(255))
    request_id: Mapped[str | None] = mapped_column(String(64))
    evidence_filename: Mapped[str | None] = mapped_column(String(255))
    evidence_sha256: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    evidence_file: Mapped[EvidenceFile | None] = relationship(back_populates="audit_events")


class ParsingResult(Base):
    """One row per evidence file, containing the parsing outcome and counters."""

    __tablename__ = "parsing_results"
    __table_args__ = (Index("ix_parsing_results_evidence", "evidence_file_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_files.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    parser_name: Mapped[str | None] = mapped_column(String(100))
    parser_version: Mapped[str | None] = mapped_column(String(32))
    status: Mapped[ParsingStatus] = mapped_column(
        enum_type(ParsingStatus, "parsing_status", 32), nullable=False
    )
    total_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blank_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_received: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    parsed_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_rejected: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    malformed_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unsupported_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unsupported_formats: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    missing_required_fields: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    missing_optional_fields: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    parser_errors: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    duplicate_records: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    timestamp_flagged_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    encoding_error_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ordering_tied_records: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    ordering_unresolved_records: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    issues_recorded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    issues_suppressed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fatal_error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    evidence_file: Mapped[EvidenceFile] = relationship(back_populates="parsing_result")
    issues: Mapped[list[ParsingIssue]] = relationship(
        back_populates="parsing_result",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ParsingIssue.line_number",
    )


class ParsedEvent(Base):
    """A normalized (but always source-traceable) event."""

    __tablename__ = "parsed_events"
    __table_args__ = (
        UniqueConstraint("evidence_file_id", "line_number", name="uq_parsed_events_file_line"),
        Index("ix_parsed_events_investigation_time", "investigation_id", "timestamp_utc"),
        Index("ix_parsed_events_investigation_type", "investigation_id", "event_type"),
        Index("ix_parsed_events_investigation_fingerprint", "investigation_id", "fingerprint_sha256"),
        Index("ix_parsed_events_evidence", "evidence_file_id"),
        Index("ix_parsed_events_hostname", "hostname"),
        Index("ix_parsed_events_source_ip", "source_ip"),
        CheckConstraint("line_number >= 1", name="ck_parsed_events_line_positive"),
        CheckConstraint(
            "fingerprint_sha256 IS NULL OR char_length(fingerprint_sha256) = 64",
            name="ck_parsed_events_fingerprint_length",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    evidence_file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    byte_offset: Mapped[int] = mapped_column(BigInteger, nullable=False)
    line_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_line: Mapped[str] = mapped_column(Text, nullable=False)

    event_category: Mapped[EventCategory] = mapped_column(
        enum_type(EventCategory, "event_category", 32), nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    username: Mapped[str | None] = mapped_column(String(255))
    process: Mapped[str | None] = mapped_column(String(100))
    pid: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str | None] = mapped_column(Text)

    http_method: Mapped[str | None] = mapped_column(String(16))
    http_path: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None] = mapped_column(Integer)
    http_bytes: Mapped[int | None] = mapped_column(BigInteger)
    http_referer: Mapped[str | None] = mapped_column(Text)
    http_user_agent: Mapped[str | None] = mapped_column(Text)

    original_timestamp_string: Mapped[str | None] = mapped_column(Text)
    original_timezone: Mapped[str | None] = mapped_column(String(64))
    timestamp_utc: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timestamp_status: Mapped[TimestampStatus] = mapped_column(
        enum_type(TimestampStatus, "timestamp_status", 32), nullable=False
    )
    timestamp_detail: Mapped[str | None] = mapped_column(Text)
    timestamp_precision: Mapped[str | None] = mapped_column(String(16))
    clock_offset_seconds: Mapped[int | None] = mapped_column(Integer)
    clock_offset_applied: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    ordering_status: Mapped[OrderingStatus] = mapped_column(
        enum_type(OrderingStatus, "event_ordering_status", 16),
        nullable=False,
        default=OrderingStatus.ORDERED,
        server_default=text("'unresolved'"),
    )
    ordering_note: Mapped[str | None] = mapped_column(Text)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64))
    dedup_status: Mapped[DuplicateStatus] = mapped_column(
        enum_type(DuplicateStatus, "event_dedup_status", 16),
        nullable=False,
        default=DuplicateStatus.UNIQUE,
        server_default=text("'unique'"),
    )
    duplicate_of_event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("parsed_events.id", ondelete="SET NULL")
    )
    extra: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    evidence_file: Mapped[EvidenceFile] = relationship(back_populates="events")
    investigation: Mapped[Investigation] = relationship()
    source: Mapped[EvidenceSource] = relationship(back_populates="events")
    duplicate_of: Mapped[ParsedEvent | None] = relationship(
        remote_side="ParsedEvent.id",
        back_populates="duplicates",
        foreign_keys=[duplicate_of_event_id],
    )
    duplicates: Mapped[list[ParsedEvent]] = relationship(
        back_populates="duplicate_of", foreign_keys=[duplicate_of_event_id]
    )


class ParsingIssue(Base):
    """Malformed records, missing fields and timestamp warnings (never silently dropped)."""

    __tablename__ = "parsing_issues"
    __table_args__ = (
        Index("ix_parsing_issues_evidence", "evidence_file_id"),
        Index("ix_parsing_issues_result", "parsing_result_id"),
        Index("ix_parsing_issues_type", "issue_type"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    evidence_file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence_files.id", ondelete="CASCADE"),
        nullable=False,
    )
    parsing_result_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("parsing_results.id", ondelete="CASCADE"),
        nullable=False,
    )
    line_number: Mapped[int | None] = mapped_column(Integer)
    byte_offset: Mapped[int | None] = mapped_column(BigInteger)
    raw_line: Mapped[str | None] = mapped_column(Text)
    issue_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[IssueSeverity] = mapped_column(
        enum_type(IssueSeverity, "issue_severity", 16), nullable=False
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    parsing_result: Mapped[ParsingResult] = relationship(back_populates="issues")


class Agent(Base):
    """A registered Linux endpoint agent.

    Only a SHA-256 hash of the bearer token is persisted. The plaintext token is
    returned once at registration and held by the agent's protected state file.
    """

    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("agent_uid", name="uq_agents_agent_uid"),
        UniqueConstraint("token_hash", name="uq_agents_token_hash"),
        Index("ix_agents_investigation", "investigation_id"),
        Index("ix_agents_last_seen", "last_seen_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_uid: Mapped[str] = mapped_column(String(128), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(120), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[AgentStatus] = mapped_column(
        enum_type(AgentStatus, "agent_status", 16), nullable=False, default=AgentStatus.ACTIVE
    )
    runtime_status: Mapped[AgentRuntimeStatus] = mapped_column(
        enum_type(AgentRuntimeStatus, "agent_runtime_status", 16),
        nullable=False,
        default=AgentRuntimeStatus.UNKNOWN,
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_collection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    queue_pending_batches: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    queue_pending_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    heartbeat_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    collection_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    measured_clock_offset_seconds: Mapped[int | None] = mapped_column(Integer)
    clock_offset_source: Mapped[str | None] = mapped_column(String(16))
    clock_offset_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_recovery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reconnection_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=utcnow
    )

    investigation: Mapped[Investigation] = relationship()
    sources: Mapped[list[AgentSource]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", passive_deletes=True
    )
    batches: Mapped[list[AgentBatch]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", passive_deletes=True
    )
    errors: Mapped[list[AgentError]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", passive_deletes=True
    )
    heartbeats: Mapped[list[AgentHeartbeat]] = relationship(
        back_populates="agent",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AgentHeartbeat.received_at",
    )


class AgentHeartbeat(Base):
    """Append-only heartbeat history used for reconnection and coverage analysis."""

    __tablename__ = "agent_heartbeats"
    __table_args__ = (
        Index("ix_agent_heartbeats_agent_time", "agent_id", "received_at"),
        Index("ix_agent_heartbeats_investigation", "investigation_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    runtime_status: Mapped[AgentRuntimeStatus] = mapped_column(
        enum_type(AgentRuntimeStatus, "heartbeat_runtime_status", 16),
        nullable=False,
        default=AgentRuntimeStatus.UNKNOWN,
    )
    heartbeat_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    collection_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    measured_clock_offset_seconds: Mapped[int | None] = mapped_column(Integer)
    queue_pending_batches: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    queue_pending_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sources_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    agent: Mapped[Agent] = relationship(back_populates="heartbeats")


class AgentSource(Base):
    """Server-side inventory entry for one configured log source on an agent."""

    __tablename__ = "agent_sources"
    __table_args__ = (
        UniqueConstraint("agent_id", "source_key", name="uq_agent_sources_agent_key"),
        Index("ix_agent_sources_agent", "agent_id"),
        Index("ix_agent_sources_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    source_key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(
        enum_type(SourceType, "agent_source_type", 32), nullable=False
    )
    path_hint: Mapped[str | None] = mapped_column(String(512))
    timezone_hint: Mapped[str | None] = mapped_column(String(64))
    default_year: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[AgentSourceStatus] = mapped_column(
        enum_type(AgentSourceStatus, "agent_source_status", 16),
        nullable=False,
        default=AgentSourceStatus.UNKNOWN,
    )
    evidence_source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_sources.id", ondelete="SET NULL")
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    cursor_bytes: Mapped[int | None] = mapped_column(BigInteger)
    clock_offset_seconds: Mapped[int | None] = mapped_column(Integer)
    expected_collection_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    collection_available: Mapped[bool | None] = mapped_column(Boolean)
    last_collection_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_collection_ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_cycle_bytes: Mapped[int | None] = mapped_column(BigInteger)
    last_cycle_lines: Mapped[int | None] = mapped_column(Integer)
    last_cycle_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    last_recovery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovery_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=utcnow
    )

    agent: Mapped[Agent] = relationship(back_populates="sources")
    batch_items: Mapped[list[AgentBatchItem]] = relationship(
        back_populates="source", passive_deletes=True
    )
    errors: Mapped[list[AgentError]] = relationship(back_populates="source", passive_deletes=True)
    collection_windows: Mapped[list[SourceCollectionWindow]] = relationship(
        back_populates="source", passive_deletes=True
    )
    gaps: Mapped[list[CollectionGap]] = relationship(
        back_populates="source", passive_deletes=True
    )


class AgentBatch(Base):
    """One idempotent upload batch from an agent."""

    __tablename__ = "agent_batches"
    __table_args__ = (
        UniqueConstraint("agent_id", "batch_id", name="uq_agent_batches_agent_batch"),
        Index("ix_agent_batches_agent_received", "agent_id", "received_at"),
        Index("ix_agent_batches_investigation", "investigation_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    batch_id: Mapped[str] = mapped_column(String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(32))
    client_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[AgentBatchStatus] = mapped_column(
        enum_type(AgentBatchStatus, "agent_batch_status", 16),
        nullable=False,
        default=AgentBatchStatus.RECEIVED,
    )
    file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    byte_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    accepted_items: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_items: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_items: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    agent: Mapped[Agent] = relationship(back_populates="batches")
    investigation: Mapped[Investigation] = relationship()
    items: Mapped[list[AgentBatchItem]] = relationship(
        back_populates="batch", cascade="all, delete-orphan", passive_deletes=True
    )
    errors: Mapped[list[AgentError]] = relationship(back_populates="batch", passive_deletes=True)


class AgentBatchItem(Base):
    """Per-file outcome for an agent batch; supports retry of only failed items."""

    __tablename__ = "agent_batch_items"
    __table_args__ = (
        UniqueConstraint("agent_batch_id", "item_id", name="uq_agent_batch_items_batch_item"),
        CheckConstraint("char_length(sha256) = 64", name="ck_agent_batch_items_sha256_length"),
        CheckConstraint("size_bytes >= 0", name="ck_agent_batch_items_size_nonnegative"),
        Index("ix_agent_batch_items_batch", "agent_batch_id"),
        Index("ix_agent_batch_items_evidence", "evidence_file_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    agent_batch_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_batches.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_sources.id", ondelete="SET NULL")
    )
    evidence_file_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_files.id", ondelete="SET NULL")
    )
    item_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(
        enum_type(SourceType, "agent_batch_item_source_type", 32), nullable=False
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collection_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    collection_ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    range_start: Mapped[int | None] = mapped_column(BigInteger)
    range_end: Mapped[int | None] = mapped_column(BigInteger)
    expected_bytes: Mapped[int | None] = mapped_column(BigInteger)
    lines_collected: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[AgentBatchItemStatus] = mapped_column(
        enum_type(AgentBatchItemStatus, "agent_batch_item_status", 16), nullable=False
    )
    error_code: Mapped[str | None] = mapped_column(String(64))
    message: Mapped[str | None] = mapped_column(Text)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    batch: Mapped[AgentBatch] = relationship(back_populates="items")
    source: Mapped[AgentSource | None] = relationship(back_populates="batch_items")
    evidence_file: Mapped[EvidenceFile | None] = relationship()
    collection_windows: Mapped[list[SourceCollectionWindow]] = relationship(
        back_populates="batch_item", passive_deletes=True
    )


class SourceCollectionWindow(Base):
    """A reported or batch-derived interval during which collection was attempted."""

    __tablename__ = "source_collection_windows"
    __table_args__ = (
        CheckConstraint(
            "bytes_collected IS NULL OR bytes_collected >= 0",
            name="ck_collection_windows_bytes_nonnegative",
        ),
        CheckConstraint(
            "expected_bytes IS NULL OR expected_bytes >= 0",
            name="ck_collection_windows_expected_nonnegative",
        ),
        Index("ix_collection_windows_source_time", "agent_source_id", "observed_at"),
        Index("ix_collection_windows_investigation_time", "investigation_id", "observed_at"),
        Index("ix_collection_windows_evidence", "evidence_file_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    agent_source_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_sources.id", ondelete="CASCADE"), nullable=False
    )
    evidence_file_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("evidence_files.id", ondelete="SET NULL")
    )
    agent_batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_batches.id", ondelete="SET NULL")
    )
    agent_batch_item_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("agent_batch_items.id", ondelete="SET NULL")
    )
    origin: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[CollectionWindowStatus] = mapped_column(
        enum_type(CollectionWindowStatus, "collection_window_status", 16), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bytes_collected: Mapped[int | None] = mapped_column(BigInteger)
    lines_collected: Mapped[int | None] = mapped_column(Integer)
    expected_bytes: Mapped[int | None] = mapped_column(BigInteger)
    range_start: Mapped[int | None] = mapped_column(BigInteger)
    range_end: Mapped[int | None] = mapped_column(BigInteger)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    source: Mapped[AgentSource] = relationship(back_populates="collection_windows")
    evidence_file: Mapped[EvidenceFile | None] = relationship()
    batch: Mapped[AgentBatch | None] = relationship()
    batch_item: Mapped[AgentBatchItem | None] = relationship(back_populates="collection_windows")


class CollectionGap(Base):
    """A persisted observed or inferred interval with no collection coverage."""

    __tablename__ = "collection_gaps"
    __table_args__ = (
        Index("ix_collection_gaps_investigation_start", "investigation_id", "gap_start"),
        Index("ix_collection_gaps_source_status", "agent_source_id", "status"),
        Index("ix_collection_gaps_agent_status", "agent_id", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL")
    )
    agent_source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_sources.id", ondelete="SET NULL")
    )
    gap_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    gap_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[CollectionGapStatus] = mapped_column(
        enum_type(CollectionGapStatus, "collection_gap_status", 16),
        nullable=False,
        default=CollectionGapStatus.OPEN,
    )
    reason: Mapped[CollectionGapReason] = mapped_column(
        enum_type(CollectionGapReason, "collection_gap_reason", 32), nullable=False
    )
    basis: Mapped[GapBasis] = mapped_column(
        enum_type(GapBasis, "collection_gap_basis", 16),
        nullable=False,
        default=GapBasis.OBSERVED,
    )
    expected_interval_seconds: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=utcnow
    )

    source: Mapped[AgentSource | None] = relationship(back_populates="gaps")
    agent: Mapped[Agent | None] = relationship()


class ReconciliationRun(Base):
    """Audit record for a duplicate-fingerprint reconciliation pass."""

    __tablename__ = "reconciliation_runs"
    __table_args__ = (
        Index("ix_reconciliation_runs_investigation_time", "investigation_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[ReconciliationStatus] = mapped_column(
        enum_type(ReconciliationStatus, "reconciliation_status", 16), nullable=False
    )
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="investigation")
    events_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_groups: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default="api")
    actor_detail: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class AgentError(Base):
    """Agent-reported collection or delivery failure."""

    __tablename__ = "agent_errors"
    __table_args__ = (
        Index("ix_agent_errors_agent_reported", "agent_id", "reported_at"),
        Index("ix_agent_errors_source", "source_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_sources.id", ondelete="SET NULL")
    )
    agent_batch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_batches.id", ondelete="SET NULL")
    )
    error_code: Mapped[str] = mapped_column(String(64), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    agent: Mapped[Agent] = relationship(back_populates="errors")
    source: Mapped[AgentSource | None] = relationship(back_populates="errors")
    batch: Mapped[AgentBatch | None] = relationship(back_populates="errors")


class EventCorrelation(Base):
    """A transparent, rule-based suggestion that two or more events are related.

    Correlations are derived material: they never alter or delete the original
    parsed events or evidence. A dismissed correlation is retained for audit.
    """

    __tablename__ = "event_correlations"
    __table_args__ = (
        Index("ix_event_correlations_investigation", "investigation_id"),
        Index("ix_event_correlations_status", "status"),
        Index("ix_event_correlations_rule", "rule_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_description: Mapped[str | None] = mapped_column(Text)
    correlation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[CorrelationConfidence] = mapped_column(
        enum_type(CorrelationConfidence, "correlation_confidence", 16),
        nullable=False,
        default=CorrelationConfidence.LOW,
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    matching_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    time_relationship: Mapped[str | None] = mapped_column(Text)
    timestamp_uncertainty: Mapped[str | None] = mapped_column(Text)
    status: Mapped[CorrelationStatus] = mapped_column(
        enum_type(CorrelationStatus, "correlation_status", 16),
        nullable=False,
        default=CorrelationStatus.SUGGESTED,
    )
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by: Mapped[str | None] = mapped_column(String(255))
    dismissal_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=utcnow
    )

    investigation: Mapped[Investigation] = relationship()
    members: Mapped[list[EventCorrelationMember]] = relationship(
        back_populates="correlation",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="EventCorrelationMember.id",
    )


class EventCorrelationMember(Base):
    """One parsed event participating in an EventCorrelation."""

    __tablename__ = "event_correlation_members"
    __table_args__ = (
        UniqueConstraint(
            "correlation_id", "event_id", name="uq_event_correlation_members_corr_event"
        ),
        Index("ix_event_correlation_members_event", "event_id"),
        Index("ix_event_correlation_members_correlation", "correlation_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("event_correlations.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("parsed_events.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="related")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    correlation: Mapped[EventCorrelation] = relationship(back_populates="members")
    event: Mapped[ParsedEvent] = relationship()
