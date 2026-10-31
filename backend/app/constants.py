"""Shared domain constants for CyberTrace.

These live outside the ORM and parser modules so that storage, parsing and API
layers can share one vocabulary without circular imports.
"""

from __future__ import annotations

from enum import Enum


class SourceType(str, Enum):
    """A log family that CyberTrace can parse."""

    LINUX_AUTH = "linux_auth"
    WEB_ACCESS = "web_access"
    UNKNOWN = "unknown"


class RequestedSourceType(str, Enum):
    """Upload-time source selection. ``auto`` uses content detection."""

    AUTO = "auto"
    LINUX_AUTH = "linux_auth"
    WEB_ACCESS = "web_access"


class EvidenceStatus(str, Enum):
    RECEIVED = "received"
    PARSED = "parsed"
    PARSED_WITH_ISSUES = "parsed_with_issues"
    FAILED = "failed"


class ParsingStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class TimestampStatus(str, Enum):
    """How much confidence we have in the UTC representation of an event.

    ``NORMALIZED``        an offset or a supplied time zone let us convert to UTC.
    ``MISSING_TIMEZONE``  the wall-clock time is complete, but no zone/offset is known.
    ``MISSING_YEAR``      the source (classic syslog) has no year and none was supplied.
    ``AMBIGUOUS``         the local time maps to two UTC instants (DST fold) or none.
    ``MISSING_TIMESTAMP`` the record has no usable timestamp field at all.
    ``INVALID``           the timestamp field exists but could not be parsed.
    """

    NORMALIZED = "normalized"
    MISSING_TIMEZONE = "missing_timezone"
    MISSING_YEAR = "missing_year"
    AMBIGUOUS = "ambiguous"
    MISSING_TIMESTAMP = "missing_timestamp"
    INVALID = "invalid"


class OrderingStatus(str, Enum):
    """Stored ordering confidence for a parsed event.

    ``ORDERED``    the UTC timestamp is unique within the investigation.
    ``TIED``       another event shares the exact same UTC timestamp; the API uses
                   deterministic evidence/line tie-breakers, not a claim of truth.
    ``UNRESOLVED`` no UTC timestamp is available; position is based on evidence
                   receipt and line order only.
    """

    ORDERED = "ordered"
    TIED = "tied"
    UNRESOLVED = "unresolved"


class DuplicateStatus(str, Enum):
    """Event-level duplicate classification. Duplicate rows are never deleted."""

    UNIQUE = "unique"
    DUPLICATE = "duplicate"


class IntegrityStatus(str, Enum):
    """Result of comparing stored bytes with the recorded evidence hash."""

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    MISSING = "missing"


class CoverageState(str, Enum):
    """Whether collection was actually running for a source.

    ``REPORTING``     the agent checked in recently and collection is available.
    ``IDLE``          collection is available but the last cycle observed no events.
    ``NOT_REPORTING`` the agent is stale or never checked in; coverage is unknown.
    ``ERROR``         the source is readable/reporting but collection failed.
    ``DISABLED``      collection is intentionally disabled.
    ``UNKNOWN``       no collection schedule is registered (for example a manual upload).
    """

    REPORTING = "reporting"
    IDLE = "idle"
    NOT_REPORTING = "not_reporting"
    ERROR = "error"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class CollectionGapReason(str, Enum):
    AGENT_OFFLINE = "agent_offline"
    HEARTBEAT_MISSING = "heartbeat_missing"
    SOURCE_ERROR = "source_error"
    SOURCE_UNREADABLE = "source_unreadable"
    BYTE_RANGE_GAP = "byte_range_gap"
    BATCH_MISSING = "batch_missing"
    UNKNOWN = "unknown"


class CollectionGapStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"


class GapBasis(str, Enum):
    """How a gap boundary was established (never invented silently)."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    ESTIMATED = "estimated"


class VerificationSource(str, Enum):
    UPLOAD = "upload"
    API = "api"
    REPARSE = "reparse"
    BULK = "bulk"
    AGENT = "agent"


class AuditActorType(str, Enum):
    API = "api"
    AGENT = "agent"
    SYSTEM = "system"


class AuditEventType(str, Enum):
    EVIDENCE_PRESERVED = "evidence_preserved"
    EVIDENCE_PARSED = "evidence_parsed"
    EVIDENCE_DOWNLOADED = "evidence_downloaded"
    EVIDENCE_VERIFIED = "evidence_verified"
    EVIDENCE_VERIFICATION_MISMATCH = "evidence_verification_mismatch"
    EVIDENCE_REPARSED = "evidence_reparsed"
    EVIDENCE_REPARSE_DENIED = "evidence_reparse_denied"
    DUPLICATE_UPLOAD_REJECTED = "duplicate_upload_rejected"
    MANIFEST_EXPORTED = "manifest_exported"
    DUPLICATES_RECONCILED = "duplicates_reconciled"
    CORRELATIONS_GENERATED = "correlations_generated"
    CORRELATION_DISMISSED = "correlation_dismissed"
    AGENT_BATCH_INGESTED = "agent_batch_ingested"
    AGENT_BATCH_DUPLICATE = "agent_batch_duplicate"


class ReconciliationStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"


class CorrelationStatus(str, Enum):
    """Lifecycle state of a suggested cross-source correlation."""

    SUGGESTED = "suggested"
    DISMISSED = "dismissed"


class CorrelationConfidence(str, Enum):
    """Documented heuristic strength of a correlation match.

    ``high``     Strong shared identifier (IP or username) across different source
                 types, both timestamps normalized, and events within 5 minutes.
    ``medium``   Strong shared identifier across sources with normalized timestamps
                 within the configured window, but without a tight sequence.
    ``low``      Shared identifier with missing/uncertain timestamps or hostname-only
                 matching; treated as a possible correlation only.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CollectionWindowStatus(str, Enum):
    COMPLETED = "completed"
    EMPTY = "empty"
    FAILED = "failed"
    DUPLICATE = "duplicate"


class IssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


class IssueType(str, Enum):
    MALFORMED_LINE = "malformed_line"
    UNSUPPORTED_FORMAT = "unsupported_format"
    MISSING_FIELD = "missing_field"
    MISSING_REQUIRED_FIELD = "missing_required_field"
    MISSING_OPTIONAL_FIELD = "missing_optional_field"
    UNKNOWN_TIMESTAMP = "unknown_timestamp"
    MISSING_TIMESTAMP = "missing_timestamp"
    AMBIGUOUS_TIMESTAMP = "ambiguous_timestamp"
    INVALID_TIMESTAMP = "invalid_timestamp"
    ENCODING_ERROR = "encoding_error"
    LINE_TOO_LONG = "line_too_long"
    PARSER_ERROR = "parser_error"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    WEB_ACCESS = "web_access"


class EventType(str, Enum):
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_INVALID_USER = "auth_invalid_user"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    SUDO_COMMAND = "sudo_command"
    AUTH_DISCONNECT = "auth_disconnect"
    AUTH_OTHER = "auth_other"
    HTTP_REQUEST = "http_request"


class AgentStatus(str, Enum):
    """Administrative state of a registered endpoint agent."""

    ACTIVE = "active"
    DISABLED = "disabled"


class AgentHealth(str, Enum):
    """Derived from last-seen time; never stored directly."""

    ONLINE = "online"
    STALE = "stale"
    NEVER_SEEN = "never_seen"
    DISABLED = "disabled"


class AgentRuntimeStatus(str, Enum):
    """Agent-reported runtime state for the latest heartbeat."""

    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    UNKNOWN = "unknown"


class AgentSourceStatus(str, Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    ERROR = "error"
    DISABLED = "disabled"


class AgentBatchStatus(str, Enum):
    RECEIVED = "received"
    PROCESSED = "processed"
    PARTIAL = "partial"
    FAILED = "failed"


class AgentBatchItemStatus(str, Enum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    FAILED = "failed"


PARSER_LINUX_AUTH = "linux_auth_syslog"
PARSER_WEB_ACCESS = "web_access_common_combined"
PARSER_VERSION = "1.1.0"

PARSER_BY_SOURCE_TYPE: dict[SourceType, str] = {
    SourceType.LINUX_AUTH: PARSER_LINUX_AUTH,
    SourceType.WEB_ACCESS: PARSER_WEB_ACCESS,
}


CYBERTRACE_VERSION = "0.4.3"
