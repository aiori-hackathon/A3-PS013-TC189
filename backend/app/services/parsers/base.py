"""Parser contracts shared by the Linux-auth and web-access parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.constants import (
    PARSER_VERSION,
    EventCategory,
    IssueSeverity,
    IssueType,
    SourceType,
    TimestampStatus,
)
from app.services.timeutil import TimestampResolution


@dataclass(frozen=True, slots=True)
class ParserConfig:
    timezone_hint: str | None = None
    default_year: int | None = None
    hostname_fallback: str | None = None


@dataclass(slots=True)
class ParsedIssueData:
    issue_type: str
    severity: IssueSeverity
    message: str


@dataclass(slots=True)
class ParsedEventData:
    event_category: EventCategory
    event_type: str
    timestamp: TimestampResolution
    hostname: str | None = None
    source_ip: str | None = None
    username: str | None = None
    process: str | None = None
    pid: int | None = None
    message: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    http_bytes: int | None = None
    http_referer: str | None = None
    http_user_agent: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LineParseResult:
    event: ParsedEventData | None
    issues: list[ParsedIssueData] = field(default_factory=list)
    optional_fields_missing: int = 0


class LogParser(ABC):
    name: str = "abstract"
    version: str = PARSER_VERSION
    source_type: SourceType = SourceType.UNKNOWN

    @abstractmethod
    def matches(self, line: str) -> bool:
        """Return True when the line has the structural shape of this format."""

    @abstractmethod
    def parse_line(self, line: str, config: ParserConfig) -> LineParseResult:
        """Parse one line, returning either an event or an explicit issue."""


def timestamp_issue(resolution: TimestampResolution) -> ParsedIssueData | None:
    """Convert a non-normalized timestamp into a visible parsing issue."""

    if resolution.status is TimestampStatus.NORMALIZED:
        return None
    if resolution.status is TimestampStatus.INVALID:
        return ParsedIssueData(
            issue_type=IssueType.INVALID_TIMESTAMP.value,
            severity=IssueSeverity.ERROR,
            message=resolution.detail or "Timestamp could not be parsed.",
        )
    if resolution.status is TimestampStatus.MISSING_TIMESTAMP:
        return ParsedIssueData(
            issue_type=IssueType.MISSING_TIMESTAMP.value,
            severity=IssueSeverity.WARNING,
            message=resolution.detail or "Record has no timestamp.",
        )
    if resolution.status is TimestampStatus.AMBIGUOUS:
        return ParsedIssueData(
            issue_type=IssueType.AMBIGUOUS_TIMESTAMP.value,
            severity=IssueSeverity.WARNING,
            message=resolution.detail or "Timestamp is ambiguous.",
        )
    return ParsedIssueData(
        issue_type=IssueType.UNKNOWN_TIMESTAMP.value,
        severity=IssueSeverity.WARNING,
        message=resolution.detail or "Timestamp could not be normalized to UTC.",
    )
