"""Apache/nginx common and combined access-log parser."""

from __future__ import annotations

import re

from app.constants import (
    EventCategory,
    EventType,
    IssueSeverity,
    IssueType,
    SourceType,
)
from app.services.parsers.base import (
    LineParseResult,
    LogParser,
    ParsedEventData,
    ParsedIssueData,
    ParserConfig,
    timestamp_issue,
)
from app.services.timeutil import missing_timestamp, resolve_web_timestamp

_WEB_ACCESS_RE = re.compile(
    r"^(?P<remote_addr>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<remote_user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<body_bytes>\d+|-|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?\s*$'
)

_REQUEST_RE = re.compile(
    r"^(?P<method>[^\s]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>\S+))?$"
)


def _none_if_dash(value: str | None) -> str | None:
    if value is None or value == "-":
        return None
    return value


class WebAccessParser(LogParser):
    name = "web_access_common_combined"
    source_type = SourceType.WEB_ACCESS

    def matches(self, line: str) -> bool:
        return bool(_WEB_ACCESS_RE.match(line.rstrip("\r\n")))

    def parse_line(self, line: str, config: ParserConfig) -> LineParseResult:
        text = line.rstrip("\r\n")
        match = _WEB_ACCESS_RE.match(text)
        if not match:
            return LineParseResult(
                event=None,
                issues=[
                    ParsedIssueData(
                        issue_type=IssueType.MALFORMED_LINE.value,
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Line does not match the supported Apache/nginx common or "
                            "combined access-log layout."
                        ),
                    )
                ],
            )

        timestamp_token = match.group("timestamp")
        if timestamp_token.strip().lower() in {"", "-", "unknown", "null", "n/a"}:
            resolution = missing_timestamp(
                "Access-log timestamp field is a placeholder; the event is retained with "
                "an unresolved timestamp."
            )
        else:
            resolution = resolve_web_timestamp(
                timestamp_token, timezone_hint=config.timezone_hint
            )

        issues: list[ParsedIssueData] = []
        ts_issue = timestamp_issue(resolution)
        if ts_issue:
            issues.append(ts_issue)

        remote_addr = _none_if_dash(match.group("remote_addr"))
        if remote_addr is None:
            issues.append(
                ParsedIssueData(
                    issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                    severity=IssueSeverity.WARNING,
                    message="Access-log record has no client IP address.",
                )
            )

        request_raw = match.group("request")
        method: str | None = None
        path: str | None = None
        protocol: str | None = None
        if request_raw and request_raw != "-":
            request = _REQUEST_RE.match(request_raw)
            if request:
                method = request.group("method")
                path = request.group("path")
                protocol = request.group("protocol")
            else:
                issues.append(
                    ParsedIssueData(
                        issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                        severity=IssueSeverity.WARNING,
                        message="Access-log request field could not be split into method/path.",
                    )
                )
        else:
            issues.append(
                ParsedIssueData(
                    issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                    severity=IssueSeverity.WARNING,
                    message="Access-log record has an empty request field.",
                )
            )

        optional_fields_missing = sum(
            1
            for group in ("referer", "user_agent")
            if match.group(group) is None
        )

        body_bytes_raw = match.group("body_bytes")
        body_bytes = None if body_bytes_raw == "-" else int(body_bytes_raw)

        extra = {
            "request_raw": request_raw,
            "protocol": protocol,
            "ident": _none_if_dash(match.group("ident")),
            "log_format": (
                "combined"
                if match.group("referer") is not None
                else "common"
            ),
        }

        event = ParsedEventData(
            event_category=EventCategory.WEB_ACCESS,
            event_type=EventType.HTTP_REQUEST.value,
            timestamp=resolution,
            hostname=config.hostname_fallback,
            source_ip=remote_addr,
            username=_none_if_dash(match.group("remote_user")),
            http_method=method,
            http_path=path,
            http_status=int(match.group("status")),
            http_bytes=body_bytes,
            http_referer=_none_if_dash(match.group("referer")),
            http_user_agent=_none_if_dash(match.group("user_agent")),
            message=request_raw,
            extra=extra,
        )
        return LineParseResult(
            event=event,
            issues=issues,
            optional_fields_missing=optional_fields_missing,
        )
