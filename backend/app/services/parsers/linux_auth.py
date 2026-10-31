"""Linux authentication log parser.

Supported line shapes:
* RFC 3164 syslog: ``Oct 31 10:15:32 host sshd[1234]: message``
* ISO / journald:  ``2026-10-31T10:15:32.123+05:30 host sshd[1234]: message``

The parser preserves the exact timestamp token and never invents a time zone or
year. RFC 3164 lines need both ``timezone_hint`` and ``default_year`` before a
UTC value can be produced.
"""

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
from app.services.timeutil import (
    missing_timestamp,
    resolve_iso_timestamp,
    resolve_syslog_timestamp,
)

_AUTH_HEADER_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<timestamp>"
    r"(?:[A-Z][a-z]{2}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)"
    r")"
    r"\s+(?P<hostname>\S+)\s+"
    r"(?P<program>[A-Za-z0-9_.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

_AUTH_NO_TIMESTAMP_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<hostname>\S+)\s+"
    r"(?P<program>[A-Za-z0-9_.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

_AUTH_HINTS = (
    "Accepted ",
    "Failed ",
    "Invalid user ",
    "session opened",
    "session closed",
    "Disconnected from",
    "Received disconnect",
    "Connection closed",
)


def _looks_like_auth_message(program: str | None, message: str) -> bool:
    if program == "sudo":
        return True
    return any(hint in message for hint in _AUTH_HINTS)

_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+)"
    r"(?: from (?P<ip>\S+) port (?P<port>\d+))?"
)
_FAILED_RE = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+)"
    r"(?: from (?P<ip>\S+) port (?P<port>\d+))?"
)
_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S+)(?: from (?P<ip>\S+))?"
)
_SESSION_OPENED_RE = re.compile(r"session opened for user (?P<user>\S+)")
_SESSION_CLOSED_RE = re.compile(r"session closed for user (?P<user>\S+)")
_DISCONNECT_USER_RE = re.compile(
    r"^(?:Disconnected from|Received disconnect from) (?:invalid user |user )?"
    r"(?P<user>\S+)? ?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]+) port (?P<port>\d+)"
)
_RECEIVED_DISCONNECT_RE = re.compile(
    r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+)(?::(?P<reason>.*))?$"
)
_CONNECTION_CLOSED_RE = re.compile(
    r"^Connection closed by (?:authenticating )?(?:user |invalid user )?"
    r"(?P<user>\S+)? ?(?P<ip>\S+) port (?P<port>\d+)"
)
_SUDO_FIELD_RE = re.compile(
    r"^(?P<actor>\S+)\s*:\s*(?P<fields>.+)$"
)
_SUDO_USER_RE = re.compile(r"(?:^|;\s*)USER=(?P<user>[^;\s]+)")
_SUDO_COMMAND_RE = re.compile(r"(?:^|;\s*)COMMAND=(?P<command>.+)$")
_SUDO_TTY_RE = re.compile(r"(?:^|;\s*)TTY=(?P<tty>[^;\s]+)")
_SUDO_PWD_RE = re.compile(r"(?:^|;\s*)PWD=(?P<pwd>[^;\s]+)")


class LinuxAuthParser(LogParser):
    name = "linux_auth_syslog"
    source_type = SourceType.LINUX_AUTH

    def matches(self, line: str) -> bool:
        text = line.rstrip("\r\n")
        if _AUTH_HEADER_RE.match(text):
            return True
        fallback = _AUTH_NO_TIMESTAMP_RE.match(text)
        return bool(
            fallback
            and _looks_like_auth_message(
                fallback.group("program"), fallback.group("message")
            )
        )

    def parse_line(self, line: str, config: ParserConfig) -> LineParseResult:
        text = line.rstrip("\r\n")
        header = _AUTH_HEADER_RE.match(text)
        issues: list[ParsedIssueData] = []
        optional_fields_missing = 0

        if header:
            timestamp_token = header.group("timestamp")
            if "T" in timestamp_token:
                resolution = resolve_iso_timestamp(
                    timestamp_token, timezone_hint=config.timezone_hint
                )
            else:
                resolution = resolve_syslog_timestamp(
                    timestamp_token,
                    timezone_hint=config.timezone_hint,
                    default_year=config.default_year,
                )
            hostname = header.group("hostname")
            program = header.group("program")
            pid = int(header.group("pid")) if header.group("pid") else None
            message = header.group("message").strip()
        else:
            fallback = _AUTH_NO_TIMESTAMP_RE.match(text)
            if not fallback or not _looks_like_auth_message(
                fallback.group("program"), fallback.group("message")
            ):
                return LineParseResult(
                    event=None,
                    issues=[
                        ParsedIssueData(
                            issue_type=IssueType.MALFORMED_LINE.value,
                            severity=IssueSeverity.ERROR,
                            message=(
                                "Line does not match the supported Linux authentication "
                                "syslog layout (timestamp + host + program: message)."
                            ),
                        )
                    ],
                )
            resolution = missing_timestamp(
                "Record matched the host/program/message layout but has no timestamp field; "
                "the event is retained with an unresolved timestamp."
            )
            hostname = fallback.group("hostname")
            program = fallback.group("program")
            pid = int(fallback.group("pid")) if fallback.group("pid") else None
            message = fallback.group("message").strip()

        ts_issue = timestamp_issue(resolution)
        if ts_issue:
            issues.append(ts_issue)

        event_type = EventType.AUTH_OTHER.value
        source_ip: str | None = None
        username: str | None = None
        extra: dict[str, object] = {}

        accepted = _ACCEPTED_RE.match(message)
        failed = _FAILED_RE.match(message)
        invalid_user = _INVALID_USER_RE.match(message)

        if accepted:
            event_type = EventType.AUTH_SUCCESS.value
            username = accepted.group("user")
            source_ip = accepted.group("ip")
            extra["auth_method"] = accepted.group("method")
            if accepted.group("port"):
                extra["source_port"] = int(accepted.group("port"))
            if not source_ip:
                issues.append(
                    ParsedIssueData(
                        issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                        severity=IssueSeverity.WARNING,
                        message="Accepted-login record has no source IP address.",
                    )
                )
            if not accepted.group("port"):
                optional_fields_missing += 1
        elif failed:
            invalid = "for invalid user " in message
            event_type = (
                EventType.AUTH_INVALID_USER.value
                if invalid
                else EventType.AUTH_FAILURE.value
            )
            username = failed.group("user")
            source_ip = failed.group("ip")
            extra["auth_method"] = failed.group("method")
            if failed.group("port"):
                extra["source_port"] = int(failed.group("port"))
            if not source_ip:
                issues.append(
                    ParsedIssueData(
                        issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                        severity=IssueSeverity.WARNING,
                        message="Failed-login record has no source IP address.",
                    )
                )
            if not failed.group("port"):
                optional_fields_missing += 1
        elif invalid_user:
            event_type = EventType.AUTH_INVALID_USER.value
            username = invalid_user.group("user")
            source_ip = invalid_user.group("ip")
        elif _SESSION_OPENED_RE.search(message):
            event_type = EventType.SESSION_OPENED.value
            username = _SESSION_OPENED_RE.search(message).group("user")  # type: ignore[union-attr]
        elif _SESSION_CLOSED_RE.search(message):
            event_type = EventType.SESSION_CLOSED.value
            username = _SESSION_CLOSED_RE.search(message).group("user")  # type: ignore[union-attr]
        elif program == "sudo":
            event_type = EventType.SUDO_COMMAND.value
            sudo = _SUDO_FIELD_RE.match(message)
            if not sudo:
                issues.append(
                    ParsedIssueData(
                        issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                        severity=IssueSeverity.WARNING,
                        message="sudo record does not match the expected field layout.",
                    )
                )
            else:
                username = sudo.group("actor")
                fields = sudo.group("fields")
                target = _SUDO_USER_RE.search(fields)
                command = _SUDO_COMMAND_RE.search(fields)
                tty = _SUDO_TTY_RE.search(fields)
                pwd = _SUDO_PWD_RE.search(fields)
                if target:
                    extra["target_user"] = target.group("user")
                if command:
                    extra["command"] = command.group("command").strip()
                else:
                    issues.append(
                        ParsedIssueData(
                            issue_type=IssueType.MISSING_REQUIRED_FIELD.value,
                            severity=IssueSeverity.WARNING,
                            message="sudo record has no COMMAND field.",
                        )
                    )
                if tty:
                    extra["tty"] = tty.group("tty")
                if pwd:
                    extra["working_directory"] = pwd.group("pwd")
        else:
            received = _RECEIVED_DISCONNECT_RE.match(message)
            user_disconnect = _DISCONNECT_USER_RE.match(message)
            closed = _CONNECTION_CLOSED_RE.match(message)
            if received:
                event_type = EventType.AUTH_DISCONNECT.value
                source_ip = received.group("ip")
                extra["source_port"] = int(received.group("port"))
                if received.group("reason"):
                    extra["disconnect_reason"] = received.group("reason")
            elif user_disconnect:
                event_type = EventType.AUTH_DISCONNECT.value
                username = user_disconnect.group("user")
                source_ip = user_disconnect.group("ip")
                extra["source_port"] = int(user_disconnect.group("port"))
            elif closed:
                event_type = EventType.AUTH_DISCONNECT.value
                username = closed.group("user")
                source_ip = closed.group("ip")
                extra["source_port"] = int(closed.group("port"))

        event = ParsedEventData(
            event_category=EventCategory.AUTHENTICATION,
            event_type=event_type,
            timestamp=resolution,
            hostname=hostname,
            source_ip=source_ip,
            username=username,
            process=program,
            pid=pid,
            message=message,
            extra=extra,
        )
        return LineParseResult(
            event=event,
            issues=issues,
            optional_fields_missing=optional_fields_missing,
        )
