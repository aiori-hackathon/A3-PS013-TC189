from __future__ import annotations

from datetime import UTC, datetime

from app.constants import EventType, IssueType, TimestampStatus
from app.services.parsers.base import ParserConfig
from app.services.parsers.linux_auth import LinuxAuthParser
from app.services.parsers.web_access import WebAccessParser


def parse_auth(line: str, **config):
    return LinuxAuthParser().parse_line(line, ParserConfig(**config))


def parse_web(line: str, **config):
    return WebAccessParser().parse_line(line, ParserConfig(**config))


def test_valid_linux_auth_iso_record_with_explicit_offset():
    line = (
        "2026-10-31T09:58:01.123456+05:30 web01 sshd[2401]: "
        "Accepted password for alice from 192.168.1.10 port 51234 ssh2"
    )
    result = parse_auth(line)

    assert result.event is not None
    event = result.event
    assert event.event_type == EventType.AUTH_SUCCESS.value
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.10"
    assert event.hostname == "web01"
    assert event.process == "sshd"
    assert event.pid == 2401
    assert event.extra["source_port"] == 51234
    assert event.timestamp.status is TimestampStatus.NORMALIZED
    assert event.timestamp.utc == datetime(2026, 10, 31, 4, 28, 1, 123456, tzinfo=UTC)
    assert event.timestamp.original_string == "2026-10-31T09:58:01.123456+05:30"
    assert not result.issues


def test_valid_linux_auth_failed_invalid_user_and_sudo():
    failed = parse_auth(
        "2026-10-31T10:00:12+05:30 web01 sshd[2402]: "
        "Failed password for invalid user admin from 203.0.113.5 port 45678 ssh2"
    )
    assert failed.event is not None
    assert failed.event.event_type == EventType.AUTH_INVALID_USER.value
    assert failed.event.username == "admin"
    assert failed.event.source_ip == "203.0.113.5"

    failed_known_user = parse_auth(
        "2026-10-31T10:00:20+05:30 web01 sshd[2402]: "
        "Failed password for alice from 203.0.113.5 port 45682 ssh2"
    )
    assert failed_known_user.event is not None
    assert failed_known_user.event.event_type == EventType.AUTH_FAILURE.value

    sudo = parse_auth(
        "2026-10-31T10:01:00+05:30 web01 sudo: "
        "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
    )
    assert sudo.event is not None
    assert sudo.event.event_type == EventType.SUDO_COMMAND.value
    assert sudo.event.username == "alice"
    assert sudo.event.extra["target_user"] == "root"
    assert sudo.event.extra["command"] == "/usr/bin/id"


def test_linux_auth_missing_field_is_flagged_but_event_kept():
    result = parse_auth(
        "2026-10-31T09:58:01+00:00 web01 sshd[1]: Accepted password for alice"
    )
    assert result.event is not None
    assert result.event.event_type == EventType.AUTH_SUCCESS.value
    assert result.event.source_ip is None
    assert any(
        issue.issue_type == IssueType.MISSING_REQUIRED_FIELD.value
        for issue in result.issues
    )


def test_malformed_linux_auth_line_is_recorded_not_dropped_silently():
    result = parse_auth("this is not an authentication log record")
    assert result.event is None
    assert any(
        issue.issue_type == IssueType.MALFORMED_LINE.value for issue in result.issues
    )


def test_valid_web_access_combined_record():
    line = (
        '203.0.113.77 - - [31/Oct/2026:09:55:12 +0530] "POST /login HTTP/1.1" '
        '401 87 "https://example.test/login" "Mozilla/5.0"'
    )
    result = parse_web(line, hostname_fallback="web-01")

    assert result.event is not None
    event = result.event
    assert event.event_type == EventType.HTTP_REQUEST.value
    assert event.hostname == "web-01"
    assert event.source_ip == "203.0.113.77"
    assert event.http_method == "POST"
    assert event.http_path == "/login"
    assert event.http_status == 401
    assert event.http_bytes == 87
    assert event.http_referer == "https://example.test/login"
    assert event.http_user_agent == "Mozilla/5.0"
    assert event.extra["protocol"] == "HTTP/1.1"
    assert event.timestamp.status is TimestampStatus.NORMALIZED
    assert event.timestamp.utc == datetime(2026, 10, 31, 4, 25, 12, tzinfo=UTC)


def test_valid_web_access_common_record_without_referer():
    line = '192.0.2.10 - - [31/Oct/2026:04:32:00 +0000] "GET /login HTTP/1.0" 200 512'
    result = parse_web(line)
    assert result.event is not None
    assert result.event.http_referer is None
    assert result.event.http_user_agent is None
    assert result.event.http_status == 200


def test_malformed_web_access_line():
    result = parse_web("definitely not an access log")
    assert result.event is None
    assert result.issues[0].issue_type == IssueType.MALFORMED_LINE.value


def test_web_access_missing_request_field_is_flagged():
    line = '192.0.2.10 - - [31/Oct/2026:04:32:00 +0000] "-" 400 0 "-" "-"'
    result = parse_web(line)
    assert result.event is not None
    assert result.event.http_method is None
    assert any(
        issue.issue_type == IssueType.MISSING_REQUIRED_FIELD.value
        for issue in result.issues
    )
