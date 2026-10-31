from __future__ import annotations

from datetime import UTC, datetime

from app.constants import TimestampStatus
from app.services.timeutil import (
    resolve_iso_timestamp,
    resolve_syslog_timestamp,
    resolve_web_timestamp,
)


def test_known_offset_is_normalized_to_utc():
    result = resolve_iso_timestamp(
        "2026-10-31T09:58:01.123456+05:30", timezone_hint=None
    )
    assert result.status is TimestampStatus.NORMALIZED
    assert result.utc == datetime(2026, 10, 31, 4, 28, 1, 123456, tzinfo=UTC)
    assert result.original_timezone == "+05:30"
    assert result.original_string == "2026-10-31T09:58:01.123456+05:30"


def test_web_offset_normalization():
    result = resolve_web_timestamp("31/Oct/2026:09:55:05 +0530", timezone_hint=None)
    assert result.status is TimestampStatus.NORMALIZED
    assert result.utc == datetime(2026, 10, 31, 4, 25, 5, tzinfo=UTC)


def test_naive_timestamp_without_timezone_is_not_guessed():
    result = resolve_web_timestamp("31/Oct/2026:09:55:05", timezone_hint=None)
    assert result.status is TimestampStatus.MISSING_TIMEZONE
    assert result.utc is None
    assert "skipped" in (result.detail or "")


def test_naive_timestamp_with_supplied_timezone_is_normalized():
    result = resolve_web_timestamp(
        "31/Oct/2026:09:55:05", timezone_hint="Asia/Kolkata"
    )
    assert result.status is TimestampStatus.NORMALIZED
    assert result.utc == datetime(2026, 10, 31, 4, 25, 5, tzinfo=UTC)
    assert result.original_timezone == "Asia/Kolkata"


def test_yearless_syslog_without_year_is_flagged():
    result = resolve_syslog_timestamp(
        "Oct 31 10:05:00", timezone_hint="Asia/Kolkata", default_year=None
    )
    assert result.status is TimestampStatus.MISSING_YEAR
    assert result.utc is None


def test_yearless_syslog_with_explicit_year_and_timezone_is_normalized():
    result = resolve_syslog_timestamp(
        "Oct 31 10:05:00", timezone_hint="Asia/Kolkata", default_year=2026
    )
    assert result.status is TimestampStatus.NORMALIZED
    assert result.utc == datetime(2026, 10, 31, 4, 35, 0, tzinfo=UTC)
    assert "default_year" in (result.detail or "").lower() or "supplied" in (
        result.detail or ""
    ).lower()


def test_syslog_year_without_timezone_is_flagged():
    result = resolve_syslog_timestamp(
        "Oct 31 10:05:00", timezone_hint=None, default_year=2026
    )
    assert result.status is TimestampStatus.MISSING_TIMEZONE
    assert result.utc is None


def test_dst_fold_is_ambiguous_and_not_guessed():
    result = resolve_syslog_timestamp(
        "Nov  1 01:30:00", timezone_hint="America/New_York", default_year=2026
    )
    assert result.status is TimestampStatus.AMBIGUOUS
    assert result.utc is None


def test_invalid_web_timestamp_is_flagged():
    result = resolve_web_timestamp("99/Foo/2026:09:55:05 +0530", timezone_hint=None)
    assert result.status is TimestampStatus.INVALID
    assert result.utc is None
