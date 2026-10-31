"""Timestamp parsing and UTC normalization.

Normalization is deliberately conservative: a UTC value is produced only when
an explicit offset or a user-supplied IANA time zone is available. Yearless
syslog is only resolved when the caller explicitly supplies a default year.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.constants import TimestampStatus

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_SYSLOG_TS_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})$"
)
_WEB_TS_RE = re.compile(
    r"^(?P<day>\d{1,2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\s+(?P<offset>Z|[+-]\d{4}))?$"
)
_OFFSET_SUFFIX_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


@dataclass(frozen=True, slots=True)
class TimestampResolution:
    utc: datetime | None
    status: TimestampStatus
    original_string: str | None
    original_timezone: str | None
    detail: str | None = None
    precision: str | None = None
    clock_offset_seconds: int | None = None
    clock_offset_applied: bool = False


def _invalid(original: str | None, detail: str) -> TimestampResolution:
    return TimestampResolution(
        utc=None,
        status=TimestampStatus.INVALID,
        original_string=original,
        original_timezone=None,
        detail=detail,
    )


def missing_timestamp(detail: str) -> TimestampResolution:
    """Return a resolution for a record that has no timestamp field at all."""

    return TimestampResolution(
        utc=None,
        status=TimestampStatus.MISSING_TIMESTAMP,
        original_string=None,
        original_timezone=None,
        detail=detail,
    )


def apply_clock_offset(
    resolution: TimestampResolution, offset_seconds: int | None
) -> TimestampResolution:
    """Apply an explicitly configured source-clock offset.

    The offset is the source clock's displacement from UTC: positive means the
    source clock is ahead of UTC, so the recorded local value is moved back.
    An unset or ``None`` offset leaves the timestamp completely untouched.
    """

    if offset_seconds is None:
        return resolution

    if offset_seconds < -86400 or offset_seconds > 86400:
        detail = (
            f"Configured source clock offset {offset_seconds:+d}s is outside the supported "
            "range (-86400..86400), so it was recorded but not applied."
        )
        return replace(
            resolution,
            detail=_join_detail(resolution.detail, detail),
            clock_offset_seconds=offset_seconds,
            clock_offset_applied=False,
        )

    if resolution.status is TimestampStatus.NORMALIZED and resolution.utc is not None:
        adjusted = resolution.utc - timedelta(seconds=offset_seconds)
        detail = (
            f"A configured source clock offset of {offset_seconds:+d}s was applied "
            "(positive means the source clock was ahead of UTC)."
        )
        return replace(
            resolution,
            utc=adjusted,
            detail=_join_detail(resolution.detail, detail),
            clock_offset_seconds=offset_seconds,
            clock_offset_applied=True,
        )

    detail = (
        f"A configured source clock offset of {offset_seconds:+d}s was recorded but not "
        "applied because this record has no normalized UTC value."
    )
    return replace(
        resolution,
        detail=_join_detail(resolution.detail, detail),
        clock_offset_seconds=offset_seconds,
        clock_offset_applied=False,
    )


def _join_detail(existing: str | None, addition: str) -> str:
    if not existing:
        return addition
    return f"{existing} {addition}"


def _normalize_local(
    naive: datetime,
    *,
    timezone_hint: str | None,
    original_string: str | None,
    original_timezone: str | None,
    extra_detail: str | None = None,
) -> TimestampResolution:
    if not timezone_hint:
        detail = (
            "Wall-clock timestamp has no UTC offset and no timezone hint was supplied; "
            "UTC normalization was skipped."
        )
        if extra_detail:
            detail = f"{detail} {extra_detail}"
        return TimestampResolution(
            utc=None,
            status=TimestampStatus.MISSING_TIMEZONE,
            original_string=original_string,
            original_timezone=None,
            detail=detail,
            precision="microsecond" if naive.microsecond else "second",
        )

    try:
        zone = ZoneInfo(timezone_hint)
    except ZoneInfoNotFoundError:
        return TimestampResolution(
            utc=None,
            status=TimestampStatus.MISSING_TIMEZONE,
            original_string=original_string,
            original_timezone=None,
            detail=f"Unknown timezone hint {timezone_hint!r}; UTC normalization was skipped.",
        )

    fold_zero = naive.replace(tzinfo=zone, fold=0)
    fold_one = naive.replace(tzinfo=zone, fold=1)
    if fold_zero.utcoffset() != fold_one.utcoffset():
        detail = (
            f"Local time {naive.isoformat(sep=' ')} is ambiguous in {timezone_hint} "
            "(DST fold); both UTC mappings are plausible, so no UTC value was chosen."
        )
        if extra_detail:
            detail = f"{detail} {extra_detail}"
        return TimestampResolution(
            utc=None,
            status=TimestampStatus.AMBIGUOUS,
            original_string=original_string,
            original_timezone=timezone_hint,
            detail=detail,
        )

    round_trip = fold_zero.astimezone(UTC).astimezone(zone).replace(tzinfo=None)
    if round_trip != naive:
        detail = (
            f"Local time {naive.isoformat(sep=' ')} does not exist in {timezone_hint} "
            "because of a DST transition, so no UTC value was chosen."
        )
        if extra_detail:
            detail = f"{detail} {extra_detail}"
        return TimestampResolution(
            utc=None,
            status=TimestampStatus.AMBIGUOUS,
            original_string=original_string,
            original_timezone=timezone_hint,
            detail=detail,
        )

    detail = f"Normalized using supplied timezone {timezone_hint}."
    if extra_detail:
        detail = f"{detail} {extra_detail}"
    return TimestampResolution(
        utc=fold_zero.astimezone(UTC),
        status=TimestampStatus.NORMALIZED,
        original_string=original_string,
        original_timezone=timezone_hint,
        detail=detail,
        precision="microsecond" if naive.microsecond else "second",
    )


def _normalize_aware(
    aware: datetime,
    *,
    original_string: str | None,
    original_timezone: str | None,
    extra_detail: str | None = None,
) -> TimestampResolution:
    detail = "Normalized using the timestamp's explicit UTC offset."
    if extra_detail:
        detail = f"{detail} {extra_detail}"
    return TimestampResolution(
        utc=aware.astimezone(UTC),
        status=TimestampStatus.NORMALIZED,
        original_string=original_string,
        original_timezone=original_timezone or _offset_text(aware),
        detail=detail,
        precision="microsecond" if aware.microsecond else "second",
    )


def _offset_text(value: datetime) -> str | None:
    offset = value.utcoffset()
    if offset is None:
        return None
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    return f"{sign}{total_minutes // 60:02d}:{total_minutes % 60:02d}"


def resolve_syslog_timestamp(
    token: str, *, timezone_hint: str | None, default_year: int | None
) -> TimestampResolution:
    """Resolve classic RFC 3164 timestamps such as ``Oct 31 10:15:32``."""

    match = _SYSLOG_TS_RE.match(token)
    if not match:
        return _invalid(token, "Timestamp does not match the RFC 3164 syslog layout.")

    month = MONTHS.get(match.group("month"))
    if month is None:
        return _invalid(token, f"Unknown month name {match.group('month')!r}.")

    if default_year is None:
        detail = (
            "RFC 3164 syslog timestamps have no year. No default_year was supplied, "
            "so UTC normalization was skipped."
        )
        if timezone_hint:
            detail = f"{detail} Timezone hint {timezone_hint!r} alone is not enough."
        return TimestampResolution(
            utc=None,
            status=TimestampStatus.MISSING_YEAR,
            original_string=token,
            original_timezone=timezone_hint,
            detail=detail,
        )

    try:
        naive = datetime(
            year=default_year,
            month=month,
            day=int(match.group("day")),
            hour=int(match.group("hour")),
            minute=int(match.group("minute")),
            second=int(match.group("second")),
        )
    except ValueError as exc:
        return _invalid(token, f"Timestamp components are invalid: {exc}.")

    return _normalize_local(
        naive,
        timezone_hint=timezone_hint,
        original_string=token,
        original_timezone=timezone_hint,
        extra_detail=f"Year {default_year} was supplied explicitly via default_year.",
    )


def resolve_iso_timestamp(token: str, *, timezone_hint: str | None) -> TimestampResolution:
    try:
        parsed = datetime.fromisoformat(token.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError as exc:
        return _invalid(token, f"ISO 8601 timestamp could not be parsed: {exc}.")

    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        suffix = _OFFSET_SUFFIX_RE.search(token)
        return _normalize_aware(
            parsed,
            original_string=token,
            original_timezone=suffix.group(1) if suffix else _offset_text(parsed),
        )

    return _normalize_local(
        parsed,
        timezone_hint=timezone_hint,
        original_string=token,
        original_timezone=timezone_hint,
    )


def resolve_web_timestamp(token: str, *, timezone_hint: str | None) -> TimestampResolution:
    """Resolve CLF/combined timestamps such as ``31/Oct/2026:09:55:05 +0530``."""

    match = _WEB_TS_RE.match(token)
    if not match:
        return _invalid(token, "Timestamp does not match the Apache/nginx access-log layout.")

    month = MONTHS.get(match.group("month").title())
    if month is None:
        return _invalid(token, f"Unknown month name {match.group('month')!r}.")

    try:
        naive = datetime(
            year=int(match.group("year")),
            month=month,
            day=int(match.group("day")),
            hour=int(match.group("hour")),
            minute=int(match.group("minute")),
            second=int(match.group("second")),
        )
    except ValueError as exc:
        return _invalid(token, f"Timestamp components are invalid: {exc}.")

    offset = match.group("offset")
    if offset:
        if offset == "Z":
            aware = naive.replace(tzinfo=UTC)
        else:
            sign = 1 if offset[0] == "+" else -1
            hours = int(offset[1:3])
            minutes = int(offset[3:5])
            if hours > 23 or minutes > 59:
                return _invalid(token, f"UTC offset {offset!r} is out of range.")
            aware = naive.replace(
                tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes))
            )
        return _normalize_aware(
            aware, original_string=token, original_timezone=offset
        )

    return _normalize_local(
        naive,
        timezone_hint=timezone_hint,
        original_string=token,
        original_timezone=timezone_hint,
    )
