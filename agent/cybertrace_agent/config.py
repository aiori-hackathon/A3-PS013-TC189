"""Strict JSON configuration loading for the CyberTrace agent."""

from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cybertrace_agent import AGENT_VERSION

SOURCE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
AGENT_UID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
ALLOWED_SOURCE_TYPES = {"linux_auth", "web_access"}
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}

_TOP_LEVEL_KEYS = {
    "server_url",
    "api_prefix",
    "enrollment_token_file",
    "state_dir",
    "investigation_id",
    "agent_uid",
    "display_name",
    "heartbeat_interval_seconds",
    "collection_interval_seconds",
    "flush_interval_seconds",
    "max_backoff_seconds",
    "http_timeout_seconds",
    "max_batch_bytes",
    "max_batch_files",
    "max_segment_bytes",
    "max_buffer_bytes",
    "start_position",
    "tls",
    "allow_insecure_localhost",
    "sources",
}
_TLS_KEYS = {"ca_file", "client_cert_file", "client_key_file"}
_SOURCE_KEYS = {
    "key",
    "name",
    "source_type",
    "path",
    "timezone_hint",
    "default_year",
    "enabled",
    "clock_offset_seconds",
    "expected_collection_interval_seconds",
}


class AgentConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TLSSettings:
    ca_file: Path | None = None
    client_cert_file: Path | None = None
    client_key_file: Path | None = None


@dataclass(frozen=True, slots=True)
class SourceConfig:
    key: str
    name: str
    source_type: str
    path: Path
    timezone_hint: str | None = None
    default_year: int | None = None
    enabled: bool = True
    clock_offset_seconds: int | None = None
    expected_collection_interval_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class AgentConfig:
    server_url: str
    scheme: str
    host: str
    port: int
    api_prefix: str
    state_dir: Path
    investigation_id: str
    enrollment_token_file: Path | None
    agent_uid: str | None
    display_name: str
    heartbeat_interval_seconds: int
    collection_interval_seconds: int
    flush_interval_seconds: int
    max_backoff_seconds: int
    http_timeout_seconds: int
    max_batch_bytes: int
    max_batch_files: int
    max_segment_bytes: int
    max_buffer_bytes: int
    start_position: str
    tls: TLSSettings
    allow_insecure_localhost: bool
    sources: tuple[SourceConfig, ...]
    agent_version: str = AGENT_VERSION

    @property
    def enabled_sources(self) -> tuple[SourceConfig, ...]:
        return tuple(source for source in self.sources if source.enabled)


def _fail(message: str) -> AgentConfigError:
    return AgentConfigError(message)


def _check_keys(data: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise _fail(f"{where} contains unknown keys: {', '.join(unknown)}")


def _require_str(data: dict[str, Any], key: str, *, maximum: int = 2048) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _fail(f"{key} must be a non-empty string")
    value = value.strip()
    if len(value) > maximum:
        raise _fail(f"{key} must be at most {maximum} characters")
    return value


def _optional_str(data: dict[str, Any], key: str, *, maximum: int = 2048) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _fail(f"{key} must be a string or null")
    value = value.strip()
    if not value:
        return None
    if len(value) > maximum:
        raise _fail(f"{key} must be at most {maximum} characters")
    return value


def _optional_bool(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise _fail(f"{key} must be true or false")
    return value


def _positive_int(
    data: dict[str, Any],
    key: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int = 10**9,
) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise _fail(f"{key} must be between {minimum} and {maximum}")
    return value


def _resolve_path(value: str, key: str) -> Path:
    if "\x00" in value:
        raise _fail(f"{key} must not contain NUL bytes")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise _fail(f"{key} must be an absolute path")
    return path.resolve(strict=False)


def _timezone_hint(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as exc:
        raise _fail(f"timezone_hint {value!r} is not a valid IANA timezone") from exc
    return value


def _load_sources(raw: Any) -> tuple[SourceConfig, ...]:
    if not isinstance(raw, list) or not raw:
        raise _fail("sources must be a non-empty list")
    sources: list[SourceConfig] = []
    keys: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise _fail(f"sources[{index}] must be an object")
        _check_keys(item, _SOURCE_KEYS, f"sources[{index}]")
        key = _require_str(item, "key", maximum=64)
        if not SOURCE_KEY_RE.fullmatch(key):
            raise _fail(
                f"sources[{index}].key must match {SOURCE_KEY_RE.pattern}"
            )
        if key in keys:
            raise _fail(f"duplicate source key {key!r}")
        keys.add(key)

        source_type = _require_str(item, "source_type", maximum=32)
        if source_type not in ALLOWED_SOURCE_TYPES:
            raise _fail(
                f"sources[{index}].source_type must be one of "
                f"{', '.join(sorted(ALLOWED_SOURCE_TYPES))}"
            )
        name = _require_str(item, "name", maximum=200)
        path = _resolve_path(_require_str(item, "path"), f"sources[{index}].path")
        if path.exists() and not path.is_file():
            raise _fail(f"sources[{index}].path is not a regular file: {path}")
        timezone_hint = _timezone_hint(
            _optional_str(item, "timezone_hint", maximum=64)
        )
        default_year = item.get("default_year")
        if default_year is not None:
            if isinstance(default_year, bool) or not isinstance(default_year, int):
                raise _fail(f"sources[{index}].default_year must be an integer")
            if not 1970 <= default_year <= 2100:
                raise _fail(f"sources[{index}].default_year must be between 1970 and 2100")
        enabled = _optional_bool(item, "enabled", True)
        clock_offset_seconds = item.get("clock_offset_seconds")
        if clock_offset_seconds is not None:
            if isinstance(clock_offset_seconds, bool) or not isinstance(
                clock_offset_seconds, int
            ):
                raise _fail(
                    f"sources[{index}].clock_offset_seconds must be an integer"
                )
            if not -86400 <= clock_offset_seconds <= 86400:
                raise _fail(
                    f"sources[{index}].clock_offset_seconds must be between "
                    "-86400 and 86400"
                )
        expected_collection_interval_seconds = item.get(
            "expected_collection_interval_seconds"
        )
        if expected_collection_interval_seconds is not None:
            if isinstance(expected_collection_interval_seconds, bool) or not isinstance(
                expected_collection_interval_seconds, int
            ):
                raise _fail(
                    f"sources[{index}].expected_collection_interval_seconds must be "
                    "an integer"
                )
            if not 5 <= expected_collection_interval_seconds <= 86400:
                raise _fail(
                    f"sources[{index}].expected_collection_interval_seconds must be "
                    "between 5 and 86400"
                )
        sources.append(
            SourceConfig(
                key=key,
                name=name,
                source_type=source_type,
                path=path,
                timezone_hint=timezone_hint,
                default_year=default_year,
                enabled=enabled,
                clock_offset_seconds=clock_offset_seconds,
                expected_collection_interval_seconds=(
                    expected_collection_interval_seconds
                ),
            )
        )
    return tuple(sources)


def _load_tls(raw: Any) -> TLSSettings:
    if raw is None:
        return TLSSettings()
    if not isinstance(raw, dict):
        raise _fail("tls must be an object")
    _check_keys(raw, _TLS_KEYS, "tls")
    ca_file = _optional_str(raw, "ca_file")
    cert_file = _optional_str(raw, "client_cert_file")
    key_file = _optional_str(raw, "client_key_file")
    if bool(cert_file) != bool(key_file):
        raise _fail("tls.client_cert_file and tls.client_key_file must be set together")
    ca_path = _resolve_path(ca_file, "tls.ca_file") if ca_file else None
    cert_path = (
        _resolve_path(cert_file, "tls.client_cert_file") if cert_file else None
    )
    key_path = _resolve_path(key_file, "tls.client_key_file") if key_file else None
    for label, path in (
        ("tls.ca_file", ca_path),
        ("tls.client_cert_file", cert_path),
        ("tls.client_key_file", key_path),
    ):
        if path is not None and not path.is_file():
            raise _fail(f"{label} does not exist or is not a file")
    return TLSSettings(
        ca_file=ca_path, client_cert_file=cert_path, client_key_file=key_path
    )


def load_config(path: str | Path) -> AgentConfig:
    config_path = Path(path).expanduser()
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise _fail(f"cannot read configuration {config_path}: {exc}") from exc
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise _fail(f"configuration is not valid JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(data, dict):
        raise _fail("configuration root must be an object")
    _check_keys(data, _TOP_LEVEL_KEYS, "configuration")

    server_url = _require_str(data, "server_url")
    parts = urlsplit(server_url)
    if parts.scheme not in {"https", "http"}:
        raise _fail("server_url must use https:// (http:// is only allowed for localhost labs)")
    if not parts.hostname:
        raise _fail("server_url must include a host")
    if parts.username or parts.password:
        raise _fail("server_url must not contain embedded credentials")
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise _fail("server_url must be an origin such as https://host:8443")

    allow_insecure = _optional_bool(data, "allow_insecure_localhost", False)
    host = parts.hostname.lower()
    if parts.scheme == "http":
        if not allow_insecure or host not in LOCAL_HOSTS:
            raise _fail(
                "plain HTTP is refused. Use HTTPS with a trusted CA, or set "
                "allow_insecure_localhost=true for 127.0.0.1/::1 only."
            )
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise _fail("server_url contains an invalid port") from exc

    api_prefix = _optional_str(data, "api_prefix", maximum=100) or "/api"
    if not api_prefix.startswith("/"):
        api_prefix = "/" + api_prefix
    api_prefix = api_prefix.rstrip("/") or "/api"

    state_dir_raw = _require_str(data, "state_dir")
    state_dir = _resolve_path(state_dir_raw, "state_dir")
    enrollment_raw = _optional_str(data, "enrollment_token_file")
    enrollment_token_file = (
        _resolve_path(enrollment_raw, "enrollment_token_file") if enrollment_raw else None
    )

    investigation_id = _require_str(data, "investigation_id", maximum=64)
    try:
        import uuid

        uuid.UUID(investigation_id)
    except ValueError as exc:
        raise _fail("investigation_id must be a UUID") from exc

    agent_uid = _optional_str(data, "agent_uid", maximum=128)
    if agent_uid is not None and not AGENT_UID_RE.fullmatch(agent_uid):
        raise _fail(f"agent_uid must match {AGENT_UID_RE.pattern}")

    display_name = _optional_str(data, "display_name", maximum=200) or socket.gethostname()
    if not display_name:
        raise _fail("display_name must not be blank")

    heartbeat = _positive_int(
        data, "heartbeat_interval_seconds", 60, minimum=5, maximum=86400
    )
    collection = _positive_int(
        data, "collection_interval_seconds", 30, minimum=1, maximum=86400
    )
    flush = _positive_int(data, "flush_interval_seconds", 30, minimum=1, maximum=86400)
    backoff = _positive_int(data, "max_backoff_seconds", 300, minimum=5, maximum=86400)
    timeout = _positive_int(data, "http_timeout_seconds", 30, minimum=1, maximum=600)
    max_batch_bytes = _positive_int(
        data, "max_batch_bytes", 1024 * 1024, minimum=1024, maximum=1024 * 1024 * 1024
    )
    max_batch_files = _positive_int(
        data, "max_batch_files", 20, minimum=1, maximum=200
    )
    max_segment_bytes = _positive_int(
        data, "max_segment_bytes", 256 * 1024, minimum=512, maximum=1024 * 1024 * 1024
    )
    if max_segment_bytes > max_batch_bytes:
        raise _fail("max_segment_bytes must not exceed max_batch_bytes")
    max_buffer_bytes = _positive_int(
        data,
        "max_buffer_bytes",
        256 * 1024 * 1024,
        minimum=max_batch_bytes,
        maximum=1024 * 1024 * 1024 * 1024,
    )

    start_position = _optional_str(data, "start_position", maximum=16) or "end"
    if start_position not in {"beginning", "end"}:
        raise _fail("start_position must be 'beginning' or 'end'")

    tls = _load_tls(data.get("tls"))
    sources = _load_sources(data.get("sources"))

    return AgentConfig(
        server_url=server_url,
        scheme=parts.scheme,
        host=host,
        port=port,
        api_prefix=api_prefix,
        state_dir=state_dir,
        investigation_id=investigation_id,
        enrollment_token_file=enrollment_token_file,
        agent_uid=agent_uid,
        display_name=display_name,
        heartbeat_interval_seconds=heartbeat,
        collection_interval_seconds=collection,
        flush_interval_seconds=flush,
        max_backoff_seconds=backoff,
        http_timeout_seconds=timeout,
        max_batch_bytes=max_batch_bytes,
        max_batch_files=max_batch_files,
        max_segment_bytes=max_segment_bytes,
        max_buffer_bytes=max_buffer_bytes,
        start_position=start_position,
        tls=tls,
        allow_insecure_localhost=allow_insecure,
        sources=sources,
    )
