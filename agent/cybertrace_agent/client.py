"""Authenticated, standard-library-only HTTP client for the CyberTrace server."""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import socket
import ssl
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from cybertrace_agent import AGENT_VERSION
from cybertrace_agent.config import AgentConfig

logger = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_USER_AGENT = f"cybertrace-agent/{AGENT_VERSION}"


class AgentClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str,
        retryable: bool,
        status_code: int | None = None,
        detail: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.status_code = status_code
        self.detail = detail
        self.retry_after = retry_after


class EnrollmentRejected(AgentClientError):
    def __init__(self, message: str, *, status_code: int, detail: str | None) -> None:
        super().__init__(
            message,
            code="enrollment_rejected",
            retryable=False,
            status_code=status_code,
            detail=detail,
        )


class AuthenticationRejected(AgentClientError):
    def __init__(self, message: str, *, status_code: int, detail: str | None) -> None:
        super().__init__(
            message,
            code="authentication_rejected",
            retryable=False,
            status_code=status_code,
            detail=detail,
        )


class RequestRejected(AgentClientError):
    def __init__(
        self, message: str, *, status_code: int, detail: str | None, code: str = "request_rejected"
    ) -> None:
        super().__init__(
            message,
            code=code,
            retryable=False,
            status_code=status_code,
            detail=detail,
        )


class PayloadTooLarge(RequestRejected):
    def __init__(self, message: str, *, status_code: int, detail: str | None) -> None:
        super().__init__(
            message,
            status_code=status_code,
            detail=detail,
            code="payload_too_large",
        )


class TransientClientError(AgentClientError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "transient_network_error",
        status_code: int | None = None,
        detail: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message,
            code=code,
            retryable=True,
            status_code=status_code,
            detail=detail,
            retry_after=retry_after,
        )


class TLSConfigurationError(AgentClientError):
    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(
            message,
            code="tls_configuration_error",
            retryable=False,
            detail=detail,
        )


class ProtocolError(AgentClientError):
    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(
            message,
            code="invalid_server_response",
            retryable=False,
            detail=detail,
        )


class SpoolFileError(AgentClientError):
    def __init__(self, message: str) -> None:
        super().__init__(
            message,
            code="local_spool_invalid",
            retryable=False,
        )


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    agent_id: str
    agent_uid: str
    investigation_id: str
    agent_token: str
    token_prefix: str
    rotated: bool
    stale_after_seconds: int
    server_time: str


@dataclass(frozen=True, slots=True)
class UploadFilePart:
    filename: str
    path: Path
    sha256: str
    size_bytes: int


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    if seconds < 0:
        return 0.0
    return seconds


class AgentClient:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._ssl_context = self._build_ssl_context() if config.scheme == "https" else None

    def _build_ssl_context(self) -> ssl.SSLContext:
        try:
            context = ssl.create_default_context(
                cafile=str(self.config.tls.ca_file) if self.config.tls.ca_file else None
            )
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if self.config.tls.client_cert_file and self.config.tls.client_key_file:
                context.load_cert_chain(
                    certfile=str(self.config.tls.client_cert_file),
                    keyfile=str(self.config.tls.client_key_file),
                )
        except (OSError, ssl.SSLError) as exc:
            raise TLSConfigurationError(
                "Could not configure TLS. Check tls.ca_file, client certificate and key paths.",
                detail=str(exc),
            ) from exc
        return context

    def _connection(self) -> http.client.HTTPConnection:
        timeout = self.config.http_timeout_seconds
        if self.config.scheme == "https":
            return http.client.HTTPSConnection(
                self.config.host,
                self.config.port,
                timeout=timeout,
                context=self._ssl_context,
            )
        if self.config.host not in {"127.0.0.1", "::1", "localhost"}:
            raise TLSConfigurationError(
                "Plain HTTP is only permitted for localhost; refusing to send data."
            )
        return http.client.HTTPConnection(
            self.config.host, self.config.port, timeout=timeout
        )

    def _url_path(self, endpoint: str) -> str:
        return f"{self.config.api_prefix}/{endpoint.lstrip('/')}"

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
        context: str = "request",
    ) -> tuple[int, Any, dict[str, str]]:
        request_headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": _USER_AGENT,
        }
        if headers:
            request_headers.update(headers)
        if token:
            request_headers["Authorization"] = f"Bearer {token}"

        connection: http.client.HTTPConnection | None = None
        try:
            connection = self._connection()
            connection.request(
                method,
                self._url_path(endpoint),
                body=body,
                headers=request_headers,
            )
            response = connection.getresponse()
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise ProtocolError(
                    f"{context}: server response exceeded the {_MAX_RESPONSE_BYTES} byte limit."
                )
            response_headers = {
                key.lower(): value for key, value in response.getheaders()
            }
            status_code = int(response.status)
        except AgentClientError:
            raise
        except ssl.SSLCertVerificationError as exc:
            raise TLSConfigurationError(
                "Server TLS certificate verification failed. Install a trusted CA and verify "
                "the configured server hostname.",
                detail=str(exc),
            ) from exc
        except ssl.SSLError as exc:
            raise TLSConfigurationError(
                "TLS handshake failed; the server certificate or TLS configuration is invalid.",
                detail=str(exc),
            ) from exc
        except (ConnectionError, TimeoutError, socket.gaierror, http.client.HTTPException) as exc:
            raise TransientClientError(
                f"{context}: temporary network failure: {exc}",
                code="temporary_network_failure",
            ) from exc
        except OSError as exc:
            raise TransientClientError(
                f"{context}: temporary connection failure: {exc}",
                code="temporary_network_failure",
            ) from exc
        finally:
            if connection is not None:
                connection.close()

        payload: Any = {}
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                if status_code < 400:
                    raise ProtocolError(
                        f"{context}: server returned a non-JSON response."
                    ) from exc
                payload = raw.decode("utf-8", errors="replace")

        if 200 <= status_code < 300:
            return status_code, payload, response_headers

        detail = self._error_detail(payload)
        server_code = self._server_code(payload)
        self._raise_status(
            status_code, detail, server_code, response_headers, context, endpoint
        )
        raise AssertionError("unreachable")

    @staticmethod
    def _server_code(payload: Any) -> str | None:
        if not isinstance(payload, dict):
            return None
        detail = payload.get("detail")
        if isinstance(detail, dict):
            code = detail.get("code")
            if isinstance(code, str) and code:
                return code[:64]
        code = payload.get("code")
        if isinstance(code, str) and code:
            return code[:64]
        return None

    @staticmethod
    def _error_detail(payload: Any) -> str | None:
        if isinstance(payload, dict):
            detail = payload.get("detail", payload.get("message"))
            if isinstance(detail, dict):
                message = detail.get("message") or detail.get("code")
                if message:
                    return str(message)[:1000]
                return json.dumps(detail, ensure_ascii=True)[:1000]
            if isinstance(detail, list):
                return json.dumps(detail, ensure_ascii=True)[:1000]
            if detail is not None:
                return str(detail)[:1000]
            return None
        if isinstance(payload, str):
            return payload[:1000]
        return None

    def _raise_status(
        self,
        status_code: int,
        detail: str | None,
        server_code: str | None,
        headers: dict[str, str],
        context: str,
        endpoint: str,
    ) -> None:
        suffix = f": {detail}" if detail else ""
        if status_code in (401, 403):
            if endpoint.lstrip("/") == "agents/register":
                raise EnrollmentRejected(
                    f"Server rejected agent enrollment{suffix}",
                    status_code=status_code,
                    detail=detail,
                )
            raise AuthenticationRejected(
                f"Server rejected the agent token{suffix}",
                status_code=status_code,
                detail=detail,
            )
        if status_code == 413:
            raise PayloadTooLarge(
                f"{context}: uploaded data exceeds the server limit{suffix}",
                status_code=status_code,
                detail=detail,
            )
        if status_code == 429:
            raise TransientClientError(
                f"{context}: server is rate limiting requests{suffix}",
                code="rate_limited",
                status_code=status_code,
                detail=detail,
                retry_after=_parse_retry_after(headers.get("retry-after")),
            )
        if status_code >= 500:
            raise TransientClientError(
                f"{context}: server error ({status_code}){suffix}",
                code="server_unavailable",
                status_code=status_code,
                detail=detail,
                retry_after=_parse_retry_after(headers.get("retry-after")),
            )
        raise RequestRejected(
            f"{context}: server rejected the request ({status_code}){suffix}",
            status_code=status_code,
            detail=detail,
            code=server_code or "request_rejected",
        )

    def health(self) -> dict[str, Any]:
        _, payload, _ = self._request("GET", "agents/health", context="health check")
        if not isinstance(payload, dict):
            raise ProtocolError("health check: server returned an unexpected response")
        return payload

    def register(
        self,
        *,
        enrollment_token: str,
        agent_uid: str,
        display_name: str,
        hostname: str,
        platform: str,
        investigation_id: str,
        sources: list[dict[str, Any]],
    ) -> RegistrationResult:
        body = json.dumps(
            {
                "agent_uid": agent_uid,
                "display_name": display_name,
                "hostname": hostname,
                "platform": platform,
                "agent_version": AGENT_VERSION,
                "investigation_id": investigation_id,
                "sources": sources,
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        _, payload, _ = self._request(
            "POST",
            "agents/register",
            body=body,
            headers={
                "Content-Type": "application/json",
                "X-Enrollment-Token": enrollment_token,
            },
            context="agent registration",
        )
        if not isinstance(payload, dict):
            raise ProtocolError("agent registration: server returned an unexpected response")
        token = payload.get("agent_token")
        if not isinstance(token, str) or not token.startswith("ct_agent_"):
            raise ProtocolError("agent registration: server did not return a valid agent token")
        agent_id = payload.get("agent_id")
        investigation = payload.get("investigation_id")
        try:
            uuid.UUID(str(agent_id))
            uuid.UUID(str(investigation))
        except (ValueError, TypeError) as exc:
            raise ProtocolError(
                "agent registration: server returned invalid identifiers"
            ) from exc
        return RegistrationResult(
            agent_id=str(agent_id),
            agent_uid=str(payload.get("agent_uid") or agent_uid),
            investigation_id=str(investigation),
            agent_token=token,
            token_prefix=str(payload.get("token_prefix") or token[:16]),
            rotated=bool(payload.get("rotated", False)),
            stale_after_seconds=int(payload.get("stale_after_seconds") or 0),
            server_time=str(payload.get("server_time") or ""),
        )

    def me(self, token: str) -> dict[str, Any]:
        _, payload, _ = self._request(
            "GET", "agents/me", token=token, context="agent identity check"
        )
        if not isinstance(payload, dict):
            raise ProtocolError("agent identity check: server returned an unexpected response")
        return payload

    def sync_sources(self, token: str, sources: list[dict[str, Any]]) -> dict[str, Any]:
        body = json.dumps({"sources": sources}, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
        _, payload, _ = self._request(
            "PUT",
            "agents/sources",
            body=body,
            headers={"Content-Type": "application/json"},
            token=token,
            context="source inventory sync",
        )
        if not isinstance(payload, dict):
            raise ProtocolError("source inventory sync: server returned an unexpected response")
        return payload

    def heartbeat(self, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        _, response, _ = self._request(
            "POST",
            "agents/heartbeat",
            body=body,
            headers={"Content-Type": "application/json"},
            token=token,
            context="heartbeat",
        )
        if not isinstance(response, dict):
            raise ProtocolError("heartbeat: server returned an unexpected response")
        return response

    def upload_batch(
        self,
        token: str,
        manifest: dict[str, Any],
        parts: list[UploadFilePart],
    ) -> dict[str, Any]:
        if len(parts) > 200:
            raise SpoolFileError("A batch cannot contain more than 200 files.")
        boundary = f"cybertrace-{uuid.uuid4().hex}"
        manifest_bytes = json.dumps(
            manifest, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        body = bytearray()
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(b'Content-Disposition: form-data; name="manifest"\r\n')
        body.extend(b"Content-Type: application/json\r\n\r\n")
        body.extend(manifest_bytes)
        body.extend(b"\r\n")

        for part in parts:
            data = self._read_verified_part(part)
            safe_filename = (
                part.filename.replace('"', "_").replace("\r", "").replace("\n", "")
            )
            body.extend(f"--{boundary}\r\n".encode("ascii"))
            body.extend(
                (
                    'Content-Disposition: form-data; name="files"; '
                    f'filename="{safe_filename}"\r\n'
                ).encode()
            )
            body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
            body.extend(data)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode("ascii"))

        _, payload, _ = self._request(
            "POST",
            "agents/batches",
            body=bytes(body),
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            token=token,
            context="batch upload",
        )
        if not isinstance(payload, dict):
            raise ProtocolError("batch upload: server returned an unexpected response")
        return payload

    @staticmethod
    def _read_verified_part(part: UploadFilePart) -> bytes:
        try:
            stat = part.path.stat()
        except OSError as exc:
            raise SpoolFileError(f"Spool file is missing or unreadable: {part.path.name}") from exc
        if not stat.st_size == part.size_bytes:
            raise SpoolFileError(
                f"Spool file size changed for {part.path.name}: expected "
                f"{part.size_bytes}, found {stat.st_size}."
            )
        try:
            data = part.path.read_bytes()
        except OSError as exc:
            raise SpoolFileError(f"Could not read spool file {part.path.name}: {exc}") from exc
        if len(data) != part.size_bytes:
            raise SpoolFileError(f"Spool file {part.path.name} changed while being read.")
        if hashlib.sha256(data).hexdigest().lower() != part.sha256.lower():
            raise SpoolFileError(
                f"Spool file {part.path.name} failed its SHA-256 check; refusing to upload it."
            )
        return data
