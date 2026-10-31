from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from cybertrace_agent.client import (
    AgentClient,
    AuthenticationRejected,
    EnrollmentRejected,
    RequestRejected,
    TransientClientError,
    UploadFilePart,
)
from cybertrace_agent.collector import Collector
from cybertrace_agent.config import (
    AgentConfig,
    AgentConfigError,
    SourceConfig,
    TLSSettings,
    load_config,
)
from cybertrace_agent.runner import AgentRunner, AgentRuntimeError
from cybertrace_agent.state import AgentState, AgentStateError


def _config(
    tmp_path: Path,
    source_path: Path,
    *,
    source_type: str = "linux_auth",
    start_position: str = "beginning",
    max_batch_bytes: int = 1024 * 1024,
    max_segment_bytes: int = 256 * 1024,
    max_batch_files: int = 20,
    max_buffer_bytes: int | None = None,
) -> AgentConfig:
    return AgentConfig(
        server_url="https://cybertrace.test:8443",
        scheme="https",
        host="cybertrace.test",
        port=8443,
        api_prefix="/api",
        state_dir=tmp_path / "state",
        investigation_id=str(uuid.uuid4()),
        enrollment_token_file=None,
        agent_uid="test-agent-12345678",
        display_name="test-agent",
        heartbeat_interval_seconds=60,
        collection_interval_seconds=30,
        flush_interval_seconds=30,
        max_backoff_seconds=300,
        http_timeout_seconds=30,
        max_batch_bytes=max_batch_bytes,
        max_batch_files=max_batch_files,
        max_segment_bytes=max_segment_bytes,
        max_buffer_bytes=max_buffer_bytes or max(max_batch_bytes * 4, 4096),
        start_position=start_position,
        tls=TLSSettings(),
        allow_insecure_localhost=False,
        sources=(
            SourceConfig(
                key="auth-log",
                name="Auth log",
                source_type=source_type,
                path=source_path,
            ),
        ),
    )


def _json_config(tmp_path: Path, source_path: Path) -> dict:
    return {
        "server_url": "https://cybertrace.test:8443",
        "state_dir": str(tmp_path / "state"),
        "investigation_id": str(uuid.uuid4()),
        "display_name": "test-agent",
        "sources": [
            {
                "key": "auth-log",
                "name": "Auth log",
                "source_type": "linux_auth",
                "path": str(source_path),
            }
        ],
    }


def test_load_config_and_reject_unsafe_settings(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line\n")
    config_path = tmp_path / "config.json"
    raw = _json_config(tmp_path, source)
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    config = load_config(config_path)
    assert config.sources[0].key == "auth-log"
    assert config.start_position == "end"

    remote_http = dict(raw)
    remote_http["server_url"] = "http://example.com"
    config_path.write_text(json.dumps(remote_http), encoding="utf-8")
    with pytest.raises(AgentConfigError):
        load_config(config_path)

    local_http = dict(raw)
    local_http["server_url"] = "http://127.0.0.1:8080"
    local_http["allow_insecure_localhost"] = True
    config_path.write_text(json.dumps(local_http), encoding="utf-8")
    assert load_config(config_path).host == "127.0.0.1"

    unknown = dict(raw)
    unknown["unexpected"] = True
    config_path.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(AgentConfigError):
        load_config(config_path)

    bad_limits = dict(raw)
    bad_limits["max_segment_bytes"] = 2048
    bad_limits["max_batch_bytes"] = 1024
    config_path.write_text(json.dumps(bad_limits), encoding="utf-8")
    with pytest.raises(AgentConfigError):
        load_config(config_path)


def test_state_persists_identity_cursors_queue_and_errors(tmp_path: Path):
    state = AgentState(tmp_path / "state")
    uid = state.get_or_create_agent_uid(None)
    assert state.get_or_create_agent_uid(None) == uid
    with pytest.raises(AgentStateError):
        state.get_or_create_agent_uid("different-agent-uid")

    token = "ct_agent_" + "x" * 43
    state.save_token(token)
    assert state.load_token() == token
    assert state.load_token() is not None
    if os.name != "nt":
        assert (state.state_dir / "agent-token").stat().st_mode & 0o777 == 0o600

    state.set_cursor(
        "auth-log",
        path="/var/log/auth.log",
        device=1,
        inode=2,
        offset=100,
    )
    cursor = state.get_cursor("auth-log")
    assert cursor is not None
    assert cursor.offset == 100
    assert cursor.device == 1

    manifest = {
        "batch_id": "batch-test",
        "investigation_id": "00000000-0000-0000-0000-000000000000",
        "items": [],
    }
    state.enqueue_batch(manifest, 123)
    assert state.batch_count() == 1
    assert state.pending_bytes() == 123
    pending = state.pending_batches()
    assert pending[0].batch_id == "batch-test"
    state.update_batch_attempt(
        "batch-test",
        error="temporary",
        next_attempt_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    assert state.pending_batches() == []
    state.remove_batch("batch-test")
    assert state.batch_count() == 0

    first = state.add_error(code="source_read_error", message="permission denied")
    second = state.add_error(code="source_read_error", message="permission denied")
    assert first == second
    assert len(state.unreported_errors()) == 1
    state.mark_errors_reported([first])
    assert state.unreported_errors() == []
    state.close()

    reopened = AgentState(tmp_path / "state")
    assert reopened.get_or_create_agent_uid(None) == uid
    assert reopened.load_token() == token
    reopened.close()


def test_collector_reads_incrementally_and_detects_rotation(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"one\ntwo\n")
    config = _config(tmp_path, source)
    state = AgentState(config.state_dir)
    collector = Collector(config, state)

    first = collector.collect_all()
    assert len(first.segments) == 1
    segment = first.segments[0]
    assert segment.size_bytes == len(b"one\ntwo\n")
    assert segment.sha256
    assert (state.state_dir / segment.spool_file).read_bytes() == b"one\ntwo\n"
    assert segment.lines_collected == 2
    assert segment.expected_bytes == len(b"one\ntwo\n")
    assert segment.collection_started_at is not None
    assert segment.collection_ended_at is not None
    assert first.statuses[0].status == "healthy"
    assert first.statuses[0].collection_available is True
    assert first.statuses[0].bytes_collected_last_cycle == len(b"one\ntwo\n")
    assert first.statuses[0].lines_collected_last_cycle == 2
    assert state.get_cursor("auth-log") is None

    state.set_cursor(
        "auth-log",
        path=str(source),
        device=segment.device,
        inode=segment.inode,
        offset=segment.range_end,
    )
    source.write_bytes(b"one\ntwo\nthree\n")
    second = collector.collect_all()
    assert len(second.segments) == 1
    assert second.segments[0].range_start == len(b"one\ntwo\n")
    assert second.segments[0].range_end == len(b"one\ntwo\nthree\n")

    state.set_cursor(
        "auth-log",
        path=str(source),
        device=segment.device,
        inode=segment.inode,
        offset=second.segments[0].range_end,
    )
    source.write_bytes(b"new\n")
    rotated = collector.collect_all()
    assert len(rotated.segments) == 1
    assert rotated.segments[0].range_start == 0
    assert rotated.segments[0].size_bytes == 4
    state.close()


def test_collector_start_at_end_and_buffer_limit(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"existing\n")
    config = _config(tmp_path, source, start_position="end")
    state = AgentState(config.state_dir)
    collector = Collector(config, state)

    initial = collector.collect_all()
    assert initial.segments == []
    cursor = state.get_cursor("auth-log")
    assert cursor is not None
    assert cursor.offset == len(b"existing\n")

    source.write_bytes(b"existing\nnew\n")
    later = collector.collect_all()
    assert len(later.segments) == 1
    assert later.segments[0].size_bytes == 4
    state.close()

    limited = _config(
        tmp_path / "limited",
        source,
        max_batch_bytes=1024,
        max_segment_bytes=512,
        max_buffer_bytes=1024,
    )
    limited_state = AgentState(limited.state_dir)
    limited_state.enqueue_batch({"batch_id": "queued"}, 1024)
    limited_collector = Collector(limited, limited_state)
    result = limited_collector.collect_all()
    assert result.segments == []
    assert result.statuses[0].status == "error"
    assert any(error.code == "buffer_full" for error in limited_state.unreported_errors())
    limited_state.close()


class _Handler(BaseHTTPRequestHandler):
    requests: list[tuple[str, str, bytes, dict[str, str]]] = []

    def log_message(self, *_args) -> None:
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _record(self, body: bytes) -> None:
        self.requests.append(
            (
                self.command,
                self.path,
                body,
                {key.lower(): value for key, value in self.headers.items()},
            )
        )

    def do_GET(self) -> None:
        body = b""
        self._record(body)
        if self.path == "/api/agents/health":
            self._send(200, {"status": "ok", "total_agents": 1})
            return
        if self.path == "/api/agents/me":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer ct_agent_0123456789abcdef0123456789abcdef":
                self._send(
                    200,
                    {
                        "agent_uid": "test-agent-12345678",
                        "investigation_id": "00000000-0000-0000-0000-000000000001",
                    },
                )
                return
            self._send(401, {"detail": {"code": "invalid_agent_token"}})
            return
        self._send(404, {"detail": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._record(body)
        if self.path == "/api/agents/register":
            if self.headers.get("X-Enrollment-Token") != "enroll-secret":
                self._send(401, {"detail": {"code": "invalid_enrollment_token"}})
                return
            self._send(
                201,
                {
                    "agent_id": "00000000-0000-0000-0000-000000000001",
                    "agent_uid": "test-agent-12345678",
                    "investigation_id": "00000000-0000-0000-0000-000000000001",
                    "agent_token": "ct_agent_0123456789abcdef0123456789abcdef",
                    "token_prefix": "ct_agent_val",
                    "rotated": False,
                    "stale_after_seconds": 300,
                    "server_time": "2026-01-01T00:00:00+00:00",
                },
            )
            return
        if self.path == "/api/agents/heartbeat":
            self._send(
                200,
                {
                    "acknowledged": True,
                    "agent_health": "online",
                    "server_time": "2026-01-01T00:00:00+00:00",
                    "stale_after_seconds": 300,
                    "ignored_sources": [],
                    "errors_recorded": 0,
                },
            )
            return
        if self.path == "/api/agents/batches":
            self._send(
                200,
                {
                    "batch_id": "batch-test",
                    "status": "processed",
                    "accepted_items": 1,
                    "duplicate_items": 0,
                    "failed_items": 0,
                    "items": [],
                },
            )
            return
        self._send(404, {"detail": "not found"})


@pytest.fixture
def http_server():
    _Handler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _localhost_config(tmp_path: Path, source: Path, port: int) -> AgentConfig:
    return AgentConfig(
        server_url=f"http://127.0.0.1:{port}",
        scheme="http",
        host="127.0.0.1",
        port=port,
        api_prefix="/api",
        state_dir=tmp_path / "state",
        investigation_id="00000000-0000-0000-0000-000000000001",
        enrollment_token_file=None,
        agent_uid=None,
        display_name="test-agent",
        heartbeat_interval_seconds=60,
        collection_interval_seconds=30,
        flush_interval_seconds=30,
        max_backoff_seconds=300,
        http_timeout_seconds=5,
        max_batch_bytes=1024 * 1024,
        max_batch_files=20,
        max_segment_bytes=256 * 1024,
        max_buffer_bytes=4 * 1024 * 1024,
        start_position="beginning",
        tls=TLSSettings(),
        allow_insecure_localhost=True,
        sources=(
            SourceConfig(
                key="auth-log",
                name="Auth log",
                source_type="linux_auth",
                path=source,
            ),
        ),
    )


def test_client_transport_and_multipart(tmp_path: Path, http_server):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line\n")
    config = _localhost_config(tmp_path, source, http_server.server_port)
    client = AgentClient(config)

    assert client.health()["status"] == "ok"
    with pytest.raises(EnrollmentRejected):
        client.register(
            enrollment_token="wrong",
            agent_uid="test-agent-12345678",
            display_name="test",
            hostname="test",
            platform="Linux",
            investigation_id=config.investigation_id,
            sources=[],
        )
    result = client.register(
        enrollment_token="enroll-secret",
        agent_uid="test-agent-12345678",
        display_name="test",
        hostname="test",
        platform="Linux",
        investigation_id=config.investigation_id,
        sources=[],
    )
    assert result.agent_token == "ct_agent_0123456789abcdef0123456789abcdef"

    spool = tmp_path / "spool.log"
    spool.write_bytes(b"line\n")
    manifest = {"batch_id": "batch-test", "items": [{"item_id": "item-1"}]}
    response = client.upload_batch(
        result.agent_token,
        manifest,
        [
            UploadFilePart(
                filename="auth.log",
                path=spool,
                sha256=hashlib.sha256(b"line\n").hexdigest(),
                size_bytes=5,
            )
        ],
    )
    assert response["batch_id"] == "batch-test"
    batch_request = [item for item in _Handler.requests if item[1] == "/api/agents/batches"][-1]
    assert b'name="manifest"' in batch_request[2]
    assert b'name="files"; filename="auth.log"' in batch_request[2]
    assert b"line\n" in batch_request[2]


def test_client_maps_authentication_errors(tmp_path: Path, http_server):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line\n")
    client = AgentClient(_localhost_config(tmp_path, source, http_server.server_port))
    with pytest.raises(AuthenticationRejected) as exc:
        client.me("ct_agent_invalid")
    assert exc.value.status_code == 401


class _FakeClock:
    def __init__(self) -> None:
        self.value = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value = self.value + timedelta(seconds=seconds)


class _FakeClient:
    def __init__(self, config: AgentConfig, mode: str = "success") -> None:
        self.config = config
        self.mode = mode
        self.calls: list[str] = []

    def me(self, token: str):
        self.calls.append("me")
        return {
            "agent_uid": "test-agent-12345678",
            "investigation_id": self.config.investigation_id,
        }

    def sync_sources(self, token: str, sources: list[dict]):
        self.calls.append("sync")
        return {"items": [], "created": 0, "updated": 0}

    def upload_batch(self, token: str, manifest: dict, parts: list):
        self.calls.append("upload")
        if self.mode == "transient":
            raise TransientClientError("server unavailable")
        if self.mode == "reject":
            raise RequestRejected(
                "invalid batch",
                status_code=422,
                detail="invalid batch",
            )
        return {
            "batch_id": manifest["batch_id"],
            "status": "processed",
            "accepted_items": len(parts),
            "duplicate_items": 0,
            "failed_items": 0,
            "items": [],
        }


def test_runner_buffers_retries_and_delivers(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line one\n")
    config = _config(tmp_path, source)
    state = AgentState(config.state_dir)
    state.save_token("ct_agent_0123456789abcdef0123456789abcdef")
    clock = _FakeClock()
    fake = _FakeClient(config, mode="transient")
    runner = AgentRunner(
        config,
        state=state,
        client=fake,
        collector=Collector(config, state, clock=clock),
        clock=clock,
    )
    runner._bootstrap()
    assert runner.collect_once() is not None
    assert state.batch_count() == 1
    assert runner.flush_once() == 0
    assert state.batch_count() == 1
    assert fake.calls.count("upload") == 1

    clock.advance(10)
    fake.mode = "success"
    assert runner.flush_once() == 1
    assert state.batch_count() == 0
    assert not any(state.spool_root.iterdir())
    state.close()


def test_runner_heartbeat_reports_intervals_and_collection_state(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line one\nline two\n")
    config = _config(tmp_path, source)
    state = AgentState(config.state_dir)
    state.save_token("ct_agent_0123456789abcdef0123456789abcdef")
    clock = _FakeClock()
    runner = AgentRunner(
        config,
        state=state,
        client=_FakeClient(config),
        collector=Collector(config, state, clock=clock),
        clock=clock,
    )
    runner._bootstrap()
    assert runner.collect_once() is not None
    payload = runner._heartbeat_payload()
    assert payload["heartbeat_interval_seconds"] == 60
    assert payload["collection_interval_seconds"] == 30
    assert payload["reported_at"]
    source_report = payload["sources"][0]
    assert source_report["last_success_at"]
    assert source_report["collection_started_at"]
    assert source_report["collection_ended_at"]
    assert source_report["collection_available"] is True
    assert source_report["bytes_collected_last_cycle"] == len(
        b"line one\nline two\n"
    )
    assert source_report["lines_collected_last_cycle"] == 2
    assert source_report["observed_size_bytes"] == len(b"line one\nline two\n")
    state.close()


def test_runner_quarantines_rejected_batch(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line one\n")
    config = _config(tmp_path, source)
    state = AgentState(config.state_dir)
    state.save_token("ct_agent_0123456789abcdef0123456789abcdef")
    clock = _FakeClock()
    fake = _FakeClient(config, mode="reject")
    runner = AgentRunner(
        config,
        state=state,
        client=fake,
        collector=Collector(config, state, clock=clock),
        clock=clock,
    )
    runner._bootstrap()
    assert runner.collect_once() is not None
    assert runner.flush_once() == 0
    assert state.batch_count() == 0
    quarantined = [path for path in state.quarantine_root.iterdir() if path.is_dir()]
    assert len(quarantined) == 1
    assert (quarantined[0] / "QUARANTINE.txt").exists()
    state.close()


def test_runner_rejects_state_investigation_conflict(tmp_path: Path):
    source = tmp_path / "auth.log"
    source.write_bytes(b"line one\n")
    config = _config(tmp_path, source)
    state = AgentState(config.state_dir)
    state.set_meta("investigation_id", str(uuid.uuid4()))
    runner = AgentRunner(
        config,
        state=state,
        client=_FakeClient(config),
        collector=Collector(config, state),
    )
    with pytest.raises(AgentRuntimeError):
        runner._bootstrap()
    state.close()



