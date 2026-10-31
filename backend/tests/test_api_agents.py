from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import Agent, EvidenceFile
from app.services.agent_auth import hash_agent_token

ENROLLMENT_HEADER = "X-Enrollment-Token"


def _agent_uid() -> str:
    return f"test-agent-{uuid.uuid4().hex[:12]}"


def _register(
    client: TestClient,
    settings,
    investigation_id: str,
    *,
    agent_uid: str | None = None,
    enrollment_token: str | None = None,
    source_key: str = "auth-log",
    source_type: str = "linux_auth",
    source_enabled: bool = True,
):
    payload = {
        "agent_uid": agent_uid or _agent_uid(),
        "display_name": "Synthetic host",
        "hostname": "web01.test",
        "platform": "Linux test",
        "agent_version": "0.2.0",
        "investigation_id": investigation_id,
        "sources": [
            {
                "key": source_key,
                "name": "Synthetic auth log",
                "source_type": source_type,
                "path_hint": "/var/log/auth.log",
                "enabled": source_enabled,
            }
        ],
    }
    return client.post(
        "/api/agents/register",
        json=payload,
        headers={
            ENROLLMENT_HEADER: enrollment_token
            if enrollment_token is not None
            else settings.agent_enrollment_token
        },
    )


def _manifest(
    investigation_id: str,
    *,
    source_key: str = "auth-log",
    source_type: str = "linux_auth",
    content: bytes | None = None,
    filename: str = "auth.log",
    batch_id: str | None = None,
    item_id: str | None = None,
    sha256: str | None = None,
    collected_at: str | None = None,
    with_errors: bool = False,
):
    body = content if content is not None else b""
    batch_id = batch_id or f"batch-{uuid.uuid4().hex}"
    item_id = item_id or uuid.uuid4().hex
    now = collected_at or datetime.now(UTC).isoformat()
    manifest = {
        "batch_id": batch_id,
        "investigation_id": investigation_id,
        "created_at": datetime.now(UTC).isoformat(),
        "agent_version": "0.2.0",
        "items": []
        if with_errors
        else [
            {
                "item_id": item_id,
                "source_key": source_key,
                "source_type": source_type,
                "filename": filename,
                "sha256": sha256 or hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
                "collected_at": now,
                "range_start": 0,
                "range_end": len(body),
            }
        ],
        "errors": [
            {
                "source_key": source_key,
                "code": "source_read_error",
                "message": "Synthetic collection failure.",
                "occurred_at": now,
            }
        ]
        if with_errors
        else [],
    }
    raw = json.dumps(manifest, separators=(",", ":"))
    return manifest, raw, body


def _upload(
    client: TestClient,
    token: str,
    manifest_raw: str,
    body: bytes | None,
    *,
    filename: str = "auth.log",
):
    files = []
    if body is not None:
        files.append(("files", (filename, body, "text/plain")))
    return client.post(
        "/api/agents/batches",
        headers={"Authorization": f"Bearer {token}"},
        data={"manifest": manifest_raw},
        files=files,
    )


def test_registration_requires_enrollment_and_stores_only_token_hash(
    client: TestClient, settings, investigation, db_session
):
    uid = _agent_uid()
    denied = _register(
        client,
        settings,
        investigation["id"],
        agent_uid=uid,
        enrollment_token="wrong-enrollment-token-0000000000",
    )
    assert denied.status_code == 401

    missing = client.post(
        "/api/agents/register",
        json={
            "agent_uid": uid,
            "display_name": "Synthetic host",
            "hostname": "web01.test",
            "platform": "Linux test",
            "agent_version": "0.2.0",
            "investigation_id": investigation["id"],
            "sources": [],
        },
    )
    assert missing.status_code == 401

    response = _register(client, settings, investigation["id"], agent_uid=uid)
    assert response.status_code == 201, response.text
    payload = response.json()
    token = payload["agent_token"]
    assert token.startswith("ct_agent_")
    assert payload["agent_uid"] == uid
    assert payload["investigation_id"] == investigation["id"]
    assert payload["rotated"] is False

    agent = db_session.scalar(select(Agent).where(Agent.id == uuid.UUID(payload["agent_id"])))
    assert agent is not None
    assert agent.token_hash == hash_agent_token(token)
    assert token not in agent.token_hash
    assert agent.token_hash != token

    me = client.get(
        "/api/agents/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert me.status_code == 200, me.text
    assert me.json()["agent_uid"] == uid
    assert [source["source_key"] for source in me.json()["sources"]] == ["auth-log"]


def test_registration_rejects_unknown_investigation_and_rotates_tokens(
    client: TestClient, settings, investigation
):
    missing = _register(
        client,
        settings,
        "00000000-0000-0000-0000-000000000000",
    )
    assert missing.status_code == 404

    first = _register(client, settings, investigation["id"])
    assert first.status_code == 201, first.text
    first_token = first.json()["agent_token"]
    uid = first.json()["agent_uid"]

    second = _register(client, settings, investigation["id"], agent_uid=uid)
    assert second.status_code == 201, second.text
    second_token = second.json()["agent_token"]
    assert second.json()["rotated"] is True
    assert second_token != first_token

    old = client.get(
        "/api/agents/me", headers={"Authorization": f"Bearer {first_token}"}
    )
    assert old.status_code == 401
    current = client.get(
        "/api/agents/me", headers={"Authorization": f"Bearer {second_token}"}
    )
    assert current.status_code == 200


def test_source_sync_and_heartbeat_report_errors(
    client: TestClient, settings, investigation
):
    registered = _register(client, settings, investigation["id"])
    assert registered.status_code == 201
    token = registered.json()["agent_token"]
    agent_id = registered.json()["agent_id"]
    headers = {"Authorization": f"Bearer {token}"}

    synced = client.put(
        "/api/agents/sources",
        headers=headers,
        json={
            "sources": [
                {
                    "key": "auth-log",
                    "name": "Updated auth log",
                    "source_type": "linux_auth",
                    "path_hint": "/var/log/auth.log",
                    "enabled": True,
                }
            ]
        },
    )
    assert synced.status_code == 200, synced.text
    assert synced.json()["updated"] == 1

    heartbeat = client.post(
        "/api/agents/heartbeat",
        headers=headers,
        json={
            "agent_version": "0.2.0",
            "runtime_status": "degraded",
            "queue_pending_batches": 2,
            "queue_pending_bytes": 4096,
            "sources": [
                {
                    "key": "auth-log",
                    "status": "error",
                    "path_readable": False,
                    "cursor_bytes": 128,
                    "last_error": "Permission denied",
                }
            ],
            "errors": [
                {
                    "source_key": "auth-log",
                    "code": "permission_denied",
                    "message": "Permission denied while reading the auth log.",
                }
            ],
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["acknowledged"] is True
    assert heartbeat.json()["errors_recorded"] == 1

    detail = client.get(f"/api/agents/{agent_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["queue_pending_batches"] == 2
    assert body["queue_pending_bytes"] == 4096
    assert body["sources"][0]["status"] == "error"
    assert (
        body["sources"][0]["last_error"]
        == "Permission denied while reading the auth log."
    )
    assert len(body["recent_errors"]) == 1
    assert body["recent_errors"][0]["error_code"] == "permission_denied"

    healthy = client.post(
        "/api/agents/heartbeat",
        headers=headers,
        json={
            "agent_version": "0.2.0",
            "runtime_status": "running",
            "sources": [
                {
                    "key": "auth-log",
                    "status": "healthy",
                    "path_readable": True,
                    "cursor_bytes": 256,
                }
            ],
        },
    )
    assert healthy.status_code == 200, healthy.text
    detail = client.get(f"/api/agents/{agent_id}").json()
    assert detail["sources"][0]["status"] == "healthy"
    assert detail["sources"][0]["last_error"] is None


def test_agent_list_detail_health_and_management(
    client: TestClient, settings, investigation, db_session
):
    registered = _register(client, settings, investigation["id"])
    assert registered.status_code == 201
    agent_id = registered.json()["agent_id"]
    token = registered.json()["agent_token"]

    listed = client.get("/api/agents")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["source_count"] == 1

    detail = client.get(f"/api/agents/{agent_id}")
    assert detail.status_code == 200
    assert detail.json()["id"] == agent_id
    assert len(detail.json()["sources"]) == 1

    health = client.get("/api/agents/health")
    assert health.status_code == 200
    assert health.json()["total_agents"] == 1
    assert health.json()["online"] == 1

    agent = db_session.scalar(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    assert agent is not None
    agent.last_seen_at = datetime.now(UTC) - timedelta(
        seconds=settings.agent_stale_after_seconds + 60
    )
    db_session.commit()

    stale = client.get("/api/agents?health=stale")
    assert stale.status_code == 200
    assert stale.json()["total"] == 1
    assert stale.json()["items"][0]["health"] == "stale"

    disabled = client.post(
        f"/api/agents/{agent_id}/disable",
        headers={ENROLLMENT_HEADER: settings.agent_enrollment_token},
    )
    assert disabled.status_code == 200
    forbidden = client.get(
        "/api/agents/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert forbidden.status_code == 403
    re_register = _register(
        client,
        settings,
        investigation["id"],
        agent_uid=registered.json()["agent_uid"],
    )
    assert re_register.status_code == 403

    enabled = client.post(
        f"/api/agents/{agent_id}/enable",
        headers={ENROLLMENT_HEADER: settings.agent_enrollment_token},
    )
    assert enabled.status_code == 200
    restored = client.get(
        "/api/agents/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert restored.status_code == 200

    deleted = client.delete(
        f"/api/agents/{agent_id}",
        headers={ENROLLMENT_HEADER: settings.agent_enrollment_token},
    )
    assert deleted.status_code == 200
    assert client.get("/api/agents").json()["total"] == 0


def test_agent_batch_is_accepted_hashed_parsed_and_idempotent(
    client: TestClient,
    settings,
    investigation,
    fixture_text,
    db_session,
):
    registered = _register(client, settings, investigation["id"])
    assert registered.status_code == 201
    token = registered.json()["agent_token"]
    content = fixture_text("linux_auth_valid.log").encode("utf-8")
    manifest, raw, body = _manifest(investigation["id"], content=content)

    first = _upload(client, token, raw, body)
    assert first.status_code == 200, first.text
    result = first.json()
    assert result["status"] == "processed"
    assert result["accepted_items"] == 1
    assert result["duplicate_items"] == 0
    assert result["failed_items"] == 0
    assert result["file_count"] == 1
    assert result["items"][0]["status"] == "accepted"

    evidence = client.get(
        f"/api/evidence?investigation_id={investigation['id']}"
    )
    assert evidence.status_code == 200
    assert evidence.json()["total"] == 1
    evidence_item = evidence.json()["items"][0]
    assert evidence_item["sha256"] == hashlib.sha256(body).hexdigest()
    assert evidence_item["parser_name"] == "linux_auth_syslog"

    stored = db_session.scalar(
        select(EvidenceFile).where(EvidenceFile.id == uuid.UUID(evidence_item["id"]))
    )
    assert stored is not None
    assert stored.metadata_json["agent"]["agent_version"] == "0.2.0"
    assert stored.metadata_json["agent_collection"]["transport_sha256"] == hashlib.sha256(
        body
    ).hexdigest()

    coverage = client.get(
        f"/api/quality/investigations/{investigation['id']}/coverage"
    )
    assert coverage.status_code == 200, coverage.text
    covered_source = coverage.json()["sources"][0]
    assert covered_source["coverage_state"] in {"reporting", "idle"}
    assert covered_source["collection_available"] is True
    assert covered_source["bytes_received"] == len(body)
    assert covered_source["observed_cycles"] >= 1
    assert covered_source["missing_cycles"] == 0
    assert covered_source["events_observed"] == 7

    replay = _upload(client, token, raw, body)
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["accepted_items"] == 1
    assert client.get(f"/api/evidence?investigation_id={investigation['id']}").json()[
        "total"
    ] == 1

    duplicate_manifest, duplicate_raw, duplicate_body = _manifest(
        investigation["id"], content=content
    )
    duplicate = _upload(client, token, duplicate_raw, duplicate_body)
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["duplicate_items"] == 1
    assert duplicate.json()["accepted_items"] == 0
    assert client.get(f"/api/evidence?investigation_id={investigation['id']}").json()[
        "total"
    ] == 1

    batches = client.get(f"/api/agents/{registered.json()['agent_id']}/batches")
    assert batches.status_code == 200
    assert batches.json()["total"] == 2


def test_agent_batch_byte_range_gap_is_recorded(
    client: TestClient, settings, investigation, fixture_text
):
    registered = _register(client, settings, investigation["id"])
    assert registered.status_code == 201
    token = registered.json()["agent_token"]
    content = fixture_text("linux_auth_valid.log").encode("utf-8")

    first_manifest, first_raw, first_body = _manifest(
        investigation["id"], content=content
    )
    first = _upload(client, token, first_raw, first_body)
    assert first.status_code == 200, first.text
    assert first.json()["accepted_items"] == 1

    second_content = content + (
        b"2026-10-31T10:05:00+00:00 web01 sshd[9]: "
        b"Accepted password for carol from 203.0.113.10 port 2222 ssh2\n"
    )
    second_manifest, _, second_body = _manifest(
        investigation["id"], content=second_content
    )
    second_manifest["items"][0]["range_start"] = len(content) + 7
    second_manifest["items"][0]["range_end"] = len(content) + 7 + len(second_body)
    second_raw = json.dumps(second_manifest, separators=(",", ":"))
    second = _upload(client, token, second_raw, second_body)
    assert second.status_code == 200, second.text
    assert second.json()["accepted_items"] == 1

    gaps = client.get(
        f"/api/quality/investigations/{investigation['id']}/gaps"
    ).json()
    assert gaps["total"] == 1
    gap = gaps["items"][0]
    assert gap["reason"] == "byte_range_gap"
    assert gap["status"] == "closed"
    assert gap["basis"] == "observed"
    assert gap["detail"]["missing_bytes"] == 7
    assert "not measured failure instants" in gap["detail"]["note"]


def test_agent_batch_validation_failures_do_not_store_evidence(
    client: TestClient, settings, investigation
):
    registered = _register(client, settings, investigation["id"])
    assert registered.status_code == 201
    token = registered.json()["agent_token"]
    content = b"2026-10-31T10:00:00+00:00 web01 sshd[1]: Accepted password for alice\n"

    _, bad_raw, bad_body = _manifest(
        investigation["id"], content=content, sha256="0" * 64
    )
    mismatch = _upload(client, token, bad_raw, bad_body)
    assert mismatch.status_code == 422
    assert "integrity" in mismatch.text.lower()

    _, unknown_raw, unknown_body = _manifest(
        investigation["id"], content=content, source_key="unknown-source"
    )
    unknown = _upload(client, token, unknown_raw, unknown_body)
    assert unknown.status_code == 422
    assert "not registered" in unknown.text.lower()

    _, wrong_raw, wrong_body = _manifest(
        investigation["id"], content=content, source_type="web_access"
    )
    wrong = _upload(client, token, wrong_raw, wrong_body)
    assert wrong.status_code == 422
    assert "does not match" in wrong.text.lower()

    assert client.get(f"/api/evidence?investigation_id={investigation['id']}").json()[
        "total"
    ] == 0
    assert client.get(f"/api/agents/{registered.json()['agent_id']}/batches").json()[
        "total"
    ] == 0

    unauthorized = _upload(client, "ct_agent_invalid-token", bad_raw, bad_body)
    assert unauthorized.status_code == 401


def test_agent_batch_accepts_manifest_errors_and_reports_them(
    client: TestClient, settings, investigation
):
    registered = _register(client, settings, investigation["id"])
    assert registered.status_code == 201
    token = registered.json()["agent_token"]
    manifest, raw, _ = _manifest(investigation["id"], with_errors=True)

    response = _upload(client, token, raw, None)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["file_count"] == 0
    assert result["status"] == "processed"
    assert result["errors_recorded"] == 1

    detail = client.get(f"/api/agents/{registered.json()['agent_id']}").json()
    assert detail["recent_errors"][0]["error_code"] == "source_read_error"

    assert client.get(f"/api/evidence?investigation_id={investigation['id']}").json()[
        "total"
    ] == 0
    assert (
        client.get(f"/api/agents/{registered.json()['agent_id']}/batches").json()[
            "total"
        ]
        == 1
    )

