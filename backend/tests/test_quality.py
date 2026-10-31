from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import EvidenceFile, ParsedEvent
from app.services import storage

ENROLLMENT_HEADER = "X-Enrollment-Token"


def _register_agent(client: TestClient, settings, investigation_id: str) -> dict:
    response = client.post(
        "/api/agents/register",
        json={
            "agent_uid": f"quality-agent-{uuid.uuid4().hex[:10]}",
            "display_name": "Quality host",
            "hostname": "quality01.test",
            "platform": "Linux test",
            "agent_version": "0.3.0",
            "investigation_id": investigation_id,
            "sources": [
                {
                    "key": "auth-log",
                    "name": "Quality auth log",
                    "source_type": "linux_auth",
                    "path_hint": "/var/log/auth.log",
                    "enabled": True,
                    "clock_offset_seconds": 5,
                    "expected_collection_interval_seconds": 30,
                }
            ],
        },
        headers={ENROLLMENT_HEADER: settings.agent_enrollment_token},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _heartbeat(
    client: TestClient,
    token: str,
    *,
    source_status: str,
    path_readable: bool,
    last_error: str | None = None,
    last_success_at: str | None = None,
    collection_available: bool | None = None,
    bytes_collected: int = 0,
    collection_started_at: str | None = None,
    collection_ended_at: str | None = None,
):
    payload = {
        "agent_version": "0.3.0",
        "runtime_status": "running" if source_status == "healthy" else "degraded",
        "heartbeat_interval_seconds": 60,
        "collection_interval_seconds": 30,
        "clock_offset_seconds": 5,
        "clock_offset_source": "measured",
        "reported_at": datetime.now(UTC).isoformat(),
        "sources": [
            {
                "key": "auth-log",
                "status": source_status,
                "path_readable": path_readable,
                "last_success_at": last_success_at,
                "collection_started_at": collection_started_at,
                "collection_ended_at": collection_ended_at,
                "bytes_collected_last_cycle": bytes_collected,
                "lines_collected_last_cycle": 0,
                "collection_available": collection_available,
                "last_error": last_error,
            }
        ],
        "errors": [],
    }
    return client.post(
        "/api/agents/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )


def test_timestamp_quality_clock_offset_integrity_and_audit(
    client: TestClient,
    investigation,
    upload_log,
    db_session,
    settings,
):
    content = (
        "2026-10-31T10:00:00+00:00 web01 sshd[1]: Accepted password for alice "
        "from 203.0.113.9 port 2222 ssh2\n"
    )
    uploaded = upload_log(
        investigation["id"],
        content,
        filename="auth.log",
        source_name="auth-quality",
        clock_offset_seconds=3600,
    )
    assert uploaded.status_code == 201, uploaded.text
    evidence = uploaded.json()
    assert evidence["clock_offset_seconds"] == 3600
    assert evidence["event_count"] == 1

    event = db_session.scalar(
        select(ParsedEvent).where(
            ParsedEvent.evidence_file_id == uuid.UUID(evidence["id"])
        )
    )
    assert event is not None
    assert event.timestamp_utc == datetime(2026, 10, 31, 9, 0, tzinfo=UTC)
    assert event.clock_offset_seconds == 3600
    assert event.clock_offset_applied is True
    assert event.timestamp_precision == "second"

    timestamps = client.get(
        f"/api/quality/investigations/{investigation['id']}/timestamps"
    )
    assert timestamps.status_code == 200, timestamps.text
    timestamp_body = timestamps.json()
    assert timestamp_body["total_events"] == 1
    assert timestamp_body["normalized_events"] == 1
    assert timestamp_body["uncertain_events"] == 0
    assert timestamp_body["clock_offset_events"] == 1
    assert "never silently applied" in timestamp_body["timestamp_rule"]

    integrity = client.get(
        f"/api/quality/investigations/{investigation['id']}/integrity"
    )
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["unverified_evidence"] == 1

    verified = client.post(f"/api/evidence/{evidence['id']}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["match"] is True
    assert verified.json()["outcome"] == "verified"

    integrity = client.get(
        f"/api/quality/investigations/{investigation['id']}/integrity"
    )
    assert integrity.json()["verified_evidence"] == 1
    assert integrity.json()["items"][0]["verification_count"] == 1

    timeline_event = client.get(
        f"/api/timeline?investigation_id={investigation['id']}"
    ).json()["items"][0]
    assert timeline_event["evidence_integrity_status"] == "verified"
    assert timeline_event["evidence_last_verified_at"] is not None

    investigation_manifest = client.get(
        f"/api/quality/investigations/{investigation['id']}/manifest"
    )
    assert investigation_manifest.status_code == 200, investigation_manifest.text
    manifest = investigation_manifest.json()
    assert manifest["item_count"] == 1
    assert manifest["items"][0]["sha256"] == evidence["sha256"]
    assert len(manifest["manifest_sha256"]) == 64

    evidence_manifest = client.get(f"/api/evidence/{evidence['id']}/manifest")
    assert evidence_manifest.status_code == 200
    assert evidence_manifest.json()["scope"] == "evidence"
    assert evidence_manifest.json()["items"][0]["sha256"] == evidence["sha256"]

    audit = client.get(f"/api/quality/evidence/{evidence['id']}/audit")
    assert audit.status_code == 200, audit.text
    audit_types = {item["event_type"] for item in audit.json()["items"]}
    assert {
        "evidence_preserved",
        "evidence_parsed",
        "evidence_verified",
        "manifest_exported",
    }.issubset(audit_types)

    verifications = client.get(f"/api/evidence/{evidence['id']}/verifications")
    assert verifications.status_code == 200
    assert verifications.json()["total"] == 1
    assert verifications.json()["items"][0]["outcome"] == "verified"

    stored = db_session.scalar(
        select(EvidenceFile).where(EvidenceFile.id == uuid.UUID(evidence["id"]))
    )
    assert stored is not None
    path = storage.resolve_relative_path(stored.stored_relative_path, settings)
    os.chmod(path, 0o644)
    path.write_bytes(b"tampered after preservation\n")

    mismatch = client.post(f"/api/evidence/{evidence['id']}/verify")
    assert mismatch.status_code == 200, mismatch.text
    assert mismatch.json()["match"] is False
    assert mismatch.json()["outcome"] == "mismatch"

    integrity = client.get(
        f"/api/quality/investigations/{investigation['id']}/integrity"
    )
    assert integrity.json()["mismatched_evidence"] == 1
    mismatch_audit = client.get(
        f"/api/quality/evidence/{evidence['id']}/audit"
    ).json()["items"]
    assert any(
        item["event_type"] == "evidence_verification_mismatch"
        for item in mismatch_audit
    )


def test_timestamp_uncertainty_and_manual_coverage_is_unknown(
    client: TestClient, investigation, upload_log
):
    content = '192.0.2.10 - - [-] "-" 400 0 "-" "-"\n'
    uploaded = upload_log(
        investigation["id"],
        content,
        filename="access.log",
        source_name="manual-web",
        source_type="web_access",
    )
    assert uploaded.status_code == 201, uploaded.text
    evidence = uploaded.json()
    assert evidence["status"] == "parsed_with_issues"
    assert evidence["event_count"] == 1

    timestamps = client.get(
        f"/api/quality/investigations/{investigation['id']}/timestamps"
    ).json()
    assert timestamps["total_events"] == 1
    assert timestamps["normalized_events"] == 0
    assert timestamps["uncertain_events"] == 1
    assert timestamps["timestamp_status_counts"]["missing_timestamp"] == 1
    assert timestamps["uncertain_samples"][0]["timestamp_utc"] is None

    coverage = client.get(
        f"/api/quality/investigations/{investigation['id']}/coverage"
    )
    assert coverage.status_code == 200, coverage.text
    body = coverage.json()
    assert body["summary"]["unknown_sources"] == 1
    assert body["summary"]["reporting_sources"] == 0
    assert body["summary"]["coverage_available"] is True
    manual = body["sources"][0]
    assert manual["coverage_state"] == "unknown"
    assert manual["collection_available"] is None
    assert "coverage cannot be inferred" in manual["collection_unavailable_reason"]

    gaps = client.get(f"/api/quality/investigations/{investigation['id']}/gaps")
    assert gaps.status_code == 200
    assert gaps.json()["total"] == 0

    overview = client.get("/api/quality/overview")
    assert overview.status_code == 200, overview.text
    item = next(
        item
        for item in overview.json()["investigations"]
        if item["investigation_id"] == investigation["id"]
    )
    assert item["timestamp_uncertain_events"] == 1
    assert item["integrity_unverified"] == 1


def test_agent_heartbeat_creates_and_closes_coverage_gap(
    client: TestClient, settings, investigation
):
    registered = _register_agent(client, settings, investigation["id"])
    token = registered["agent_token"]
    now = datetime.now(UTC)

    healthy = _heartbeat(
        client,
        token,
        source_status="healthy",
        path_readable=True,
        last_success_at=(now - timedelta(seconds=30)).isoformat(),
        collection_available=True,
        collection_started_at=(now - timedelta(seconds=30)).isoformat(),
        collection_ended_at=now.isoformat(),
    )
    assert healthy.status_code == 200, healthy.text

    coverage = client.get(
        f"/api/quality/investigations/{investigation['id']}/coverage"
    ).json()
    source = coverage["sources"][0]
    assert source["coverage_state"] in {"reporting", "idle"}
    assert source["collection_available"] is True
    assert source["clock_offset_seconds"] == 5
    assert source["expected_interval_seconds"] == 30
    assert source["missing_cycles"] == 0

    failed = _heartbeat(
        client,
        token,
        source_status="error",
        path_readable=False,
        last_error="Permission denied while reading auth.log",
        collection_available=False,
    )
    assert failed.status_code == 200, failed.text

    gaps = client.get(f"/api/quality/investigations/{investigation['id']}/gaps").json()
    assert gaps["total"] == 1
    gap = gaps["items"][0]
    assert gap["status"] == "open"
    assert gap["reason"] == "source_error"
    assert gap["gap_end"] is None
    assert "not a measured failure instant" in gap["detail"]["note"]

    recovered = _heartbeat(
        client,
        token,
        source_status="healthy",
        path_readable=True,
        last_success_at=datetime.now(UTC).isoformat(),
        collection_available=True,
        bytes_collected=0,
        collection_started_at=datetime.now(UTC).isoformat(),
        collection_ended_at=datetime.now(UTC).isoformat(),
    )
    assert recovered.status_code == 200, recovered.text

    coverage = client.get(
        f"/api/quality/investigations/{investigation['id']}/coverage"
    ).json()
    source = coverage["sources"][0]
    assert source["coverage_state"] in {"reporting", "idle"}
    assert source["open_gap"] is None
    assert source["recovery_count"] == 1
    assert all(gap["status"] == "closed" for gap in coverage["gaps"])

    detail = client.get(f"/api/agents/{registered['agent_id']}").json()
    assert detail["heartbeat_interval_seconds"] == 60
    assert detail["collection_interval_seconds"] == 30
    assert detail["measured_clock_offset_seconds"] == 5
    assert len(detail["recent_heartbeats"]) == 3
    assert detail["recent_heartbeats"][0]["heartbeat_interval_seconds"] == 60


def test_duplicates_are_linked_and_never_deleted(
    client: TestClient, investigation, upload_log
):
    line = (
        "2026-10-31T11:00:00+00:00 web01 sshd[2]: Accepted password for bob "
        "from 198.51.100.4 port 2222 ssh2\n"
    )
    first = upload_log(
        investigation["id"], line, filename="auth-1.log", source_name="same-source"
    )
    second = upload_log(
        investigation["id"],
        line + "\n",
        filename="auth-2.log",
        source_name="same-source",
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text

    evidence_list = client.get(
        f"/api/evidence?investigation_id={investigation['id']}"
    ).json()
    assert evidence_list["total"] == 2

    duplicates = client.get(
        f"/api/quality/investigations/{investigation['id']}/duplicates"
    )
    assert duplicates.status_code == 200, duplicates.text
    body = duplicates.json()
    assert body["total_events"] == 2
    assert body["duplicate_events"] == 1
    assert body["unique_events"] == 1
    assert body["duplicate_groups"] == 1
    group = body["groups"][0]
    assert group["event_count"] == 2
    assert group["canonical_event"]["dedup_status"] == "unique"
    assert group["duplicate_events"][0]["dedup_status"] == "duplicate"
    assert (
        group["duplicate_events"][0]["duplicate_of_event_id"]
        == group["canonical_event"]["event_id"]
    )

    reconcile = client.post(
        f"/api/quality/investigations/{investigation['id']}/reconcile"
    )
    assert reconcile.status_code == 200, reconcile.text
    reconciled = reconcile.json()
    assert reconciled["duplicate_events"] == 1
    assert reconciled["run"]["status"] == "completed"
    assert reconciled["total_events"] == 2

    timeline = client.get(
        f"/api/timeline?investigation_id={investigation['id']}"
    )
    assert timeline.status_code == 200
    assert timeline.json()["total"] == 2
