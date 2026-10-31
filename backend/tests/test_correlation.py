from __future__ import annotations

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import EventCorrelation


def _upload_pair(client, investigation_id, auth_line, web_line, *, window_ok=True):
    auth = client.post(
        f"/api/investigations/{investigation_id}/evidence",
        files={"file": ("auth.log", auth_line.encode("utf-8"), "text/plain")},
        data={
            "source_name": "auth-server",
            "source_type": "linux_auth",
            "timezone_hint": "UTC",
            "default_year": 2026,
        },
    )
    assert auth.status_code == 201, auth.text
    web = client.post(
        f"/api/investigations/{investigation_id}/evidence",
        files={"file": ("access.log", web_line.encode("utf-8"), "text/plain")},
        data={
            "source_name": "web-server",
            "source_type": "web_access",
            "hostname": "portal",
            "timezone_hint": "UTC",
            "default_year": 2026,
        },
    )
    assert web.status_code == 201, web.text
    return auth.json(), web.json()


AUTH = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n"
WEB = '203.0.113.5 - alice [31/Oct/2026:10:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'


def test_positive_correlation_created(client: TestClient, investigation, upload_log):
    _upload_pair(client, investigation["id"], AUTH, WEB)
    response = client.get(f"/api/investigations/{investigation['id']}/correlations")
    assert response.status_code == 200
    correlations = response.json()
    assert len(correlations) >= 1
    correlation = correlations[0]
    assert correlation["confidence"] == "high"
    assert "source_ip" in correlation["matching_fields"]
    assert "username" in correlation["matching_fields"]
    assert correlation["status"] == "suggested"
    assert correlation["events"] and len(correlation["events"]) == 2
    assert "Possible correlation" in correlation["explanation"]
    assert correlation["time_relationship"]
    assert correlation["timestamp_uncertainty"]
    assert set(correlation["source_systems"]) == {"auth-server", "web-server"}
    assert all(event["evidence_sha256"] for event in correlation["events"])


def test_negative_no_shared_identifier(client: TestClient, investigation, upload_log):
    auth = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n"
    web = '198.51.100.7 - bob [31/Oct/2026:10:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'
    _upload_pair(client, investigation["id"], auth, web)
    response = client.get(f"/api/investigations/{investigation['id']}/correlations")
    assert response.status_code == 200
    assert response.json() == []


def test_missing_ip_still_correlates_on_username(client: TestClient, investigation, upload_log):
    auth = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from  port 123\n".replace("from  port", "for alice")
    # Construct a line with no IP by using invalid-user style without IP.
    auth = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice\n"
    web = '203.0.113.5 - alice [31/Oct/2026:10:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'
    _upload_pair(client, investigation["id"], auth, web)
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    assert len(correlations) >= 1
    assert "username" in correlations[0]["matching_fields"]
    # IP was not shared because auth has no IP.
    assert "source_ip" not in correlations[0]["matching_fields"]


def test_missing_all_identifiers_no_correlation(client: TestClient, investigation, upload_log):
    auth = "Oct 31 10:15:32 host sshd[1]: session opened for user\n".replace("user\n", "user root\n")
    # Use lines with no shared IP/username/hostname across sources.
    auth = "Oct 31 10:15:32 host1 sshd[1]: session opened for user root\n"
    web = '203.0.113.5 - - [31/Oct/2026:10:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'
    _upload_pair(client, investigation["id"], auth, web)
    # hostname differs (host1 vs portal fallback web host? portal set as hostname fallback? web hostname fallback is source hostname portal, event hostname portal)
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    # hostname host1 vs portal no match; no IP/username shared.
    assert correlations == []


def test_timestamp_uncertainty_correlation(client: TestClient, investigation, upload_log):
    auth = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n"
    # Web line with no timezone/year uses missing timestamp handling? Use legacy auth style for both? Instead make auth missing timezone.
    auth = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n"
    web = '203.0.113.5 - alice [31/Oct/2026:10:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'
    # Upload auth without timezone hint/default year to force missing_year.
    a = client.post(
        f"/api/investigations/{investigation['id']}/evidence",
        files={"file": ("auth.log", auth.encode("utf-8"), "text/plain")},
        data={"source_name": "auth-server", "source_type": "linux_auth"},
    )
    assert a.status_code == 201, a.text
    w = client.post(
        f"/api/investigations/{investigation['id']}/evidence",
        files={"file": ("access.log", web.encode("utf-8"), "text/plain")},
        data={"source_name": "web-server", "source_type": "web_access", "hostname": "portal", "timezone_hint": "UTC", "default_year": 2026},
    )
    assert w.status_code == 201, w.text
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    assert len(correlations) >= 1
    correlation = correlations[0]
    assert correlation["confidence"] == "low"
    assert "missing" in correlation["timestamp_uncertainty"].lower() or "missing_year" in correlation["timestamp_uncertainty"].lower()
    assert "precise time ordering" in correlation["time_relationship"] or "reliable UTC" in correlation["time_relationship"]


def test_outside_time_window(client: TestClient, investigation, upload_log):
    auth = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n"
    web = '203.0.113.5 - alice [31/Oct/2026:12:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'
    _upload_pair(client, investigation["id"], auth, web)
    # default run uses 30 min window; events 2 hours apart should not correlate.
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    assert correlations == []
    # Even explicit larger window creates correlation.
    run = client.post(
        f"/api/investigations/{investigation['id']}/correlations?time_window_seconds=86400"
    )
    assert run.status_code == 200
    assert len(run.json()["items"]) >= 1


def test_duplicate_events_do_not_break_correlation(client: TestClient, investigation, upload_log):
    _upload_pair(client, investigation["id"], AUTH, WEB)
    # Upload duplicate auth evidence.
    dup = client.post(
        f"/api/investigations/{investigation['id']}/evidence",
        files={"file": ("auth-dup.log", AUTH.encode("utf-8"), "text/plain")},
        data={
            "source_name": "auth-server",
            "source_type": "linux_auth",
            "timezone_hint": "UTC",
            "default_year": 2026,
            "allow_duplicate": "true",
        },
    )
    assert dup.status_code == 201, dup.text
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    assert isinstance(correlations, list)
    assert len(correlations) >= 1


def test_event_correlation_navigation(client: TestClient, investigation, upload_log):
    _upload_pair(client, investigation["id"], AUTH, WEB)
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    assert correlations
    event_id = correlations[0]["event_ids"][0]
    response = client.get(f"/api/events/{event_id}/correlations")
    assert response.status_code == 200
    assert response.json()
    # detail endpoint
    detail = client.get(f"/api/correlations/{correlations[0]['id']}")
    assert detail.status_code == 200
    assert detail.json()["id"] == correlations[0]["id"]


def test_dismiss_and_preserve(client: TestClient, investigation, upload_log):
    _upload_pair(client, investigation["id"], AUTH, WEB)
    correlations = client.get(f"/api/investigations/{investigation['id']}/correlations").json()
    assert correlations
    cid = correlations[0]["id"]
    dismissed = client.post(f"/api/correlations/{cid}/dismiss", json={"reason": "coincidental shared IP"})
    assert dismissed.status_code == 200
    assert dismissed.json()["status"] == "dismissed"
    assert dismissed.json()["dismissal_reason"] == "coincidental shared IP"
    # Re-run preserves dismissed correlation.
    run = client.post(f"/api/investigations/{investigation['id']}/correlations")
    assert run.status_code == 200
    assert run.json()["preserved_dismissed"] >= 1
    suggested = client.get(f"/api/investigations/{investigation['id']}/correlations?status=suggested").json()
    assert all(item["id"] != cid for item in suggested)


def test_database_persistence(client: TestClient, investigation, upload_log, db_session):
    _upload_pair(client, investigation["id"], AUTH, WEB)
    rows = db_session.scalars(
        select(EventCorrelation).where(EventCorrelation.investigation_id == uuid.UUID(investigation["id"]))
    ).all()
    assert len(rows) >= 1


def test_dashboard_integration_files():
    from pathlib import Path

    static_root = Path(__file__).resolve().parents[1] / "app" / "static"
    html = (static_root / "dashboard.html").read_text(encoding="utf-8")
    js = (static_root / "dashboard.js").read_text(encoding="utf-8")
    assert "Event correlations" in html
    assert "correlation-list" in html
    assert "loadCorrelations" in js
    assert "renderCorrelations" in js