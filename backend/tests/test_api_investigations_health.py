from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient


def _dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def test_health_reports_database_schema_and_storage(client: TestClient):
    response = client.get("/api/health")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database"] == "ok"
    assert payload["schema_status"] == "ok"
    assert payload["storage"] == "ok"
    assert payload["version"] == "0.4.3"


def test_openapi_documents_phase_1_and_agent_endpoints(client: TestClient):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/investigations" in paths
    assert "/api/investigations/{investigation_id}/evidence" in paths
    assert "/api/investigations/{investigation_id}/sources" in paths
    assert "/api/timeline" in paths
    assert "/api/evidence/{evidence_id}/verify" in paths
    assert "/api/evidence/{evidence_id}/reparse" in paths
    assert "/api/agents/register" in paths
    assert "/api/agents/heartbeat" in paths
    assert "/api/agents/batches" in paths
    assert "/api/quality/overview" in paths
    assert "/api/quality/investigations/{investigation_id}/coverage" in paths
    assert "/api/quality/investigations/{investigation_id}/manifest" in paths


def test_dashboards_are_served(client: TestClient):
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Investigation Dashboard - CyberTrace" in dashboard.text
    assert "/static/dashboard.js" in dashboard.text

    dashboard_alias = client.get("/dashboard")
    assert dashboard_alias.status_code == 200
    assert dashboard_alias.text == dashboard.text

    workspace = client.get("/workspace")
    assert workspace.status_code == 200
    assert "Digital Forensics Timeline Analyzer" in workspace.text
    assert "/static/app.js" in workspace.text

    agents = client.get("/agents")
    assert agents.status_code == 200
    assert "Endpoint agents" in agents.text
    assert "/static/agents.js" in agents.text

    quality = client.get("/quality")
    assert quality.status_code == 200
    assert "Evidence quality" in quality.text
    assert "/static/quality.js" in quality.text


def test_create_list_and_get_investigation(client: TestClient):
    created = client.post(
        "/api/investigations",
        json={"name": "  Incident 42  ", "description": "  Synthetic scenario  "},
    )
    assert created.status_code == 201, created.text
    investigation = created.json()
    assert investigation["name"] == "Incident 42"
    assert investigation["description"] == "Synthetic scenario"
    assert investigation["source_count"] == 0
    assert investigation["evidence_count"] == 0
    assert investigation["event_count"] == 0

    listed = client.get("/api/investigations")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()] == [investigation["id"]]

    fetched = client.get(f"/api/investigations/{investigation['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == investigation["id"]


def test_investigation_validation_and_not_found(client: TestClient):
    assert client.post("/api/investigations", json={"name": "   "}).status_code == 422
    assert client.post("/api/investigations", json={"name": ""}).status_code == 422

    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/investigations/{missing}").status_code == 404
    assert client.get(f"/api/investigations/{missing}/summary").status_code == 404
    assert client.get(f"/api/evidence?investigation_id={missing}").status_code == 404


def test_empty_investigation_summary_and_timeline(client: TestClient, investigation):
    summary = client.get(f"/api/investigations/{investigation['id']}/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["sources"] == 0
    assert payload["evidence_files"] == 0
    assert payload["events"] == 0
    assert payload["issues_total"] == 0
    assert payload["hashes_unverified"] == 0
    assert payload["earliest_collected_at"] is None
    assert payload["latest_collected_at"] is None

    timeline = client.get(f"/api/timeline?investigation_id={investigation['id']}")
    assert timeline.status_code == 200
    assert timeline.json()["items"] == []
    assert timeline.json()["total"] == 0


def test_sources_and_summary_collection_range(
    client: TestClient, investigation, upload_log, fixture_text
):
    auth = upload_log(
        investigation["id"],
        fixture_text("linux_auth_valid.log"),
        filename="auth.log",
        source_name="auth-b",
        collected_at="2026-10-31T10:30:00+05:30",
    )
    assert auth.status_code == 201, auth.text
    web = upload_log(
        investigation["id"],
        fixture_text("nginx_access_valid.log"),
        filename="access.log",
        source_name="web-a",
        collected_at="2026-10-31T06:00:00Z",
    )
    assert web.status_code == 201, web.text

    sources = client.get(f"/api/investigations/{investigation['id']}/sources")
    assert sources.status_code == 200, sources.text
    payload = sources.json()
    assert [item["name"] for item in payload] == ["auth-b", "web-a"]
    assert all(item["investigation_id"] == investigation["id"] for item in payload)

    summary = client.get(f"/api/investigations/{investigation['id']}/summary")
    assert summary.status_code == 200, summary.text
    body = summary.json()
    assert body["sources"] == 2
    assert body["evidence_files"] == 2
    assert _dt(body["earliest_collected_at"]) == datetime(2026, 10, 31, 5, 0, tzinfo=UTC)
    assert _dt(body["latest_collected_at"]) == datetime(2026, 10, 31, 6, 0, tzinfo=UTC)

    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/investigations/{missing}/sources").status_code == 404
