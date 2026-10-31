from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SAMPLE_ROOT = Path(__file__).resolve().parents[2] / "samples"


@pytest.mark.parametrize(
    ("scenario", "auth_events", "web_events"),
    [
        ("scenario_1_ssh_bruteforce", 7, 5),
        ("scenario_2_web_intrusion", 4, 5),
        ("scenario_3_timezone_gap", 2, 1),
    ],
)
def test_synthetic_incident_scenarios_are_fully_ingestible(
    client: TestClient,
    investigation,
    upload_log,
    scenario: str,
    auth_events: int,
    web_events: int,
):
    folder = SAMPLE_ROOT / scenario
    login_refs = upload_log(
        investigation["id"],
        (folder / "auth.log").read_bytes(),
        filename=f"{scenario}-auth.log",
        source_name=f"{scenario}-auth",
        source_type="linux_auth",
        timezone_hint="Asia/Kolkata",
        default_year=2026,
    )
    assert login_refs.status_code == 201, login_refs.text
    login_evidence = login_refs.json()
    assert login_evidence["event_count"] == auth_events
    assert login_evidence["status"] == "parsed"
    assert login_evidence["parsing_result"]["issues_recorded"] == 0

    web_refs = upload_log(
        investigation["id"],
        (folder / "access.log").read_bytes(),
        filename=f"{scenario}-access.log",
        source_name=f"{scenario}-web",
        source_type="web_access",
        hostname="portal",
        timezone_hint="Asia/Kolkata",
        default_year=2026,
    )
    assert web_refs.status_code == 201, web_refs.text
    web_evidence = web_refs.json()
    assert web_evidence["event_count"] == web_events
    assert web_evidence["status"] == "parsed"
    assert web_evidence["parsing_result"]["issues_recorded"] == 0

    timeline = client.get(
        f"/api/timeline?investigation_id={investigation['id']}&include_unknown_time=false"
    )
    assert timeline.status_code == 200, timeline.text
    payload = timeline.json()
    assert payload["total"] == auth_events + web_events
    assert all(item["timestamp_status"] == "normalized" for item in payload["items"])

    summary = client.get(f"/api/investigations/{investigation['id']}/summary").json()
    assert summary["sources"] == 2
    assert summary["evidence_files"] == 2
    assert summary["events"] == auth_events + web_events
    assert summary["issues_total"] == 0
