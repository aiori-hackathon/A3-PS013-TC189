from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

AUTH = "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n"
WEB = '203.0.113.5 - alice [31/Oct/2026:10:16:00 +0000] "GET /admin HTTP/1.1" 200 10\n'


def _seed(client: TestClient, investigation_id: str):
    a = client.post(
        f"/api/investigations/{investigation_id}/evidence",
        files={"file": ("auth.log", AUTH.encode("utf-8"), "text/plain")},
        data={"source_name": "auth-server", "source_type": "linux_auth", "timezone_hint": "UTC", "default_year": 2026},
    )
    assert a.status_code == 201, a.text
    w = client.post(
        f"/api/investigations/{investigation_id}/evidence",
        files={"file": ("access.log", WEB.encode("utf-8"), "text/plain")},
        data={"source_name": "web-server", "source_type": "web_access", "hostname": "portal", "timezone_hint": "UTC", "default_year": 2026},
    )
    assert w.status_code == 201, w.text
    # Force an uncertain timestamp by uploading legacy auth without tz/year.
    legacy = "Oct 31 10:20:00 host sshd[2]: Failed password for bob from 198.51.100.7 port 9\n"
    legacy_upload = client.post(
        f"/api/investigations/{investigation_id}/evidence",
        files={"file": ("legacy.log", legacy.encode("utf-8"), "text/plain")},
        data={"source_name": "legacy-server", "source_type": "linux_auth"},
    )
    assert legacy_upload.status_code == 201, legacy_upload.text
    return a.json(), w.json(), legacy_upload.json()


def test_pdf_generation_and_download(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    response = client.get(f"/api/investigations/{investigation['id']}/report.pdf")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert "attachment" in response.headers.get("content-disposition", "")
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 1000


def test_pdf_empty_investigation(client: TestClient, investigation, upload_log):
    response = client.get(f"/api/investigations/{investigation['id']}/report.pdf")
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF")


def test_csv_timeline_export(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    response = client.get(f"/api/investigations/{investigation['id']}/export/timeline.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.splitlines()
    assert lines[0].startswith("event_id,")
    assert len(lines) >= 4
    assert all(len(row.split(",")[0]) > 0 for row in lines[1:])


def test_csv_evidence_export_contains_hashes(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    response = client.get(f"/api/investigations/{investigation['id']}/export/evidence.csv")
    assert response.status_code == 200
    header = response.text.splitlines()[0]
    assert "sha256" in header
    data_lines = response.text.splitlines()[1:]
    assert data_lines
    for line in data_lines:
        # SHA-256 appears as a 64-character hex field.
        assert any(len(field) == 64 for field in line.split(","))


def test_csv_coverage_export(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    response = client.get(f"/api/investigations/{investigation['id']}/export/coverage.csv")
    assert response.status_code == 200
    assert "coverage_state" in response.text.splitlines()[0]


def test_csv_parsing_export(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    response = client.get(f"/api/investigations/{investigation['id']}/export/parsing.csv")
    assert response.status_code == 200
    assert "records_rejected" in response.text.splitlines()[0]


def test_csv_correlations_export(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    response = client.get(f"/api/investigations/{investigation['id']}/export/correlations.csv")
    assert response.status_code == 200
    header = response.text.splitlines()[0]
    assert "correlation_id" in header
    assert "explanation" in header


def test_csv_gaps_export(client: TestClient, investigation, upload_log):
    response = client.get(f"/api/investigations/{investigation['id']}/export/gaps.csv")
    assert response.status_code == 200
    assert "gap_start" in response.text.splitlines()[0]


def test_invalid_report_requests(client: TestClient, investigation, upload_log):
    missing_id = str(uuid.uuid4())
    assert client.get(f"/api/investigations/{missing_id}/report.pdf").status_code == 404
    assert client.get(f"/api/investigations/{investigation['id']}/export/unknown.csv").status_code == 404
    bad_range = client.get(
        f"/api/investigations/{investigation['id']}/report.pdf?start=2026-10-31T12:00:00Z&end=2026-10-31T10:00:00Z"
    )
    assert bad_range.status_code == 422
    bad_csv_range = client.get(
        f"/api/investigations/{investigation['id']}/export/timeline.csv?start=not-a-date"
    )
    assert bad_csv_range.status_code == 422


def test_report_alias_and_dataset_alias(client: TestClient, investigation, upload_log):
    _seed(client, investigation["id"])
    pdf = client.get(f"/api/investigations/{investigation['id']}/report")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    csv = client.get(f"/api/investigations/{investigation['id']}/exports/timeline")
    assert csv.status_code == 200
    assert csv.text.splitlines()[0].startswith("event_id,")


def test_dashboard_report_controls():
    from pathlib import Path

    static_root = Path(__file__).resolve().parents[1] / "app" / "static"
    html = (static_root / "dashboard.html").read_text(encoding="utf-8")
    js = (static_root / "dashboard.js").read_text(encoding="utf-8")
    assert "Investigation reports and exports" in html
    assert "download-pdf" in html
    assert "export-timeline-csv" in html
    assert "updateReportLinks" in js


def test_pdf_table_widths_fit_page(db_session, settings, investigation, upload_log):
    from app.services import reporting as reporting_module
    from app.services.reporting import _table, build_pdf, gather_report_data

    upload = upload_log(
        investigation["id"],
        "Oct 31 10:15:32 host sshd[1]: Accepted password for alice from 203.0.113.5 port 123\n",
        filename="auth.log",
    )
    assert upload.status_code == 201, upload.text

    captured: list[list[float]] = []
    real_table = _table

    def wrapper(headers, rows, widths):
        captured.append(list(widths))
        return real_table(headers, rows, widths)

    reporting_module._table = wrapper  # test instrumentation
    try:
        pdf = build_pdf(
            gather_report_data(db_session, settings, uuid.UUID(investigation["id"]))
        )
    finally:
        reporting_module._table = real_table

    assert pdf.startswith(b"%PDF")
    assert captured, "expected report tables to be built"
    page_text_width = 8.5 * 72 - 2 * (0.7 * 72)
    for widths in captured:
        smallest = min(widths)
        # The tightest intended column is 0.6 inch (43.2pt); a points-for-inches
        # regression would produce columns under 3pt.
        assert smallest >= 20, f"column too narrow (points/inches regression?): {widths}"
        assert sum(widths) <= page_text_width + 0.5, f"table wider than page: {widths}"