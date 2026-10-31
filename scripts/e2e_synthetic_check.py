"""End-to-end synthetic verification against a running CyberTrace backend.

Usage: python scripts/e2e_synthetic_check.py [base_url]
Default base URL: http://127.0.0.1:8931

Uploads the three synthetic scenarios from samples/, then exercises the
timeline, quality, correlation, dashboards, PDF, and CSV endpoints. Prints one
PASS/FAIL line per check and exits non-zero on any failure.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"

YEAR_HINT = "2026"

RESULT_LINES: list[str] = []
FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    line = f"PASS {name}" if condition else f"FAIL {name} {detail}".rstrip()
    RESULT_LINES.append(line)
    if not condition:
        FAILURES.append(line)
        print(line)
    else:
        print(line)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8931"
    base = base.rstrip("/")

    with httpx.Client(base_url=base, timeout=30.0) as user:
        health = user.get("/api/health")
        check("health responds 200", health.status_code == 200)
        try:
            payload = health.json()
            check("health reports version 0.4.3", payload.get("version") == "0.4.3",
                  f"got {payload.get('version')}")
        except Exception as exc:  # noqa: BLE001
            check("health JSON parses", False, str(exc))

        dashboards = ["/" , "/agents", "/quality", "/workspace"]
        for path in dashboards:
            resp = user.get(path)
            check(f"dashboard {path} responds 200", resp.status_code == 200,
                  f"status {resp.status_code}")

        created = user.post(
            "/api/investigations",
            json={
                "name": "E2E synthetic demonstration",
                "description": "Automated end-to-end check with synthetic scenario data.",
            },
        )
        check("investigation creation 201", created.status_code == 201, str(created.status_code))
        if created.status_code != 201:
            return 1
        investigation = created.json()
        investigation_id = investigation["id"]

        uploads: list[tuple[Path, dict]] = [
            (SAMPLES / "scenario_1_ssh_bruteforce" / "auth.log",
             {"source_name": "linux-host-1", "source_type": "linux_auth",
              "timezone_hint": "UTC", "default_year": YEAR_HINT, "hostname": "linux-host-1"}),
            (SAMPLES / "scenario_1_ssh_bruteforce" / "access.log",
             {"source_name": "web-host-1", "source_type": "web_access",
              "timezone_hint": "UTC", "default_year": YEAR_HINT, "hostname": "web-host-1"}),
            (SAMPLES / "scenario_2_web_intrusion" / "auth.log",
             {"source_name": "linux-host-2", "source_type": "linux_auth",
              "timezone_hint": "UTC", "default_year": YEAR_HINT, "hostname": "linux-host-2"}),
            (SAMPLES / "scenario_2_web_intrusion" / "access.log",
             {"source_name": "web-host-2", "source_type": "web_access",
              "timezone_hint": "UTC", "default_year": YEAR_HINT, "hostname": "web-host-2"}),
            (SAMPLES / "scenario_3_timezone_gap" / "auth.log",
             {"source_name": "legacy-auth", "source_type": "linux_auth",
              "timezone_hint": "Asia/Kolkata", "default_year": YEAR_HINT}),
            (SAMPLES / "scenario_3_timezone_gap" / "access.log",
             {"source_name": "legacy-web", "source_type": "web_access",
              "timezone_hint": "Asia/Kolkata", "default_year": YEAR_HINT}),
        ]

        for path, form in uploads:
            body = path.read_bytes()
            resp = user.post(
                f"/api/investigations/{investigation_id}/evidence",
                files={"file": (path.name, body, "text/plain")},
                data=form,
            )
            check(f"evidence upload {path.parent.name}/{path.name} 201",
                  resp.status_code == 201, f"status {resp.status_code} body={resp.text[:200]}")

        summary = user.get(f"/api/investigations/{investigation_id}/summary")
        check("summary endpoint 200", summary.status_code == 200)
        if summary.status_code == 200:
            data = summary.json()
            events_total = data.get("events", 0)
            check("timeline events equal 24 (12+9+3)", events_total == 24,
                  f"got {events_total}")

        timeline = user.get(f"/api/timeline?investigation_id={investigation_id}&limit=100")
        check("timeline endpoint 200", timeline.status_code == 200)
        if timeline.status_code == 200:
            events = timeline.json().get("items", [])
            check("timeline returns events", len(events) > 0)
            scenario3_ok = any(
                "2026-10-31T18:10:01" in (event.get("timestamp_utc") or "")
                for event in events
            )
            check("scenario 3 timezone hint normalized (18:10:01Z visible)",
                  scenario3_ok,
                  json.dumps([e.get("timestamp_utc") for e in events[:5]]))

        run = user.post(
            f"/api/investigations/{investigation_id}/correlations"
        )
        check("correlation run 200", run.status_code == 200,
              f"status {run.status_code} body={run.text[:300]}")
        if run.status_code == 200:
            data = run.json()
            # Evidence ingest auto-generates correlations; an explicit run may
            # legitimately only refresh them.
            check("correlations are present or updated",
                  data.get("created", 0) >= 1 or data.get("updated", 0) >= 1,
                  f"created={data.get('created')} updated={data.get('updated')}")

        correlations = user.get(
            f"/api/investigations/{investigation_id}/correlations?include_dismissed=false"
        )
        check("correlations list 200", correlations.status_code == 200)

        quality = user.get("/api/quality/overview")
        check("quality overview 200", quality.status_code == 200)

        pdf = user.get(f"/api/investigations/{investigation_id}/report.pdf")
        check("report.pdf 200", pdf.status_code == 200, f"status {pdf.status_code}")
        check("report.pdf starts with %PDF", pdf.content.startswith(b"%PDF"))
        check("report.pdf sensible size", len(pdf.content) > 1000)

        for dataset in ("timeline", "evidence", "coverage", "gaps", "parsing", "correlations"):
            resp = user.get(f"/api/investigations/{investigation_id}/export/{dataset}.csv")
            ok = resp.status_code == 200 and resp.text.strip() != ""
            check(f"export {dataset}.csv ok", ok, f"status {resp.status_code}")

        print(f"\nInvestigation ID for the demo: {investigation_id}")

    if FAILURES:
        print(f"\n{len(FAILURES)} check(s) FAILED")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
