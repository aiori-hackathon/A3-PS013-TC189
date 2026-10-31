from __future__ import annotations

from fastapi.testclient import TestClient


def _timeline(client: TestClient, investigation_id: str, query: str = ""):
    separator = "&" if query else ""
    response = client.get(f"/api/timeline?investigation_id={investigation_id}{separator}{query}")
    assert response.status_code == 200, response.text
    return response.json()


def test_timeline_orders_mixed_sources_by_utc_and_supports_filters(
    client: TestClient, investigation, upload_log, fixture_text
):
    auth = upload_log(
        investigation["id"],
        fixture_text("linux_auth_valid.log"),
        filename="auth.log",
        source_name="auth-server",
    )
    assert auth.status_code == 201, auth.text
    web = upload_log(
        investigation["id"],
        fixture_text("nginx_access_valid.log"),
        filename="access.log",
        source_name="web-server",
        hostname="web-01",
    )
    assert web.status_code == 201, web.text

    payload = _timeline(client, investigation["id"])
    assert payload["total"] == 12
    assert len(payload["items"]) == 12
    timestamps = [item["timestamp_utc"] for item in payload["items"]]
    assert timestamps == sorted(timestamps)
    assert timestamps[0] == "2026-10-31T04:25:05Z"
    assert timestamps[-1] == "2026-10-31T04:51:00Z"
    assert [item["line_number"] for item in payload["items"][:2]] == [1, 2]

    descending = _timeline(client, investigation["id"], "sort=desc&limit=3")
    assert [item["timestamp_utc"] for item in descending["items"]] == [
        "2026-10-31T04:51:00Z",
        "2026-10-31T04:50:00Z",
        "2026-10-31T04:35:00Z",
    ]

    assert _timeline(client, investigation["id"], "source_type=web_access")["total"] == 5
    assert _timeline(client, investigation["id"], "source_type=linux_auth")["total"] == 7
    assert (
        _timeline(client, investigation["id"], "event_type=auth_invalid_user")["total"] == 2
    )
    assert _timeline(client, investigation["id"], "hostname=web01")["total"] == 7
    assert _timeline(client, investigation["id"], "hostname=WEB-01")["total"] == 5
    assert _timeline(client, investigation["id"], "username=alice")["total"] > 0
    assert _timeline(client, investigation["id"], "source_ip=203.0.113.5")["total"] == 2
    assert _timeline(client, investigation["id"], "http_status=401")["total"] == 1
    assert _timeline(client, investigation["id"], "q=admin")["total"] == 3
    assert _timeline(client, investigation["id"], "q=/login")["total"] == 2
    assert _timeline(client, investigation["id"], "q=%25")["total"] == 0

    ranged = _timeline(
        client,
        investigation["id"],
        "start=2026-10-31T04:30:00Z&end=2026-10-31T04:31:00Z",
    )
    assert ranged["total"] == 4
    assert all(
        "2026-10-31T04:30:00Z" <= item["timestamp_utc"] <= "2026-10-31T04:31:00Z"
        for item in ranged["items"]
    )

    paged = _timeline(client, investigation["id"], "limit=2&offset=2")
    assert paged["total"] == 12
    assert paged["limit"] == 2
    assert paged["offset"] == 2
    assert [item["timestamp_utc"] for item in paged["items"]] == [
        "2026-10-31T04:28:01.123456Z",
        "2026-10-31T04:30:00Z",
    ]


def test_timeline_unknown_time_handling(
    client: TestClient, investigation, upload_log, fixture_text
):
    response = upload_log(
        investigation["id"],
        fixture_text("linux_auth_unknown_tz.log"),
        filename="legacy.log",
        source_type="linux_auth",
        timezone_hint="Asia/Kolkata",
    )
    assert response.status_code == 201, response.text

    included = _timeline(client, investigation["id"])
    assert included["total"] == 2
    assert all(item["timestamp_utc"] is None for item in included["items"])

    excluded = _timeline(client, investigation["id"], "include_unknown_time=false")
    assert excluded["total"] == 0
    assert excluded["items"] == []

    filtered = _timeline(client, investigation["id"], "timestamp_status=missing_year")
    assert filtered["total"] == 2


def test_timeline_rejects_naive_or_invalid_ranges(
    client: TestClient, investigation, upload_log, fixture_text
):
    assert upload_log(
        investigation["id"],
        fixture_text("linux_auth_valid.log"),
        filename="auth.log",
    ).status_code == 201

    naive = client.get(
        f"/api/timeline?investigation_id={investigation['id']}"
        "&start=2026-10-31T10:00:00"
    )
    assert naive.status_code == 422
    assert "UTC offset" in naive.json()["detail"]

    reversed_range = client.get(
        f"/api/timeline?investigation_id={investigation['id']}"
        "&start=2026-10-31T11:00:00Z&end=2026-10-31T10:00:00Z"
    )
    assert reversed_range.status_code == 422

    missing = client.get(
        "/api/timeline?investigation_id=00000000-0000-0000-0000-000000000000"
    )
    assert missing.status_code == 404


def test_event_detail_round_trip(client: TestClient, investigation, upload_log, fixture_text):
    upload = upload_log(
        investigation["id"],
        fixture_text("nginx_access_valid.log"),
        filename="access.log",
        hostname="web-01",
    )
    assert upload.status_code == 201

    item = _timeline(client, investigation["id"], "limit=1")["items"][0]
    assert item["evidence_filename"] == "access.log"
    assert len(item["evidence_sha256"]) == 64
    assert item["evidence_size_bytes"] > 0
    assert item["evidence_status"] == "parsed"
    assert item["evidence_integrity_status"] == "unverified"
    assert item["evidence_last_verified_at"] is None
    assert item["evidence_received_at"]
    assert item["evidence_collected_at"]

    detail = client.get(f"/api/events/{item['id']}")
    assert detail.status_code == 200
    assert detail.json() == item
    assert detail.json()["evidence_download_url"].endswith("/download")
    assert detail.json()["raw_line"].startswith("203.0.113.77")
