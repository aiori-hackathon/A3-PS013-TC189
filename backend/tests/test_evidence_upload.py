from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.config import get_settings
from app.models import EvidenceFile, EvidenceHash, ParsedEvent


def _evidence(evidence: dict) -> EvidenceFile:
    return evidence


def test_upload_valid_linux_auth_is_preserved_hashed_and_parsed(
    client: TestClient,
    db_session,
    investigation,
    upload_log,
    fixture_text,
):
    content = fixture_text("linux_auth_valid.log")
    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    response = upload_log(
        investigation["id"],
        content,
        filename="auth.log",
        source_name="auth-server",
        collected_at="2026-10-31T10:30:00+05:30",
    )
    assert response.status_code == 201, response.text
    evidence = response.json()

    assert evidence["source_type"] == "linux_auth"
    assert evidence["status"] == "parsed"
    assert evidence["sha256"] == expected_hash
    assert evidence["size_bytes"] == len(content.encode("utf-8"))
    assert evidence["event_count"] == 7
    assert evidence["original_filename"] == "auth.log"
    assert len(evidence["hashes"]) == 1
    assert evidence["hashes"][0]["hash_value"] == expected_hash
    assert evidence["parsing_result"]["status"] == "completed"
    assert evidence["parsing_result"]["total_lines"] == 7
    assert evidence["parsing_result"]["parsed_records"] == 7
    assert evidence["parsing_result"]["malformed_records"] == 0
    assert evidence["parsing_result"]["parser_version"] == "1.1.0"

    stored = db_session.scalar(
        select(EvidenceFile).where(EvidenceFile.id == uuid.UUID(evidence["id"]))
    )
    assert stored is not None
    assert stored.stored_relative_path.startswith("evidence/")
    assert stored.original_filename == "auth.log"
    stored_path = Path(get_settings().storage_root) / stored.stored_relative_path
    assert stored_path.read_bytes() == content.encode("utf-8")

    download = client.get(evidence["download_url"])
    assert download.status_code == 200
    assert download.content == content.encode("utf-8")
    assert download.headers["x-cybertrace-sha256"] == expected_hash

    verified = client.post(evidence["verify_url"])
    assert verified.status_code == 200, verified.text
    payload = verified.json()
    assert payload["match"] is True
    assert payload["expected_sha256"] == expected_hash
    assert payload["actual_sha256"] == expected_hash

    db_session.expire_all()
    hash_record = db_session.scalar(
        select(EvidenceHash).where(EvidenceHash.evidence_file_id == stored.id)
    )
    assert hash_record is not None
    assert hash_record.verified is True
    assert hash_record.verified_at is not None

    issues = client.get(evidence["issues_url"])
    assert issues.status_code == 200
    assert issues.json()["total"] == 0


def test_upload_valid_web_access_records(client: TestClient, investigation, upload_log, fixture_text):
    response = upload_log(
        investigation["id"],
        fixture_text("nginx_access_valid.log"),
        filename="access.log",
        hostname="web-01",
    )
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["source_type"] == "web_access"
    assert evidence["status"] == "parsed"
    assert evidence["event_count"] == 5
    assert evidence["source"]["hostname"] == "web-01"
    assert evidence["parsing_result"]["parsed_records"] == 5
    assert evidence["parsing_result"]["malformed_records"] == 0

    timeline = client.get(
        f"/api/timeline?investigation_id={investigation['id']}&source_type=web_access"
    )
    assert timeline.status_code == 200
    items = timeline.json()["items"]
    assert len(items) == 5
    assert all(item["source_type"] == "web_access" for item in items)
    assert items[0]["timestamp_utc"] == "2026-10-31T04:25:05Z"
    assert items[0]["hostname"] == "web-01"
    assert items[0]["http_method"] == "GET"
    assert items[0]["http_path"] == "/index.html"
    assert items[0]["http_status"] == 200


def test_malformed_line_is_retained_as_issue_and_rest_of_file_parses(
    client: TestClient, investigation, upload_log, fixture_text
):
    response = upload_log(
        investigation["id"],
        fixture_text("linux_auth_mixed.log"),
        filename="mixed.log",
    )
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["status"] == "parsed_with_issues"
    assert evidence["event_count"] == 2
    assert evidence["parsing_result"]["status"] == "partial"
    assert evidence["parsing_result"]["malformed_records"] == 1
    assert evidence["parsing_result"]["parsed_records"] == 2

    issues = client.get(evidence["issues_url"] + "?severity=error")
    assert issues.status_code == 200
    payload = issues.json()
    assert payload["total"] == 1
    issue = payload["items"][0]
    assert issue["issue_type"] == "malformed_line"
    assert issue["line_number"] == 2
    assert issue["byte_offset"] is not None
    assert "garbage line" in issue["raw_line"]
    assert issue["severity"] == "error"


def test_unsupported_format_is_preserved_hashed_and_reported(
    client: TestClient, db_session, investigation, upload_log, fixture_text
):
    content = fixture_text("unsupported.log")
    response = upload_log(investigation["id"], content, filename="notes.log")
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["source_type"] == "unknown"
    assert evidence["status"] == "failed"
    assert evidence["event_count"] == 0
    assert evidence["parser_name"] is None
    assert evidence["parsing_result"]["status"] == "failed"
    assert evidence["parsing_result"]["unsupported_records"] == 2
    assert evidence["sha256"] == hashlib.sha256(content.encode("utf-8")).hexdigest()

    issues = client.get(evidence["issues_url"])
    assert issues.status_code == 200
    issue = issues.json()["items"][0]
    assert issue["issue_type"] == "unsupported_format"
    assert issue["severity"] == "error"
    assert issue["line_number"] is None

    download = client.get(evidence["download_url"])
    assert download.content == content.encode("utf-8")

    reparse = client.post(f"/api/evidence/{evidence['id']}/reparse")
    assert reparse.status_code == 422
    assert reparse.json()["detail"]["code"] == "unsupported_reparse"


def test_yearless_syslog_is_flagged_until_year_and_timezone_are_supplied(
    client: TestClient,
    make_investigation,
    upload_log,
    fixture_text,
):
    first = make_investigation("Unknown year")
    response = upload_log(
        first["id"],
        fixture_text("linux_auth_unknown_tz.log"),
        filename="syslog.log",
        source_type="linux_auth",
        timezone_hint="Asia/Kolkata",
    )
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["status"] == "parsed_with_issues"
    assert evidence["event_count"] == 2
    assert evidence["parsing_result"]["timestamp_flagged_records"] == 2

    timeline = client.get(f"/api/timeline?investigation_id={first['id']}")
    items = timeline.json()["items"]
    assert all(item["timestamp_utc"] is None for item in items)
    assert all(item["timestamp_status"] == "missing_year" for item in items)

    issues = client.get(evidence["issues_url"])
    assert issues.json()["total"] == 2
    assert {item["issue_type"] for item in issues.json()["items"]} == {"unknown_timestamp"}
    assert all(item["severity"] == "warning" for item in issues.json()["items"])

    second = make_investigation("Known year")
    resolved = upload_log(
        second["id"],
        fixture_text("linux_auth_unknown_tz.log"),
        filename="syslog.log",
        source_type="linux_auth",
        timezone_hint="Asia/Kolkata",
        default_year=2026,
    )
    assert resolved.status_code == 201, resolved.text
    assert resolved.json()["status"] == "parsed"
    resolved_timeline = client.get(f"/api/timeline?investigation_id={second['id']}")
    resolved_items = resolved_timeline.json()["items"]
    assert [item["timestamp_utc"] for item in resolved_items] == [
        "2026-10-31T04:35:00Z",
        "2026-10-31T04:36:00Z",
    ]
    assert all(item["timestamp_status"] == "normalized" for item in resolved_items)


def test_dst_fold_is_flagged_as_ambiguous(
    client: TestClient, investigation, upload_log
):
    content = (
        "Nov  1 01:30:00 web01 sshd[1]: Failed password for alice from 192.0.2.5 "
        "port 2200 ssh2\n"
    )
    response = upload_log(
        investigation["id"],
        content,
        filename="dst.log",
        source_type="linux_auth",
        timezone_hint="America/New_York",
        default_year=2026,
    )
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["event_count"] == 1
    assert evidence["status"] == "parsed_with_issues"

    timeline = client.get(f"/api/timeline?investigation_id={investigation['id']}")
    item = timeline.json()["items"][0]
    assert item["timestamp_utc"] is None
    assert item["timestamp_status"] == "ambiguous"

    issues = client.get(evidence["issues_url"]).json()["items"]
    assert issues[0]["issue_type"] == "ambiguous_timestamp"


def test_duplicate_evidence_is_rejected_unless_explicitly_allowed(
    client: TestClient, db_session, investigation, upload_log, fixture_text
):
    content = fixture_text("linux_auth_valid.log")
    first = upload_log(investigation["id"], content, filename="auth.log")
    assert first.status_code == 201
    first_id = first.json()["id"]

    rejected = upload_log(investigation["id"], content, filename="auth-copy.log")
    assert rejected.status_code == 409
    detail = rejected.json()["detail"]
    assert detail["code"] == "duplicate_evidence"
    assert detail["existing_evidence_id"] == first_id

    allowed = upload_log(
        investigation["id"],
        content,
        filename="auth-copy.log",
        allow_duplicate=True,
    )
    assert allowed.status_code == 201, allowed.text
    duplicate = allowed.json()
    assert duplicate["duplicate_of_evidence_id"] == first_id
    assert duplicate["event_count"] == 7
    assert db_session.scalar(select(func.count(EvidenceFile.id))) == 2
    assert db_session.scalar(select(func.count(ParsedEvent.id))) == 14


def test_reparse_from_preserved_original_replaces_derived_events(
    client: TestClient, db_session, investigation, upload_log, fixture_text
):
    response = upload_log(
        investigation["id"],
        fixture_text("linux_auth_valid.log"),
        filename="auth.log",
    )
    evidence = response.json()
    first_result_id = evidence["parsing_result"]["id"]
    first_event_ids = set(
        db_session.scalars(
            select(ParsedEvent.id).where(
                ParsedEvent.evidence_file_id == uuid.UUID(evidence["id"])
            )
        ).all()
    )
    assert len(first_event_ids) == 7

    reparsed = client.post(f"/api/evidence/{evidence['id']}/reparse")
    assert reparsed.status_code == 200, reparsed.text
    payload = reparsed.json()["evidence"]
    assert payload["event_count"] == 7
    assert payload["parsing_result"]["id"] != first_result_id
    assert payload["status"] == "parsed"

    db_session.expire_all()
    second_event_ids = set(
        db_session.scalars(
            select(ParsedEvent.id).where(
                ParsedEvent.evidence_file_id == uuid.UUID(evidence["id"])
            )
        ).all()
    )
    assert len(second_event_ids) == 7
    assert second_event_ids.isdisjoint(first_event_ids)


def test_tampered_evidence_fails_verification_and_reparse(
    client: TestClient, db_session, investigation, upload_log, fixture_text
):
    content = fixture_text("linux_auth_valid.log")
    response = upload_log(investigation["id"], content, filename="auth.log")
    evidence = response.json()
    stored = db_session.get(EvidenceFile, uuid.UUID(evidence["id"]))
    assert stored is not None
    stored_path = Path(get_settings().storage_root) / stored.stored_relative_path

    os.chmod(stored_path, 0o666)
    stored_path.write_bytes(stored_path.read_bytes() + b"tampered\n")

    verified = client.post(evidence["verify_url"])
    assert verified.status_code == 200
    assert verified.json()["match"] is False

    reparsed = client.post(evidence["verify_url"].replace("/verify", "/reparse"))
    assert reparsed.status_code == 409
    assert reparsed.json()["detail"]["code"] == "checksum_mismatch"
    db_session.expire_all()
    assert db_session.scalar(select(func.count(ParsedEvent.id))) == 7


def test_upload_rejects_unsafe_or_invalid_content(
    client: TestClient, investigation, upload_log, fixture_text
):
    too_many = upload_log(investigation["id"], b"x" * 2048, filename="large.log")
    assert too_many.status_code == 201

    empty = upload_log(investigation["id"], b"", filename="empty.log")
    assert empty.status_code == 422
    assert empty.json()["detail"]["code"] == "empty_file"

    binary = upload_log(investigation["id"], b"abc\x00def", filename="binary.log")
    assert binary.status_code == 415
    assert binary.json()["detail"]["code"] == "binary_content"

    extension = upload_log(
        investigation["id"], fixture_text("linux_auth_valid.log"), filename="evidence.exe"
    )
    assert extension.status_code == 415
    assert extension.json()["detail"]["code"] == "unsupported_file_type"


def test_upload_size_limit_returns_413(client: TestClient, investigation, upload_log):
    from app.main import app

    original = app.dependency_overrides.get(get_settings)
    app.dependency_overrides[get_settings] = lambda: get_settings().model_copy(
        update={"max_upload_size_bytes": 1024}
    )
    try:
        response = upload_log(investigation["id"], b"a" * 2048, filename="large.log")
    finally:
        if original is None:
            app.dependency_overrides.pop(get_settings, None)
        else:
            app.dependency_overrides[get_settings] = original

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "file_too_large"


def test_invalid_ingest_options_are_rejected(
    client: TestClient, investigation, upload_log, fixture_text
):
    content = fixture_text("linux_auth_valid.log")
    cases = [
        ({"timezone_hint": "Mars/Olympus_Mons"}, "invalid_timezone"),
        ({"source_ip": "999.1.1.1"}, "invalid_source_ip"),
        ({"default_year": 1900}, "invalid_default_year"),
        ({"collected_at": "2026-10-31T10:00:00"}, "invalid_collected_at"),
    ]
    for form, code in cases:
        response = upload_log(investigation["id"], content, filename="auth.log", **form)
        assert response.status_code == 422, (form, response.text)
        assert response.json()["detail"]["code"] == code

    assert client.get(f"/api/investigations/{investigation['id']}").json()["evidence_count"] == 0


def test_upload_path_traversal_filename_is_sanitized(
    client: TestClient, db_session, investigation, upload_log, fixture_text
):
    response = upload_log(
        investigation["id"],
        fixture_text("linux_auth_valid.log"),
        filename="..\\..\\windows\\evil.log",
    )
    assert response.status_code == 201, response.text
    evidence = response.json()
    assert evidence["original_filename"] == "evil.log"
    stored = db_session.get(EvidenceFile, uuid.UUID(evidence["id"]))
    assert stored is not None
    assert stored.stored_relative_path.startswith(f"evidence/{investigation['id']}/")
    assert ".." not in stored.stored_relative_path


def test_source_conflict_is_rejected(
    client: TestClient, investigation, upload_log, fixture_text
):
    first = upload_log(
        investigation["id"],
        fixture_text("linux_auth_valid.log"),
        filename="auth.log",
        source_name="shared-source",
        hostname="web-01",
    )
    assert first.status_code == 201

    conflicting = upload_log(
        investigation["id"],
        fixture_text("linux_auth_unknown_tz.log"),
        filename="auth-2.log",
        source_name="shared-source",
        hostname="web-02",
    )
    assert conflicting.status_code == 409
    assert conflicting.json()["detail"]["code"] == "source_conflict"


def test_evidence_and_event_lookup_404s(client: TestClient):
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/evidence/{missing}").status_code == 404
    assert client.get(f"/api/evidence/{missing}/status").status_code == 404
    assert client.get(f"/api/evidence/{missing}/issues").status_code == 404
    assert client.get(f"/api/evidence/{missing}/download").status_code == 404
    assert client.get("/api/events/999999").status_code == 404
