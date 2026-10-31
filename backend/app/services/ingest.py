"""Evidence ingestion pipeline: validate, hash, preserve, parse, persist."""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, insert, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import Settings
from app.constants import (
    AuditEventType,
    DuplicateStatus,
    EvidenceStatus,
    IntegrityStatus,
    IssueSeverity,
    IssueType,
    OrderingStatus,
    ParsingStatus,
    RequestedSourceType,
    SourceType,
    TimestampStatus,
    VerificationSource,
)
from app.models import (
    EvidenceFile,
    EvidenceHash,
    EvidenceSource,
    EvidenceVerification,
    Investigation,
    ParsedEvent,
    ParsingIssue,
    ParsingResult,
    utcnow,
)
from app.services import storage
from app.services.correlation import run_investigation_correlations
from app.services.errors import IngestError
from app.services.parsers import detect_source_type, get_parser
from app.services.parsers.base import ParsedEventData, ParsedIssueData, ParserConfig
from app.services.quality import (
    event_fingerprint,
    mark_ordering,
    reconcile_duplicates,
    record_audit,
    refresh_parsing_ordering_counts,
)
from app.services.timeutil import apply_clock_offset

logger = logging.getLogger(__name__)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ISSUE_MESSAGE_LIMIT = 2000
_BULK_CHUNK = 500


@dataclass(slots=True)
class IngestOptions:
    requested_source_type: RequestedSourceType = RequestedSourceType.AUTO
    source_id: uuid.UUID | None = None
    source_name: str | None = None
    hostname: str | None = None
    source_ip: str | None = None
    timezone_hint: str | None = None
    default_year: int | None = None
    collected_at: datetime | None = None
    notes: str | None = None
    allow_duplicate: bool = False
    content_type: str | None = None
    clock_offset_seconds: int | None = None
    actor_type: str = "api"
    actor_detail: str | None = None
    request_id: str | None = None


@dataclass(slots=True)
class ParseStats:
    total_lines: int = 0
    blank_lines: int = 0
    records_received: int = 0
    parsed_records: int = 0
    records_rejected: int = 0
    malformed_records: int = 0
    unsupported_records: int = 0
    unsupported_formats: int = 0
    missing_required_fields: int = 0
    missing_optional_fields: int = 0
    parser_errors: int = 0
    duplicate_records: int = 0
    timestamp_flagged_records: int = 0
    encoding_error_lines: int = 0
    issues_recorded: int = 0
    issues_suppressed: int = 0
    error_issue_count: int = 0


@dataclass(slots=True)
class RawLogLine:
    number: int
    offset: int
    data: bytes
    truncated: bool


def _stored_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]} ...[truncated in analysis copy; original evidence retained]"


def _clean_optional(value: str | None, *, field: str, max_length: int) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    cleaned = _CONTROL_RE.sub(" ", cleaned)
    if len(cleaned) > max_length:
        raise IngestError(
            422,
            f"invalid_{field}",
            f"{field.replace('_', ' ').title()} must be at most {max_length} characters.",
        )
    return cleaned


def iter_log_lines(path: Path, max_line_bytes: int) -> Iterator[RawLogLine]:
    """Yield complete lines while capping memory use for pathological input."""

    with path.open("rb") as handle:
        offset = 0
        number = 0
        while True:
            start = offset
            data = handle.readline(max_line_bytes)
            if not data:
                break
            number += 1
            offset += len(data)
            truncated = False

            if len(data) >= max_line_bytes and not data.endswith(b"\n"):
                extra = handle.read(1)
                if extra:
                    offset += len(extra)
                    if extra != b"\n":
                        truncated = True
                        while True:
                            chunk = handle.readline(max_line_bytes)
                            if not chunk:
                                break
                            offset += len(chunk)
                            if chunk.endswith(b"\n"):
                                break

            yield RawLogLine(number=number, offset=start, data=data, truncated=truncated)


class IngestService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def ingest(
        self,
        investigation: Investigation,
        upload_source: BinaryIO,
        original_filename: str,
        options: IngestOptions,
    ) -> EvidenceFile:
        validated = self._validate_options(options)
        temp = storage.stream_to_temp(upload_source, original_filename, self.settings)

        try:
            existing = self.session.scalar(
                select(EvidenceFile)
                .where(
                    EvidenceFile.investigation_id == investigation.id,
                    EvidenceFile.sha256 == temp.sha256,
                )
                .order_by(EvidenceFile.received_at.asc())
                .limit(1)
            )
            if existing and not validated.allow_duplicate:
                raise IngestError(
                    409,
                    "duplicate_evidence",
                    "An evidence file with the same SHA-256 hash already exists in this investigation.",
                    existing_evidence_id=str(existing.id),
                    sha256=temp.sha256,
                )

            detected_type = SourceType.UNKNOWN
            if validated.requested_source_type is RequestedSourceType.AUTO:
                detected_type = (
                    detect_source_type(temp.path, self.settings.max_line_bytes)
                    or SourceType.UNKNOWN
                )
            else:
                detected_type = SourceType(validated.requested_source_type.value)

            source, resolved_type = self._resolve_source(
                investigation.id, detected_type, validated, temp.original_filename
            )
            self.session.flush()

            evidence_id = uuid.uuid4()
            stored_relative = storage.finalize_upload(
                temp,
                investigation_id=investigation.id,
                evidence_id=evidence_id,
                settings=self.settings,
            )
        except Exception:
            storage.cleanup_temp(temp.path)
            raise

        try:
            evidence = EvidenceFile(
                id=evidence_id,
                investigation_id=investigation.id,
                source_id=source.id,
                original_filename=temp.original_filename,
                stored_relative_path=stored_relative,
                sha256=temp.sha256,
                size_bytes=temp.size_bytes,
                content_type=_stored_text(validated.content_type or "", 120) or None,
                source_type=resolved_type,
                status=EvidenceStatus.RECEIVED,
                collected_at=validated.collected_at,
                timezone_hint=validated.timezone_hint,
                default_year=validated.default_year,
                clock_offset_seconds=validated.clock_offset_seconds,
                notes=validated.notes,
                metadata_json={
                    "requested_source_type": validated.requested_source_type.value,
                    "detected_source_type": detected_type.value,
                    "duplicate_allowed": validated.allow_duplicate,
                },
                duplicate_of_evidence_id=existing.id if existing else None,
            )
            self.session.add(evidence)
            self.session.add(
                EvidenceHash(
                    evidence_file_id=evidence.id,
                    algorithm="sha256",
                    hash_value=temp.sha256,
                )
            )
            self.session.flush()
            result = self._parse_evidence(evidence, source)
            record_audit(
                self.session,
                investigation_id=evidence.investigation_id,
                event_type=AuditEventType.EVIDENCE_PRESERVED,
                evidence=evidence,
                actor_type=validated.actor_type,
                actor_detail=validated.actor_detail,
                request_id=validated.request_id,
                detail={
                    "size_bytes": evidence.size_bytes,
                    "stored_relative_path": evidence.stored_relative_path,
                    "duplicate_allowed": validated.allow_duplicate,
                    "duplicate_of_evidence_id": (
                        str(evidence.duplicate_of_evidence_id)
                        if evidence.duplicate_of_evidence_id
                        else None
                    ),
                },
            )
            record_audit(
                self.session,
                investigation_id=evidence.investigation_id,
                event_type=AuditEventType.EVIDENCE_PARSED,
                evidence=evidence,
                actor_type=validated.actor_type,
                actor_detail=validated.actor_detail,
                request_id=validated.request_id,
                detail={
                    "parsing_status": result.status.value,
                    "parser_name": result.parser_name,
                    "parser_version": result.parser_version,
                    "parsed_records": result.parsed_records,
                    "records_rejected": result.records_rejected,
                    "issues_recorded": result.issues_recorded,
                },
            )
            self.session.commit()
        except IngestError:
            self.session.rollback()
            raise
        except SQLAlchemyError as exc:
            self.session.rollback()
            logger.exception(
                "Database failure after preserving evidence file at %s", stored_relative
            )
            raise IngestError(
                500,
                "database_error",
                "Evidence was written to disk but its database metadata could not be committed.",
                stored_relative_path=stored_relative,
            ) from exc
        except Exception as exc:
            self.session.rollback()
            logger.exception("Unexpected ingestion failure for %s", stored_relative)
            raise IngestError(
                500,
                "ingest_error",
                "Evidence was preserved but parsing failed unexpectedly.",
                stored_relative_path=stored_relative,
            ) from exc

        self.session.refresh(evidence)
        return evidence

    def reparse(
        self,
        evidence: EvidenceFile,
        *,
        actor_type: str = "api",
        actor_detail: str | None = None,
        request_id: str | None = None,
    ) -> EvidenceFile:
        source = self.session.get(EvidenceSource, evidence.source_id)
        if source is None:
            raise IngestError(409, "source_missing", "The evidence source no longer exists.")
        if evidence.source_type is SourceType.UNKNOWN:
            raise IngestError(
                422,
                "unsupported_reparse",
                "This evidence has no recognized source type, so it cannot be reparsed.",
            )

        try:
            match, actual, _record = self.verify_hash(
                evidence,
                commit=False,
                source=VerificationSource.REPARSE,
                actor_type=actor_type,
                actor_detail=actor_detail,
                request_id=request_id,
            )
        except IngestError:
            self.session.commit()
            raise
        if not match:
            record_audit(
                self.session,
                investigation_id=evidence.investigation_id,
                event_type=AuditEventType.EVIDENCE_REPARSE_DENIED,
                evidence=evidence,
                actor_type=actor_type,
                actor_detail=actor_detail,
                request_id=request_id,
                detail={
                    "reason": "checksum_mismatch",
                    "expected_sha256": evidence.sha256,
                    "actual_sha256": actual,
                },
            )
            self.session.commit()
            raise IngestError(
                409,
                "checksum_mismatch",
                "Evidence hash verification failed. Reparse was refused because the original file changed.",
                expected_sha256=evidence.sha256,
                actual_sha256=actual,
            )

        record_audit(
            self.session,
            investigation_id=evidence.investigation_id,
            event_type=AuditEventType.EVIDENCE_REPARSED,
            evidence=evidence,
            actor_type=actor_type,
            actor_detail=actor_detail,
            request_id=request_id,
            detail={"stage": "started"},
        )

        self.session.execute(
            delete(ParsingIssue).where(ParsingIssue.evidence_file_id == evidence.id)
        )
        self.session.execute(delete(ParsedEvent).where(ParsedEvent.evidence_file_id == evidence.id))
        self.session.execute(
            delete(ParsingResult).where(ParsingResult.evidence_file_id == evidence.id)
        )
        evidence.status = EvidenceStatus.RECEIVED
        evidence.parser_name = None
        self.session.flush()

        try:
            result = self._parse_evidence(evidence, source)
            record_audit(
                self.session,
                investigation_id=evidence.investigation_id,
                event_type=AuditEventType.EVIDENCE_REPARSED,
                evidence=evidence,
                actor_type=actor_type,
                actor_detail=actor_detail,
                request_id=request_id,
                detail={
                    "stage": "completed",
                    "parsing_status": result.status.value,
                    "parsed_records": result.parsed_records,
                    "records_rejected": result.records_rejected,
                },
            )
            self.session.commit()
        except SQLAlchemyError as exc:
            self.session.rollback()
            logger.exception("Database failure while reparsing evidence %s", evidence.id)
            raise IngestError(500, "database_error", "Reparse failed while saving results.") from exc

        self.session.refresh(evidence)
        return evidence

    def verify_hash(
        self,
        evidence: EvidenceFile,
        *,
        commit: bool = True,
        source: VerificationSource = VerificationSource.API,
        actor_type: str = "api",
        actor_detail: str | None = None,
        request_id: str | None = None,
    ) -> tuple[bool, str, EvidenceHash]:
        started = time.perf_counter()
        missing_error: IngestError | None = None
        try:
            match, actual = storage.verify_stored_file(
                evidence.stored_relative_path, evidence.sha256, self.settings
            )
            outcome = IntegrityStatus.VERIFIED if match else IntegrityStatus.MISMATCH
        except IngestError as exc:
            if exc.code != "evidence_file_missing":
                raise
            match = False
            actual = ""
            outcome = IntegrityStatus.MISSING
            missing_error = exc

        verified_at = utcnow()
        duration_ms = int((time.perf_counter() - started) * 1000)
        hash_record = self.session.scalar(
            select(EvidenceHash).where(
                EvidenceHash.evidence_file_id == evidence.id,
                EvidenceHash.algorithm == "sha256",
            )
        )
        if hash_record is None:
            hash_record = EvidenceHash(
                evidence_file_id=evidence.id,
                algorithm="sha256",
                hash_value=evidence.sha256,
            )
            self.session.add(hash_record)
            self.session.flush()

        note = {
            IntegrityStatus.VERIFIED: "Hash matches the recorded value.",
            IntegrityStatus.MISMATCH: (
                "Hash mismatch: stored bytes differ from the collection-time hash."
            ),
            IntegrityStatus.MISSING: "Original evidence file is missing from storage.",
        }[outcome]
        hash_record.verified = match
        hash_record.verified_at = verified_at
        hash_record.verification_note = note

        evidence.integrity_status = outcome
        evidence.last_verified_at = verified_at
        evidence.last_verification_source = source.value
        evidence.verification_count = (evidence.verification_count or 0) + 1
        self.session.add(
            EvidenceVerification(
                evidence_file_id=evidence.id,
                algorithm="sha256",
                expected_sha256=evidence.sha256,
                actual_sha256=actual or None,
                outcome=outcome,
                source=source,
                actor_type=actor_type,
                actor_detail=actor_detail,
                note=note,
                duration_ms=duration_ms,
                verified_at=verified_at,
            )
        )
        record_audit(
            self.session,
            investigation_id=evidence.investigation_id,
            event_type=(
                AuditEventType.EVIDENCE_VERIFIED
                if outcome is IntegrityStatus.VERIFIED
                else AuditEventType.EVIDENCE_VERIFICATION_MISMATCH
            ),
            evidence=evidence,
            actor_type=actor_type,
            actor_detail=actor_detail,
            request_id=request_id,
            detail={
                "outcome": outcome.value,
                "source": source.value,
                "expected_sha256": evidence.sha256,
                "actual_sha256": actual or None,
                "duration_ms": duration_ms,
            },
        )

        if commit:
            self.session.commit()
            self.session.refresh(evidence)
        if missing_error is not None:
            raise missing_error
        return match, actual, hash_record

    def _validate_options(self, options: IngestOptions) -> IngestOptions:
        source_name = _clean_optional(options.source_name, field="source_name", max_length=200)
        hostname = _clean_optional(options.hostname, field="hostname", max_length=255)
        source_ip = _clean_optional(options.source_ip, field="source_ip", max_length=64)
        notes = _clean_optional(options.notes, field="notes", max_length=5000)
        timezone_hint = _clean_optional(
            options.timezone_hint, field="timezone_hint", max_length=64
        )

        if source_ip:
            try:
                ipaddress.ip_address(source_ip)
            except ValueError as exc:
                raise IngestError(
                    422, "invalid_source_ip", "source_ip must be a valid IPv4 or IPv6 address."
                ) from exc

        if timezone_hint:
            try:
                ZoneInfo(timezone_hint)
            except ZoneInfoNotFoundError as exc:
                raise IngestError(
                    422,
                    "invalid_timezone",
                    "timezone_hint must be a valid IANA timezone name such as Asia/Kolkata.",
                ) from exc

        if options.default_year is not None and not (1970 <= options.default_year <= 2100):
            raise IngestError(
                422, "invalid_default_year", "default_year must be between 1970 and 2100."
            )

        if options.clock_offset_seconds is not None and not (
            -86400 <= options.clock_offset_seconds <= 86400
        ):
            raise IngestError(
                422,
                "invalid_clock_offset",
                "clock_offset_seconds must be between -86400 and 86400.",
            )

        actor_type = _clean_optional(
            options.actor_type, field="actor_type", max_length=16
        ) or "api"
        actor_detail = _clean_optional(
            options.actor_detail, field="actor_detail", max_length=255
        )
        request_id = _clean_optional(
            options.request_id, field="request_id", max_length=64
        )

        collected_at = options.collected_at
        if collected_at is not None and (
            collected_at.tzinfo is None or collected_at.utcoffset() is None
        ):
            raise IngestError(
                422,
                "invalid_collected_at",
                "collected_at must include a UTC offset or timezone (for example 2026-10-31T10:00:00Z).",
            )
        if collected_at is None:
            collected_at = utcnow()
        else:
            collected_at = collected_at.astimezone(UTC)

        content_type = _clean_optional(
            options.content_type, field="content_type", max_length=120
        )

        return IngestOptions(
            requested_source_type=options.requested_source_type,
            source_id=options.source_id,
            source_name=source_name,
            hostname=hostname,
            source_ip=source_ip,
            timezone_hint=timezone_hint,
            default_year=options.default_year,
            collected_at=collected_at,
            notes=notes,
            allow_duplicate=options.allow_duplicate,
            content_type=content_type,
            clock_offset_seconds=options.clock_offset_seconds,
            actor_type=actor_type,
            actor_detail=actor_detail,
            request_id=request_id,
        )

    def _resolve_source(
        self,
        investigation_id: uuid.UUID,
        detected_type: SourceType,
        options: IngestOptions,
        safe_filename: str,
    ) -> tuple[EvidenceSource, SourceType]:
        if options.source_id:
            source = self.session.get(EvidenceSource, options.source_id)
            if source is None or source.investigation_id != investigation_id:
                raise IngestError(
                    404, "source_not_found", "Evidence source was not found in this investigation."
                )
        else:
            name = options.source_name or Path(safe_filename).stem or "Uploaded source"
            source = self.session.scalar(
                select(EvidenceSource).where(
                    EvidenceSource.investigation_id == investigation_id,
                    EvidenceSource.name == name,
                )
            )
            if source is None:
                source = EvidenceSource(
                    investigation_id=investigation_id,
                    name=name,
                    source_type=detected_type,
                    hostname=options.hostname,
                    ip_address=options.source_ip,
                    metadata_json={"created_by": "evidence_upload"},
                )
                self.session.add(source)
            else:
                if (
                    options.hostname
                    and source.hostname
                    and options.hostname.casefold() != source.hostname.casefold()
                ):
                    raise IngestError(
                        409,
                        "source_conflict",
                        "A source with this name already exists with a different hostname.",
                        source_id=str(source.id),
                    )
                if (
                    options.source_ip
                    and source.ip_address
                    and options.source_ip != source.ip_address
                ):
                    raise IngestError(
                        409,
                        "source_conflict",
                        "A source with this name already exists with a different IP address.",
                        source_id=str(source.id),
                    )

        resolved_type = detected_type
        if source.source_type is not SourceType.UNKNOWN and resolved_type is SourceType.UNKNOWN:
            resolved_type = source.source_type
        elif (
            source.source_type is not SourceType.UNKNOWN
            and resolved_type is not SourceType.UNKNOWN
            and source.source_type is not resolved_type
        ):
            raise IngestError(
                409,
                "source_type_conflict",
                "The detected log format conflicts with the existing source type.",
                source_id=str(source.id),
                existing_source_type=source.source_type.value,
                detected_source_type=resolved_type.value,
            )

        if source.source_type is SourceType.UNKNOWN and resolved_type is not SourceType.UNKNOWN:
            source.source_type = resolved_type
        if options.hostname and not source.hostname:
            source.hostname = options.hostname
        if options.source_ip and not source.ip_address:
            source.ip_address = options.source_ip

        return source, resolved_type

    def _parse_evidence(self, evidence: EvidenceFile, source: EvidenceSource) -> ParsingResult:
        result = ParsingResult(
            evidence_file_id=evidence.id,
            status=ParsingStatus.FAILED,
            started_at=utcnow(),
        )
        self.session.add(result)
        self.session.flush()

        parser = get_parser(evidence.source_type)
        if parser is None:
            self._record_unsupported(evidence, result)
            return result

        result.parser_name = parser.name
        result.parser_version = parser.version
        evidence.parser_name = parser.name
        config = ParserConfig(
            timezone_hint=evidence.timezone_hint,
            default_year=evidence.default_year,
            hostname_fallback=source.hostname or source.name,
        )
        path = storage.resolve_relative_path(evidence.stored_relative_path, self.settings)
        try:
            stats = self._run_parser(evidence, result, path, parser, config)
        except IngestError as exc:
            self.session.execute(
                delete(ParsedEvent).where(ParsedEvent.evidence_file_id == evidence.id)
            )
            self.session.execute(
                delete(ParsingIssue).where(ParsingIssue.evidence_file_id == evidence.id)
            )
            result.status = ParsingStatus.FAILED
            result.fatal_error = exc.message
            result.completed_at = utcnow()
            result.duration_ms = int(
                (result.completed_at - result.started_at).total_seconds() * 1000
            )
            result.issues_recorded = 1
            result.parser_errors = 1
            self.session.add(
                ParsingIssue(
                    evidence_file_id=evidence.id,
                    parsing_result_id=result.id,
                    issue_type=IssueType.PARSER_ERROR.value,
                    severity=IssueSeverity.ERROR,
                    message=exc.message,
                )
            )
            evidence.status = EvidenceStatus.FAILED
            self.session.flush()
            return result

        if stats.parsed_records == 0:
            status = ParsingStatus.FAILED
        elif (
            stats.malformed_records > 0
            or stats.encoding_error_lines > 0
            or stats.error_issue_count > 0
        ):
            status = ParsingStatus.PARTIAL
        else:
            status = ParsingStatus.COMPLETED

        result.status = status
        result.total_lines = stats.total_lines
        result.blank_lines = stats.blank_lines
        result.records_received = stats.records_received
        result.parsed_records = stats.parsed_records
        result.records_rejected = stats.records_rejected
        result.malformed_records = stats.malformed_records
        result.unsupported_records = stats.unsupported_records
        result.unsupported_formats = stats.unsupported_formats
        result.missing_required_fields = stats.missing_required_fields
        result.missing_optional_fields = stats.missing_optional_fields
        result.parser_errors = stats.parser_errors
        result.timestamp_flagged_records = stats.timestamp_flagged_records
        result.encoding_error_lines = stats.encoding_error_lines
        result.issues_recorded = stats.issues_recorded
        result.issues_suppressed = stats.issues_suppressed
        result.completed_at = utcnow()
        result.duration_ms = int(
            (result.completed_at - result.started_at).total_seconds() * 1000
        )
        evidence.parser_name = parser.name

        mark_ordering(self.session, evidence.investigation_id)
        refresh_parsing_ordering_counts(self.session, evidence.investigation_id)
        reconcile_duplicates(self.session, evidence.investigation_id)
        run_investigation_correlations(self.session, evidence.investigation_id)
        has_material_issue = bool(
            stats.records_rejected
            or stats.malformed_records
            or stats.unsupported_records
            or stats.unsupported_formats
            or stats.missing_required_fields
            or stats.parser_errors
            or stats.timestamp_flagged_records
            or stats.encoding_error_lines
        )
        if status is ParsingStatus.FAILED:
            evidence.status = EvidenceStatus.FAILED
        elif has_material_issue:
            evidence.status = EvidenceStatus.PARSED_WITH_ISSUES
        else:
            evidence.status = EvidenceStatus.PARSED
        self.session.flush()
        return result

    def _record_unsupported(self, evidence: EvidenceFile, result: ParsingResult) -> None:
        stats = ParseStats()
        path = storage.resolve_relative_path(evidence.stored_relative_path, self.settings)
        try:
            for line in iter_log_lines(path, self.settings.max_line_bytes):
                stats.total_lines += 1
                if not line.data.strip():
                    stats.blank_lines += 1
                else:
                    stats.records_received += 1
                    stats.unsupported_records += 1
                    stats.records_rejected += 1
        except OSError as exc:
            result.fatal_error = f"Evidence file could not be read: {exc}"
            result.status = ParsingStatus.FAILED
            result.completed_at = utcnow()
            result.duration_ms = int(
                (result.completed_at - result.started_at).total_seconds() * 1000
            )
            evidence.status = EvidenceStatus.FAILED
            self.session.flush()
            return

        message = (
            "Content did not match any supported log format (Linux authentication "
            "syslog or Apache/nginx common/combined access log). The original "
            "evidence was preserved and hashed; no events were created."
        )
        self.session.add(
            ParsingIssue(
                evidence_file_id=evidence.id,
                parsing_result_id=result.id,
                issue_type=IssueType.UNSUPPORTED_FORMAT.value,
                severity=IssueSeverity.ERROR,
                message=message,
            )
        )
        result.status = ParsingStatus.FAILED
        result.total_lines = stats.total_lines
        result.blank_lines = stats.blank_lines
        result.records_received = stats.records_received
        result.records_rejected = stats.records_rejected
        result.unsupported_records = stats.unsupported_records
        result.unsupported_formats = 1
        result.issues_recorded = 1
        result.fatal_error = message
        result.completed_at = utcnow()
        result.duration_ms = int(
            (result.completed_at - result.started_at).total_seconds() * 1000
        )
        evidence.status = EvidenceStatus.FAILED
        self.session.flush()

    def _run_parser(
        self,
        evidence: EvidenceFile,
        result: ParsingResult,
        path: Path,
        parser,
        config: ParserConfig,
    ) -> ParseStats:
        stats = ParseStats()
        event_buffer: list[dict] = []
        issue_buffer: list[dict] = []

        def flush_events() -> None:
            if event_buffer:
                self.session.execute(insert(ParsedEvent), event_buffer)
                event_buffer.clear()

        def flush_issues() -> None:
            if issue_buffer:
                self.session.execute(insert(ParsingIssue), issue_buffer)
                issue_buffer.clear()

        def add_issue(
            issue: ParsedIssueData,
            raw_line: RawLogLine | None,
            stored_line: str | None,
        ) -> None:
            if issue.severity is IssueSeverity.ERROR:
                stats.error_issue_count += 1
            if issue.issue_type == IssueType.MISSING_REQUIRED_FIELD.value:
                stats.missing_required_fields += 1
            elif issue.issue_type == IssueType.MISSING_OPTIONAL_FIELD.value:
                stats.missing_optional_fields += 1
            elif issue.issue_type == IssueType.PARSER_ERROR.value:
                stats.parser_errors += 1
            elif issue.issue_type == IssueType.UNSUPPORTED_FORMAT.value:
                stats.unsupported_formats += 1
            if stats.issues_recorded >= self.settings.max_parsing_issues:
                stats.issues_suppressed += 1
                return
            issue_buffer.append(
                {
                    "evidence_file_id": evidence.id,
                    "parsing_result_id": result.id,
                    "line_number": raw_line.number if raw_line else None,
                    "byte_offset": raw_line.offset if raw_line else None,
                    "raw_line": _stored_text(stored_line, self.settings.max_stored_raw_line_chars)
                    if stored_line is not None
                    else None,
                    "issue_type": issue.issue_type,
                    "severity": issue.severity,
                    "message": _stored_text(issue.message, _ISSUE_MESSAGE_LIMIT),
                }
            )
            stats.issues_recorded += 1
            if len(issue_buffer) >= _BULK_CHUNK:
                flush_issues()

        try:
            for raw_line in iter_log_lines(path, self.settings.max_line_bytes):
                stats.total_lines += 1

                if raw_line.truncated:
                    stats.records_received += 1
                    stats.records_rejected += 1
                    stats.malformed_records += 1
                    text = raw_line.data.decode("utf-8", errors="replace").rstrip("\r\n")
                    add_issue(
                        ParsedIssueData(
                            issue_type=IssueType.LINE_TOO_LONG.value,
                            severity=IssueSeverity.ERROR,
                            message=(
                                f"Line exceeds the {self.settings.max_line_bytes}-byte analysis "
                                "limit and was not parsed. The original evidence is retained."
                            ),
                        ),
                        raw_line,
                        text,
                    )
                    continue

                try:
                    text = raw_line.data.decode("utf-8")
                except UnicodeDecodeError:
                    stats.encoding_error_lines += 1
                    text = raw_line.data.decode("utf-8", errors="replace")
                    stored = text.rstrip("\r\n")
                    add_issue(
                        ParsedIssueData(
                            issue_type=IssueType.ENCODING_ERROR.value,
                            severity=IssueSeverity.WARNING,
                            message=(
                                "Line is not valid UTF-8; invalid bytes were replaced for "
                                "analysis. The original bytes remain unchanged."
                            ),
                        ),
                        raw_line,
                        stored,
                    )

                line = text.rstrip("\r\n")
                if not line.strip():
                    stats.blank_lines += 1
                    continue
                stats.records_received += 1

                try:
                    parsed = parser.parse_line(line, config)
                except Exception as exc:  # defensive: one line must not abort a file
                    stats.malformed_records += 1
                    stats.records_rejected += 1
                    logger.exception(
                        "Parser %s raised on evidence %s line %s",
                        parser.name,
                        evidence.id,
                        raw_line.number,
                    )
                    add_issue(
                        ParsedIssueData(
                            issue_type=IssueType.PARSER_ERROR.value,
                            severity=IssueSeverity.ERROR,
                            message=(
                                f"Parser raised {type(exc).__name__}; the record was not parsed. "
                                "The original evidence is retained."
                            ),
                        ),
                        raw_line,
                        line,
                    )
                    continue

                event = parsed.event
                if event is None:
                    stats.malformed_records += 1
                    stats.records_rejected += 1
                    if not any(
                        issue.severity is IssueSeverity.ERROR for issue in parsed.issues
                    ):
                        parsed.issues.append(
                            ParsedIssueData(
                                issue_type=IssueType.MALFORMED_LINE.value,
                                severity=IssueSeverity.ERROR,
                                message="Record could not be parsed into a normalized event.",
                            )
                        )
                else:
                    stats.parsed_records += 1
                    stats.missing_optional_fields += parsed.optional_fields_missing
                    if event.timestamp.status is not TimestampStatus.NORMALIZED:
                        stats.timestamp_flagged_records += 1
                    event_buffer.append(
                        self._event_row(evidence, raw_line, line, event)
                    )
                    if len(event_buffer) >= _BULK_CHUNK:
                        flush_events()

                for issue in parsed.issues:
                    add_issue(issue, raw_line, line)

            flush_events()
            flush_issues()
        except OSError as exc:
            result.fatal_error = f"Evidence file could not be read completely: {exc}"
            logger.exception("Failed while reading evidence %s", evidence.id)
            raise IngestError(
                500, "evidence_read_error", "The stored evidence file could not be read."
            ) from exc
        except Exception:
            flush_events()
            flush_issues()
            raise

        return stats

    def _event_row(
        self,
        evidence: EvidenceFile,
        raw_line: RawLogLine,
        line: str,
        event: ParsedEventData,
    ) -> dict:
        resolution = apply_clock_offset(event.timestamp, evidence.clock_offset_seconds)
        line_hash = hashlib.sha256(raw_line.data).hexdigest()
        return {
            "evidence_file_id": evidence.id,
            "investigation_id": evidence.investigation_id,
            "source_id": evidence.source_id,
            "line_number": raw_line.number,
            "byte_offset": raw_line.offset,
            "line_sha256": line_hash,
            "raw_line": _stored_text(line, self.settings.max_stored_raw_line_chars),
            "event_category": event.event_category,
            "event_type": event.event_type,
            "hostname": event.hostname,
            "source_ip": event.source_ip,
            "username": event.username,
            "process": event.process,
            "pid": event.pid,
            "message": event.message,
            "http_method": event.http_method,
            "http_path": event.http_path,
            "http_status": event.http_status,
            "http_bytes": event.http_bytes,
            "http_referer": event.http_referer,
            "http_user_agent": event.http_user_agent,
            "original_timestamp_string": resolution.original_string,
            "original_timezone": resolution.original_timezone,
            "timestamp_utc": resolution.utc,
            "timestamp_status": resolution.status,
            "timestamp_detail": resolution.detail,
            "timestamp_precision": resolution.precision,
            "clock_offset_seconds": resolution.clock_offset_seconds,
            "clock_offset_applied": resolution.clock_offset_applied,
            "ordering_status": (
                OrderingStatus.UNRESOLVED
                if resolution.utc is None
                else OrderingStatus.ORDERED
            ),
            "dedup_status": DuplicateStatus.UNIQUE,
            "fingerprint_sha256": event_fingerprint(
                source_id=evidence.source_id,
                event_category=event.event_category,
                event_type=event.event_type,
                timestamp_utc=resolution.utc,
                original_timestamp_string=resolution.original_string,
                line_sha256=line_hash,
            ),
            "extra": event.extra,
        }
