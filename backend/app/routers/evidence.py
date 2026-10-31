"""Evidence upload, preservation, status, download and verification endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.config import Settings, get_settings
from app.constants import (
    AuditEventType,
    IssueSeverity,
    RequestedSourceType,
    VerificationSource,
)
from app.database import get_db
from app.models import (
    EvidenceFile,
    EvidenceVerification,
    Investigation,
    ParsedEvent,
    ParsingIssue,
    utcnow,
)
from app.schemas import (
    EvidenceListPage,
    EvidenceRead,
    EvidenceStatusRead,
    EvidenceVerificationRead,
    ManifestItemRead,
    ManifestRead,
    ParsingIssuePage,
    ParsingIssueRead,
    ReparseResponse,
    VerificationPage,
    VerifyHashResponse,
)
from app.serializers import evidence_read
from app.services import storage
from app.services.errors import IngestError
from app.services.ingest import IngestOptions, IngestService
from app.services.quality import build_manifest, record_audit

router = APIRouter(tags=["evidence"])

_EVIDENCE_OPTIONS = (
    selectinload(EvidenceFile.source),
    selectinload(EvidenceFile.hashes),
    selectinload(EvidenceFile.parsing_result),
)


def _event_count(session: Session, evidence_id: uuid.UUID) -> int:
    return int(
        session.scalar(
            select(func.count(ParsedEvent.id)).where(ParsedEvent.evidence_file_id == evidence_id)
        )
        or 0
    )


def _get_evidence(session: Session, evidence_id: uuid.UUID) -> EvidenceFile:
    evidence = session.scalar(
        select(EvidenceFile).options(*_EVIDENCE_OPTIONS).where(EvidenceFile.id == evidence_id)
    )
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    return evidence


def _reload_evidence(session: Session, evidence_id: uuid.UUID) -> EvidenceFile:
    session.expire_all()
    return _get_evidence(session, evidence_id)


def _raise_ingest(exc: IngestError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.as_detail()) from exc


def _request_meta(request: Request) -> tuple[str | None, str | None]:
    client = request.client.host if request.client else None
    request_id = request.headers.get("x-request-id") or None
    return client, request_id


@router.post(
    "/investigations/{investigation_id}/evidence",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
def upload_evidence(
    investigation_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(..., description="Plain-text Linux auth or web access log"),
    source_type: RequestedSourceType = Form(RequestedSourceType.AUTO),
    source_id: uuid.UUID | None = Form(None),
    source_name: str | None = Form(None),
    hostname: str | None = Form(None),
    source_ip: str | None = Form(None),
    timezone_hint: str | None = Form(None),
    default_year: int | None = Form(None),
    clock_offset_seconds: int | None = Form(None),
    collected_at: datetime | None = Form(None),
    notes: str | None = Form(None),
    allow_duplicate: bool = Form(False),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EvidenceRead:
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    if not file.filename:
        raise HTTPException(status_code=422, detail="Uploaded file must have a filename.")

    file.file.seek(0)
    actor_detail, request_id = _request_meta(request)
    options = IngestOptions(
        requested_source_type=source_type,
        source_id=source_id,
        source_name=source_name,
        hostname=hostname,
        source_ip=source_ip,
        timezone_hint=timezone_hint,
        default_year=default_year,
        clock_offset_seconds=clock_offset_seconds,
        collected_at=collected_at,
        notes=notes,
        allow_duplicate=allow_duplicate,
        content_type=file.content_type,
        actor_type="api",
        actor_detail=actor_detail,
        request_id=request_id,
    )
    service = IngestService(session, settings)
    try:
        evidence = service.ingest(investigation, file.file, file.filename, options)
    except IngestError as exc:
        if exc.code == "duplicate_evidence":
            existing_id = exc.extra.get("existing_evidence_id")
            existing = (
                session.get(EvidenceFile, uuid.UUID(existing_id)) if existing_id else None
            )
            if existing is not None:
                record_audit(
                    session,
                    investigation_id=investigation.id,
                    event_type=AuditEventType.DUPLICATE_UPLOAD_REJECTED,
                    evidence=existing,
                    actor_type="api",
                    actor_detail=actor_detail,
                    request_id=request_id,
                    detail={"sha256": exc.extra.get("sha256")},
                )
                session.commit()
        _raise_ingest(exc)

    evidence = _reload_evidence(session, evidence.id)
    return evidence_read(
        evidence, settings, event_count=_event_count(session, evidence.id)
    )


@router.get("/evidence", response_model=EvidenceListPage)
def list_evidence(
    investigation_id: uuid.UUID = Query(...),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EvidenceListPage:
    if session.get(Investigation, investigation_id) is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    total = int(
        session.scalar(
            select(func.count(EvidenceFile.id)).where(
                EvidenceFile.investigation_id == investigation_id
            )
        )
        or 0
    )
    evidence_files = session.scalars(
        select(EvidenceFile)
        .options(*_EVIDENCE_OPTIONS)
        .where(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.received_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    counts = dict(
        session.execute(
            select(ParsedEvent.evidence_file_id, func.count(ParsedEvent.id))
            .where(
                ParsedEvent.evidence_file_id.in_([item.id for item in evidence_files])
            )
            .group_by(ParsedEvent.evidence_file_id)
        ).all()
    )
    items = [
        evidence_read(
            evidence, settings, event_count=int(counts.get(evidence.id, 0))
        )
        for evidence in evidence_files
    ]
    return EvidenceListPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/evidence/{evidence_id}", response_model=EvidenceRead)
def get_evidence(
    evidence_id: uuid.UUID,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> EvidenceRead:
    evidence = _get_evidence(session, evidence_id)
    return evidence_read(
        evidence, settings, event_count=_event_count(session, evidence.id)
    )


@router.get("/evidence/{evidence_id}/status", response_model=EvidenceStatusRead)
def get_evidence_status(
    evidence_id: uuid.UUID, session: Session = Depends(get_db)
) -> EvidenceStatusRead:
    evidence = _get_evidence(session, evidence_id)
    event_count = _event_count(session, evidence_id)

    issue_by_type = {
        str(issue_type): int(count)
        for issue_type, count in session.execute(
            select(ParsingIssue.issue_type, func.count(ParsingIssue.id))
            .where(ParsingIssue.evidence_file_id == evidence_id)
            .group_by(ParsingIssue.issue_type)
        ).all()
    }
    issue_by_severity = {
        str(getattr(severity, "value", severity)): int(count)
        for severity, count in session.execute(
            select(ParsingIssue.severity, func.count(ParsingIssue.id))
            .where(ParsingIssue.evidence_file_id == evidence_id)
            .group_by(ParsingIssue.severity)
        ).all()
    }
    timestamp_by_status = {
        str(getattr(timestamp_status, "value", timestamp_status)): int(count)
        for timestamp_status, count in session.execute(
            select(ParsedEvent.timestamp_status, func.count(ParsedEvent.id))
            .where(ParsedEvent.evidence_file_id == evidence_id)
            .group_by(ParsedEvent.timestamp_status)
        ).all()
    }

    return EvidenceStatusRead(
        evidence_id=evidence.id,
        status=evidence.status,
        parser_name=evidence.parser_name,
        parsing_result=evidence.parsing_result,
        event_count=event_count,
        issue_counts_by_type=issue_by_type,
        issue_counts_by_severity=issue_by_severity,
        timestamp_status_counts=timestamp_by_status,
    )


@router.get("/evidence/{evidence_id}/issues", response_model=ParsingIssuePage)
def list_issues(
    evidence_id: uuid.UUID,
    severity: IssueSeverity | None = Query(None),
    issue_type: str | None = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> ParsingIssuePage:
    if session.get(EvidenceFile, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence file not found.")

    conditions = [ParsingIssue.evidence_file_id == evidence_id]
    if severity is not None:
        conditions.append(ParsingIssue.severity == severity)
    if issue_type:
        conditions.append(ParsingIssue.issue_type == issue_type)

    total = int(
        session.scalar(select(func.count(ParsingIssue.id)).where(*conditions)) or 0
    )
    issues = session.scalars(
        select(ParsingIssue)
        .where(*conditions)
        .order_by(ParsingIssue.line_number.asc().nulls_last(), ParsingIssue.id.asc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ParsingIssuePage(
        items=[ParsingIssueRead.model_validate(issue) for issue in issues],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/evidence/{evidence_id}/download")
def download_evidence(
    evidence_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FileResponse:
    evidence = session.get(EvidenceFile, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    path = storage.resolve_relative_path(evidence.stored_relative_path, settings)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Original evidence file is missing from storage.")

    actor_detail, request_id = _request_meta(request)
    record_audit(
        session,
        investigation_id=evidence.investigation_id,
        event_type=AuditEventType.EVIDENCE_DOWNLOADED,
        evidence=evidence,
        actor_type="api",
        actor_detail=actor_detail,
        request_id=request_id,
        detail={"filename": evidence.original_filename, "size_bytes": evidence.size_bytes},
    )
    session.commit()

    return FileResponse(
        path=Path(path),
        media_type="text/plain",
        filename=evidence.original_filename,
        headers={
            "X-CyberTrace-SHA256": evidence.sha256,
            "Cache-Control": "no-store",
        },
    )


@router.post("/evidence/{evidence_id}/verify", response_model=VerifyHashResponse)
def verify_evidence_hash(
    evidence_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> VerifyHashResponse:
    evidence = _get_evidence(session, evidence_id)
    service = IngestService(session, settings)
    actor_detail, request_id = _request_meta(request)
    try:
        match, actual, hash_record = service.verify_hash(
            evidence,
            source=VerificationSource.API,
            actor_type="api",
            actor_detail=actor_detail,
            request_id=request_id,
        )
    except IngestError as exc:
        _raise_ingest(exc)

    return VerifyHashResponse(
        evidence_id=evidence.id,
        algorithm=hash_record.algorithm,
        expected_sha256=evidence.sha256,
        actual_sha256=actual,
        match=match,
        outcome=evidence.integrity_status,
        source=evidence.last_verification_source or "api",
        verified_at=hash_record.verified_at,
        note=hash_record.verification_note or "",
    )


@router.get("/evidence/{evidence_id}/verifications", response_model=VerificationPage)
def list_verifications(
    evidence_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db),
) -> VerificationPage:
    if session.get(EvidenceFile, evidence_id) is None:
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    total = int(
        session.scalar(
            select(func.count(EvidenceVerification.id)).where(
                EvidenceVerification.evidence_file_id == evidence_id
            )
        )
        or 0
    )
    items = session.scalars(
        select(EvidenceVerification)
        .where(EvidenceVerification.evidence_file_id == evidence_id)
        .order_by(EvidenceVerification.verified_at.desc(), EvidenceVerification.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return VerificationPage(
        items=[
            EvidenceVerificationRead.model_validate(item) for item in items
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/evidence/{evidence_id}/manifest", response_model=ManifestRead)
def get_evidence_manifest(
    evidence_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
) -> ManifestRead:
    evidence = session.get(EvidenceFile, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence file not found.")
    body, digest = build_manifest(
        [evidence], scope="evidence", investigation_id=evidence.investigation_id
    )
    actor_detail, request_id = _request_meta(request)
    record_audit(
        session,
        investigation_id=evidence.investigation_id,
        event_type=AuditEventType.MANIFEST_EXPORTED,
        evidence=evidence,
        actor_type="api",
        actor_detail=actor_detail,
        request_id=request_id,
        detail={"scope": "evidence", "manifest_sha256": digest},
    )
    session.commit()
    return ManifestRead(
        scope=body["scope"],
        investigation_id=evidence.investigation_id,
        generated_at=utcnow(),
        manifest_sha256=digest,
        item_count=body["item_count"],
        items=[ManifestItemRead(**item) for item in body["items"]],
        note=(
            "The manifest hash covers the canonical scope/investigation/items body. "
            "Verification checks stored bytes against the recorded hash; it does not "
            "prove authenticity before collection."
        ),
    )


@router.post("/evidence/{evidence_id}/reparse", response_model=ReparseResponse)
def reparse_evidence(
    evidence_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ReparseResponse:
    evidence = _get_evidence(session, evidence_id)
    service = IngestService(session, settings)
    actor_detail, request_id = _request_meta(request)
    try:
        reparsed = service.reparse(
            evidence,
            actor_type="api",
            actor_detail=actor_detail,
            request_id=request_id,
        )
    except IngestError as exc:
        _raise_ingest(exc)

    reparsed = _reload_evidence(session, reparsed.id)
    return ReparseResponse(
        evidence=evidence_read(
            reparsed, settings, event_count=_event_count(session, reparsed.id)
        ),
        message="Reparsed from the preserved original evidence after hash verification.",
    )
