"""Safe evidence storage.

Original bytes are written to a per-evidence directory, hashed while streaming
and made read-only after the write. The analysis database only ever stores a
relative path, never a client-supplied path.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.config import Settings
from app.services.errors import IngestError

_CHUNK_SIZE = 1024 * 1024
_UNSAFE_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


@dataclass(slots=True)
class TempUpload:
    path: Path
    original_filename: str
    sha256: str
    size_bytes: int


def sanitize_filename(filename: str, allowed_extensions: set[str]) -> str:
    if not filename or not filename.strip():
        raise IngestError(422, "invalid_filename", "A filename is required.")

    normalized = unicodedata.normalize("NFKC", filename.replace("\\", "/"))
    name = normalized.rsplit("/", 1)[-1].strip()
    name = _UNSAFE_CHARS_RE.sub("_", name).strip(" .")

    if not name or name in {".", ".."}:
        raise IngestError(422, "invalid_filename", "Filename is empty after sanitization.")

    extension = Path(name).suffix.lower()
    if extension not in allowed_extensions:
        allowed = ", ".join(sorted(allowed_extensions))
        raise IngestError(
            415,
            "unsupported_file_type",
            f"Unsupported file extension {extension or '(none)'!r}. Allowed: {allowed}.",
        )

    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        name = f"_{name}"

    stem, suffix = os.path.splitext(name)
    suffix = suffix[:20]
    byte_budget = 200 - len(suffix.encode("utf-8"))
    while len(stem.encode("utf-8")) > max(byte_budget, 1):
        stem = stem[:-1]
    if not stem:
        stem = "evidence"
    return f"{stem}{suffix}"


def stream_to_temp(
    source: BinaryIO,
    original_filename: str,
    settings: Settings,
) -> TempUpload:
    safe_name = sanitize_filename(original_filename, settings.allowed_extension_set)
    settings.temp_root.mkdir(parents=True, exist_ok=True)
    temp_path = settings.temp_root / f"{uuid.uuid4().hex}.upload"
    digest = hashlib.sha256()
    size = 0

    try:
        with temp_path.open("wb") as target:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                if b"\x00" in chunk:
                    raise IngestError(
                        415,
                        "binary_content",
                        "The upload contains NUL bytes and does not look like a text log.",
                    )
                size += len(chunk)
                if size > settings.max_upload_size_bytes:
                    raise IngestError(
                        413,
                        "file_too_large",
                        f"Upload exceeds the {settings.max_upload_size_bytes} byte limit.",
                    )
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    if size == 0:
        temp_path.unlink(missing_ok=True)
        raise IngestError(422, "empty_file", "Empty files are not accepted as evidence.")

    return TempUpload(
        path=temp_path,
        original_filename=safe_name,
        sha256=digest.hexdigest(),
        size_bytes=size,
    )


def finalize_upload(
    temp: TempUpload,
    *,
    investigation_id: uuid.UUID,
    evidence_id: uuid.UUID,
    settings: Settings,
) -> str:
    destination_dir = settings.evidence_root / str(investigation_id) / str(evidence_id)
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / temp.original_filename
    try:
        os.replace(temp.path, destination)
        try:
            os.chmod(destination, 0o444)
        except OSError:
            pass
    except OSError as exc:
        temp.path.unlink(missing_ok=True)
        raise IngestError(
            500, "storage_error", f"Could not store evidence securely: {exc}."
        ) from exc

    return destination.relative_to(settings.storage_root).as_posix()


def resolve_relative_path(relative_path: str, settings: Settings) -> Path:
    root = settings.storage_root.resolve()
    candidate = (root / relative_path).resolve()
    if not candidate.is_relative_to(root):
        raise IngestError(400, "invalid_storage_path", "Stored evidence path is invalid.")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_stored_file(relative_path: str, expected_sha256: str, settings: Settings) -> tuple[bool, str]:
    path = resolve_relative_path(relative_path, settings)
    if not path.is_file():
        raise IngestError(404, "evidence_file_missing", "Original evidence file is missing from storage.")
    actual = sha256_file(path)
    return actual == expected_sha256, actual


def cleanup_temp(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def check_storage_writable(settings: Settings) -> tuple[bool, str]:
    try:
        settings.temp_root.mkdir(parents=True, exist_ok=True)
        probe = settings.temp_root / f".write-probe-{uuid.uuid4().hex}"
        probe.write_bytes(b"ok")
        probe.unlink(missing_ok=True)
        return True, "ok"
    except OSError as exc:
        return False, str(exc)
