"""Parser registry and content-based source detection."""

from __future__ import annotations

from pathlib import Path

from app.constants import SourceType
from app.services.parsers.base import LogParser
from app.services.parsers.linux_auth import LinuxAuthParser
from app.services.parsers.web_access import WebAccessParser

PARSERS: dict[SourceType, LogParser] = {
    SourceType.LINUX_AUTH: LinuxAuthParser(),
    SourceType.WEB_ACCESS: WebAccessParser(),
}

DETECTION_SAMPLE_LINES = 100


def get_parser(source_type: SourceType) -> LogParser | None:
    return PARSERS.get(source_type)


def detect_source_type(path: Path, max_line_bytes: int) -> SourceType | None:
    """Sniff up to 100 non-blank lines and choose the best-supported format.

    If no line matches a supported parser the file is treated as an unsupported
    format. It is still preserved and hashed; the parse result records the gap.
    """

    counts = {SourceType.LINUX_AUTH: 0, SourceType.WEB_ACCESS: 0}
    inspected = 0
    try:
        with path.open("rb") as handle:
            for raw in handle:
                stripped = raw.strip()
                if not stripped:
                    continue
                inspected += 1
                try:
                    line = stripped.decode("utf-8")
                except UnicodeDecodeError:
                    line = stripped.decode("utf-8", errors="replace")
                for source_type, parser in PARSERS.items():
                    if parser.matches(line):
                        counts[source_type] += 1
                if inspected >= DETECTION_SAMPLE_LINES:
                    break
    except OSError:
        return None

    if counts[SourceType.LINUX_AUTH] == 0 and counts[SourceType.WEB_ACCESS] == 0:
        return None
    if counts[SourceType.LINUX_AUTH] >= counts[SourceType.WEB_ACCESS]:
        return SourceType.LINUX_AUTH
    return SourceType.WEB_ACCESS
