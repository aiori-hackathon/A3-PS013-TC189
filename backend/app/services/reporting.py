"""Reproducible investigation report and CSV export helpers."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.constants import TimestampStatus
from app.models import (
    EvidenceFile,
    EvidenceSource,
    Investigation,
    ParsedEvent,
    ParsingResult,
)
from app.services.analytics import build_summary
from app.services.correlation import list_correlations
from app.services.coverage import build_investigation_coverage, default_coverage_window


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def gather_report_data(
    session: Session,
    settings: Settings,
    investigation_id: uuid.UUID,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        raise ValueError("Investigation not found.")

    start_utc = _aware(start)
    end_utc = _aware(end)
    summary = build_summary(session, investigation_id)

    sources = session.scalars(
        select(EvidenceSource)
        .where(EvidenceSource.investigation_id == investigation_id)
        .order_by(EvidenceSource.name.asc())
    ).all()

    evidence_files = session.scalars(
        select(EvidenceFile)
        .where(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.received_at.asc(), EvidenceFile.id.asc())
    ).all()

    event_rows = session.execute(
        select(ParsedEvent, EvidenceSource, EvidenceFile)
        .join(EvidenceSource, ParsedEvent.source_id == EvidenceSource.id)
        .join(EvidenceFile, ParsedEvent.evidence_file_id == EvidenceFile.id)
        .where(ParsedEvent.investigation_id == investigation_id)
        .order_by(ParsedEvent.id.asc())
    ).all()

    filtered_events: list[tuple[ParsedEvent, EvidenceSource, EvidenceFile]] = []
    for event, source, evidence in event_rows:
        if start_utc is not None and event.timestamp_utc is not None and event.timestamp_utc < start_utc:
            continue
        if end_utc is not None and event.timestamp_utc is not None and event.timestamp_utc > end_utc:
            continue
        filtered_events.append((event, source, evidence))

    correlations = list_correlations(session, investigation_id)

    now = datetime.now(UTC)
    if start_utc is None or end_utc is None:
        window_start, window_end = default_coverage_window(settings, now)
        window_start = start_utc or window_start
        window_end = end_utc or window_end
    else:
        window_start, window_end = start_utc, end_utc
    coverage = build_investigation_coverage(
        session,
        settings,
        investigation_id=investigation_id,
        window_start=window_start,
        window_end=window_end,
        now=now,
    )

    # Parsing quality items, matching quality endpoint.
    parsing_rows = session.execute(
        select(EvidenceFile, EvidenceSource)
        .join(EvidenceSource, EvidenceSource.id == EvidenceFile.source_id)
        .where(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.received_at.desc())
    ).all()
    parsing_items = []
    for evidence, source in parsing_rows:
        result = session.scalar(
            select(ParsingResult).where(ParsingResult.evidence_file_id == evidence.id)
        )
        parsing_items.append((evidence, source, result))

    return {
        "investigation": investigation,
        "summary": summary,
        "sources": sources,
        "evidence_files": evidence_files,
        "events": filtered_events,
        "correlations": correlations,
        "coverage": coverage,
        "parsing_items": parsing_items,
        "window_start": window_start,
        "window_end": window_end,
        "generated_at": now,
        "start": start_utc,
        "end": end_utc,
    }


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(0.75 * inch, 0.45 * inch, f"CyberTrace investigation report - page {doc.page}")
    canvas.restoreState()


def build_pdf(data: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
    )
    styles = getSampleStyleSheet()
    normal = styles["BodyText"]
    normal.fontSize = 9
    small = styles["BodyText"]
    small.fontSize = 8
    heading = styles["Heading2"]
    title = styles["Title"]
    story: list[Any] = []

    investigation = data["investigation"]
    story.append(Paragraph("CyberTrace Investigation Report", title))
    story.append(Spacer(1, 0.1 * inch))
    story.append(
        Paragraph(
            "Reproducible report generated from stored investigation data. "
            "Original evidence files remain separate from this generated report.",
            small,
        )
    )
    story.append(Spacer(1, 0.15 * inch))

    meta_rows = [
        ["Investigation name", investigation.name],
        ["Investigation ID", str(investigation.id)],
        ["Description", investigation.description or "Not provided"],
        ["Report generated (UTC)", data["generated_at"].strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Created (UTC)", investigation.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Event scope", _scope_text(data)],
    ]
    story.append(_table(["Field", "Value"], meta_rows, [1.7 * inch, 5.1 * inch]))
    story.append(Spacer(1, 0.15 * inch))

    # Incident summary
    story.append(Paragraph("1. Incident summary", heading))
    summary = data["summary"]
    summary_rows = [
        ["Timeline events", str(summary.events)],
        ["Evidence files", str(summary.evidence_files)],
        ["Sources", str(summary.sources)],
        ["Parsed records", str(summary.parsed_records)],
        ["Rejected records", str(summary.records_rejected)],
        ["Malformed records", str(summary.malformed_records)],
        ["Unsupported records", str(summary.unsupported_records)],
        ["Timestamp-uncertain events", str(summary.timestamp_flagged_records)],
        ["Duplicate records", str(summary.duplicate_records)],
        ["Open collection gaps", str(data["coverage"].summary.open_gaps)],
        ["Integrity attention", str(summary.integrity_mismatched + summary.integrity_unverified + summary.integrity_missing)],
        ["Correlations", str(len(data["correlations"]))],
    ]
    story.append(_table(["Metric", "Value"], summary_rows, [3.2 * inch, 1.5 * inch]))
    story.append(Spacer(1, 0.1 * inch))

    # Investigation scope
    story.append(Paragraph("2. Investigation scope", heading))
    story.append(
        Paragraph(
            "This report summarizes the investigation identified above, including all stored "
            "evidence, parsed events, collection coverage, integrity state, and correlations "
            "available at report generation time. Missing or unavailable information is marked explicitly.",
            normal,
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    # Source systems and evidence files
    story.append(Paragraph("3. Source systems and evidence files", heading))
    if data["sources"]:
        source_rows = [
            [source.name, source.source_type.value, source.hostname or "Unknown", source.ip_address or "Unknown"]
            for source in data["sources"]
        ]
        story.append(
            _table(
                ["Source", "Type", "Hostname", "IP address"],
                source_rows,
                [1.6 * inch, 1.2 * inch, 2.0 * inch, 2.0 * inch],
            )
        )
    else:
        story.append(Paragraph("No source systems recorded.", normal))
    story.append(Spacer(1, 0.1 * inch))

    if data["evidence_files"]:
        evidence_rows = []
        for evidence in data["evidence_files"]:
            evidence_rows.append(
                [
                    evidence.original_filename,
                    evidence.source.name if evidence.source else "Unknown",
                    evidence.source_type.value,
                    str(evidence.size_bytes),
                    evidence.sha256,
                    evidence.integrity_status.value,
                ]
            )
        story.append(
            _table(
                ["Filename", "Source", "Type", "Size", "SHA-256", "Integrity"],
                evidence_rows,
                [1.35 * inch, 1.0 * inch, 0.8 * inch, 0.6 * inch, 2.0 * inch, 0.85 * inch],
            )
        )
    else:
        story.append(Paragraph("No evidence files recorded.", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Timeline
    story.append(Paragraph("4. Relevant incident timeline", heading))
    if data["events"]:
        timeline_rows = []
        for event, source, _evidence in data["events"]:
            timeline_rows.append(
                [
                    event.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S UTC") if event.timestamp_utc else "Unresolved",
                    event.original_timestamp_string or "Not available",
                    f"{event.event_type} (event {event.id})",
                    source.name,
                ]
            )
        story.append(
            _table(
                ["Normalized UTC", "Original timestamp", "Event", "Source"],
                timeline_rows,
                [1.5 * inch, 1.9 * inch, 1.9 * inch, 1.5 * inch],
            )
        )
    else:
        story.append(Paragraph("No events recorded for this scope.", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Timestamp uncertainty
    story.append(Paragraph("5. Timestamp uncertainty warnings", heading))
    uncertain = [
        (event, source, evidence)
        for event, source, evidence in data["events"]
        if getattr(event.timestamp_status, "value", event.timestamp_status) != TimestampStatus.NORMALIZED.value
    ]
    if uncertain:
        for event, source, _evidence in uncertain[:100]:
            story.append(
                Paragraph(
                    f"Event {event.id} ({event.event_type}, {source.name}): "
                    f"{getattr(event.timestamp_status, 'value', event.timestamp_status)} - "
                    f"{event.timestamp_detail or 'no UTC timestamp available'}. "
                    f"Original timestamp: {event.original_timestamp_string or 'not available'}.",
                    normal,
                )
            )
            story.append(Spacer(1, 0.04 * inch))
    else:
        story.append(Paragraph("All recorded events in this scope have normalized UTC timestamps.", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Evidence integrity
    story.append(Paragraph("6. Evidence integrity verification status", heading))
    integrity_rows = [
        [
            evidence.original_filename,
            evidence.integrity_status.value,
            str(evidence.verification_count),
            evidence.last_verified_at.strftime("%Y-%m-%d %H:%M:%S UTC") if evidence.last_verified_at else "Never",
        ]
        for evidence in data["evidence_files"]
    ]
    if integrity_rows:
        story.append(_table(["Evidence", "Integrity", "Verifications", "Last verified"], integrity_rows, [2.2 * inch, 1.0 * inch, 1.0 * inch, 1.8 * inch]))
    else:
        story.append(Paragraph("No evidence files recorded.", normal))
    story.append(
        Paragraph(
            "A hash match shows that stored bytes are unchanged since preservation. "
            "It does not prove that the evidence was authentic before collection.",
            small,
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    # Collection coverage
    story.append(Paragraph("7. Collection coverage and missing intervals", heading))
    coverage = data["coverage"]
    coverage_rows = [
        [
            source.name,
            source.coverage_state,
            f"{source.observed_cycles}/{source.expected_cycles}",
            source.bytes_missing and str(source.bytes_missing) or "0",
        ]
        for source in coverage.sources
    ]
    if coverage_rows:
        story.append(_table(["Source", "Coverage", "Cycles observed/expected", "Bytes missing"], coverage_rows, [2.0 * inch, 1.2 * inch, 1.8 * inch, 1.2 * inch]))
    else:
        story.append(Paragraph("No collection coverage data available.", normal))
    if coverage.gaps:
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph("Missing intervals:", normal))
        for gap in coverage.gaps[:100]:
            story.append(
                Paragraph(
                    f"{gap.source_name or gap.agent_name or 'Agent scope'}: "
                    f"{gap.gap_start.strftime('%Y-%m-%d %H:%M:%S UTC')} to "
                    f"{gap.gap_end.strftime('%Y-%m-%d %H:%M:%S UTC') if gap.gap_end else 'ongoing'} "
                    f"({gap.reason}, {gap.basis}).",
                    small,
                )
            )
    story.append(Spacer(1, 0.1 * inch))

    # Parsing failures
    story.append(Paragraph("8. Parsing failures and unsupported records", heading))
    parsing_rows = []
    for evidence, source, result in data["parsing_items"]:
        if result is None:
            parsing_rows.append([evidence.original_filename, source.name, "not parsed", "0", "0", "0"])
            continue
        parsing_rows.append(
            [
                evidence.original_filename,
                source.name,
                result.status.value,
                str(result.parsed_records),
                str(result.records_rejected),
                str(result.issues_recorded),
            ]
        )
    if parsing_rows:
        story.append(
            _table(
                ["Evidence", "Source", "Status", "Parsed", "Rejected", "Issues"],
                parsing_rows,
                [1.9 * inch, 1.3 * inch, 0.9 * inch, 0.7 * inch, 0.8 * inch, 0.7 * inch],
            )
        )
    else:
        story.append(Paragraph("No parsing results recorded.", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Correlations
    story.append(Paragraph("9. Cross-system correlation results", heading))
    if data["correlations"]:
        for correlation in data["correlations"]:
            story.append(Paragraph(f"{correlation.title}", styles["Heading3"]))
            corr_rows = [
                ["Rule", correlation.rule_name],
                ["Confidence", correlation.confidence.value if hasattr(correlation.confidence, "value") else str(correlation.confidence)],
                ["Status", correlation.status.value if hasattr(correlation.status, "value") else str(correlation.status)],
                ["Matching fields", ", ".join(correlation.matching_fields or []) or "None"],
                ["Source systems", ", ".join(sorted({member.event.source.name for member in correlation.members}))],
                ["Linked events", ", ".join(str(member.event_id) for member in correlation.members)],
            ]
            story.append(_table(["Field", "Value"], corr_rows, [1.7 * inch, 5.1 * inch]))
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph(f"Time relationship: {correlation.time_relationship or 'Not available'}", normal))
            story.append(Paragraph(f"Timestamp uncertainty: {correlation.timestamp_uncertainty or 'None recorded'}", normal))
            story.append(Paragraph(f"Explanation: {correlation.explanation}", normal))
            # Source record references
            refs = []
            for member in correlation.members:
                event = member.event
                evidence = event.evidence_file
                refs.append(
                    f"Event {event.id}: {evidence.original_filename}, line {event.line_number}, "
                    f"SHA-256 {evidence.sha256}"
                )
            if refs:
                story.append(Paragraph("Source records: " + "; ".join(refs), small))
            story.append(Spacer(1, 0.1 * inch))
    else:
        story.append(Paragraph("No correlations recorded.", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Analyst notes
    story.append(Paragraph("10. Analyst notes", heading))
    notes_found = False
    for evidence in data["evidence_files"]:
        if evidence.notes:
            notes_found = True
            story.append(Paragraph(f"{evidence.original_filename}: {evidence.notes}", normal))
    if not notes_found:
        story.append(Paragraph("No analyst notes recorded.", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Known limitations
    story.append(Paragraph("11. Known limitations and caveats", heading))
    limitations = [
        "Correlations are heuristic and inferred; they do not prove an attack or common actor.",
        "Shared IP addresses may be coincidental, especially behind NAT or proxies.",
        "Missing or uncertain timestamps are not used as precise ordering evidence.",
        "Collection coverage describes collected data, not necessarily all host activity.",
        "A hash match does not prove evidence authenticity before collection.",
        "Reports reflect the database state at generation time.",
    ]
    for item in limitations:
        story.append(Paragraph(f"- {item}", normal))
    story.append(Spacer(1, 0.1 * inch))

    # Conclusion
    story.append(Paragraph("12. Conclusion", heading))
    conclusion = _conclusion(data)
    story.append(Paragraph(conclusion, normal))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def _scope_text(data: dict[str, Any]) -> str:
    if data["start"] or data["end"]:
        start = data["start"].strftime("%Y-%m-%d %H:%M:%S UTC") if data["start"] else "beginning"
        end = data["end"].strftime("%Y-%m-%d %H:%M:%S UTC") if data["end"] else "end"
        return f"{start} to {end}"
    return "All recorded events"


def _conclusion(data: dict[str, Any]) -> str:
    summary = data["summary"]
    coverage = data["coverage"]
    parts = [
        f"The investigation contains {summary.events} timeline events from {summary.evidence_files} evidence files "
        f"and {summary.sources} sources."
    ]
    if summary.timestamp_flagged_records:
        parts.append(f"{summary.timestamp_flagged_records} timestamp-related records require review.")
    if coverage.summary.open_gaps:
        parts.append(f"{coverage.summary.open_gaps} open collection gap(s) indicate potentially missing evidence.")
    if summary.records_rejected or summary.malformed_records or summary.unsupported_records:
        parts.append("Parsing failures or unsupported records are present and should be reviewed.")
    if summary.integrity_mismatched or summary.integrity_missing:
        parts.append("Evidence integrity attention is required.")
    if data["correlations"]:
        parts.append(f"{len(data['correlations'])} possible correlation(s) were generated and require analyst review.")
    else:
        parts.append("No correlations were generated.")
    parts.append("This conclusion is based only on recorded evidence and derived quality indicators.")
    return " ".join(parts)


def _table(headers: list[str], rows: list[list[Any]], widths: list[float]) -> Table:
    table_data = [headers] + rows
    table = Table(table_data, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d9e2f3")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
            ]
        )
    )
    return table


def build_csv(dataset: str, data: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    if dataset == "timeline":
        writer.writerow(
            [
                "event_id", "normalized_utc", "original_timestamp", "timestamp_status",
                "event_type", "event_category", "source_name", "source_type", "hostname",
                "source_ip", "username", "evidence_filename", "evidence_sha256",
                "line_number", "byte_offset", "raw_line",
            ]
        )
        for event, source, evidence in data["events"]:
            writer.writerow(
                [
                    event.id,
                    event.timestamp_utc.isoformat() if event.timestamp_utc else "",
                    event.original_timestamp_string or "",
                    getattr(event.timestamp_status, "value", event.timestamp_status),
                    event.event_type,
                    getattr(event.event_category, "value", event.event_category),
                    source.name,
                    getattr(source.source_type, "value", source.source_type),
                    event.hostname or "",
                    event.source_ip or "",
                    event.username or "",
                    evidence.original_filename,
                    evidence.sha256,
                    event.line_number,
                    event.byte_offset,
                    event.raw_line,
                ]
            )
    elif dataset == "evidence":
        writer.writerow(
            [
                "evidence_id", "filename", "source_name", "source_type", "size_bytes",
                "sha256", "integrity_status", "verification_count", "last_verified_at",
                "collected_at", "received_at", "parser_name", "status", "notes",
            ]
        )
        for evidence in data["evidence_files"]:
            writer.writerow(
                [
                    str(evidence.id),
                    evidence.original_filename,
                    evidence.source.name if evidence.source else "",
                    getattr(evidence.source_type, "value", evidence.source_type),
                    evidence.size_bytes,
                    evidence.sha256,
                    getattr(evidence.integrity_status, "value", evidence.integrity_status),
                    evidence.verification_count,
                    evidence.last_verified_at.isoformat() if evidence.last_verified_at else "",
                    evidence.collected_at.isoformat() if evidence.collected_at else "",
                    evidence.received_at.isoformat() if evidence.received_at else "",
                    evidence.parser_name or "",
                    getattr(evidence.status, "value", evidence.status),
                    evidence.notes or "",
                ]
            )
    elif dataset == "coverage":
        writer.writerow(
            [
                "source_name", "coverage_state", "expected_cycles", "observed_cycles",
                "missing_cycles", "bytes_expected", "bytes_received", "bytes_missing",
                "events_observed", "last_success_at", "open_gap",
            ]
        )
        coverage = data["coverage"]
        for source in coverage.sources:
            writer.writerow(
                [
                    source.name,
                    source.coverage_state,
                    source.expected_cycles,
                    source.observed_cycles,
                    source.missing_cycles,
                    source.bytes_expected,
                    source.bytes_received,
                    source.bytes_missing,
                    source.events_observed,
                    source.last_success_at.isoformat() if source.last_success_at else "",
                    "yes" if source.open_gap else "no",
                ]
            )
    elif dataset == "gaps":
        writer.writerow(
            [
                "gap_id", "source_name", "agent_name", "status", "reason", "basis",
                "gap_start", "gap_end", "duration_seconds", "expected_interval_seconds",
            ]
        )
        for gap in data["coverage"].gaps:
            writer.writerow(
                [
                    gap.id,
                    gap.source_name or "",
                    gap.agent_name or "",
                    gap.status,
                    gap.reason,
                    gap.basis,
                    gap.gap_start.isoformat() if gap.gap_start else "",
                    gap.gap_end.isoformat() if gap.gap_end else "",
                    gap.duration_seconds,
                    gap.expected_interval_seconds,
                ]
            )
    elif dataset == "parsing":
        writer.writerow(
            [
                "evidence_id", "filename", "source_name", "parser_name", "status",
                "parsed_records", "records_rejected", "malformed_records",
                "unsupported_records", "missing_required_fields", "timestamp_flagged_records",
                "ordering_tied_records", "ordering_unresolved_records", "issues_recorded",
            ]
        )
        for evidence, source, result in data["parsing_items"]:
            if result is None:
                writer.writerow([str(evidence.id), evidence.original_filename, source.name, "", "not parsed"] + [""] * 9)
                continue
            writer.writerow(
                [
                    str(evidence.id),
                    evidence.original_filename,
                    source.name,
                    result.parser_name or "",
                    getattr(result.status, "value", result.status),
                    result.parsed_records,
                    result.records_rejected,
                    result.malformed_records,
                    result.unsupported_records,
                    result.missing_required_fields,
                    result.timestamp_flagged_records,
                    result.ordering_tied_records,
                    result.ordering_unresolved_records,
                    result.issues_recorded,
                ]
            )
    elif dataset == "correlations":
        writer.writerow(
            [
                "correlation_id", "rule_id", "rule_name", "confidence", "status",
                "matching_fields", "source_systems", "event_id", "event_type",
                "source_name", "evidence_filename", "evidence_sha256", "normalized_utc",
                "explanation",
            ]
        )
        for correlation in data["correlations"]:
            source_systems = ", ".join(sorted({member.event.source.name for member in correlation.members}))
            for member in correlation.members:
                event = member.event
                evidence = event.evidence_file
                writer.writerow(
                    [
                        str(correlation.id),
                        correlation.rule_id,
                        correlation.rule_name,
                        getattr(correlation.confidence, "value", correlation.confidence),
                        getattr(correlation.status, "value", correlation.status),
                        ", ".join(correlation.matching_fields or []),
                        source_systems,
                        event.id,
                        event.event_type,
                        event.source.name,
                        evidence.original_filename,
                        evidence.sha256,
                        event.timestamp_utc.isoformat() if event.timestamp_utc else "",
                        correlation.explanation,
                    ]
                )
    else:
        raise ValueError(f"Unsupported dataset: {dataset}")

    return output.getvalue()
