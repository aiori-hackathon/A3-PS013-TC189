"use strict";

const state = {
  overview: null,
  investigationId: "",
  loadedAt: null,
};

const $ = (id) => document.getElementById(id);

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function clear(element) {
  element.replaceChildren();
}

function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

function fmtBytes(value) {
  if (value === null || value === undefined) return "—";
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  if (number < 1024) return `${number} B`;
  if (number < 1024 * 1024) return `${(number / 1024).toFixed(1)} KiB`;
  return `${(number / (1024 * 1024)).toFixed(1)} MiB`;
}

function fmtNumber(value) {
  return value === null || value === undefined ? "—" : Number(value).toLocaleString();
}

function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const value = Number(seconds);
  if (value < 60) return `${value}s`;
  if (value < 3600) return `${Math.round(value / 60)}m`;
  if (value < 86400) return `${(value / 3600).toFixed(1)}h`;
  return `${(value / 86400).toFixed(1)}d`;
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function badge(text, tone = "neutral") {
  return node("span", `badge ${tone}`, titleCase(text));
}

function toneFor(value, map, fallback = "neutral") {
  return map[String(value)] || fallback;
}

function showError(message) {
  const alert = $("page-alert");
  alert.textContent = message;
  alert.hidden = false;
}

function hideError() {
  const alert = $("page-alert");
  alert.textContent = "";
  alert.hidden = true;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    ...options,
  });
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!response.ok) {
    const detail =
      body && body.detail
        ? typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail)
        : `${response.status} ${response.statusText}`;
    throw new Error(detail);
  }
  return body;
}

function setPill(stateName, label) {
  const pill = $("quality-pill");
  pill.className = `badge ${stateName}`;
  pill.textContent = label;
}

function tableMessage(tbody, columns, message) {
  clear(tbody);
  const row = document.createElement("tr");
  const cell = node("td", "muted", message);
  cell.colSpan = columns;
  row.append(cell);
  tbody.append(row);
}

function chips(container, items) {
  clear(container);
  for (const [label, value, tone] of items) {
    const chip = node("div", "quality-chip");
    chip.append(node("span", "quality-chip-label", label));
    chip.append(node("strong", `quality-chip-value ${tone || ""}`, value));
    container.append(chip);
  }
}

function windowQuery() {
  const hours = Math.max(1, Math.min(720, Number($("window-hours").value) || 24));
  const end = new Date();
  const start = new Date(end.getTime() - hours * 3600 * 1000);
  return `start=${encodeURIComponent(start.toISOString())}&end=${encodeURIComponent(end.toISOString())}`;
}

function renderOverview(overview) {
  state.overview = overview;
  const select = $("investigation-select");
  clear(select);
  if (!overview.investigations.length) {
    select.append(new Option("No investigations", ""));
    select.disabled = true;
    $("quality-scope-count").textContent = "0";
    $("quality-title").textContent = "No investigations";
    $("quality-description").textContent =
      "Create an investigation and import or collect evidence before evaluating quality.";
    return;
  }
  select.disabled = false;
  for (const investigation of overview.investigations) {
    select.append(
      new Option(
        `${investigation.name} · ${investigation.coverage_state}`,
        investigation.investigation_id,
      ),
    );
  }
  if (!overview.investigations.some((item) => item.investigation_id === state.investigationId)) {
    state.investigationId = overview.investigations[0].investigation_id;
  }
  select.value = state.investigationId;
  $("quality-scope-count").textContent = String(overview.investigations.length);
}

function renderSelectionSummary(item) {
  if (!item) return;
  $("quality-title").textContent = item.name;
  $("quality-description").textContent =
    `Coverage ${item.coverage_state.replaceAll("_", " ")} · ` +
    `${item.source_count} source(s) · ${item.registered_sources} in coverage inventory`;
  $("metric-coverage").textContent = String(item.reporting_sources + item.idle_sources);
  $("metric-coverage-detail").textContent =
    `${item.registered_sources} source(s) · ${item.unknown_sources} unknown/manual`;
  $("metric-gaps").textContent = fmtNumber(item.open_gaps);
  $("metric-uncertain").textContent = fmtNumber(item.timestamp_uncertain_events);
  $("metric-duplicates").textContent = fmtNumber(item.duplicate_events);
  $("metric-mismatch").textContent = fmtNumber(item.integrity_mismatched);
  $("metric-audit").textContent = fmtNumber(item.audit_events);
}

function renderCoverage(coverage) {
  const summary = coverage.summary;
  chips($("coverage-summary"), [
    ["Reporting", summary.reporting_sources, "positive"],
    ["Idle", summary.idle_sources, "neutral"],
    ["Not reporting", summary.not_reporting_sources, summary.not_reporting_sources ? "warning" : "neutral"],
    ["Error", summary.error_sources, summary.error_sources ? "danger" : "neutral"],
    ["Disabled", summary.disabled_sources, "neutral"],
    ["Unknown / manual", summary.unknown_sources, "caution"],
    ["Open gaps", summary.open_gaps, summary.open_gaps ? "warning" : "positive"],
    ["No events observed", summary.no_events_observed_sources, "neutral"],
  ]);

  const tbody = $("coverage-body");
  clear(tbody);
  if (!coverage.sources.length) {
    tableMessage(
      tbody,
      7,
      "No agent or source inventory. Manually uploaded evidence is reported as unknown coverage, not healthy coverage.",
    );
  }
  const stateTones = {
    reporting: "positive",
    idle: "neutral",
    not_reporting: "warning",
    error: "danger",
    disabled: "neutral",
    unknown: "caution",
  };
  for (const source of coverage.sources) {
    const row = document.createElement("tr");
    const name = node("td");
    name.append(node("strong", "", source.name));
    name.append(
      node(
        "div",
        "muted small",
        `${source.inventory_origin} · ${source.source_type}${source.agent_name ? ` · ${source.agent_name}` : ""}`,
      ),
    );
    row.append(name);

    const stateCell = node("td");
    stateCell.append(badge(source.coverage_state, stateTones[source.coverage_state] || "neutral"));
    if (source.collection_unavailable_reason) {
      stateCell.append(node("div", "muted small", source.collection_unavailable_reason));
    }
    stateCell.append(
      node(
        "div",
        "muted small",
        source.last_success_at ? `Last success ${fmtDate(source.last_success_at)}` : "No successful cycle observed",
      ),
    );
    row.append(stateCell);

    row.append(
      node(
        "td",
        "",
        `${fmtNumber(source.observed_cycles)} observed / ${fmtNumber(source.expected_cycles)} expected`,
      ),
    );
    row.append(node("td", source.missing_cycles ? "warning-text" : "", fmtNumber(source.missing_cycles)));
    row.append(
      node(
        "td",
        "",
        `${fmtBytes(source.bytes_expected)} / ${fmtBytes(source.bytes_received)}` +
          (source.bytes_missing ? ` · ${fmtBytes(source.bytes_missing)} missing` : ""),
      ),
    );
    row.append(
      node(
        "td",
        "",
        `${fmtNumber(source.events_observed)}${source.no_events_observed ? " · none" : ""}`,
      ),
    );
    row.append(
      node(
        "td",
        "",
        source.clock_offset_seconds === null
          ? "—"
          : `${source.clock_offset_seconds > 0 ? "+" : ""}${source.clock_offset_seconds}s (${source.clock_offset_source || "unknown"})`,
      ),
    );
    tbody.append(row);
  }

  const gapList = $("gap-list");
  clear(gapList);
  if (!coverage.gaps.length) {
    gapList.append(node("p", "muted small", "No collection gaps were derived in this window."));
  } else {
    for (const gap of coverage.gaps.slice(0, 20)) {
      const item = node("div", `quality-list-item gap-${gap.status}`);
      const heading = node("div", "quality-list-heading");
      heading.append(node("strong", "", titleCase(gap.reason)));
      heading.append(badge(gap.status, gap.status === "open" ? "warning" : "neutral"));
      heading.append(node("span", "muted small", `${gap.basis} basis`));
      item.append(heading);
      const target = gap.source_name || gap.agent_name || gap.scope;
      item.append(
        node(
          "p",
          "small",
          `${target} · ${fmtDate(gap.gap_start)} → ${gap.gap_end ? fmtDate(gap.gap_end) : "ongoing"}` +
            (gap.expected_interval_seconds
              ? ` · expected every ${fmtDuration(gap.expected_interval_seconds)}`
              : ""),
        ),
      );
      if (gap.detail && Object.keys(gap.detail).length) {
        const note = gap.detail.note || gap.detail.reason || "";
        if (note) item.append(node("p", "muted small", note));
        if (gap.detail.missing_bytes !== undefined) {
          item.append(node("p", "muted small", `Missing bytes: ${fmtBytes(gap.detail.missing_bytes)}`));
        }
      }
      gapList.append(item);
    }
    if (coverage.gaps.length > 20) {
      gapList.append(node("p", "muted small", `Showing 20 of ${coverage.gaps.length} gaps.`));
    }
  }
  $("coverage-window-note").textContent =
    `${fmtDate(coverage.window_start)} → ${fmtDate(coverage.window_end)}`;
  $("coverage-note").textContent = coverage.note;
}

function renderParsing(parsing) {
  const totals = parsing.totals;
  chips($("parsing-totals"), [
    ["Evidence files", fmtNumber(totals.evidence_files), ""],
    ["Records received", fmtNumber(totals.records_received), ""],
    ["Parsed", fmtNumber(totals.parsed_records), "positive"],
    ["Rejected", fmtNumber(totals.records_rejected), totals.records_rejected ? "warning" : ""],
    ["Missing required", fmtNumber(totals.missing_required_fields), totals.missing_required_fields ? "warning" : ""],
    ["Missing optional", fmtNumber(totals.missing_optional_fields), "neutral"],
    ["Timestamp flags", fmtNumber(totals.timestamp_flagged_records), totals.timestamp_flagged_records ? "caution" : ""],
    ["Ordering ties", fmtNumber(totals.ordering_tied_records), "neutral"],
    ["Unresolved ordering", fmtNumber(totals.ordering_unresolved_records), totals.ordering_unresolved_records ? "caution" : ""],
    ["Duplicates", fmtNumber(totals.duplicate_records), "neutral"],
    ["Issues recorded", fmtNumber(totals.issues_recorded), "neutral"],
    ["Issues suppressed", fmtNumber(totals.issues_suppressed), "neutral"],
  ]);
  $("parsing-note").textContent =
    `${parsing.evidence_with_issues} evidence file(s) with material issues · ` +
    `${parsing.evidence_without_parser} without parser output.`;

  const tbody = $("parsing-body");
  clear(tbody);
  if (!parsing.items.length) {
    tableMessage(tbody, 9, "No evidence files have been uploaded or collected yet.");
    return;
  }
  const statusTones = {
    parsed: "positive",
    parsed_with_issues: "warning",
    unsupported_format: "caution",
    failed: "danger",
  };
  for (const item of parsing.items) {
    const result = item.parsing_result;
    const row = document.createElement("tr");
    const file = node("td");
    file.append(node("strong", "", item.filename));
    file.append(node("div", "muted small", `${item.source_name} · ${fmtDate(item.received_at)}`));
    row.append(file);

    row.append(
      node(
        "td",
        "",
        result ? `${result.parser_name || "unknown"} ${result.parser_version || ""}` : "Not parsed",
      ),
    );
    const statusCell = node("td");
    statusCell.append(
      result
        ? badge(result.status, statusTones[result.status] || "neutral")
        : badge("no parser output", "caution"),
    );
    row.append(statusCell);

    row.append(
      node(
        "td",
        "",
        result
          ? `${fmtNumber(result.parsed_records)} / ${fmtNumber(result.records_rejected)} of ${fmtNumber(result.records_received)}`
          : "—",
      ),
    );
    row.append(node("td", result && result.missing_required_fields ? "warning-text" : "", result ? fmtNumber(result.missing_required_fields) : "—"));
    row.append(node("td", "", result ? fmtNumber(result.missing_optional_fields) : "—"));
    row.append(
      node(
        "td",
        result && result.timestamp_flagged_records ? "caution-text" : "",
        result ? fmtNumber(result.timestamp_flagged_records) : "—",
      ),
    );
    row.append(
      node(
        "td",
        "",
        result
          ? `${fmtNumber(result.ordering_tied_records)} ties · ${fmtNumber(result.ordering_unresolved_records)} unresolved`
          : "—",
      ),
    );
    row.append(node("td", "", result ? fmtNumber(result.duplicate_records) : "—"));
    tbody.append(row);
  }
}

function renderTimestamps(timestamps) {
  chips($("timestamp-summary"), [
    ["Total events", fmtNumber(timestamps.total_events), ""],
    ["UTC normalized", fmtNumber(timestamps.normalized_events), "positive"],
    ["Uncertain / unresolved", fmtNumber(timestamps.uncertain_events), timestamps.uncertain_events ? "caution" : "positive"],
    ["Clock offset recorded", fmtNumber(timestamps.clock_offset_events), "neutral"],
    ...Object.entries(timestamps.timestamp_status_counts).map(([status, count]) => [
      titleCase(status),
      fmtNumber(count),
      status === "normalized" ? "positive" : "caution",
    ]),
  ]);
  $("timestamp-rule").textContent = timestamps.timestamp_rule;
  $("ordering-rule").textContent = timestamps.ordering_rule;

  const samples = $("timestamp-samples");
  clear(samples);
  if (!timestamps.uncertain_samples.length) {
    samples.append(node("p", "muted small", "No uncertain timestamps in this investigation."));
    return;
  }
  for (const sample of timestamps.uncertain_samples) {
    const item = node("div", "quality-list-item");
    const heading = node("div", "quality-list-heading");
    heading.append(node("strong", "", sample.event_type));
    heading.append(badge(sample.timestamp_status, "caution"));
    if (sample.ordering_status !== "resolved") {
      heading.append(badge(`order: ${sample.ordering_status}`, "neutral"));
    }
    item.append(heading);
    item.append(
      node(
        "p",
        "small",
        `${sample.source_name} · ${sample.evidence_filename}:${sample.line_number} · ${fmtDate(sample.timestamp_utc)}`,
      ),
    );
    if (sample.original_timestamp_string) {
      item.append(node("p", "muted small", `Original: ${sample.original_timestamp_string}`));
    }
    if (sample.timestamp_detail) {
      item.append(node("p", "muted small", sample.timestamp_detail));
    }
    item.append(
      node(
        "p",
        "muted small",
        `Precision: ${sample.timestamp_precision || "unknown"} · Clock offset: ${
          sample.clock_offset_seconds === null
            ? "none"
            : `${sample.clock_offset_seconds}s${sample.clock_offset_applied ? " applied" : " recorded, not applied"}`
        }`,
      ),
    );
    samples.append(item);
  }
}

function renderDuplicates(duplicates) {
  chips($("duplicate-summary"), [
    ["Total events", fmtNumber(duplicates.total_events), ""],
    ["Unique", fmtNumber(duplicates.unique_events), "positive"],
    ["Duplicate / linked", fmtNumber(duplicates.duplicate_events), duplicates.duplicate_events ? "warning" : "neutral"],
    ["Groups", fmtNumber(duplicates.duplicate_groups), ""],
  ]);
  $("duplicate-note").textContent = duplicates.note;
  if (duplicates.last_reconciliation) {
    $("duplicate-note").textContent +=
      ` Last reconciliation: ${fmtDate(duplicates.last_reconciliation.completed_at || duplicates.last_reconciliation.started_at)}` +
      ` (${fmtNumber(duplicates.last_reconciliation.events_scanned)} scanned).`;
  }

  const list = $("duplicate-list");
  clear(list);
  if (!duplicates.groups.length) {
    list.append(node("p", "muted small", "No duplicate groups detected."));
    return;
  }
  for (const group of duplicates.groups) {
    const item = node("div", "quality-list-item");
    const heading = node("div", "quality-list-heading");
    heading.append(node("strong", "", group.canonical_event.event_type));
    heading.append(badge(`${group.event_count} linked`, "warning"));
    item.append(heading);
    const canonical = group.canonical_event;
    item.append(
      node(
        "p",
        "small",
        `Canonical #${canonical.event_id} · ${canonical.source_name} · ${canonical.evidence_filename}:${canonical.line_number} · ${fmtDate(canonical.timestamp_utc)}`,
      ),
    );
    for (const duplicate of group.duplicate_events) {
      item.append(
        node(
          "p",
          "muted small",
          `Duplicate #${duplicate.event_id} → #${duplicate.duplicate_of_event_id} · ${duplicate.source_name} · ${duplicate.evidence_filename}:${duplicate.line_number}`,
        ),
      );
    }
    list.append(item);
  }
}

function renderIntegrity(integrity) {
  chips($("integrity-summary"), [
    ["Evidence files", fmtNumber(integrity.evidence_count), ""],
    ["Verified", fmtNumber(integrity.verified_evidence), "positive"],
    ["Unverified", fmtNumber(integrity.unverified_evidence), integrity.unverified_evidence ? "caution" : ""],
    ["Mismatched", fmtNumber(integrity.mismatched_evidence), integrity.mismatched_evidence ? "danger" : "positive"],
    ["Missing", fmtNumber(integrity.missing_evidence), integrity.missing_evidence ? "danger" : "neutral"],
  ]);
  $("integrity-note").textContent = integrity.note;

  const tbody = $("integrity-body");
  clear(tbody);
  if (!integrity.items.length) {
    tableMessage(tbody, 5, "No evidence files loaded.");
    return;
  }
  const tones = { verified: "positive", unverified: "caution", mismatch: "danger", missing: "danger" };
  for (const evidence of integrity.items) {
    const row = document.createElement("tr");
    const file = node("td");
    file.append(node("strong", "", evidence.filename));
    file.append(
      node(
        "div",
        "muted small",
        `${fmtBytes(evidence.size_bytes)} · sha256 ${evidence.sha256.slice(0, 16)}…`,
      ),
    );
    row.append(file);
    const integrityCell = node("td");
    integrityCell.append(
      badge(evidence.integrity_status, tones[evidence.integrity_status] || "neutral"),
    );
    row.append(integrityCell);
    const checks = node("td");
    checks.append(node("div", "", fmtNumber(evidence.verification_count)));
    checks.append(node("div", "muted small", evidence.last_verification_source || "not checked"));
    row.append(checks);
    row.append(node("td", "", fmtDate(evidence.last_verified_at)));

    const actions = node("td", "quality-actions");
    const verify = node("button", "link-button", "Verify");
    verify.type = "button";
    verify.addEventListener("click", async () => {
      verify.disabled = true;
      try {
        await api(evidence.verify_url, { method: "POST" });
        await loadInvestigation(state.investigationId);
      } catch (error) {
        showError(`Verification failed: ${error.message}`);
        verify.disabled = false;
      }
    });
    const manifest = node("a", "link-button", "Manifest");
    manifest.href = evidence.manifest_url;
    manifest.target = "_blank";
    manifest.rel = "noopener";
    const download = node("a", "link-button", "Download");
    download.href = evidence.download_url;
    actions.append(verify, manifest, download);
    row.append(actions);
    tbody.append(row);
  }
}

function renderAudit(audit) {
  $("metric-audit").textContent = fmtNumber(audit.total);
  const list = $("audit-list");
  clear(list);
  if (!audit.items.length) {
    list.append(node("p", "muted small", "No audit events recorded for this investigation."));
    return;
  }
  for (const event of audit.items) {
    const item = node("div", "quality-list-item");
    const heading = node("div", "quality-list-heading");
    heading.append(node("strong", "", titleCase(event.event_type)));
    heading.append(badge(event.actor_type, "neutral"));
    item.append(heading);
    const target = event.evidence_filename ? ` · ${event.evidence_filename}` : "";
    item.append(
      node(
        "p",
        "small",
        `${fmtDate(event.occurred_at)}${target} · actor ${event.actor_detail || "unknown"}`,
      ),
    );
    if (event.detail && Object.keys(event.detail).length) {
      item.append(node("pre", "audit-detail", JSON.stringify(event.detail, null, 2)));
    }
    list.append(item);
  }
}

function renderAll(data) {
  renderSelectionSummary(data.overviewItem);
  renderCoverage(data.coverage);
  renderParsing(data.parsing);
  renderTimestamps(data.timestamps);
  renderDuplicates(data.duplicates);
  renderIntegrity(data.integrity);
  renderAudit(data.audit);

  $("metric-gaps-detail").textContent =
    `${data.coverage.summary.open_gaps} open · ${data.coverage.summary.closed_gaps} closed`;
  $("metric-uncertain-detail").textContent =
    `${fmtNumber(data.timestamps.uncertain_events)} of ${fmtNumber(data.timestamps.total_events)} events`;
  $("metric-duplicates-detail").textContent =
    `${fmtNumber(data.duplicates.duplicate_groups)} group(s) · linked, never deleted`;
  $("metric-mismatch-detail").textContent =
    `${fmtNumber(data.integrity.unverified_evidence)} unverified · ${fmtNumber(data.integrity.missing_evidence)} missing`;
  state.loadedAt = new Date();
  $("quality-updated").textContent = `Updated ${fmtDate(data.coverage.generated_at)}`;
}

async function loadInvestigation(investigationId) {
  if (!investigationId) return;
  hideError();
  const overviewItem = state.overview?.investigations.find(
    (item) => item.investigation_id === investigationId,
  );
  renderSelectionSummary(overviewItem);
  $("quality-updated").textContent = "Loading…";
  const base = `/api/quality/investigations/${investigationId}`;
  try {
    const coverageQuery = windowQuery();
    const [coverage, parsing, timestamps, integrity, duplicates, audit] = await Promise.all([
      api(`${base}/coverage?${coverageQuery}`),
      api(`${base}/parsing?limit=200`),
      api(`${base}/timestamps?sample_limit=50`),
      api(`${base}/integrity`),
      api(`${base}/duplicates?group_limit=50`),
      api(`${base}/audit?limit=100`),
    ]);
    renderAll({ overviewItem, coverage, parsing, timestamps, integrity, duplicates, audit });
  } catch (error) {
    setPill("danger", "quality unavailable");
    showError(`Could not load evidence quality: ${error.message}`);
    $("quality-updated").textContent = "Load failed";
  }
}

async function loadOverview({ preserveSelection = true } = {}) {
  hideError();
  setPill("neutral", "checking quality");
  if (preserveSelection) state.investigationId = $("investigation-select").value || state.investigationId;
  try {
    const overview = await api("/api/quality/overview");
    renderOverview(overview);
    if (!overview.investigations.length) {
      setPill("caution", "no investigations");
      return;
    }
    const selected = $("investigation-select").value;
    state.investigationId = selected;
    await loadInvestigation(selected);
    const hasProblems =
      (overview.totals.integrity_mismatched || 0) > 0 || (overview.totals.open_gaps || 0) > 0;
    setPill(
      hasProblems ? "warning" : "positive",
      hasProblems ? "quality attention needed" : "quality evaluated",
    );
  } catch (error) {
    setPill("danger", "quality unavailable");
    showError(`Could not load quality overview: ${error.message}`);
  }
}

function bindEvents() {
  $("investigation-select").addEventListener("change", async (event) => {
    state.investigationId = event.target.value;
    await loadInvestigation(state.investigationId);
  });
  $("window-hours").addEventListener("change", async () => {
    if (state.investigationId) await loadInvestigation(state.investigationId);
  });
  $("refresh-button").addEventListener("click", () => loadOverview());
  $("reconcile-button").addEventListener("click", async () => {
    if (!state.investigationId) return;
    const button = $("reconcile-button");
    button.disabled = true;
    hideError();
    try {
      const result = await api(
        `/api/quality/investigations/${state.investigationId}/reconcile`,
        { method: "POST" },
      );
      await loadInvestigation(state.investigationId);
      $("quality-updated").textContent =
        `Reconciled ${fmtNumber(result.total_events)} events · ` +
        `${fmtNumber(result.duplicate_events)} duplicates in ${fmtNumber(result.duplicate_groups)} group(s)`;
    } catch (error) {
      showError(`Reconciliation failed: ${error.message}`);
    } finally {
      button.disabled = false;
    }
  });
}

bindEvents();
loadOverview({ preserveSelection: false });
