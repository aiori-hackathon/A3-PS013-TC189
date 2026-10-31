const API = "/api";
const STORAGE_KEY = "cybertrace.currentInvestigation";

const state = {
  investigations: [],
  currentId: null,
  summary: null,
  evidence: [],
  timeline: [],
  timelineTotal: 0,
  timelineOffset: 0,
  timelineLimit: 100,
};

const EVENT_LABELS = {
  auth_success: "Auth success",
  auth_failure: "Auth failure",
  auth_invalid_user: "Invalid user",
  session_opened: "Session opened",
  session_closed: "Session closed",
  sudo_command: "Sudo command",
  auth_disconnect: "Disconnect",
  auth_other: "Other auth",
  http_request: "HTTP request",
};

const SOURCE_LABELS = {
  linux_auth: "Linux auth",
  web_access: "Web access",
  unknown: "Unknown",
};

const EVIDENCE_TONE = {
  parsed: "good",
  parsed_with_issues: "warn",
  failed: "bad",
  received: "info",
};

const PARSING_TONE = {
  completed: "good",
  partial: "warn",
  failed: "bad",
};

const TIMESTAMP_TONE = {
  normalized: "good",
  missing_timezone: "warn",
  missing_year: "warn",
  ambiguous: "warn",
  invalid: "bad",
};

const $ = (selector) => document.querySelector(selector);
let toastTimer = null;

function createElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function badge(text, tone = "neutral") {
  return createElement("span", `badge ${tone}`, String(text).replaceAll("_", " "));
}

function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function toast(message, type = "info") {
  const node = $("#toast");
  node.textContent = message;
  node.className = `toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.className = "toast";
  }, type === "error" ? 8000 : 4500);
}

function errorMessage(error) {
  if (error && error.detail) {
    if (typeof error.detail === "string") return error.detail;
    if (error.detail.message) return error.detail.message;
    return JSON.stringify(error.detail);
  }
  return error?.message || "Unexpected error";
}

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, options);
  const text = await response.text();
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = text; }
  }
  if (!response.ok) {
    const error = new Error(`HTTP ${response.status}`);
    error.status = response.status;
    error.detail = payload?.detail ?? payload;
    throw error;
  }
  return payload;
}

async function withBusy(button, action) {
  if (!button) return action();
  button.disabled = true;
  button.classList.add("loading");
  try {
    return await action();
  } finally {
    button.classList.remove("loading");
    button.disabled = false;
  }
}

function formatUtc(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function formatLocalInputToIso(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("Invalid date filter.");
  return date.toISOString();
}

function typeLabel(value) {
  return EVENT_LABELS[value] || String(value || "unknown").replaceAll("_", " ");
}

function currentInvestigation() {
  return state.investigations.find((item) => item.id === state.currentId) || null;
}

async function init() {
  bindEvents();
  await checkHealth();
  await loadInvestigations();
  if (state.currentId) {
    await loadWorkspace();
  } else {
    renderEmptyWorkspace();
  }
}

function bindEvents() {
  $("#create-investigation-form").addEventListener("submit", onCreateInvestigation);
  $("#upload-form").addEventListener("submit", onUpload);
  $("#upload-file").addEventListener("change", () => {
    const file = $("#upload-file").files[0];
    $("#file-name").textContent = file
      ? `${file.name} · ${(file.size / 1024).toFixed(1)} KB`
      : "No file selected · max 50 MB · UTF-8 text logs";
  });
  $("#timeline-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    state.timelineOffset = 0;
    loadTimeline();
  });
  $("#filter-reset").addEventListener("click", () => {
    $("#timeline-filters").reset();
    $("#filter-unknown").checked = true;
    state.timelineOffset = 0;
    loadTimeline();
  });
  $("#timeline-prev").addEventListener("click", () => {
    state.timelineOffset = Math.max(0, state.timelineOffset - state.timelineLimit);
    loadTimeline();
  });
  $("#timeline-next").addEventListener("click", () => {
    if (state.timelineOffset + state.timelineLimit < state.timelineTotal) {
      state.timelineOffset += state.timelineLimit;
      loadTimeline();
    }
  });
  $("#refresh-button").addEventListener("click", async (event) => {
    await withBusy(event.currentTarget, async () => {
      state.timelineOffset = 0;
      await loadInvestigations(false);
      await loadWorkspace();
      toast("Workspace refreshed.", "success");
    });
  });
  document.querySelectorAll("[data-close-dialog]").forEach((button) => {
    button.addEventListener("click", () => {
      document.getElementById(button.dataset.closeDialog)?.close();
    });
  });
  document.querySelectorAll("dialog.drawer").forEach((dialog) => {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  });
}

async function checkHealth() {
  const pill = $("#health-pill");
  try {
    const response = await fetch(`${API}/health`);
    const payload = await response.json();
    if (response.ok) {
      pill.textContent = `system online · v${payload.version}`;
      pill.className = "badge good";
    } else {
      pill.textContent = `degraded · ${payload.database}/${payload.schema_status}/${payload.storage}`;
      pill.className = "badge warn";
    }
  } catch {
    pill.textContent = "system unreachable";
    pill.className = "badge bad";
  }
}

async function loadInvestigations(keepSelection = true) {
  const list = await api("/investigations");
  state.investigations = list;
  $("#investigation-count").textContent = String(list.length);

  if (keepSelection) {
    const stored = state.currentId || localStorage.getItem(STORAGE_KEY);
    const exists = list.some((item) => item.id === stored);
    state.currentId = exists ? stored : (list[0]?.id || null);
  } else if (!list.some((item) => item.id === state.currentId)) {
    state.currentId = list[0]?.id || null;
  }
  if (state.currentId) localStorage.setItem(STORAGE_KEY, state.currentId);
  else localStorage.removeItem(STORAGE_KEY);

  renderInvestigationList();
  renderInvestigationHeader();
}

function renderInvestigationList() {
  const listNode = $("#investigation-list");
  clearNode(listNode);
  if (!state.investigations.length) {
    listNode.append(createElement("p", "muted small", "No investigations yet. Create one to begin."));
    return;
  }
  for (const investigation of state.investigations) {
    const button = createElement("button", "investigation-item");
    button.type = "button";
    if (investigation.id === state.currentId) button.classList.add("active");
    const name = createElement("strong", null, investigation.name);
    const meta = createElement(
      "span",
      null,
      `${investigation.evidence_count} files · ${investigation.event_count} events`
    );
    button.append(name, meta);
    button.addEventListener("click", () => selectInvestigation(investigation.id));
    listNode.append(button);
  }
}

function renderInvestigationHeader() {
  const investigation = currentInvestigation();
  if (!investigation) {
    $("#investigation-title").textContent = "No investigation selected";
    $("#investigation-meta").textContent = "Create or select an investigation to begin.";
    $("#upload-submit").disabled = true;
    return;
  }
  $("#investigation-title").textContent = investigation.name;
  const created = formatUtc(investigation.created_at);
  const description = investigation.description ? ` · ${investigation.description}` : "";
  $("#investigation-meta").textContent = `Opened ${created}${description}`;
  $("#upload-submit").disabled = false;
}

async function selectInvestigation(id) {
  if (state.currentId === id) return;
  state.currentId = id;
  state.timelineOffset = 0;
  localStorage.setItem(STORAGE_KEY, id);
  renderInvestigationList();
  renderInvestigationHeader();
  await loadWorkspace();
}

async function loadWorkspace() {
  if (!state.currentId) {
    renderEmptyWorkspace();
    return;
  }
  await Promise.allSettled([loadSummary(), loadEvidence(), loadTimeline()]);
}

function renderEmptyWorkspace() {
  state.summary = null;
  state.evidence = [];
  state.timeline = [];
  state.timelineTotal = 0;
  renderSummary();
  $("#evidence-body").replaceChildren(
    Object.assign(document.createElement("tr"), {
      innerHTML: '<td colspan="5" class="empty-cell">No investigation selected.</td>',
    })
  );
  $("#timeline-body").replaceChildren(
    Object.assign(document.createElement("tr"), {
      innerHTML: '<td colspan="5" class="empty-cell">No investigation selected.</td>',
    })
  );
  $("#timeline-count-label").textContent = "0 events";
  $("#evidence-count-label").textContent = "0 files";
  $("#timeline-page-label").textContent = "0–0 of 0";
  $("#timeline-prev").disabled = true;
  $("#timeline-next").disabled = true;
}

async function loadSummary() {
  try {
    state.summary = await api(`/investigations/${state.currentId}/summary`);
    renderSummary();
  } catch (error) {
    toast(errorMessage(error), "error");
  }
}

function renderSummary() {
  const summary = state.summary;
  const uncertain = summary
    ? Object.entries(summary.timestamp_status_counts || {})
        .filter(([key]) => key !== "normalized")
        .reduce((total, [, value]) => total + value, 0)
    : 0;
  $("#metric-evidence").textContent = summary?.evidence_files ?? 0;
  $("#metric-sources").textContent = `${summary?.sources ?? 0} sources`;
  $("#metric-events").textContent = summary?.events ?? 0;
  $("#metric-lines").textContent = `${summary?.total_lines ?? 0} lines · ${summary?.parsed_records ?? 0} parsed`;
  $("#metric-gaps").textContent = (summary?.malformed_records ?? 0) + (summary?.unsupported_records ?? 0);
  $("#metric-gap-detail").textContent = `${summary?.malformed_records ?? 0} malformed · ${summary?.unsupported_records ?? 0} unsupported`;
  $("#metric-uncertain").textContent = uncertain;
  $("#metric-uncertain-detail").textContent = `${summary?.timestamp_flagged_records ?? 0} flagged during parsing`;
  $("#metric-verified").textContent = summary?.hashes_verified ?? 0;
  $("#metric-hash-detail").textContent = `${summary?.hashes_unverified ?? 0} unverified · ${summary?.hashes_mismatched ?? 0} mismatched`;
  $("#metric-issues").textContent = summary?.issues_total ?? 0;
  const issueTypes = Object.entries(summary?.issue_counts_by_type || {});
  $("#metric-issue-detail").textContent = issueTypes.length
    ? issueTypes.slice(0, 2).map(([key, value]) => `${key.replaceAll("_", " ")} ${value}`).join(" · ")
    : "no issues recorded";
}

async function loadEvidence() {
  try {
    const payload = await api(
      `/evidence?investigation_id=${encodeURIComponent(state.currentId)}&limit=200`
    );
    state.evidence = payload.items;
    renderEvidence(payload.total);
  } catch (error) {
    toast(errorMessage(error), "error");
  }
}

function renderEvidence(total) {
  const body = $("#evidence-body");
  clearNode(body);
  $("#evidence-count-label").textContent = `${total} file${total === 1 ? "" : "s"}`;
  if (!state.evidence.length) {
    const row = document.createElement("tr");
    const cell = createElement("td", "empty-cell", "No evidence collected yet.");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
    return;
  }

  for (const evidence of state.evidence) {
    const row = document.createElement("tr");

    const fileCell = document.createElement("td");
    fileCell.append(createElement("div", "cell-title", evidence.original_filename));
    const hash = createElement(
      "div",
      "cell-sub mono truncate",
      evidence.sha256.slice(0, 20) + "…"
    );
    hash.title = `SHA-256: ${evidence.sha256}`;
    fileCell.append(hash);
    if (evidence.duplicate_of_evidence_id) {
      fileCell.append(badge("duplicate", "warn"));
    }

    const sourceCell = document.createElement("td");
    sourceCell.append(createElement("div", "cell-title", evidence.source.name));
    const sourceLine = createElement("div", "cell-sub");
    sourceLine.append(badge(SOURCE_LABELS[evidence.source_type] || evidence.source_type, "neutral"));
    if (evidence.source.hostname) sourceLine.append(document.createTextNode(` ${evidence.source.hostname}`));
    sourceCell.append(sourceLine);

    const collectedCell = document.createElement("td");
    collectedCell.append(createElement("div", "mono", formatUtc(evidence.collected_at)));

    const parsingCell = document.createElement("td");
    parsingCell.append(badge(evidence.status, EVIDENCE_TONE[evidence.status] || "neutral"));
    const result = evidence.parsing_result;
    if (result) {
      parsingCell.append(
        createElement(
          "div",
          "cell-sub",
          `${result.parsed_records} parsed · ${result.malformed_records} malformed · ${result.timestamp_flagged_records} time flags`
        )
      );
      if (result.issues_suppressed) {
        parsingCell.append(createElement("div", "cell-sub", `${result.issues_suppressed} issues suppressed`));
      }
      if (result.fatal_error) {
        const fatal = createElement("div", "cell-sub", result.fatal_error);
        fatal.title = result.fatal_error;
        parsingCell.append(fatal);
      }
    }

    const actionsCell = document.createElement("td");
    const actions = createElement("div", "actions");
    const detailsButton = createElement("button", "secondary mini-button", "Details");
    detailsButton.type = "button";
    detailsButton.addEventListener("click", () => openEvidenceDialog(evidence));
    const verifyButton = createElement("button", "secondary mini-button", "Verify hash");
    verifyButton.type = "button";
    verifyButton.addEventListener("click", () =>
      withBusy(verifyButton, async () => {
        try {
          const result = await api(`/evidence/${evidence.id}/verify`, { method: "POST" });
          toast(
            result.match
              ? `Hash verified: ${evidence.original_filename} is unchanged.`
              : `HASH MISMATCH: ${evidence.original_filename} changed after collection.`,
            result.match ? "success" : "error"
          );
          await Promise.all([loadSummary(), loadEvidence()]);
        } catch (error) {
          toast(errorMessage(error), "error");
        }
      })
    );
    const reparseButton = createElement("button", "secondary mini-button", "Reparse");
    reparseButton.type = "button";
    reparseButton.addEventListener("click", () =>
      withBusy(reparseButton, async () => {
        if (!window.confirm("Reparse this file from the preserved original? Derived events will be rebuilt.")) {
          return;
        }
        try {
          await api(`/evidence/${evidence.id}/reparse`, { method: "POST" });
          toast("Evidence reparsed after hash verification.", "success");
          state.timelineOffset = 0;
          await loadWorkspace();
          await loadInvestigations(false);
        } catch (error) {
          toast(errorMessage(error), "error");
          await loadEvidence();
        }
      })
    );
    const downloadLink = createElement("a", "secondary mini-button", "Download");
    downloadLink.href = evidence.download_url || `${API}/evidence/${evidence.id}/download`;
    downloadLink.target = "_blank";
    downloadLink.rel = "noopener";
    actions.append(detailsButton, verifyButton, reparseButton, downloadLink);
    actionsCell.append(actions);

    row.append(fileCell, sourceCell, collectedCell, parsingCell, actionsCell);
    body.append(row);
  }
}

async function openEvidenceDialog(evidence) {
  const dialog = $("#evidence-dialog");
  const body = $("#dialog-evidence-body");
  $("#dialog-evidence-title").textContent = evidence.original_filename;
  clearNode(body);
  if (!dialog.open) dialog.showModal();

  body.append(badge(evidence.status, EVIDENCE_TONE[evidence.status] || "neutral"));
  const result = evidence.parsing_result;
  if (result?.fatal_error) {
    body.append(createElement("div", "notice bad", result.fatal_error));
  }

  const grid = createElement("div", "detail-grid");
  grid.append(
    detailBlock("Source", evidence.source.name),
    detailBlock("Source type", SOURCE_LABELS[evidence.source_type] || evidence.source_type),
    detailBlock("SHA-256", evidence.sha256, true),
    detailBlock("Collected", formatUtc(evidence.collected_at)),
    detailBlock("Timezone hint", evidence.timezone_hint || "none supplied"),
    detailBlock("Default year", evidence.default_year || "none supplied"),
    detailBlock("Parser", evidence.parser_name || "not selected"),
    detailBlock("Size", `${evidence.size_bytes} bytes`)
  );
  body.append(grid);

  if (result) {
    body.append(createElement("p", "section-label", "Parsing counters"));
    const counters = createElement("div", "detail-grid");
    counters.append(
      detailBlock("Total lines", result.total_lines),
      detailBlock("Parsed", result.parsed_records),
      detailBlock("Malformed", result.malformed_records),
      detailBlock("Unsupported", result.unsupported_records),
      detailBlock("Timestamp flags", result.timestamp_flagged_records),
      detailBlock("Encoding errors", result.encoding_error_lines),
      detailBlock("Issues recorded", result.issues_recorded),
      detailBlock("Issues suppressed", result.issues_suppressed)
    );
    body.append(counters);
  }

  const statusSection = createElement("div");
  body.append(statusSection);
  statusSection.append(createElement("p", "section-label", "Issue breakdown"));

  const issueSection = createElement("div");
  body.append(issueSection);
  issueSection.append(createElement("p", "section-label", "Recorded issues (newest cap: 200)"));
  issueSection.append(createElement("p", "muted small", "Loading issues…"));

  const actions = createElement("div", "actions");
  const download = createElement("a", "secondary mini-button", "Download original");
  download.href = evidence.download_url;
  download.target = "_blank";
  download.rel = "noopener";
  actions.append(download);
  body.append(actions);

  try {
    const [status, issues] = await Promise.all([
      api(`/evidence/${evidence.id}/status`),
      api(`/evidence/${evidence.id}/issues?limit=200`),
    ]);

    clearNode(statusSection);
    statusSection.append(createElement("p", "section-label", "Issue breakdown"));
    const chips = createElement("div", "inline-chips");
    const issueEntries = Object.entries(status.issue_counts_by_type || {});
    if (!issueEntries.length) {
      chips.append(createElement("span", "muted small", "No issue types recorded."));
    }
    for (const [issueType, count] of issueEntries) {
      chips.append(badge(`${issueType.replaceAll("_", " ")} ${count}`, "warn"));
    }
    statusSection.append(chips);

    clearNode(issueSection);
    issueSection.append(
      createElement(
        "p",
        "section-label",
        `Recorded issues (showing ${issues.items.length} of ${issues.total})`
      )
    );
    if (!issues.items.length) {
      issueSection.append(createElement("p", "muted small", "No issues stored for this file."));
    } else {
      const list = createElement("div", "issue-list");
      for (const issue of issues.items) {
        const card = createElement("article", `issue-card ${issue.severity}`);
        const head = createElement("div", "issue-head");
        const left = createElement("div");
        left.append(badge(issue.severity, issue.severity === "error" ? "bad" : "warn"));
        left.append(document.createTextNode(` ${issue.issue_type.replaceAll("_", " ")}`));
        head.append(left, createElement("span", "mono muted", issue.line_number ? `line ${issue.line_number}` : "file-level"));
        card.append(head, createElement("p", null, issue.message));
        const rawText = issue.raw_line
          ? issue.raw_line
          : "Line-level raw content is not available for this file-level issue.";
        const details = createElement("details");
        details.append(createElement("summary", null, "Original line / context"));
        details.append(createElement("pre", null, rawText));
        card.append(details);
        list.append(card);
      }
      issueSection.append(list);
    }
  } catch (error) {
    toast(errorMessage(error), "error");
  }
}

function detailBlock(label, value, mono = false) {
  const block = createElement("div", "detail");
  block.append(createElement("span", null, label));
  const strong = createElement(mono ? "code" : "strong", null, value ?? "—");
  block.append(strong);
  return block;
}

async function onUpload(event) {
  event.preventDefault();
  if (!state.currentId) {
    toast("Create or select an investigation first.", "error");
    return;
  }
  const file = $("#upload-file").files[0];
  if (!file) {
    toast("Select a log file to import.", "error");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);
  formData.append("source_type", $("#upload-source-type").value);
  const fields = {
    source_name: $("#upload-source-name").value.trim(),
    hostname: $("#upload-hostname").value.trim(),
    timezone_hint: $("#upload-timezone").value.trim(),
    default_year: $("#upload-year").value,
    collected_at: $("#upload-collected-at").value,
    notes: $("#upload-notes").value.trim(),
    allow_duplicate: $("#upload-allow-duplicate").checked,
  };
  for (const [key, value] of Object.entries(fields)) {
    if (value === "" || value === null || value === undefined || value === false) continue;
    if (key === "collected_at") {
      try {
        formData.append(key, formatLocalInputToIso(value));
      } catch (error) {
        toast(error.message, "error");
        return;
      }
    } else {
      formData.append(key, String(value));
    }
  }
  if ($("#upload-allow-duplicate").checked) {
    formData.append("allow_duplicate", "true");
  }

  const submit = $("#upload-submit");
  await withBusy(submit, async () => {
    try {
      const evidence = await api(
        `/investigations/${state.currentId}/evidence`,
        { method: "POST", body: formData }
      );
      const result = evidence.parsing_result;
      if (evidence.status === "failed") {
        toast(
          `Evidence preserved and hashed, but parsing failed. ${result?.fatal_error || "Open Details to inspect issues."}`,
          "error"
        );
      } else {
        toast(
          `Imported ${evidence.original_filename}: ${result?.parsed_records ?? 0} events, ${result?.malformed_records ?? 0} malformed, ${result?.timestamp_flagged_records ?? 0} timestamp flags.`,
          "success"
        );
      }
      $("#upload-form").reset();
      $("#file-name").textContent = "No file selected · max 50 MB · UTF-8 text logs";
      state.timelineOffset = 0;
      await loadInvestigations(false);
      await loadWorkspace();
    } catch (error) {
      const detail = error.detail;
      if (detail && detail.code === "duplicate_evidence") {
        toast(`${detail.message} Existing evidence: ${detail.existing_evidence_id}`, "error");
      } else {
        toast(errorMessage(error), "error");
      }
    }
  });
}

async function onCreateInvestigation(event) {
  event.preventDefault();
  const name = $("#new-investigation-name").value.trim();
  if (!name) {
    toast("Investigation name is required.", "error");
    return;
  }
  const description = $("#new-investigation-description").value.trim();
  const button = event.currentTarget.querySelector("button[type='submit']");
  await withBusy(button, async () => {
    try {
      const investigation = await api("/investigations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, description: description || null }),
      });
      state.currentId = investigation.id;
      localStorage.setItem(STORAGE_KEY, investigation.id);
      $("#create-investigation-form").reset();
      toast("Investigation created.", "success");
      await loadInvestigations(false);
      state.timelineOffset = 0;
      await loadWorkspace();
    } catch (error) {
      toast(errorMessage(error), "error");
    }
  });
}

function currentFilters() {
  const params = new URLSearchParams();
  params.set("investigation_id", state.currentId);
  params.set("limit", String(state.timelineLimit));
  params.set("offset", String(state.timelineOffset));
  params.set("include_unknown_time", $("#filter-unknown").checked ? "true" : "false");
  params.set("sort", $("#filter-sort").value);

  const q = $("#filter-q").value.trim();
  const start = $("#filter-start").value;
  const end = $("#filter-end").value;
  const sourceType = $("#filter-source-type").value;
  const eventType = $("#filter-event-type").value;
  const hostname = $("#filter-hostname").value.trim();
  const timestampStatus = $("#filter-timestamp-status").value;

  if (q) params.set("q", q);
  if (start) params.set("start", formatLocalInputToIso(start));
  if (end) params.set("end", formatLocalInputToIso(end));
  if (sourceType) params.set("source_type", sourceType);
  if (eventType) params.set("event_type", eventType);
  if (hostname) params.set("hostname", hostname);
  if (timestampStatus) params.set("timestamp_status", timestampStatus);
  return params;
}

async function loadTimeline() {
  if (!state.currentId) {
    return;
  }
  try {
    const params = currentFilters();
    const payload = await api(`/timeline?${params.toString()}`);
    state.timeline = payload.items;
    state.timelineTotal = payload.total;
    renderTimeline();
  } catch (error) {
    toast(errorMessage(error), "error");
  }
}

function renderTimeline() {
  const body = $("#timeline-body");
  clearNode(body);
  $("#timeline-count-label").textContent = `${state.timelineTotal} event${state.timelineTotal === 1 ? "" : "s"}`;

  if (!state.timeline.length) {
    const row = document.createElement("tr");
    const cell = createElement("td", "empty-cell", "No events match the current filters.");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
  } else {
    for (const event of state.timeline) {
      const row = document.createElement("tr");
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute("aria-label", `Open event ${typeLabel(event.event_type)}`);
      row.addEventListener("click", () => openEventDialog(event));
      row.addEventListener("keydown", (keyboardEvent) => {
        if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
          keyboardEvent.preventDefault();
          openEventDialog(event);
        }
      });

      const timeCell = document.createElement("td");
      if (event.timestamp_utc) {
        timeCell.append(createElement("div", "mono", formatUtc(event.timestamp_utc)));
      } else {
        timeCell.append(badge("unresolved", "warn"));
      }
      if (event.timestamp_status !== "normalized") {
        const statusLine = createElement("div", "cell-sub");
        statusLine.append(badge(event.timestamp_status, TIMESTAMP_TONE[event.timestamp_status] || "warn"));
        timeCell.append(statusLine);
      }
      if (event.original_timestamp_string) {
        const original = createElement("div", "cell-sub", event.original_timestamp_string);
        original.title = event.timestamp_detail || "";
        timeCell.append(original);
      }

      const sourceCell = document.createElement("td");
      sourceCell.append(createElement("div", "cell-title", event.source_name));
      const sourceMeta = createElement("div", "cell-sub");
      sourceMeta.append(badge(SOURCE_LABELS[event.source_type] || event.source_type, "neutral"));
      if (event.hostname) sourceMeta.append(document.createTextNode(` ${event.hostname}`));
      sourceCell.append(sourceMeta);

      const eventCell = document.createElement("td");
      eventCell.append(badge(typeLabel(event.event_type), event.event_type.startsWith("auth") ? "info" : "teal"));
      eventCell.append(createElement("div", "cell-sub", event.event_category.replaceAll("_", " ")));

      const detailCell = document.createElement("td");
      if (event.username || event.source_ip) {
        const chips = createElement("div", "cell-sub");
        if (event.username) chips.append(badge(event.username, "neutral"));
        if (event.source_ip) chips.append(badge(event.source_ip, "neutral"));
        detailCell.append(chips);
      }
      let summary = event.message || "";
      if (event.event_type === "http_request") {
        summary = `${event.http_method || "?"} ${event.http_path || "?"} · ${event.http_status ?? "?"}`;
      }
      const summaryNode = createElement("div", "cell-sub truncate", summary);
      summaryNode.title = summary;
      detailCell.append(summaryNode);

      const traceCell = document.createElement("td");
      const fileLabel = createElement("div", "mono truncate", event.evidence_filename);
      fileLabel.title = event.evidence_filename;
      traceCell.append(fileLabel);
      traceCell.append(
        createElement("div", "cell-sub", `line ${event.line_number} · byte ${event.byte_offset}`)
      );

      row.append(timeCell, sourceCell, eventCell, detailCell, traceCell);
      body.append(row);
    }
  }

  const from = state.timeline.length ? state.timelineOffset + 1 : 0;
  const to = state.timelineOffset + state.timeline.length;
  $("#timeline-page-label").textContent = `${from}–${to} of ${state.timelineTotal}`;
  $("#timeline-prev").disabled = state.timelineOffset === 0;
  $("#timeline-next").disabled =
    state.timelineOffset + state.timelineLimit >= state.timelineTotal;
}

function openEventDialog(event) {
  const dialog = $("#event-dialog");
  const body = $("#dialog-event-body");
  $("#dialog-event-title").textContent = `${typeLabel(event.event_type)} · line ${event.line_number}`;
  clearNode(body);
  if (!dialog.open) dialog.showModal();

  const header = createElement("div", "inline-chips");
  header.append(badge(SOURCE_LABELS[event.source_type] || event.source_type, "neutral"));
  header.append(badge(event.event_category, "info"));
  header.append(badge(event.timestamp_status, TIMESTAMP_TONE[event.timestamp_status] || "neutral"));
  body.append(header);

  if (event.timestamp_status !== "normalized") {
    body.append(
      createElement(
        "div",
        "notice",
        event.timestamp_detail || "This event has no trustworthy UTC timestamp."
      )
    );
  }

  const grid = createElement("div", "detail-grid");
  grid.append(
    detailBlock("Normalized UTC", formatUtc(event.timestamp_utc), true),
    detailBlock("Original timestamp", event.original_timestamp_string || "—", true),
    detailBlock("Original timezone", event.original_timezone || "unknown"),
    detailBlock("Timestamp status", event.timestamp_status),
    detailBlock("Hostname", event.hostname || "—"),
    detailBlock("Client / source IP", event.source_ip || "—"),
    detailBlock("Username", event.username || "—"),
    detailBlock("Process", event.process ? `${event.process}${event.pid ? ` [${event.pid}]` : ""}` : "—"),
    detailBlock("Evidence file", event.evidence_filename, true),
    detailBlock("Trace location", `line ${event.line_number} · byte ${event.byte_offset}`, true),
    detailBlock("Source", event.source_name),
    detailBlock("Event type", event.event_type)
  );
  if (event.event_type === "http_request") {
    grid.append(
      detailBlock("HTTP method", event.http_method || "—"),
      detailBlock("HTTP path", event.http_path || "—"),
      detailBlock("HTTP status", event.http_status ?? "—"),
      detailBlock("Response bytes", event.http_bytes ?? "—"),
      detailBlock("Referer", event.http_referer || "—"),
      detailBlock("User agent", event.http_user_agent || "—")
    );
  }
  body.append(grid);

  if (event.timestamp_detail) {
    body.append(createElement("p", "section-label", "Timestamp note"));
    body.append(createElement("p", "muted small", event.timestamp_detail));
  }

  body.append(createElement("p", "section-label", "Raw source line"));
  body.append(createElement("pre", "raw", event.raw_line));

  body.append(createElement("p", "section-label", "Structured metadata"));
  body.append(createElement("pre", "raw", JSON.stringify(event.extra || {}, null, 2)));

  const links = createElement("div", "actions");
  const download = createElement("a", "secondary mini-button", "Download original evidence");
  download.href = event.evidence_download_url;
  download.target = "_blank";
  download.rel = "noopener";
  links.append(download);
  body.append(links);
}

init().catch((error) => toast(errorMessage(error), "error"));
