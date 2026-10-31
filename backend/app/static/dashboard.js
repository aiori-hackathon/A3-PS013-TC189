"use strict";

const API = "/api";
const STORAGE_KEY = "cybertrace.currentInvestigation";

const EVENT_LABELS = {
  auth_success: "Auth success",
  auth_failure: "Auth failure",
  auth_invalid_user: "Invalid user",
  session_opened: "Session opened",
  session_closed: "Session closed",
  sudo_command: "Sudo command",
  auth_disconnect: "Disconnect",
  auth_other: "Other auth record",
  http_request: "HTTP request",
};

const SOURCE_TYPE_LABELS = {
  linux_auth: "Linux authentication",
  web_access: "Web access",
  unknown: "Unknown",
};

const COVERAGE_TONES = {
  reporting: "good",
  idle: "neutral",
  not_reporting: "warn",
  error: "bad",
  disabled: "neutral",
  unknown: "info",
};

const AGENT_HEALTH_TONES = {
  online: "good",
  stale: "warn",
  never_seen: "warn",
  disabled: "neutral",
};

const INTEGRITY_TONES = {
  verified: "good",
  unverified: "info",
  mismatch: "bad",
  missing: "bad",
};

const PARSING_TONES = {
  completed: "good",
  partial: "warn",
  failed: "bad",
};

const TIMESTAMP_TONES = {
  normalized: "good",
  missing_timezone: "warn",
  missing_year: "warn",
  missing_timestamp: "warn",
  ambiguous: "warn",
  invalid: "bad",
};

const ORDERING_TONES = {
  ordered: "good",
  tied: "warn",
  unresolved: "warn",
};

const EVENT_TONES = {
  auth_success: "good",
  auth_failure: "bad",
  auth_invalid_user: "bad",
  session_opened: "info",
  session_closed: "info",
  sudo_command: "warn",
  auth_disconnect: "neutral",
  auth_other: "neutral",
  http_request: "info",
};

const state = {
  investigations: [],
  currentId: null,
  summary: null,
  sources: [],
  coverage: null,
  parsing: null,
  timestamps: null,
  integrity: null,
  correlations: [],
  correlationEventIds: new Set(),
  timeline: [],
  timelineTotal: 0,
  timelineOffset: 0,
  timelineLimit: 50,
  requestToken: 0,
  eventRequestToken: 0,
};

const $ = (selector) => document.querySelector(selector);
let toastTimer = null;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

function clear(element) {
  element.replaceChildren();
}

function badge(text, tone = "neutral") {
  return node("span", `badge ${tone}`, titleCase(text));
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function typeLabel(value) {
  return EVENT_LABELS[value] || titleCase(value || "unknown");
}

function sourceTypeLabel(value) {
  return SOURCE_TYPE_LABELS[value] || titleCase(value || "unknown");
}

function formatUtc(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function formatUtcShort(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "-";
  return date.toISOString().slice(0, 16).replace("T", " ");
}

function formatLocalInputToIso(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("Invalid date filter.");
  return date.toISOString();
}

function formatNumber(value) {
  if (value === null || value === undefined) return "-";
  return Number(value).toLocaleString();
}

function formatBytes(value) {
  if (value === null || value === undefined) return "-";
  const number = Number(value);
  if (!Number.isFinite(number)) return "-";
  if (number < 1024) return `${number} B`;
  if (number < 1024 * 1024) return `${(number / 1024).toFixed(1)} KiB`;
  if (number < 1024 * 1024 * 1024) return `${(number / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(number / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return "-";
  const value = Math.max(0, Number(seconds));
  if (value < 60) return `${value}s`;
  if (value < 3600) return `${Math.round(value / 60)}m`;
  if (value < 86400) return `${(value / 3600).toFixed(1)}h`;
  return `${(value / 86400).toFixed(1)}d`;
}

function errorMessage(error) {
  if (!error) return "Unexpected error";
  if (error.detail) {
    if (typeof error.detail === "string") return error.detail;
    if (error.detail.message) return error.detail.message;
    return JSON.stringify(error.detail);
  }
  return error.message || "Unexpected error";
}

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    headers: { Accept: "application/json", ...(options.headers || {}) },
    ...options,
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }
  if (!response.ok) {
    const error = new Error(`${response.status} ${response.statusText}`);
    error.status = response.status;
    error.detail = payload && payload.detail ? payload.detail : null;
    throw error;
  }
  return payload;
}

function toast(message, tone = "info") {
  const element = $("#toast");
  element.textContent = message;
  element.className = `toast show ${tone}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    element.className = "toast";
  }, tone === "error" ? 8000 : 4500);
}

function showGlobalAlert(message) {
  const alert = $("#global-alert");
  alert.textContent = message;
  alert.hidden = false;
}

function clearGlobalAlert() {
  const alert = $("#global-alert");
  alert.textContent = "";
  alert.hidden = true;
}

async function withBusy(button, action) {
  if (!button) return action();
  const previous = button.textContent;
  button.disabled = true;
  button.textContent = "Working...";
  try {
    return await action();
  } finally {
    button.disabled = false;
    button.textContent = previous;
  }
}

function tableMessage(body, columns, message, tone = "table-message") {
  clear(body);
  const row = document.createElement("tr");
  const cell = node("td", tone, message);
  cell.colSpan = columns;
  row.append(cell);
  body.append(row);
}

function tableError(body, columns, message, retry) {
  clear(body);
  const row = document.createElement("tr");
  const cell = node("td", "table-message table-error");
  cell.colSpan = columns;
  cell.append(document.createTextNode(message));
  const button = node("button", "secondary mini", "Retry");
  button.type = "button";
  button.addEventListener("click", retry);
  cell.append(document.createTextNode(" "), button);
  row.append(cell);
  body.append(row);
}

function chips(container, items) {
  clear(container);
  if (!items.length) {
    container.append(node("span", "muted small", "No values available."));
    return;
  }
  for (const item of items) {
    const chip = node("span", `chip ${item.tone || ""}`);
    chip.append(document.createTextNode(item.label));
    chip.append(node("strong", null, item.value));
    container.append(chip);
  }
}

function detailBlock(label, value, mono = false) {
  const block = node("div", "detail");
  block.append(node("span", null, label));
  block.append(node(mono ? "code" : "strong", null, value === null || value === undefined || value === "" ? "-" : value));
  return block;
}

function currentInvestigation() {
  return state.investigations.find((item) => item.id === state.currentId) || null;
}

function maxDate(values) {
  let result = null;
  for (const value of values) {
    if (!value) continue;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) continue;
    if (!result || date > result) result = date;
  }
  return result;
}

async function checkHealth() {
  const pill = $("#global-health");
  try {
    const response = await fetch(`${API}/health`, { headers: { Accept: "application/json" } });
    const payload = await response.json();
    if (response.ok) {
      pill.textContent = `System online - v${payload.version}`;
      pill.className = "status-pill good";
    } else {
      pill.textContent = `Degraded - ${payload.database}/${payload.schema_status}/${payload.storage}`;
      pill.className = "status-pill warn";
    }
  } catch {
    pill.textContent = "System unreachable";
    pill.className = "status-pill bad";
  }
}

async function init() {
  bindEvents();
  await checkHealth();
  await loadInvestigations();
  if (state.currentId) {
    await loadWorkspace();
  } else {
    renderNoInvestigation();
  }
}

function bindEvents() {
  const eventTypeSelect = $("#filter-event-type");
  for (const [value, label] of Object.entries(EVENT_LABELS)) {
    eventTypeSelect.append(new Option(label, value));
  }
  $("#create-investigation-form").addEventListener("submit", onCreateInvestigation);
  $("#refresh-dashboard").addEventListener("click", onRefresh);
  $("#coverage-window").addEventListener("change", onCoverageWindowChange);
  $("#timeline-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    state.timelineLimit = Number($("#filter-limit").value) || 50;
    state.timelineOffset = 0;
    loadTimeline(state.requestToken);
  });
  $("#filter-reset").addEventListener("click", () => {
    $("#timeline-filters").reset();
    $("#filter-include-unknown").checked = true;
    $("#filter-include-duplicates").checked = true;
    state.timelineLimit = 50;
    state.timelineOffset = 0;
    loadTimeline(state.requestToken);
  });
  $("#timeline-prev").addEventListener("click", () => {
    state.timelineOffset = Math.max(0, state.timelineOffset - state.timelineLimit);
    loadTimeline(state.requestToken);
  });
  $("#timeline-next").addEventListener("click", () => {
    if (state.timelineOffset + state.timelineLimit < state.timelineTotal) {
      state.timelineOffset += state.timelineLimit;
      loadTimeline(state.requestToken);
    }
  });
   $("#event-dialog-close").addEventListener("click", () => $("#event-dialog").close());
   const runCorrelationsButton = $("#run-correlations");
   if (runCorrelationsButton) {
     runCorrelationsButton.addEventListener("click", () => runCorrelationsAction(runCorrelationsButton));
   }
  $("#event-dialog").addEventListener("click", (event) => {
    if (event.target === $("#event-dialog")) $("#event-dialog").close();
  });
}

async function loadInvestigations(keepSelection = true) {
  try {
    const investigations = await api("/investigations");
    state.investigations = investigations;
    $("#investigation-count").textContent = String(investigations.length);
    if (keepSelection) {
      const stored = state.currentId || localStorage.getItem(STORAGE_KEY);
      state.currentId = investigations.some((item) => item.id === stored)
        ? stored
        : investigations[0]?.id || null;
    } else if (!investigations.some((item) => item.id === state.currentId)) {
      state.currentId = investigations[0]?.id || null;
    }
    if (state.currentId) {
      localStorage.setItem(STORAGE_KEY, state.currentId);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
    renderInvestigationList();
    renderInvestigationHeader();
  } catch (error) {
    state.investigations = [];
    state.currentId = null;
    renderInvestigationList();
    renderInvestigationHeader();
    showGlobalAlert(`Could not load investigations. ${errorMessage(error)}`);
  }
}

function renderInvestigationList() {
  const list = $("#investigation-list");
  clear(list);
  if (!state.investigations.length) {
    list.append(node("p", "muted small", "No investigations yet. Create one to begin."));
    return;
  }
  for (const investigation of state.investigations) {
    const button = node("button", "investigation-item");
    button.type = "button";
    if (investigation.id === state.currentId) button.classList.add("active");
    button.append(node("strong", null, investigation.name));
    button.append(
      node("span", null, `${investigation.evidence_count} evidence - ${investigation.event_count} events`)
    );
    button.addEventListener("click", () => selectInvestigation(investigation.id));
    list.append(button);
  }
}

function renderInvestigationHeader() {
  const investigation = currentInvestigation();
  if (!investigation) {
    $("#investigation-title").textContent = "No investigation selected";
    $("#investigation-meta").textContent = "Create or select an investigation to begin.";
    $("#overview-created").textContent = "-";
    $("#overview-collected-range").textContent = "-";
    $("#overview-last-success").textContent = "-";
    $("#overview-window").textContent = "-";
    return;
  }
  $("#investigation-title").textContent = investigation.name;
  const description = investigation.description ? ` - ${investigation.description}` : "";
  $("#investigation-meta").textContent =
    `${investigation.evidence_count} evidence file(s), ${investigation.event_count} event(s)${description}`;
  $("#overview-created").textContent = formatUtc(investigation.created_at);
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

function resetDashboardData() {
  state.summary = null;
  state.sources = [];
  state.coverage = null;
  state.parsing = null;
  state.timestamps = null;
  state.integrity = null;
  state.correlations = [];
  state.correlationEventIds = new Set();
  state.timeline = [];
  state.timelineTotal = 0;
}

function setPanelLoading() {
  $("#coverage-note").textContent = "Loading coverage...";
  chips($("#coverage-chips"), []);
  tableMessage($("#source-body"), 7, "Loading registered sources and agent status...");
  chips($("#gap-chips"), []);
  tableMessage($("#gap-body"), 7, "Loading collection gaps...");
  chips($("#parsing-chips"), []);
  tableMessage($("#parsing-body"), 7, "Loading parsing outcomes...");
  chips($("#timestamp-chips"), []);
  clear($("#timestamp-samples"));
  $("#timestamp-samples").append(node("p", "muted small", "Loading uncertain event samples..."));
  chips($("#integrity-chips"), []);
  tableMessage($("#integrity-body"), 5, "Loading integrity status...");
  $("#timeline-count").textContent = "Loading events...";
  tableMessage($("#timeline-body"), 5, "Loading timeline events...");
  const correlationListLoading = $("#correlation-list");
  if (correlationListLoading) {
    clear(correlationListLoading);
    correlationListLoading.append(node("p", "muted small", "Loading correlations..."));
  }
  $("#timeline-page-label").textContent = "0 of 0 events";
  $("#timeline-prev").disabled = true;
  $("#timeline-next").disabled = true;
  $("#incident-flags").replaceChildren(node("span", "muted", "Loading quality indicators..."));
}

function updateReportLinks() {
  const id = state.currentId;
  const pdf = $("#download-pdf");
  const links = {
    "export-timeline-csv": "timeline.csv",
    "export-evidence-csv": "evidence.csv",
    "export-coverage-csv": "coverage.csv",
    "export-parsing-csv": "parsing.csv",
    "export-correlations-csv": "correlations.csv",
  };
  if (!id) {
    if (pdf) pdf.removeAttribute("href");
    for (const elementId of Object.keys(links)) {
      const link = $(`#${elementId}`);
      if (link) link.removeAttribute("href");
    }
    return;
  }
  if (pdf) pdf.href = `/api/investigations/${id}/report.pdf`;
  for (const [elementId, dataset] of Object.entries(links)) {
    const link = $(`#${elementId}`);
    if (link) link.href = `/api/investigations/${id}/export/${dataset}`;
  }
}

async function loadWorkspace() {
  if (!state.currentId) {
    renderNoInvestigation();
    updateReportLinks();
    return;
  }
  clearGlobalAlert();
  resetDashboardData();
  const token = ++state.requestToken;
  state.timelineOffset = 0;
  state.timelineLimit = Number($("#filter-limit").value) || 50;
   renderInvestigationHeader();
   renderMetricDefaults();
   updateReportLinks();
   setPanelLoading();
   await Promise.allSettled([
    loadSummary(token),
    loadEvidenceSources(token),
    loadCoverage(token),
    loadParsing(token),
    loadTimestamps(token),
     loadIntegrity(token),
     loadCorrelations(token),
   ]);
  if (token !== state.requestToken) return;
  await loadTimeline(token);
}

function renderNoInvestigation() {
  resetDashboardData();
  renderMetricDefaults();
  renderInvestigationHeader();
  $("#incident-flags").replaceChildren(node("span", "muted", "No investigation selected."));
  $("#coverage-note").textContent = "Coverage not loaded.";
  chips($("#coverage-chips"), []);
  tableMessage($("#source-body"), 7, "Select an investigation to view sources.");
  chips($("#gap-chips"), []);
  tableMessage($("#gap-body"), 7, "Select an investigation to view collection gaps.");
  chips($("#parsing-chips"), []);
  tableMessage($("#parsing-body"), 7, "Select an investigation to view parsing outcomes.");
  chips($("#timestamp-chips"), []);
  clear($("#timestamp-samples"));
  $("#timestamp-samples").append(node("p", "muted small", "Select an investigation to view timestamp uncertainty."));
  chips($("#integrity-chips"), []);
  tableMessage($("#integrity-body"), 5, "Select an investigation to view integrity status.");
  $("#timeline-count").textContent = "0 events";
  tableMessage($("#timeline-body"), 5, "Select an investigation to load the timeline.");
  $("#timeline-page-label").textContent = "0 of 0 events";
  $("#timeline-prev").disabled = true;
  $("#timeline-next").disabled = true;
  const sourceSelect = $("#filter-source-id");
  clear(sourceSelect);
  sourceSelect.append(new Option("All sources", ""));
   $("#event-dialog").close();
   updateReportLinks();
 }

function renderMetricDefaults() {
  $("#metric-events").textContent = "0";
  $("#metric-events-sub").textContent = "No events loaded";
  $("#metric-evidence").textContent = "0";
  $("#metric-evidence-sub").textContent = "0 sources";
  $("#metric-coverage").textContent = "-";
  $("#metric-coverage-sub").textContent = "Coverage not loaded";
  $("#metric-last-success").textContent = "-";
  $("#metric-last-success-sub").textContent = "No successful agent cycle recorded";
  $("#metric-gaps").textContent = "0";
  $("#metric-gaps-sub").textContent = "No gaps loaded";
  $("#metric-parsing").textContent = "0";
  $("#metric-parsing-sub").textContent = "No parser data loaded";
  $("#metric-integrity").textContent = "0";
  $("#metric-integrity-sub").textContent = "No integrity data loaded";
  $("#metric-uncertain").textContent = "0";
  $("#metric-uncertain-sub").textContent = "No timestamp data loaded";
  $("#overview-collected-range").textContent = "-";
  $("#overview-last-success").textContent = "-";
  $("#overview-window").textContent = "-";
}

async function loadSummary(token) {
  try {
    const summary = await api(`/investigations/${state.currentId}/summary`);
    if (token !== state.requestToken) return;
    state.summary = summary;
    renderMetrics();
    renderOverview();
  } catch (error) {
    if (token !== state.requestToken) return;
    $("#metric-events-sub").textContent = "Summary unavailable";
    $("#metric-evidence-sub").textContent = "Summary unavailable";
    $("#metric-parsing-sub").textContent = "Summary unavailable";
    $("#overview-collected-range").textContent = "Summary unavailable";
  }
}

async function loadEvidenceSources(token) {
  try {
    const sources = await api(`/investigations/${state.currentId}/sources`);
    if (token !== state.requestToken) return;
    state.sources = sources;
    renderSourceFilter();
  } catch {
    if (token !== state.requestToken) return;
    state.sources = [];
    renderSourceFilter();
  }
}

function renderSourceFilter() {
  const select = $("#filter-source-id");
  const previous = select.value;
  clear(select);
  select.append(new Option("All sources", ""));
  for (const source of state.sources) {
    select.append(
      new Option(`${source.name} (${sourceTypeLabel(source.source_type)})`, source.id)
    );
  }
  if (state.sources.some((source) => source.id === previous)) {
    select.value = previous;
  }
}

async function loadCoverage(token) {
  const hours = Number($("#coverage-window").value) || 24;
  state.coverage = null;
  const end = new Date();
  const start = new Date(end.getTime() - hours * 3600 * 1000);
  const query =
    `start=${encodeURIComponent(start.toISOString())}` +
    `&end=${encodeURIComponent(end.toISOString())}`;
  try {
    const coverage = await api(
      `/quality/investigations/${state.currentId}/coverage?${query}`
    );
    if (token !== state.requestToken) return;
    state.coverage = coverage;
    renderCoverage();
    renderMetrics();
    renderOverview();
  } catch (error) {
    if (token !== state.requestToken) return;
    $("#coverage-note").textContent = "Coverage unavailable.";
    chips($("#coverage-chips"), []);
    tableError($("#source-body"), 7, `Could not load coverage. ${errorMessage(error)}`, () =>
      loadCoverage(state.requestToken)
    );
    tableError($("#gap-body"), 7, `Could not load collection gaps. ${errorMessage(error)}`, () =>
      loadCoverage(state.requestToken)
    );
    $("#metric-coverage").textContent = "-";
    $("#metric-coverage-sub").textContent = "Coverage unavailable";
    $("#metric-last-success").textContent = "-";
    $("#metric-last-success-sub").textContent = "Coverage unavailable";
    $("#overview-last-success").textContent = "Unavailable";
    $("#overview-window").textContent = "Unavailable";
  }
}

function renderCoverage() {
  const coverage = state.coverage;
  if (!coverage) return;
  const summary = coverage.summary;
  const evaluable = summary.reporting_sources + summary.idle_sources;

  $("#coverage-note").textContent =
    `Window ${formatUtc(coverage.window_start)} to ${formatUtc(coverage.window_end)}. ` +
    "Manual uploads remain unknown coverage.";

  chips($("#coverage-chips"), [
    { label: "Reporting", value: summary.reporting_sources, tone: "good" },
    { label: "Idle", value: summary.idle_sources, tone: "neutral" },
    {
      label: "Not reporting",
      value: summary.not_reporting_sources,
      tone: summary.not_reporting_sources ? "warn" : "neutral",
    },
    {
      label: "Error",
      value: summary.error_sources,
      tone: summary.error_sources ? "bad" : "neutral",
    },
    { label: "Disabled", value: summary.disabled_sources, tone: "neutral" },
    { label: "Unknown / manual", value: summary.unknown_sources, tone: "info" },
    {
      label: "Open gaps",
      value: summary.open_gaps,
      tone: summary.open_gaps ? "warn" : "good",
    },
    {
      label: "Zero-byte cycles",
      value: summary.no_events_observed_sources,
      tone: "neutral",
    },
    { label: "Evaluable sources", value: evaluable, tone: "neutral" },
  ]);

  const body = $("#source-body");
  clear(body);
  if (!coverage.sources.length) {
    tableMessage(
      body,
      7,
      "No registered agent or evidence sources yet. Upload evidence or enroll an agent to populate this view."
    );
  }

  for (const source of coverage.sources) {
    const row = document.createElement("tr");

    const sourceCell = document.createElement("td");
    sourceCell.append(node("span", "cell-title", source.name));
    const clock =
      source.clock_offset_seconds === null || source.clock_offset_seconds === undefined
        ? ""
        : ` - clock offset ${source.clock_offset_seconds}s (${source.clock_offset_source || "recorded"})`;
    sourceCell.append(
      node(
        "span",
        "cell-sub",
        `${sourceTypeLabel(source.source_type)}${source.source_key ? ` - ${source.source_key}` : ""}${clock}`
      )
    );

    const agentCell = document.createElement("td");
    if (source.agent_name) {
      agentCell.append(node("span", "cell-title", source.agent_name));
      const agentLine = node("span", "cell-sub");
      if (source.agent_health) {
        agentLine.append(
          badge(source.agent_health, AGENT_HEALTH_TONES[source.agent_health] || "neutral")
        );
      }
      agentLine.append(document.createTextNode(` ${source.inventory_origin}`));
      agentCell.append(agentLine);
      if (source.last_heartbeat_at) {
        agentCell.append(
          node("span", "cell-sub", `Last heartbeat ${formatUtc(source.last_heartbeat_at)}`)
        );
      }
    } else {
      agentCell.append(node("span", "cell-title", "Manual upload"));
      agentCell.append(node("span", "cell-sub", source.inventory_origin));
    }

    const coverageCell = document.createElement("td");
    coverageCell.append(
      badge(source.coverage_state, COVERAGE_TONES[source.coverage_state] || "neutral")
    );
    if (source.open_gap) {
      coverageCell.append(badge("open gap", "warn"));
    }
    if (source.collection_unavailable_reason) {
      const reason = node("span", "cell-sub truncate", source.collection_unavailable_reason);
      reason.title = source.collection_unavailable_reason;
      coverageCell.append(reason);
    } else if (source.status) {
      coverageCell.append(node("span", "cell-sub", `Source state: ${titleCase(source.status)}`));
    }

    const successCell = document.createElement("td");
    if (source.last_success_at) {
      successCell.append(node("span", "mono", formatUtc(source.last_success_at)));
    } else {
      successCell.append(node("span", "cell-sub", "No successful collection recorded"));
    }
    if (source.last_collection_ended_at) {
      successCell.append(
        node("span", "cell-sub", `Last cycle ended ${formatUtc(source.last_collection_ended_at)}`)
      );
    }

    const cyclesCell = document.createElement("td");
    cyclesCell.append(
      node("span", "mono", `${formatNumber(source.expected_cycles)} / ${formatNumber(source.observed_cycles)}`)
    );
    cyclesCell.append(
      node(
        "span",
        "cell-sub",
        `${formatNumber(source.missing_cycles)} missing cycle(s) in window`
      )
    );

    const missingCell = document.createElement("td");
    missingCell.append(node("span", "mono", formatBytes(source.bytes_missing)));
    missingCell.append(
      node(
        "span",
        "cell-sub",
        `${formatBytes(source.bytes_received)} received of ${formatBytes(source.bytes_expected)} expected`
      )
    );

    const eventsCell = document.createElement("td");
    eventsCell.append(node("span", "mono", formatNumber(source.events_observed)));
    if (source.no_events_observed) {
      eventsCell.append(badge("zero-byte cycle", "neutral"));
    }
    const lastCycle =
      source.last_cycle_bytes === null || source.last_cycle_bytes === undefined
        ? "No cycle byte count reported"
        : `${formatNumber(source.last_cycle_bytes)} bytes, ${formatNumber(source.last_cycle_lines)} lines in last cycle`;
    eventsCell.append(node("span", "cell-sub", lastCycle));

    row.append(sourceCell, agentCell, coverageCell, successCell, cyclesCell, missingCell, eventsCell);
    body.append(row);
  }

  renderGaps();
}

function renderGaps() {
  const coverage = state.coverage;
  if (!coverage) return;
  const gaps = [...coverage.gaps].sort((left, right) => {
    if (left.status !== right.status) return left.status === "open" ? -1 : 1;
    return new Date(right.gap_start) - new Date(left.gap_start);
  });
  const open = gaps.filter((gap) => gap.status === "open").length;
  const closed = gaps.length - open;

  chips($("#gap-chips"), [
    { label: "Open", value: open, tone: open ? "warn" : "good" },
    { label: "Closed", value: closed, tone: "neutral" },
    { label: "Observed", value: gaps.filter((gap) => gap.basis === "observed").length, tone: "info" },
    { label: "Inferred", value: gaps.filter((gap) => gap.basis === "inferred").length, tone: "warn" },
    { label: "Estimated", value: gaps.filter((gap) => gap.basis === "estimated").length, tone: "warn" },
  ]);

  const body = $("#gap-body");
  clear(body);
  if (!gaps.length) {
    tableMessage(
      body,
      7,
      "No collection gaps recorded in the available coverage data. This is not proof of uninterrupted collection."
    );
    return;
  }

  for (const gap of gaps) {
    const row = document.createElement("tr");

    const statusCell = document.createElement("td");
    statusCell.append(badge(gap.status, gap.status === "open" ? "warn" : "neutral"));
    if (gap.derived) statusCell.append(badge("derived", "info"));

    const scopeCell = document.createElement("td");
    scopeCell.append(node("span", "cell-title", gap.source_name || gap.agent_name || "Agent scope"));
    scopeCell.append(
      node(
        "span",
        "cell-sub",
        [gap.scope, gap.source_key, gap.agent_name].filter(Boolean).join(" - ")
      )
    );

    const reasonCell = document.createElement("td");
    reasonCell.append(node("span", null, titleCase(gap.reason)));
    if (gap.expected_interval_seconds) {
      reasonCell.append(
        node("span", "cell-sub", `Expected every ${formatDuration(gap.expected_interval_seconds)}`)
      );
    }

    const basisCell = document.createElement("td");
    basisCell.append(
      badge(gap.basis, gap.basis === "observed" ? "info" : "warn")
    );
    if (gap.derived) {
      basisCell.append(node("span", "cell-sub", "Synthesized from last observed state"));
    }

    const intervalCell = document.createElement("td");
    intervalCell.append(node("span", "mono", formatUtc(gap.gap_start)));
    intervalCell.append(
      node("span", "cell-sub", gap.gap_end ? `to ${formatUtc(gap.gap_end)}` : "ongoing")
    );

    const durationCell = document.createElement("td");
    durationCell.append(node("span", "mono", formatDuration(gap.duration_seconds)));

    const noteCell = document.createElement("td");
    const detail = gap.detail || {};
    const note = detail.note || detail.closed_note || detail.last_error || "";
    const noteNode = node("span", "cell-sub truncate", note || "-");
    noteNode.title = note || "";
    noteCell.append(noteNode);
    if (detail.last_error) {
      const errorNode = node("span", "cell-sub truncate", `Last error: ${detail.last_error}`);
      errorNode.title = detail.last_error;
      noteCell.append(errorNode);
    }

    row.append(statusCell, scopeCell, reasonCell, basisCell, intervalCell, durationCell, noteCell);
    body.append(row);
  }
}

async function loadParsing(token) {
  try {
    const parsing = await api(
      `/quality/investigations/${state.currentId}/parsing?limit=500`
    );
    if (token !== state.requestToken) return;
    state.parsing = parsing;
    renderParsing();
    renderMetrics();
  } catch (error) {
    if (token !== state.requestToken) return;
    chips($("#parsing-chips"), []);
    tableError($("#parsing-body"), 7, `Could not load parser outcomes. ${errorMessage(error)}`, () =>
      loadParsing(state.requestToken)
    );
    $("#metric-parsing").textContent = "0";
    $("#metric-parsing-sub").textContent = "Parser data unavailable";
  }
}

function renderParsing() {
  const parsing = state.parsing;
  if (!parsing) return;
  const totals = parsing.totals || {};
  chips($("#parsing-chips"), [
    { label: "Evidence files", value: formatNumber(totals.evidence_files), tone: "neutral" },
    { label: "Parsed records", value: formatNumber(totals.parsed_records), tone: "good" },
    {
      label: "Rejected records",
      value: formatNumber(totals.records_rejected),
      tone: totals.records_rejected ? "bad" : "neutral",
    },
    {
      label: "Malformed",
      value: formatNumber(totals.malformed_records),
      tone: totals.malformed_records ? "warn" : "neutral",
    },
    {
      label: "Unsupported",
      value: formatNumber(totals.unsupported_records),
      tone: totals.unsupported_records ? "warn" : "neutral",
    },
    {
      label: "Missing required fields",
      value: formatNumber(totals.missing_required_fields),
      tone: totals.missing_required_fields ? "warn" : "neutral",
    },
    { label: "Missing optional fields", value: formatNumber(totals.missing_optional_fields), tone: "neutral" },
    {
      label: "Parser errors",
      value: formatNumber(totals.parser_errors),
      tone: totals.parser_errors ? "bad" : "neutral",
    },
    {
      label: "Timestamp flags",
      value: formatNumber(totals.timestamp_flagged_records),
      tone: totals.timestamp_flagged_records ? "warn" : "neutral",
    },
    {
      label: "Ordering ties",
      value: formatNumber(totals.ordering_tied_records),
      tone: totals.ordering_tied_records ? "warn" : "neutral",
    },
    {
      label: "Unresolved ordering",
      value: formatNumber(totals.ordering_unresolved_records),
      tone: totals.ordering_unresolved_records ? "warn" : "neutral",
    },
    {
      label: "Issues suppressed",
      value: formatNumber(totals.issues_suppressed),
      tone: totals.issues_suppressed ? "warn" : "neutral",
    },
  ]);

  const body = $("#parsing-body");
  clear(body);
  if (!parsing.items.length) {
    tableMessage(body, 7, "No evidence files have been imported into this investigation yet.");
    return;
  }

  for (const item of parsing.items) {
    const row = document.createElement("tr");
    const result = item.parsing_result;

    const evidenceCell = document.createElement("td");
    evidenceCell.append(node("span", "cell-title", item.filename));
    evidenceCell.append(
      node(
        "span",
        "cell-sub",
        `${item.source_name} - received ${formatUtc(item.received_at)}`
      )
    );

    const parserCell = document.createElement("td");
    parserCell.append(node("span", null, result?.parser_name || "No parser"));
    if (result?.parser_version) {
      parserCell.append(node("span", "cell-sub", `Version ${result.parser_version}`));
    }
    if (item.clock_offset_seconds !== null && item.clock_offset_seconds !== undefined) {
      parserCell.append(
        node("span", "cell-sub", `Clock offset ${item.clock_offset_seconds}s`)
      );
    }

    const statusCell = document.createElement("td");
    if (result) {
      statusCell.append(badge(result.status, PARSING_TONES[result.status] || "neutral"));
    } else {
      statusCell.append(badge("not parsed", "warn"));
    }

    const recordsCell = document.createElement("td");
    recordsCell.append(
      node(
        "span",
        "mono",
        result
          ? `${formatNumber(result.parsed_records)} / ${formatNumber(result.records_rejected)}`
          : "-"
      )
    );
    if (result) {
      recordsCell.append(
        node(
          "span",
          "cell-sub",
          `${formatNumber(result.malformed_records)} malformed, ${formatNumber(result.unsupported_records)} unsupported`
        )
      );
    }

    const fieldsCell = document.createElement("td");
    fieldsCell.append(
      node("span", "mono", result ? formatNumber(result.missing_required_fields) : "-")
    );
    fieldsCell.append(
      node(
        "span",
        "cell-sub",
        result ? `${formatNumber(result.missing_optional_fields)} optional missing` : ""
      )
    );

    const timestampCell = document.createElement("td");
    timestampCell.append(
      node("span", "mono", result ? formatNumber(result.timestamp_flagged_records) : "-")
    );
    timestampCell.append(
      node(
        "span",
        "cell-sub",
        result ? `${formatNumber(result.encoding_error_lines)} encoding errors` : ""
      )
    );

    const orderingCell = document.createElement("td");
    orderingCell.append(
      node(
        "span",
        "mono",
        result
          ? `${formatNumber(result.ordering_tied_records)} / ${formatNumber(result.ordering_unresolved_records)}`
          : "-"
      )
    );
    orderingCell.append(node("span", "cell-sub", "tied / unresolved"));

    row.append(evidenceCell, parserCell, statusCell, recordsCell, fieldsCell, timestampCell, orderingCell);
    body.append(row);
  }
}

async function loadTimestamps(token) {
  try {
    const timestamps = await api(
      `/quality/investigations/${state.currentId}/timestamps?sample_limit=25`
    );
    if (token !== state.requestToken) return;
    state.timestamps = timestamps;
    renderTimestamps();
    renderMetrics();
  } catch (error) {
    if (token !== state.requestToken) return;
    chips($("#timestamp-chips"), []);
    clear($("#timestamp-samples"));
    $("#timestamp-samples").append(
      node("p", "warn-note bad", `Could not load timestamp quality. ${errorMessage(error)}`)
    );
    $("#metric-uncertain").textContent = "0";
    $("#metric-uncertain-sub").textContent = "Timestamp data unavailable";
  }
}

function renderTimestamps() {
  const timestamps = state.timestamps;
  if (!timestamps) return;
  const statusItems = Object.entries(timestamps.timestamp_status_counts || {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([status, count]) => ({
      label: titleCase(status),
      value: formatNumber(count),
      tone: TIMESTAMP_TONES[status] || "neutral",
    }));
  chips($("#timestamp-chips"), [
    { label: "Total events", value: formatNumber(timestamps.total_events), tone: "neutral" },
    { label: "Normalized", value: formatNumber(timestamps.normalized_events), tone: "good" },
    {
      label: "Uncertain",
      value: formatNumber(timestamps.uncertain_events),
      tone: timestamps.uncertain_events ? "warn" : "good",
    },
    {
      label: "Clock offsets",
      value: formatNumber(timestamps.clock_offset_events),
      tone: timestamps.clock_offset_events ? "info" : "neutral",
    },
    ...statusItems,
  ]);
  $("#timestamp-rule").textContent = timestamps.timestamp_rule;
  $("#ordering-rule").textContent = timestamps.ordering_rule;

  const samples = $("#timestamp-samples");
  clear(samples);
  if (!timestamps.uncertain_samples.length) {
    samples.append(
      node(
        "p",
        "muted small",
        timestamps.total_events
          ? "All parsed events currently have a normalized UTC timestamp."
          : "No events have been parsed yet."
      )
    );
    return;
  }

  for (const sample of timestamps.uncertain_samples) {
    const card = node("article", "sample");
    const button = node("button");
    button.type = "button";
    button.append(node("span", "sample-title", typeLabel(sample.event_type)));
    button.append(
      node(
        "span",
        "sample-meta",
        `${sample.original_timestamp_string || "No timestamp text"} - ${titleCase(sample.timestamp_status)}`
      )
    );
    button.append(
      node(
        "span",
        "sample-meta",
        `${sample.source_name} - ${sample.evidence_filename} line ${sample.line_number}`
      )
    );
    if (sample.timestamp_detail) {
      const detail = node("span", "sample-meta", sample.timestamp_detail);
      detail.title = sample.timestamp_detail;
      button.append(detail);
    }
    button.addEventListener("click", () => openEventById(sample.event_id));
    card.append(button);
    samples.append(card);
  }
}

async function loadIntegrity(token) {
  try {
    const integrity = await api(`/quality/investigations/${state.currentId}/integrity`);
    if (token !== state.requestToken) return;
    state.integrity = integrity;
    renderIntegrity();
    renderMetrics();
  } catch (error) {
    if (token !== state.requestToken) return;
    chips($("#integrity-chips"), []);
    tableError($("#integrity-body"), 5, `Could not load integrity status. ${errorMessage(error)}`, () =>
      loadIntegrity(state.requestToken)
    );
    $("#metric-integrity").textContent = "0";
    $("#metric-integrity-sub").textContent = "Integrity data unavailable";
  }
}

async function loadCorrelations(token) {
  if (!state.currentId) return;
  try {
    const correlations = await api(`/investigations/${state.currentId}/correlations`);
    if (token !== state.requestToken) return;
    state.correlations = correlations;
    state.correlationEventIds = new Set();
    for (const correlation of correlations) {
      if (correlation.status === "dismissed") continue;
      for (const eventId of correlation.event_ids || []) {
        state.correlationEventIds.add(eventId);
      }
    }
    renderCorrelations();
  } catch (error) {
    if (token !== state.requestToken) return;
    state.correlations = [];
    state.correlationEventIds = new Set();
    const container = $("#correlation-list");
    if (container) {
      clear(container);
      container.append(node("p", "warn-note bad", `Could not load correlations. ${errorMessage(error)}`));
    }
  }
}

async function runCorrelationsAction(button) {
  if (!state.currentId) return;
  await withBusy(button, async () => {
    try {
      const windowHours = Number($("#coverage-window").value) || 24;
      const seconds = Math.max(60, windowHours * 3600);
      const response = await api(
        `/investigations/${state.currentId}/correlations?time_window_seconds=${seconds}`,
        { method: "POST" }
      );
      state.correlations = response.items || [];
      state.correlationEventIds = new Set();
      for (const correlation of state.correlations) {
        if (correlation.status === "dismissed") continue;
        for (const eventId of correlation.event_ids || []) {
          state.correlationEventIds.add(eventId);
        }
      }
      renderCorrelations();
      await loadTimeline(state.requestToken);
      toast(`Correlation run complete: ${response.created} created, ${response.updated} updated.`, "success");
    } catch (error) {
      toast(errorMessage(error), "error");
    }
  });
}

async function dismissCorrelationAction(correlationId, button) {
  const reason = window.prompt("Reason for dismissing this correlation:");
  if (!reason || !reason.trim()) return;
  await withBusy(button, async () => {
    try {
      await api(`/correlations/${correlationId}/dismiss`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reason: reason.trim() }),
      });
      await loadCorrelations(state.requestToken);
      await loadTimeline(state.requestToken);
      toast("Correlation dismissed.", "success");
    } catch (error) {
      toast(errorMessage(error), "error");
    }
  });
}

function renderCorrelations() {
  const correlations = state.correlations || [];
  const container = $("#correlation-list");
  if (!container) return;
  clear(container);
  const active = correlations.filter((item) => item.status !== "dismissed");
  const dismissed = correlations.length - active.length;
  const chipContainer = $("#correlation-chips");
  if (chipContainer) {
    chips(chipContainer, [
      { label: "Suggested", value: active.length, tone: active.length ? "info" : "neutral" },
      { label: "Dismissed", value: dismissed, tone: "neutral" },
      {
        label: "Correlated events",
        value: state.correlationEventIds.size,
        tone: state.correlationEventIds.size ? "warn" : "neutral",
      },
    ]);
  }
  const count = $("#correlation-count");
  if (count) count.textContent = `${correlations.length} correlation(s)`;

  if (!correlations.length) {
    container.append(node("p", "muted small", "No correlations generated yet. Import events from multiple sources, then run correlation."));
    return;
  }

  for (const correlation of correlations) {
    const card = node("article", "sample");
    const head = node("div", "flag-row");
    head.style.marginBottom = "8px";
    head.append(node("strong", null, correlation.title));
    head.append(badge(correlation.confidence, correlation.confidence === "high" ? "good" : correlation.confidence === "medium" ? "warn" : "neutral"));
    head.append(badge(correlation.status, correlation.status === "dismissed" ? "neutral" : "info"));
    card.append(head);

    const meta = node("p", "muted small");
    meta.textContent = `${correlation.rule_name} - sources: ${(correlation.source_systems || []).join(", ")}`;
    card.append(meta);

    const fields = node("p", "muted small");
    fields.append(document.createTextNode("Matching fields: "));
    fields.append(node("strong", null, (correlation.matching_fields || []).join(", ") || "-"));
    card.append(fields);

    if (correlation.time_relationship) {
      card.append(node("p", "muted small", correlation.time_relationship));
    }
    if (correlation.timestamp_uncertainty) {
      card.append(node("p", "muted small", correlation.timestamp_uncertainty));
    }
    card.append(node("p", "help", correlation.explanation));

    const eventsRow = node("div", "inline-actions");
    for (const event of correlation.events || []) {
      const button = node("button", "secondary mini", `Event ${event.event_id}`);
      button.type = "button";
      button.addEventListener("click", () => openEventById(event.event_id));
      eventsRow.append(button);
    }
    if (correlation.status !== "dismissed") {
      const dismissButton = node("button", "secondary mini", "Dismiss");
      dismissButton.type = "button";
      dismissButton.addEventListener("click", () => dismissCorrelationAction(correlation.id, dismissButton));
      eventsRow.append(dismissButton);
    }
    card.append(eventsRow);
    container.append(card);
  }
}

function renderIntegrity() {
  const integrity = state.integrity;
  if (!integrity) return;
  chips($("#integrity-chips"), [
    { label: "Evidence files", value: formatNumber(integrity.evidence_count), tone: "neutral" },
    { label: "Verified", value: formatNumber(integrity.verified_evidence), tone: "good" },
    { label: "Unverified", value: formatNumber(integrity.unverified_evidence), tone: "info" },
    {
      label: "Mismatch",
      value: formatNumber(integrity.mismatched_evidence),
      tone: integrity.mismatched_evidence ? "bad" : "neutral",
    },
    {
      label: "Missing",
      value: formatNumber(integrity.missing_evidence),
      tone: integrity.missing_evidence ? "bad" : "neutral",
    },
  ]);

  const body = $("#integrity-body");
  clear(body);
  if (!integrity.items.length) {
    tableMessage(body, 5, "No preserved evidence files in this investigation yet.");
    return;
  }

  for (const item of integrity.items) {
    const row = document.createElement("tr");

    const evidenceCell = document.createElement("td");
    evidenceCell.append(node("span", "cell-title", item.filename));
    evidenceCell.append(
      node("span", "cell-sub", `${formatBytes(item.size_bytes)} - ${item.verification_count} verification(s)`)
    );

    const integrityCell = document.createElement("td");
    integrityCell.append(
      badge(item.integrity_status, INTEGRITY_TONES[item.integrity_status] || "neutral")
    );

    const hashCell = document.createElement("td");
    const hash = node("span", "hash", item.sha256);
    hash.title = `SHA-256: ${item.sha256}`;
    hashCell.append(hash);

    const verifiedCell = document.createElement("td");
    if (item.last_verified_at) {
      verifiedCell.append(node("span", "mono", formatUtc(item.last_verified_at)));
      verifiedCell.append(node("span", "cell-sub", item.last_verification_source || ""));
    } else {
      verifiedCell.append(node("span", "cell-sub", "Never verified"));
    }

    const actionCell = document.createElement("td");
    const actions = node("div", "inline-actions");
    const verifyButton = node("button", "secondary mini", "Verify hash");
    verifyButton.type = "button";
    verifyButton.addEventListener("click", () =>
      verifyEvidence(item.evidence_id, verifyButton)
    );
    const downloadLink = node("a", "secondary mini", "Download");
    downloadLink.href = item.download_url;
    downloadLink.target = "_blank";
    downloadLink.rel = "noopener";
    downloadLink.style.padding = "4px 8px";
    downloadLink.style.border = "1px solid var(--border)";
    downloadLink.style.borderRadius = "6px";
    downloadLink.style.textDecoration = "none";
    const manifestLink = node("a", "secondary mini", "Manifest");
    manifestLink.href = item.manifest_url;
    manifestLink.target = "_blank";
    manifestLink.rel = "noopener";
    manifestLink.style.padding = "4px 8px";
    manifestLink.style.border = "1px solid var(--border)";
    manifestLink.style.borderRadius = "6px";
    manifestLink.style.textDecoration = "none";
    actions.append(verifyButton, downloadLink, manifestLink);
    actionCell.append(actions);

    row.append(evidenceCell, integrityCell, hashCell, verifiedCell, actionCell);
    body.append(row);
  }
}

async function verifyEvidence(evidenceId, button, onVerified) {
  await withBusy(button, async () => {
    try {
      const result = await api(`/evidence/${evidenceId}/verify`, { method: "POST" });
      if (result.match) {
        toast("Hash verified. The preserved evidence is unchanged.", "success");
      } else {
        toast("HASH MISMATCH. The preserved evidence changed after collection.", "error");
      }
      if (onVerified) onVerified(result);
      await Promise.all([
        loadSummary(state.requestToken),
        loadIntegrity(state.requestToken),
        loadTimeline(state.requestToken),
      ]);
      renderOverview();
    } catch (error) {
      toast(errorMessage(error), "error");
    }
  });
}

function renderMetrics() {
  const summary = state.summary;
  const coverage = state.coverage;
  const timestamps = state.timestamps;
  const integrity = state.integrity;

  if (summary) {
    const uncertainFromSummary = Object.entries(summary.timestamp_status_counts || {})
      .filter(([key]) => key !== "normalized")
      .reduce((total, [, value]) => total + value, 0);
    const parsingFailed = summary.parsing_status_counts?.failed || 0;
    $("#metric-events").textContent = formatNumber(summary.events);
    $("#metric-events-sub").textContent =
      `${formatNumber(summary.parsed_records)} parsed records, ${formatNumber(summary.issues_total)} issue(s)`;
    $("#metric-evidence").textContent = formatNumber(summary.evidence_files);
    $("#metric-evidence-sub").textContent = `${formatNumber(summary.sources)} source(s)`;
    $("#metric-parsing").textContent = formatNumber(parsingFailed);
    $("#metric-parsing-sub").textContent =
      `${formatNumber(summary.records_rejected)} rejected, ${formatNumber(summary.malformed_records)} malformed, ${formatNumber(summary.unsupported_records)} unsupported`;
    $("#overview-collected-range").textContent = summary.evidence_files
      ? `${formatUtcShort(summary.earliest_collected_at)} to ${formatUtcShort(summary.latest_collected_at)} UTC`
      : "No evidence collected";
    if (!timestamps) {
      $("#metric-uncertain").textContent = formatNumber(uncertainFromSummary);
      $("#metric-uncertain-sub").textContent =
        `${formatNumber(summary.timestamp_flagged_records)} timestamp flag(s) during parsing`;
    }
  }

  if (coverage) {
    const summaryCoverage = coverage.summary;
    const reporting = summaryCoverage.reporting_sources + summaryCoverage.idle_sources;
    const latestSuccess = maxDate(coverage.sources.map((source) => source.last_success_at));
    const latestHeartbeat = maxDate(coverage.agents.map((agent) => agent.last_heartbeat_at));
    $("#metric-coverage").textContent =
      `${formatNumber(reporting)} / ${formatNumber(summaryCoverage.registered_sources)}`;
    $("#metric-coverage-sub").textContent =
      `${summaryCoverage.not_reporting_sources} not reporting, ${summaryCoverage.error_sources} error, ${summaryCoverage.unknown_sources} unknown/manual`;
    $("#metric-gaps").textContent = formatNumber(summaryCoverage.open_gaps);
    $("#metric-gaps-sub").textContent =
      `${formatNumber(summaryCoverage.closed_gaps)} closed gap(s) in available data`;
    $("#metric-last-success").textContent = latestSuccess
      ? formatUtcShort(latestSuccess)
      : "No successful collection";
    $("#metric-last-success-sub").textContent = latestHeartbeat
      ? `Latest agent heartbeat ${formatUtcShort(latestHeartbeat)} UTC`
      : "No agent heartbeat recorded";
    $("#overview-last-success").textContent = latestSuccess
      ? formatUtc(latestSuccess)
      : "No successful agent collection recorded";
    $("#overview-window").textContent =
      `${formatUtcShort(coverage.window_start)} to ${formatUtcShort(coverage.window_end)} UTC`;
  }

  if (timestamps) {
    $("#metric-uncertain").textContent = formatNumber(timestamps.uncertain_events);
    $("#metric-uncertain-sub").textContent =
      `${formatNumber(timestamps.normalized_events)} normalized, ${formatNumber(timestamps.clock_offset_events)} with clock offset`;
  }

  if (integrity) {
    const attention = integrity.mismatched_evidence + integrity.unverified_evidence + integrity.missing_evidence;
    $("#metric-integrity").textContent = formatNumber(attention);
    $("#metric-integrity-sub").textContent =
      `${formatNumber(integrity.verified_evidence)} verified, ${formatNumber(integrity.mismatched_evidence)} mismatch, ${formatNumber(integrity.unverified_evidence)} unverified, ${formatNumber(integrity.missing_evidence)} missing`;
  }
}

function renderOverview() {
  const coverage = state.coverage;
  const summary = state.summary;
  const timestamps = state.timestamps;
  const integrity = state.integrity;
  const flags = [];

  if (coverage) {
    const coverageSummary = coverage.summary;
    if (coverageSummary.reporting_sources + coverageSummary.idle_sources > 0) {
      flags.push({
        tone: "good",
        text: `${coverageSummary.reporting_sources + coverageSummary.idle_sources} source(s) with collection coverage`,
      });
    } else {
      flags.push({ tone: "info", text: "No agent collection coverage in this window" });
    }
    if (coverageSummary.not_reporting_sources) {
      flags.push({
        tone: "warn",
        text: `${coverageSummary.not_reporting_sources} source(s) not reporting`,
      });
    }
    if (coverageSummary.error_sources) {
      flags.push({ tone: "bad", text: `${coverageSummary.error_sources} source error(s)` });
    }
    if (coverageSummary.open_gaps) {
      flags.push({ tone: "warn", text: `${coverageSummary.open_gaps} open collection gap(s)` });
    } else {
      flags.push({ tone: "good", text: "No open collection gaps in available data" });
    }
  } else {
    flags.push({ tone: "neutral", text: "Coverage not loaded" });
  }

  if (summary) {
    const failed = summary.parsing_status_counts?.failed || 0;
    if (failed) {
      flags.push({ tone: "bad", text: `${failed} evidence file(s) failed parsing` });
    } else if (summary.evidence_files) {
      flags.push({ tone: "good", text: "No evidence files failed parsing" });
    }
    if (summary.records_rejected) {
      flags.push({ tone: "warn", text: `${formatNumber(summary.records_rejected)} record(s) rejected` });
    }
  }

  if (timestamps) {
    flags.push(
      timestamps.uncertain_events
        ? { tone: "warn", text: `${formatNumber(timestamps.uncertain_events)} uncertain timestamp(s)` }
        : { tone: "good", text: "All event timestamps normalized to UTC" }
    );
  }

  if (integrity) {
    if (integrity.mismatched_evidence) {
      flags.push({ tone: "bad", text: `${integrity.mismatched_evidence} integrity mismatch(es)` });
    }
    if (integrity.missing_evidence) {
      flags.push({ tone: "bad", text: `${integrity.missing_evidence} evidence file(s) missing` });
    }
    if (integrity.unverified_evidence) {
      flags.push({ tone: "info", text: `${integrity.unverified_evidence} evidence file(s) unverified` });
    }
    if (!integrity.mismatched_evidence && !integrity.missing_evidence && integrity.evidence_count) {
      flags.push({ tone: "good", text: "No integrity mismatches or missing evidence" });
    }
  }

  const container = $("#incident-flags");
  clear(container);
  if (!flags.length) {
    container.append(node("span", "muted", "Quality indicators not loaded."));
    return;
  }
  for (const flag of flags) {
    container.append(node("span", `flag ${flag.tone}`, flag.text));
  }
}

function currentTimelineParams() {
  const params = new URLSearchParams();
  params.set("investigation_id", state.currentId);
  params.set("limit", String(state.timelineLimit));
  params.set("offset", String(state.timelineOffset));
  params.set("sort", $("#filter-sort").value);
  params.set(
    "include_unknown_time",
    $("#filter-include-unknown").checked ? "true" : "false"
  );
  params.set(
    "include_duplicates",
    $("#filter-include-duplicates").checked ? "true" : "false"
  );

  const q = $("#filter-q").value.trim();
  const sourceId = $("#filter-source-id").value;
  const sourceType = $("#filter-source-type").value;
  const eventType = $("#filter-event-type").value;
  const hostname = $("#filter-hostname").value.trim();
  const timestampStatus = $("#filter-timestamp-status").value;
  if (q) params.set("q", q);
  if (sourceId) params.set("source_id", sourceId);
  if (sourceType) params.set("source_type", sourceType);
  if (eventType) params.set("event_type", eventType);
  if (hostname) params.set("hostname", hostname);
  if (timestampStatus) params.set("timestamp_status", timestampStatus);
  const start = $("#filter-start").value;
  const end = $("#filter-end").value;
  if (start) params.set("start", formatLocalInputToIso(start));
  if (end) params.set("end", formatLocalInputToIso(end));
  return params;
}

async function loadTimeline(token) {
  if (!state.currentId) {
    renderNoInvestigation();
    return;
  }
  $("#timeline-count").textContent = "Loading events...";
  tableMessage($("#timeline-body"), 5, "Loading timeline events...");
  $("#timeline-page-label").textContent = "0 of 0 events";
  $("#timeline-prev").disabled = true;
  $("#timeline-next").disabled = true;

  let params;
  try {
    params = currentTimelineParams();
  } catch (error) {
    toast(error.message, "error");
    tableError($("#timeline-body"), 5, error.message, () => loadTimeline(state.requestToken));
    return;
  }

  try {
    const payload = await api(`/timeline?${params.toString()}`);
    if (token !== state.requestToken) return;
    state.timeline = payload.items;
    state.timelineTotal = payload.total;
    renderTimeline(payload.ordering_rule);
  } catch (error) {
    if (token !== state.requestToken) return;
    $("#timeline-count").textContent = "Timeline unavailable";
    tableError($("#timeline-body"), 5, `Could not load timeline. ${errorMessage(error)}`, () =>
      loadTimeline(state.requestToken)
    );
    $("#timeline-page-label").textContent = "0 of 0 events";
  }
}

function renderTimeline(orderingRule) {
  const body = $("#timeline-body");
  clear(body);
  $("#timeline-count").textContent =
    `${formatNumber(state.timelineTotal)} event${state.timelineTotal === 1 ? "" : "s"}`;

  if (!state.timeline.length) {
    tableMessage(
      body,
      5,
      "No events match the current search and filters. Adjust the filters or import additional evidence."
    );
  }

  for (const event of state.timeline) {
    const row = document.createElement("tr");
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.setAttribute("aria-label", `Open ${typeLabel(event.event_type)} event detail`);
    row.addEventListener("click", () => openEventById(event.id));
    row.addEventListener("keydown", (keyboardEvent) => {
      if (keyboardEvent.key === "Enter" || keyboardEvent.key === " ") {
        keyboardEvent.preventDefault();
        openEventById(event.id);
      }
    });

    const timeCell = document.createElement("td");
    if (event.timestamp_utc) {
      timeCell.append(node("span", "timeline-time", formatUtc(event.timestamp_utc)));
    } else {
      timeCell.append(badge("unresolved time", "warn"));
    }
    if (event.timestamp_status !== "normalized") {
      timeCell.append(
        badge(event.timestamp_status, TIMESTAMP_TONES[event.timestamp_status] || "warn")
      );
    }
    if (event.original_timestamp_string) {
      const original = node("span", "timeline-error-line", event.original_timestamp_string);
      original.title = event.timestamp_detail || "";
      timeCell.append(original);
    }

    const eventCell = document.createElement("td");
    eventCell.append(badge(event.event_type, EVENT_TONES[event.event_type] || "info"));
    if (event.ordering_status !== "ordered") {
      eventCell.append(
        badge(`ordering ${event.ordering_status}`, ORDERING_TONES[event.ordering_status] || "warn")
      );
    }
     if (event.dedup_status === "duplicate") {
       eventCell.append(badge("duplicate", "warn"));
     }
     if (state.correlationEventIds.has(event.id)) {
       eventCell.append(badge("correlated", "info"));
     }
    eventCell.append(node("span", "cell-sub", titleCase(event.event_category)));
    let summary = event.message || "";
    if (event.event_type === "http_request") {
      summary = `${event.http_method || "?"} ${event.http_path || "?"} - status ${event.http_status ?? "?"}`;
    }
    if (summary) {
      const summaryNode = node("span", "event-summary", summary);
      summaryNode.title = summary;
      eventCell.append(summaryNode);
    }

    const sourceCell = document.createElement("td");
    sourceCell.append(node("span", "cell-title", event.source_name));
    sourceCell.append(
      node("span", "cell-sub", sourceTypeLabel(event.source_type))
    );
    if (event.source_hostname) {
      sourceCell.append(node("span", "cell-sub", `Source host ${event.source_hostname}`));
    }

    const actorCell = document.createElement("td");
    if (event.hostname) {
      actorCell.append(node("span", "cell-title", event.hostname));
    }
    const actorLine = node("span", "cell-sub");
    if (event.username) actorLine.append(badge(event.username, "neutral"));
    if (event.source_ip) actorLine.append(badge(event.source_ip, "neutral"));
    if (!event.username && !event.source_ip) {
      actorLine.append(document.createTextNode("No actor fields"));
    }
    actorCell.append(actorLine);
    if (event.process) {
      actorCell.append(
        node(
          "span",
          "cell-sub",
          `${event.process}${event.pid ? ` [${event.pid}]` : ""}`
        )
      );
    }

    const traceCell = document.createElement("td");
    traceCell.append(node("span", "cell-title", event.evidence_filename));
    traceCell.append(
      node("span", "cell-sub", `Line ${event.line_number}, byte ${event.byte_offset}`)
    );
    const traceMeta = node("span", "cell-sub");
    traceMeta.append(
      badge(
        event.evidence_integrity_status,
        INTEGRITY_TONES[event.evidence_integrity_status] || "neutral"
      )
    );
    traceMeta.append(document.createTextNode(` ${event.evidence_sha256.slice(0, 12)}...`));
    traceCell.append(traceMeta);

    row.append(timeCell, eventCell, sourceCell, actorCell, traceCell);
    body.append(row);
  }

  const from = state.timeline.length ? state.timelineOffset + 1 : 0;
  const to = state.timelineOffset + state.timeline.length;
  $("#timeline-page-label").textContent = `${formatNumber(from)}-${formatNumber(to)} of ${formatNumber(state.timelineTotal)} events`;
  $("#timeline-prev").disabled = state.timelineOffset === 0;
  $("#timeline-next").disabled =
    state.timelineOffset + state.timelineLimit >= state.timelineTotal;
  if (orderingRule) {
    const help = $(".timeline-help");
    if (help) help.title = orderingRule;
  }
}

async function openEventById(eventId) {
  const dialog = $("#event-dialog");
  const body = $("#event-dialog-body");
  $("#event-dialog-title").textContent = "Loading event";
  clear(body);
  body.append(node("p", "muted", "Loading event detail..."));
  if (!dialog.open) dialog.showModal();
  const token = ++state.eventRequestToken;
  try {
    const event = await api(`/events/${eventId}`);
    if (token !== state.eventRequestToken) return;
    renderEventDialog(event);
  } catch (error) {
    if (token !== state.eventRequestToken) return;
    $("#event-dialog-title").textContent = "Event unavailable";
    clear(body);
    const note = node("div", "warn-note bad", `Could not load event detail. ${errorMessage(error)}`);
    body.append(note);
    const retry = node("button", "secondary", "Retry");
    retry.type = "button";
    retry.addEventListener("click", () => openEventById(eventId));
    body.append(retry);
  }
}

function renderEventDialog(event) {
  $("#event-dialog-title").textContent = `${typeLabel(event.event_type)} - line ${event.line_number}`;
  const body = $("#event-dialog-body");
  clear(body);

  const badges = node("div", "flag-row");
  badges.style.marginBottom = "12px";
  badges.append(badge(event.event_type, EVENT_TONES[event.event_type] || "info"));
  badges.append(badge(event.source_type, "neutral"));
  badges.append(
    badge(event.timestamp_status, TIMESTAMP_TONES[event.timestamp_status] || "warn")
  );
  badges.append(
    badge(event.ordering_status, ORDERING_TONES[event.ordering_status] || "neutral")
  );
  badges.append(
    badge(
      event.evidence_integrity_status,
      INTEGRITY_TONES[event.evidence_integrity_status] || "neutral"
    )
  );
  if (event.dedup_status === "duplicate") badges.append(badge("duplicate", "warn"));
  body.append(badges);

  if (event.timestamp_status !== "normalized") {
    body.append(
      node(
        "div",
        "warn-note",
        event.timestamp_detail ||
          "This event has no trustworthy UTC timestamp. The original timestamp text is preserved and the event is kept in the timeline."
      )
    );
  }
  if (event.ordering_status === "tied") {
    body.append(
      node(
        "div",
        "warn-note info",
        event.ordering_note ||
          "This event shares its normalized timestamp with another event. The displayed order is deterministic, not a claim about real-world order."
      )
    );
  }
  if (event.ordering_status === "unresolved") {
    body.append(
      node(
        "div",
        "warn-note",
        event.ordering_note ||
          "This event has no resolved UTC time. Its timeline position is based on evidence receipt and line order only."
      )
    );
  }
  if (event.dedup_status === "duplicate") {
    body.append(
      node(
        "div",
        "warn-note info",
        `This is a linked duplicate of event ${event.duplicate_of_event_id ?? "unknown"}. Both rows are retained; deduplication does not delete evidence.`
      )
    );
  }
  if (event.clock_offset_applied) {
    body.append(
      node(
        "div",
        "warn-note info",
        `A configured source clock offset of ${event.clock_offset_seconds} seconds was applied to the normalized UTC time.`
      )
    );
  }

  const observed = node("section", "detail-section");
  observed.append(node("p", "section-title", "Observed record"));
  observed.append(
    node(
      "p",
      "help",
      "These values come from the preserved source record and its evidence trace."
    )
  );
  const observedGrid = node("div", "detail-grid");
  observedGrid.append(
    detailBlock("Source", event.source_name),
    detailBlock("Source type", sourceTypeLabel(event.source_type)),
    detailBlock("Hostname", event.hostname),
    detailBlock("Source IP", event.source_ip),
    detailBlock("Username", event.username),
    detailBlock(
      "Process",
      event.process ? `${event.process}${event.pid ? ` [${event.pid}]` : ""}` : null
    ),
    detailBlock("Evidence file", event.evidence_filename, true),
    detailBlock("Trace location", `Line ${event.line_number}, byte ${event.byte_offset}`, true),
    detailBlock("Evidence received", formatUtc(event.evidence_received_at)),
    detailBlock("Evidence collected", formatUtc(event.evidence_collected_at)),
    detailBlock("Evidence size", formatBytes(event.evidence_size_bytes)),
    detailBlock("Evidence SHA-256", event.evidence_sha256, true),
    detailBlock(
      "Evidence integrity",
      `${titleCase(event.evidence_integrity_status)}${event.evidence_last_verified_at ? ` (last verified ${formatUtc(event.evidence_last_verified_at)})` : ""}`
    ),
    detailBlock("Original timestamp", event.original_timestamp_string, true),
    detailBlock("Original timezone", event.original_timezone || "not supplied"),
    detailBlock("Timestamp precision", event.timestamp_precision || "unknown")
  );
  observed.append(observedGrid);
  observed.append(node("p", "section-title", "Raw source line"));
  observed.append(node("pre", "raw", event.raw_line));
  body.append(observed);

  const derived = node("section", "detail-section");
  derived.append(node("p", "section-title", "Derived analysis"));
  derived.append(
    node(
      "p",
      "help",
      "These values are generated by CyberTrace from the observed record. They are not additional source evidence."
    )
  );
  const derivedGrid = node("div", "detail-grid");
  derivedGrid.append(
    detailBlock("Normalized UTC", formatUtc(event.timestamp_utc), true),
    detailBlock("Timestamp status", titleCase(event.timestamp_status)),
    detailBlock("Timestamp detail", event.timestamp_detail),
    detailBlock("Ordering status", titleCase(event.ordering_status)),
    detailBlock("Ordering note", event.ordering_note),
    detailBlock("Event category", titleCase(event.event_category)),
    detailBlock("Event type", event.event_type),
    detailBlock("Duplicate status", titleCase(event.dedup_status)),
    detailBlock(
      "Duplicate of event",
      event.duplicate_of_event_id === null ? "not a duplicate" : event.duplicate_of_event_id
    ),
    detailBlock("Fingerprint SHA-256", event.fingerprint_sha256 || "not available", true),
    detailBlock(
      "Clock offset",
      event.clock_offset_seconds === null
        ? "none recorded"
        : `${event.clock_offset_seconds} seconds${event.clock_offset_applied ? " (applied)" : " (recorded, not applied)"}`
    ),
    detailBlock("Event id", event.id)
  );
  if (event.event_type === "http_request") {
    derivedGrid.append(
      detailBlock("HTTP method", event.http_method),
      detailBlock("HTTP path", event.http_path, true),
      detailBlock("HTTP status", event.http_status),
      detailBlock("Response bytes", event.http_bytes),
      detailBlock("Referer", event.http_referer),
      detailBlock("User agent", event.http_user_agent)
    );
  }
  derived.append(derivedGrid);
  body.append(derived);

  const metadata = node("section", "detail-section");
  metadata.append(node("p", "section-title", "Structured metadata"));
  metadata.append(node("pre", "raw", JSON.stringify(event.extra || {}, null, 2)));
  body.append(metadata);

  const actions = node("div", "inline-actions");
  const download = node("a", "secondary", "Download original evidence");
  download.href = event.evidence_download_url;
  download.target = "_blank";
  download.rel = "noopener";
  download.style.padding = "7px 11px";
  download.style.border = "1px solid var(--border)";
  download.style.borderRadius = "7px";
  download.style.textDecoration = "none";
  const verifyButton = node("button", "secondary", "Verify evidence hash");
  verifyButton.type = "button";
  verifyButton.addEventListener("click", () => {
    verifyEvidence(event.evidence_file_id, verifyButton, () => {
      openEventById(event.id);
    });
  });
  actions.append(download, verifyButton);
  body.append(actions);
}

async function onRefresh(event) {
  const button = event.currentTarget;
  await withBusy(button, async () => {
    await loadInvestigations(false);
    if (state.currentId) {
      await loadWorkspace();
      toast("Dashboard refreshed.", "success");
    } else {
      renderNoInvestigation();
    }
  });
}

async function onCoverageWindowChange() {
  if (!state.currentId) return;
  state.coverage = null;
  chips($("#coverage-chips"), []);
  tableMessage($("#source-body"), 7, "Loading coverage window...");
  chips($("#gap-chips"), []);
  tableMessage($("#gap-body"), 7, "Loading collection gaps...");
  await loadCoverage(state.requestToken);
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
      $("#create-investigation-form").closest("details").open = false;
      toast("Investigation created.", "success");
      await loadInvestigations(false);
      await loadWorkspace();
    } catch (error) {
      toast(errorMessage(error), "error");
    }
  });
}

init().catch((error) => {
  showGlobalAlert(`CyberTrace dashboard failed to initialize. ${errorMessage(error)}`);
  toast(errorMessage(error), "error");
});
