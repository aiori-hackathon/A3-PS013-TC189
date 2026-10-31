const API = "/api";
const REFRESH_MS = 15000;

const state = {
  investigations: [],
  fleet: null,
  agents: [],
  selectedAgentId: null,
  selectedAgent: null,
  loadingList: false,
  listRequestId: 0,
  detailRequestId: 0,
  lastUpdated: null,
  toastTimer: null,
};

const els = {
  fleetPill: document.getElementById("fleet-pill"),
  agentCount: document.getElementById("agent-count"),
  fleetDescription: document.getElementById("fleet-description"),
  fleetUpdated: document.getElementById("fleet-updated"),
  pageAlert: document.getElementById("page-alert"),
  investigationFilter: document.getElementById("investigation-filter"),
  healthFilter: document.getElementById("health-filter"),
  refreshButton: document.getElementById("refresh-button"),
  adminToken: document.getElementById("admin-token"),
  agentRows: document.getElementById("agent-rows"),
  agentListNote: document.getElementById("agent-list-note"),
  metricTotal: document.getElementById("metric-total"),
  metricTotalDetail: document.getElementById("metric-total-detail"),
  metricOnline: document.getElementById("metric-online"),
  metricAttention: document.getElementById("metric-attention"),
  metricAttentionDetail: document.getElementById("metric-attention-detail"),
  metricQueue: document.getElementById("metric-queue"),
  metricQueueDetail: document.getElementById("metric-queue-detail"),
  detailPanel: document.getElementById("detail-panel"),
  detailEmpty: document.getElementById("detail-empty"),
  detailTitle: document.getElementById("detail-title"),
  detailSubtitle: document.getElementById("detail-subtitle"),
  detailBadges: document.getElementById("detail-badges"),
  detailActions: document.getElementById("detail-actions"),
  detailError: document.getElementById("detail-error"),
  detailMeta: document.getElementById("detail-meta"),
  sourceRows: document.getElementById("source-rows"),
  batchRows: document.getElementById("batch-rows"),
  errorRows: document.getElementById("error-rows"),
  toast: document.getElementById("toast"),
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDetail(data) {
  const detail = data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (detail && typeof detail === "object") {
    if (typeof detail.message === "string" && detail.message.trim()) {
      return detail.message;
    }
    if (Array.isArray(detail)) {
      const messages = detail
        .map((item) => item?.msg || item?.message)
        .filter((item) => typeof item === "string" && item.trim());
      if (messages.length) return messages.join("; ");
    }
  }
  return "";
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API}${path}`, {
      ...options,
      headers: { Accept: "application/json", ...(options.headers || {}) },
    });
  } catch {
    throw new Error("Could not reach the CyberTrace API.");
  }

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!response.ok) {
    throw new Error(
      formatDetail(data) || `Request failed with HTTP ${response.status}.`,
    );
  }
  return data;
}

function formatTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function formatRelative(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const future = seconds > 0;
  const magnitude = Math.abs(seconds);
  if (magnitude < 45) return future ? "in a moment" : "just now";
  const units = [
    ["year", 31536000],
    ["month", 2592000],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, size] of units) {
    if (magnitude >= size) {
      const amount = Math.round(magnitude / size);
      const label = `${amount} ${unit}${amount === 1 ? "" : "s"}`;
      return future ? `in ${label}` : `${label} ago`;
    }
  }
  return future ? "in a moment" : "just now";
}

function formatBytes(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = number;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  const digits = amount >= 10 || unit === 0 ? 0 : 1;
  return `${amount.toFixed(digits)} ${units[unit]}`;
}

function badge(label, tone) {
  return `<span class="badge ${tone}">${escapeHtml(label)}</span>`;
}

function healthTone(health) {
  return {
    online: "good",
    stale: "warn",
    never_seen: "info",
    disabled: "neutral",
  }[health] || "neutral";
}

function runtimeTone(runtime) {
  return {
    running: "good",
    degraded: "warn",
    stopped: "bad",
    unknown: "neutral",
  }[runtime] || "neutral";
}

function sourceTone(status) {
  return {
    healthy: "good",
    error: "bad",
    disabled: "neutral",
    unknown: "info",
  }[status] || "neutral";
}

function batchTone(status) {
  return {
    processed: "good",
    partial: "warn",
    failed: "bad",
    received: "info",
  }[status] || "neutral";
}

function humanize(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function investigationName(id) {
  const match = state.investigations.find((item) => item.id === id);
  return match ? match.name : id || "Unknown";
}

function timeCell(value) {
  if (!value) return `<span class="text-muted">Never</span>`;
  return `<span class="nowrap">${escapeHtml(formatTime(value))}</span>
    <div class="cell-sub">${escapeHtml(formatRelative(value))}</div>`;
}

function showToast(message, tone = "") {
  els.toast.textContent = message;
  els.toast.className = `toast show ${tone}`.trim();
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => {
    els.toast.className = "toast";
  }, 4800);
}

function showAlert(message) {
  els.pageAlert.textContent = message;
  els.pageAlert.hidden = false;
}

function clearAlert() {
  els.pageAlert.hidden = true;
  els.pageAlert.textContent = "";
}

function setListLoading(loading, { initial = false } = {}) {
  state.loadingList = loading;
  els.refreshButton.disabled = loading;
  els.refreshButton.classList.toggle("loading", loading);
  if (loading && initial) {
    els.agentRows.innerHTML =
      '<tr><td class="empty-cell" colspan="8">Loading registered agents…</td></tr>';
  }
}

function renderFleet() {
  const fleet = state.fleet;
  if (!fleet) {
    els.fleetPill.className = "badge neutral";
    els.fleetPill.textContent = "fleet unavailable";
    return;
  }

  const tone = fleet.status === "ok" ? "good" : fleet.status === "empty" ? "info" : "warn";
  const label =
    fleet.status === "ok"
      ? "fleet healthy"
      : fleet.status === "empty"
        ? "no agents registered"
        : "fleet degraded";
  els.fleetPill.className = `badge ${tone}`;
  els.fleetPill.textContent = label;

  els.agentCount.textContent = String(fleet.total_agents);
  els.metricTotal.textContent = String(fleet.total_agents);
  els.metricTotalDetail.textContent = `${fleet.online} online · ${fleet.never_seen} never seen · ${fleet.disabled} disabled`;
  els.metricOnline.textContent = String(fleet.online);
  els.metricAttention.textContent = String(fleet.stale);
  els.metricAttentionDetail.textContent = `${fleet.stale} stale · ${fleet.agents_with_errors} reporting errors`;
  els.metricQueue.textContent = String(fleet.pending_batches);
  els.metricQueueDetail.textContent = `${formatBytes(fleet.pending_bytes)} pending across agents`;

  if (fleet.status === "ok") {
    els.fleetDescription.textContent =
      "Health, collection inventory and delivery outcomes reported by registered agents.";
  } else if (fleet.status === "empty") {
    els.fleetDescription.textContent =
      "No agents have registered yet. Install an agent and enroll it with the server.";
  } else {
    els.fleetDescription.textContent =
      "One or more agents are stale or reporting errors. Review the fleet table for details.";
  }
}

function renderAgentRows() {
  if (!state.agents.length) {
    const noFleet = state.fleet && state.fleet.total_agents === 0;
    const message = noFleet
      ? "No agents registered yet. Install an agent and enroll it with the server."
      : "No agents match the current investigation and health filters.";
    els.agentRows.innerHTML = `<tr><td class="empty-cell" colspan="8">${escapeHtml(message)}</td></tr>`;
    els.agentListNote.textContent = noFleet
      ? "No registered agents"
      : "No agents match the current filters";
    return;
  }

  els.agentRows.innerHTML = state.agents
    .map((agent) => {
      const selected = agent.id === state.selectedAgentId ? " selected" : "";
      const errorHint = agent.last_error
        ? `<div class="health-reason">Error reported ${escapeHtml(formatRelative(agent.last_error_at))}</div>`
        : "";
      return `<tr class="${selected}" data-agent-row="${escapeHtml(agent.id)}">
        <td>
          <button type="button" class="agent-name-button" data-agent-id="${escapeHtml(agent.id)}">
            ${escapeHtml(agent.display_name)}
          </button>
          <div class="agent-sub">${escapeHtml(agent.hostname)} · ${escapeHtml(agent.platform)} · v${escapeHtml(agent.agent_version)}</div>
        </td>
        <td>
          <div class="health-cell">
            ${badge(humanize(agent.health), healthTone(agent.health))}
            ${errorHint}
          </div>
        </td>
        <td>${badge(humanize(agent.runtime_status), runtimeTone(agent.runtime_status))}</td>
        <td>${timeCell(agent.last_seen_at)}</td>
        <td>${escapeHtml(investigationName(agent.investigation_id))}</td>
        <td>
          <strong>${agent.source_count}</strong>
          <div class="cell-sub">${agent.batch_count} batch${agent.batch_count === 1 ? "" : "es"}</div>
        </td>
        <td>
          <strong>${agent.queue_pending_batches}</strong>
          <div class="cell-sub">${escapeHtml(formatBytes(agent.queue_pending_bytes))}</div>
        </td>
        <td>${agent.batch_count}</td>
      </tr>`;
    })
    .join("");

  const total = state.fleet?.total_agents ?? state.agents.length;
  els.agentListNote.textContent = `${state.agents.length} shown · ${total} registered`;
}

function detailMetaItem(label, value, { wide = false, code = false } = {}) {
  const content = code
    ? `<code>${escapeHtml(value || "—")}</code>`
    : `<strong>${escapeHtml(value || "—")}</strong>`;
  return `<div class="detail${wide ? " wide" : ""}"><span>${escapeHtml(label)}</span>${content}</div>`;
}

function renderDetail() {
  const agent = state.selectedAgent;
  if (!agent) return;

  els.detailPanel.hidden = false;
  els.detailEmpty.hidden = true;
  els.detailTitle.textContent = agent.display_name;
  els.detailSubtitle.textContent = `${agent.hostname} · ${agent.agent_uid}`;
  els.detailBadges.innerHTML = [
    badge(humanize(agent.health), healthTone(agent.health)),
    badge(humanize(agent.runtime_status), runtimeTone(agent.runtime_status)),
    badge(humanize(agent.status), agent.status === "disabled" ? "neutral" : "teal"),
  ].join("");

  const actionButton =
    agent.status === "disabled"
      ? '<button type="button" class="secondary mini-button" data-agent-action="enable">Enable agent</button>'
      : '<button type="button" class="secondary mini-button" data-agent-action="disable">Disable agent</button>';
  els.detailActions.innerHTML = `${actionButton}
    <button type="button" class="secondary mini-button danger-button" data-agent-action="delete">Delete agent</button>`;

  if (agent.last_error) {
    els.detailError.hidden = false;
    els.detailError.textContent = `${agent.last_error} (reported ${formatTime(agent.last_error_at)})`;
  } else {
    els.detailError.hidden = true;
    els.detailError.textContent = "";
  }

  els.detailMeta.innerHTML = [
    detailMetaItem("Investigation", investigationName(agent.investigation_id), { wide: true }),
    detailMetaItem("Agent UID", agent.agent_uid, { code: true, wide: true }),
    detailMetaItem("Platform", agent.platform),
    detailMetaItem("Agent version", agent.agent_version),
    detailMetaItem("Registered", formatTime(agent.registered_at)),
    detailMetaItem("Last seen", formatTime(agent.last_seen_at)),
    detailMetaItem("Last heartbeat", formatTime(agent.last_heartbeat_at)),
    detailMetaItem("Last collection", formatTime(agent.last_collection_at)),
    detailMetaItem("Queue", `${agent.queue_pending_batches} batches`, { wide: true }),
    detailMetaItem("Queue bytes", formatBytes(agent.queue_pending_bytes)),
    detailMetaItem("Sources", String(agent.source_count)),
    detailMetaItem("Batches", String(agent.batch_count)),
  ].join("");

  renderSources(agent);
  renderBatches(agent);
  renderErrors(agent);
}

function renderSources(agent) {
  if (!agent.sources.length) {
    els.sourceRows.innerHTML =
      '<tr><td class="empty-cell" colspan="6">No sources registered.</td></tr>';
    return;
  }
  els.sourceRows.innerHTML = agent.sources
    .map((source) => {
      const sourceLabel = `${escapeHtml(source.name)}
        <div class="cell-sub">${escapeHtml(source.source_key)}${source.path_hint ? ` · ${escapeHtml(source.path_hint)}` : ""}</div>`;
      const status = source.enabled ? source.status : "disabled";
      const lastError = source.last_error
        ? `<div class="detail-error-cell">${escapeHtml(source.last_error)}</div>
           <div class="cell-sub">${escapeHtml(formatRelative(source.last_error_at))}</div>`
        : '<span class="text-muted">None</span>';
      const cursor =
        source.cursor_bytes === null || source.cursor_bytes === undefined
          ? '<span class="text-muted">—</span>'
          : `<span class="mono">${escapeHtml(formatBytes(source.cursor_bytes))}</span>`;
      return `<tr data-source-id="${escapeHtml(source.id)}">
        <td>${sourceLabel}</td>
        <td>${escapeHtml(humanize(source.source_type))}</td>
        <td>${badge(humanize(status), sourceTone(status))}</td>
        <td>${timeCell(source.last_collected_at)}</td>
        <td>${cursor}</td>
        <td>${lastError}</td>
      </tr>`;
    })
    .join("");
}

function renderBatches(agent) {
  if (!agent.recent_batches.length) {
    els.batchRows.innerHTML =
      '<tr><td class="empty-cell" colspan="8">No batches received.</td></tr>';
    return;
  }
  els.batchRows.innerHTML = agent.recent_batches
    .map(
      (batch) => `<tr>
        <td>
          <span class="batch-id">${escapeHtml(batch.batch_id)}</span>
          <div class="cell-sub">${escapeHtml(formatBytes(batch.byte_count))} · ${batch.file_count} file${batch.file_count === 1 ? "" : "s"}</div>
        </td>
        <td>${badge(humanize(batch.status), batchTone(batch.status))}</td>
        <td>${timeCell(batch.received_at)}</td>
        <td>${batch.file_count}</td>
        <td>${batch.accepted_items}</td>
        <td>${batch.duplicate_items}</td>
        <td class="${batch.failed_items ? "text-bad" : ""}">${batch.failed_items}</td>
        <td class="${batch.error_count ? "text-warn" : ""}">${batch.error_count}</td>
      </tr>`,
    )
    .join("");
}

function renderErrors(agent) {
  if (!agent.recent_errors.length) {
    els.errorRows.innerHTML =
      '<tr><td class="empty-cell" colspan="5">No errors reported.</td></tr>';
    return;
  }
  const sources = new Map(agent.sources.map((source) => [source.id, source]));
  els.errorRows.innerHTML = agent.recent_errors
    .map((error) => {
      const source = sources.get(error.source_id);
      const sourceLabel = source
        ? `${escapeHtml(source.name)}<div class="cell-sub">${escapeHtml(source.source_key)}</div>`
        : '<span class="text-muted">Agent</span>';
      return `<tr>
        <td>${timeCell(error.occurred_at)}</td>
        <td><code>${escapeHtml(error.error_code)}</code></td>
        <td>${sourceLabel}</td>
        <td class="detail-error-cell">${escapeHtml(error.message)}</td>
        <td>${timeCell(error.reported_at)}</td>
      </tr>`;
    })
    .join("");
}

function markSelectedRow() {
  for (const row of els.agentRows.querySelectorAll("[data-agent-row]")) {
    row.classList.toggle("selected", row.dataset.agentRow === state.selectedAgentId);
  }
}

function clearDetail() {
  state.selectedAgentId = null;
  state.selectedAgent = null;
  els.detailPanel.hidden = true;
  els.detailEmpty.hidden = false;
  els.detailError.hidden = true;
  markSelectedRow();
}

async function loadInvestigations() {
  const data = await api("/investigations");
  state.investigations = Array.isArray(data) ? data : [];
  const current = els.investigationFilter.value;
  els.investigationFilter.innerHTML = [
    '<option value="">All investigations</option>',
    ...state.investigations.map(
      (investigation) =>
        `<option value="${escapeHtml(investigation.id)}">${escapeHtml(investigation.name)}</option>`,
    ),
  ].join("");
  if (current && state.investigations.some((item) => item.id === current)) {
    els.investigationFilter.value = current;
  }
}

async function loadFleet() {
  const data = await api("/agents/health");
  state.fleet = data;
  renderFleet();
}

function filterQuery() {
  const params = new URLSearchParams();
  if (els.investigationFilter.value) {
    params.set("investigation_id", els.investigationFilter.value);
  }
  if (els.healthFilter.value) {
    params.set("health", els.healthFilter.value);
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

async function loadAgents({ initial = false } = {}) {
  const requestId = ++state.listRequestId;
  setListLoading(true, { initial });
  try {
    const data = await api(`/agents${filterQuery()}`);
    if (requestId !== state.listRequestId) return;
    state.agents = Array.isArray(data.items) ? data.items : [];
    renderAgentRows();
    markSelectedRow();
    state.lastUpdated = new Date();
    els.fleetUpdated.textContent = `Updated ${state.lastUpdated.toLocaleTimeString()}`;
  } catch (error) {
    if (requestId !== state.listRequestId) return;
    if (!state.agents.length) {
      els.agentRows.innerHTML =
        '<tr><td class="empty-cell" colspan="8">Agent data is unavailable.</td></tr>';
    }
    els.agentListNote.textContent = "Refresh failed";
    showAlert(`Could not load agents: ${error.message}`);
  } finally {
    if (requestId === state.listRequestId) setListLoading(false);
  }
}

async function loadAgentDetail(agentId) {
  const requestId = ++state.detailRequestId;
  const target = agentId;
  try {
    const data = await api(`/agents/${encodeURIComponent(target)}`);
    if (requestId !== state.detailRequestId || state.selectedAgentId !== target) return;
    state.selectedAgent = data;
    renderDetail();
  } catch (error) {
    if (requestId !== state.detailRequestId || state.selectedAgentId !== target) return;
    els.detailTitle.textContent = "Agent unavailable";
    els.detailSubtitle.textContent = error.message;
    els.detailBadges.innerHTML = "";
    els.detailActions.innerHTML = "";
    els.detailMeta.innerHTML = "";
    els.sourceRows.innerHTML =
      '<tr><td class="empty-cell" colspan="6">Source inventory is unavailable.</td></tr>';
    els.batchRows.innerHTML =
      '<tr><td class="empty-cell" colspan="8">Batch history is unavailable.</td></tr>';
    els.errorRows.innerHTML =
      '<tr><td class="empty-cell" colspan="5">Reported errors are unavailable.</td></tr>';
    showAlert(`Could not load agent detail: ${error.message}`);
  }
}

async function selectAgent(agentId) {
  if (!agentId) {
    clearDetail();
    return;
  }
  state.selectedAgentId = agentId;
  state.selectedAgent = null;
  els.detailPanel.hidden = false;
  els.detailEmpty.hidden = true;
  els.detailTitle.textContent = "Loading agent…";
  els.detailSubtitle.textContent = "";
  els.detailBadges.innerHTML = "";
  els.detailActions.innerHTML = "";
  els.detailError.hidden = true;
  els.detailMeta.innerHTML = "";
  els.sourceRows.innerHTML =
    '<tr><td class="empty-cell" colspan="6">Loading sources…</td></tr>';
  els.batchRows.innerHTML =
    '<tr><td class="empty-cell" colspan="8">Loading batches…</td></tr>';
  els.errorRows.innerHTML =
    '<tr><td class="empty-cell" colspan="5">Loading errors…</td></tr>';
  markSelectedRow();
  await loadAgentDetail(agentId);
}

async function refreshAll({ initial = false } = {}) {
  clearAlert();
  try {
    await loadFleet();
  } catch (error) {
    showAlert(`Could not load fleet health: ${error.message}`);
  }
  await loadAgents({ initial });
  if (state.selectedAgentId) {
    await loadAgentDetail(state.selectedAgentId);
  }
}

async function adminRequest(path, method, { refresh = true } = {}) {
  const token = els.adminToken.value.trim();
  if (!token) {
    showToast("Enter the enrollment token before using a management action.", "error");
    els.adminToken.focus();
    return false;
  }
  try {
    const data = await api(path, {
      method,
      headers: { "X-Enrollment-Token": token },
    });
    showToast(data?.message || "Action completed.", "success");
    if (refresh) await refreshAll();
    return true;
  } catch (error) {
    showToast(`Management action failed: ${error.message}`, "error");
    return false;
  }
}

async function handleDetailAction(action) {
  const agent = state.selectedAgent;
  if (!agent) return;
  if (action === "disable" || action === "enable") {
    await adminRequest(`/agents/${encodeURIComponent(agent.id)}/${action}`, "POST");
    return;
  }
  if (action === "delete") {
    const confirmed = window.confirm(
      `Delete registration and delivery history for ${agent.display_name}? ` +
        "Preserved evidence and timeline events are retained.",
    );
    if (!confirmed) return;
    const deleted = await adminRequest(
      `/agents/${encodeURIComponent(agent.id)}`,
      "DELETE",
      { refresh: false },
    );
    if (deleted) {
      clearDetail();
      await refreshAll();
    }
  }
}

function bindEvents() {
  els.refreshButton.addEventListener("click", () => refreshAll());

  for (const filter of [els.investigationFilter, els.healthFilter]) {
    filter.addEventListener("change", () => {
      clearDetail();
      clearAlert();
      loadAgents();
    });
  }

  els.agentRows.addEventListener("click", (event) => {
    const button = event.target.closest("[data-agent-id]");
    if (!button) return;
    selectAgent(button.dataset.agentId);
  });

  els.detailActions.addEventListener("click", (event) => {
    const button = event.target.closest("[data-agent-action]");
    if (!button) return;
    handleDetailAction(button.dataset.agentAction);
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshAll();
  });
}

async function init() {
  bindEvents();
  try {
    await loadInvestigations();
  } catch (error) {
    showAlert(`Could not load investigations: ${error.message}`);
  }
  await refreshAll({ initial: true });
  setInterval(() => {
    if (!document.hidden) refreshAll();
  }, REFRESH_MS);
}

init();
