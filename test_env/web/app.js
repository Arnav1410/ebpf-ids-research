"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const unavailable = "unavailable";
  const precisionUnavailable = "unavailable (integer precision)";
  const state = {
    snapshot: null,
    selectedKey: null,
    lastSuccess: null,
    failure: null,
    inFlight: false,
  };

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  }

  function exact(value) {
    if (value === null || value === undefined) return unavailable;
    if (typeof value !== "number" || !Number.isFinite(value)) return unavailable;
    return Number.isSafeInteger(value) ? String(value) : precisionUnavailable;
  }

  function count(value) {
    if (typeof value === "number" && Number.isSafeInteger(value)) return value.toLocaleString();
    return exact(value);
  }

  function rate(value) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return unavailable;
    if (value > Number.MAX_SAFE_INTEGER) return precisionUnavailable;
    return value.toLocaleString(undefined, { maximumFractionDigits: 2 });
  }

  function safeJSON(value) {
    return JSON.stringify(value, (_key, item) => {
      if (typeof item === "number" && (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item)))) {
        return precisionUnavailable;
      }
      return item;
    }, 2);
  }

  function display(value) {
    if (value === null || value === undefined) return unavailable;
    if (typeof value === "number") return exact(value);
    if (typeof value === "boolean") return value ? "yes" : "no";
    return typeof value === "object" ? safeJSON(value) : String(value);
  }

  function text(id, value) {
    byId(id).textContent = value;
  }

  function facts(container, rows) {
    container.replaceChildren();
    for (const [label, value] of rows) {
      container.append(node("dt", label), node("dd", display(value)));
    }
  }

  function emptyRow(body, columns, message) {
    const row = node("tr");
    const cell = node("td", message, "empty");
    cell.colSpan = columns;
    row.append(cell);
    body.append(row);
  }

  function cell(row, value, className) {
    const element = node("td", value, className);
    row.append(element);
    return element;
  }

  function flowKey(row, index) {
    return Number.isSafeInteger(row.flow.id) ? `id-${row.flow.id}` : `precision-row-${index}`;
  }

  function selectedFlow() {
    return state.snapshot?.flows.find((row, index) => flowKey(row, index) === state.selectedKey);
  }

  function classificationText(row) {
    if (row.classification_state === "unclassified") return "Pending / unclassified";
    if (row.classification_state === "failed") return `Failed · status ${exact(row.classification?.status)}`;
    return `Scored · numeric label ${exact(row.classification?.label)}`;
  }

  function classificationClass(row) {
    if (row.classification_state === "classified") return "scored";
    return row.classification_state === "failed" ? "failed" : "pending";
  }

  function endpoint(address, port) {
    return `${display(address)}:${exact(port)}`;
  }

  function tuple(key) {
    if (!key) return unavailable;
    return `${endpoint(key.a_addr, key.a_port)} ↔ ${endpoint(key.b_addr, key.b_port)}`;
  }

  function renderMode() {
    const snapshot = state.snapshot;
    const banner = byId("mode-banner");
    if (!snapshot) return;
    banner.className = `mode-banner ${snapshot.mode}`;
    banner.textContent = snapshot.mode === "replay"
      ? "SIMULATED REPLAY — recorded data only · not a live producer"
      : "LIVE — localhost collector · kernel-produced telemetry";
  }

  function renderConnection() {
    const snapshot = state.snapshot;
    const elapsed = state.lastSuccess === null ? null : performance.now() - state.lastSuccess;
    const expired = elapsed !== null && elapsed > 3500;
    const readerDisconnected = snapshot?.mode === "live" &&
      (snapshot.health.connected !== true || snapshot.health.producer_alive === false);
    const stale = Boolean(state.failure || expired || readerDisconnected);
    const status = byId("connection-status");
    const notice = byId("freshness-notice");
    byId("dashboard").classList.toggle("stale", stale);
    status.className = stale ? "disconnected" : snapshot ? "connected" : "";
    notice.classList.toggle("alert", stale);

    if (state.failure) {
      status.textContent = "DISCONNECTED · STALE";
      notice.textContent = snapshot
        ? "Fetch failed. All values below are the last successful snapshot and are STALE. Retrying automatically every second."
        : "Fetch failed. No snapshot is available. Retrying automatically every second.";
      text("poll-status", state.failure);
    } else if (readerDisconnected) {
      status.textContent = "DISCONNECTED · STALE";
      notice.textContent = "The API is reachable, but the live reader or producer is disconnected. Retained telemetry is STALE; it is not current traffic.";
      text("poll-status", `Reader: ${display(snapshot.health.reader_status)} · reconnect polled automatically`);
    } else if (expired) {
      status.textContent = "DISCONNECTED · STALE";
      notice.textContent = "No complete API refresh has arrived recently. Displayed values are STALE. A pending request will time out and reconnect automatically.";
      text("poll-status", "Waiting for a complete refresh");
    } else if (snapshot?.mode === "replay") {
      status.textContent = "REPLAY API CONNECTED";
      const progress = snapshot.health.replay_progress;
      const progressText = progress
        ? `${count(progress.visible)} / ${count(progress.total)} recorded events revealed${progress.complete ? " · complete" : ""}`
        : "Recorded events only";
      notice.textContent = `SIMULATED: every value below is from replay, including events originally marked live. ${progressText}. No current hooks, rates or live flow activity are claimed.`;
      text("poll-status", "API refreshed · simulated reader, no live connection expected");
    } else if (snapshot) {
      status.textContent = "LIVE READER CONNECTED";
      notice.textContent = "Latest complete API refresh shown. Endpoints are independent collector snapshots, not an atomic kernel transaction. No inference is performed by this page.";
      text("poll-status", `Reader: ${display(snapshot.health.reader_status)} · refresh every second`);
    } else {
      status.textContent = "CONNECTING";
    }
  }

  function renderOverview() {
    const { summary, events, mode } = state.snapshot;
    const rates = mode === "live" ? summary.rates : null;
    text("ingress-rate", rate(rates?.hook_packets_per_second?.ingress));
    text("egress-rate", rate(rates?.hook_packets_per_second?.egress));
    text("inference-rate", rate(rates?.inference_per_second?.complete));
    text("rate-scope", mode === "replay"
      ? "SIMULATED REPLAY: live TC hook and inference rates are unavailable. Recorded per-flow direction counts are not hook rates."
      : `Measured interval: ${exact(rates?.interval_ns)} ns · sample timestamp: ${exact(rates?.timestamp_ns)} monotonic ns. RX/TX are TC hooks, not canonical A → B / B → A directions.`);
    text("label-zero", count(summary.numeric_labels?.["0"]));
    text("label-one", count(summary.numeric_labels?.["1"]));
    text("failed-classifications", count(summary.failed_classifications));
    text("label-scope", `${display(summary.scope)}. Labels 0 and 1 have UNVERIFIED meanings; no accuracy or class semantics are claimed.`);
    const last = events.slice().reverse().find((event) => event.status === 0 && (event.label === 0 || event.label === 1));
    text("last-prediction", last ? `Numeric label ${exact(last.label)}` : "No retained scored result");
    text("prediction-context", last
      ? `Latest scored arrival · flow ${exact(last.flow_id)} · sequence ${exact(last.sequence)} · ${exact(last.timestamp_ns)} monotonic ns · meaning UNVERIFIED`
      : "Pending flows and failed classifications are not predictions");
  }

  function select(key) {
    state.selectedKey = key;
    if (!key) byId("selected-only").checked = false;
    renderFlows();
    renderFlowDetails();
    renderEvents();
  }

  function renderFlows() {
    const { flows, summary, mode } = state.snapshot;
    const pending = flows.filter((row) => row.classification_state === "unclassified").length;
    const scored = flows.filter((row) => row.classification_state === "classified").length;
    const failed = flows.filter((row) => row.classification_state === "failed").length;
    text("flow-counts", `${count(flows.length)} retained · ${count(pending)} pending / unclassified · ${count(scored)} scored · ${count(failed)} failed`);
    const inspection = summary.flow_inspection;
    text("flow-scope", mode === "replay"
      ? "SIMULATED: these flows project recorded event tuples, state and valid count prefixes only. Current activity, map occupancy and missing fields are unavailable. Unclassified means no retained score, not a predicted label."
      : inspection
        ? `${display(inspection.scope)} · retained ${count(inspection.flows_retained)} / observed total ${count(inspection.flows_total)} · source row limit ${count(inspection.source_row_limit)} · truncated: ${display(inspection.flows_truncated)} · snapshot ${exact(inspection.snapshot_ns)}–${exact(inspection.snapshot_end_ns)} monotonic ns. No retained score does not prove a flow was never classified.`
        : "No flow inspection snapshot available yet. Pending / unclassified means no retained score, not a numeric label. Flow and classification histories are independently bounded.");

    const focusedKey = document.activeElement?.dataset?.flowKey;
    const body = byId("flow-body");
    body.replaceChildren();
    flows.forEach((row, index) => {
      const key = flowKey(row, index);
      const flow = row.flow;
      const tr = node("tr");
      if (key === state.selectedKey) tr.classList.add("selected");
      cell(tr, exact(flow.id), "numeric");
      const tupleCell = cell(tr, undefined, "tuple");
      tupleCell.append(node("span", tuple(flow.key)), node("span", `Protocol ${exact(flow.key?.protocol)} · ifindex ${exact(flow.key?.ifindex)}`, "tuple-meta"));
      cell(tr, classificationText(row), classificationClass(row));
      cell(tr, `${display(flow.state)} · activity ${row.active === null || row.active === undefined ? "unknown" : row.active ? "active" : "inactive"}`);
      cell(tr, `${count(flow.a_to_b?.packets)} / ${count(flow.b_to_a?.packets)}`, "numeric");
      const button = node("button", key === state.selectedKey ? "Selected" : "Details");
      button.type = "button";
      button.dataset.flowKey = key;
      button.setAttribute("aria-label", `Inspect flow ${exact(flow.id)}`);
      button.setAttribute("aria-pressed", String(key === state.selectedKey));
      button.addEventListener("click", () => select(key));
      cell(tr).append(button);
      body.append(tr);
      if (focusedKey === key) button.focus({ preventScroll: true });
    });
    if (!flows.length) emptyRow(body, 6, "No flows in the retained snapshot. This is not a claim that no traffic exists.");
  }

  function renderFlowDetails() {
    const row = selectedFlow();
    const container = byId("flow-details");
    byId("clear-selection").disabled = !row;
    byId("selected-only").disabled = !row;
    container.replaceChildren();
    if (!row) {
      container.append(node("p", "Select a flow to inspect observed counts and its last retained kernel result. Pending / unclassified is not a prediction.", "muted"));
      return;
    }
    const flow = row.flow;
    container.append(node("p", classificationText(row), classificationClass(row)));
    const details = node("dl", undefined, "facts");
    facts(details, [
      ["Flow ID", flow.id], ["Canonical tuple", tuple(flow.key)],
      ["Protocol / ifindex", `${exact(flow.key?.protocol)} / ${exact(flow.key?.ifindex)}`],
      ["Initiator", flow.initiator], ["State", flow.state],
      ["Currently active", row.active], ["Observed ordinal", flow.ordinal],
      ["First (monotonic ns)", flow.first_ns], ["Last (monotonic ns)", flow.last_ns],
      ["Closed (monotonic ns)", flow.closed_ns],
    ]);
    container.append(details, node("h4", "Canonical direction observations"));
    const table = node("table", undefined, "direction-table");
    const head = node("thead");
    const header = node("tr");
    for (const label of ["Observed field", "A → B", "B → A"]) {
      const th = node("th", label);
      th.scope = "col";
      header.append(th);
    }
    head.append(header);
    const body = node("tbody");
    for (const [field, label] of [
      ["packets", "Packets"], ["ipv4_bytes", "IPv4 bytes"],
      ["tcp_segment_bytes", "TCP segment bytes"], ["tcp_header_bytes", "TCP header bytes"],
      ["min_segment_bytes", "Min segment bytes"], ["max_segment_bytes", "Max segment bytes"],
      ["first_ns", "First monotonic ns"], ["last_ns", "Last monotonic ns"], ["max_iat_ns", "Max IAT ns"],
    ]) {
      const tr = node("tr");
      cell(tr, label);
      cell(tr, exact(flow.a_to_b?.[field]));
      cell(tr, exact(flow.b_to_a?.[field]));
      body.append(tr);
    }
    table.append(head, body);
    container.append(table, node("p", "Canonical directions are not RX/TX. Zero-valued fields are shown as reported; missing values are unavailable.", "muted"));
    container.append(node("h4", "Last retained kernel classification"));
    if (!row.classification) {
      container.append(node("p", "No retained kernel score for this flow. No label is inferred.", "muted"));
      return;
    }
    const event = row.classification;
    const prediction = node("dl", undefined, "facts");
    facts(prediction, [
      ["Numeric label", event.status === 0 ? event.label : null], ["Label meaning", "UNVERIFIED"],
      ["Status code", event.status], ["Sequence", event.sequence], ["Trigger", event.reason],
      ["Trigger ordinal", event.trigger_ordinal], ["Timestamp (monotonic ns)", event.timestamp_ns],
      ["Model ID", event.model_id], ["Stage bitmap", event.stage_bitmap],
      ["Features (recorded)", event.features], ["Output (recorded)", event.output],
      ["Counts valid", event.counts_valid], ["Counts ordinal", event.counts_ordinal],
      ["Counts timestamp (monotonic ns)", event.counts_timestamp_ns],
    ]);
    container.append(prediction);
  }

  function renderEvents() {
    const { events, summary } = state.snapshot;
    const selected = selectedFlow();
    const filtered = byId("selected-only").checked && selected;
    const rows = filtered ? events.filter((event) => Number.isSafeInteger(event.flow_id) && event.flow_id === selected.flow.id) : events;
    const flowIndices = new Map();
    state.snapshot.flows.forEach((row, index) => {
      if (Number.isSafeInteger(row.flow.id)) flowIndices.set(row.flow.id, index);
    });
    text("event-count", count(events.length));
    text("event-caption", `${count(rows.length)} shown / ${count(events.length)} retained${filtered ? " · selected flow filter" : ""} · capacity ${count(summary.history_capacity)} · newest arrival first`);
    const body = byId("event-body");
    body.replaceChildren();
    for (const event of rows.slice().reverse()) {
      const tr = node("tr");
      cell(tr, exact(event.sequence), "numeric");
      const flowCell = cell(tr);
      const index = Number.isSafeInteger(event.flow_id) ? flowIndices.get(event.flow_id) : undefined;
      if (index !== undefined) {
        const button = node("button", exact(event.flow_id), "link-button");
        button.type = "button";
        button.setAttribute("aria-label", `Inspect flow ${exact(event.flow_id)} from event ${exact(event.sequence)}`);
        button.addEventListener("click", () => {
          select(flowKey(state.snapshot.flows[index], index));
          byId("flow-details").scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
        flowCell.append(button);
      } else {
        flowCell.textContent = exact(event.flow_id);
      }
      cell(tr, exact(event.trigger_ordinal), "numeric");
      cell(tr, exact(event.timestamp_ns), "numeric");
      cell(tr, event.status === 0 ? `${exact(event.label)} · UNVERIFIED` : "No score", event.status === 0 ? "scored" : "failed");
      cell(tr, event.status === 0 ? "0 · completed" : `${exact(event.status)} · failed`, event.status === 0 ? "" : "failed");
      cell(tr, display(event.reason));
      cell(tr, event.counts_valid === true ? exact(event.counts_ordinal) : "unavailable · counts invalid");
      body.append(tr);
    }
    if (!rows.length) emptyRow(body, 8, filtered ? "No retained events match this flow." : "No classification events in the retained history yet.");
  }

  function renderDiagnostics() {
    const { health, summary, mode } = state.snapshot;
    const sequence = health.sequence;
    text("kernel-drops", mode === "live" ? count(health.kernel_ring_drops) : "unavailable · replay");
    text("python-drops", count(health.python_queue_drops));
    text("queue-status", `Queue ${count(health.queue_size)} / ${count(health.queue_capacity)} · policy: ${display(health.queue_policy)}`);
    text("sequence-holes", count(sequence?.sequence_gaps));
    text("sequence-scope", `Recent unresolved: ${count(sequence?.recent_unresolved_gaps)} · finalized outside window: ${count(sequence?.finalized_gaps)}. Holes are not a drop total and are never added to kernel / Python drops.`);
    const journal = health.journal;
    facts(byId("diagnostic-details"), [
      ["Reader status / generation", `${display(health.reader_status)} / ${exact(health.reader_generation)}`],
      ["Reader decode errors", health.reader_decode_errors], ["Schema errors", health.schema_errors],
      ["Collector error count", health.error_count], ["Highest received sequence", sequence?.highest_received],
      ["Duplicate sequences", sequence?.duplicates], ["Late outside sequence window", sequence?.late_outside_window],
      ["Sequence window capacity", sequence?.window_capacity],
      ["History retained / capacity", `${count(summary.retained_classifications)} / ${count(summary.history_capacity)}`],
      ["Classified flows retained / flow capacity", `${count(summary.retained_classified_flows)} / ${count(summary.flow_capacity)}`],
      ["History retention evictions", health.history_retention_evictions],
      ["Classification retention evictions", health.classification_retention_evictions],
      ["Flow retention evictions", health.flow_retention_evictions],
      ["Journal", journal === null || journal === undefined ? "unavailable / disabled" : journal],
    ]);
    const errors = byId("collector-errors");
    errors.replaceChildren();
    if (Array.isArray(health.errors) && health.errors.length) {
      errors.append(node("h4", "Retained collector errors"));
      const list = node("ul");
      for (const error of health.errors) list.append(node("li", display(error)));
      errors.append(list);
    }
    const source = health.source || summary.source || {};
    const sourceRows = [
      ["Model ID", source.model_id], ["Owner PID", source.owner_pid],
      ["Reader connected", health.connected], ["Producer alive", health.producer_alive],
      ["Interface", health.interface], ["Namespace", health.namespace],
      ["Source timestamp (monotonic ns)", health.source_timestamp_ns],
      ["Native receive timestamp (monotonic ns)", health.last_native_received_monotonic_ns],
    ];
    for (const field of ["ring_map_id", "counters_map_id", "sequence_map_id", "slots_map_id", "control_map_id", "hook_counts_map_id", "flow_stats_map_id"]) {
      sourceRows.push([field.replaceAll("_", " "), source[field]]);
    }
    facts(byId("source-details"), sourceRows);
    text("source-counters", safeJSON({
      inference_counters: summary.inference_counters ?? null,
      hook_counts: mode === "live" ? summary.hook_counts ?? null : null,
      hooks_verified_at_start_only: health.hooks ?? null,
    }));
  }

  function hasUnsafeInteger(value) {
    if (typeof value === "number") return !Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value));
    if (!value || typeof value !== "object") return false;
    return Object.values(value).some(hasUnsafeInteger);
  }

  function renderSnapshot() {
    const flows = state.snapshot.flows;
    if (state.selectedKey?.startsWith("precision-row-") || !flows.some((row, index) => flowKey(row, index) === state.selectedKey)) {
      state.selectedKey = null;
      byId("selected-only").checked = false;
    }
    renderMode();
    renderOverview();
    renderFlows();
    renderFlowDetails();
    renderEvents();
    renderDiagnostics();
    const unsafe = hasUnsafeInteger(state.snapshot);
    byId("precision-notice").classList.toggle("alert", unsafe);
    text("precision-notice", unsafe
      ? "PRECISION WARNING: the API returned integers outside JavaScript’s exact range. Affected values are unavailable (integer precision), not exact rounded claims. Unsafe flow IDs cannot be correlated with events."
      : "Integer safety: values outside JavaScript’s exact integer range are displayed as unavailable, not rounded claims. All kernel timestamps remain monotonic nanoseconds.");
  }

  async function fetchSnapshot() {
    if (state.inFlight) return;
    state.inFlight = true;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    try {
      const names = ["health", "summary", "flows", "events"];
      const envelopes = await Promise.all(names.map(async (name) => {
        const response = await fetch(`/${name}`, { cache: "no-store", signal: controller.signal });
        if (!response.ok) throw new Error(`/${name}: HTTP ${response.status}`);
        return response.json();
      }));
      const mode = envelopes[0]?.mode;
      if (mode !== "live" && mode !== "replay") throw new Error("Unknown API mode");
      if (!envelopes.every((item) => item?.schema_version === 1 && item.mode === mode && item.simulated === (mode === "replay") && item.data !== undefined)) {
        throw new Error("Inconsistent API envelopes; refusing mixed live / replay data");
      }
      const [health, summary, flows, events] = envelopes.map((item) => item.data);
      if (!health || !summary || !Array.isArray(flows) || !Array.isArray(events) || !flows.every((row) => row && row.flow)) {
        throw new Error("Invalid API state shape");
      }
      state.snapshot = { mode, health, summary, flows, events };
      state.lastSuccess = performance.now();
      state.failure = null;
      renderSnapshot();
    } catch (error) {
      controller.abort();
      state.failure = error.name === "AbortError" ? "API refresh timed out" : `API refresh failed: ${error.message}`;
    } finally {
      clearTimeout(timeout);
      state.inFlight = false;
      renderConnection();
    }
  }

  byId("clear-selection").addEventListener("click", () => select(null));
  byId("selected-only").addEventListener("change", () => {
    if (state.snapshot) renderEvents();
  });
  fetchSnapshot();
  setInterval(() => {
    renderConnection();
    fetchSnapshot();
  }, 1000);
})();
