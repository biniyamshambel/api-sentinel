/* API Sentinel dashboard logic.
 *
 * Security notes:
 *  - All target-controlled values are rendered with textContent / DOM text nodes.
 *  - No innerHTML is used for report data.
 *  - Report values used in class names are whitelisted.
 */

(() => {
  "use strict";

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEVERITY_LABELS = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
  };
  const CHECK_LABELS = {
    pass: "PASS",
    warn: "WARN",
    fail: "FAIL",
    not_applicable: "N/A",
    unknown: "?",
  };
  const CHECK_CLASSES = {
    pass: "is-pass",
    warn: "is-warn",
    fail: "is-fail",
    not_applicable: "is-na",
    unknown: "is-unknown",
  };
  const RISK_LEVELS = ["low", "moderate", "high", "critical"];

  const state = {
    report: null,
    filter: "all",
    busy: false,
  };

  const dom = {};

  function cacheDom() {
    const ids = [
      "system-state",
      "system-state-text",
      "scan-panel",
      "scan-form",
      "target-url",
      "scan-button",
      "scan-button-label",
      "scan-spinner",
      "demo-button",
      "error-banner",
      "error-title",
      "error-message",
      "demo-note",
      "loading",
      "loading-target",
      "empty-state",
      "results",
      "results-heading",
      "target-url-display",
      "scan-time",
      "redirect-summary",
      "demo-badge",
      "download-button",
      "reachability-card",
      "reachability-value",
      "reachability-note",
      "status-value",
      "status-note",
      "application-value",
      "application-note",
      "latency-value",
      "risk-card",
      "risk-score",
      "risk-level",
      "risk-progress",
      "risk-note",
      "findings-count",
      "severity-filters",
      "findings-list",
      "findings-empty",
      "checks-list",
      "score-method",
      "weight-list",
      "score-bands",
      "score-disclaimer",
      "limitations-list",
      "redirect-panel",
      "redirect-count",
      "redirect-list",
      "redirect-problem",
      "redirect-problem-text",
      "sr-announcer",
      "app-version",
      "finding-template",
      "check-template",
      "group-template",
    ];
    for (const id of ids) {
      dom[id.replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase())] = document.getElementById(id);
    }
  }

  function init() {
    cacheDom();
    dom.scanForm.addEventListener("submit", handleSubmit);
    dom.demoButton.addEventListener("click", loadDemo);
    dom.downloadButton.addEventListener("click", downloadReport);
    dom.downloadButton.disabled = true;
    dom.targetUrl.addEventListener("input", () => {
      if (!dom.errorBanner.hidden) hideError();
    });
    dom.severityFilters.addEventListener("click", handleFilterClick);
    loadHealth();
  }

  async function fetchJson(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          ...(options.headers || {}),
        },
      });

      let body = null;
      try {
        body = await response.json();
      } catch {
        body = null;
      }

      if (!response.ok) {
        const error = new Error(
          extractErrorMessage(body) || `Request failed with HTTP ${response.status}.`
        );
        error.status = response.status;
        error.code = body && typeof body.code === "string" ? body.code : null;
        throw error;
      }
      return body;
    } finally {
      window.clearTimeout(timer);
    }
  }

  function extractErrorMessage(body) {
    if (!body) return "";
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail
        .map((item) => (item && typeof item.msg === "string" ? item.msg : ""))
        .filter(Boolean)
        .join(" ");
    }
    if (body.detail && typeof body.detail.message === "string") {
      return body.detail.message;
    }
    return "";
  }

  function setSystemState(kind, text) {
    dom.systemState.dataset.state = kind;
    dom.systemStateText.textContent = text;
  }

  async function loadHealth() {
    setSystemState("checking", "Checking service…");
    try {
      const health = await fetchJson("/api/health", {}, 6000);
      if (!health || health.status !== "ok") {
        throw new Error("Unexpected health response.");
      }
      setSystemState("online", `Service online · v${health.version}`);
      dom.appVersion.textContent = `v${health.version}`;
    } catch {
      setSystemState("offline", "Service unavailable");
    }
  }

  function validateTarget(raw) {
    if (!raw) {
      return "Enter an API URL, for example https://api.example.com/health.";
    }
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return "Enter a complete URL including http:// or https://.";
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "Only http:// and https:// URLs can be assessed.";
    }
    if (parsed.username || parsed.password) {
      return "URLs containing embedded usernames or passwords are not permitted.";
    }
    return null;
  }

  function handleSubmit(event) {
    event.preventDefault();
    if (state.busy) return;

    const raw = dom.targetUrl.value.trim();
    const problem = validateTarget(raw);
    if (problem) {
      showError("Check the target URL", problem);
      dom.targetUrl.focus();
      return;
    }
    runScan(raw);
  }

  async function runScan(url) {
    state.report = null;
    startBusy(`Requesting ${url} and validating its destination…`);
    try {
      const report = await fetchJson(
        "/api/scan",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        },
        40000
      );
      setBusy(false);
      renderReport(report);
      announce(
        `Assessment complete. Risk score ${report.risk_score} out of 100, ${riskLabel(
          report.risk_level
        )}. ${(report.findings || []).length} findings.`
      );
    } catch (error) {
      setBusy(false);
      if (error && error.name === "AbortError") {
        showError(
          "Scan timed out",
          "API Sentinel did not finish within 40 seconds. The target may be slow or unresponsive. Try again or choose a different endpoint."
        );
      } else if (error instanceof TypeError) {
        showError(
          "Cannot reach API Sentinel",
          "The browser could not contact the local backend. Confirm the Uvicorn server is running at http://127.0.0.1:8000."
        );
      } else {
        showError("Scan could not be completed", error.message || "An unexpected error occurred.");
      }
    }
  }

  async function loadDemo() {
    if (state.busy) return;
    state.report = null;
    startBusy("Loading the locally generated sample report…");
    try {
      const report = await fetchJson("/api/demo", {}, 10000);
      setBusy(false);
      renderReport(report);
      announce("Sample report loaded. No outbound request was made.");
    } catch (error) {
      setBusy(false);
      showError(
        "Sample report unavailable",
        error.message || "The demo endpoint could not be loaded."
      );
    }
  }

  function startBusy(message) {
    state.busy = true;
    state.filter = "all";
    hideError();
    dom.demoNote.hidden = true;
    dom.emptyState.hidden = true;
    dom.results.hidden = true;
    dom.loading.hidden = false;
    dom.loadingTarget.textContent = message;
    dom.scanButton.disabled = true;
    dom.demoButton.disabled = true;
    dom.downloadButton.disabled = true;
    dom.scanButtonLabel.textContent = "Scanning…";
    dom.scanSpinner.hidden = false;
    dom.scanPanel.setAttribute("aria-busy", "true");
    dom.loading.scrollIntoView({ block: "nearest", behavior: prefersReducedMotion() ? "auto" : "smooth" });
  }

  function setBusy(busy) {
    state.busy = busy;
    dom.scanButton.disabled = busy;
    dom.demoButton.disabled = busy;
    dom.scanButtonLabel.textContent = busy ? "Scanning…" : "Scan API";
    dom.scanSpinner.hidden = !busy;
    dom.scanPanel.setAttribute("aria-busy", String(busy));
    dom.loading.hidden = !busy;
    dom.downloadButton.disabled = busy || !state.report;
  }

  function showError(title, message) {
    dom.errorTitle.textContent = title;
    dom.errorMessage.textContent = message;
    dom.errorBanner.hidden = false;
    dom.errorBanner.focus({ preventScroll: true });
    dom.errorBanner.scrollIntoView({ block: "nearest", behavior: prefersReducedMotion() ? "auto" : "smooth" });
    announce(`${title}. ${message}`);
  }

  function hideError() {
    dom.errorBanner.hidden = true;
    dom.errorTitle.textContent = "Scan could not start";
    dom.errorMessage.textContent = "";
  }

  function riskLabel(level) {
    const safe = RISK_LEVELS.includes(level) ? level : "low";
    return safe.charAt(0).toUpperCase() + safe.slice(1);
  }

  function severityLabel(severity) {
    return SEVERITY_LABELS[severity] || "Info";
  }

  function prefersReducedMotion() {
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function renderReport(report) {
    if (!report || typeof report !== "object") {
      showError("Unexpected response", "The server returned an empty or invalid report.");
      return;
    }

    state.report = report;
    state.filter = "all";
    hideError();

    const findings = Array.isArray(report.findings) ? report.findings : [];
    const checks = Array.isArray(report.checks) ? report.checks : [];
    const limitations = Array.isArray(report.limitations) ? report.limitations : [];
    const chain = Array.isArray(report.redirect_chain) ? report.redirect_chain : [];

    dom.emptyState.hidden = true;
    dom.results.hidden = false;
    dom.demoNote.hidden = !report.demo;
    dom.demoBadge.hidden = !report.demo;

    dom.targetUrlDisplay.textContent = report.target_url || "Unknown target";
    if (report.final_url && report.final_url !== report.target_url) {
      dom.targetUrlDisplay.title = `Final URL: ${report.final_url}`;
    } else {
      dom.targetUrlDisplay.removeAttribute("title");
    }

    const scanned = new Date(report.scanned_at);
    if (Number.isNaN(scanned.getTime())) {
      dom.scanTime.textContent = report.scanned_at ? `Scanned ${report.scanned_at}` : "Scan time unavailable";
    } else {
      dom.scanTime.textContent = `Scanned ${scanned.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      })}`;
      dom.scanTime.title = report.scanned_at;
    }

    const redirectCount = Number.isInteger(report.redirect_count) ? report.redirect_count : 0;
    dom.redirectSummary.textContent = report.redirect_problem
      ? "Redirect not followed"
      : redirectCount === 0
        ? "No redirects"
        : `${redirectCount} redirect${redirectCount === 1 ? "" : "s"} followed`;

    renderReachability(report);
    renderHttpStatus(report);
    renderApplication(report);
    renderLatency(report);
    renderRisk(report, findings);
    renderFilters(findings);
    renderFindings(findings);
    renderChecks(checks);
    renderScoreModel(report.risk_model);
    renderLimitations(limitations);
    renderRedirects(chain, report);

    dom.resultsHeading.textContent = "Assessment complete";
    dom.downloadButton.disabled = false;
    dom.results.scrollIntoView({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
  }

  function setMetricState(card, kind) {
    card.classList.remove("status-good", "status-warn", "status-bad");
    if (kind) card.classList.add(kind);
  }

  function renderReachability(report) {
    dom.reachabilityValue.textContent = report.reachable ? "Reachable" : "Unreachable";
    setMetricState(dom.reachabilityCard, report.reachable ? "status-good" : "status-bad");
    if (report.reachable) {
      dom.reachabilityNote.textContent = "An HTTP response was received.";
    } else {
      dom.reachabilityNote.textContent =
        (report.error && report.error.message) || "No HTTP response was received.";
    }
  }

  function renderHttpStatus(report) {
    const status = report.http_status;
    if (typeof status !== "number") {
      dom.statusValue.textContent = "No response";
      setMetricState(dom.statusValue.closest(".metric-card"), "status-bad");
      dom.statusNote.textContent = "The target did not return an HTTP status.";
      return;
    }

    dom.statusValue.textContent = String(status);
    dom.statusNote.textContent = report.http_reason || "HTTP response";
    if (status >= 200 && status < 300) {
      setMetricState(dom.statusValue.closest(".metric-card"), "status-good");
    } else if (status >= 300 && status < 400) {
      setMetricState(dom.statusValue.closest(".metric-card"), "status-warn");
    } else {
      setMetricState(dom.statusValue.closest(".metric-card"), "status-bad");
    }
  }

  function renderApplication(report) {
    const card = dom.applicationValue.closest(".metric-card");
    if (report.application_ok === true) {
      dom.applicationValue.textContent = "2xx success";
      dom.applicationNote.textContent = "Successful application-layer response.";
      setMetricState(card, "status-good");
    } else if (report.application_ok === false) {
      dom.applicationValue.textContent =
        typeof report.http_status === "number" ? `${report.http_status} response` : "Not successful";
      dom.applicationNote.textContent = "Reachable does not mean the application succeeded.";
      setMetricState(card, "status-bad");
    } else {
      dom.applicationValue.textContent = "Not received";
      dom.applicationNote.textContent = "No application response could be assessed.";
      setMetricState(card, "status-warn");
    }
  }

  function renderLatency(report) {
    const card = dom.latencyValue.closest(".metric-card");
    const ms = report.response_time_ms;
    if (typeof ms !== "number") {
      dom.latencyValue.textContent = "—";
      setMetricState(card, null);
      return;
    }
    dom.latencyValue.textContent = `${Math.round(ms)} ms`;
    if (ms >= 3000) {
      setMetricState(card, "status-bad");
    } else if (ms >= 1000) {
      setMetricState(card, "status-warn");
    } else {
      setMetricState(card, "status-good");
    }
  }

  function renderRisk(report, findings) {
    const score = Number.isFinite(report.risk_score) ? Math.max(0, Math.min(100, report.risk_score)) : 0;
    const level = RISK_LEVELS.includes(report.risk_level) ? report.risk_level : "low";
    dom.riskCard.className = `metric-card risk-card risk-${level}`;
    dom.riskScore.textContent = String(Math.round(score));
    dom.riskLevel.textContent = riskLabel(level);
    dom.riskProgress.value = score;
    dom.riskProgress.setAttribute("aria-valuetext", `${Math.round(score)} out of 100, ${riskLabel(level)}`);
    dom.riskNote.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"} · capped at 100`;
  }

  function renderFilters(findings) {
    dom.severityFilters.textContent = "";
    const counts = new Map();
    for (const severity of SEVERITIES) counts.set(severity, 0);
    for (const finding of findings) {
      const severity = SEVERITIES.includes(finding.severity) ? finding.severity : "info";
      counts.set(severity, (counts.get(severity) || 0) + 1);
    }

    dom.severityFilters.appendChild(createFilterButton("all", "All", findings.length));
    for (const severity of SEVERITIES) {
      const count = counts.get(severity) || 0;
      if (count > 0) {
        dom.severityFilters.appendChild(
          createFilterButton(severity, severityLabel(severity), count)
        );
      }
    }
    dom.severityFilters.hidden = findings.length === 0;
    updateFilterButtons();
  }

  function createFilterButton(filter, label, count) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "filter-chip" + (filter === "all" ? "" : ` filter-${filter}`);
    button.dataset.filter = filter;
    button.textContent = `${label} ${count}`;
    button.setAttribute("aria-pressed", String(state.filter === filter));
    return button;
  }

  function handleFilterClick(event) {
    const button = event.target.closest("button[data-filter]");
    if (!button) return;
    const filter = button.dataset.filter;
    if (filter !== "all" && !SEVERITIES.includes(filter)) return;
    state.filter = filter;
    updateFilterButtons();
    applyFilter();
  }

  function updateFilterButtons() {
    const buttons = dom.severityFilters.querySelectorAll("button[data-filter]");
    for (const button of buttons) {
      button.setAttribute("aria-pressed", String(button.dataset.filter === state.filter));
    }
  }

  function applyFilter() {
    const groups = dom.findingsList.querySelectorAll(".finding-group");
    for (const group of groups) {
      group.hidden = state.filter !== "all" && group.dataset.severity !== state.filter;
    }
  }

  function renderFindings(findings) {
    dom.findingsList.textContent = "";
    dom.findingsCount.textContent = String(findings.length);
    dom.findingsEmpty.hidden = findings.length !== 0;

    const ordered = [...findings].sort((a, b) => {
      const severityDelta =
        severityIndex(a.severity) - severityIndex(b.severity);
      if (severityDelta !== 0) return severityDelta;
      return (Number(b.weight) || 0) - (Number(a.weight) || 0);
    });

    for (const severity of SEVERITIES) {
      const groupFindings = ordered.filter(
        (finding) => normalizeSeverity(finding.severity) === severity
      );
      if (groupFindings.length === 0) continue;

      const group = dom.groupTemplate.content.firstElementChild.cloneNode(true);
      group.dataset.severity = severity;
      group.querySelector(".group-title").textContent = severityLabel(severity);
      group.querySelector(".group-count").textContent = `${groupFindings.length} finding${
        groupFindings.length === 1 ? "" : "s"
      }`;
      const container = group.querySelector(".group-items");
      for (const finding of groupFindings) {
        container.appendChild(renderFinding(finding, severity));
      }
      dom.findingsList.appendChild(group);
    }

    applyFilter();
  }

  function renderFinding(finding, severity) {
    const node = dom.findingTemplate.content.firstElementChild.cloneNode(true);
    node.querySelector(".severity-badge").textContent = severityLabel(severity);
    node.querySelector(".finding-title").textContent = finding.title || "Untitled finding";
    node.querySelector(".finding-description").textContent = finding.description || "";
    node.querySelector(".evidence-code").textContent = finding.evidence || "No evidence recorded.";
    node.querySelector(".recommendation-text").textContent =
      finding.recommendation || "No recommendation provided.";
    node.querySelector(".finding-category").textContent = finding.category || "General";
    const weight = Number(finding.weight) || 0;
    node.querySelector(".finding-weight").textContent =
      weight === 0 ? "0 points (informational)" : `${weight} points`;
    return node;
  }

  function severityIndex(severity) {
    const index = SEVERITIES.indexOf(normalizeSeverity(severity));
    return index === -1 ? SEVERITIES.length : index;
  }

  function normalizeSeverity(severity) {
    return SEVERITIES.includes(severity) ? severity : "info";
  }

  function renderChecks(checks) {
    dom.checksList.textContent = "";
    if (checks.length === 0) {
      const item = document.createElement("li");
      item.className = "check-item";
      item.textContent = "No check details were returned.";
      dom.checksList.appendChild(item);
      return;
    }

    for (const check of checks) {
      const status = CHECK_CLASSES[check.status] ? check.status : "unknown";
      const item = dom.checkTemplate.content.firstElementChild.cloneNode(true);
      const statusNode = item.querySelector(".check-status");
      statusNode.textContent = CHECK_LABELS[status] || "?";
      statusNode.classList.add(CHECK_CLASSES[status]);
      item.querySelector(".check-label").textContent = check.label || check.id || "Check";
      item.querySelector(".check-detail").textContent = check.detail || "";
      dom.checksList.appendChild(item);
    }
  }

  function renderScoreModel(model) {
    dom.scoreMethod.textContent =
      (model && model.method) || "Additive rule-based risk score.";
    dom.weightList.textContent = "";

    const weights = (model && model.weights) || {};
    for (const severity of SEVERITIES) {
      if (!(severity in weights)) continue;
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = severityLabel(severity);
      const value = document.createElement("code");
      value.textContent = `${weights[severity]} pts`;
      item.append(label, value);
      dom.weightList.appendChild(item);
    }

    const bands = (model && model.bands) || {};
    const bandParts = [];
    for (const level of RISK_LEVELS) {
      if (level in bands) {
        bandParts.push(`${riskLabel(level)} ${bands[level]}`);
      }
    }
    dom.scoreBands.textContent = bandParts.length
      ? `Bands: ${bandParts.join(" · ")}`
      : "";
    dom.scoreDisclaimer.textContent =
      (model && model.disclaimer) ||
      "The score is a project rubric, not a validated industry-standard risk rating.";
  }

  function renderLimitations(limitations) {
    dom.limitationsList.textContent = "";
    for (const limitation of limitations) {
      const item = document.createElement("li");
      item.textContent = String(limitation);
      dom.limitationsList.appendChild(item);
    }
  }

  function renderRedirects(chain, report) {
    dom.redirectList.textContent = "";
    const count = Number.isInteger(report.redirect_count) ? report.redirect_count : 0;
    dom.redirectCount.textContent = String(count);

    if (chain.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No redirect chain was recorded.";
      dom.redirectList.appendChild(item);
    } else {
      for (const url of chain) {
        const item = document.createElement("li");
        item.textContent = String(url);
        dom.redirectList.appendChild(item);
      }
    }

    if (report.redirect_problem) {
      const problem = report.redirect_problem;
      dom.redirectProblem.hidden = false;
      dom.redirectProblemText.textContent = `${problem.message} Destination: ${problem.location}`;
      dom.redirectPanel.open = true;
    } else {
      dom.redirectProblem.hidden = true;
      dom.redirectProblemText.textContent = "";
      dom.redirectPanel.open = count > 0;
    }
  }

  function downloadReport() {
    if (!state.report) return;
    const text = JSON.stringify(state.report, null, 2);
    const blob = new Blob([text], { type: "application/json" });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");

    let host = "report";
    try {
      host = new URL(state.report.target_url).hostname || "report";
    } catch {
      host = "report";
    }
    const hostPart = host.replace(/[^a-z0-9.-]/gi, "_");
    const stamp = String(state.report.scanned_at || "")
      .replace(/[:.]/g, "-")
      .replace(/[^a-zA-Z0-9-]/g, "");
    anchor.href = objectUrl;
    anchor.download = `api-sentinel-${hostPart}-${stamp || Date.now()}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    announce("JSON report downloaded.");
  }

  function announce(message) {
    dom.srAnnouncer.textContent = "";
    window.setTimeout(() => {
      dom.srAnnouncer.textContent = message;
    }, 60);
  }

  init();
})();
