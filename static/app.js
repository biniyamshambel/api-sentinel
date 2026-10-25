/* API Sentinel dashboard logic.
 *
 * Security notes:
 *  - All target-controlled values are rendered with textContent / DOM text nodes.
 *  - No innerHTML is used for report data.
 *  - Report values used in class names are whitelisted.
 *  - Browser history stores summaries only, with query strings removed.
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
  const HISTORY_KEY = "api-sentinel-history-v1";
  const HISTORY_LIMIT = 5;

  const state = {
    report: null,
    filter: "all",
    busy: false,
    exporting: false,
  };

  const dom = {};

  function cacheDom() {
    const ids = [
      "system-state",
      "system-state-text",
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
      "report-id",
      "pdf-button",
      "pdf-button-label",
      "pdf-spinner",
      "download-button",
      "export-status",
      "reachability-card",
      "reachability-value",
      "reachability-note",
      "status-card",
      "status-value",
      "status-note",
      "latency-card",
      "latency-value",
      "latency-note",
      "findings-stat-card",
      "findings-stat-value",
      "findings-stat-note",
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
      "history-list",
      "history-empty",
      "history-clear",
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
    dom.pdfButton.addEventListener("click", downloadPdf);
    dom.downloadButton.addEventListener("click", downloadReport);
    dom.historyClear.addEventListener("click", clearHistory);
    dom.pdfButton.disabled = true;
    dom.downloadButton.disabled = true;
    dom.targetUrl.addEventListener("input", () => {
      if (!dom.errorBanner.hidden) hideError();
    });
    dom.severityFilters.addEventListener("click", handleFilterClick);
    renderHistory(loadHistory());
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
    if (state.busy || state.exporting) return;

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
        `Assessment complete. Security score ${report.risk_score} out of 100, ${riskLabel(
          report.risk_level
        )}. ${(report.findings || []).length} findings.`
      );
    } catch (error) {
      setBusy(false);
      dom.emptyState.hidden = false;
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
    if (state.busy || state.exporting) return;
    state.report = null;
    startBusy("Loading the locally generated sample report…");
    try {
      const report = await fetchJson("/api/demo", {}, 10000);
      setBusy(false);
      renderReport(report);
      announce("Sample report loaded. No outbound request was made.");
    } catch (error) {
      setBusy(false);
      dom.emptyState.hidden = false;
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
    setExportStatus("");
    dom.demoNote.hidden = true;
    dom.emptyState.hidden = true;
    dom.results.hidden = true;
    dom.loading.hidden = false;
    dom.loadingTarget.textContent = message;
    dom.scanButton.disabled = true;
    dom.demoButton.disabled = true;
    dom.pdfButton.disabled = true;
    dom.downloadButton.disabled = true;
    dom.scanButtonLabel.textContent = "Scanning…";
    dom.scanSpinner.hidden = false;
    dom.scanForm.setAttribute("aria-busy", "true");
    dom.loading.scrollIntoView({ block: "nearest", behavior: prefersReducedMotion() ? "auto" : "smooth" });
  }

  function setBusy(busy) {
    state.busy = busy;
    dom.scanButton.disabled = busy;
    dom.demoButton.disabled = busy;
    dom.scanButtonLabel.textContent = busy ? "Scanning…" : "Run Security Scan";
    dom.scanSpinner.hidden = !busy;
    dom.scanForm.setAttribute("aria-busy", String(busy));
    dom.loading.hidden = !busy;
    updateExportControls();
  }

  function updateExportControls() {
    const available = Boolean(state.report) && !state.busy && !state.exporting;
    dom.pdfButton.disabled = !available;
    dom.downloadButton.disabled = !available;
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

    dom.targetUrlDisplay.textContent = displayUrl(report.target_url) || "Unknown target";
    if (report.final_url && report.final_url !== report.target_url) {
      dom.targetUrlDisplay.title = `Final URL: ${displayUrl(report.final_url)}`;
    } else {
      dom.targetUrlDisplay.removeAttribute("title");
    }

    const scanned = new Date(report.scanned_at);
    if (Number.isNaN(scanned.getTime())) {
      dom.scanTime.textContent = report.scanned_at ? `Scanned ${report.scanned_at}` : "Scan time unavailable";
      dom.scanTime.title = "";
    } else {
      dom.scanTime.textContent = `Scanned ${scanned.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      })}`;
      dom.scanTime.title = report.scanned_at;
    }

    dom.reportId.textContent = report.report_id ? `Report ${report.report_id}` : "";

    const redirectCount = Number.isInteger(report.redirect_count) ? report.redirect_count : 0;
    dom.redirectSummary.textContent = report.redirect_problem
      ? "Redirect not followed"
      : redirectCount === 0
        ? "No redirects"
        : `${redirectCount} redirect${redirectCount === 1 ? "" : "s"} followed`;

    renderReachability(report);
    renderHttpStatus(report);
    renderLatency(report);
    renderFindingsStat(findings);
    renderRisk(report, findings);
    renderFilters(findings);
    renderFindings(findings);
    renderChecks(checks);
    renderScoreModel(report.risk_model);
    renderLimitations(limitations);
    renderRedirects(chain, report);

    dom.resultsHeading.textContent = "Assessment complete";
    dom.pdfButtonLabel.textContent = "Download PDF Report";
    dom.pdfSpinner.hidden = true;
    updateExportControls();
    saveHistory(report);
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
      setMetricState(dom.statusCard, "status-bad");
      dom.statusNote.textContent = "The target did not return an HTTP status.";
      return;
    }

    dom.statusValue.textContent = String(status);
    dom.statusNote.textContent = report.http_reason || "HTTP response";
    if (status >= 200 && status < 300) {
      setMetricState(dom.statusCard, "status-good");
      dom.statusNote.textContent = `${report.http_reason || "HTTP response"} · application success`;
    } else if (status >= 300 && status < 400) {
      setMetricState(dom.statusCard, "status-warn");
    } else {
      setMetricState(dom.statusCard, "status-bad");
      dom.statusNote.textContent = `${report.http_reason || "HTTP response"} · application not successful`;
    }
  }

  function renderLatency(report) {
    const ms = report.response_time_ms;
    if (typeof ms !== "number") {
      dom.latencyValue.textContent = "—";
      setMetricState(dom.latencyCard, null);
      dom.latencyNote.textContent = report.reachable
        ? "The target did not report response timing."
        : "No response timing is available.";
      return;
    }

    dom.latencyValue.textContent = `${Math.round(ms)} ms`;
    if (ms >= 3000) {
      setMetricState(dom.latencyCard, "status-bad");
      dom.latencyNote.textContent = "Slow response · final headers took 3 s or more.";
    } else if (ms >= 1000) {
      setMetricState(dom.latencyCard, "status-warn");
      dom.latencyNote.textContent = "Elevated response time · final headers took 1 s or more.";
    } else {
      setMetricState(dom.latencyCard, "status-good");
      dom.latencyNote.textContent = "Time to final response headers for this request.";
    }
    dom.latencyNote.title = "Latency measures the request until final response headers, not full application processing.";
  }

  function renderFindingsStat(findings) {
    dom.findingsStatValue.textContent = String(findings.length);
    dom.findingsStatNote.textContent = findingSummary(findings);
  }

  function findingSummary(findings) {
    if (findings.length === 0) return "No findings from the performed checks.";
    const counts = countSeverities(findings);
    const parts = SEVERITIES.filter((severity) => counts[severity] > 0).map(
      (severity) => `${counts[severity]} ${severityLabel(severity).toLowerCase()}`
    );
    return parts.join(" · ");
  }

  function countSeverities(findings) {
    const counts = {};
    for (const severity of SEVERITIES) counts[severity] = 0;
    for (const finding of findings) {
      counts[normalizeSeverity(finding.severity)] += 1;
    }
    return counts;
  }

  function renderRisk(report, findings) {
    const score = Number.isFinite(report.risk_score)
      ? Math.max(0, Math.min(100, report.risk_score))
      : 0;
    const level = RISK_LEVELS.includes(report.risk_level) ? report.risk_level : "low";
    dom.riskCard.className = `stat-card score-card risk-${level}`;
    dom.riskScore.textContent = String(Math.round(score));
    dom.riskLevel.textContent = riskLabel(level);
    dom.riskProgress.value = score;
    dom.riskProgress.setAttribute(
      "aria-valuetext",
      `${Math.round(score)} out of 100, ${riskLabel(level)} risk`
    );
    const count = findings.length;
    dom.riskNote.textContent = `${count} finding${count === 1 ? "" : "s"} · higher values indicate more configuration risk.`;
  }

  function renderFilters(findings) {
    dom.severityFilters.textContent = "";
    const counts = countSeverities(findings);

    dom.severityFilters.appendChild(createFilterButton("all", "All", findings.length));
    for (const severity of SEVERITIES) {
      const count = counts[severity] || 0;
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
      const severityDelta = severityIndex(a.severity) - severityIndex(b.severity);
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
    node.classList.add(`severity-${severity}`);
    const badge = node.querySelector(".severity-badge");
    badge.textContent = severityLabel(severity);
    badge.classList.add(`severity-${severity}`);
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
        item.textContent = displayUrl(url);
        dom.redirectList.appendChild(item);
      }
    }

    if (report.redirect_problem) {
      const problem = report.redirect_problem;
      dom.redirectProblem.hidden = false;
      dom.redirectProblemText.textContent = `${problem.message} Destination: ${displayUrl(problem.location)}`;
      dom.redirectPanel.open = true;
    } else {
      dom.redirectProblem.hidden = true;
      dom.redirectProblemText.textContent = "";
      dom.redirectPanel.open = count > 0;
    }
  }

  /* ---------- Exports ---------- */

  function setExportStatus(message, kind) {
    dom.exportStatus.textContent = message;
    dom.exportStatus.classList.remove("is-error", "is-success");
    if (kind) dom.exportStatus.classList.add(`is-${kind}`);
  }

  function setExportBusy(busy) {
    state.exporting = busy;
    dom.pdfSpinner.hidden = !busy;
    dom.pdfButtonLabel.textContent = busy ? "Generating PDF…" : "Download PDF Report";
    updateExportControls();
  }

  async function downloadPdf() {
    if (!state.report || state.busy || state.exporting) return;

    setExportStatus("Generating a PDF from the report currently displayed…");
    setExportBusy(true);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 30000);

    try {
      const response = await fetch("/api/report/pdf", {
        method: "POST",
        signal: controller.signal,
        headers: {
          Accept: "application/pdf",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(state.report),
      });

      if (!response.ok) {
        let body = null;
        try {
          body = await response.json();
        } catch {
          body = null;
        }
        throw new Error(
          extractErrorMessage(body) || `PDF export failed with HTTP ${response.status}.`
        );
      }

      const blob = await response.blob();
      if (blob.type && !blob.type.includes("application/pdf")) {
        throw new Error("The server did not return a PDF document.");
      }

      const filename =
        filenameFromDisposition(response.headers.get("Content-Disposition")) ||
        fallbackPdfName(state.report);
      triggerDownload(blob, filename);
      setExportStatus(`PDF report downloaded (${filename}).`, "success");
      announce("PDF report downloaded.");
    } catch (error) {
      const message =
        error && error.name === "AbortError"
          ? "PDF generation timed out. Try again."
          : error instanceof TypeError
            ? "The browser could not contact API Sentinel. Confirm the local server is running."
            : (error && error.message) || "The PDF report could not be generated.";
      setExportStatus(message, "error");
      announce(`PDF export failed. ${message}`);
    } finally {
      window.clearTimeout(timer);
      setExportBusy(false);
    }
  }

  function filenameFromDisposition(value) {
    if (!value) return "";
    const match = /filename="?([^";]+)"?/i.exec(value);
    if (!match) return "";
    const name = match[1].trim().split(/[\\/]/).pop() || "";
    return /^[\w.-]+\.pdf$/i.test(name) ? name : "";
  }

  function fallbackPdfName(report) {
    const raw = String(report && report.scanned_at ? report.scanned_at : "");
    const match = /^(\d{4}-\d{2}-\d{2})/.exec(raw);
    const date = match ? match[1] : new Date().toISOString().slice(0, 10);
    return `api-sentinel-report-${date}.pdf`;
  }

  function downloadReport() {
    if (!state.report || state.busy || state.exporting) return;
    setExportStatus("Preparing JSON report…");

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
    setExportStatus(`JSON report downloaded (${anchor.download}).`, "success");
    announce("JSON report downloaded.");
  }

  function triggerDownload(blob, filename) {
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  }

  /* ---------- Temporary browser history ---------- */

  function displayUrl(raw) {
    const text = String(raw || "").trim();
    if (!text) return "";
    try {
      const parsed = new URL(text);
      return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    } catch {
      return text.split("?")[0].split("#")[0];
    }
  }

  function loadHistory() {
    try {
      const raw = window.sessionStorage.getItem(HISTORY_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed.filter((item) => item && typeof item === "object").slice(0, HISTORY_LIMIT);
    } catch {
      return [];
    }
  }

  function saveHistory(report) {
    if (!report || !report.report_id) return;
    try {
      const entries = loadHistory().filter(
        (item) => !(item.report_id === report.report_id && item.target === displayUrl(report.target_url))
      );
      entries.unshift({
        report_id: String(report.report_id),
        target: displayUrl(report.target_url),
        scanned_at: String(report.scanned_at || ""),
        risk_score: Number(report.risk_score) || 0,
        risk_level: RISK_LEVELS.includes(report.risk_level) ? report.risk_level : "low",
        demo: Boolean(report.demo),
      });
      window.sessionStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, HISTORY_LIMIT)));
      renderHistory(entries.slice(0, HISTORY_LIMIT));
    } catch {
      // Private browsing or a full session store must not break scanning.
    }
  }

  function renderHistory(entries) {
    dom.historyList.textContent = "";
    dom.historyEmpty.hidden = entries.length > 0;
    dom.historyClear.hidden = entries.length === 0;

    for (const entry of entries) {
      const item = document.createElement("li");
      item.className = "history-item";

      const targetWrap = document.createElement("div");
      targetWrap.className = "history-target";
      const code = document.createElement("code");
      code.textContent = entry.target || "Unknown target";
      const meta = document.createElement("p");
      meta.className = "history-meta";
      const scanned = new Date(entry.scanned_at);
      const when = Number.isNaN(scanned.getTime())
        ? entry.scanned_at || "Time unavailable"
        : scanned.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
      meta.textContent = `${when} · ${entry.demo ? "sample" : "live scan"}`;
      targetWrap.append(code, meta);

      const badge = document.createElement("span");
      badge.className = "history-badge";
      badge.textContent = `${riskLabel(entry.risk_level)} · ${entry.risk_score}/100`;

      item.append(targetWrap, badge);
      dom.historyList.appendChild(item);
    }
  }

  function clearHistory() {
    try {
      window.sessionStorage.removeItem(HISTORY_KEY);
    } catch {
      // Ignore storage failures; the visible list is still cleared.
    }
    renderHistory([]);
    announce("Temporary scan history cleared.");
  }

  function announce(message) {
    dom.srAnnouncer.textContent = "";
    window.setTimeout(() => {
      dom.srAnnouncer.textContent = message;
    }, 60);
  }

  init();
})();
