const apiBaseInput = document.getElementById("api-base");
const saveSettingsButton = document.getElementById("save-settings");
const connectionPill = document.getElementById("connection-pill");
const scanCurrentUrlButton = document.getElementById("scan-current-url");
const scanSelectionButton = document.getElementById("scan-selection");
const scanPageTextButton = document.getElementById("scan-page-text");
const scanScreenshotButton = document.getElementById("scan-screenshot");
const analysisInput = document.getElementById("analysis-input");
const runAnalysisButton = document.getElementById("run-analysis");
const runBulkButton = document.getElementById("run-bulk");
const importEmailButton = document.getElementById("import-email-file");
const emailFileInput = document.getElementById("email-file-input");
const exportCsvButton = document.getElementById("export-csv");
const exportJsonButton = document.getElementById("export-json");
const clearResultButton = document.getElementById("clear-result");
const clearHistoryButton = document.getElementById("clear-history");
const clearScreenshotButton = document.getElementById("clear-screenshot");
const feedbackFalsePositiveButton = document.getElementById("feedback-false-positive");
const feedbackMissedThreatButton = document.getElementById("feedback-missed-threat");
const resultCard = document.getElementById("result-card");
const historyList = document.getElementById("history-list");
const trendCard = document.getElementById("risk-trend");
const screenshotPreviewFrame = document.getElementById("screenshot-preview-frame");
const screenshotPreview = document.getElementById("screenshot-preview");
const screenshotPlaceholder = document.getElementById("screenshot-placeholder");

const SETTINGS_KEY = "phishshield_settings";
const HISTORY_KEY = "phishshield_history";
const DEFAULT_API_BASE = "http://127.0.0.1:5000";

let currentResult = null;
let currentScreenshot = "";
let historyState = [];

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        const text = String(error.message || "");
        if (!text.includes("Receiving end does not exist") && !text.includes("Could not establish connection")) {
          reject(new Error(error.message));
          return;
        }
      }

      if (response?.ok) {
        resolve(response.result);
        return;
      }

      fallbackMessage(message)
        .then(resolve)
        .catch((fallbackError) => reject(fallbackError));
    });
  });
}

function isMissingReceiverError(error) {
  const text = String(error?.message || error || "");
  return text.includes("Receiving end does not exist") || text.includes("Could not establish connection");
}

function looksLikeUrl(text) {
  const value = String(text || "").trim();
  if (!value) return false;
  return /^https?:\/\//i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(value);
}

async function getStoredSettings() {
  const data = await chrome.storage.sync.get(SETTINGS_KEY);
  return data[SETTINGS_KEY] || {};
}

async function getApiBase() {
  const settings = await getStoredSettings();
  return settings.apiBase || apiBaseInput?.value?.trim() || DEFAULT_API_BASE;
}

async function postJson(path, body) {
  const apiBase = await getApiBase();
  const response = await fetch(`${apiBase}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload?.error || `Request failed with status ${response.status}`);
  }
  return payload;
}

async function getHistoryLocal() {
  const data = await chrome.storage.local.get(HISTORY_KEY);
  return Array.isArray(data[HISTORY_KEY]) ? data[HISTORY_KEY] : [];
}

async function pushHistoryLocal(entry) {
  const history = await getHistoryLocal();
  history.unshift({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...entry,
  });
  await chrome.storage.local.set({ [HISTORY_KEY]: history.slice(0, 25) });
}

async function directGetActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

async function directExecuteOnActiveTab(func) {
  const tab = await directGetActiveTab();
  if (!tab?.id) return null;
  return await new Promise((resolve, reject) => {
    chrome.scripting.executeScript({ target: { tabId: tab.id }, func }, (results) => {
      const error = chrome.runtime.lastError;
      if (error) {
        const text = String(error.message || "");
        if (text.includes("Cannot access contents of the page") || text.includes("Could not establish connection") || text.includes("Receiving end does not exist")) {
          resolve(null);
          return;
        }
        reject(new Error(error.message));
        return;
      }
      resolve(results?.[0]?.result ?? null);
    });
  });
}

async function directScanUrl(url) {
  const result = await postJson("/api/check-url", { url });
  await pushHistoryLocal({ kind: "url", input: url, result });
  return result;
}

async function directScanEmail(text) {
  const result = await postJson("/api/check-email", { text });
  await pushHistoryLocal({ kind: "email", input: text.slice(0, 240), result });
  return result;
}

async function directFullAnalysis(payload) {
  const result = await postJson("/api/full-analysis", payload);
  await pushHistoryLocal({ kind: "full", input: payload, result });
  return result;
}

async function directBulkScan(urls) {
  const result = await postJson("/api/bulk-scan", { urls });
  await pushHistoryLocal({ kind: "bulk", input: urls.slice(0, 20), result });
  return result;
}

async function directScanScreenshot() {
  const tab = await directGetActiveTab();
  if (!tab?.url) throw new Error("No active tab URL available");

  const [screenshot, pageContext, urlResult] = await Promise.all([
    new Promise((resolve) => {
      chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
        const error = chrome.runtime.lastError;
        if (error) {
          resolve(null);
          return;
        }
        resolve(dataUrl);
      });
    }),
    directExecuteOnActiveTab(() => {
      const getHostname = (url) => {
        try { return new URL(url, location.href).hostname.replace(/^www\./, "").toLowerCase(); } catch { return ""; }
      };
      const isProbablyUrl = (text) => /^https?:\/\//i.test(String(text || "").trim()) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(String(text || "").trim());
      const extractTextDomain = (text) => {
        if (!isProbablyUrl(text)) return "";
        try { const raw = String(text).startsWith("http") ? String(text) : `https://${text}`; return new URL(raw).hostname.replace(/^www\./, "").toLowerCase(); } catch { return ""; }
      };
      const linkWarnings = Array.from(document.querySelectorAll("a[href]"))
        .map((anchor) => {
          const href = anchor.getAttribute("href") || "";
          if (!href || href.startsWith("#") || href.startsWith("javascript:")) return null;
          const text = (anchor.textContent || "").trim().replace(/\s+/g, " ");
          const hrefHost = getHostname(href);
          const textHost = extractTextDomain(text);
          const visibleText = text.slice(0, 120) || href;
          if (textHost && hrefHost && textHost !== hrefHost) return { reason: `Displayed text points to ${textHost} but the real destination is ${hrefHost}` };
          if (hrefHost && visibleText.toLowerCase().includes("login") && !hrefHost.includes("login")) return { reason: `Login-related link points to ${hrefHost}` };
          return null;
        })
        .filter(Boolean)
        .slice(0, 6);
      const suspiciousForms = Array.from(document.forms)
        .map((form) => {
          const text = (form.innerText || "").toLowerCase();
          const action = (form.getAttribute("action") || location.href || "").toLowerCase();
          const inputs = Array.from(form.querySelectorAll("input, button, textarea, select"));
          const hasPassword = inputs.some((item) => (item.getAttribute("type") || "").toLowerCase() === "password");
          const hiddenInputs = inputs.filter((item) => (item.getAttribute("type") || "").toLowerCase() === "hidden").length;
          const submitText = inputs.map((item) => (item.textContent || item.value || "").toLowerCase()).join(" ");
          let score = 0;
          const reasons = [];
          if (hasPassword) { score += 1; reasons.push("Password field present"); }
          if (hiddenInputs > 0) { score += 1; reasons.push(`${hiddenInputs} hidden field${hiddenInputs > 1 ? "s" : ""}`); }
          if (!action || action === location.href.toLowerCase() || action.includes("javascript:")) { score += 1; reasons.push("Suspicious or missing form action"); }
          if (/login|sign in|verify|payment|checkout|wallet|account/.test(text + " " + submitText)) { score += 1; reasons.push("Login/payment language detected"); }
          if (form.querySelector('input[type="password"][autocomplete="off"]')) { score += 1; reasons.push("Password field disables autocomplete"); }
          if (score < 2) return null;
          return { reason: reasons.join("; "), score };
        })
        .filter(Boolean)
        .slice(0, 6);
      return { url: location.href, title: document.title || "", linkWarnings, suspiciousForms, summary: [suspiciousForms.length ? `${suspiciousForms.length} suspicious form${suspiciousForms.length > 1 ? "s" : ""}` : null, linkWarnings.length ? `${linkWarnings.length} link mismatch${linkWarnings.length > 1 ? "es" : ""}` : null].filter(Boolean).join(" · ") };
    }).catch(() => ({ url: "", title: "", linkWarnings: [], suspiciousForms: [], summary: "" })),
    postJson("/api/check-url", { url: tab.url }),
  ]);

  const visualSignals = [];
  if (pageContext?.suspiciousForms?.length) {
    visualSignals.push(...pageContext.suspiciousForms.slice(0, 3).map((item) => `Form: ${item.reason}`));
  }
  if (pageContext?.linkWarnings?.length) {
    visualSignals.push(...pageContext.linkWarnings.slice(0, 3).map((item) => `Link: ${item.reason}`));
  }

  const result = {
    label: urlResult.label,
    confidence: urlResult.confidence,
    confidence_score: urlResult.confidence_score,
    threat_signals: [...signalList(urlResult), ...visualSignals],
    screenshot,
    page_context: pageContext,
    url: tab.url,
    scan_type: "screenshot",
  };
  await pushHistoryLocal({ kind: "screenshot", input: tab.url, result: { ...result, screenshot: undefined } });
  return result;
}

async function directGetSelection() {
  const selection = await directExecuteOnActiveTab(() => window.getSelection()?.toString().trim() || "");
  return { selection: selection || "" };
}

async function directGetPageText() {
  return (await directExecuteOnActiveTab(() => ({ title: document.title || "", text: (document.body?.innerText || "").slice(0, 10000) }))) || { title: "", text: "" };
}

async function directGetPageContext() {
  return await directScanScreenshot().then((result) => result?.page_context || { url: "", title: "", linkWarnings: [], suspiciousForms: [], summary: "" }).catch(() => ({ url: "", title: "", linkWarnings: [], suspiciousForms: [], summary: "" }));
}

async function directGetHistory() {
  return await getHistoryLocal();
}

async function directClearHistory() {
  await chrome.storage.local.set({ [HISTORY_KEY]: [] });
  return { ok: true };
}

async function directSaveSettings(apiBase) {
  await chrome.storage.sync.set({ [SETTINGS_KEY]: { apiBase: String(apiBase || DEFAULT_API_BASE).trim() } });
  return { ok: true };
}

async function directGetSettings() {
  return { apiBase: await getApiBase() };
}

async function directSendFeedback(payload) {
  await postJson("/api/extension-feedback", payload);
  await pushHistoryLocal({ kind: "feedback", input: payload.url || payload.label || payload.feedback, result: payload });
  return { ok: true };
}

async function fallbackMessage(message) {
  switch (message?.type) {
    case "GET_SETTINGS": return await directGetSettings();
    case "SAVE_SETTINGS": return await directSaveSettings(message.apiBase);
    case "SCAN_URL": return await directScanUrl(message.url);
    case "SCAN_EMAIL": return await directScanEmail(message.text);
    case "FULL_ANALYSIS": return await directFullAnalysis(message.payload || {});
    case "BULK_SCAN": return await directBulkScan(Array.isArray(message.urls) ? message.urls : []);
    case "SCAN_SCREENSHOT": return await directScanScreenshot();
    case "SEND_FEEDBACK": return await directSendFeedback(message.payload || {});
    case "GET_SELECTION": return await directGetSelection();
    case "GET_PAGE_TEXT": return await directGetPageText();
    case "GET_PAGE_CONTEXT": return await directGetPageContext();
    case "GET_HISTORY": return await directGetHistory();
    case "CLEAR_HISTORY": return await directClearHistory();
    default: throw new Error("Request failed");
  }
}

function setConnectionStatus(text, kind = "idle") {
  connectionPill.textContent = text;
  connectionPill.style.background = kind === "error"
    ? "rgba(251, 113, 133, 0.16)"
    : kind === "success"
      ? "rgba(34, 197, 94, 0.16)"
      : "rgba(56, 189, 248, 0.16)";
}

function fmtPercent(value) {
  return `${Math.round(Number(value || 0) * 100)}%`;
}

function resultScore(result) {
  if (!result) return null;
  if (typeof result.score === "number") return result.score;
  if (typeof result.confidence_score === "number") {
    return Math.round(result.confidence_score * 100);
  }
  return null;
}

function getTopItems(obj, limit = 4) {
  if (!obj || typeof obj !== "object") return [];
  return Object.entries(obj)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, limit)
    .map(([key, value]) => `${key}: ${value}`);
}

function signalList(result) {
  const items = [];
  if (Array.isArray(result?.threat_signals)) items.push(...result.threat_signals);
  if (Array.isArray(result?.flagged_tokens) && result.flagged_tokens.length) {
    items.push(`Flagged: ${result.flagged_tokens.join(", ")}`);
  }
  if (result?.feature_flags && typeof result.feature_flags === "object") {
    items.push(...getTopItems(result.feature_flags, 4));
  }
  if (result?.contributions && typeof result.contributions === "object") {
    items.push(...getTopItems(result.contributions, 4));
  }
  if (result?.page_context?.summary) {
    items.push(result.page_context.summary);
  }
  return items;
}

function renderScreenshot(dataUrl) {
  currentScreenshot = dataUrl || "";
  if (!dataUrl) {
    screenshotPreviewFrame.classList.remove("has-image");
    screenshotPreview.removeAttribute("src");
    screenshotPlaceholder.textContent = "No screenshot captured yet.";
    return;
  }
  screenshotPreview.src = dataUrl;
  screenshotPreviewFrame.classList.add("has-image");
  screenshotPlaceholder.textContent = "";
}

function renderResult(result) {
  currentResult = result || null;

  if (!result) {
    resultCard.className = "result-card empty";
    resultCard.textContent = "No scan yet.";
    return;
  }

  const label = result.label || result.level || result.scan_type || "Result";
  const score = resultScore(result);
  const tone = /Phishing|Spam|High|Critical/i.test(label) ? "#fb7185" : "#22c55e";
  const chips = signalList(result);

  resultCard.className = "result-card";
  resultCard.innerHTML = `
    <div class="result-title">
      <div>
        <div style="color:${tone}; font-weight:800; font-size:18px;">${label}</div>
        <div class="history-item__meta">Confidence ${result.confidence || result.level || "n/a"}</div>
      </div>
      <div class="score-badge">${score === null ? "n/a" : fmtPercent(score / 100)}</div>
    </div>
    ${result.url ? `<div class="history-item__meta" style="word-break:break-all;">${result.url}</div>` : ""}
    ${result.level ? `<div class="history-item__meta" style="margin-top:6px;">Risk level: ${result.level}</div>` : ""}
    ${result.keyword_count !== undefined ? `<div class="history-item__meta" style="margin-top:6px;">Keyword hits: ${result.keyword_count}</div>` : ""}
    ${result.scan_type ? `<div class="history-item__meta" style="margin-top:6px;">Scan type: ${result.scan_type}</div>` : ""}
    ${result.screenshot ? `<div class="history-item__meta" style="margin-top:6px;">Screenshot captured</div>` : ""}
    <div class="chips">${chips.length ? chips.slice(0, 8).map((item) => `<span class="chip">${item}</span>`).join("") : '<span class="chip">No extra signals returned</span>'}</div>
  `;

  if (result.screenshot) {
    renderScreenshot(result.screenshot);
  }
}

function renderHistory(history) {
  historyState = Array.isArray(history) ? history : [];

  if (!historyState.length) {
    historyList.innerHTML = '<div class="history-item__meta">No scans yet.</div>';
    return;
  }

  historyList.innerHTML = historyState.map((entry) => {
    const result = entry.result || {};
    const label = result.label || result.level || entry.kind || "Scan";
    const score = resultScore(result);
    const input = typeof entry.input === "string" ? entry.input : JSON.stringify(entry.input);
    return `
      <article class="history-item">
        <div class="history-item__top">
          <div class="history-item__label">${label}</div>
          <div class="score-badge">${score === null ? "n/a" : fmtPercent(score / 100)}</div>
        </div>
        <div class="history-item__meta">${entry.kind || "scan"} · ${input.slice(0, 100)}</div>
        <div class="history-item__time">${new Date(entry.timestamp).toLocaleString()}</div>
      </article>
    `;
  }).join("");
}

function renderTrend(history) {
  const scored = (history || [])
    .map((entry) => ({
      kind: entry.kind,
      label: entry.result?.label || entry.result?.level || entry.kind || "scan",
      score: resultScore(entry.result),
      timestamp: entry.timestamp,
      input: entry.input,
    }))
    .filter((entry) => typeof entry.score === "number")
    .slice(0, 6);

  if (!scored.length) {
    trendCard.textContent = "No trend data yet.";
    return;
  }

  const latest = scored[0];
  const previous = scored[1];
  const delta = previous ? latest.score - previous.score : 0;
  const deltaText = previous ? `${delta >= 0 ? "+" : ""}${delta.toFixed(0)} vs previous` : "First data point";

  trendCard.innerHTML = [
    `<div class="trend-line"><span class="trend-label">Latest</span><span class="trend-score">${latest.label} ${fmtPercent(latest.score / 100)}</span></div>`,
    `<div class="trend-line"><span class="trend-label">Change</span><span class="trend-score">${deltaText}</span></div>`,
    ...scored.slice(1, 5).map((item) => `
      <div class="trend-line">
        <span class="trend-label">${item.label}</span>
        <span class="trend-score">${fmtPercent(item.score / 100)}</span>
      </div>
    `),
  ].join("");
}

async function refreshHistory() {
  const history = await sendMessage({ type: "GET_HISTORY" });
  renderHistory(history || []);
  renderTrend(history || []);
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

async function scanCurrentUrl() {
  const tab = await getActiveTab();
  if (!tab?.url) throw new Error("No active tab URL available");
  const result = await sendMessage({ type: "SCAN_URL", url: tab.url });
  renderResult(result);
  setConnectionStatus("Scan complete", "success");
  await refreshHistory();
}

async function scanSelection() {
  const { selection } = await sendMessage({ type: "GET_SELECTION" });
  const value = String(selection || "").trim();
  if (!value) {
    setConnectionStatus("No text selected", "error");
    return;
  }
  const payload = looksLikeUrl(value) ? { type: "SCAN_URL", url: value } : { type: "SCAN_EMAIL", text: value };
  const scan = await sendMessage(payload);
  renderResult(scan);
  setConnectionStatus("Selection scan complete", "success");
  await refreshHistory();
}

async function scanPageText() {
  const page = await sendMessage({ type: "GET_PAGE_TEXT" });
  const result = await sendMessage({ type: "SCAN_EMAIL", text: page.text || page.title || "" });
  renderResult(result);
  setConnectionStatus("Page text scan complete", "success");
  await refreshHistory();
}

async function scanScreenshot() {
  const result = await sendMessage({ type: "SCAN_SCREENSHOT" });
  renderResult(result);
  if (result?.screenshot) {
    renderScreenshot(result.screenshot);
  }
  setConnectionStatus("Screenshot scan complete", "success");
  await refreshHistory();
}

async function runFullAnalysis() {
  const text = analysisInput.value.trim();
  if (!text) throw new Error("Paste a URL or email text first");
  const payload = /^https?:\/\//i.test(text) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(text)
    ? { url: text }
    : { email: text };
  const result = await sendMessage({ type: "FULL_ANALYSIS", payload });
  renderResult(result.risk || result.email_analysis || result.url_analysis);
  setConnectionStatus("Analysis complete", "success");
  await refreshHistory();
}

async function runBulk() {
  const lines = analysisInput.value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!lines.length) throw new Error("Paste one URL per line for bulk scanning");
  const result = await sendMessage({ type: "BULK_SCAN", urls: lines });
  renderResult({
    label: `Bulk scan: ${result.threats}/${result.total} threats`,
    confidence_score: result.threats / Math.max(result.total, 1),
    threat_signals: result.results.slice(0, 5).map((item) => `${item.label}: ${item.url}`),
    scan_type: "bulk",
  });
  setConnectionStatus("Bulk scan complete", "success");
  await refreshHistory();
}

async function readEmailFile(file) {
  return await file.text();
}

async function importEmailFile() {
  const [file] = emailFileInput.files || [];
  if (!file) throw new Error("Choose an .eml or .txt file first");
  const text = await readEmailFile(file);
  analysisInput.value = text;
  const result = await sendMessage({ type: "SCAN_EMAIL", text });
  renderResult(result);
  setConnectionStatus(`Imported ${file.name}`, "success");
  await refreshHistory();
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportHistory(format) {
  const payload = historyState.map((entry) => {
    const result = entry.result || {};
    return {
      kind: entry.kind,
      timestamp: entry.timestamp,
      input: typeof entry.input === "string" ? entry.input : JSON.stringify(entry.input),
      label: result.label || result.level || "",
      score: resultScore(result) ?? "",
      confidence: result.confidence || "",
      url: result.url || "",
      signals: signalList(result).join(" | "),
    };
  });

  if (format === "json") {
    downloadFile(`phishshield-history-${Date.now()}.json`, JSON.stringify(payload, null, 2), "application/json");
    return;
  }

  const headers = ["kind", "timestamp", "input", "label", "score", "confidence", "url", "signals"];
  const csv = [
    headers.join(","),
    ...payload.map((row) => headers.map((key) => `"${String(row[key] ?? "").replace(/"/g, '""')}"`).join(",")),
  ].join("\n");
  downloadFile(`phishshield-history-${Date.now()}.csv`, csv, "text/csv");
}

async function saveFeedback(feedback) {
  if (!currentResult) throw new Error("Run a scan first");
  const payload = {
    feedback,
    url: currentResult.url || (await getActiveTab())?.url || "",
    label: currentResult.label || currentResult.level || currentResult.scan_type || "",
    score: resultScore(currentResult) ?? 0,
    signals: signalList(currentResult).slice(0, 8),
    note: feedback === "false-positive" ? "User marked this as a false positive" : "User marked this as a missed threat",
    source: "popup",
  };
  await sendMessage({ type: "SEND_FEEDBACK", payload });
  setConnectionStatus("Feedback saved", "success");
}

async function init() {
  try {
    const settings = await sendMessage({ type: "GET_SETTINGS" });
    apiBaseInput.value = settings.apiBase || "http://127.0.0.1:5000";
    setConnectionStatus("Ready", "success");
  } catch (error) {
    apiBaseInput.value = "http://127.0.0.1:5000";
    setConnectionStatus(error.message || "API unavailable", "error");
  }

  await refreshHistory();
}

saveSettingsButton.addEventListener("click", async () => {
  try {
    await sendMessage({ type: "SAVE_SETTINGS", apiBase: apiBaseInput.value.trim() });
    setConnectionStatus("Saved", "success");
  } catch (error) {
    setConnectionStatus(error.message || "Save failed", "error");
  }
});

scanCurrentUrlButton.addEventListener("click", async () => {
  try { await scanCurrentUrl(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

scanSelectionButton.addEventListener("click", async () => {
  try { await scanSelection(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

scanPageTextButton.addEventListener("click", async () => {
  try { await scanPageText(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

scanScreenshotButton.addEventListener("click", async () => {
  try { await scanScreenshot(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

runAnalysisButton.addEventListener("click", async () => {
  try { await runFullAnalysis(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

runBulkButton.addEventListener("click", async () => {
  try { await runBulk(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

importEmailButton.addEventListener("click", () => emailFileInput.click());
emailFileInput.addEventListener("change", async () => {
  try { await importEmailFile(); } catch (error) { setConnectionStatus(error.message, "error"); }
});

exportCsvButton.addEventListener("click", () => exportHistory("csv"));
exportJsonButton.addEventListener("click", () => exportHistory("json"));

clearResultButton.addEventListener("click", () => {
  currentResult = null;
  renderResult(null);
});

clearScreenshotButton.addEventListener("click", () => renderScreenshot(""));

clearHistoryButton.addEventListener("click", async () => {
  await sendMessage({ type: "CLEAR_HISTORY" });
  historyState = [];
  renderHistory([]);
  renderTrend([]);
});

feedbackFalsePositiveButton.addEventListener("click", async () => {
  try { await saveFeedback("false-positive"); } catch (error) { setConnectionStatus(error.message, "error"); }
});

feedbackMissedThreatButton.addEventListener("click", async () => {
  try { await saveFeedback("missed-threat"); } catch (error) { setConnectionStatus(error.message, "error"); }
});

init();
