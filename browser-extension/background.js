const DEFAULT_API_BASE = "http://127.0.0.1:5000";
const HISTORY_KEY = "phishshield_history";
const SETTINGS_KEY = "phishshield_settings";
const HISTORY_LIMIT = 25;
const ALERT_SCORE_THRESHOLD = 0.65;

async function getSettings() {
  const data = await chrome.storage.sync.get(SETTINGS_KEY);
  return {
    apiBase: data[SETTINGS_KEY]?.apiBase || DEFAULT_API_BASE,
  };
}

async function fetchJson(path, body) {
  const { apiBase } = await getSettings();
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

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

async function executeOnActiveTab(func, args = []) {
  const tab = await getActiveTab();
  if (!tab?.id) return null;

  return await new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      { target: { tabId: tab.id }, func, args },
      (results) => {
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
      }
    );
  });
}

async function readSelectionFromActiveTab() {
  return (await executeOnActiveTab(() => window.getSelection()?.toString().trim() || "")) || "";
}

async function readPageTextFromActiveTab() {
  return (await executeOnActiveTab(() => ({
    title: document.title || "",
    text: (document.body?.innerText || "").slice(0, 10000),
  }))) || { title: "", text: "" };
}

async function readPageContextFromActiveTab() {
  const context = await executeOnActiveTab(() => {
    const getHostname = (url) => {
      try {
        return new URL(url, location.href).hostname.replace(/^www\./, "").toLowerCase();
      } catch {
        return "";
      }
    };

    const isProbablyUrl = (text) => /^https?:\/\//i.test(String(text || "").trim()) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(String(text || "").trim());

    const extractTextDomain = (text) => {
      if (!isProbablyUrl(text)) return "";
      try {
        const raw = String(text).startsWith("http") ? String(text) : `https://${text}`;
        return new URL(raw).hostname.replace(/^www\./, "").toLowerCase();
      } catch {
        return "";
      }
    };

    const linkWarnings = Array.from(document.querySelectorAll("a[href]"))
      .map((anchor) => {
        const href = anchor.getAttribute("href") || "";
        if (!href || href.startsWith("#") || href.startsWith("javascript:")) return null;
        const text = (anchor.textContent || "").trim().replace(/\s+/g, " ");
        const hrefHost = getHostname(href);
        const textHost = extractTextDomain(text);
        const visibleText = text.slice(0, 120) || href;

        if (textHost && hrefHost && textHost !== hrefHost) {
          return {
            text: visibleText,
            href: new URL(href, location.href).href,
            reason: `Displayed text points to ${textHost} but the real destination is ${hrefHost}`,
          };
        }

        if (hrefHost && visibleText.toLowerCase().includes("login") && !hrefHost.includes("login")) {
          return {
            text: visibleText,
            href: new URL(href, location.href).href,
            reason: `Login-related link points to ${hrefHost}`,
          };
        }

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

        if (hasPassword) {
          score += 1;
          reasons.push("Password field present");
        }
        if (hiddenInputs > 0) {
          score += 1;
          reasons.push(`${hiddenInputs} hidden field${hiddenInputs > 1 ? "s" : ""}`);
        }
        if (!action || action === location.href.toLowerCase() || action.includes("javascript:")) {
          score += 1;
          reasons.push("Suspicious or missing form action");
        }
        if (/login|sign in|verify|payment|checkout|wallet|account/.test(text + " " + submitText)) {
          score += 1;
          reasons.push("Login/payment language detected");
        }
        if (form.querySelector('input[type="password"][autocomplete="off"]')) {
          score += 1;
          reasons.push("Password field disables autocomplete");
        }

        if (score < 2) return null;
        return { reason: reasons.join("; "), score };
      })
      .filter(Boolean)
      .slice(0, 6);

    return {
      url: location.href,
      title: document.title || "",
      linkWarnings,
      suspiciousForms,
      summary: [
        suspiciousForms.length ? `${suspiciousForms.length} suspicious form${suspiciousForms.length > 1 ? "s" : ""}` : null,
        linkWarnings.length ? `${linkWarnings.length} link mismatch${linkWarnings.length > 1 ? "es" : ""}` : null,
      ].filter(Boolean).join(" · "),
    };
  });
  return context || { url: "", title: "", linkWarnings: [], suspiciousForms: [], summary: "" };
}

async function captureScreenshot() {
  return await new Promise((resolve, reject) => {
    chrome.tabs.captureVisibleTab(null, { format: "png" }, (dataUrl) => {
      const error = chrome.runtime.lastError;
      if (error) {
        const text = String(error.message || "");
        if (text.includes("Cannot access contents of the page") || text.includes("Could not establish connection")) {
          resolve(null);
          return;
        }
        reject(new Error(error.message));
        return;
      }
      resolve(dataUrl);
    });
  });
}

async function getPageContext() {
  return await readPageContextFromActiveTab();
}

function summarizeSignals(result) {
  if (Array.isArray(result?.threat_signals) && result.threat_signals.length) {
    return result.threat_signals.slice(0, 3);
  }
  if (Array.isArray(result?.flagged_tokens) && result.flagged_tokens.length) {
    return result.flagged_tokens.slice(0, 3).map((item) => `Token: ${item}`);
  }
  return [];
}

async function syncAlert(payload) {
  try {
    await fetchJson("/api/extension-alert", payload);
  } catch {
    return;
  }
}

async function syncFeedback(payload) {
  try {
    await fetchJson("/api/extension-feedback", payload);
  } catch {
    return;
  }
}

async function getHistory() {
  const data = await chrome.storage.local.get(HISTORY_KEY);
  return Array.isArray(data[HISTORY_KEY]) ? data[HISTORY_KEY] : [];
}

async function pushHistory(entry) {
  const history = await getHistory();
  history.unshift({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...entry,
  });
  await chrome.storage.local.set({ [HISTORY_KEY]: history.slice(0, HISTORY_LIMIT) });
}

function looksLikeUrl(text) {
  const value = String(text || "").trim();
  if (!value) return false;
  return /^https?:\/\//i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(value);
}

function safeHostname(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    return new URL(text.startsWith("http") ? text : `https://${text}`).hostname;
  } catch {
    return "";
  }
}

async function scanUrl(url) {
  const result = await fetchJson("/api/check-url", { url });
  await pushHistory({ kind: "url", input: url, domain: safeHostname(url), result });
  if ((result.confidence_score || 0) >= ALERT_SCORE_THRESHOLD || result.label === "Phishing") {
    await syncAlert({
      source: "url-scan",
      url,
      label: result.label,
      score: result.confidence_score || 0,
      level: result.label === "Phishing" ? "high" : "medium",
      signals: summarizeSignals(result),
      summary: `URL scan flagged as ${result.label}`,
    });
  }
  return result;
}

async function scanEmail(text) {
  const result = await fetchJson("/api/check-email", { text });
  await pushHistory({ kind: "email", input: text.slice(0, 240), result });
  if ((result.confidence_score || 0) >= ALERT_SCORE_THRESHOLD || result.label === "Spam/Scam") {
    await syncAlert({
      source: "email-scan",
      label: result.label,
      score: result.confidence_score || 0,
      level: result.label === "Spam/Scam" ? "high" : "medium",
      signals: summarizeSignals(result),
      summary: `Email scan flagged as ${result.label}`,
    });
  }
  return result;
}

async function runFullAnalysis(payload) {
  const result = await fetchJson("/api/full-analysis", payload);
  await pushHistory({ kind: "full", input: payload, result });
  return result;
}

async function bulkScan(urls) {
  const result = await fetchJson("/api/bulk-scan", { urls });
  await pushHistory({ kind: "bulk", input: urls.slice(0, 20), result });
  return result;
}

async function scanScreenshot() {
  const tab = await getActiveTab();
  if (!tab?.url) throw new Error("No active tab URL available");

  const [screenshot, pageContext, urlResult] = await Promise.all([
    captureScreenshot().catch(() => null),
    getPageContext().catch(() => ({ url: "", title: "", linkWarnings: [], suspiciousForms: [], summary: "" })),
    fetchJson("/api/check-url", { url: tab.url }),
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
    threat_signals: [...summarizeSignals(urlResult), ...visualSignals],
    screenshot,
    page_context: pageContext,
    url: tab.url,
    scan_type: "screenshot",
  };
  await pushHistory({ kind: "screenshot", input: tab.url, result: { ...result, screenshot: undefined } });
  if ((result.confidence_score || 0) >= ALERT_SCORE_THRESHOLD || result.label === "Phishing") {
    await syncAlert({
      source: "screenshot-scan",
      url: tab.url,
      label: result.label,
      score: result.confidence_score || 0,
      level: result.label === "Phishing" ? "high" : "medium",
      signals: result.threat_signals.slice(0, 8),
      summary: "Visible page screenshot scan flagged the current tab",
    });
  }
  return result;
}

async function submitFeedback(payload) {
  const entry = {
    source: "extension",
    ...payload,
  };
  await syncFeedback(entry);
  await pushHistory({ kind: "feedback", input: payload.url || payload.label || payload.feedback, result: entry });
  return { ok: true };
}

async function notify(title, message) {
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon128.svg",
      title,
      message,
    });
  } catch {
    return;
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishshield-scan-selection",
    title: "Scan selected text with PhishShield",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== "phishshield-scan-selection") return;
  const selected = String(info.selectionText || "").trim();
  if (!selected) return;

  try {
    const result = looksLikeUrl(selected) ? await scanUrl(selected) : await scanEmail(selected);
    const summary = result.label || result.level || "Scan complete";
    const extra = result.threat_signals?.length
      ? result.threat_signals.slice(0, 2).join("; ")
      : result.flagged_tokens?.length
        ? result.flagged_tokens.slice(0, 3).join(", ")
        : "No notable signals";
    await notify(`PhishShield AI: ${summary}`, extra);
  } catch (error) {
    await notify("PhishShield AI scan failed", error.message || String(error));
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handlers = {
    GET_SETTINGS: async () => getSettings(),
    SAVE_SETTINGS: async () => {
      await chrome.storage.sync.set({ [SETTINGS_KEY]: { apiBase: String(message.apiBase || DEFAULT_API_BASE).trim() } });
      return { ok: true };
    },
    SCAN_URL: async () => scanUrl(message.url),
    SCAN_EMAIL: async () => scanEmail(message.text),
    FULL_ANALYSIS: async () => runFullAnalysis(message.payload || {}),
    BULK_SCAN: async () => bulkScan(Array.isArray(message.urls) ? message.urls : []),
    SCAN_SCREENSHOT: async () => scanScreenshot(),
    SEND_FEEDBACK: async () => submitFeedback(message.payload || {}),
    GET_SELECTION: async () => ({ selection: await readSelectionFromActiveTab() }),
    GET_PAGE_TEXT: async () => await readPageTextFromActiveTab(),
    GET_PAGE_CONTEXT: async () => await readPageContextFromActiveTab(),
    GET_HISTORY: async () => getHistory(),
    CLEAR_HISTORY: async () => {
      await chrome.storage.local.set({ [HISTORY_KEY]: [] });
      return { ok: true };
    },
  };

  const handler = handlers[message?.type];
  if (!handler) return false;

  handler()
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

  return true;
});
