const BANNER_ID = "phishshield-banner";
const HOVER_ID = "phishshield-hover-tip";
const FORM_CLASS = "phishshield-form-warning";
const SETTINGS_KEY = "phishshield_settings";
const DEFAULT_API_BASE = "http://127.0.0.1:5000";
const STORAGE_KEY = "phishshield_page_state";
let lastUrl = "";
let bannerElement = null;
let hoverElement = null;
let pageScanTimer = null;
let pageContextCache = null;
let lastScanUrl = "";
let lastScanAt = 0;
let autoScanTimer = null;
let lastScanSignature = "";

function isHttpPage(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isGmailPage(url = location.href) {
  try {
    return new URL(url).hostname === "mail.google.com";
  } catch {
    return false;
  }
}

function normalizeText(text) {
  return String(text || "").replace(/\s+/g, " ").trim();
}

function firstText(root, selectors) {
  for (const selector of selectors) {
    const element = root.querySelector(selector);
    const text = normalizeText(element?.innerText || element?.textContent || "");
    if (text) return text;
  }
  return "";
}

function collectGmailMessageContext() {
  if (!isGmailPage()) return null;

  const root = document.querySelector('div[role="main"]') || document.body;
  if (!root) return null;

  const subject = firstText(root, [
    'h2.hP',
    'h2.bog',
    '[role="heading"][aria-level="2"]',
    'h2',
  ]);

  const sender = firstText(root, [
    'span.gD',
    'span[email]',
    '.go',
    '.afK',
  ]);

  const bodyNodes = Array.from(root.querySelectorAll('.a3s.aiL, .ii.gt, .a3s'));
  const body = bodyNodes
    .map((node) => normalizeText(node.innerText || node.textContent || ""))
    .filter(Boolean)
    .join("\n\n")
    .trim();

  if (!body) return null;

  return {
    url: location.href,
    title: document.title || "",
    subject,
    sender,
    body: body.slice(0, 12000),
    summary: [
      subject ? `Subject: ${subject}` : null,
      sender ? `From: ${sender}` : null,
    ].filter(Boolean).join(" · "),
  };
}

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      if (!response?.ok) {
        reject(new Error(response?.error || "Unknown extension error"));
        return;
      }
      resolve(response.result);
    });
  });
}

async function getApiBase() {
  const data = await chrome.storage.sync.get(SETTINGS_KEY);
  return data[SETTINGS_KEY]?.apiBase || DEFAULT_API_BASE;
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

function getHostname(url) {
  try {
    return new URL(url, location.href).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

function isProbablyUrl(text) {
  const value = String(text || "").trim();
  return /^https?:\/\//i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(value);
}

function extractTextDomain(text) {
  if (!isProbablyUrl(text)) return "";
  try {
    const raw = text.startsWith("http") ? text : `https://${text}`;
    return new URL(raw).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

function showHoverTip(anchor, warning) {
  hideHoverTip();
  const tip = document.createElement("div");
  tip.id = HOVER_ID;
  tip.textContent = warning;

  const rect = anchor.getBoundingClientRect();
  const left = Math.min(window.innerWidth - 260, Math.max(12, rect.left + window.scrollX));
  const top = Math.max(12, rect.bottom + window.scrollY + 8);
  tip.style.left = `${left}px`;
  tip.style.top = `${top}px`;

  document.documentElement.appendChild(tip);
  hoverElement = tip;
}

function hideHoverTip() {
  if (hoverElement) hoverElement.remove();
  hoverElement = null;
}

function linkWarning(anchor) {
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
}

function formWarning(form) {
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
  return {
    form,
    reasons,
    reason: reasons.join("; "),
    score,
  };
}

function collectPageContext() {
  const linkWarnings = Array.from(document.querySelectorAll("a[href]"))
    .map(linkWarning)
    .filter(Boolean)
    .slice(0, 6);

  const suspiciousForms = Array.from(document.forms)
    .map(formWarning)
    .filter(Boolean)
    .slice(0, 6);

  pageContextCache = {
    url: location.href,
    title: document.title || "",
    linkWarnings,
    suspiciousForms: suspiciousForms.map((item) => ({
      reason: item.reason,
      score: item.score,
    })),
    summary: [
      suspiciousForms.length ? `${suspiciousForms.length} suspicious form${suspiciousForms.length > 1 ? "s" : ""}` : null,
      linkWarnings.length ? `${linkWarnings.length} link mismatch${linkWarnings.length > 1 ? "es" : ""}` : null,
    ].filter(Boolean).join(" · "),
  };
  return pageContextCache;
}

function markSuspiciousForms() {
  const forms = Array.from(document.forms);
  forms.forEach((form) => {
    const warning = formWarning(form);
    if (!warning) return;
    if (form.dataset.phishshieldMarked === "1") return;
    form.dataset.phishshieldMarked = "1";
    form.classList.add(FORM_CLASS);
    form.title = `PhishShield warning: ${warning.reason}`;
  });
}

function installLinkPreview() {
  document.addEventListener("mouseover", (event) => {
    const anchor = event.target?.closest?.("a[href]");
    if (!anchor) return;
    const warning = linkWarning(anchor);
    if (!warning) return;
    showHoverTip(anchor, warning.reason);
  }, true);

  document.addEventListener("focusin", (event) => {
    const anchor = event.target?.closest?.("a[href]");
    if (!anchor) return;
    const warning = linkWarning(anchor);
    if (!warning) return;
    showHoverTip(anchor, warning.reason);
  }, true);

  document.addEventListener("mouseout", hideHoverTip, true);
  document.addEventListener("focusout", hideHoverTip, true);
}

function watchDomMutations() {
  const observer = new MutationObserver(() => {
    markSuspiciousForms();
    pageContextCache = null;
    if (isGmailPage() && collectGmailMessageContext()) {
      scheduleAutoScan(1500);
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
}

function removeBanner() {
  if (bannerElement) bannerElement.remove();
  bannerElement = null;
}

function createBanner(result, pageContext = null) {
  removeBanner();

  const threatPct = typeof result.threat_score_pct === "number"
    ? result.threat_score_pct
    : typeof result.threat_score === "number"
      ? Math.round(result.threat_score * 100)
      : typeof result.confidence_score === "number"
        ? Math.max(0, Math.round((1 - result.confidence_score) * 100))
        : null;

  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.dataset.level = result.label === "Phishing" ? "danger" : "safe";
  banner.innerHTML = `
    <div class="phishshield-banner__content">
      <div>
        <div class="phishshield-banner__eyebrow">PhishShield AI</div>
        <div class="phishshield-banner__title">${result.label || "Scan complete"}</div>
        <div class="phishshield-banner__meta">Confidence ${result.confidence || "n/a"}</div>
      </div>
      <div class="phishshield-banner__score">${threatPct === null ? "n/a" : `${threatPct}%`}</div>
    </div>
    ${pageContext?.summary ? `<div class="phishshield-banner__summary">${pageContext.summary}</div>` : ""}
    <div class="phishshield-banner__signals"></div>
    <div class="phishshield-banner__actions">
      <button type="button" data-action="rescan">Rescan</button>
      <button type="button" data-action="dismiss">Dismiss</button>
    </div>
  `;

  const signals = banner.querySelector(".phishshield-banner__signals");
  const items = [];
  if (Array.isArray(result.threat_signals) && result.threat_signals.length) {
    items.push(...result.threat_signals.slice(0, 3));
  }
  if (Array.isArray(result.flagged_tokens) && result.flagged_tokens.length) {
    items.push(`Tokens: ${result.flagged_tokens.slice(0, 4).join(", ")}`);
  }
  if (Array.isArray(result.feature_flags)) {
    items.push(...result.feature_flags.slice(0, 3));
  }
  if (result.feature_flags && typeof result.feature_flags === "object") {
    const active = Object.entries(result.feature_flags)
      .filter(([, value]) => Boolean(value))
      .map(([key]) => key)
      .slice(0, 4);
    items.push(...active);
  }
  if (result.contributions && typeof result.contributions === "object") {
    const top = Object.entries(result.contributions)
      .sort((a, b) => Number(b[1]) - Number(a[1]))
      .slice(0, 3)
      .map(([key, value]) => `${key}: +${value}`);
    items.push(...top);
  }

  signals.innerHTML = items.length
    ? items.map((item) => `<span class="phishshield-chip">${item}</span>`).join("")
    : `<span class="phishshield-chip">No major signals found</span>`;

  banner.addEventListener("click", async (event) => {
    const action = event.target?.dataset?.action;
    if (action === "dismiss") {
      removeBanner();
      await chrome.storage.local.set({ [STORAGE_KEY]: { hiddenForUrl: location.href, hiddenAt: Date.now() } });
    }
    if (action === "rescan") {
      scanCurrentPage(true);
    }
  });

  document.documentElement.appendChild(banner);
  bannerElement = banner;
}

async function scanCurrentPage(force = false) {
  const current = location.href;
  const now = Date.now();
  if (!isHttpPage(current)) {
    removeBanner();
    return;
  }
  if (!force && current === lastUrl && now - lastScanAt < 15000) return;
  lastUrl = current;
  lastScanAt = now;

  try {
    const pageContext = collectPageContext();
    const state = await chrome.storage.local.get(STORAGE_KEY);
    const hidden = state[STORAGE_KEY]?.hiddenForUrl === current && Date.now() - (state[STORAGE_KEY]?.hiddenAt || 0) < 15 * 60 * 1000;
    if (hidden) return;

    const result = await postJson("/api/check-url", { url: current });
    createBanner(result, pageContext);
    markSuspiciousForms();
  } catch {
    removeBanner();
  }
}

async function scanGmailMessage(force = false) {
  const message = collectGmailMessageContext();
  if (!message) {
    removeBanner();
    return;
  }

  const signature = `${message.subject}|${message.sender}|${message.body.slice(0, 1000)}`;
  const now = Date.now();
  if (!force && signature === lastScanSignature && now - lastScanAt < 20000) return;

  lastScanSignature = signature;
  lastScanAt = now;

  try {
    const emailText = [
      message.subject ? `Subject: ${message.subject}` : "",
      message.sender ? `From: ${message.sender}` : "",
      message.body,
    ].filter(Boolean).join("\n\n");

    const result = await sendMessage({ type: "SCAN_EMAIL", text: emailText.slice(0, 15000) });
    createBanner(result, {
      url: message.url,
      title: message.title,
      summary: [message.summary || "Gmail message scanned", result?.privacy_note || ""].filter(Boolean).join(" · "),
    });
  } catch {
    removeBanner();
  }
}

async function scanActiveContext(force = false) {
  if (isGmailPage()) {
    return await scanGmailMessage(force);
  }
  return await scanCurrentPage(force);
}

function scheduleScan(delayMs = 1200) {
  const waitMs = Number.isFinite(Number(delayMs)) ? Math.max(0, Number(delayMs)) : 1200;
  clearTimeout(pageScanTimer);
  pageScanTimer = setTimeout(() => scanActiveContext(true), waitMs);
}

function scheduleAutoScan(delayMs = 1200) {
  const waitMs = Number.isFinite(Number(delayMs)) ? Math.max(0, Number(delayMs)) : 1200;
  clearTimeout(autoScanTimer);
  autoScanTimer = setTimeout(() => scanActiveContext(true), waitMs);
}

window.addEventListener("DOMContentLoaded", scheduleScan, { once: true });
window.addEventListener("load", scheduleScan, { once: true });
window.addEventListener("pageshow", scheduleScan, { once: true });
window.addEventListener("popstate", scheduleScan);
window.addEventListener("hashchange", scheduleScan);

installLinkPreview();
markSuspiciousForms();
watchDomMutations();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_SELECTION") {
    const selection = window.getSelection()?.toString().trim() || "";
    sendResponse({ ok: true, result: { selection } });
    return true;
  }

  if (message?.type === "GET_PAGE_TEXT") {
    const text = document.body?.innerText?.slice(0, 10000) || "";
    sendResponse({ ok: true, result: { text, title: document.title || "" } });
    return true;
  }

  if (message?.type === "GET_PAGE_CONTEXT") {
    sendResponse({ ok: true, result: collectPageContext() });
    return true;
  }

  if (message?.type === "SCAN_SELECTION") {
    const selection = window.getSelection()?.toString().trim() || "";
    sendMessage(selection ? { type: "SCAN_EMAIL", text: selection } : { type: "SCAN_URL", url: location.href })
      .then((result) => sendResponse({ ok: true, result }))
      .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));
    return true;
  }

  if (message?.type === "AUTO_SCAN_PAGE") {
    const requestedUrl = String(message.url || location.href || "");
    if (!isHttpPage(requestedUrl) || requestedUrl !== location.href) {
      sendResponse({ ok: true, result: { skipped: true } });
      return false;
    }

    const delayMs = Number(message.delayMs || 1200);
    scheduleAutoScan(Number.isFinite(delayMs) ? Math.max(250, delayMs) : 1200);
    sendResponse({ ok: true, result: { scheduled: true } });
    return true;
  }

  return false;
});

scheduleAutoScan();
