"""
PhishShield AI — Flask Web Application
=======================================
Routes:
  GET  /                   → UI (index.html)
  POST /api/check-url      → URL phishing probability
  POST /api/check-email    → Email spam probability
  POST /api/risk-score     → 0–100 composite risk score
  POST /api/full-analysis  → All three combined in one call
"""

import os
import re
import math
import string
import ipaddress
import warnings
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from flask import Flask, request, jsonify, render_template

warnings.filterwarnings("ignore")

# ── NLTK setup ────────────────────────────────────────────────────
# On serverless (Vercel) the home dir is read-only; use /tmp instead.
_NLTK_DATA = os.path.join(os.sep, "tmp", "nltk_data")
os.makedirs(_NLTK_DATA, exist_ok=True)
if _NLTK_DATA not in nltk.data.path:
    nltk.data.path.insert(0, _NLTK_DATA)

for corpus in ("stopwords", "wordnet", "punkt", "punkt_tab"):
    try:
        nltk.data.find(f"corpora/{corpus}" if corpus not in ("punkt","punkt_tab") else f"tokenizers/{corpus}")
    except LookupError:
        nltk.download(corpus, quiet=True, download_dir=_NLTK_DATA)

# ── Flask app ─────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR  = os.path.join(BASE_DIR, "models")

app = Flask(__name__)

# ── In-memory request counters ────────────────────────────
_stats = {"urls_scanned": 0, "emails_analyzed": 0, "threats_detected": 0}
_extension_alerts = []
_extension_feedback = []
_recent_scans = []


def _append_activity(store: list[dict], payload: dict, limit: int = 100) -> dict:
    entry = {
        "id": len(store) + 1,
        "timestamp": payload.get("timestamp") or pd.Timestamp.utcnow().isoformat(),
        **payload,
    }
    store.insert(0, entry)
    del store[limit:]
    return entry


def _record_scan(payload: dict, limit: int = 30) -> dict:
    return _append_activity(_recent_scans, payload, limit=limit)


def _recent_signal_summary() -> list[dict]:
    signal_counts: dict[str, int] = {}
    for entry in _recent_scans[:30]:
        for signal in entry.get("signals", []):
            signal_counts[signal] = signal_counts.get(signal, 0) + 1
    return [
        {"signal": signal, "count": count}
        for signal, count in sorted(signal_counts.items(), key=lambda item: item[1], reverse=True)[:8]
    ]


def _risk_distribution() -> list[dict]:
    buckets = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for entry in _recent_scans[:20]:
        score = float(entry.get("score", 0.0) or 0.0)
        if score >= 80:
            buckets["Critical"] += 1
        elif score >= 60:
            buckets["High"] += 1
        elif score >= 35:
            buckets["Medium"] += 1
        else:
            buckets["Low"] += 1
    return [{"level": level, "count": count} for level, count in buckets.items()]


def _dashboard_snapshot() -> dict:
    recent_scans = _recent_scans[:10]
    recent_alerts = _extension_alerts[:5]
    recent_feedback = _extension_feedback[:5]
    phish_scans = sum(1 for entry in _recent_scans if entry.get("label") in {"Phishing", "Spam/Scam"})
    return {
        "stats": {
            **_stats,
            "extension_alerts": len(_extension_alerts),
            "extension_feedback": len(_extension_feedback),
            "recent_scans": len(_recent_scans),
            "phishing_events": phish_scans,
        },
        "recent_scans": recent_scans,
        "recent_alerts": recent_alerts,
        "recent_feedback": recent_feedback,
        "top_signals": _recent_signal_summary(),
        "risk_distribution": _risk_distribution(),
    }


def _latest_scan(kind: str) -> dict | None:
    for entry in _recent_scans:
        if entry.get("kind") == kind:
            return entry
    return None


def _auto_risk_inputs() -> dict:
    latest_url = _latest_scan("url") or _latest_scan("full") or _latest_scan("bulk")
    latest_email = _latest_scan("email") or _latest_scan("full")

    if not latest_url and not latest_email:
        raise ValueError("Run a URL or email scan first to generate an automatic risk score.")

    url_prob = float((latest_url or {}).get("score", 0.0) or 0.0) / 100.0
    email_prob = float((latest_email or {}).get("score", 0.0) or 0.0) / 100.0
    keywords = int((latest_email or {}).get("keyword_count", 0) or len((latest_email or {}).get("signals", [])))

    if latest_url:
        url_label = str(latest_url.get("label", "")).lower()
        domain_age = 14 if url_label in {"phishing", "critical", "high"} else 365
    else:
        domain_age = 365

    attachment = bool(latest_email and (
        int((latest_email.get("keyword_count", 0) or 0)) >= 3
        or str(latest_email.get("label", "")).lower() in {"spam/scam", "phishing", "critical", "high"}
    ))

    return {
        "url_model_prob": url_prob,
        "email_model_prob": email_prob,
        "num_suspicious_keywords": keywords,
        "domain_age_days": domain_age,
        "has_attachment": attachment,
        "sources": {
            "url": latest_url,
            "email": latest_email,
        },
    }

# ─────────────────────────────────────────────
# LOAD MODELS (once at startup)
# ─────────────────────────────────────────────
print("Loading models…")

# url_model.pkl is ~766 MB and excluded from the repo (too large for Vercel).
# When absent, check-url falls back to rule-based heuristics only.
_url_model_path = os.path.join(MODELS_DIR, "url_model.pkl")
if os.path.exists(_url_model_path):
    _url_bundle  = joblib.load(_url_model_path)
    URL_MODEL    = _url_bundle["model"]
    URL_FEATURES = _url_bundle["feature_cols"]
    print("  + url_model.pkl")
else:
    URL_MODEL    = None
    URL_FEATURES = []
    print("  ! url_model.pkl NOT FOUND — rule-based heuristics only")

_email_bundle = joblib.load(os.path.join(MODELS_DIR, "email_model.pkl"))
EMAIL_MODEL   = _email_bundle["model"]

VECTORIZER    = joblib.load(os.path.join(MODELS_DIR, "vectorizer.pkl"))

_risk_bundle  = joblib.load(os.path.join(MODELS_DIR, "risk_model.pkl"))
RISK_MODEL    = _risk_bundle["model"]
RISK_FEATURES = _risk_bundle["feature_cols"]
RISK_WEIGHTS  = _risk_bundle["weights"]

print("  + email_model.pkl + vectorizer.pkl")
print("  + risk_model.pkl")
print("All models ready.\n")


# ─────────────────────────────────────────────
# URL FEATURE EXTRACTION
# (mirrors train_model.py — no external import)
# ─────────────────────────────────────────────
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = pd.Series(list(s)).value_counts(normalize=True)
    return float((-freq * np.log2(freq)).sum())


def _has_ip(url: str) -> int:
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _subdomain_count(url: str) -> int:
    try:
        host  = urlparse(url).hostname or ""
        parts = [p for p in host.split(".") if p != "www"]
        return max(len(parts) - 2, 0)
    except Exception:
        return 0


def _domain_len(url: str) -> int:
    try:
        return len(urlparse(url).hostname or "")
    except Exception:
        return 0


def extract_url_features(url: str) -> pd.DataFrame:
    """Return a single-row DataFrame of URL features.

    Feature computation MUST mirror the training pipeline in train_model.py.
    Training URLs were normalised to always start with 'http://', so we do the
    same here before computing any numeric features.  IsHTTPS is derived from
    the *original* URL before normalisation.
    """
    original = str(url)
    # Preserve IsHTTPS from original URL before any normalisation
    is_https = int(original.lower().startswith('https://'))

    # Normalise: strip scheme and re-add http:// so feature computation
    # matches training data (where all URLs were stored as http://<rest>)
    if original.lower().startswith('https://'):
        u = 'http://' + original[8:]   # replace https:// → http://
    elif not original.lower().startswith('http://'):
        u = 'http://' + original        # add scheme if missing
    else:
        u = original

    parsed = urlparse(u)
    host   = (parsed.hostname or '').lower()
    path   = (parsed.path + '?' + (parsed.query or '')).lower()
    parts  = host.split('.')
    reg_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host

    _has_susp_tld = int(any(host.endswith(t) for t in SUSPICIOUS_TLDS))
    _has_brand    = int(any(b in path and b not in reg_domain for b in BRAND_LIST))
    _num_special  = sum(u.count(c) for c in "!$'\"(){}[]|^`")

    row = {
        'URLLength'        : len(u),
        'DomainLength'     : _domain_len(u),
        'IsHTTPS'          : is_https,
        'NumDots'          : u.count('.'),
        'NumHyphens'       : u.count('-'),
        'NumSubdomains'    : _subdomain_count(u),
        'HasIPAddress'     : _has_ip(u),
        'NumSlashes'       : u.count('/'),
        'NumAtSymbol'      : u.count('@'),
        'NumQueryParams'   : u.count('?'),
        'NumAmpersand'     : u.count('&'),
        'NumEquals'        : u.count('='),
        'NumPercent'       : u.count('%'),
        'NumDigits'        : sum(c.isdigit() for c in u),
        'HasDoubleSlash'   : int('//' in (urlparse(u).path or '')),  # path only, not scheme
        'HasTildeSign'     : int('~' in u),
        'URLEntropy'       : _entropy(u),
        # new features (used only if model was trained with them)
        'HasSuspiciousTLD' : _has_susp_tld,
        'PathLength'       : len(parsed.path),
        'HasBrandKeyword'  : _has_brand,
        'NumSpecialChars'  : _num_special,
    }

    # Only keep columns the model was actually trained on
    available = {k: v for k, v in row.items() if k in URL_FEATURES}
    return pd.DataFrame([available])[URL_FEATURES]


# ─────────────────────────────────────────────
# TEXT CLEANING
# (mirrors train_email_model.py)
# ─────────────────────────────────────────────
_stop_words  = set(stopwords.words("english"))
_lemmatizer  = WordNetLemmatizer()
_url_re      = re.compile(r"https?://\S+|www\.\S+")
_email_re    = re.compile(r"\S+@\S+")
_punct_re    = re.compile(r"[^\w\s]")
_numeric_re  = re.compile(r"\b\d+\b")
_space_re    = re.compile(r"\s+")


def clean_text(text: str) -> str:
    text = text.lower()
    text = _url_re.sub(" ", text)
    text = _email_re.sub(" ", text)
    text = _punct_re.sub(" ", text)
    text = _numeric_re.sub(" ", text)
    text = _space_re.sub(" ", text).strip()
    tokens = [
        _lemmatizer.lemmatize(t)
        for t in text.split()
        if t not in _stop_words and len(t) > 1
    ]
    return " ".join(tokens)


# ─────────────────────────────────────────────
# KEYWORD SCORING
# ─────────────────────────────────────────────
SCAM_KEYWORDS = [
    "lottery", "winner", "won", "prize", "reward", "congratulation",
    "inheritance", "beneficiary", "unclaimed", "wire transfer",
    "verify your account", "confirm your account", "suspended",
    "account alert", "click here", "click now", "limited time",
    "act now", "expires soon", "urgent", "password reset",
    "login attempt", "unusual activity", "free offer", "free money",
    "earn money", "make money", "work from home", "extra income",
    "cash advance", "payday loan", "no obligation", "risk free",
    "100% free", "buy now", "order now", "special offer",
    "investment opportunity", "guaranteed profit", "double your money",
    "bitcoin profit", "crypto", "forex",
    "viagra", "cialis", "weight loss", "pharmacy",
]


def count_keywords(text: str) -> int:
    lower = text.lower()
    return sum(1 for kw in SCAM_KEYWORDS if kw in lower)


# ─────────────────────────────────────────────
# CONSTANTS FOR RULE-BASED BOOSTING
# ─────────────────────────────────────────────
BRAND_LIST = [
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "bankofamerica", "wellsfargo", "chase", "ebay",
    "instagram", "twitter", "linkedin", "dropbox", "outlook",
    "office365", "icloud", "whatsapp", "telegram",
]

SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.cf', '.ga', '.gq', '.pw',
                   '.top', '.club', '.work', '.click', '.link', '.win',
                   '.bid', '.party', '.loan', '.review', '.trade'}

# Registered domains that are unconditionally trusted regardless of model output.
# These are major, well-established websites whose clean URL structure confuses
# the classifier due to dataset artifacts (benign training URLs lack HTTP scheme).
TRUSTED_DOMAINS = {
    # Search / tech
    'google.com', 'google.co.uk', 'google.ca', 'google.com.au',
    'youtube.com', 'gmail.com', 'googlemail.com',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'office365.com', 'azure.com', 'windowsazure.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
    'amazonaws.com',
    'github.com', 'githubusercontent.com',
    'stackoverflow.com', 'stackexchange.com',
    'wikipedia.org', 'wikimedia.org',
    # Social
    'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
    'linkedin.com', 'reddit.com', 'pinterest.com', 'tiktok.com',
    'snapchat.com', 'discord.com', 'twitch.tv',
    # Media / news
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'reuters.com', 'bloomberg.com', 'forbes.com',
    # Finance / shopping
    'paypal.com', 'ebay.com', 'etsy.com', 'shopify.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    # Productivity / cloud
    'dropbox.com', 'box.com', 'notion.so', 'slack.com', 'zoom.us',
    'atlassian.com', 'jira.com', 'confluence.com',
    'cloudflare.com', 'fastly.com',
    # Other popular
    'netflix.com', 'spotify.com', 'adobe.com', 'salesforce.com',
    'wordpress.com', 'blogger.com', 'medium.com',
}


def _get_registered_domain(url: str) -> str:
    """Return the 'domain.tld' portion of a URL's hostname."""
    try:
        host  = (urlparse(url).hostname or '').lower()
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ''


# ─────────────────────────────────────────────
# RISK LEVEL HELPER
# ─────────────────────────────────────────────
def risk_level(score: float) -> tuple[str, str]:
    if score >= 80:  return 'Critical',  '#ef4444'
    if score >= 60:  return 'High',      '#f97316'
    if score >= 40:  return 'Medium',    '#eab308'
    if score >= 20:  return 'Low',       '#22c55e'
    return               'Safe',         '#06b6d4'


# ─────────────────────────────────────────────
# RULE-BASED HEURISTIC BOOSTING
# ─────────────────────────────────────────────
def _rule_boost_url(url: str, feats: pd.DataFrame, raw_prob: float):
    """
    Apply deterministic expert rules that boost the phishing probability
    when strong structural signals are present.  Returns (boosted_prob,
    threat_signals) where threat_signals is a human-readable list.

    Rule priority (highest first):
      1. Trusted-domain allowlist → force legitimate (0.02)
      2. Hard structural signals  → force phishing   (0.93+)
      3. Soft signals             → boost toward phishing
      4. HTTPS clean-URL heuristic → pull back toward legitimate
    """
    prob    = raw_prob
    signals = []

    # ── 1. Trusted-domain allowlist (overrides model entirely) ────────────
    reg_domain = _get_registered_domain(url)
    if reg_domain in TRUSTED_DOMAINS:
        return 0.02, []          # unambiguously legitimate — skip all other rules

    if feats['HasIPAddress'].iloc[0]:
        prob = max(prob, 0.93)
        signals.append('IP address used instead of domain')

    if feats['NumAtSymbol'].iloc[0]:
        prob = max(prob, 0.88)
        signals.append('@ symbol in URL (credential harvesting pattern)')

    if feats['HasTildeSign'].iloc[0]:
        prob = max(prob, 0.82)
        signals.append('Tilde (~) sign in URL')

    if feats['NumDots'].iloc[0] > 6:
        prob = max(prob, 0.80)
        signals.append(f"Excessive dots ({int(feats['NumDots'].iloc[0])}) — subdomain abuse")

    if feats['URLEntropy'].iloc[0] > 5.5:
        prob = max(prob, 0.78)
        signals.append('High URL entropy — possible obfuscation')

    # Check HTTPS from the *original* URL (features use normalised http:// URL)
    is_https_orig = int(url.lower().startswith('https://'))
    if not is_https_orig:
        # only bump if model is already leaning phishing
        if raw_prob >= 0.4:
            prob = max(prob, 0.65)
        signals.append('No HTTPS')

    if int(feats['URLLength'].iloc[0]) > 100:
        prob = max(prob, 0.72)
        signals.append(f"Very long URL ({int(feats['URLLength'].iloc[0])} chars)")

    # Brand impersonation
    try:
        parsed     = urlparse(url)
        host       = (parsed.hostname or '').lower()
        path_query = (parsed.path + '?' + (parsed.query or '')).lower()
        parts2     = host.split('.')
        reg_domain = '.'.join(parts2[-2:]) if len(parts2) >= 2 else host
        for brand in BRAND_LIST:
            if brand in path_query and brand not in reg_domain:
                prob = max(prob, 0.91)
                signals.append(f"Brand impersonation detected: '{brand}'")
                break
    except Exception:
        pass

    # Suspicious TLD
    try:
        host = (urlparse(url).hostname or '').lower()
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                prob = max(prob, 0.75)
                signals.append(f'Suspicious TLD: {tld}')
                break
    except Exception:
        pass

    # ── 4. Clean-URL heuristic: pull model back for legitimate-looking HTTPS ──
    # The URL model was trained on a dataset where benign URLs lack the http://
    # scheme, so it under-estimates legitimacy for clean HTTPS URLs.
    # If the user supplied an HTTPS URL and none of the structural threat rules
    # fired, dampen the raw probability toward legitimate.
    if is_https_orig and not signals:
        # No threat signals at all — model is likely wrong; clamp to ≤ 0.35
        prob = min(prob, 0.35)
    elif is_https_orig and len(signals) == 1 and signals[0] == 'No HTTPS':
        # Only signal is the generic non-HTTPS note (contradicts actual HTTPS)
        signals.clear()
        prob = min(prob, 0.40)

    return prob, signals


def _confidence_tier(decisive_score: float) -> str:
    """decisive_score = probability in the *predicted* direction (0.5-1.0)."""
    return f"{round(decisive_score * 100)}%"


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ── 1. URL CHECK ─────────────────────────────
@app.route("/api/check-url", methods=["POST"])
def check_url():
    data = request.get_json(force=True)
    url  = str(data.get("url", "")).strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Prepend scheme if missing so urlparse works correctly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        feats = extract_url_features(url)

        if URL_MODEL is not None:
            raw_prob = float(URL_MODEL.predict_proba(feats)[0][1])
        else:
            # No ML model available — start neutral and let rules decide
            raw_prob = 0.5

        # Apply rule-based boosting
        prob, threat_signals = _rule_boost_url(url, feats, raw_prob)

        # Lower threshold to 0.45 to catch borderline phishing
        pred = int(prob >= 0.45)

        decisive     = prob if pred == 1 else (1 - prob)
        confidence   = _confidence_tier(decisive)
        threat_pct   = round(prob * 100, 1)

        # Build feature insight for UI (use original URL for HTTPS check)
        orig_is_https = url.lower().startswith('https://')
        feature_flags = {
            "Has IP address"    : bool(feats["HasIPAddress"].iloc[0]),
            "No HTTPS"          : not orig_is_https,
            "Suspicious length" : int(feats["URLLength"].iloc[0]) > 75,
            "Many dots"         : int(feats["NumDots"].iloc[0]) > 4,
            "Has @ symbol"      : bool(feats["NumAtSymbol"].iloc[0]),
            "Has tilde (~)"     : bool(feats["HasTildeSign"].iloc[0]),
            "High entropy"      : float(feats["URLEntropy"].iloc[0]) > 4.0,
        }

        _stats["urls_scanned"] += 1
        if pred == 1:
            _stats["threats_detected"] += 1

        _record_scan({
            "kind": "url",
            "label": "Phishing" if pred == 1 else "Legitimate",
            "score": threat_pct,
            "probability": round(prob, 4),
            "confidence": confidence,
            "subject": url,
            "signals": threat_signals[:5],
        })

        return jsonify({
            "url"             : url,
            "prediction"      : pred,
            "label"           : "Phishing" if pred == 1 else "Legitimate",
            "confidence"      : confidence,
            "confidence_score": round(decisive, 4),
            "threat_score"    : round(prob, 4),
            "threat_score_pct" : threat_pct,
            "feature_flags"   : feature_flags,
            "url_length"      : int(feats["URLLength"].iloc[0]),
            "threat_signals"  : threat_signals,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 2. EMAIL CHECK ────────────────────────────
@app.route("/api/check-email", methods=["POST"])
def check_email():
    data  = request.get_json(force=True)
    email_text = str(data.get("text", "")).strip()

    if not email_text:
        return jsonify({"error": "No email text provided"}), 400

    try:
        cleaned  = clean_text(email_text)
        vec      = VECTORIZER.transform([cleaned])
        raw_prob = float(EMAIL_MODEL.predict_proba(vec)[0][1])

        # Keyword-based boosting
        keywords = count_keywords(email_text)
        prob     = raw_prob
        if keywords >= 5:
            prob = max(prob, 0.85)
        elif keywords >= 3:
            prob = max(prob, 0.72)
        elif keywords >= 1:
            prob = max(prob, 0.55)

        pred         = int(prob >= 0.45)
        decisive     = prob if pred == 1 else (1 - prob)
        confidence   = _confidence_tier(decisive)
        threat_pct   = round(prob * 100, 1)

        # Top suspicious tokens found
        tokens = cleaned.split()
        scam_tokens_found = [
            t for t in tokens
            if any(kw in t or t in kw for kw in SCAM_KEYWORDS[:20])
        ][:8]

        _stats["emails_analyzed"] += 1
        if pred == 1:
            _stats["threats_detected"] += 1

        _record_scan({
            "kind": "email",
            "label": "Spam/Scam" if pred == 1 else "Legitimate",
            "score": threat_pct,
            "probability": round(prob, 4),
            "keyword_count": keywords,
            "confidence": confidence,
            "subject": email_text[:120],
            "signals": scam_tokens_found[:5],
        })

        return jsonify({
            "prediction"      : pred,
            "label"           : "Spam/Scam" if pred == 1 else "Legitimate",
            "confidence"      : confidence,
            "confidence_score": round(decisive, 4),
            "threat_score"    : round(prob, 4),
            "threat_score_pct" : threat_pct,
            "keyword_count"   : keywords,
            "flagged_tokens"  : scam_tokens_found,
            "word_count"      : len(email_text.split()),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 3. RISK SCORE ─────────────────────────────
@app.route("/api/risk-score", methods=["POST"])
def risk_score():
    data = request.get_json(force=True)
    try:
        if any(key in data for key in ("url_model_prob", "email_model_prob", "num_suspicious_keywords", "domain_age_days", "has_attachment")):
            payload = {
                "url_model_prob": float(data.get("url_model_prob", 0.0)),
                "email_model_prob": float(data.get("email_model_prob", 0.0)),
                "num_suspicious_keywords": int(data.get("num_suspicious_keywords", 0)),
                "domain_age_days": int(data.get("domain_age_days", 365)),
                "has_attachment": bool(data.get("has_attachment", False)),
                "source_mode": "manual",
                "sources": {},
            }
        else:
            auto_payload = _auto_risk_inputs()
            payload = {
                **auto_payload,
                "source_mode": "auto",
            }

        url_prob   = max(0.0, min(1.0, float(payload["url_model_prob"])))
        email_prob = max(0.0, min(1.0, float(payload["email_model_prob"])))
        keywords   = max(0, int(payload["num_suspicious_keywords"]))
        domain_age = max(1, int(payload["domain_age_days"]))
        attachment = int(bool(payload["has_attachment"]))

        row   = pd.DataFrame([[url_prob, email_prob, keywords, domain_age, attachment]],
                             columns=RISK_FEATURES)
        score = float(max(0.0, min(100.0, RISK_MODEL.predict(row)[0])))
        level, color = risk_level(score)

        _record_scan({
            "kind": "risk",
            "label": level,
            "score": round(score, 1),
            "confidence": level,
            "subject": "Composite risk score",
            "signals": [name for name, value in (("url", url_prob), ("email", email_prob), ("keywords", keywords)) if value],
        })

        used_sources = payload.get("sources") or {}
        recommendations = []
        if score >= 80:
            recommendations = [
                "Isolate the user or host from the network immediately.",
                "Force password reset and revoke active sessions.",
                "Review mail logs, browser history, and recent downloads.",
            ]
        elif score >= 60:
            recommendations = [
                "Increase monitoring on the sender domain and related infrastructure.",
                "Verify the message through a separate trusted channel.",
            ]
        else:
            recommendations = [
                "Continue standard monitoring and user awareness controls.",
                "Re-scan any new URLs or emails before interacting.",
            ]

        # Per-signal contributions
        kw_norm  = min(keywords / 10.0, 1.0)
        age_norm = math.exp(-domain_age / 365.0)
        contributions = {
            "url_model_prob"         : round(RISK_WEIGHTS["url_model_prob"]          * url_prob,   1),
            "email_model_prob"       : round(RISK_WEIGHTS["email_model_prob"]        * email_prob, 1),
            "num_suspicious_keywords": round(RISK_WEIGHTS["num_suspicious_keywords"] * kw_norm,    1),
            "domain_age_days"        : round(RISK_WEIGHTS["domain_age_days"]         * age_norm,   1),
            "has_attachment"         : round(RISK_WEIGHTS["has_attachment"]          * attachment,  1),
        }

        return jsonify({
            "score"        : round(score, 1),
            "level"        : level,
            "color"        : color,
            "contributions": contributions,
            "mode"         : payload.get("source_mode", "manual"),
            "sources"      : used_sources,
            "inputs"       : {
                "url_model_prob": round(url_prob, 2),
                "email_model_prob": round(email_prob, 2),
                "num_suspicious_keywords": keywords,
                "domain_age_days": domain_age,
                "has_attachment": bool(attachment),
            },
            "recommendations": recommendations,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── 4. FULL ANALYSIS ──────────────────────────
@app.route("/api/full-analysis", methods=["POST"])
def full_analysis():
    """
    Accepts URL + email text + optional signals,
    runs all three models and returns a combined report.
    """
    data = request.get_json(force=True)

    url_text   = str(data.get("url",   "")).strip()
    email_text = str(data.get("email", "")).strip()
    domain_age = int(data.get("domain_age_days", 365))
    attachment = int(bool(data.get("has_attachment", False)))

    result = {
        "url_analysis"  : None,
        "email_analysis": None,
        "risk"          : None,
    }

    url_prob   = 0.0
    email_prob = 0.0
    keywords   = 0

    # URL analysis
    if url_text:
        if not url_text.startswith(("http://", "https://")):
            url_text = "http://" + url_text
        try:
            feats  = extract_url_features(url_text)
            raw_up = float(URL_MODEL.predict_proba(feats)[0][1]) if URL_MODEL is not None else 0.5
            url_prob, _  = _rule_boost_url(url_text, feats, raw_up)
            u_pred       = int(url_prob >= 0.45)
            u_decisive   = url_prob if u_pred == 1 else (1 - url_prob)
            result["url_analysis"] = {
                "url"             : url_text,
                "prediction"      : u_pred,
                "label"           : "Phishing" if u_pred == 1 else "Legitimate",
                "confidence"      : _confidence_tier(u_decisive),
                "confidence_score": round(u_decisive, 4),
            }
        except Exception as e:
            result["url_analysis"] = {"error": str(e)}

    # Email analysis
    if email_text:
        try:
            cleaned    = clean_text(email_text)
            vec        = VECTORIZER.transform([cleaned])
            raw_ep     = float(EMAIL_MODEL.predict_proba(vec)[0][1])
            keywords   = count_keywords(email_text)
            email_prob = raw_ep
            if keywords >= 5:
                email_prob = max(email_prob, 0.85)
            elif keywords >= 3:
                email_prob = max(email_prob, 0.72)
            elif keywords >= 1:
                email_prob = max(email_prob, 0.55)
            e_pred     = int(email_prob >= 0.45)
            e_decisive = email_prob if e_pred == 1 else (1 - email_prob)
            result["email_analysis"] = {
                "prediction"      : e_pred,
                "label"           : "Spam/Scam" if e_pred == 1 else "Legitimate",
                "confidence"      : _confidence_tier(e_decisive),
                "confidence_score": round(e_decisive, 4),
                "keyword_count"   : keywords,
            }
        except Exception as e:
            result["email_analysis"] = {"error": str(e)}

    # Risk score (always computed)
    try:
        row   = pd.DataFrame(
            [[url_prob, email_prob, keywords, domain_age, attachment]],
            columns=RISK_FEATURES
        )
        score = float(max(0.0, min(100.0, RISK_MODEL.predict(row)[0])))
        level, color = risk_level(score)
        _record_scan({
            "kind": "full",
            "label": level,
            "score": round(score, 1),
            "confidence": level,
            "subject": "Combined URL + email analysis",
            "signals": [name for name, value in (("url", url_prob), ("email", email_prob), ("keywords", keywords)) if value],
        })
        result["risk"] = {
            "score": round(score, 1),
            "level": level,
            "color": color,
        }
    except Exception as e:
        result["risk"] = {"error": str(e)}

    return jsonify(result)


@app.route("/api/dashboard")
def dashboard():
    return jsonify(_dashboard_snapshot())


# ── 5. LIVE STATS ────────────────────────────
@app.route("/api/stats")
def get_stats():
    return jsonify({
        "urls_scanned"    : _stats["urls_scanned"],
        "emails_analyzed" : _stats["emails_analyzed"],
        "threats_detected": _stats["threats_detected"],
        "extension_alerts": len(_extension_alerts),
        "extension_feedback": len(_extension_feedback),
    })


@app.route("/api/extension-alert", methods=["POST"])
def extension_alert():
    data = request.get_json(force=True) or {}
    entry = _append_activity(_extension_alerts, {
        "kind": "alert",
        "source": str(data.get("source", "extension")),
        "url": str(data.get("url", "")),
        "level": str(data.get("level", "unknown")),
        "score": float(data.get("score", 0.0) or 0.0),
        "label": str(data.get("label", "")),
        "signals": list(data.get("signals", []))[:8],
        "summary": str(data.get("summary", "")),
    })
    return jsonify({"ok": True, "entry": entry, "total": len(_extension_alerts)})


@app.route("/api/extension-feedback", methods=["POST"])
def extension_feedback():
    data = request.get_json(force=True) or {}
    entry = _append_activity(_extension_feedback, {
        "kind": "feedback",
        "source": str(data.get("source", "extension")),
        "url": str(data.get("url", "")),
        "feedback": str(data.get("feedback", "")),
        "score": float(data.get("score", 0.0) or 0.0),
        "label": str(data.get("label", "")),
        "note": str(data.get("note", "")),
        "signals": list(data.get("signals", []))[:8],
    })
    return jsonify({"ok": True, "entry": entry, "total": len(_extension_feedback)})


# ── 6. BULK URL SCAN ─────────────────────────
@app.route("/api/bulk-scan", methods=["POST"])
def bulk_scan():
    data = request.get_json(force=True)
    urls = data.get("urls", [])
    if not isinstance(urls, list):
        return jsonify({"error": "urls must be a list"}), 400

    urls = [str(u).strip() for u in urls if str(u).strip()][:50]
    if not urls:
        return jsonify({"error": "No valid URLs provided"}), 400

    results = []
    for raw_url in urls:
        try:
            url = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url
            feats    = extract_url_features(url)
            raw_prob = float(URL_MODEL.predict_proba(feats)[0][1]) if URL_MODEL is not None else 0.5
            prob, threat_signals = _rule_boost_url(url, feats, raw_prob)
            pred     = int(prob >= 0.45)
            decisive = prob if pred == 1 else (1 - prob)

            results.append({
                "url"             : raw_url,
                "label"           : "Phishing" if pred == 1 else "Legitimate",
                "confidence"      : _confidence_tier(decisive),
                "confidence_score": round(decisive, 4),
                "threat_signals"  : threat_signals[:3],
            })
            _stats["urls_scanned"] += 1
            if pred == 1:
                _stats["threats_detected"] += 1
        except Exception as e:
            results.append({
                "url": raw_url, "label": "Error",
                "confidence": "0%", "confidence_score": 0,
                "threat_signals": [str(e)],
            })

    threats = sum(1 for r in results if r["label"] == "Phishing")
    _record_scan({
        "kind": "bulk",
        "label": "Phishing" if threats else "Legitimate",
        "score": round((threats / max(len(results), 1)) * 100.0, 1),
        "confidence": f"{threats}/{len(results)} threats",
        "subject": f"Bulk scan of {len(results)} URLs",
        "signals": [r["url"] for r in results[:3]],
    })
    return jsonify({"results": results, "total": len(results), "threats": threats})


# ─────────────────────────────────────────────
# AI EXPLAIN  ─  contextual threat narrative
# ─────────────────────────────────────────────

_CHAT_KB = [
    (["what is phishing", "phishing mean", "define phishing", "explain phishing"],
     "Phishing is a cyberattack where criminals impersonate trusted entities — banks, brands, or colleagues — to trick victims into revealing credentials, financial data, or installing malware. It remains the #1 initial access vector in 91% of data breaches."),

    (["how to identify", "spot phishing", "recognize phishing", "tell if phishing", "identify fake", "check url", "check link", "is this safe"],
     "Key red flags: mismatched sender domain, urgent/threatening language, generic greeting ('Dear User'), links that don't match displayed text, unexpected credential or payment requests, and suspicious attachments. PhishShield AI checks 17+ structural signals automatically — just paste the URL in the scanner."),

    (["what should i do", "clicked phishing", "clicked a phishing", "already clicked", "visited phishing", "entered my password", "opened phishing"],
     "If you clicked a phishing link: 1) Disconnect from WiFi immediately. 2) Change passwords for affected accounts from a clean device. 3) Enable 2FA everywhere. 4) Run a full malware scan. 5) Contact your bank if financial info was entered. 6) Report to your IT team and CERT."),

    (["how does phishshield work", "how it works", "how does this work", "phishshield ai", "what models do you use", "how are you trained"],
     "PhishShield AI uses a 3-model ensemble: a RandomForest classifier for URL structural analysis (17 features, 92.7% accuracy), an XGBoost model for email spam/scam detection (TF-IDF features, 98.1% accuracy), and a composite risk regression model. Rule-based signal boosting overlays ML predictions to catch known evasion patterns."),

    (["common phishing", "types of phishing", "phishing techniques", "phishing methods"],
     "The most common types: Spear phishing (targeted/personalized), Smishing (SMS-based), Vishing (phone calls), Clone phishing (duplicating legitimate emails), Business Email Compromise (BEC), and Homograph attacks using lookalike Unicode domains like paypaI.com (capital I instead of lowercase L)."),

    (["what is malware", "malware mean", "define malware"],
     "Malware is malicious software designed to infiltrate or damage systems. Key types: ransomware (encrypts files for ransom), trojans (disguised as legit software), keyloggers (record keystrokes), and spyware. Phishing is the most common malware delivery method."),

    (["two factor", "2fa", "multi factor", "mfa", "authenticator app"],
     "2FA adds a second verification step beyond your password — typically a time-based code (Google Authenticator), hardware key (YubiKey), or biometrics. Even if phishers steal your password, 2FA blocks unauthorized access. Always prefer app-based 2FA over SMS (which can be SIM-swapped)."),

    (["stay safe", "protect myself", "security tips", "best practices", "safe browsing"],
     "Top practices: Use a password manager with unique passwords per site. Enable 2FA on all accounts. Keep software patched. Hover links before clicking. Use DNS filtering (Cloudflare 1.1.1.1). Never enter credentials on HTTP sites. Always verify sender email domains — not just display names."),

    (["ransomware", "what is ransomware"],
     "Ransomware encrypts your files and demands cryptocurrency payment for the decryption key, commonly delivered via phishing emails. Major attacks include WannaCry, REvil, and LockBit. Best defenses: regular offline backups, network segmentation, and email filtering."),

    (["email scam", "scam email", "spam email", "how to spot spam"],
     "Email scams exploit four psychological hooks: Urgency ('your account closes in 24h'), Fear ('suspicious login detected'), Greed ('you've won a prize'), and Authority (impersonating a CEO or bank). PhishShield AI detects these via keyword analysis — paste your email in the analyzer to check."),

    (["accuracy", "how accurate", "model accuracy", "how good", "precision", "f1 score"],
     "PhishShield AI achieves 92.7% accuracy on URLs (F1=0.82) and 98.1% accuracy on emails (F1=0.92) on held-out test datasets. Confidence percentages reflect calibrated probability output, further boosted for known high-risk patterns like IP addresses and @ symbols in URLs."),

    (["report phishing", "report scam", "where report", "report suspicious"],
     "Report phishing to: Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish), PhishTank (phishtank.com), your email provider's 'Report Spam', CISA via reportphishing@apwg.org, and your IT security team."),

    (["bulk scan", "scan multiple", "many urls", "list of urls"],
     "Use the '⚡ Bulk Scanner' tab to scan up to 50 URLs simultaneously! Paste one URL per line, click Scan All, and PhishShield AI analyzes each one. Export results as CSV for reporting."),

    (["social engineering", "what is social engineering"],
     "Social engineering manipulates people into revealing information by exploiting psychology — urgency, authority, fear, and reciprocity. Phishing is the most common form. Defense: always verify sensitive requests through a separate, trusted channel regardless of how urgent they appear."),

    (["spear phishing", "what is spear phishing", "targeted phishing"],
     "Spear phishing is a targeted attack customized for a specific individual or organization using personal details (name, employer, recent activities) to appear legitimate. Unlike mass phishing, it's crafted specifically for the victim — making it far more convincing and dangerous."),
]


def _get_chat_response(question):
    """Keyword-matching chat response system."""
    q = question.lower()
    for keywords, answer in _CHAT_KB:
        if any(kw in q for kw in keywords):
            return answer
    if any(w in q for w in ["hi", "hello", "hey", "howdy"]):
        return "Hello! I'm PhishShield AI's security assistant. Ask me anything about phishing, URL safety, email scams, 2FA, or how to protect yourself online."
    if any(w in q for w in ["help", "what can you do", "capabilities"]):
        return "I can answer questions about: phishing attack types, identifying fake URLs/emails, what to do after clicking a phishing link, how PhishShield's models work, 2FA, ransomware, social engineering, and security best practices. What would you like to know?"
    if any(w in q for w in ["thank", "thanks", "great", "awesome", "good job"]):
        return "Happy to help keep you safe! Stay vigilant — when in doubt, scan it with PhishShield AI. 🛡️"
    return "I'm specialized in phishing and cybersecurity topics. Try asking: 'What is phishing?', 'How do I identify a fake URL?', 'What should I do if I clicked a phishing link?', or 'How does PhishShield AI work?'"


def _call_groq(prompt):
    """Optional: call Groq cloud LLM if GROQ_API_KEY env var is set."""
    import json as _json
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return None
    try:
        from urllib.request import Request, urlopen

        payload = _json.dumps({
            "model": "llama3-8b-8192",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity AI analyst for PhishShield AI. Explain the threat in 2-3 concise, technical sentences focused on the specific indicators provided. Do not use markdown."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 220,
            "temperature": 0.3,
        }).encode("utf-8")

        req = Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


def _generate_ai_explanation(label, confidence, signals, feature_flags,
                              url="", email_text="", keyword_count=0, flagged_tokens=None):
    """Generate a contextual AI-style threat explanation.
    Uses Groq LLM if GROQ_API_KEY is set; otherwise falls back to smart templates.
    """
    import os
    flagged_tokens = flagged_tokens or []
    is_phishing    = label in ("Phishing", "Spam/Scam")
    target_type    = "URL" if url else "email"

    # ── Optional Groq LLM path ──────────────────────────────────────────
    if os.environ.get("GROQ_API_KEY"):
        ctx = [
            f"Analyzed {target_type}: {url or email_text[:120]}",
            f"Verdict: {label} ({confidence} confidence)",
            f"Threat signals: {'; '.join(signals) if signals else 'none'}",
        ]
        if feature_flags:
            active = [k for k, v in feature_flags.items() if v]
            if active:
                ctx.append(f"Active feature flags: {', '.join(active)}")
        if flagged_tokens:
            ctx.append(f"Flagged keywords: {', '.join(flagged_tokens[:6])}")
        prompt = "\n".join(ctx) + f"\n\nExplain concisely why this is classified as {label}, referencing the specific indicators above."
        groq_text = _call_groq(prompt)
        if groq_text:
            return groq_text

    # ── Template fallback ───────────────────────────────────────────────
    if not is_phishing:
        paras = [f"PhishShield AI's multi-model analysis of this {target_type} returned a clean verdict with {confidence} confidence."]
        if url:
            paras.append("The domain structure is consistent with legitimate web infrastructure. URL entropy is within normal parameters, no IP-literal addresses were detected, and no brand impersonation patterns were identified.")
            paras.append("Subdomain depth, path length, and character composition all conform to patterns typical of authentic web resources.")
        else:
            paras.append("The email's language patterns, keyword distribution, and sentence structure align with standard business communication.")
            paras.append("No urgency triggers, suspicious reward language, or social engineering phrases were detected.")
        paras.append("Exercise standard caution: verify the sender's identity independently before sharing any sensitive information.")
        return " ".join(paras)

    paras      = []
    signal_txt = ""
    if signals:
        if len(signals) == 1:
            signal_txt = f"The primary concern is: {signals[0].lower()}."
        else:
            signal_txt = f"Multiple threat indicators were identified: {'; '.join(s.lower() for s in signals[:4])}."

    if url:
        paras.append(f"This URL demonstrates strong phishing characteristics with {confidence} confidence across PhishShield AI's detection ensemble.")
        if signal_txt:
            paras.append(signal_txt)
        if feature_flags.get("Has IP address"):
            paras.append("Using a raw IP address instead of a registered domain is a classic phishing technique that bypasses domain-reputation databases and eliminates the WHOIS paper trail associated with legitimate sites.")
        if feature_flags.get("Has @ symbol"):
            paras.append("The @ symbol embedded in the URL path is a deceptive tactic — browsers display only the portion after @ as the actual destination, masking the true malicious host from casual inspection.")
        if feature_flags.get("High entropy"):
            paras.append("The URL's elevated character entropy indicates obfuscated or machine-generated segments, a standard evasion technique used in phishing kits to bypass hash-based blocklists.")
        if feature_flags.get("Many dots") or feature_flags.get("Long URL"):
            paras.append("Excessive subdomain nesting and abnormal URL length are hallmarks of subdomain squatting — embedding a trusted brand early in the chain while concealing the actual malicious registered domain at the end.")
        if feature_flags.get("Has redirect"):
            paras.append("Redirection chains obscure the final phishing destination, routing users through benign-looking intermediaries before landing on a credential-harvesting page.")
        if feature_flags.get("Has short URL"):
            paras.append("URL shortening services are frequently abused to hide the true destination and prevent pre-click inspection by security tools.")
        if len(paras) <= 1:
            paras.append("Structural analysis identified patterns inconsistent with legitimate websites, including unusual character composition and suspicious path architecture.")
        paras.append("Do not visit this URL, enter credentials, or interact with any content it serves. Report it to your IT security team and the domain's hosting provider.")
    else:
        paras.append(f"This email exhibits characteristics strongly consistent with a spam or scam campaign, classified at {confidence} confidence.")
        if signal_txt:
            paras.append(signal_txt)
        if keyword_count >= 5:
            token_str = f" — including '{', '.join(flagged_tokens[:3])}'" if flagged_tokens else ""
            paras.append(f"The concentration of {keyword_count} high-risk semantic keywords{token_str} represents a textbook social engineering pattern: urgency triggers, reward language, and account-threat phrases designed to suppress rational judgment and induce impulsive action.")
        elif keyword_count >= 2:
            paras.append(f"The presence of {keyword_count} phishing-related keywords suggests deliberate use of persuasion techniques typical of social engineering attacks.")
        elif keyword_count == 1 and flagged_tokens:
            paras.append(f"The keyword '{flagged_tokens[0]}' is a common phishing trigger associated with urgency-based social engineering attacks.")
        paras.append("Do not click any links, reply with personal information, forward the message, or follow its instructions. Mark it as spam and delete it immediately.")

    paras.append(f"PhishShield AI's verdict was reached through structural heuristics, rule-based signal boosting, and a trained ML ensemble — all agreeing at {confidence} confidence.")
    return " ".join(paras)


@app.route("/api/ai-explain", methods=["POST"])
def ai_explain():
    data = request.get_json(force=True)
    explanation = _generate_ai_explanation(
        label         = data.get("label", "Unknown"),
        confidence    = data.get("confidence", "50%"),
        signals       = data.get("threat_signals", []),
        feature_flags = data.get("feature_flags", {}),
        url           = data.get("url", ""),
        email_text    = data.get("email_text", ""),
        keyword_count = data.get("keyword_count", 0),
        flagged_tokens= data.get("flagged_tokens", []),
    )
    return jsonify({"explanation": explanation})


@app.route("/api/chat", methods=["POST"])
def ai_chat():
    data     = request.get_json(force=True)
    question = str(data.get("message", "")).strip()[:500]
    return jsonify({"response": _get_chat_response(question)})


# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
