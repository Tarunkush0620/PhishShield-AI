# Technical Assessment — Comprehensive Repository Audit

**Target Repository:** `Tarunkush0620/PhishShield-AI`  
**Base Commit:** `c104dc2` (`main`)  
**Assessment Branch:** `assessment/ai-code-review-benchmark`  
**Engineer:** Software Engineering Internship Candidate  
**Date:** November 2026  

---

## 1. Executive Summary

A comprehensive architectural, security, and quality assurance audit was conducted on the **PhishShield AI** repository. PhishShield AI is an intelligent cybersecurity application combining machine learning classifiers (URL phishing detection, email spam classification, composite risk scoring), a Flask REST API backend, an interactive web UI, and a Chromium Manifest V3 browser extension.

The audit revealed a working, high-value cybersecurity product with significant engineering strengths in model training, heuristic threat intelligence, and user-facing tooling. However, critical vulnerabilities and architectural friction points were uncovered across API error handling, input validation, test isolation, and deployment ergonomics.

---

## 2. Architecture & Component Inventory

### 2.1 Backend (`phishshield/`)
- **Web Framework:** Flask 3.1.0 with Flask-CORS and Flask-Limiter.
- **ORM / Persistence:** Flask-SQLAlchemy 3.1.1 with SQLite database (`phishshield.db`).
  - `GlobalStat`: Tracks total URLs scanned, emails analyzed, and threats detected.
  - `Scan`: Logs historical scans with confidence scores, labels, timestamps, and threat signals.
  - `ExtensionAlert`: Logs extension-triggered detection alerts.
  - `ExtensionFeedback`: Logs user false positive/negative feedback.
- **Entry Points & Configuration:**
  - `Procfile`: Specifies `web: gunicorn --chdir phishshield app:app`.
  - `app.py`: Application entry point.
  - Working tree state at audit: A partial migration had begun to refactor `app.py` into `__init__.py`, `routes.py`, `models.py`, `ml_services.py`, and `run.py`. Four active API routes were missing from this blueprint refactor (`/api/bulk-scan`, `/api/full-analysis`, `/api/extension-alert`, `/api/extension-feedback`), which broke existing frontend features.

### 2.2 Machine Learning Inference & Pipelines (`training/`)
- **URL Model (`url_model.pkl`):** 803.4 MB Random Forest classifier trained on 17 extracted lexical, structural, and entropy features (`URLLength`, `HasIPAddress`, `URLEntropy`, etc.). Augmented with heuristic rule boosts (`_rule_boost_url`).
- **Email Model (`email_model.pkl` & `vectorizer.pkl`):** 6.2 MB Multinomial Naive Bayes classifier with TF-IDF vectorizer (5,000 features) combined with regex-based scam keyword frequency heuristics.
- **Risk Model (`risk_model.pkl`):** 1.3 MB Random Forest regressor (100 estimators) predicting composite risk (0–100) based on URL probability, email probability, keyword counts, domain age in days, and attachment indicators.

### 2.3 Browser Extension (`browser-extension/`)
- **Manifest:** Manifest V3 (`manifest.json`) requesting permissions: `activeTab`, `storage`, `notifications`, `alarms`, with host permissions for `<all_urls>` and `https://mail.google.com/*`.
- **Background Worker (`background.js`):** Intercepts tab updates, manages telemetry, and communicates with the backend API.
- **Content Scripts (`content.js`):** Injected into pages and Gmail web interface to scan DOM text and hyperlinks. Includes client-side PII redaction (phone numbers, emails, SSNs).
- **Popup (`popup.html`, `popup.js`, `popup.css`):** User dashboard, live scan triggers, heuristic details, and security chatbot interface.

---

## 3. Detailed Audit Findings

### Finding A: Uncaught `OverflowError` on Float Infinity Inputs
- **File:** `phishshield/routes.py` (`_clean_int()`)
- **Severity:** High (Availability / Denial of Service)
- **Description:** When JSON payloads contained string representations of infinity (`"Infinity"`, `"-inf"`) for numeric integer inputs (`domain_age_days`, `num_suspicious_keywords`), `isinstance(val, float)` evaluated to `False`. The code executed `int(float("Infinity"))`, raising `OverflowError: cannot convert float infinity to integer`. Because only `(TypeError, ValueError)` were caught, unhandled 500 Internal Server Errors were triggered.

### Finding B: Case-Sensitive URL Scheme Corruption
- **File:** `phishshield/routes.py` (`check_url`, `bulk_scan`, `full_analysis`)
- **Severity:** Medium (Functional Bug / Threat Evasion)
- **Description:** The URL scheme check used `url.startswith(("http://", "https://"))`. When a user submitted an uppercase or mixed-case scheme (`"HTTPS://google.com"`), the system prepended `"http://"`, resulting in `"http://HTTPS://google.com"`. This corrupted domain extraction, broke entropy calculations, and caused valid HTTPS sites to be flagged as lacking HTTPS.

### Finding C: Risk Score Historical Auto-Scoring Polluted by Bulk Scans
- **File:** `phishshield/routes.py` (`risk_score`)
- **Severity:** High (Data Integrity / ML Logic)
- **Description:** In auto risk score mode, the API queried `Scan.kind.in_(['url', 'full', 'bulk'])`. However, bulk scans record batch statistics and store `probability=None`. If the latest scan was a bulk scan, `latest_url.probability` resolved to `None` (defaulting to 0.0), completely zeroing out the URL risk component for subsequent composite scores.

### Finding D: Extension Data Serialized with Python `str()` Repr
- **File:** `phishshield/routes.py` (`extension_alert`, `extension_feedback`)
- **Severity:** Medium (Schema Corruption / UI Crash)
- **Description:** Ingestion routes stored incoming payloads using `details=str(data)`. This wrote Python dictionary strings with single quotes (`{'url': 'https://...'}`) into the database instead of valid RFC 8259 JSON (`{"url": "https://..."}`). When `/api/dashboard` returned these strings to the frontend, browser-side `JSON.parse()` threw unhandled exceptions.

### Finding E: Verbose Internal Exception Disclosure in Error Responses
- **File:** `phishshield/routes.py`
- **Severity:** Medium (CWE-209: Information Exposure Through an Error Message)
- **Description:** API 500 error handlers returned `{"details": str(e)}`. In production, this exposed internal paths, library versions, database schema names, and runtime tracebacks to unauthenticated callers.

### Finding F: Test Database Engine Re-Binding Failure
- **File:** `phishshield/__init__.py`
- **Severity:** High (Test Suite Reliability)
- **Description:** `create_app()` initialized SQLAlchemy without accepting a test configuration dictionary. Overriding `app.config["SQLALCHEMY_DATABASE_URI"]` post-creation did not rebind SQLAlchemy's underlying engine. Consequently, automated tests executed against the on-disk `phishshield.db` and dropped production tables on `tearDown()`.

### Finding G: 803 MB Pickle Deserialization Latency
- **File:** `phishshield/ml_services.py`
- **Severity:** Medium (Startup Latency / Memory Footprint)
- **Description:** Loading `url_model.pkl` synchronously on startup consumes ~1.2 GB of RAM and requires 60–90 seconds on Windows filesystem environments, causing startup timeouts and making un-mocked unit testing impractical.

---

## 4. Remediation Prioritization

| Finding | Severity | Category | Status |
| :--- | :--- | :--- | :--- |
| Uncaught `OverflowError` on Infinity | High | Robustness / DoS | Resolved & Tested |
| Auto-Scoring Bulk Scan Corruption | High | Logic / ML Integrity | Resolved & Tested |
| Test DB Re-Binding Collision | High | Test Infrastructure | Resolved & Tested |
| Case-Sensitive URL Scheme Prepension | Medium | Functional / ML | Resolved & Tested |
| Extension Single-Quote JSON Deserialization | Medium | API Schema / Frontend | Resolved & Tested |
| Verbose Exception Detail Disclosure | Medium | Security (CWE-209) | Resolved & Tested |
| Missing Blueprint Endpoints | Critical | System Integration | Resolved & Tested |
