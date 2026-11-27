# Technical Assessment — Baseline Environment & System State

**Target Repository:** `Tarunkush0620/PhishShield-AI`  
**Date:** November 2026  

---

## 1. Local Environment Specification

Prior to introducing changes or executing tests, the host execution environment was inspected:

| Property | Value | Notes |
| :--- | :--- | :--- |
| **Operating System** | Windows 11 / Windows NT 10.0 | Powershell & CMD shells available |
| **Primary Python** | Python 3.14.0 (`.\.venv\Scripts\python.exe`) | Active virtual environment |
| **Secondary Python** | Python 3.11.5 (`C:\Program Files\Python311\python.exe`) | System fallback |
| **Git Version** | Git 2.47.1.windows.1 | Working tree cleanly tracked |
| **Active Branch** | `assessment/ai-code-review-benchmark` | Branched from `main` (`c104dc2`) |
| **Gunicorn Target** | `phishshield app:app` | Specified in `Procfile` |

---

## 2. Model Artifacts & Data Tracking

The repository depends on pre-trained serialized scikit-learn models located in `training/`:

| Artifact | Size on Disk | Git Tracked? | Health Status |
| :--- | :--- | :--- | :--- |
| `training/url_model.pkl` | 803.4 MB | Yes (LFS / direct commit) | Valid `RandomForestClassifier` (17 features) |
| `training/email_model.pkl` | 6.2 MB | Yes | Valid `MultinomialNB` |
| `training/vectorizer.pkl` | 1.8 MB | Yes | Valid `TfidfVectorizer` (5,000 vocab) |
| `training/risk_model.pkl` | 1.3 MB | Yes | Valid `RandomForestRegressor` (5 features) |

> [!WARNING]
> Because `url_model.pkl` exceeds 800 MB, standard un-mocked application imports incur substantial deserialization latency (60–90 seconds). All automated unit tests must isolate this loading process using lightweight fixtures to achieve sub-10-second test cycles.

---

## 3. Baseline Testing Infrastructure Evaluation

Inspection of testing facilities prior to Phase 11:
- **Existing File:** `phishshield/test_api.py`
- **Assessment:** Not an automated unit test suite. It was a manual smoke-test script using `requests.post()` against `http://localhost:5000/api/...`.
- **Defects of Baseline Approach:**
  1. Required a live, manually started server process running on port 5000.
  2. Depended on a network socket and external port availability.
  3. Modified live SQLite database records during execution.
  4. Did not assert boundary conditions, non-dict payloads, or exception safety.
  5. Failed immediately if the server was offline (`ConnectionRefusedError`).

---

## 4. Working Tree State Discovery

Upon inspecting the repository working tree, an uncommitted architectural refactoring was identified:
- The original monolithic `phishshield/app.py` had been split into:
  - `phishshield/__init__.py` (`create_app` factory pattern)
  - `phishshield/routes.py` (API routes blueprint)
  - `phishshield/models.py` (SQLAlchemy models)
  - `phishshield/ml_services.py` (Feature extractors and model loaders)
  - `phishshield/run.py` (Standalone dev server runner)
- **Critical Regressions in Uncommitted State:**
  - `phishshield/app.py` was deleted, breaking Heroku/Render `Procfile` (`web: gunicorn --chdir phishshield app:app`).
  - Four endpoints were missing from `routes.py`:
    - `/api/bulk-scan`
    - `/api/full-analysis`
    - `/api/extension-alert`
    - `/api/extension-feedback`
  - Parameter mismatch on `/api/chat`: Chrome extension sent `{"question": "..."}`, whereas `routes.py` expected `{"message": "..."}`.

---

## 5. Baseline Baseline Test Command & Execution Log

```powershell
# Verification of baseline smoke-test script behavior without running server:
.\.venv\Scripts\python.exe phishshield/test_api.py
```
**Result:** Exit code 1 (`requests.exceptions.ConnectionError: HTTPConnectionPool(host='localhost', port=5000): Max retries exceeded`).  
**Conclusion:** Automated testing was completely absent; introducing a proper `unittest` test suite was mandatory.
