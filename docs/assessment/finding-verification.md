# Technical Assessment — Empirical Finding Verification

**Assessment Context:** Verification of reviewer findings through code execution, tracebacks, and automated unit tests.

---

## 1. Verified Defect 1: Uncaught `OverflowError` in `_clean_int()`

### Reviewers Identifying Issue:
Security Reviewer, QA Reviewer, Systems Architect (Unanimous).

### Code Investigation:
In `phishshield/routes.py`, `_clean_int()` was implemented as:
```python
def _clean_int(val, min_val=0, max_val=100000, default=0):
    try:
        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            return default
        i = int(float(val))
        return max(min_val, min(max_val, i))
    except (TypeError, ValueError):
        return default
```

### Empirical Reproduction:
When a client sends:
```json
{
  "url_model_prob": 0.5,
  "domain_age_days": "Infinity",
  "num_suspicious_keywords": "inf"
}
```
1. `val` is of type `str` (`"Infinity"`).
2. `isinstance(val, float)` is `False`. The `math.isinf()` guard is completely bypassed.
3. `float("Infinity")` executes and returns Python float `inf`.
4. `int(inf)` executes, which in Python 3 raises:
   ```text
   OverflowError: cannot convert float infinity to integer
   ```
5. Because the exception handler only caught `(TypeError, ValueError)`, `OverflowError` escaped unhandled, resulting in an HTTP 500 error.

### Regression Test:
`test_risk_score_overflow_error_with_string_infinity` in `tests/test_api_validation.py`.
- **Pre-Fix:** HTTP 500 Internal Server Error (`OverflowError`).
- **Post-Fix:** HTTP 200 OK with `domain_age_days` safely defaulted to 365.

---

## 2. Verified Defect 2: Case-Sensitive URL Scheme Corruption

### Reviewers Identifying Issue:
QA Reviewer.

### Code Investigation:
In `phishshield/routes.py`:
```python
if not url.startswith(("http://", "https://")):
    url = "http://" + url
```

### Empirical Reproduction:
When a user entered `"HTTPS://google.com"`:
1. `"HTTPS://google.com".startswith(("http://", "https://"))` evaluated to `False`.
2. The code executed `"http://" + "HTTPS://google.com"`, resulting in `"http://HTTPS://google.com"`.
3. `extract_url_features()` parsed hostname as `"http"`, computed incorrect entropy, and marked `No HTTPS: True` despite the original URL being HTTPS.

### Regression Test:
`test_check_url_case_insensitive_scheme` in `tests/test_api_validation.py`.
- **Pre-Fix:** Returned `{"url": "http://HTTPS://google.com"}`.
- **Post-Fix:** Returned `{"url": "HTTPS://google.com"}` and evaluated HTTPS features accurately.

---

## 3. Verified Defect 3: Auto Risk Score Corrupted by Bulk Scans

### Reviewers Identifying Issue:
QA Reviewer, Systems Architect.

### Code Investigation:
In `phishshield/routes.py`:
```python
latest_url = Scan.query.filter(Scan.kind.in_(['url', 'full', 'bulk'])).order_by(Scan.id.desc()).first()
```
In `bulk_scan()`:
```python
_record_scan({
    "kind": "bulk",
    "label": "Phishing" if threat_count else "Legitimate",
    "score": round((threat_count / max(len(results), 1)) * 100.0, 1),
    # probability is NOT provided, so it is stored as NULL in the database!
})
```

### Empirical Reproduction:
1. User scans a phishing URL -> `probability = 0.95` stored.
2. User runs a bulk scan of 5 URLs -> `Scan(kind="bulk", probability=None)` stored.
3. User navigates to dashboard to generate composite risk score in `auto` mode.
4. `latest_url` query fetches the `bulk` record.
5. `latest_url.probability` is `None` -> defaults to `0.0`.
6. Composite risk model is evaluated with `url_prob = 0.0`, masking severe threat indicators.

### Regression Test:
`test_risk_score_auto_mode_ignores_bulk_scan_without_prob` in `tests/test_api_validation.py`.
- **Pre-Fix:** Auto score returned 400 or evaluated URL probability as 0.0.
- **Post-Fix:** Auto score queries only `['url', 'full']` and correctly consumes the individual URL probability.

---

## 4. Verified Defect 4: Single-Quote Representation Crashing Frontend

### Reviewers Identifying Issue:
Security Reviewer, QA Reviewer.

### Code Investigation:
In `extension_alert()` and `extension_feedback()`:
```python
alert = ExtensionAlert(details=str(data))
```

### Empirical Reproduction:
1. Browser extension posts `{"url": "https://phish.xyz", "blocked": true}`.
2. `str(data)` converts the Python dict to string: `"{'url': 'https://phish.xyz', 'blocked': True}"`.
3. Client dashboard fetches `/api/dashboard`, which returns `details` as string.
4. Browser JavaScript executes `JSON.parse(alert.details)`.
5. Fails with `SyntaxError: Unexpected token ' in JSON at position 1`.

### Regression Test:
`test_extension_alert_and_feedback_stored_as_valid_json` in `tests/test_api_validation.py`.
- **Pre-Fix:** Stored raw string with single quotes.
- **Post-Fix:** Stored RFC 8259 JSON via `json.dumps(data)` and returned structured dictionary objects in dashboard API.
