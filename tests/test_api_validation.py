"""
PhishShield AI - API Input Validation & Edge Case Regression Test Suite
======================================================================
Tests defensive parsing, HTTP status codes, schema consistency,
and edge case protections across all PhishShield endpoints.

Follows Phase 8 guidelines:
- Fast, isolated test suite.
- Uses lightweight fixture for the 800MB URL model artifact.
- Exercises real route validation, risk scoring, email models, and database.
"""

import unittest
import math
from unittest.mock import MagicMock, patch
import numpy as np
import pandas as pd
import joblib

# Set up lightweight mock for 800MB url_model.pkl before importing phishshield
_orig_load = joblib.load

def _fast_model_loader(filepath, *args, **kwargs):
    if "url_model.pkl" in str(filepath):
        mock_url_model = MagicMock()
        mock_url_model.predict_proba.return_value = np.array([[0.1, 0.9]])
        return {
            "model": mock_url_model,
            "feature_cols": [
                'URLLength', 'DomainLength', 'IsHTTPS', 'NumDots', 'NumHyphens',
                'NumSubdomains', 'HasIPAddress', 'NumSlashes', 'NumAtSymbol',
                'NumQueryParams', 'NumAmpersand', 'NumEquals', 'NumPercent',
                'NumDigits', 'HasDoubleSlash', 'HasTildeSign', 'URLEntropy'
            ]
        }
    return _orig_load(filepath, *args, **kwargs)

with patch("joblib.load", side_effect=_fast_model_loader):
    from phishshield import create_app, limiter
    from phishshield.models import db, Scan


class TestAPIInputValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        limiter.enabled = False
        cls.client = cls.app.test_client()

    def setUp(self):
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    # =========================================================================
    # 1. /api/check-url Edge Cases
    # =========================================================================

    def test_check_url_valid_payload(self):
        """Valid URL request should return 200 with predictable schema."""
        res = self.client.post("/api/check-url", json={"url": "https://google.com"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("url", data)
        self.assertIn("label", data)
        self.assertIn("confidence", data)
        self.assertIn("threat_signals", data)

    def test_check_url_non_dict_payload_returns_400(self):
        """Sending a JSON list or string instead of a dict should return 400 Bad Request."""
        res = self.client.post("/api/check-url", json=["https://google.com"])
        self.assertEqual(res.status_code, 400, "Non-dict JSON payload should return 400")
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_url_null_url_returns_400(self):
        """Sending {'url': None} must return 400 and not evaluate string 'None'."""
        res = self.client.post("/api/check-url", json={"url": None})
        self.assertEqual(res.status_code, 400, "Null URL must return 400 Bad Request")
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_url_empty_or_whitespace_returns_400(self):
        """Sending empty or whitespace URL should return 400 Bad Request."""
        for payload in [{"url": ""}, {"url": "   "}, {}]:
            res = self.client.post("/api/check-url", json=payload)
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertIn("error", data)

    # =========================================================================
    # 2. /api/check-email Edge Cases
    # =========================================================================

    def test_check_email_valid_payload(self):
        """Valid email request should return 200."""
        res = self.client.post("/api/check-email", json={"text": "Meeting scheduled for tomorrow at 10am."})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("label", data)
        self.assertIn("threat_score", data)

    def test_check_email_non_dict_payload_returns_400(self):
        """Sending a non-dict payload should return 400 Bad Request, not 500."""
        res = self.client.post("/api/check-email", json=["Urgent account verification required!"])
        self.assertEqual(res.status_code, 400, "Non-dict email payload should return 400")
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_email_null_text_returns_400(self):
        """Sending {'text': None} must return 400 Bad Request, not analyze string 'None'."""
        res = self.client.post("/api/check-email", json={"text": None})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_check_email_empty_or_whitespace_returns_400(self):
        """Sending empty or whitespace text should return 400."""
        for payload in [{"text": ""}, {"text": "   \n\t  "}, {}]:
            res = self.client.post("/api/check-email", json=payload)
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertIn("error", data)

    # =========================================================================
    # 3. /api/risk-score Edge Cases
    # =========================================================================

    def test_risk_score_valid_manual_payload(self):
        """Valid manual inputs return 200 with calibrated score."""
        res = self.client.post("/api/risk-score", json={
            "url_model_prob": 0.85,
            "email_model_prob": 0.72,
            "num_suspicious_keywords": 4,
            "domain_age_days": 30,
            "has_attachment": True
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("score", data)
        self.assertIn("level", data)
        self.assertTrue(0 <= data["score"] <= 100)

    def test_risk_score_non_dict_payload_returns_400(self):
        """Non-dict payload to /api/risk-score must return 400, not 500."""
        res = self.client.post("/api/risk-score", json=[0.85, 0.72, 4, 30, True])
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_risk_score_nan_infinity_sanitization(self):
        """Passing NaN or Inf values must not crash scikit-learn with 500 ValueError."""
        res = self.client.post("/api/risk-score", json={
            "url_model_prob": "NaN",
            "email_model_prob": "Infinity",
            "num_suspicious_keywords": "invalid",
            "domain_age_days": -50,
            "has_attachment": False
        })
        self.assertEqual(res.status_code, 200, "NaN/Inf input must be sanitized and return 200")
        data = res.get_json()
        self.assertTrue(0 <= data["score"] <= 100)

    def test_risk_score_auto_mode_empty_history(self):
        """Auto mode with no scan history should return 400 Bad Request, not 500 ValueError."""
        res = self.client.post("/api/risk-score", json={})
        self.assertEqual(res.status_code, 400, "Auto mode with empty DB should return 400")
        data = res.get_json()
        self.assertIn("error", data)

    # =========================================================================
    # 4. /api/bulk-scan Resilience & Index Alignment
    # =========================================================================

    def test_bulk_scan_route_exists(self):
        """Endpoint /api/bulk-scan must be registered and return 200."""
        res = self.client.post("/api/bulk-scan", json={"urls": ["https://google.com"]})
        self.assertEqual(res.status_code, 200, "/api/bulk-scan endpoint must return 200")

    def test_bulk_scan_non_dict_payload_returns_400(self):
        """Posting a list or string to /api/bulk-scan should return 400 Bad Request, not 500."""
        res = self.client.post("/api/bulk-scan", json=["https://google.com"])
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_bulk_scan_missing_or_invalid_urls_returns_400(self):
        """Missing 'urls' field or non-list 'urls' should return 400."""
        for payload in [{}, {"urls": "https://google.com"}, {"urls": 123}]:
            res = self.client.post("/api/bulk-scan", json=payload)
            self.assertEqual(res.status_code, 400)
            data = res.get_json()
            self.assertIn("error", data)

    def test_bulk_scan_preserves_order_and_index_alignment(self):
        """
        Input array with empty strings, nulls, and valid URLs must preserve
        exact index alignment. Output length must equal input length.
        """
        inputs = [
            "https://google.com",
            "",
            None,
            "http://paypa1.com.evil-xyz.biz/verify"
        ]
        res = self.client.post("/api/bulk-scan", json={"urls": inputs})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        results = data.get("results", [])
        self.assertEqual(len(results), len(inputs), "Result array length must exactly match input array length")

        # Item 0: valid google.com
        self.assertEqual(results[0]["url"], "https://google.com")
        self.assertIn(results[0]["label"], ("Legitimate", "Phishing"))

        # Item 1: empty string -> should be marked invalid/error without crashing or dropping
        self.assertEqual(results[1]["url"], "")
        self.assertEqual(results[1]["label"], "Error")

        # Item 2: null -> should be marked invalid/error, NOT scanned as "http://None"
        self.assertEqual(results[2]["label"], "Error")
        self.assertNotEqual(results[2].get("url"), "http://None")

        # Item 3: phishing URL
        self.assertEqual(results[3]["url"], "http://paypa1.com.evil-xyz.biz/verify")
        self.assertIn(results[3]["label"], ("Legitimate", "Phishing"))

    def test_bulk_scan_does_not_leak_exception_in_signals(self):
        """When an entry fails, raw Python exception must not corrupt threat_signals."""
        res = self.client.post("/api/bulk-scan", json={"urls": [""]})
        self.assertEqual(res.status_code, 200)
        results = res.get_json().get("results", [])
        self.assertEqual(len(results), 1)
        self.assertIn("error", results[0])
        self.assertEqual(results[0]["threat_signals"], [])

    # =========================================================================
    # 5. /api/full-analysis Route Availability & Validation
    # =========================================================================

    def test_full_analysis_route_exists(self):
        """Endpoint /api/full-analysis must be registered and return 200."""
        res = self.client.post("/api/full-analysis", json={
            "url": "https://google.com",
            "email": "Invoice details for review."
        })
        self.assertEqual(res.status_code, 200, "/api/full-analysis endpoint must be registered")
        data = res.get_json()
        self.assertIn("url_analysis", data)
        self.assertIn("email_analysis", data)
        self.assertIn("risk", data)

    # =========================================================================
    # 6. /api/chat Parameter Harmonization (Extension vs Web UI)
    # =========================================================================

    def test_chat_accepts_message_and_question_parameters(self):
        """
        Chat endpoint must accept both 'message' (used by Web UI)
        and 'question' (used by Chrome Extension popup).
        """
        # Test Web UI key
        res_web = self.client.post("/api/chat", json={"message": "What is phishing?"})
        self.assertEqual(res_web.status_code, 200)
        web_reply = res_web.get_json().get("response", "")
        self.assertIn("phishing", web_reply.lower())

        # Test Chrome Extension key
        res_ext = self.client.post("/api/chat", json={"question": "What is phishing?"})
        self.assertEqual(res_ext.status_code, 200)
        ext_reply = res_ext.get_json().get("response", "")
        self.assertIn("phishing", ext_reply.lower(), "Chrome Extension query using 'question' must be parsed")


if __name__ == "__main__":
    unittest.main()
