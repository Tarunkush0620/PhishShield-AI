import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class GlobalStat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    urls_scanned = db.Column(db.Integer, default=0)
    emails_analyzed = db.Column(db.Integer, default=0)
    threats_detected = db.Column(db.Integer, default=0)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(50))  # 'url', 'email', 'risk', 'full', 'bulk'
    timestamp = db.Column(db.String(100), default=lambda: datetime.now(timezone.utc).isoformat())
    label = db.Column(db.String(50))
    score = db.Column(db.Float)
    probability = db.Column(db.Float, nullable=True)
    confidence = db.Column(db.String(50), nullable=True)
    subject = db.Column(db.Text, nullable=True)
    signals = db.Column(db.Text, nullable=True)  # Store as JSON string
    keyword_count = db.Column(db.Integer, nullable=True)

    def set_signals(self, signals_list):
        self.signals = json.dumps(signals_list)

    def get_signals(self):
        if not self.signals:
            return []
        try:
            val = json.loads(self.signals)
            if isinstance(val, dict) and "threat_signals" in val:
                return val.get("threat_signals", [])
            return val if isinstance(val, list) else []
        except (json.JSONDecodeError, TypeError, ValueError):
            return []

    def get_raw_signals(self):
        if not self.signals:
            return {}
        try:
            val = json.loads(self.signals)
            return val if isinstance(val, dict) else {"threat_signals": val}
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}

class ExtensionAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(100), default=lambda: datetime.now(timezone.utc).isoformat())
    details = db.Column(db.Text)  # JSON string

    def get_details(self):
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {"raw": self.details}

class ExtensionFeedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(100), default=lambda: datetime.now(timezone.utc).isoformat())
    details = db.Column(db.Text)  # JSON string

    def get_details(self):
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {"raw": self.details}
