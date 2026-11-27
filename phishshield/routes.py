from flask import Blueprint, request, jsonify, render_template
import json
import math
import pandas as pd
from datetime import datetime, timezone
from .models import db, GlobalStat, Scan, ExtensionAlert, ExtensionFeedback
from . import limiter
from .ml_services import (
    URL_MODEL, EMAIL_MODEL, VECTORIZER, RISK_MODEL, RISK_FEATURES, RISK_WEIGHTS,
    extract_url_features, clean_text, count_keywords, _rule_boost_url,
    risk_level, _confidence_tier, _generate_ai_explanation, _get_chat_response
)

api_bp = Blueprint('api', __name__)

def _parse_json_object():
    """
    Safely extract JSON body, ensuring the root payload is a dictionary.
    Returns (data_dict, error_response_tuple).
    """
    try:
        data = request.get_json(force=True, silent=True)
    except Exception:
        return None, (jsonify({"error": "Invalid JSON format"}), 400)

    if data is None:
        return None, (jsonify({"error": "No JSON payload provided"}), 400)

    if not isinstance(data, dict):
        return None, (jsonify({"error": "Payload must be a JSON object"}), 400)

    return data, None

def get_global_stat():
    stat = GlobalStat.query.first()
    if not stat:
        stat = GlobalStat()
        db.session.add(stat)
        db.session.commit()
    return stat

def _record_scan(payload: dict, limit: int = 30) -> dict:
    scan = Scan(
        kind=payload.get("kind"),
        label=payload.get("label"),
        score=payload.get("score"),
        probability=payload.get("probability"),
        confidence=payload.get("confidence"),
        subject=payload.get("subject"),
        keyword_count=payload.get("keyword_count")
    )
    if "signals" in payload:
        scan.set_signals(payload["signals"])
    db.session.add(scan)
    db.session.commit()
    return payload

@api_bp.route("/")
def index():
    return render_template("index.html")

# ─────────────────────────────────────────────────────────────────────────────
# 1. URL CHECK
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/check-url", methods=["POST"])
@limiter.limit("30 per minute")
def check_url():
    data, err = _parse_json_object()
    if err:
        return err

    raw_url = data.get("url")
    if raw_url is None or not isinstance(raw_url, str):
        return jsonify({"error": "No URL provided"}), 400

    url = raw_url.strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    url_lower = url.lower()
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        url = "http://" + url

    try:
        feats = extract_url_features(url)

        if URL_MODEL is not None:
            raw_prob = float(URL_MODEL.predict_proba(feats)[0][1])
        else:
            raw_prob = 0.5

        prob, threat_signals = _rule_boost_url(url, feats, raw_prob)
        pred = int(prob >= 0.45)
        decisive     = prob if pred == 1 else (1 - prob)
        confidence   = _confidence_tier(decisive)
        threat_pct   = round(prob * 100, 1)

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

        stat = get_global_stat()
        stat.urls_scanned += 1
        if pred == 1:
            stat.threats_detected += 1
        db.session.commit()

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
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Failed to analyze URL"}), 500

# ─────────────────────────────────────────────────────────────────────────────
# 2. EMAIL CHECK
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/check-email", methods=["POST"])
@limiter.limit("30 per minute")
def check_email():
    data, err = _parse_json_object()
    if err:
        return err

    raw_text = data.get("text")
    if raw_text is None or not isinstance(raw_text, str):
        return jsonify({"error": "No email text provided"}), 400

    email_text = raw_text.strip()
    if not email_text:
        return jsonify({"error": "No email text provided"}), 400

    try:
        cleaned  = clean_text(email_text)
        vec      = VECTORIZER.transform([cleaned])
        raw_prob = float(EMAIL_MODEL.predict_proba(vec)[0][1])

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

        from .ml_services import SCAM_KEYWORDS
        tokens = cleaned.split()
        scam_tokens_found = [
            t for t in tokens
            if any(kw in t or t in kw for kw in SCAM_KEYWORDS[:20])
        ][:8]

        stat = get_global_stat()
        stat.emails_analyzed += 1
        if pred == 1:
            stat.threats_detected += 1
        db.session.commit()

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
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Failed to analyze email text"}), 500

# ─────────────────────────────────────────────────────────────────────────────
# 3. RISK SCORE
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/risk-score", methods=["POST"])
@limiter.limit("30 per minute")
def risk_score():
    data, err = _parse_json_object()
    if err:
        return err

    def _clean_prob(val, default=0.0):
        try:
            f = float(val)
            if math.isnan(f) or math.isinf(f):
                return default
            return max(0.0, min(1.0, f))
        except (TypeError, ValueError, OverflowError):
            return default

    def _clean_int(val, min_val=0, max_val=100000, default=0):
        try:
            f = float(val)
            if math.isnan(f) or math.isinf(f):
                return default
            i = int(f)
            return max(min_val, min(max_val, i))
        except (TypeError, ValueError, OverflowError):
            return default

    try:
        manual_keys = ("url_model_prob", "email_model_prob", "num_suspicious_keywords", "domain_age_days", "has_attachment")
        if any(key in data for key in manual_keys):
            url_prob   = _clean_prob(data.get("url_model_prob", 0.0))
            email_prob = _clean_prob(data.get("email_model_prob", 0.0))
            keywords   = _clean_int(data.get("num_suspicious_keywords", 0), min_val=0)
            domain_age = _clean_int(data.get("domain_age_days", 365), min_val=1, default=365)
            attachment = int(bool(data.get("has_attachment", False)))
            mode = "manual"
            sources = {}
        else:
            latest_url = Scan.query.filter_by(kind='url').order_by(Scan.id.desc()).first()
            latest_email = Scan.query.filter_by(kind='email').order_by(Scan.id.desc()).first()
            latest_full = Scan.query.filter_by(kind='full').order_by(Scan.id.desc()).first()

            if not latest_url and not latest_email and not latest_full:
                return jsonify({"error": "No scan history available. Run a URL or email scan first to generate an automatic risk score."}), 400

            url_prob = 0.0
            email_prob = 0.0
            keywords = 0

            # Prioritize dedicated URL scan, or fall back to full scan's recorded url_prob
            if latest_url and latest_url.probability is not None:
                url_prob = latest_url.probability
            elif latest_full:
                sigs = latest_full.get_raw_signals()
                if "url_prob" in sigs:
                    url_prob = sigs["url_prob"]

            # Prioritize dedicated Email scan, or fall back to full scan's email_prob & keyword_count
            if latest_email and latest_email.probability is not None:
                email_prob = latest_email.probability
                keywords = latest_email.keyword_count or 0
            elif latest_full:
                sigs = latest_full.get_raw_signals()
                if "email_prob" in sigs:
                    email_prob = sigs["email_prob"]
                if latest_full.keyword_count is not None:
                    keywords = latest_full.keyword_count

            domain_age = 365
            if (latest_url and latest_url.label in {"Phishing", "Critical", "High"}) or \
               (latest_full and latest_full.label in {"Critical", "High"}):
                domain_age = 14

            attachment = 0
            if (latest_email and (keywords >= 3 or latest_email.label in {"Spam/Scam", "Phishing"})) or \
               (latest_full and keywords >= 3):
                attachment = 1

            url_prob   = _clean_prob(url_prob)
            email_prob = _clean_prob(email_prob)
            keywords   = _clean_int(keywords, min_val=0)
            domain_age = _clean_int(domain_age, min_val=0, default=365)
            mode = "auto"
            sources = {}

        row   = pd.DataFrame([[url_prob, email_prob, keywords, domain_age, attachment]],
                             columns=RISK_FEATURES)
        raw_pred = RISK_MODEL.predict(row)[0]
        score = float(max(0.0, min(100.0, raw_pred)))
        level, color = risk_level(score)

        _record_scan({
            "kind": "risk",
            "label": level,
            "score": round(score, 1),
            "confidence": level,
            "subject": "Composite risk score",
            "signals": [name for name, value in (("url", url_prob), ("email", email_prob), ("keywords", keywords)) if value],
        })

        recommendations = []
        if score >= 80:
            recommendations = ["Isolate the user or host from the network immediately.", "Force password reset and revoke active sessions.", "Review mail logs, browser history, and recent downloads."]
        elif score >= 60:
            recommendations = ["Increase monitoring on the sender domain and related infrastructure.", "Verify the message through a separate trusted channel."]
        else:
            recommendations = ["Continue standard monitoring and user awareness controls.", "Re-scan any new URLs or emails before interacting."]

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
            "mode"         : mode,
            "sources"      : sources,
            "inputs"       : {
                "url_model_prob": round(url_prob, 2),
                "email_model_prob": round(email_prob, 2),
                "num_suspicious_keywords": keywords,
                "domain_age_days": domain_age,
                "has_attachment": bool(attachment),
            },
            "recommendations": recommendations,
        })
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Failed to compute risk score"}), 500

# ─────────────────────────────────────────────────────────────────────────────
# 4. FULL ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/full-analysis", methods=["POST"])
@limiter.limit("20 per minute")
def full_analysis():
    data, err = _parse_json_object()
    if err:
        return err

    url_text   = str(data.get("url", "") or "").strip()
    email_text = str(data.get("email", "") or "").strip()
    if not url_text and not email_text:
        return jsonify({"error": "At least one of 'url' or 'email' must be provided"}), 400

    try:
        val = data.get("domain_age_days")
        if val is None or val == "":
            domain_age = 365
        else:
            raw_age = float(val)
            if math.isnan(raw_age) or math.isinf(raw_age):
                domain_age = 365
            else:
                domain_age = max(0, min(100000, int(raw_age)))
    except (ValueError, TypeError, OverflowError):
        domain_age = 365
    attachment = int(bool(data.get("has_attachment", False)))

    result = {
        "url_analysis"  : None,
        "email_analysis": None,
        "risk"          : None,
    }

    url_prob   = 0.0
    email_prob = 0.0
    keywords   = 0

    if url_text:
        url_lower = url_text.lower()
        if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
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

    try:
        row   = pd.DataFrame(
            [[url_prob, email_prob, keywords, domain_age, attachment]],
            columns=RISK_FEATURES
        )
        score = float(max(0.0, min(100.0, RISK_MODEL.predict(row)[0])))
        level, color = risk_level(score)
        full_signals = [name for name, value in (("url", url_prob), ("email", email_prob), ("keywords", keywords)) if value]
        _record_scan({
            "kind": "full",
            "label": level,
            "score": round(score, 1),
            "probability": round(score / 100.0, 4),
            "confidence": level,
            "subject": "Combined URL + email analysis",
            "keyword_count": keywords,
            "signals": {
                "threat_signals": full_signals,
                "url_prob": round(url_prob, 4),
                "email_prob": round(email_prob, 4)
            },
        })

        stat = get_global_stat()
        if url_text:
            stat.urls_scanned += 1
        if email_text:
            stat.emails_analyzed += 1
        if (result["url_analysis"] and result["url_analysis"].get("prediction") == 1) or \
           (result["email_analysis"] and result["email_analysis"].get("prediction") == 1) or \
           (score >= 60.0):
            stat.threats_detected += 1
        db.session.commit()

        result["risk"] = {
            "score": round(score, 1),
            "level": level,
            "color": color,
        }
        result["inputs"] = {
            "domain_age_days": domain_age,
            "has_attachment": bool(attachment),
        }
    except Exception as e:
        result["risk"] = {"error": str(e)}

    return jsonify(result)

# ─────────────────────────────────────────────────────────────────────────────
# 5. BULK URL SCAN
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/bulk-scan", methods=["POST"])
@limiter.limit("20 per minute")
def bulk_scan():
    data, err = _parse_json_object()
    if err:
        return err

    urls = data.get("urls")
    if not isinstance(urls, list):
        return jsonify({"error": "urls must be a list"}), 400

    if not urls:
        return jsonify({"error": "No valid URLs provided"}), 400

    # Cap to max 50 URLs while preserving exact 1:1 input ordering
    batch = urls[:50]
    results = []
    scanned_count = 0
    threat_count = 0

    for raw_item in batch:
        if raw_item is None or not isinstance(raw_item, str) or not raw_item.strip():
            results.append({
                "url": str(raw_item) if raw_item is not None else "",
                "label": "Error",
                "confidence": "0%",
                "confidence_score": 0.0,
                "threat_signals": [],
                "error": "Empty or invalid URL"
            })
            continue

        raw_url = raw_item.strip()
        url_lower = raw_url.lower()
        url = raw_url if (url_lower.startswith("http://") or url_lower.startswith("https://")) else "http://" + raw_url
        try:
            feats = extract_url_features(url)
            raw_prob = float(URL_MODEL.predict_proba(feats)[0][1]) if URL_MODEL is not None else 0.5
            prob, threat_signals = _rule_boost_url(url, feats, raw_prob)
            pred = int(prob >= 0.45)
            decisive = prob if pred == 1 else (1 - prob)
            label = "Phishing" if pred == 1 else "Legitimate"

            scanned_count += 1
            if pred == 1:
                threat_count += 1

            results.append({
                "url": raw_item,
                "label": label,
                "confidence": _confidence_tier(decisive),
                "confidence_score": round(decisive, 4),
                "threat_signals": threat_signals[:3]
            })
        except Exception:
            results.append({
                "url": raw_item,
                "label": "Error",
                "confidence": "0%",
                "confidence_score": 0.0,
                "threat_signals": [],
                "error": "Scan processing failed"
            })

    if scanned_count > 0:
        stat = get_global_stat()
        stat.urls_scanned += scanned_count
        stat.threats_detected += threat_count
        db.session.commit()

    _record_scan({
        "kind": "bulk",
        "label": "Phishing" if threat_count else "Legitimate",
        "score": round((threat_count / max(len(results), 1)) * 100.0, 1),
        "confidence": f"{threat_count}/{len(results)} threats",
        "subject": f"Bulk scan of {len(results)} URLs",
        "signals": [r["url"] for r in results[:3] if r.get("url")]
    })

    return jsonify({"results": results, "total": len(results), "threats": threat_count})

# ─────────────────────────────────────────────────────────────────────────────
# 6. EXTENSION ALERTS & FEEDBACK
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/extension-alert", methods=["POST"])
@limiter.limit("60 per minute")
def extension_alert():
    data, err = _parse_json_object()
    if err:
        return err

    alert = ExtensionAlert(details=json.dumps(data))
    db.session.add(alert)
    db.session.commit()
    return jsonify({"ok": True, "id": alert.id, "total": ExtensionAlert.query.count()})

@api_bp.route("/api/extension-feedback", methods=["POST"])
@limiter.limit("60 per minute")
def extension_feedback():
    data, err = _parse_json_object()
    if err:
        return err

    feedback = ExtensionFeedback(details=json.dumps(data))
    db.session.add(feedback)
    db.session.commit()
    return jsonify({"ok": True, "id": feedback.id, "total": ExtensionFeedback.query.count()})

# ─────────────────────────────────────────────────────────────────────────────
# 7. DASHBOARD & STATS
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/dashboard")
@limiter.limit("120 per minute")
def dashboard():
    stat = get_global_stat()
    recent_scans = Scan.query.order_by(Scan.id.desc()).limit(10).all()
    recent_alerts = ExtensionAlert.query.order_by(ExtensionAlert.id.desc()).limit(5).all()
    recent_feedback = ExtensionFeedback.query.order_by(ExtensionFeedback.id.desc()).limit(5).all()
    phishing_events = Scan.query.filter(Scan.label.in_(['Phishing', 'Spam/Scam'])).count()

    # Aggregate top signals and risk distribution from recent scans
    signal_counts = {}
    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for s in recent_scans:
        for sig in s.get_signals():
            sig_name = str(sig).strip()
            if sig_name:
                signal_counts[sig_name] = signal_counts.get(sig_name, 0) + 1
        lbl = s.label or s.confidence
        if lbl in risk_counts:
            risk_counts[lbl] += 1

    top_signals = [{"signal": k, "count": v} for k, v in sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)[:5]]
    risk_distribution = [{"level": k, "count": v} for k, v in risk_counts.items() if v > 0]

    return jsonify({
        "stats": {
            "urls_scanned": stat.urls_scanned,
            "emails_analyzed": stat.emails_analyzed,
            "threats_detected": stat.threats_detected,
            "extension_alerts": ExtensionAlert.query.count(),
            "extension_feedback": ExtensionFeedback.query.count(),
            "recent_scans": Scan.query.count(),
            "phishing_events": phishing_events,
        },
        "recent_scans": [{
            "id": s.id, "kind": s.kind, "label": s.label, "score": s.score, 
            "confidence": s.confidence, "subject": s.subject, "signals": s.get_signals(), "timestamp": s.timestamp
        } for s in recent_scans],
        "recent_alerts": [{"id": a.id, "details": a.get_details(), "timestamp": a.timestamp} for a in recent_alerts],
        "recent_feedback": [{"id": f.id, "details": f.get_details(), "timestamp": f.timestamp} for f in recent_feedback],
        "top_signals": top_signals,
        "risk_distribution": risk_distribution
    })

@api_bp.route("/api/stats")
@limiter.limit("300 per minute")
def get_stats():
    stat = get_global_stat()
    return jsonify({
        "urls_scanned"    : stat.urls_scanned,
        "emails_analyzed" : stat.emails_analyzed,
        "threats_detected": stat.threats_detected,
        "extension_alerts": ExtensionAlert.query.count(),
        "extension_feedback": ExtensionFeedback.query.count(),
    })

# ─────────────────────────────────────────────────────────────────────────────
# 8. AI EXPLANATION & CHAT ASSISTANT
# ─────────────────────────────────────────────────────────────────────────────
@api_bp.route("/api/ai-explain", methods=["POST"])
@limiter.limit("20 per minute")
def ai_explain():
    data, err = _parse_json_object()
    if err:
        return err

    explanation = _generate_ai_explanation(
        label         = data.get("label", "Unknown"),
        confidence    = data.get("confidence", "50%"),
        signals       = data.get("threat_signals", []) or [],
        feature_flags = data.get("feature_flags", {}) or {},
        url           = data.get("url", ""),
        email_text    = data.get("email_text", ""),
        keyword_count = data.get("keyword_count", 0) or 0,
        flagged_tokens= data.get("flagged_tokens", []) or [],
    )
    return jsonify({"explanation": explanation})

@api_bp.route("/api/chat", methods=["POST"])
@limiter.limit("30 per minute")
def ai_chat():
    data, err = _parse_json_object()
    if err:
        return err

    # Harmonize both 'message' (Web UI) and 'question' (Chrome Extension popup)
    msg = data.get("message")
    q = data.get("question")
    raw_query = ""
    if isinstance(msg, str) and msg.strip():
        raw_query = msg.strip()
    elif isinstance(q, str) and q.strip():
        raw_query = q.strip()

    if not raw_query:
        return jsonify({"error": "No question or message provided"}), 400

    question = raw_query[:500]
    return jsonify({"response": _get_chat_response(question)})
