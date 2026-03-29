"""
PhishShield AI — Risk Score Inference Script
=============================================
Loads risk_model.pkl and predicts a 0–100 risk score
from the five signals produced by the upstream pipeline.

Usage:
    python predict_risk.py                          # built-in demo scenarios
    python predict_risk.py 0.85 0.72 4 30 1        # single prediction
        args: url_prob  email_prob  keywords  domain_age_days  has_attachment
"""

import sys
import os
import joblib
import pandas as pd

# ─────────────────────────────────────────────
# LOAD ARTIFACT
# ─────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "risk_model.pkl")

print("Loading risk model …")
bundle    = joblib.load(MODEL_PATH)
model     = bundle["model"]
feat_cols = bundle["feature_cols"]
weights   = bundle["weights"]
metrics   = bundle["metrics"]

print(f"  Model   : GradientBoostingRegressor")
print(f"  MAE     : {metrics['MAE']} pts   RMSE: {metrics['RMSE']} pts   R²: {metrics['R²']}")
print()


# ─────────────────────────────────────────────
# RISK LEVEL CLASSIFIER
# ─────────────────────────────────────────────
def risk_level(score: float) -> tuple[str, str]:
    """Return (level_label, icon) for a given 0-100 score."""
    if score >= 80:
        return "CRITICAL", "🔴"
    elif score >= 60:
        return "HIGH",     "🟠"
    elif score >= 40:
        return "MEDIUM",   "🟡"
    elif score >= 20:
        return "LOW",      "🟢"
    else:
        return "SAFE",     "✅"


# ─────────────────────────────────────────────
# PREDICTION FUNCTION
# ─────────────────────────────────────────────
def predict_risk(
    url_model_prob: float,
    email_model_prob: float,
    num_suspicious_keywords: int,
    domain_age_days: int,
    has_attachment: int,
) -> dict:
    """
    Predict the composite risk score for one case.

    Parameters
    ----------
    url_model_prob          : float  0.0–1.0  (output of url_model.pkl)
    email_model_prob        : float  0.0–1.0  (output of email_model.pkl)
    num_suspicious_keywords : int    count of scam keywords detected
    domain_age_days         : int    age of domain in days
    has_attachment          : int    1 = has attachment, 0 = none

    Returns
    -------
    dict with score, level, icon, and a per-feature contribution breakdown
    """
    # Validate inputs
    url_model_prob   = float(max(0.0, min(1.0, url_model_prob)))
    email_model_prob = float(max(0.0, min(1.0, email_model_prob)))
    num_suspicious_keywords = int(max(0, num_suspicious_keywords))
    domain_age_days  = int(max(1, domain_age_days))
    has_attachment   = int(bool(has_attachment))

    row = pd.DataFrame([[
        url_model_prob,
        email_model_prob,
        num_suspicious_keywords,
        domain_age_days,
        has_attachment,
    ]], columns=feat_cols)

    raw_score = float(model.predict(row)[0])
    score     = round(max(0.0, min(100.0, raw_score)), 1)
    level, icon = risk_level(score)

    # Approximate per-signal contribution (based on training weights)
    import math
    kw_norm  = min(num_suspicious_keywords / 10.0, 1.0)
    age_norm = math.exp(-domain_age_days / 365.0)
    contributions = {
        "url_model_prob"         : round(weights["url_model_prob"]          * url_model_prob,   1),
        "email_model_prob"       : round(weights["email_model_prob"]        * email_model_prob, 1),
        "num_suspicious_keywords": round(weights["num_suspicious_keywords"] * kw_norm,          1),
        "domain_age_days"        : round(weights["domain_age_days"]         * age_norm,         1),
        "has_attachment"         : round(weights["has_attachment"]          * has_attachment,    1),
    }

    return {
        "score"        : score,
        "level"        : level,
        "icon"         : icon,
        "contributions": contributions,
        "inputs": {
            "url_model_prob"         : url_model_prob,
            "email_model_prob"       : email_model_prob,
            "num_suspicious_keywords": num_suspicious_keywords,
            "domain_age_days"        : domain_age_days,
            "has_attachment"         : has_attachment,
        },
    }


# ─────────────────────────────────────────────
# PRETTY PRINTER
# ─────────────────────────────────────────────
def print_result(result: dict, label: str = "") -> None:
    score      = result["score"]
    level      = result["level"]
    icon       = result["icon"]
    inputs     = result["inputs"]
    contribs   = result["contributions"]

    filled = int(score / 100 * 30)
    bar    = "█" * filled + "░" * (30 - filled)

    if label:
        print(f"\n  {icon}  {label}")
    print(f"  ┌{'─'*58}┐")
    print(f"  │  Risk Score  [{bar}]  {score:>5.1f}/100          │")
    print(f"  │  Threat Level: {level:<10}                              │")
    print(f"  ├{'─'*58}┤")
    print(f"  │  Inputs & Contributions                               │")
    print(f"  │{'─'*58}│")

    rows = [
        ("url_model_prob",          f"{inputs['url_model_prob']:.2f}",   f"+{contribs['url_model_prob']:.1f} pts"),
        ("email_model_prob",        f"{inputs['email_model_prob']:.2f}", f"+{contribs['email_model_prob']:.1f} pts"),
        ("num_suspicious_keywords", str(inputs['num_suspicious_keywords']),f"+{contribs['num_suspicious_keywords']:.1f} pts"),
        ("domain_age_days",         f"{inputs['domain_age_days']}d",     f"+{contribs['domain_age_days']:.1f} pts"),
        ("has_attachment",          str(inputs['has_attachment']),        f"+{contribs['has_attachment']:.1f} pts"),
    ]
    for name, val, contrib in rows:
        print(f"  │    {name:<28} {val:>8}   {contrib:>10}   │")

    print(f"  └{'─'*58}┘")


# ─────────────────────────────────────────────
# DEMO SCENARIOS
# ─────────────────────────────────────────────
DEMO_SCENARIOS = [
    # label                         url_p  em_p  kw   age   att
    ("Obvious phishing attack",     0.97,  0.94,  9,   12,   1),
    ("Credential-harvesting page",  0.85,  0.72,  4,   30,   1),
    ("Suspicious unknown domain",   0.78,  0.55,  3,   45,   1),
    ("Borderline risky email",      0.55,  0.62,  2,  180,   0),
    ("Low-confidence anomaly",      0.40,  0.35,  1,  300,   0),
    ("Probably legitimate",         0.15,  0.10,  0, 1825,   0),
    ("Trusted corporate domain",    0.03,  0.02,  0, 4380,   0),
]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main() -> None:

    # ── Command-line single prediction ──────────────────────────────
    if len(sys.argv) == 6:
        try:
            url_p, em_p, kw, age, att = (
                float(sys.argv[1]), float(sys.argv[2]),
                int(sys.argv[3]),   int(sys.argv[4]),
                int(sys.argv[5]),
            )
        except ValueError:
            print("Usage: python predict_risk.py <url_prob> <email_prob> "
                  "<keywords> <domain_age_days> <has_attachment>")
            sys.exit(1)

        print("─" * 62)
        print("  Single Risk Prediction")
        print("─" * 62)
        result = predict_risk(url_p, em_p, kw, age, att)
        print_result(result)
        print()
        return

    # ── Demo batch ───────────────────────────────────────────────────
    print("═" * 62)
    print("  PhishShield AI — Risk Score Predictor  (Demo Mode)")
    print("═" * 62)

    for label, url_p, em_p, kw, age, att in DEMO_SCENARIOS:
        result = predict_risk(url_p, em_p, kw, age, att)
        print_result(result, label)

    # Summary table
    print(f"\n  {'─'*58}")
    print(f"  {'Scenario':<32} {'Score':>7}  {'Level'}")
    print(f"  {'─'*58}")
    for label, url_p, em_p, kw, age, att in DEMO_SCENARIOS:
        r = predict_risk(url_p, em_p, kw, age, att)
        print(f"  {r['icon']}  {label:<30} {r['score']:>5.1f}    {r['level']}")
    print(f"  {'─'*58}\n")


if __name__ == "__main__":
    main()
