"""
PhishShield AI — Scam Email Inference Script
=============================================
Loads email_model.pkl + vectorizer.pkl and predicts
whether a given email text is SPAM or HAM.

Usage:
    python predict_email.py                  # runs built-in demo emails
    python predict_email.py "your email text here"   # single prediction
"""

import sys
import os
import joblib

# ── Ensure imports from the same directory ──────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from train_email_model import clean_text  # reuse the exact same cleaner

# ─────────────────────────────────────────────
# LOAD ARTIFACTS
# ─────────────────────────────────────────────
MODEL_PATH      = os.path.join(BASE_DIR, "email_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")

print("Loading model and vectorizer …")
bundle     = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

model      = bundle["model"]
model_name = bundle["model_name"]
label_map  = bundle["label_map"]       # {0: "ham", 1: "spam"}
metrics    = bundle["metrics"]

print(f"  Model      : {model_name}")
print(f"  F1-Score   : {metrics['F1-Score']}")
print(f"  Accuracy   : {metrics['Accuracy']}")
print()


# ─────────────────────────────────────────────
# PREDICTION FUNCTION
# ─────────────────────────────────────────────
def predict(email_text: str) -> dict:
    """
    Predict spam / ham for a single email string.

    Returns a dict:
        label      → "spam" or "ham"
        confidence → probability of SPAM (0.0 – 1.0)
        verdict    → human-readable verdict string
        cleaned    → the cleaned token string fed to the model
    """
    cleaned  = clean_text(email_text)
    vec      = vectorizer.transform([cleaned])
    pred_int = model.predict(vec)[0]                  # 0 or 1
    prob     = model.predict_proba(vec)[0][1]         # P(spam)

    label   = label_map[pred_int]                     # "ham" or "spam"
    verdict = "SPAM ⚠" if pred_int == 1 else "Ham  ✓"

    # Confidence tier
    if prob >= 0.90:
        confidence_tier = "Very High"
    elif prob >= 0.70:
        confidence_tier = "High"
    elif prob >= 0.50:
        confidence_tier = "Moderate"
    else:
        confidence_tier = "Low"

    return {
        "label"           : label,
        "prediction_int"  : int(pred_int),
        "spam_probability": round(float(prob), 4),
        "ham_probability" : round(1 - float(prob), 4),
        "confidence_tier" : confidence_tier,
        "verdict"         : verdict,
        "cleaned_tokens"  : cleaned[:120] + ("…" if len(cleaned) > 120 else ""),
    }


def print_result(result: dict, email_text: str) -> None:
    """Pretty-print a single prediction result."""
    bar_len  = int(result["spam_probability"] * 30)
    spam_bar = "█" * bar_len + "░" * (30 - bar_len)

    print("┌" + "─" * 62 + "┐")
    print(f"│  Input  : {email_text[:55]:<55}│" if len(email_text) <= 55
          else f"│  Input  : {email_text[:52]+'...':<55}│")
    print(f"│  Verdict: {result['verdict']:<52}│")
    print(f"│  Spam P : [{spam_bar}] {result['spam_probability']:.0%}  ({result['confidence_tier']}){'':>3}│")
    print(f"│  Ham  P : {result['ham_probability']:.0%}{'':>51}│")
    print(f"│  Tokens : {result['cleaned_tokens']:<52}│")
    print("└" + "─" * 62 + "┘")
    print()


# ─────────────────────────────────────────────
# DEMO EMAILS
# ─────────────────────────────────────────────
DEMO_EMAILS = [
    # ── Spam examples ──────────────────────────────────────────────
    "Congratulations! You have WON a $1,000,000 lottery prize. "
    "Click here NOW to claim your reward before it expires!",

    "URGENT: Your bank account has been suspended. "
    "Verify your account immediately at this link to avoid permanent closure.",

    "Make money from home — earn $500 daily GUARANTEED! "
    "No experience needed. Limited spots available. Act now! Free sign-up.",

    "Dear Beneficiary, I am the attorney to a deceased client who left "
    "an unclaimed inheritance of $4.5 million. I need your help to transfer "
    "these funds. Full confidentiality assured. Reply for details.",

    "You have been selected for an exclusive investment opportunity. "
    "Double your money in 7 days with our guaranteed crypto trading signals!",

    # ── Ham examples ───────────────────────────────────────────────
    "Hi team, please find the Q4 financial report attached. "
    "Let's discuss in tomorrow's 10am standup.",

    "Reminder: your dentist appointment is scheduled for Friday at 2:30pm. "
    "Please call us if you need to reschedule.",

    "Hi John, just following up on the project proposal we discussed last week. "
    "Could you share the updated timeline by Thursday?",

    "Your Amazon order #112-3456789 has been shipped and is expected "
    "to arrive by March 7. Track your package here.",

    "Meeting notes from today's sprint review are now available in Confluence. "
    "Action items assigned — please review before end of day.",
]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main() -> None:

    # ── Command-line single prediction ──────────────
    if len(sys.argv) > 1:
        user_text = " ".join(sys.argv[1:])
        print("─" * 64)
        print("Single prediction:")
        print("─" * 64)
        result = predict(user_text)
        print_result(result, user_text)
        return

    # ── Demo batch ───────────────────────────────────
    print("═" * 64)
    print("  PhishShield AI — Scam Email Detector  (Demo Mode)")
    print("═" * 64)
    print()

    spam_count = 0
    for i, email_text in enumerate(DEMO_EMAILS, 1):
        print(f"  [{i:02d}/{len(DEMO_EMAILS)}]")
        result = predict(email_text)
        print_result(result, email_text)
        if result["prediction_int"] == 1:
            spam_count += 1

    # Summary
    print("─" * 64)
    print(f"  Checked : {len(DEMO_EMAILS)} emails")
    print(f"  Spam    : {spam_count}")
    print(f"  Ham     : {len(DEMO_EMAILS) - spam_count}")
    print("─" * 64)
    print()


if __name__ == "__main__":
    main()
