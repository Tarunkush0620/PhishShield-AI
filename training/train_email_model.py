"""
PhishShield AI — Scam Email Detection Training Pipeline
========================================================
Dataset  : emails.csv  (file, message)  — Enron email corpus
Task     : Binary classification — spam/scam (1) vs. ham (0)
Label    : Derived via X-Folder path + weighted keyword scoring
Text     : RFC-2822 parsed subject + body
Models   : Naive Bayes | Logistic Regression | SVM (LinearSVC)
Output   : email_model.pkl  +  vectorizer.pkl
"""

import os
import re
import string
import email as email_lib
import warnings
import itertools
from email.header import decode_header

import numpy as np
import pandas as pd
import joblib

import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
)
from sklearn.pipeline import Pipeline

import matplotlib
matplotlib.use("Agg")          # non-interactive backend (no display needed)
import matplotlib.pyplot as plt

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT        = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATASET_PATH     = os.path.join(REPO_ROOT, "datasets", "emails.csv")
MODEL_DIR        = os.path.join(REPO_ROOT, "phishshield", "models")
MODEL_OUTPUT     = os.path.join(MODEL_DIR, "email_model.pkl")
VECTORIZER_OUT   = os.path.join(MODEL_DIR, "vectorizer.pkl")
CM_IMAGE_OUT     = os.path.join(SCRIPT_DIR, "confusion_matrices.png")

RANDOM_STATE     = 42
TEST_SIZE        = 0.20
SAMPLE_ROWS      = 200_000    # rows read from CSV  (full file = 517K; adjust as needed)
MAX_PER_CLASS    = 40_000     # balance cap per class after labelling


# ─────────────────────────────────────────────
# SPAM KEYWORD SCORING
# ─────────────────────────────────────────────
# Weights: 3 = very strong indicator, 2 = strong, 1 = moderate
SPAM_KEYWORDS: dict[str, int] = {
    # financial scams
    "lottery":         3, "winner":        3, "won":           3,
    "prize":           3, "reward":        3, "congratulation": 3,
    "inheritance":     3, "beneficiary":   3, "nigerian":       3,
    "unclaimed":       3, "million dollar": 3, "billion":       2,
    "wire transfer":   3, "western union":  3,

    # phishing / credential theft
    "verify your account": 3, "confirm your account": 3,
    "suspended":       3, "account alert":  3, "update your info": 3,
    "click here":      3, "click below":    3, "click now":      3,
    "limited time":    2, "act now":        3, "expires soon":   3,
    "urgent":          2, "immediately":    2,
    "password reset":  3, "login attempt":  3, "unusual activity": 3,

    # spam offers
    "free offer":      3, "free money":     3, "earn money":    3,
    "make money":      3, "work from home": 3, "extra income":  3,
    "cash advance":    3, "payday loan":    3, "debt relief":   2,
    "no obligation":   2, "risk free":      2, "money back":    2,
    "100% free":       3, "absolutely free": 3, "buy now":      2,
    "order now":       2, "special offer":   2, "discount":     1,
    "subscribe":       1, "unsubscribe":     2,

    # adult / pharma spam
    "viagra":          3, "cialis":         3, "enlargement":   3,
    "penis":           3, "sex":            1, "adult":         1,
    "pharmacy":        2, "medication":     1, "weight loss":   2,

    # investment fraud
    "investment opportunity": 3, "guaranteed profit": 3,
    "double your money": 3, "trading signal": 2, "crypto":      1,
    "bitcoin profit":  3, "forex":          2,
}

# Folders that are confirmed spam by folder name
SPAM_FOLDERS = {"junk", "junk_mail", "junk_e_mail", "spam", "bulk_mail"}

SPAM_SCORE_THRESHOLD = 4   # min score for keyword-based spam label


# ─────────────────────────────────────────────
# EMAIL PARSING
# ─────────────────────────────────────────────
def _decode_mime_words(s: str) -> str:
    """Decode RFC-2047 encoded header."""
    if not s:
        return ""
    parts = decode_header(s)
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded)


def parse_email(raw: str) -> tuple[str, str]:
    """Return (subject, body_text) from a raw RFC-2822 email string."""
    try:
        msg = email_lib.message_from_string(raw)
        subject = _decode_mime_words(msg.get("Subject", ""))

        body_parts = []
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    try:
                        body_parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))
                    except Exception:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_parts.append(payload.decode("utf-8", errors="replace"))
                else:
                    body_parts.append(str(msg.get_payload()))
            except Exception:
                body_parts.append(str(msg.get_payload()))

        body = " ".join(body_parts).strip()
        return subject, body
    except Exception:
        return "", str(raw)[:500]


# ─────────────────────────────────────────────
# LABEL DERIVATION
# ─────────────────────────────────────────────
def derive_label(file_path: str, subject: str, body: str) -> int:
    """
    Return 1 (spam) or 0 (ham).
    Priority:
      1. Explicit junk folder  → spam
      2. X-Folder header keyword → spam
      3. Weighted keyword score  → spam if score >= threshold
      4. Default                 → ham
    """
    # 1. Folder-path check
    parts = str(file_path).lower().replace("\\", "/").split("/")
    if len(parts) > 1 and parts[1] in SPAM_FOLDERS:
        return 1

    combined = (subject + " " + body[:3000]).lower()

    # 2. Keyword score
    score = 0
    for kw, weight in SPAM_KEYWORDS.items():
        if kw in combined:
            score += weight
            if score >= SPAM_SCORE_THRESHOLD:
                return 1      # short-circuit once we're sure

    return 0


# ─────────────────────────────────────────────
# TEXT CLEANING
# ─────────────────────────────────────────────
_stop_words = set(stopwords.words("english"))
_lemmatizer = WordNetLemmatizer()
_punct_re   = re.compile(r"[^\w\s]")
_numeric_re = re.compile(r"\b\d+\b")
_space_re   = re.compile(r"\s+")
_url_re     = re.compile(r"https?://\S+|www\.\S+")
_email_re   = re.compile(r"\S+@\S+")


def clean_text(text: str) -> str:
    """
    Pipeline:
      lowercase → strip URLs/emails → remove punctuation → remove isolated
      numbers → tokenize → remove stopwords → lemmatize → rejoin
    """
    text = text.lower()
    text = _url_re.sub(" ", text)
    text = _email_re.sub(" ", text)
    text = _punct_re.sub(" ", text)
    text = _numeric_re.sub(" ", text)
    text = _space_re.sub(" ", text).strip()
    tokens = text.split()
    tokens = [_lemmatizer.lemmatize(t) for t in tokens if t not in _stop_words and len(t) > 1]
    return " ".join(tokens)


# ─────────────────────────────────────────────
# MODEL DEFINITIONS
# ─────────────────────────────────────────────
MODELS = {
    "NaiveBayes": MultinomialNB(alpha=0.1),

    "LogisticRegression": LogisticRegression(
        C=5.0,
        solver="lbfgs",
        max_iter=1000,
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    ),

    # LinearSVC wrapped for probability estimates
    "SVM (LinearSVC)": CalibratedClassifierCV(
        LinearSVC(
            C=1.0,
            max_iter=2000,
            random_state=RANDOM_STATE,
            class_weight="balanced",
        )
    ),

    "XGBoost": XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.7,
        gamma=0.5,
        reg_alpha=0.1,
        reg_lambda=1.0,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    ),
}


# ─────────────────────────────────────────────
# EVALUATION HELPERS
# ─────────────────────────────────────────────
def evaluate(name: str, model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    return {
        "Model"    : name,
        "Accuracy" : round(accuracy_score(y_test, y_pred),                    4),
        "Precision": round(precision_score(y_test, y_pred, zero_division=0),  4),
        "Recall"   : round(recall_score(y_test, y_pred,    zero_division=0),  4),
        "F1-Score" : round(f1_score(y_test, y_pred,        zero_division=0),  4),
        "_y_pred"  : y_pred,
    }


def print_comparison_table(results: list[dict]) -> None:
    df = pd.DataFrame([{k: v for k, v in r.items() if not k.startswith("_")} for r in results])
    df = df.sort_values("F1-Score", ascending=False)
    print("\n" + "═" * 68)
    print(f"  {'Model':<22} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1-Score':>9}")
    print("─" * 68)
    for _, row in df.iterrows():
        marker = " ◀ best" if row.name == df.index[0] else ""
        print(
            f"  {row['Model']:<22} {row['Accuracy']:>9.4f}"
            f" {row['Precision']:>10.4f} {row['Recall']:>8.4f}"
            f" {row['F1-Score']:>9.4f}{marker}"
        )
    print("═" * 68)


def plot_confusion_matrices(results: list[dict], y_test, path: str) -> None:
    n = len(results)
    fig, axes = plt.subplots(1, n, figsize=(6 * n, 5))
    if n == 1:
        axes = [axes]
    for ax, res in zip(axes, results):
        cm   = confusion_matrix(y_test, res["_y_pred"])
        disp = ConfusionMatrixDisplay(cm, display_labels=["Ham (0)", "Spam (1)"])
        disp.plot(ax=ax, colorbar=False, cmap="Blues")
        ax.set_title(f"{res['Model']}\nF1={res['F1-Score']:.4f}", fontsize=11)
    plt.suptitle("Confusion Matrices — Scam Email Detector", fontsize=13, y=1.02)
    plt.tight_layout()
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"      Confusion matrix plot saved → {path}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main() -> None:
    os.makedirs(MODEL_DIR, exist_ok=True)


    # ── 1. Load ──────────────────────────────
    print(f"\n[1/7] Loading up to {SAMPLE_ROWS:,} rows from:\n      {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH, nrows=SAMPLE_ROWS)
    print(f"      Loaded  : {len(df):,} rows  |  Columns: {list(df.columns)}")

    # ── 2. Handle missing values ─────────────
    print("\n[2/7] Handling missing values …")
    before = len(df)
    df.dropna(subset=["message"], inplace=True)
    df["file"]    = df["file"].fillna("").astype(str)
    df["message"] = df["message"].astype(str)
    print(f"      Dropped {before - len(df):,} rows with null messages.")

    # ── 3. Parse emails → subject + body ─────
    print("\n[3/7] Parsing RFC-2822 email messages …")
    parsed = df["message"].apply(parse_email)
    df["subject"] = [p[0] for p in parsed]
    df["body"]    = [p[1] for p in parsed]
    df["raw_text"] = df["subject"] + " " + df["body"]
    print(f"      Parsed {len(df):,} emails.")

    # ── 4. Derive labels ─────────────────────
    print("\n[4/7] Deriving labels (folder path + keyword scoring) …")
    df["label"] = df.apply(
        lambda r: derive_label(r["file"], r["subject"], r["body"]), axis=1
    )
    spam_count = df["label"].sum()
    ham_count  = (df["label"] == 0).sum()
    print(f"      Raw  →  Spam: {spam_count:,}  |  Ham: {ham_count:,}")

    # Balance classes
    df_spam = df[df["label"] == 1].sample(min(spam_count, MAX_PER_CLASS), random_state=RANDOM_STATE)
    df_ham  = df[df["label"] == 0].sample(min(ham_count,  MAX_PER_CLASS), random_state=RANDOM_STATE)
    df_bal  = pd.concat([df_spam, df_ham]).sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    print(f"      Balanced →  Spam: {(df_bal['label']==1).sum():,}  |  Ham: {(df_bal['label']==0).sum():,}")

    # ── 5. Text cleaning ─────────────────────
    print("\n[5/7] Cleaning text (lowercase → URLs/emails stripped →")
    print("      punctuation removed → stopwords → lemmatization) …")
    df_bal["clean_text"] = df_bal["raw_text"].apply(clean_text)

    # Sanity-check empty texts
    empty = (df_bal["clean_text"].str.strip() == "").sum()
    print(f"      Empty texts after cleaning: {empty:,}  (will be kept as blank tokens)")

    # ── 5b. Train / test split ────────────────
    X_raw   = df_bal["clean_text"].values
    y       = df_bal["label"].values

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n      Train: {len(X_train_raw):,}  |  Test: {len(X_test_raw):,}")

    # ── 5c. TF-IDF Vectorization ──────────────
    print("\n      Fitting TF-IDF vectorizer (max_features=50,000, 1-3 grams) …")
    vectorizer = TfidfVectorizer(
        max_features=50_000,
        ngram_range=(1, 3),
        sublinear_tf=True,
        min_df=2,
        max_df=0.95,
        analyzer="word",
    )
    X_train = vectorizer.fit_transform(X_train_raw)
    X_test  = vectorizer.transform(X_test_raw)
    print(f"      Vocabulary size : {len(vectorizer.vocabulary_):,}")
    print(f"      Train matrix    : {X_train.shape}")
    print(f"      Test  matrix    : {X_test.shape}")

    # ── 6. Train & evaluate all models ───────
    print("\n[6/7] Training and evaluating models …\n")
    results         = []
    trained_models  = {}

    for name, model in MODELS.items():
        print(f"  ▶ {name}")
        print(f"    Training … ", end="", flush=True)
        model.fit(X_train, y_train)
        print("done")

        res = evaluate(name, model, X_test, y_test)
        results.append(res)
        trained_models[name] = model

        y_pred = res["_y_pred"]
        print(f"    Accuracy={res['Accuracy']:.4f}  Precision={res['Precision']:.4f}"
              f"  Recall={res['Recall']:.4f}  F1={res['F1-Score']:.4f}")

        # Full classification report
        report = classification_report(
            y_test, y_pred,
            target_names=["Ham (0)", "Spam (1)"],
            zero_division=0
        )
        print("    " + "─" * 52)
        for line in report.splitlines():
            print(f"    {line}")
        print()

    # Comparison table
    print("[─] Model Comparison Table")
    print_comparison_table(results)

    # Confusion matrix plot
    plot_confusion_matrices(results, y_test, CM_IMAGE_OUT)

    # ── 7. Save best model ─────────────────
    best_result = max(results, key=lambda r: r["F1-Score"])
    best_name   = best_result["Model"]
    best_model  = trained_models[best_name]
    best_metrics = {k: v for k, v in best_result.items() if not k.startswith("_")}

    print(f"\n[7/7] Best model  → {best_name}  (F1={best_result['F1-Score']:.4f})")

    # Save vectorizer
    joblib.dump(vectorizer, VECTORIZER_OUT)
    sz_v = os.path.getsize(VECTORIZER_OUT) / 1024
    print(f"      Vectorizer saved → {VECTORIZER_OUT}  ({sz_v:.1f} KB)")

    # Save model
    joblib.dump(
        {
            "model"      : best_model,
            "model_name" : best_name,
            "metrics"    : best_metrics,
            "label_map"  : {0: "ham", 1: "spam"},
        },
        MODEL_OUTPUT,
    )
    sz_m = os.path.getsize(MODEL_OUTPUT) / 1024
    print(f"      Model saved      → {MODEL_OUTPUT}  ({sz_m:.1f} KB)")

    print("\n✓ Training complete.\n")

    # ── Quick inference demo ──────────────────
    demo_emails = [
        "Congratulations! You have won a lottery prize of $1,000,000. Click here to claim your reward now.",
        "Hi team, please find attached the Q4 financial report for your review. Meeting at 3pm.",
        "URGENT: Your account has been suspended. Verify your account immediately to avoid losing access.",
        "Reminder: Project standup tomorrow at 10am. Don't forget to update Jira tickets.",
        "Make money from home! Earn $500 daily guaranteed. No experience needed. Act now! Limited offer.",
    ]
    print("─" * 60)
    print("Demo predictions (best model):")
    print("─" * 60)
    for em in demo_emails:
        cleaned = clean_text(em)
        vec     = vectorizer.transform([cleaned])
        pred    = best_model.predict(vec)[0]
        prob    = best_model.predict_proba(vec)[0][1]
        label   = "SPAM ⚠" if pred == 1 else "Ham  ✓"
        print(f"  [{label}]  (conf={prob:.2f})  {em[:70]}…" if len(em) > 70 else f"  [{label}]  (conf={prob:.2f})  {em}")
    print()


if __name__ == "__main__":
    main()
