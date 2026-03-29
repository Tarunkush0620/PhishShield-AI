"""
PhishShield AI — URL Phishing Detection Model Training Script
=============================================================
Dataset  : malicious_phish.csv  (url, type)
Task     : Binary classification — phishing (1) vs. legitimate (0)
Models   : RandomForest | LogisticRegression | GradientBoosting
Output   : url_model.pkl  (best model saved via joblib)
"""

import re
import os
import warnings
import ipaddress
from urllib.parse import urlparse

import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT     = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATASET_PATH  = os.path.join(REPO_ROOT, "datasets", "malicious_phish.csv")
MODEL_OUTPUT  = os.path.join(REPO_ROOT, "phishshield", "models", "url_model.pkl")
RANDOM_STATE  = 42
TEST_SIZE     = 0.20


# ─────────────────────────────────────────────
# FEATURE ENGINEERING
# ─────────────────────────────────────────────
def has_ip_address(url: str) -> int:
    """Return 1 if the hostname is a raw IPv4/IPv6 address."""
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return 1
    except (ValueError, Exception):
        return 0


def count_subdomains(url: str) -> int:
    """Number of meaningful subdomains (dots in host minus 1, ignoring www)."""
    try:
        host = urlparse(url).hostname or ""
        parts = [p for p in host.split(".") if p != "www"]
        return max(len(parts) - 2, 0)
    except Exception:
        return 0


def domain_length(url: str) -> int:
    try:
        host = urlparse(url).hostname or ""
        return len(host)
    except Exception:
        return 0


# Known phishing-heavy TLDs
_SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".cf", ".ga", ".gq", ".pw",
                    ".top", ".club", ".work", ".click", ".link", ".win",
                    ".bid", ".party", ".loan", ".review", ".trade"}

# Brand keywords often impersonated in URL paths
_BRAND_KEYWORDS = {
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "bankofamerica", "wellsfargo", "chase", "ebay",
    "instagram", "twitter", "linkedin", "dropbox", "outlook",
    "office365", "icloud", "whatsapp", "telegram",
}


def _has_suspicious_tld(url: str) -> int:
    try:
        host = urlparse(url).hostname or ""
        for tld in _SUSPICIOUS_TLDS:
            if host.endswith(tld):
                return 1
    except Exception:
        pass
    return 0


def _path_length(url: str) -> int:
    try:
        return len(urlparse(url).path)
    except Exception:
        return 0


def _has_brand_keyword(url: str) -> int:
    """Brand name appears in URL path/query but NOT in the registered domain."""
    try:
        parsed = urlparse(url)
        host   = (parsed.hostname or "").lower()
        path   = (parsed.path + "?" + parsed.query).lower()
        # registered domain = last two parts of host
        parts  = host.split(".")
        reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
        for brand in _BRAND_KEYWORDS:
            if brand in path and brand not in reg_domain:
                return 1
    except Exception:
        pass
    return 0


def _num_special_chars(url: str) -> int:
    """Count of special chars often used in obfuscation."""
    return sum(url.count(c) for c in "!$'\"(){}[]|^`")


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Derive numeric features from raw URL strings."""
    urls = df["url"].astype(str)

    features = pd.DataFrame()
    features["URLLength"]        = urls.str.len()
    features["DomainLength"]     = urls.apply(domain_length)
    features["IsHTTPS"]          = urls.str.startswith("https").astype(int)
    features["NumDots"]          = urls.str.count(r"\.")
    features["NumHyphens"]       = urls.str.count(r"-")
    features["NumSubdomains"]    = urls.apply(count_subdomains)
    features["HasIPAddress"]     = urls.apply(has_ip_address)

    # Extra discriminative features
    features["NumSlashes"]       = urls.str.count(r"/")
    features["NumAtSymbol"]      = urls.str.count(r"@")
    features["NumQueryParams"]   = urls.str.count(r"\?")
    features["NumAmpersand"]     = urls.str.count(r"&")
    features["NumEquals"]        = urls.str.count(r"=")
    features["NumPercent"]       = urls.str.count(r"%")
    features["NumDigits"]        = urls.apply(lambda u: sum(c.isdigit() for c in u))
    def _safe_path_doubleslash(u: str) -> int:
        try:
            return int("//" in (urlparse(u).path or ""))
        except Exception:
            return 0

    features["HasDoubleSlash"]   = urls.apply(_safe_path_doubleslash)
    features["HasTildeSign"]     = urls.str.contains("~", regex=False).astype(int)
    features["URLEntropy"]       = urls.apply(_url_entropy)

    # ── New high-signal features ───────────────
    features["HasSuspiciousTLD"] = urls.apply(_has_suspicious_tld)
    features["PathLength"]       = urls.apply(_path_length)
    features["HasBrandKeyword"]  = urls.apply(_has_brand_keyword)
    features["NumSpecialChars"]  = urls.apply(_num_special_chars)

    return features


def _url_entropy(url: str) -> float:
    """Shannon entropy of the URL string (proxy for obfuscation)."""
    if not url:
        return 0.0
    freq = pd.Series(list(url)).value_counts(normalize=True)
    return float((-freq * np.log2(freq)).sum())


# ─────────────────────────────────────────────
# LABEL ENCODING
# ─────────────────────────────────────────────
def encode_labels(series: pd.Series) -> pd.Series:
    """Binary: phishing → 1, benign → 0.  Defacement/malware excluded at load."""
    return (series.str.strip().str.lower() == "phishing").astype(int)


# ─────────────────────────────────────────────
# MODEL DEFINITIONS
# ─────────────────────────────────────────────
MODELS = {
    "RandomForest": RandomForestClassifier(
        n_estimators=300,
        max_depth=25,
        min_samples_split=4,
        n_jobs=-1,
        random_state=RANDOM_STATE,
        class_weight="balanced",
    ),
    "LogisticRegression": LogisticRegression(
        max_iter=1000,
        solver="lbfgs",
        random_state=RANDOM_STATE,
        class_weight="balanced",
        n_jobs=-1,
    ),
    "GradientBoosting": GradientBoostingClassifier(
        n_estimators=300,
        learning_rate=0.08,
        max_depth=7,
        subsample=0.8,
        random_state=RANDOM_STATE,
    ),
    "XGBoost": XGBClassifier(
        n_estimators=400,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=1,
        reg_alpha=0.1,
        reg_lambda=1.5,
        scale_pos_weight=1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    ),
}


# ─────────────────────────────────────────────
# EVALUATION
# ─────────────────────────────────────────────
def evaluate_model(name: str, model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    return {
        "Model"    : name,
        "Accuracy" : round(accuracy_score(y_test, y_pred),  4),
        "Precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "Recall"   : round(recall_score(y_test, y_pred,    zero_division=0), 4),
        "F1-Score" : round(f1_score(y_test, y_pred,        zero_division=0), 4),
    }


def print_comparison_table(results: list[dict]) -> None:
    df = pd.DataFrame(results).sort_values("F1-Score", ascending=False)
    print("\n" + "═" * 66)
    print(f"  {'Model':<22} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1-Score':>9}")
    print("─" * 66)
    for _, row in df.iterrows():
        print(
            f"  {row['Model']:<22} {row['Accuracy']:>9.4f}"
            f" {row['Precision']:>10.4f} {row['Recall']:>8.4f}"
            f" {row['F1-Score']:>9.4f}"
        )
    print("═" * 66)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main() -> None:
    os.makedirs(os.path.dirname(MODEL_OUTPUT), exist_ok=True)

    # ── 1. Load dataset ──────────────────────
    print(f"\n[1/6] Loading dataset from:\n      {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"      Rows: {len(df):,}  |  Columns: {list(df.columns)}")
    print(f"      Label distribution:\n{df['type'].value_counts().to_string()}\n")

    # ── 2. Handle missing values & filter to benign vs phishing ─────────
    print("[2/6] Preprocessing …")
    initial_len = len(df)
    df.dropna(subset=["url", "type"], inplace=True)
    df["url"]  = df["url"].astype(str).str.strip()
    df["type"] = df["type"].str.strip().str.lower()

    # Keep only benign (legitimate) and phishing rows for clean binary task
    df = df[df["type"].isin(["benign", "phishing"])].copy()
    print(f"      Kept benign + phishing only: {len(df):,} rows  (dropped {initial_len - len(df):,})")

    # ── Normalize URLs: add http:// to any URL missing a scheme ──────────
    # The dataset has benign URLs without scheme (e.g. "google.com/path")
    # and phishing URLs with scheme (e.g. "http://evil.com/...").
    # Without normalisation, features like NumSlashes are heavily biased.
    def add_scheme(u):
        if u.startswith("http://") or u.startswith("https://"):
            return u
        return "http://" + u
    df["url"] = df["url"].apply(add_scheme)
    print(f"      URLs normalised (scheme added where missing).")

    # Balance: cap benign at 4× phishing count so model isn't overwhelmed
    phish_rows = df[df["type"] == "phishing"]
    benign_rows = df[df["type"] == "benign"].sample(
        min(len(phish_rows) * 4, len(df[df["type"] == "benign"])),
        random_state=RANDOM_STATE
    )
    df = pd.concat([phish_rows, benign_rows]).sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
    print(f"      After balancing — Phishing: {(df['type']=='phishing').sum():,}  |  Benign: {(df['type']=='benign').sum():,}")

    # ── 3. Feature engineering ───────────────
    print("[3/6] Engineering features …")
    X = extract_features(df)
    y = encode_labels(df["type"])

    print(f"      Feature matrix shape : {X.shape}")
    print(f"      Phishing samples (1) : {y.sum():,}")
    print(f"      Legitimate samples(0): {(y == 0).sum():,}")
    print(f"      Class balance        : {y.mean()*100:.1f}% phishing\n")

    # ── 4. Train / test split ────────────────
    print("[4/6] Splitting data (80 % train / 20 % test) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"      Train: {len(X_train):,}  |  Test: {len(X_test):,}\n")

    # ── 5. Train & evaluate all models ───────
    print("[5/6] Training and evaluating models …")
    results      = []
    trained_models = {}

    for name, model in MODELS.items():
        print(f"      ▶ {name} … ", end="", flush=True)
        model.fit(X_train, y_train)
        metrics = evaluate_model(name, model, X_test, y_test)
        results.append(metrics)
        trained_models[name] = model
        print(f"done  (F1={metrics['F1-Score']:.4f})")

        # Detailed classification report
        y_pred = model.predict(X_test)
        print("        " + "-" * 50)
        report = classification_report(
            y_test, y_pred,
            target_names=["Legitimate (0)", "Phishing (1)"],
            zero_division=0
        )
        for line in report.splitlines():
            print(f"        {line}")
        print()

    # ── 5b. Comparison table ──────────────────
    print("\n[─] Model Comparison Table")
    print_comparison_table(results)

    # ── 6. Save best model ───────────────────
    best_result = max(results, key=lambda r: r["F1-Score"])
    best_name   = best_result["Model"]
    best_model  = trained_models[best_name]

    print(f"\n[6/6] Best model  → {best_name}  (F1={best_result['F1-Score']:.4f})")
    print(f"      Saving to   → {MODEL_OUTPUT}")

    joblib.dump(
        {
            "model"       : best_model,
            "model_name"  : best_name,
            "feature_cols": list(X.columns),
            "metrics"     : best_result,
        },
        MODEL_OUTPUT
    )

    size_kb = os.path.getsize(MODEL_OUTPUT) / 1024
    print(f"      File size   : {size_kb:.1f} KB")
    print("\n✓ Training complete.\n")


if __name__ == "__main__":
    main()
