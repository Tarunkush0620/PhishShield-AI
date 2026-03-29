"""
PhishShield AI — Composite Risk Scoring Model
==============================================
Builds a 0–100 risk score by combining five signals:
  1. url_model_prob        – probability from URL phishing detector
  2. email_model_prob      – probability from email scam detector
  3. num_suspicious_keywords – count of scam/phishing keywords found
  4. domain_age_days       – age of the domain in days
  5. has_attachment        – 1 if email/page has an attachment, else 0

Strategy
--------
  • Load Phishing_Legitimate_full.csv  (10 000 real phishing-feature rows)
  • Derive the 5 risk inputs from real features + calibrated synthetic noise
  • Construct a continuous 0–100 risk-score target via a deterministic
    weighted formula (so the GBR learns the true signal, not pure noise)
  • Train a GradientBoostingRegressor
  • Evaluate (MAE, RMSE, R²) and show feature importances
  • Save model as risk_model.pkl

Output
------
  risk_model.pkl  — GBR model + feature metadata
"""

import os
import warnings
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.preprocessing import MinMaxScaler

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT     = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DATASET_PATH  = os.path.join(REPO_ROOT, "datasets", "Phishing_Legitimate_full.csv")
MODEL_DIR     = os.path.join(REPO_ROOT, "phishshield", "models")
MODEL_OUTPUT  = os.path.join(MODEL_DIR, "risk_model.pkl")
PLOT_OUTPUT   = os.path.join(SCRIPT_DIR, "risk_model_analysis.png")
RANDOM_STATE  = 42
TEST_SIZE     = 0.20

# Risk-score weight per input  (must sum to 100)
WEIGHTS = {
    "url_model_prob"         : 35,   # strongest signal
    "email_model_prob"       : 25,
    "num_suspicious_keywords": 20,
    "domain_age_days"        : 10,   # inverse — young domain = risky
    "has_attachment"         : 10,
}
assert sum(WEIGHTS.values()) == 100, "Weights must sum to 100"

FEATURE_COLS = list(WEIGHTS.keys())


# ─────────────────────────────────────────────
# SYNTHETIC FEATURE GENERATION
# (grounded in real phishing-feature columns)
# ─────────────────────────────────────────────
def build_url_model_prob(df: pd.DataFrame, rng: np.random.Generator) -> np.ndarray:
    """
    Approximate what a URL phishing model's output probability looks like.
    Derived from real URL features + calibrated Gaussian noise.
    """
    # Normalise each contributing feature to [0, 1]
    scaler = MinMaxScaler()
    url_feats = scaler.fit_transform(
        df[["UrlLength", "NumDots", "SubdomainLevel", "NumDash",
            "IpAddress", "NoHttps", "NumSensitiveWords",
            "PctExtHyperlinks", "PctNullSelfRedirectHyperlinks"]].fillna(0)
    )
    # Weighted sum → squeeze through sigmoid → add small noise
    w = np.array([0.15, 0.10, 0.12, 0.08, 0.15, 0.15, 0.12, 0.08, 0.05])
    logit = (url_feats * w).sum(axis=1)                       # 0–1 range
    prob  = logit + rng.normal(0, 0.06, size=len(df))
    # Phishing rows pushed higher, legit rows pushed lower
    prob  = np.where(df["CLASS_LABEL"] == 1,
                     prob + rng.uniform(0.25, 0.45, len(df)),
                     prob + rng.uniform(-0.10, 0.15, len(df)))
    return np.clip(prob, 0.01, 0.99)


def build_email_model_prob(df: pd.DataFrame, rng: np.random.Generator) -> np.ndarray:
    """
    Synthetic email-model probability correlated with phishing class.
    """
    base = np.where(
        df["CLASS_LABEL"] == 1,
        rng.beta(7, 2, size=len(df)),   # skewed high  for phishing
        rng.beta(2, 7, size=len(df)),   # skewed low   for legit
    )
    # Extra signal: InsecureForms, SubmitInfoToEmail push probability up
    push = (df["InsecureForms"].fillna(0) * 0.08 +
            df["SubmitInfoToEmail"].fillna(0) * 0.10)
    return np.clip(base + push.values, 0.01, 0.99)


def build_suspicious_keywords(df: pd.DataFrame, rng: np.random.Generator) -> np.ndarray:
    """
    Map real NumSensitiveWords + synthetic scam-keyword count.
    Phishing rows draw from a higher-mean Poisson.
    """
    base = df["NumSensitiveWords"].fillna(0).values.copy().astype(float)
    extra = np.where(
        df["CLASS_LABEL"] == 1,
        rng.poisson(3.5, size=len(df)),
        rng.poisson(0.4, size=len(df)),
    )
    return np.clip(base + extra, 0, 20).astype(int)


def build_domain_age(df: pd.DataFrame, rng: np.random.Generator) -> np.ndarray:
    """
    Domain age in days.
    Phishing domains tend to be very new (< 6 months).
    Legitimate domains tend to be older (1–15 years).
    """
    age = np.where(
        df["CLASS_LABEL"] == 1,
        rng.exponential(scale=90, size=len(df)),       # mostly < 180 days
        rng.uniform(365, 5475, size=len(df)),           # 1 – 15 years
    )
    return np.clip(age, 1, 6000).astype(int)


def build_has_attachment(df: pd.DataFrame, rng: np.random.Generator) -> np.ndarray:
    """
    Binary: phishing emails more often carry attachments.
    """
    prob_attach = np.where(df["CLASS_LABEL"] == 1, 0.60, 0.12)
    return (rng.random(size=len(df)) < prob_attach).astype(int)


# ─────────────────────────────────────────────
# RISK SCORE TARGET FORMULA
# ─────────────────────────────────────────────
def compute_risk_score(
    url_prob      : np.ndarray,
    email_prob    : np.ndarray,
    keywords      : np.ndarray,
    domain_age    : np.ndarray,
    attachment    : np.ndarray,
    rng           : np.random.Generator,
) -> np.ndarray:
    """
    Deterministic weighted formula → 0-100 risk score.

    Components
    ----------
    url signal      : 0-35   (url_prob   × 35)
    email signal    : 0-25   (email_prob × 25)
    keyword signal  : 0-20   (capped at 10 keywords → scaled to 20)
    domain age      : 0-10   (young domain → high score; tapers off)
    attachment      : 0-10   (binary × 10)
    noise           : ±3     (realistic jitter)
    """
    kw_norm       = np.clip(keywords / 10.0, 0, 1)             # 0–10 kw → 0–1
    age_norm      = np.exp(-domain_age / 365.0)                 # young → near 1
    noise         = rng.normal(0, 1.5, size=len(url_prob))

    score = (
        WEIGHTS["url_model_prob"]          * url_prob
        + WEIGHTS["email_model_prob"]      * email_prob
        + WEIGHTS["num_suspicious_keywords"] * kw_norm
        + WEIGHTS["domain_age_days"]       * age_norm
        + WEIGHTS["has_attachment"]        * attachment
        + noise
    )
    return np.clip(score, 0.0, 100.0)


# ─────────────────────────────────────────────
# GBR MODEL
# ─────────────────────────────────────────────
def build_model() -> GradientBoostingRegressor:
    return GradientBoostingRegressor(
        n_estimators      = 500,
        learning_rate     = 0.05,
        max_depth         = 5,
        min_samples_split = 10,
        subsample         = 0.8,
        loss              = "huber",          # robust to outliers
        random_state      = RANDOM_STATE,
    )


# ─────────────────────────────────────────────
# EVALUATION
# ─────────────────────────────────────────────
def evaluate(model, X_test, y_test) -> dict:
    y_pred = model.predict(X_test)
    mae    = mean_absolute_error(y_test, y_pred)
    rmse   = mean_squared_error(y_test, y_pred) ** 0.5
    r2     = r2_score(y_test, y_pred)
    return {"MAE": round(mae, 3), "RMSE": round(rmse, 3), "R²": round(r2, 4),
            "y_pred": y_pred}


def print_metrics(metrics: dict) -> None:
    print("  ┌─────────────────────────────┐")
    print(f"  │  MAE   (avg error pts)  {metrics['MAE']:>5.2f} │")
    print(f"  │  RMSE  (root mean sq)   {metrics['RMSE']:>5.2f} │")
    print(f"  │  R²    (explained var)  {metrics['R²']:>5.4f} │")
    print("  └─────────────────────────────┘")


# ─────────────────────────────────────────────
# PLOTS
# ─────────────────────────────────────────────
def save_plots(model, X_test, y_test, y_pred, feature_names, path):
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    # 1. Predicted vs Actual
    ax = axes[0]
    ax.scatter(y_test, y_pred, alpha=0.3, s=8, color="steelblue")
    mn, mx = min(y_test.min(), y_pred.min()), max(y_test.max(), y_pred.max())
    ax.plot([mn, mx], [mn, mx], "r--", lw=1.5, label="Perfect fit")
    ax.set_xlabel("Actual Risk Score")
    ax.set_ylabel("Predicted Risk Score")
    ax.set_title("Predicted vs Actual")
    ax.legend()

    # 2. Residuals
    ax = axes[1]
    residuals = y_pred - y_test
    ax.hist(residuals, bins=50, color="coral", edgecolor="white")
    ax.axvline(0, color="black", lw=1.5, ls="--")
    ax.set_xlabel("Residual (Predicted − Actual)")
    ax.set_ylabel("Count")
    ax.set_title("Residual Distribution")

    # 3. Feature importances
    ax = axes[2]
    importances = model.feature_importances_
    idx = np.argsort(importances)[::-1]
    bars = ax.bar(range(len(feature_names)),
                  importances[idx] * 100,
                  color="mediumseagreen", edgecolor="white")
    ax.set_xticks(range(len(feature_names)))
    ax.set_xticklabels([feature_names[i] for i in idx], rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("Importance (%)")
    ax.set_title("Feature Importances")

    plt.suptitle("PhishShield AI — Risk Score Model Analysis", fontsize=13, y=1.02)
    plt.tight_layout()
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    print(f"      Analysis plot saved → {path}")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main() -> None:
    rng = np.random.default_rng(RANDOM_STATE)
    os.makedirs(MODEL_DIR, exist_ok=True)

    # ── 1. Load real dataset ─────────────────
    print(f"\n[1/6] Loading dataset …\n      {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"      Rows: {len(df):,}  |  Phishing: {(df['CLASS_LABEL']==1).sum():,}"
          f"  |  Legit: {(df['CLASS_LABEL']==0).sum():,}")

    # ── 2. Generate synthetic risk inputs ────
    print("\n[2/6] Generating synthetic risk-input features …")
    url_prob   = build_url_model_prob(df, rng)
    email_prob = build_email_model_prob(df, rng)
    keywords   = build_suspicious_keywords(df, rng)
    domain_age = build_domain_age(df, rng)
    attachment = build_has_attachment(df, rng)

    X = pd.DataFrame({
        "url_model_prob"         : url_prob,
        "email_model_prob"       : email_prob,
        "num_suspicious_keywords": keywords,
        "domain_age_days"        : domain_age,
        "has_attachment"         : attachment,
    })

    print("      Feature statistics:")
    print(X.describe().round(3).to_string())

    # ── 3. Compute risk-score target ─────────
    print("\n[3/6] Computing ground-truth risk scores …")
    y = compute_risk_score(url_prob, email_prob, keywords, domain_age, attachment, rng)

    phishing_scores = y[df["CLASS_LABEL"] == 1]
    legit_scores    = y[df["CLASS_LABEL"] == 0]
    print(f"      Phishing → mean={phishing_scores.mean():.1f}  "
          f"min={phishing_scores.min():.1f}  max={phishing_scores.max():.1f}")
    print(f"      Legit    → mean={legit_scores.mean():.1f}  "
          f"min={legit_scores.min():.1f}  max={legit_scores.max():.1f}")

    # Score bucket distribution
    buckets = pd.cut(y, bins=[0,20,40,60,80,100],
                     labels=["0-20 (Safe)","20-40 (Low)","40-60 (Med)",
                             "60-80 (High)","80-100 (Critical)"])
    print("\n      Risk bucket distribution:")
    for label, cnt in buckets.value_counts().sort_index().items():
        bar = "█" * (cnt // 100)
        print(f"        {str(label):<20} {cnt:>5}  {bar}")

    # ── 4. Train / Test split ────────────────
    print("\n[4/6] Splitting data (80/20 stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
    )
    print(f"      Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── 5. Train & Evaluate ──────────────────
    print("\n[5/6] Training GradientBoostingRegressor …")
    model = build_model()
    model.fit(X_train, y_train)
    print("      Training complete.")

    metrics = evaluate(model, X_test, y_test)
    print("\n      Test-set metrics:")
    print_metrics(metrics)

    # 5-fold cross-validation
    cv_scores = cross_val_score(
        build_model(), X, y, cv=5, scoring="r2", n_jobs=-1
    )
    print(f"\n      5-Fold CV R²: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # Feature importances
    print("\n      Feature importances:")
    for feat, imp in sorted(
        zip(FEATURE_COLS, model.feature_importances_),
        key=lambda x: -x[1]
    ):
        bar = "█" * int(imp * 50)
        print(f"        {feat:<28}  {imp*100:>5.1f}%  {bar}")

    # Save analysis plot
    save_plots(model, X_test, y_test, metrics["y_pred"], FEATURE_COLS, PLOT_OUTPUT)

    # ── 6. Save model ────────────────────────
    print("\n[6/6] Saving model …")
    payload = {
        "model"       : model,
        "feature_cols": FEATURE_COLS,
        "weights"     : WEIGHTS,
        "metrics"     : {k: v for k, v in metrics.items() if k != "y_pred"},
        "description" : "GBR risk scorer: outputs 0-100 risk score from 5 signals",
    }
    joblib.dump(payload, MODEL_OUTPUT)
    sz = os.path.getsize(MODEL_OUTPUT) / 1024
    print(f"      Saved → {MODEL_OUTPUT}  ({sz:.1f} KB)")
    print("\n✓ Risk model training complete.\n")

    # ── Inference demo ───────────────────────
    print("─" * 62)
    print("  Risk Score Demo  (5 synthetic threat scenarios)")
    print("─" * 62)
    demo_cases = [
        # name,                        url_p  em_p  kw  age    att
        ("Obvious phishing attack",    0.97,  0.94, 9,  12,    1),
        ("Suspicious unknown domain",  0.78,  0.55, 3,  45,    1),
        ("Borderline risky email",     0.55,  0.62, 2,  180,   0),
        ("Probably legitimate",        0.15,  0.10, 0,  1825,  0),
        ("Trusted corporate domain",   0.03,  0.02, 0,  4380,  0),
    ]

    bundle    = joblib.load(MODEL_OUTPUT)
    inf_model = bundle["model"]
    feat_cols = bundle["feature_cols"]

    for name, url_p, em_p, kw, age, att in demo_cases:
        row   = pd.DataFrame([[url_p, em_p, kw, age, att]], columns=feat_cols)
        score = float(inf_model.predict(row)[0])
        score = max(0.0, min(100.0, score))

        if score >= 80:
            level, icon = "CRITICAL", "🔴"
        elif score >= 60:
            level, icon = "HIGH    ", "🟠"
        elif score >= 40:
            level, icon = "MEDIUM  ", "🟡"
        elif score >= 20:
            level, icon = "LOW     ", "🟢"
        else:
            level, icon = "SAFE    ", "✅"

        bar   = "█" * int(score / 3.33) + "░" * (30 - int(score / 3.33))
        print(f"\n  {icon} {name}")
        print(f"     Inputs  → url_prob={url_p:.2f}  email_prob={em_p:.2f}"
              f"  keywords={kw}  domain_age={age}d  attachment={att}")
        print(f"     Score   → [{bar}] {score:5.1f}/100  [{level}]")

    print("\n" + "─" * 62 + "\n")


if __name__ == "__main__":
    main()
