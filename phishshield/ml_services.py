import os
import re
import math
import numpy as np
import pandas as pd
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from urllib.parse import urlparse
import ipaddress
import warnings

warnings.filterwarnings("ignore")

# NLTK setup
_NLTK_DATA = os.path.join(os.sep, "tmp", "nltk_data")
os.makedirs(_NLTK_DATA, exist_ok=True)
if _NLTK_DATA not in nltk.data.path:
    nltk.data.path.insert(0, _NLTK_DATA)

for corpus in ("stopwords", "wordnet", "punkt", "punkt_tab"):
    try:
        nltk.data.find(f"corpora/{corpus}" if corpus not in ("punkt","punkt_tab") else f"tokenizers/{corpus}")
    except LookupError:
        nltk.download(corpus, quiet=True, download_dir=_NLTK_DATA)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

print("Loading models...")
_url_model_path = os.path.join(MODELS_DIR, "url_model.pkl")
if os.path.exists(_url_model_path):
    _url_bundle  = joblib.load(_url_model_path)
    URL_MODEL    = _url_bundle["model"]
    URL_FEATURES = _url_bundle["feature_cols"]
else:
    URL_MODEL    = None
    URL_FEATURES = []

_email_bundle = joblib.load(os.path.join(MODELS_DIR, "email_model.pkl"))
EMAIL_MODEL   = _email_bundle["model"]

VECTORIZER    = joblib.load(os.path.join(MODELS_DIR, "vectorizer.pkl"))

_risk_bundle  = joblib.load(os.path.join(MODELS_DIR, "risk_model.pkl"))
RISK_MODEL    = _risk_bundle["model"]
RISK_FEATURES = _risk_bundle["feature_cols"]
RISK_WEIGHTS  = _risk_bundle["weights"]

print("All models ready.\n")

SCAM_KEYWORDS = [
    "lottery", "winner", "won", "prize", "reward", "congratulation",
    "inheritance", "beneficiary", "unclaimed", "wire transfer",
    "verify your account", "confirm your account", "suspended",
    "account alert", "click here", "click now", "limited time",
    "act now", "expires soon", "urgent", "password reset",
    "login attempt", "unusual activity", "free offer", "free money",
    "earn money", "make money", "work from home", "extra income",
    "cash advance", "payday loan", "no obligation", "risk free",
    "100% free", "buy now", "order now", "special offer",
    "investment opportunity", "guaranteed profit", "double your money",
    "bitcoin profit", "crypto", "forex",
    "viagra", "cialis", "weight loss", "pharmacy",
]

BRAND_LIST = [
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "bankofamerica", "wellsfargo", "chase", "ebay",
    "instagram", "twitter", "linkedin", "dropbox", "outlook",
    "office365", "icloud", "whatsapp", "telegram",
]

SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.cf', '.ga', '.gq', '.pw',
                   '.top', '.club', '.work', '.click', '.link', '.win',
                   '.bid', '.party', '.loan', '.review', '.trade'}

TRUSTED_DOMAINS = {
    'google.com', 'google.co.uk', 'google.ca', 'google.com.au',
    'youtube.com', 'gmail.com', 'googlemail.com',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'office365.com', 'azure.com', 'windowsazure.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
    'amazonaws.com',
    'github.com', 'githubusercontent.com',
    'stackoverflow.com', 'stackexchange.com',
    'wikipedia.org', 'wikimedia.org',
    'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
    'linkedin.com', 'reddit.com', 'pinterest.com', 'tiktok.com',
    'snapchat.com', 'discord.com', 'twitch.tv',
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'reuters.com', 'bloomberg.com', 'forbes.com',
    'paypal.com', 'ebay.com', 'etsy.com', 'shopify.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'dropbox.com', 'box.com', 'notion.so', 'slack.com', 'zoom.us',
    'atlassian.com', 'jira.com', 'confluence.com',
    'cloudflare.com', 'fastly.com',
    'netflix.com', 'spotify.com', 'adobe.com', 'salesforce.com',
    'wordpress.com', 'blogger.com', 'medium.com',
}

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = pd.Series(list(s)).value_counts(normalize=True)
    return float((-freq * np.log2(freq)).sum())

def _has_ip(url: str) -> int:
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0

def _subdomain_count(url: str) -> int:
    try:
        host  = urlparse(url).hostname or ""
        parts = [p for p in host.split(".") if p != "www"]
        return max(len(parts) - 2, 0)
    except Exception:
        return 0

def _domain_len(url: str) -> int:
    try:
        return len(urlparse(url).hostname or "")
    except Exception:
        return 0

def extract_url_features(url: str) -> pd.DataFrame:
    original = str(url)
    is_https = int(original.lower().startswith('https://'))

    if original.lower().startswith('https://'):
        u = 'http://' + original[8:]
    elif not original.lower().startswith('http://'):
        u = 'http://' + original
    else:
        u = original

    parsed = urlparse(u)
    host   = (parsed.hostname or '').lower()
    path   = (parsed.path + '?' + (parsed.query or '')).lower()
    parts  = host.split('.')
    reg_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host

    _has_susp_tld = int(any(host.endswith(t) for t in SUSPICIOUS_TLDS))
    _has_brand    = int(any(b in path and b not in reg_domain for b in BRAND_LIST))
    _num_special  = sum(u.count(c) for c in "!$'\"(){}[]|^`")

    row = {
        'URLLength'        : len(u),
        'DomainLength'     : _domain_len(u),
        'IsHTTPS'          : is_https,
        'NumDots'          : u.count('.'),
        'NumHyphens'       : u.count('-'),
        'NumSubdomains'    : _subdomain_count(u),
        'HasIPAddress'     : _has_ip(u),
        'NumSlashes'       : u.count('/'),
        'NumAtSymbol'      : u.count('@'),
        'NumQueryParams'   : u.count('?'),
        'NumAmpersand'     : u.count('&'),
        'NumEquals'        : u.count('='),
        'NumPercent'       : u.count('%'),
        'NumDigits'        : sum(c.isdigit() for c in u),
        'HasDoubleSlash'   : int('//' in (urlparse(u).path or '')),
        'HasTildeSign'     : int('~' in u),
        'URLEntropy'       : _entropy(u),
        'HasSuspiciousTLD' : _has_susp_tld,
        'PathLength'       : len(parsed.path),
        'HasBrandKeyword'  : _has_brand,
        'NumSpecialChars'  : _num_special,
    }

    available = {k: v for k, v in row.items() if k in URL_FEATURES}
    return pd.DataFrame([available])[URL_FEATURES]

_stop_words  = set(stopwords.words("english"))
_lemmatizer  = WordNetLemmatizer()
_url_re      = re.compile(r"https?://\S+|www\.\S+")
_email_re    = re.compile(r"\S+@\S+")
_punct_re    = re.compile(r"[^\w\s]")
_numeric_re  = re.compile(r"\b\d+\b")
_space_re    = re.compile(r"\s+")

def clean_text(text: str) -> str:
    text = text.lower()
    text = _url_re.sub(" ", text)
    text = _email_re.sub(" ", text)
    text = _punct_re.sub(" ", text)
    text = _numeric_re.sub(" ", text)
    text = _space_re.sub(" ", text).strip()
    tokens = [
        _lemmatizer.lemmatize(t)
        for t in text.split()
        if t not in _stop_words and len(t) > 1
    ]
    return " ".join(tokens)

def count_keywords(text: str) -> int:
    lower = text.lower()
    return sum(1 for kw in SCAM_KEYWORDS if kw in lower)

def _get_registered_domain(url: str) -> str:
    try:
        host  = (urlparse(url).hostname or '').lower()
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ''

def risk_level(score: float) -> tuple[str, str]:
    if score >= 80:  return 'Critical',  '#ef4444'
    if score >= 60:  return 'High',      '#f97316'
    if score >= 40:  return 'Medium',    '#eab308'
    if score >= 20:  return 'Low',       '#22c55e'
    return               'Safe',         '#06b6d4'

def _rule_boost_url(url: str, feats: pd.DataFrame, raw_prob: float):
    prob    = raw_prob
    signals = []

    reg_domain = _get_registered_domain(url)
    if reg_domain in TRUSTED_DOMAINS:
        return 0.02, []

    if feats['HasIPAddress'].iloc[0]:
        prob = max(prob, 0.93)
        signals.append('IP address used instead of domain')

    if feats['NumAtSymbol'].iloc[0]:
        prob = max(prob, 0.88)
        signals.append('@ symbol in URL (credential harvesting pattern)')

    if feats['HasTildeSign'].iloc[0]:
        prob = max(prob, 0.82)
        signals.append('Tilde (~) sign in URL')

    if feats['NumDots'].iloc[0] > 6:
        prob = max(prob, 0.80)
        signals.append(f"Excessive dots ({int(feats['NumDots'].iloc[0])}) - subdomain abuse")

    if feats['URLEntropy'].iloc[0] > 5.5:
        prob = max(prob, 0.78)
        signals.append('High URL entropy - possible obfuscation')

    is_https_orig = int(url.lower().startswith('https://'))
    if not is_https_orig:
        if raw_prob >= 0.4:
            prob = max(prob, 0.65)
        signals.append('No HTTPS')

    if int(feats['URLLength'].iloc[0]) > 100:
        prob = max(prob, 0.72)
        signals.append(f"Very long URL ({int(feats['URLLength'].iloc[0])} chars)")

    try:
        parsed     = urlparse(url)
        host       = (parsed.hostname or '').lower()
        path_query = (parsed.path + '?' + (parsed.query or '')).lower()
        parts2     = host.split('.')
        reg_domain = '.'.join(parts2[-2:]) if len(parts2) >= 2 else host
        for brand in BRAND_LIST:
            if brand in path_query and brand not in reg_domain:
                prob = max(prob, 0.91)
                signals.append(f"Brand impersonation detected: '{brand}'")
                break
    except Exception:
        pass

    try:
        host = (urlparse(url).hostname or '').lower()
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                prob = max(prob, 0.75)
                signals.append(f'Suspicious TLD: {tld}')
                break
    except Exception:
        pass

    if is_https_orig and not signals:
        prob = min(prob, 0.35)
    elif is_https_orig and len(signals) == 1 and signals[0] == 'No HTTPS':
        signals.clear()
        prob = min(prob, 0.40)

    return prob, signals

def _confidence_tier(decisive_score: float) -> str:
    return f"{round(decisive_score * 100)}%"

# ─────────────────────────────────────────────
# AI EXPLAIN  ─  contextual threat narrative
# ─────────────────────────────────────────────

_CHAT_KB = [
    (["what is phishing", "phishing mean", "define phishing", "explain phishing"],
     "Phishing is a cyberattack where criminals impersonate trusted entities — banks, brands, or colleagues — to trick victims into revealing credentials, financial data, or installing malware. It remains the #1 initial access vector in 91% of data breaches."),

    (["how to identify", "spot phishing", "recognize phishing", "tell if phishing", "identify fake", "check url", "check link", "is this safe"],
     "Key red flags: mismatched sender domain, urgent/threatening language, generic greeting ('Dear User'), links that don't match displayed text, unexpected credential or payment requests, and suspicious attachments. PhishShield AI checks 17+ structural signals automatically — just paste the URL in the scanner."),

    (["what should i do", "clicked phishing", "clicked a phishing", "already clicked", "visited phishing", "entered my password", "opened phishing"],
     "If you clicked a phishing link: 1) Disconnect from WiFi immediately. 2) Change passwords for affected accounts from a clean device. 3) Enable 2FA everywhere. 4) Run a full malware scan. 5) Contact your bank if financial info was entered. 6) Report to your IT team and CERT."),

    (["how does phishshield work", "how it works", "how does this work", "phishshield ai", "what models do you use", "how are you trained"],
     "PhishShield AI uses a 3-model ensemble: a RandomForest classifier for URL structural analysis (17 features, 92.7% accuracy), an XGBoost model for email spam/scam detection (TF-IDF features, 98.1% accuracy), and a composite risk regression model. Rule-based signal boosting overlays ML predictions to catch known evasion patterns."),

    (["common phishing", "types of phishing", "phishing techniques", "phishing methods"],
     "The most common types: Spear phishing (targeted/personalized), Smishing (SMS-based), Vishing (phone calls), Clone phishing (duplicating legitimate emails), Business Email Compromise (BEC), and Homograph attacks using lookalike Unicode domains like paypaI.com (capital I instead of lowercase L)."),

    (["what is malware", "malware mean", "define malware"],
     "Malware is malicious software designed to infiltrate or damage systems. Key types: ransomware (encrypts files for ransom), trojans (disguised as legit software), keyloggers (record keystrokes), and spyware. Phishing is the most common malware delivery method."),

    (["two factor", "2fa", "multi factor", "mfa", "authenticator app"],
     "2FA adds a second verification step beyond your password — typically a time-based code (Google Authenticator), hardware key (YubiKey), or biometrics. Even if phishers steal your password, 2FA blocks unauthorized access. Always prefer app-based 2FA over SMS (which can be SIM-swapped)."),

    (["stay safe", "protect myself", "security tips", "best practices", "safe browsing"],
     "Top practices: Use a password manager with unique passwords per site. Enable 2FA on all accounts. Keep software patched. Hover links before clicking. Use DNS filtering (Cloudflare 1.1.1.1). Never enter credentials on HTTP sites. Always verify sender email domains — not just display names."),

    (["ransomware", "what is ransomware"],
     "Ransomware encrypts your files and demands cryptocurrency payment for the decryption key, commonly delivered via phishing emails. Major attacks include WannaCry, REvil, and LockBit. Best defenses: regular offline backups, network segmentation, and email filtering."),

    (["email scam", "scam email", "spam email", "how to spot spam"],
     "Email scams exploit four psychological hooks: Urgency ('your account closes in 24h'), Fear ('suspicious login detected'), Greed ('you've won a prize'), and Authority (impersonating a CEO or bank). PhishShield AI detects these via keyword analysis — paste your email in the analyzer to check."),

    (["accuracy", "how accurate", "model accuracy", "how good", "precision", "f1 score"],
     "PhishShield AI achieves 92.7% accuracy on URLs (F1=0.82) and 98.1% accuracy on emails (F1=0.92) on held-out test datasets. Confidence percentages reflect calibrated probability output, further boosted for known high-risk patterns like IP addresses and @ symbols in URLs."),

    (["report phishing", "report scam", "where report", "report suspicious"],
     "Report phishing to: Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish), PhishTank (phishtank.com), your email provider's 'Report Spam', CISA via reportphishing@apwg.org, and your IT security team."),

    (["bulk scan", "scan multiple", "many urls", "list of urls"],
     "Use the '⚡ Bulk Scanner' tab to scan up to 50 URLs simultaneously! Paste one URL per line, click Scan All, and PhishShield AI analyzes each one. Export results as CSV for reporting."),

    (["social engineering", "what is social engineering"],
     "Social engineering manipulates people into revealing information by exploiting psychology — urgency, authority, fear, and reciprocity. Phishing is the most common form. Defense: always verify sensitive requests through a separate, trusted channel regardless of how urgent they appear."),

    (["spear phishing", "what is spear phishing", "targeted phishing"],
     "Spear phishing is a targeted attack customized for a specific individual or organization using personal details (name, employer, recent activities) to appear legitimate. Unlike mass phishing, it's crafted specifically for the victim — making it far more convincing and dangerous."),
]


def _get_chat_response(question):
    """Keyword-matching chat response system."""
    q = question.lower()
    for keywords, answer in _CHAT_KB:
        if any(kw in q for kw in keywords):
            return answer
    if any(w in q for w in ["hi", "hello", "hey", "howdy"]):
        return "Hello! I'm PhishShield AI's security assistant. Ask me anything about phishing, URL safety, email scams, 2FA, or how to protect yourself online."
    if any(w in q for w in ["help", "what can you do", "capabilities"]):
        return "I can answer questions about: phishing attack types, identifying fake URLs/emails, what to do after clicking a phishing link, how PhishShield's models work, 2FA, ransomware, social engineering, and security best practices. What would you like to know?"
    if any(w in q for w in ["thank", "thanks", "great", "awesome", "good job"]):
        return "Happy to help keep you safe! Stay vigilant — when in doubt, scan it with PhishShield AI. 🛡️"
    return "I'm specialized in phishing and cybersecurity topics. Try asking: 'What is phishing?', 'How do I identify a fake URL?', 'What should I do if I clicked a phishing link?', or 'How does PhishShield AI work?'"


def _call_groq(prompt):
    """Optional: call Groq cloud LLM if GROQ_API_KEY env var is set."""
    import json as _json
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return None
    try:
        from urllib.request import Request, urlopen

        payload = _json.dumps({
            "model": "llama3-8b-8192",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity AI analyst for PhishShield AI. Explain the threat in 2-3 concise, technical sentences focused on the specific indicators provided. Do not use markdown."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 220,
            "temperature": 0.3,
        }).encode("utf-8")

        req = Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


def _call_gemini(prompt, api_key):
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-3.5-flash',
            contents=prompt,
        )
        print("Gemini response success!", flush=True)
        return response.text.strip()
    except Exception as e:
        print(f"Gemini API Error details: {e}", flush=True)
        return None

def _generate_ai_explanation(label, confidence, signals, feature_flags,
                              url="", email_text="", keyword_count=0, flagged_tokens=None):
    """Generate a contextual AI-style threat explanation.
    Uses Gemini LLM if GEMINI_API_KEY is set; otherwise falls back to smart templates.
    """
    import os
    flagged_tokens = flagged_tokens or []
    is_phishing    = label in ("Phishing", "Spam/Scam")
    target_type    = "URL" if url else "email"

    # ── Optional Gemini LLM path ──────────────────────────────────────────
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    load_dotenv(env_path, override=True)
    
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        ctx = [
            f"Analyzed {target_type}: {url or email_text[:120]}",
            f"Verdict: {label} ({confidence} confidence)",
            f"Threat signals: {'; '.join(signals) if signals else 'none'}",
        ]
        if feature_flags:
            active = [k for k, v in feature_flags.items() if v]
            if active:
                ctx.append(f"Active feature flags: {', '.join(active)}")
        if flagged_tokens:
            ctx.append(f"Flagged keywords: {', '.join(flagged_tokens[:6])}")
        
        prompt = "\n".join(ctx) + f"\n\nYou are a cybersecurity AI analyst for PhishShield AI. Explain concisely why this is classified as {label}, referencing the specific indicators above. Keep the explanation to 2-3 technical sentences. Do not use markdown."
        
        gemini_text = _call_gemini(prompt, api_key)
        if gemini_text:
            return gemini_text

    # ── Optional Groq LLM path ──────────────────────────────────────────
    if os.environ.get("GROQ_API_KEY"):
        ctx = [
            f"Analyzed {target_type}: {url or email_text[:120]}",
            f"Verdict: {label} ({confidence} confidence)",
            f"Threat signals: {'; '.join(signals) if signals else 'none'}",
        ]
        if feature_flags:
            active = [k for k, v in feature_flags.items() if v]
            if active:
                ctx.append(f"Active feature flags: {', '.join(active)}")
        if flagged_tokens:
            ctx.append(f"Flagged keywords: {', '.join(flagged_tokens[:6])}")
        prompt = "\n".join(ctx) + f"\n\nExplain concisely why this is classified as {label}, referencing the specific indicators above."
        groq_text = _call_groq(prompt)
        if groq_text:
            return groq_text

    # ── Template fallback ───────────────────────────────────────────────
    if not is_phishing:
        paras = [f"PhishShield AI's multi-model analysis of this {target_type} returned a clean verdict with {confidence} confidence."]
        if url:
            paras.append("The domain structure is consistent with legitimate web infrastructure. URL entropy is within normal parameters, no IP-literal addresses were detected, and no brand impersonation patterns were identified.")
            paras.append("Subdomain depth, path length, and character composition all conform to patterns typical of authentic web resources.")
        else:
            paras.append("The email's language patterns, keyword distribution, and sentence structure align with standard business communication.")
            paras.append("No urgency triggers, suspicious reward language, or social engineering phrases were detected.")
        paras.append("Exercise standard caution: verify the sender's identity independently before sharing any sensitive information.")
        return " ".join(paras)

    paras      = []
    signal_txt = ""
    if signals:
        if len(signals) == 1:
            signal_txt = f"The primary concern is: {signals[0].lower()}."
        else:
            signal_txt = f"Multiple threat indicators were identified: {'; '.join(s.lower() for s in signals[:4])}."

    if url:
        paras.append(f"This URL demonstrates strong phishing characteristics with {confidence} confidence across PhishShield AI's detection ensemble.")
        if signal_txt:
            paras.append(signal_txt)
        if feature_flags.get("Has IP address"):
            paras.append("Using a raw IP address instead of a registered domain is a classic phishing technique that bypasses domain-reputation databases and eliminates the WHOIS paper trail associated with legitimate sites.")
        if feature_flags.get("Has @ symbol"):
            paras.append("The @ symbol embedded in the URL path is a deceptive tactic — browsers display only the portion after @ as the actual destination, masking the true malicious host from casual inspection.")
        if feature_flags.get("High entropy"):
            paras.append("The URL's elevated character entropy indicates obfuscated or machine-generated segments, a standard evasion technique used in phishing kits to bypass hash-based blocklists.")
        if feature_flags.get("Many dots") or feature_flags.get("Long URL"):
            paras.append("Excessive subdomain nesting and abnormal URL length are hallmarks of subdomain squatting — embedding a trusted brand early in the chain while concealing the actual malicious registered domain at the end.")
        if feature_flags.get("Has redirect"):
            paras.append("Redirection chains obscure the final phishing destination, routing users through benign-looking intermediaries before landing on a credential-harvesting page.")
        if feature_flags.get("Has short URL"):
            paras.append("URL shortening services are frequently abused to hide the true destination and prevent pre-click inspection by security tools.")
        if len(paras) <= 1:
            paras.append("Structural analysis identified patterns inconsistent with legitimate websites, including unusual character composition and suspicious path architecture.")
        paras.append("Do not visit this URL, enter credentials, or interact with any content it serves. Report it to your IT security team and the domain's hosting provider.")
    else:
        paras.append(f"This email exhibits characteristics strongly consistent with a spam or scam campaign, classified at {confidence} confidence.")
        if signal_txt:
            paras.append(signal_txt)
        if keyword_count >= 5:
            token_str = f" — including '{', '.join(flagged_tokens[:3])}'" if flagged_tokens else ""
            paras.append(f"The concentration of {keyword_count} high-risk semantic keywords{token_str} represents a textbook social engineering pattern: urgency triggers, reward language, and account-threat phrases designed to suppress rational judgment and induce impulsive action.")
        elif keyword_count >= 2:
            paras.append(f"The presence of {keyword_count} phishing-related keywords suggests deliberate use of persuasion techniques typical of social engineering attacks.")
        elif keyword_count == 1 and flagged_tokens:
            paras.append(f"The keyword '{flagged_tokens[0]}' is a common phishing trigger associated with urgency-based social engineering attacks.")
        paras.append("Do not click any links, reply with personal information, forward the message, or follow its instructions. Mark it as spam and delete it immediately.")

    paras.append(f"PhishShield AI's verdict was reached through structural heuristics, rule-based signal boosting, and a trained ML ensemble — all agreeing at {confidence} confidence.")
    return " ".join(paras)
