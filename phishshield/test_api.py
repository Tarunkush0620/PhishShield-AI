import requests

BASE = "http://127.0.0.1:5000"

# 1. URL check
r = requests.post(f"{BASE}/api/check-url",
    json={"url": "http://paypa1.com.evil-xyz.biz/verify?user=update"})
d = r.json()
print(f"[URL]   {d.get('label')}  —  phishing: {d.get('phishing_prob',0)*100:.1f}%")

# 2. Email check
r = requests.post(f"{BASE}/api/check-email",
    json={"text": "Congratulations! You won a million dollar lottery prize. Click here to claim your reward now. URGENT act now free money!"})
d = r.json()
print(f"[Email] {d.get('label')}  —  spam: {d.get('spam_prob',0)*100:.1f}%  keywords: {d.get('keyword_count')}")

# 3. Risk score
r = requests.post(f"{BASE}/api/risk-score", json={
    "url_model_prob": 0.85, "email_model_prob": 0.72,
    "num_suspicious_keywords": 4, "domain_age_days": 30, "has_attachment": True})
d = r.json()
print(f"[Risk]  {d.get('score')}/100  —  {d.get('level')}")

# 4. Full analysis
r = requests.post(f"{BASE}/api/full-analysis", json={
    "url": "http://192.168.1.99/login~verify",
    "email": "Verify your account immediately or it will be suspended.",
    "domain_age_days": 10, "has_attachment": True})
d = r.json()
ua = d.get("url_analysis") or {}
ea = d.get("email_analysis") or {}
rs = d.get("risk") or {}
print(f"[Full]  URL: {ua.get('label')}  Email: {ea.get('label')}  Risk: {rs.get('score')}/100 ({rs.get('level')})")
