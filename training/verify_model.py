"""
verify_model.py — test URL model predictions using the same feature extraction
as train_url_model.py (via direct import).
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import joblib
import pandas as pd
import train_url_model as tm

bundle = joblib.load(os.path.join(BASE_DIR, '..', 'phishshield', 'models', 'url_model.pkl'))
m    = bundle['model']
cols = bundle['feature_cols']


def predict(url: str):
    """Mirror app.py normalisation then extract features via train_model."""
    original = url
    is_https = int(original.lower().startswith('https://'))
    if original.lower().startswith('https://'):
        norm = 'http://' + original[8:]
    elif not original.lower().startswith('http://'):
        norm = 'http://' + original
    else:
        norm = original

    df   = pd.DataFrame({'url': [norm]})
    feat = tm.extract_features(df)
    # Override IsHTTPS with original URL value
    if 'IsHTTPS' in feat.columns:
        feat['IsHTTPS'] = is_https
    row  = feat[cols]
    prob = m.predict_proba(row)[0]
    return prob[0], prob[1]


tests = [
    ('https://www.google.com',                0),
    ('https://www.amazon.com',                0),
    ('https://github.com',                    0),
    ('https://www.microsoft.com',             0),
    ('https://stackoverflow.com',             0),
    ('http://paypal-secure-login.tk/verify',  1),
    ('http://192.168.1.1/paypal/login',       1),
    ('http://google-account-verify.ml',       1),
    ('http://secure-amazon.fakesite.top',     1),
    ('http://update-account.xyz/secure/login/paypal', 1),
]

THRESHOLD = 0.45
print(f"\n{'URL':55s}  legit   phish  pred   exp    status")
print("-" * 95)
all_ok = True
for url, expected in tests:
    legit, phish = predict(url)
    pred = int(phish > THRESHOLD)
    ok = pred == expected
    all_ok = all_ok and ok
    label    = "PHISH" if pred    else "LEGIT"
    exp_lbl  = "PHISH" if expected else "LEGIT"
    status   = "OK   " if ok      else "WRONG"
    print(f"{url[:55]:55s}  {legit:.3f}  {phish:.3f}  {label:5s}  {exp_lbl:5s}  [{status}]")

print()
print("All tests passed!" if all_ok else "Some tests FAILED — review model or thresholds.")
