from pathlib import Path

import joblib
import numpy as np
import re

MODELS_DIR = Path(__file__).resolve().parent / "app" / "ml" / "saved_models"

print("=" * 60)
print("🛡️  SCAM SHIELD — MODEL ACCURACY TEST")
print("=" * 60)

# ── Load Models ────────────────────────────────────────────
email_model   = joblib.load(MODELS_DIR / "email_model.pkl")
sms_model     = joblib.load(MODELS_DIR / "sms_model.pkl")
url_model     = joblib.load(MODELS_DIR / "url_model.pkl")
print("✅ All models loaded\n")

# ── Email Tests ────────────────────────────────────────────
print("📧 EMAIL MODEL TEST")
print("-" * 40)
email_tests = [
    ("SCAM",  "Congratulations! You won $1000. Click here to claim your prize now!"),
    ("SCAM",  "URGENT: Your bank account suspended. Verify immediately at paypal-secure.xyz"),
    ("SCAM",  "FREE iPhone! You have been selected. Limited time offer. Act now!"),
    ("SCAM",  "Dear winner, You have won £500,000. Send your details to claim."),
    ("LEGIT", "Hi team, please find the project report attached for tomorrow meeting."),
    ("LEGIT", "Your order #4521 has been delivered. Thank you for shopping with us."),
    ("LEGIT", "Meeting rescheduled to 3pm. Please confirm your attendance."),
    ("LEGIT", "Dear Muhammad, your invoice is ready. Login to view details."),
]

email_correct = 0
for expected, text in email_tests:
    prob = email_model.predict_proba([text])[0]
    predicted = "SCAM" if prob[1] > 0.92 else "LEGIT"
    correct = "✅" if predicted == expected else "❌"
    email_correct += 1 if predicted == expected else 0
    print(f"  {correct} Expected: {expected:5} | Got: {predicted:5} ({prob[1]*100:.1f}%) | {text[:45]}...")

print(f"\n  📊 Email Accuracy: {email_correct}/{len(email_tests)} = {email_correct/len(email_tests)*100:.0f}%\n")

# ── SMS Tests ──────────────────────────────────────────────
print("📱 SMS MODEL TEST")
print("-" * 40)
sms_tests = [
    ("SPAM",  "Congratulations! You've won a free vacation. Call 0800-FREE now!"),
    ("SPAM",  "WINNER!! You have been selected for $1000 Walmart gift card. Claim now!"),
    ("SPAM",  "FREE entry in a weekly competition to win FA Cup tickets. Text FA to 87121"),
    ("SPAM",  "URGENT: Your mobile won £2000 prize. Call 09061701461 immediately!"),
    ("LEGIT", "Hey, are you coming to the party tonight? Let me know!"),
    ("LEGIT", "Your OTP is 482910. Do not share this with anyone."),
    ("LEGIT", "Can you pick up the kids from school today please?"),
    ("LEGIT", "Meeting at 3pm confirmed. See you there!"),
]

sms_correct = 0
for expected, text in sms_tests:
    prob = sms_model.predict_proba([text])[0]
    predicted = "SPAM" if prob[1] > 0.5 else "LEGIT"
    correct = "✅" if predicted == expected else "❌"
    sms_correct += 1 if predicted == expected else 0
    print(f"  {correct} Expected: {expected:5} | Got: {predicted:5} ({prob[1]*100:.1f}%) | {text[:45]}...")

print(f"\n  📊 SMS Accuracy: {sms_correct}/{len(sms_tests)} = {sms_correct/len(sms_tests)*100:.0f}%\n")

# ── URL Tests ──────────────────────────────────────────────
print("🔗 URL MODEL TEST")
print("-" * 40)

def extract_url_features(url):
    url = str(url).lower().strip()
    try:
        domain = url.split("/")[2] if len(url.split("/")) > 2 else url
    except:
        domain = url
    return [
        len(url), len(domain),
        url.count("."), url.count("-"), url.count("/"),
        url.count("@"), url.count("?"), url.count("="),
        url.count("_"), url.count("%"), url.count("~"), url.count("#"),
        sum(c.isdigit() for c in url),
        sum(c.isupper() for c in url),
        sum(c.isalpha() for c in url),
        int("https" in url),
        int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
        int(any(t in domain for t in [".tk",".ml",".xyz",".win",".click",".gq",".cf",".ga"])),
        int("login" in url), int("verify" in url),
        int("secure" in url), int("account" in url),
        int("update" in url), int("free" in url),
        int("paypal" in url), int("bank" in url),
        int("signin" in url), int("confirm" in url),
        int("password" in url), int("admin" in url),
        len(domain.replace("www.", "")),
        domain.count("-"), domain.count("."),
    ]

url_tests = [
    ("MALICIOUS", "http://paypal-secure-verify.xyz/login/confirm"),
    ("MALICIOUS", "http://free-iphone-winner.tk/claim-now"),
    ("MALICIOUS", "http://amazon-prize-winner.ml/verify-account"),
    ("MALICIOUS", "http://192.168.1.1/admin/steal-data"),
    ("SAFE",      "https://www.google.com"),
    ("SAFE",      "https://github.com/user/project"),
    ("SAFE",      "https://stackoverflow.com/questions/123"),
    ("SAFE",      "https://docs.python.org/3/library/"),
]

url_correct = 0
for expected, url in url_tests:
    features = np.array([extract_url_features(url)])
    prob = url_model.predict_proba(features)[0]
    predicted = "MALICIOUS" if prob[1] > 0.5 else "SAFE"
    correct = "✅" if predicted == expected else "❌"
    url_correct += 1 if predicted == expected else 0
    print(f"  {correct} Expected: {expected:10} | Got: {predicted:10} ({prob[1]*100:.1f}%) | {url[:40]}...")

print(f"\n  📊 URL Accuracy: {url_correct}/{len(url_tests)} = {url_correct/len(url_tests)*100:.0f}%\n")

# ── Final Summary ──────────────────────────────────────────
print("=" * 60)
print("📊 FINAL SUMMARY")
print("=" * 60)
total = len(email_tests) + len(sms_tests) + len(url_tests)
correct = email_correct + sms_correct + url_correct
print(f"  📧 Email Model:  {email_correct}/{len(email_tests)} = {email_correct/len(email_tests)*100:.0f}%")
print(f"  📱 SMS Model:    {sms_correct}/{len(sms_tests)} = {sms_correct/len(sms_tests)*100:.0f}%")
print(f"  🔗 URL Model:    {url_correct}/{len(url_tests)} = {url_correct/len(url_tests)*100:.0f}%")
print(f"\n  🎯 Overall:      {correct}/{total} = {correct/total*100:.0f}%")
print("=" * 60)