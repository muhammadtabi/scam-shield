import joblib
import numpy as np
import re
import os
from typing import Tuple, List
from lime.lime_text import LimeTextExplainer

# ── Paths ──────────────────────────────────────────────────
BASE = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE, "saved_models")

# ── Load Models ────────────────────────────────────────────
email_model   = None
sms_model     = None
url_model     = None
anomaly_model = None

def load_models():
    global email_model, sms_model, url_model, anomaly_model
    try:
        email_model   = joblib.load(os.path.join(MODELS_DIR, "email_model.pkl"))
        print("Email model loaded")
    except Exception as e:
        print(f"Email model not found: {e}")

    try:
        sms_model     = joblib.load(os.path.join(MODELS_DIR, "sms_model.pkl"))
        print("SMS model loaded")
    except Exception as e:
        print(f"SMS model not found: {e}")

    try:
        url_model     = joblib.load(os.path.join(MODELS_DIR, "url_model.pkl"))
        print("URL model loaded")
    except Exception as e:
        print(f"URL model not found: {e}")

    try:
        anomaly_model = joblib.load(os.path.join(MODELS_DIR, "anomaly_model.pkl"))
        print("Anomaly model loaded")
    except Exception as e:
        print(f"Anomaly model not found: {e}")

# ── URL Feature Extractor ──────────────────────────────────
def extract_url_features(url: str) -> list:
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

# ── Scam Level Helper ──────────────────────────────────────
def get_scam_level(confidence: float) -> str:
    if confidence >= 0.70:
        return "scam"
    elif confidence >= 0.40:
        return "suspicious"
    return "safe"

# ── Email Detection ────────────────────────────────────────
def detect_email(subject: str, sender: str, body: str) -> dict:
    reasons = []

    # Check if empty
    if not subject.strip() and not body.strip():
        return {
            "detection_type": "email",
            "scam_level": "safe",
            "confidence": 0,
            "reasons": ["No content provided to analyze"],
            "explanation": "Please provide email subject and body",
            "input_data": {"subject": subject, "sender": sender, "body": body}
        }

    if email_model is None:
        return {"error": "Email model not loaded"}

    text = f"{subject} {sender} {body}"
    text_lower = text.lower()
    sender_lower = sender.lower()
    prob = email_model.predict_proba([text])[0]
    confidence = float(prob[1])

    # Trust known legitimate senders — reduce false alarms from real companies
    trusted_email_domains = {
        "amazon.com", "microsoft.com", "apple.com", "google.com", "github.com",
        "netflix.com", "paypal.com", "stripe.com", "square.com", "linkedin.com",
        "facebook.com", "twitter.com", "instagram.com", "youtube.com", "reddit.com",
        "wikipedia.org", "stackoverflow.com", "github.com",
        # Banks and financial
        "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
        "hsbc.com", "barclays.com", "lloyds.com", "nab.com.au", "anz.com.au",
    }
    is_trusted_sender = any(
        sender_lower.endswith(f"@{domain}") or sender_lower.endswith(f".{domain}")
        for domain in trusted_email_domains
    )

    # Define keyword lists once for consistent use
    aggressive_scam_keywords = ["congratulations", "you won", "claim your", "act now", 
                                "limited time", "click here", "urgent action",
                                "verify account", "confirm identity", "update payment",
                                "suspended", "compromised", "immediately"]
    found_aggressive = [kw for kw in aggressive_scam_keywords if kw in text_lower]
    
    generic_keywords = ["verify", "click", "confirm", "password", "account", "update"]
    found_generic = [kw for kw in generic_keywords if kw in text_lower]

    # For trusted senders, trust them completely — only flag if AGGRESSIVE scam keywords
    if is_trusted_sender:
        scam_level = "safe"
        # Only override to suspicious if aggressive scam keywords are present AND high model confidence
        if found_aggressive and confidence >= 0.80:
            scam_level = "suspicious"
    else:
        # Use higher thresholds to reduce false positives on unknown senders
        # The model is already well-calibrated (98.96% accuracy in training)
        if confidence >= 0.95:
            scam_level = "scam"
        elif confidence >= 0.85:
            scam_level = "suspicious"
        else:
            scam_level = "safe"

    # Rule-based reasons — only count aggressive scam patterns, not general business words

    if found_aggressive and not is_trusted_sender:
        reasons.append(f"Aggressive scam keywords detected: {', '.join(found_aggressive)}")
    elif found_generic and confidence >= 0.70 and not is_trusted_sender:
        reasons.append(f"Generic action keywords detected: {', '.join(found_generic)}")

    if re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+', body):
        reasons.append("Contains embedded URLs — verify authenticity before clicking")

    # Suspicious sender domains only matter if model already suspects it AND not a trusted sender
    suspicious_sender_domains = [".xyz", ".tk", ".ml", ".gq", ".cf", ".win", ".click"]
    if not is_trusted_sender:
        if any(x in sender_lower for x in suspicious_sender_domains) and confidence >= 0.60:
            reasons.append("Sender uses highly suspicious domain extension")
        elif re.search(r'\d{5,}@', sender) and confidence >= 0.60:
            reasons.append("Sender email contains suspicious number sequence")

    # LIME explanation
    explanation = None
    try:
        explainer = LimeTextExplainer(class_names=["Legit", "Scam"])
        exp = explainer.explain_instance(
            text, email_model.predict_proba, num_features=5
        )
        top_words = [f"'{w}' ({'+' if s > 0 else ''}{s:.3f})"
                     for w, s in exp.as_list()]
        explanation = "Key factors: " + ", ".join(top_words)
    except:
        explanation = "Explanation unavailable"

    if not reasons:
        reasons.append("AI model flagged content as suspicious" if scam_level != "safe"
                       else "No suspicious patterns detected — email appears legitimate")

    return {
        "detection_type": "email",
        "scam_level": scam_level,
        "confidence": round(confidence * 100, 2),
        "reasons": reasons,
        "explanation": explanation,
        "input_data": {"subject": subject, "sender": sender, "body": body[:200]}
    }

# ── SMS Detection ──────────────────────────────────────────
def detect_sms(sender_id: str, message: str) -> dict:
    reasons = []

    if sms_model is None:
        return {"error": "SMS model not loaded"}

    prob = sms_model.predict_proba([message])[0]
    confidence = float(prob[1])
    scam_level = get_scam_level(confidence)

    spam_keywords = ["free", "winner", "prize", "urgent", "claim",
                     "won", "cash", "call now", "limited", "offer",
                     "txt", "mobile", "stop", "reply"]
    found = [kw for kw in spam_keywords if kw in message.lower()]
    if found:
        reasons.append(f"Spam keywords found: {', '.join(found)}")

    if re.search(r'\b\d{5,}\b', message):
        reasons.append("Contains suspicious number sequence")

    if re.search(r'http[s]?://', message):
        reasons.append("Contains URL in SMS — potential phishing link")

    if re.search(r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}', message):
        reasons.append("Contains phone number — potential scam callback")

    if not reasons:
        reasons.append("AI model flagged as spam" if scam_level != "safe"
                       else "No suspicious patterns detected")

    return {
        "detection_type": "sms",
        "scam_level": scam_level,
        "confidence": round(confidence * 100, 2),
        "reasons": reasons,
        "explanation": f"SMS analyzed for {len(message)} characters. Model confidence: {confidence*100:.1f}%",
        "input_data": {
            "sender_id": sender_id,
            "message": message[:200]
        }
    }

import urllib.parse

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "stackoverflow.com",
    "python.org",
    "bbc.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "netflix.com",
    "instagram.com",
    "facebook.com",
    "whatsapp.com",
    "youtube.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
}

# ── URL Detection ──────────────────────────────────────────
def detect_url(url: str) -> dict:
    reasons = []
    url_lower = url.lower().strip()

    # Extract domain using urllib
    try:
        parsed_url = urllib.parse.urlparse(url_lower)
        # If there's no scheme, netloc points to the path sometimes.
        domain = parsed_url.netloc or parsed_url.path.split("/")[0]
    except Exception:
        domain = url_lower

    # Normalize host for suffix checks and trusted-domain matching.
    host = domain.split("@")[-1].split(":")[0].strip(".").lower()
    host_no_www = host[4:] if host.startswith("www.") else host

    is_trusted_domain = any(
        host_no_www == trusted or host_no_www.endswith(f".{trusted}")
        for trusted in TRUSTED_DOMAINS
    )

    # Rule-based scoring
    score = 0

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host_no_www):
        score += 40
        reasons.append("Uses raw IP address instead of domain name")

    if any(host_no_www.endswith(t) for t in [".tk", ".ml", ".xyz", ".win", ".click", ".gq", ".cf", ".ga", ".top", ".cc", ".cn"]):
        score += 35
        reasons.append("Uses a highly suspicious domain extension")

    # Brand spoofing checks: If the URL contains a brand name, but the domain doesn't match the brand
    targeted_brands = ["paypal", "apple", "netflix", "amazon", "google", "microsoft", "facebook", "chase", "bankofamerica", "wellsfargo"]
    for brand in targeted_brands:
        if brand in url_lower and brand not in host_no_www:
            score += 30
            reasons.append(f"Spoofs brand '{brand}' outside of the main domain")

    suspicious_words = ["login", "verify", "secure", "account", "auth",
                        "update", "bank", "signin", "support",
                        "confirm", "password", "winner", "free", "prize", "invoice"]
    
    # We only penalize general suspicious words if they appear in an unusually constructed URL or not organically part of a safe brand
    is_safe_domain = is_trusted_domain

    if not is_safe_domain:
        found = [w for w in suspicious_words if w in url_lower]
        if found:
            score += len(found) * 15
            reasons.append(f"Suspicious keywords in URL: {', '.join(found)}")

    if not url_lower.startswith("https://"):
        score += 20
        reasons.append("URL does not use HTTPS — connection is not secure")

    if url.count("-") > 3:
        score += 20
        reasons.append("Excessive hyphens in URL — common phishing pattern")

    if host_no_www.count(".") > 3:
        score += 15
        reasons.append("Too many subdomains — common phishing/obfuscation pattern")

    if len(url) > 100:
        score += 10
        reasons.append("Unusually long URL — common obfuscation technique")

    if "@" in url:
        score += 30
        reasons.append("URL contains @ symbol — hides true destination")

    # Cap score at 100
    score = min(score, 99)

    # Blend rule-based score with the trained URL model when available.
    # The classifier is useful as a signal, but it should not override a URL
    # that has no meaningful phishing indicators on its own.
    ml_confidence = None
    heuristic_score = score
    if url_model is not None:
        try:
            features = np.array([extract_url_features(url_lower)])
            prob = url_model.predict_proba(features)[0]
            classes = list(getattr(url_model, "classes_", [0, 1]))
            malicious_label = 1 if 1 in classes else classes[-1]
            malicious_idx = classes.index(malicious_label)
            ml_confidence = round(float(prob[malicious_idx]) * 100, 2)

            # Use model prediction as a signal, but do not let it blindly override trusted domains.
            model_pred = url_model.predict(features)[0]
            model_flags_malicious = model_pred == malicious_label

            if model_flags_malicious and ml_confidence >= 75 and not is_trusted_domain:
                if heuristic_score >= 30:
                    score = min(99, max(score, heuristic_score + 30))
                    reasons.append("AI URL model reinforced suspicious URL patterns")
                else:
                    score = max(score, 25)
                    reasons.append("AI URL model flagged the link, but heuristics were weak")
            elif ml_confidence <= 30:
                reasons.append("AI URL model classified this link as low risk")
        except Exception as e:
            print(f"URL ML Prediction Error: {e}")

    if is_trusted_domain and score < 60:
        score = min(score, 20)
        if not any("trusted" in reason.lower() for reason in reasons):
            reasons.append("Domain matches a trusted provider and no strong phishing indicators were found")

    # Determine level
    if score >= 65:
        scam_level = "scam"
    elif score >= 30:
        scam_level = "suspicious"
    else:
        scam_level = "safe"

    if not reasons:
        reasons.append("URL appears to be a standard secure format")

    # Confidence is reported as scam probability on a 0-100 scale.
    confidence = float(score)

    explanation = "URL analyzed using domain reputation heuristics."
    if ml_confidence is not None:
        explanation = f"URL analyzed using the trained URL model plus heuristics. ML confidence: {ml_confidence:.1f}%"

    return {
        "detection_type": "url",
        "scam_level": scam_level,
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "explanation": explanation,
        "input_data": {"url": url}
    }