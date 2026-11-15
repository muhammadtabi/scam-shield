import joblib
import numpy as np
import re
import os
import ipaddress
from typing import Any, Dict, List, Optional

from app.ml.email_features import explain_linear_text_pipeline, extract_email_signals
from app.ml.sms_features import extract_sms_signals
from app.ml.url_features import extract_url_features, parse_canonical_url, predict_url_bundle

# ── Paths ──────────────────────────────────────────────────
BASE = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE, "saved_models")

# ── Load Models ────────────────────────────────────────────
email_model      = None
email_meta_model = None
sms_model        = None
sms_meta_model   = None
url_model        = None
anomaly_model    = None

def load_models():
    global email_model, email_meta_model, sms_model, sms_meta_model, url_model, anomaly_model
    try:
        email_model   = joblib.load(os.path.join(MODELS_DIR, "email_model.pkl"))
        print("Email model loaded")
    except Exception as e:
        print(f"Email model not found: {e}")

    try:
        email_meta_model = joblib.load(os.path.join(MODELS_DIR, "email_meta_model.pkl"))
    except Exception:
        email_meta_model = None

    try:
        sms_model     = joblib.load(os.path.join(MODELS_DIR, "sms_model.pkl"))
        print("SMS model loaded")
    except Exception as e:
        print(f"SMS model not found: {e}")

    try:
        sms_meta_model = joblib.load(os.path.join(MODELS_DIR, "sms_meta_model.pkl"))
    except Exception:
        sms_meta_model = None

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

# ── Scam Level Helper ──────────────────────────────────────
def get_scam_level(confidence: float) -> str:
    if confidence >= 0.70:
        return "scam"
    elif confidence >= 0.40:
        return "suspicious"
    return "safe"

# ── Email Detection ────────────────────────────────────────
TRUSTED_EMAIL_DOMAINS = {
    "amazon.com", "microsoft.com", "apple.com", "google.com", "github.com",
    "netflix.com", "paypal.com", "stripe.com", "square.com", "linkedin.com",
    "facebook.com", "twitter.com", "instagram.com", "youtube.com", "reddit.com",
    "wikipedia.org", "stackoverflow.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "citibank.com", "hsbc.com", "barclays.com", "lloyds.com",
    "nab.com.au", "anz.com.au", "americanexpress.com", "visa.com", "mastercard.com",
    "nayapay.com", "emergent.sh", "skool.com",
}


def detect_email(
    subject: str,
    sender: str,
    body: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> dict:
    """Analyze email context via debiased ML, sender impersonation, and URL risk checks."""
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

    sig = extract_email_signals(
        subject, sender, body, url_risk_fn=detect_url, metadata=metadata
    )
    p_text = float(email_model.predict_proba([sig.cleaned_model_text])[0][1])

    if isinstance(email_meta_model, dict) and email_meta_model.get("meta_clf") is not None:
        X_meta = np.array([sig.to_meta_vector(p_text)], dtype=float)
        p_meta = float(email_meta_model["meta_clf"].predict_proba(X_meta)[0][1])
        # When sender/links are absent (raw body paste), keep high-confidence text signal intact.
        p_fused = max(p_meta, p_text * 0.90) if (not sig.sender_domain and not sig.extracted_urls and p_text >= 0.70) else p_meta
    else:
        p_fused = p_text

    # Corroborate verifiable phishing, spoofing, BEC, and malicious-link cues.
    if sig.flagged_urls:
        p_fused = max(p_fused, min(0.99, sig.max_url_risk * 0.96))
    if sig.has_anchor_href_mismatch:
        p_fused = max(p_fused, 0.88)
    if sig.sender_brand_domain_spoof:
        p_fused = max(p_fused, 0.86)
    if sig.display_name_spoof and (
        sig.has_credential_harvest
        or sig.has_urgency_threat
        or sig.flagged_urls
        or sig.has_remote_support_scam
        or sig.sender_digit_run
        or sig.sender_is_freemail
        or sig.sender_suspicious_tld
    ):
        p_fused = max(p_fused, 0.85)
    if sig.has_credential_harvest and (
        sig.sender_suspicious_tld
        or sig.sender_is_freemail
        or sig.flagged_urls
        or sig.has_urgency_threat
        or (sig.extracted_urls and not sig.links_match_sender_domain)
    ):
        p_fused = max(p_fused, 0.84)
    if sig.has_bec_giftcard or sig.has_remote_support_scam:
        p_fused = max(p_fused, 0.84)
    if sig.has_advance_fee_lure and not sig.links_match_sender_domain:
        p_fused = max(p_fused, 0.84)
    if sig.auth_failed:
        if sig.has_credential_harvest or sig.has_urgency_threat or sig.flagged_urls or sig.reply_to_mismatch:
            p_fused = max(p_fused, 0.84)
        else:
            p_fused = max(p_fused, 0.55)

    has_any_threat_signal = bool(
        sig.flagged_urls
        or sig.has_anchor_href_mismatch
        or sig.sender_brand_domain_spoof
        or sig.display_name_spoof
        or sig.sender_suspicious_tld
        or sig.has_credential_harvest
        or sig.has_bec_giftcard
        or sig.has_remote_support_scam
        or sig.has_advance_fee_lure
        or sig.auth_failed
        or sig.reply_to_mismatch
    )

    # Reduce false positives on genuine transactional alerts, OTPs, and opt-in marketing
    # only when zero verifiable phishing or spoofing cues exist.
    if not has_any_threat_signal:
        if sig.links_match_sender_domain or sig.auth_passed or sig.has_otp_disclaimer:
            p_fused = min(p_fused, 0.22)
        elif (sig.has_legit_transactional or sig.has_unsubscribe_marketing) and not sig.has_urgency_threat:
            p_fused = min(p_fused, 0.25)
        elif sig.sender_registrable_domain in TRUSTED_EMAIL_DOMAINS:
            p_fused = min(p_fused, 0.22)
        elif p_text < 0.78:
            p_fused = min(p_fused, 0.42)

    p_fused = max(0.0, min(0.99, p_fused))

    if p_fused >= 0.72:
        scam_level = "scam"
    elif p_fused >= 0.45:
        scam_level = "suspicious"
    else:
        scam_level = "safe"

    reasons: List[str] = []
    if sig.flagged_urls:
        reasons.append(f"Contains suspicious/malicious link ({', '.join(sig.flagged_urls[:2])})")
    if sig.has_anchor_href_mismatch:
        reasons.append("HTML link text displays a different domain than the actual destination URL")
    if sig.sender_brand_domain_spoof:
        reasons.append(f"Sender domain ({sig.sender_domain}) mimics or spoofs a trusted brand")
    if sig.display_name_spoof:
        reasons.append("Sender display name impersonates an organization from an unverified domain")
    if sig.sender_suspicious_tld and scam_level != "safe":
        reasons.append(f"Sender uses a high-abuse domain extension ({sig.sender_domain})")
    if sig.has_credential_harvest:
        reasons.append("Requests sensitive password, PIN, OTP, or financial card details")
    if sig.has_bec_giftcard:
        reasons.append("Matches executive impersonation / gift-card fraud patterns")
    if sig.has_remote_support_scam:
        reasons.append("Matches fake refund / remote-support desk scam patterns")
    if sig.has_advance_fee_lure and not sig.links_match_sender_domain:
        reasons.append("Contains lottery, inheritance, or advance-fee giveaway wording")
    if sig.auth_failed:
        reasons.append("Email authentication check (SPF/DKIM/DMARC) failed")
    if sig.reply_to_mismatch:
        reasons.append("Reply-To points to a freemail address different from the sender domain")

    if scam_level == "safe":
        if sig.links_match_sender_domain:
            reasons.append(f"Embedded URLs verified on sender domain ({sig.sender_registrable_domain})")
        if sig.has_legit_transactional:
            reasons.append("Legitimate transactional/account notification context with no spoofing cues")
        elif sig.has_unsubscribe_marketing:
            reasons.append("Standard opt-in newsletter or promotional email with no phishing cues")
        if not reasons:
            reasons.append("Calibrated email content and sender checks appear legitimate")
    elif not reasons:
        reasons.append("Calibrated email classifier flagged elevated phishing/spam probability")

    confidence = round(p_fused * 100.0, 2)
    if scam_level == "scam":
        if sig.flagged_urls or sig.has_anchor_href_mismatch:
            explanation = (
                "This email is dangerous. It contains deceptive or fake links trying to direct you to an untrusted website "
                "to steal your passwords or payment info. What to do: Do not click any links or download attachments. Delete this email."
            )
        elif sig.has_credential_harvest:
            explanation = (
                "This email is attempting to steal your private credentials (like your password, PIN, or payment details). "
                "Legitimate organizations will never ask you to send these via email. What to do: Do not reply or provide any personal information."
            )
        elif sig.sender_brand_domain_spoof or sig.display_name_spoof:
            explanation = (
                f"This email pretends to be from a trusted organization, but the sender address ({sig.sender_domain}) is fake or unverified. "
                "What to do: Do not trust this message. Contact the organization directly through their official app or website."
            )
        elif sig.has_bec_giftcard or sig.has_advance_fee_lure:
            explanation = (
                "This message shows classic fraud tricks—such as claiming you won a prize, inheritance, or urgently asking for gift cards or fees. "
                "What to do: Do not send any money, cards, or personal details. Delete this email immediately."
            )
        else:
            explanation = (
                "This email has been flagged as a dangerous scam due to strong phishing and deception patterns in the text. "
                "What to do: Do not click links, open attachments, or reply."
            )
    elif scam_level == "suspicious":
        explanation = (
            "Be cautious with this email. It shows warning signs—such as unusual sender details or unverified links—that don't match typical safe messages. "
            "What to do: Double-check the sender carefully and do not click links or enter passwords unless you are certain who sent it."
        )
    else:
        if sig.has_legit_transactional:
            explanation = (
                "This email appears to be a legitimate notification, receipt, or service update. The sender identity and embedded links match normal safe communication."
            )
        elif sig.has_unsubscribe_marketing:
            explanation = (
                "This email looks like a standard newsletter or promotional message. It contains standard unsubscribe options and shows no signs of phishing or malware."
            )
        else:
            explanation = (
                "This email appears safe and normal. No fake links, urgent threats, or suspicious sender addresses were detected."
            )

    return {
        "detection_type": "email",
        "scam_level": scam_level,
        "confidence": confidence,
        "reasons": reasons,
        "explanation": explanation,
        "input_data": {"subject": subject, "sender": sender, "body": body[:200]}
    }

# ── SMS Detection ──────────────────────────────────────────
def detect_sms(sender_id: str, message: str) -> dict:
    """Analyze an SMS using sender context, embedded URL checks, and calibrated ML fusion."""
    if sms_model is None:
        return {"error": "SMS model not loaded"}

    sig = extract_sms_signals(sender_id, message, url_risk_fn=detect_url)
    p_text = float(sms_model.predict_proba([sig.model_input_text])[0][1])

    if isinstance(sms_meta_model, dict) and sms_meta_model.get("meta_clf") is not None:
        X_meta = np.array([sig.to_meta_vector(p_text)], dtype=float)
        p_meta = float(sms_meta_model["meta_clf"].predict_proba(X_meta)[0][1])
        # Never let neutral metadata suppress strong calibrated text probabilities
        # unless an explicit verified benign context guard applies below.
        p_fused = max(p_meta, p_text * 0.90) if p_text >= 0.65 else p_meta
    else:
        p_fused = p_text

    # Corroborate verifiable smishing/social-engineering cues and dampen verified benign patterns.
    if sig.flagged_urls:
        p_fused = max(p_fused, min(0.99, sig.max_url_risk * 0.96))
    if sig.asks_for_secret and not sig.has_otp_disclaimer:
        p_fused = max(p_fused, 0.80)
    if sig.has_job_loan_bait:
        p_fused = max(p_fused, 0.78)
    if sig.has_payment_fee_ask and (sig.flagged_urls or sig.sender_is_mobile or sig.has_urgency_suspension):
        p_fused = max(p_fused, 0.78)
    if sig.has_prize_claim and (sig.flagged_urls or sig.sender_is_mobile or sig.sender_is_premium_num or sig.has_payment_fee_ask):
        p_fused = max(p_fused, 0.78)
    if sig.sender_is_mobile and sig.has_urgency_suspension and (sig.flagged_urls or sig.asks_for_secret or sig.has_payment_fee_ask):
        p_fused = max(p_fused, 0.82)

    is_registered_sender = sig.sender_is_alpha or sig.sender_is_shortcode
    if sig.has_otp_disclaimer and not sig.asks_for_secret and not sig.flagged_urls and not sig.has_payment_fee_ask:
        p_fused = min(p_fused, 0.18)
    elif (
        sig.has_legit_transactional
        and not sig.flagged_urls
        and not sig.asks_for_secret
        and not sig.has_payment_fee_ask
        and not sig.has_prize_claim
        and not sig.has_job_loan_bait
        and p_text < 0.75
    ):
        p_fused = min(p_fused, 0.22)
    elif (
        sig.extracted_urls
        and not sig.flagged_urls
        and sig.max_url_risk < 0.25
        and is_registered_sender
        and not sig.asks_for_secret
        and not sig.has_payment_fee_ask
        and not sig.has_prize_claim
        and not sig.has_job_loan_bait
        and not sig.has_urgency_suspension
    ):
        p_fused = min(p_fused, 0.28)
    elif (
        sig.has_opt_out
        and is_registered_sender
        and not sig.flagged_urls
        and not sig.asks_for_secret
        and not sig.has_payment_fee_ask
        and not sig.has_job_loan_bait
    ):
        p_fused = min(p_fused, 0.35)

    p_fused = max(0.0, min(0.99, p_fused))

    if p_fused >= 0.72:
        scam_level = "scam"
    elif p_fused >= 0.45:
        scam_level = "suspicious"
    else:
        scam_level = "safe"

    reasons: List[str] = []
    if sig.flagged_urls:
        reasons.append(f"Contains suspicious/malicious link ({', '.join(sig.flagged_urls[:2])})")
    if sig.asks_for_secret and not sig.has_otp_disclaimer:
        reasons.append("Asks recipient to share, reply, or forward an OTP, PIN, or card credentials")
    if sig.has_payment_fee_ask and (sig.flagged_urls or sig.sender_is_mobile or sig.has_urgency_suspension):
        reasons.append("Requests urgent customs, toll, or verification fee payment")
    if sig.has_prize_claim and (sig.flagged_urls or sig.sender_is_mobile or sig.sender_is_premium_num or sig.has_payment_fee_ask):
        reasons.append("Uses lottery, prize, or cash-reward claim wording")
    if sig.has_job_loan_bait:
        reasons.append("Matches task-job or instant-loan scam patterns")
    if sig.sender_is_mobile and (sig.has_urgency_suspension or sig.flagged_urls or sig.asks_for_secret):
        reasons.append("Urgent account or verification alert sent from a mobile number")

    if scam_level == "safe":
        if sig.has_otp_disclaimer:
            reasons.append("Legitimate verification alert advising not to share the code")
        if sig.has_opt_out:
            reasons.append("Standard service/promotional notification with opt-out instructions")
        if sig.extracted_urls and not sig.flagged_urls:
            reasons.append("Embedded URL passed domain & phishing checks")
        if not reasons:
            reasons.append("Calibrated SMS text and sender context appear legitimate")
    elif not reasons:
        reasons.append("Calibrated SMS language classifier flagged elevated scam risk")

    confidence = round(p_fused * 100.0, 2)
    sender_kind = (
        "alphanumeric brand ID"
        if sig.sender_is_alpha
        else "premium number"
        if sig.sender_is_premium_num
        else "carrier/brand shortcode"
        if sig.sender_is_shortcode
        else "mobile/numeric"
    )

    if scam_level == "scam":
        if sig.flagged_urls or (sig.extracted_urls and sig.has_urgency_suspension):
            explanation = (
                "This text is a fake alert (smishing scam). The sender is using fake urgency (like a missed package delivery or account lock) "
                "to trick you into opening a dangerous link that steals personal information or payment cards. "
                "What to do: Do not tap the link. Delete this message."
            )
        elif sig.has_prize_claim:
            explanation = (
                "This is a lottery or prize scam. Scammers send fake notifications claiming you won money to trick you into sharing bank details "
                "or paying fake release fees. What to do: Never send personal details or money. Block this number."
            )
        elif sig.has_job_loan_bait:
            explanation = (
                "This is an employment or fast-cash scam offering unrealistic daily pay to lure you into chatting on WhatsApp or paying upfront fees. "
                "What to do: Do not reply or click any links."
            )
        elif sig.asks_for_secret:
            explanation = (
                "This message is attempting to steal your private security code (OTP) or password. Real companies will never ask you to text your code. "
                "What to do: Never share verification codes with anyone."
            )
        else:
            explanation = (
                "This message shows strong smishing patterns designed to trick you. "
                "What to do: Do not click any links or share private codes."
            )
    elif scam_level == "suspicious":
        explanation = (
            f"This text looks suspicious. It was sent from a {sender_kind} ({sender_id}) with high-pressure wording or an unverified link. "
            "What to do: Do not click links or share information unless you independently verify with the company first."
        )
    else:
        if sig.sender_is_shortcode:
            explanation = (
                f"This message was sent from an official carrier/brand shortcode ({sender_id}). It appears to be a routine security code or service update "
                "with standard safety notices and no suspicious links."
            )
        elif sig.sender_is_alpha:
            explanation = (
                f"This message was sent from an official registered sender name ({sender_id}). It contains routine service information with no signs of phishing or fake links."
            )
        else:
            explanation = (
                "This message appears safe. It does not contain deceptive links, urgent threats, or requests for private information."
            )

    return {
        "detection_type": "sms",
        "scam_level": scam_level,
        "confidence": confidence,
        "reasons": reasons,
        "explanation": explanation,
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
    """Analyze a URL using scheme-invariant lexical + structural ML and verified spoofing signals."""
    info = parse_canonical_url(url)
    reasons: List[str] = []

    # Recognize local development / loopback hosts as safe internal environments
    is_loopback = False
    try:
        ip_obj = ipaddress.ip_address(info.host)
        is_loopback = ip_obj.is_loopback
    except ValueError:
        is_loopback = info.host in ("localhost", "0.0.0.0", "::1") or info.host.endswith(".localhost")

    if is_loopback:
        return {
            "detection_type": "url",
            "url": url,
            "scam_level": "safe",
            "confidence": 0.0,
            "reasons": ["Local development / loopback host (localhost or 127.0.0.1)"],
            "explanation": "This address points to your local machine (localhost / 127.0.0.1). It is an internal development environment and is safe from external phishing.",
        }

    is_trusted_domain = (
        info.registrable_domain in TRUSTED_DOMAINS
        and not info.has_userinfo_at
        and not info.is_ip_host
    )

    p_ml = 0.0
    p_host = 0.0
    p_path = 0.0
    ml_available = False
    if url_model is not None:
        try:
            scored = predict_url_bundle(url_model, [url])[0]
            p_ml = scored["prob"]
            p_host = scored["p_host"]
            p_path = scored["p_path"]
            ml_available = True
        except Exception as exc:
            print(f"URL ML Prediction Error: {exc}")

    # Collect verifiable domain/authority security signals (avoiding path-keyword traps).
    verified_floor = 0.0
    additive_nudge = 0.0
    has_host_risk_cue = False

    if info.has_userinfo_at:
        verified_floor = max(verified_floor, 0.85)
        has_host_risk_cue = True
        reasons.append("URL uses '@' credential syntax to mask the true destination domain")

    if info.is_ip_host:
        ip_floor = 0.80 if (info.auth_path_hits or info.has_executable_ext or info.has_nonstandard_port) else 0.58
        verified_floor = max(verified_floor, ip_floor)
        has_host_risk_cue = True
        reasons.append("Uses raw IP address instead of a registered domain name")

    if info.brand_typosquat_hits:
        verified_floor = max(verified_floor, 0.86)
        has_host_risk_cue = True
        reasons.append(
            f"Domain mimics trusted brand ({', '.join(info.brand_typosquat_hits)}) via lookalike spelling"
        )

    if info.brand_subdomain_hits:
        verified_floor = max(verified_floor, 0.85)
        has_host_risk_cue = True
        reasons.append(
            f"Brand name ({', '.join(info.brand_subdomain_hits)}) spoofed in subdomain of '{info.registrable_domain}'"
        )

    if info.brand_squat_hits:
        squat_floor = 0.86 if (info.suspicious_tld or info.auth_domain_hits or info.auth_path_hits) else 0.78
        verified_floor = max(verified_floor, squat_floor)
        has_host_risk_cue = True
        reasons.append(
            f"Domain combines brand keyword ({', '.join(info.brand_squat_hits)}) with deceptive terms"
        )

    if info.is_punycode:
        verified_floor = max(verified_floor, 0.55)
        has_host_risk_cue = True
        reasons.append("Uses internationalized punycode ('xn--') domain encoding")

    if info.has_executable_ext:
        verified_floor = max(verified_floor, 0.78)
        has_host_risk_cue = True
        reasons.append("Direct link to an executable or binary payload")

    if info.has_phishing_kit_path:
        has_host_risk_cue = True
        additive_nudge += 0.14
        reasons.append("Path matches automated phishing-kit directory patterns")

    if info.suspicious_tld:
        has_host_risk_cue = True
        additive_nudge += 0.12
        if info.auth_domain_hits or info.auth_path_hits:
            verified_floor = max(verified_floor, 0.52)
        reasons.append(f"Uses a high-abuse top-level domain (.{info.suffix})")

    if info.has_nonstandard_port:
        has_host_risk_cue = True
        additive_nudge += 0.10
        reasons.append("Specifies a non-standard network port")

    if info.subdomain_depth >= 3 or (info.domain_label_entropy >= 3.80 and len(info.domain_label) >= 12):
        if not is_trusted_domain and not info.trusted_suffix:
            has_host_risk_cue = True
            additive_nudge += 0.10
            reasons.append("Deep subdomain nesting or high-randomness domain string")

    if info.auth_domain_hits and not is_trusted_domain and info.subdomain_depth == 0:
        # Terms like login/verify inside the registrable domain itself (e.g. login-verify-portal.com).
        if not info.trusted_suffix and "-" in info.domain_label:
            has_host_risk_cue = True
            additive_nudge += 0.08

    if info.is_shortener:
        additive_nudge += 0.12
        reasons.append(f"Uses URL shortener ({info.registrable_domain}) hiding the final destination")

    # Optional benign-trained IsolationForest novelty check (advisory only).
    is_anomalous_structure = False
    if anomaly_model is not None and not is_trusted_domain:
        try:
            iso_pred = int(anomaly_model.predict([list(info.features)])[0])
            is_anomalous_structure = iso_pred == -1
        except Exception:
            is_anomalous_structure = False

    if is_anomalous_structure and has_host_risk_cue:
        additive_nudge += 0.05
        reasons.append("Structural anomaly detector flagged unusual domain/URL structure")

    fused = min(0.99, p_ml + additive_nudge) if ml_available else min(0.99, additive_nudge)
    fused = max(fused, verified_floor)

    # Guard against path-only false positives when the host itself looks benign.
    if (
        ml_available
        and not has_host_risk_cue
        and not info.has_phishing_kit_path
        and p_host < 0.78
    ):
        fused = min(fused, max(0.32, p_host * 0.45))
    elif (
        ml_available
        and info.suspicious_tld
        and verified_floor == 0.0
        and not info.has_phishing_kit_path
        and not info.has_nonstandard_port
        and not info.is_shortener
        and not info.auth_domain_hits
        and not info.auth_path_hits
        and not info.brand_path_hits
        and info.subdomain_depth < 3
        and info.domain_label_entropy < 3.80
        and "-" not in info.host
        and not any(ch.isdigit() for ch in info.host)
        and p_host < 0.78
        and p_path < 0.55
    ):
        # A clean domain/path whose sole risk indicator is a high-abuse gTLD warrants caution ('suspicious'), not 99% scam.
        fused = min(fused, max(0.54, min(0.64, p_host * 0.90 + 0.08)))

    if is_trusted_domain:
        fused = min(fused, 0.12)
        reasons.append(f"Domain matches trusted provider ({info.registrable_domain})")
    elif info.trusted_suffix and not has_host_risk_cue:
        fused = min(fused, 0.25)
        reasons.append(f"Institutional domain extension (.{info.suffix}) with no spoofing cues")

    if not info.scheme_is_https and info.scheme == "http":
        if fused >= 0.45 or info.auth_path_hits:
            reasons.append("Uses unencrypted HTTP rather than HTTPS")

    if fused >= 0.72:
        scam_level = "scam"
    elif fused >= 0.45:
        scam_level = "suspicious"
    else:
        scam_level = "safe"

    if ml_available:
        if p_ml >= 0.70 and "AI URL model" not in " ".join(reasons):
            reasons.append(f"Calibrated ML model scored host/URL patterns high risk ({p_ml*100:.1f}%)")
        elif scam_level == "safe" and not reasons:
            reasons.append("Calibrated ML model and domain checks indicate a benign URL")

    if not reasons:
        reasons.append("URL structure appears legitimate with no spoofing indicators")

    confidence = round(float(fused) * 100.0, 2)
    domain_display = info.registrable_domain or info.host
    brand_hits = info.brand_typosquat_hits or info.brand_subdomain_hits or info.brand_squat_hits or info.brand_path_hits
    brand_name = brand_hits[0].title() if brand_hits else None

    if scam_level == "scam":
        if brand_name:
            explanation = (
                f"This website is dangerous. It pretends to be '{brand_name}', but the actual link leads to an untrusted domain ('{domain_display}'). "
                "It is designed to steal your passwords or payment details. What to do: Do not visit this site or enter any personal information."
            )
        elif info.is_ip_host:
            explanation = (
                "This web address points directly to a raw numerical IP address instead of a recognized website name. "
                "Scammers use this technique to hide deceptive phishing pages. What to do: Do not open this link."
            )
        else:
            explanation = (
                f"This website address ('{domain_display}') has been flagged as a dangerous scam or phishing site. "
                "Opening it could expose you to identity theft or malicious downloads. What to do: Do not open this link."
            )
    elif scam_level == "suspicious":
        if not info.scheme_is_https:
            explanation = (
                f"Proceed with caution. The website '{domain_display}' does not use secure encryption (HTTPS), meaning any passwords or information you enter could be intercepted. "
                "What to do: Never enter passwords or card numbers on an unencrypted website."
            )
        else:
            explanation = (
                f"Proceed with caution. This website address ('{domain_display}') has unusual patterns or an unfamiliar domain ending. "
                "What to do: Double-check that this is the exact website you intended to visit before logging in."
            )
    else:
        if domain_display in TRUSTED_DOMAINS:
            explanation = (
                f"This web address is safe. It belongs to the official verified website of '{domain_display}' and uses secure encryption."
            )
        else:
            explanation = (
                f"This website address ('{domain_display}') appears legitimate and safe. It uses standard secure protocols with no signs of spoofing or phishing."
            )

    return {
        "detection_type": "url",
        "scam_level": scam_level,
        "confidence": confidence,
        "reasons": reasons,
        "explanation": explanation,
        "input_data": {"url": url.lower().strip()}
    }