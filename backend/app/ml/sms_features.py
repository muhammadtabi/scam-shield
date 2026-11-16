"""Shared SMS sender parsing, URL extraction, and behavioral signal extraction.

Used by both ``retrain_sms.py`` and ``app.ml.predictor.detect_sms`` so
training and live inference evaluate identical context features.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from app.ml.url_features import URL_SHORTENERS, parse_canonical_url

URL_IN_TEXT_RE = re.compile(
    r"(?:https?://[^\s<>\"']+|(?:www\.|(?:[a-z0-9-]+\.)+(?:com|net|org|edu|gov|pk|uk|ca|au|io|co|so|me|tk|ml|ga|cf|gq|xyz|top|win|click|cfd|ly|gl)/)[^\s<>\"']*)",
    re.IGNORECASE,
)

SMS_META_FEATURE_NAMES: List[str] = [
    "p_text_ml",
    "sender_is_alpha",
    "sender_is_mobile",
    "sender_is_premium_num",
    "url_count",
    "max_url_risk",
    "has_shortener_url",
    "has_otp_disclaimer",
    "asks_for_secret",
    "has_opt_out",
    "has_urgency_suspension",
    "has_payment_fee_ask",
    "has_prize_claim",
    "has_job_loan_bait",
    "has_legit_transactional",
    "has_callback_number",
    "upper_ratio",
    "exclam_count",
]


@dataclass(frozen=True)
class SmsSignalInfo:
    """Structured context extracted from SMS sender and message content."""

    sender_id: str
    sender_is_alpha: bool
    sender_is_mobile: bool
    sender_is_premium_num: bool
    extracted_urls: Tuple[str, ...]
    max_url_risk: float
    flagged_urls: Tuple[str, ...]
    has_shortener_url: bool
    has_otp_disclaimer: bool
    asks_for_secret: bool
    has_opt_out: bool
    has_urgency_suspension: bool
    has_payment_fee_ask: bool
    has_prize_claim: bool
    has_job_loan_bait: bool
    has_legit_transactional: bool
    has_callback_number: bool
    upper_ratio: float
    exclam_count: int
    model_input_text: str
    sender_is_shortcode: bool = False

    def to_meta_vector(self, p_text_ml: float) -> List[float]:
        """Build numeric feature vector aligned with SMS_META_FEATURE_NAMES."""
        return [
            float(p_text_ml),
            float(int(self.sender_is_alpha)),
            float(int(self.sender_is_mobile)),
            float(int(self.sender_is_premium_num)),
            float(len(self.extracted_urls)),
            float(self.max_url_risk),
            float(int(self.has_shortener_url)),
            float(int(self.has_otp_disclaimer)),
            float(int(self.asks_for_secret)),
            float(int(self.has_opt_out)),
            float(int(self.has_urgency_suspension)),
            float(int(self.has_payment_fee_ask)),
            float(int(self.has_prize_claim)),
            float(int(self.has_job_loan_bait)),
            float(int(self.has_legit_transactional)),
            float(int(self.has_callback_number)),
            float(self.upper_ratio),
            float(self.exclam_count),
        ]


def is_sms_shortcode(sender_id: str) -> bool:
    """Return True for 4-6 digit carrier/bank SMS shortcodes that are not premium-rate prefixes."""
    cleaned = re.sub(r"\s+", "", str(sender_id or ""))
    if not cleaned.isdigit() or not (4 <= len(cleaned) <= 6):
        return False
    return not re.match(r"^(?:090\d|087\d|084\d|070\d)", cleaned)


def classify_sms_sender(sender_id: str) -> Tuple[bool, bool, bool]:
    """Return (is_alpha, is_mobile, is_premium_num) for a validated SMS sender."""
    cleaned = re.sub(r"\s+", "", str(sender_id or ""))
    if re.search(r"[A-Za-z]", cleaned):
        return True, False, False
    digits = re.sub(r"\D", "", cleaned)
    # Premium-rate UK/international prefixes commonly seen in lottery/ringtone scams.
    is_premium = bool(re.match(r"^(?:090\d|087\d|084\d|070\d)", digits))
    is_shortcode = is_sms_shortcode(cleaned)
    is_mobile = bool(digits) and not is_premium and not is_shortcode
    return False, is_mobile, is_premium


def extract_urls_from_text(text: str) -> List[str]:
    """Extract cleaned candidate URLs from plain message text."""
    seen = set()
    urls: List[str] = []
    for match in URL_IN_TEXT_RE.findall(text or ""):
        u = match.rstrip(".,;:!?)\"'")
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def extract_sms_signals(
    sender_id: str,
    message: str,
    url_risk_fn: Optional[Callable[[str], Dict[str, object]]] = None,
) -> SmsSignalInfo:
    """Analyze SMS sender metadata, embedded links, and conversational/scam cues."""
    msg = str(message or "").strip()
    lower = msg.lower()
    is_alpha, is_mobile, is_premium = classify_sms_sender(sender_id)
    is_shortcode = is_sms_shortcode(sender_id)

    urls = extract_urls_from_text(msg)
    max_url_risk = 0.0
    flagged_urls: List[str] = []
    has_shortener = False

    for u in urls:
        parsed_u = parse_canonical_url(u)
        if parsed_u.is_shortener or parsed_u.registrable_domain in URL_SHORTENERS:
            has_shortener = True
        if url_risk_fn is not None:
            res = url_risk_fn(u)
            risk = float(res.get("confidence", 0.0)) / 100.0
            max_url_risk = max(max_url_risk, risk)
            if res.get("scam_level") in {"suspicious", "scam"}:
                flagged_urls.append(u)
        else:
            # Lightweight fallback scoring for offline dataset prep without circular import.
            heur = 0.0
            if parsed_u.suspicious_tld:
                heur = max(heur, 0.72)
            if parsed_u.brand_subdomain_hits or parsed_u.brand_squat_hits or parsed_u.brand_typosquat_hits:
                heur = max(heur, 0.88)
            if parsed_u.is_ip_host or parsed_u.has_userinfo_at:
                heur = max(heur, 0.85)
            if parsed_u.is_shortener:
                heur = max(heur, 0.55)
            max_url_risk = max(max_url_risk, heur)
            if heur >= 0.45:
                flagged_urls.append(u)

    has_otp_disclaimer = bool(
        re.search(
            r"\b(?:do not share|don't share|never share|never disclose|expires? in \d+|valid for \d+|if you did not request|was not you|wasn't you)\b",
            lower,
        )
    )

    asks_for_secret = bool(
        re.search(
            r"(?:"
            r"(?:reply|send|forward|share|provide|give)\b.{0,45}\b(?:otp|pin|mpin|passcode|password|verification code|6-digit code|cvv|debit card|credit card|cnic|bank details)"
            r"|(?:enter|submit|type)\b.{0,30}\b(?:your\s+)?(?:otp|mpin|atm pin|bank pin|passcode|password|cvv|debit card|credit card|cnic|bank details)"
            r"|(?:accidentally|mistakenly)\s+sent\b.{0,40}\b(?:code|otp)"
            r"|enter\s+(?:mpin|pin|card|otp)\s*(?:\+|and)\s*(?:otp|pin|mpin)"
            r")",
            lower,
        )
    )

    has_opt_out = bool(
        re.search(
            r"\b(?:reply stop|text stop|stop all|stop to opt out|stop to unsubscribe|to unsubscribe)\b",
            lower,
        )
    )

    has_urgency_suspension = bool(
        re.search(
            r"\b(?:suspended|will be blocked|account(?:\s+\w+){0,2}\s+blocked|restricted|deactivated|biometric verification expired|avoid return|avoid (?:license )?suspension|within \d+ hours|final reminder|unrecognized|unauthorized login|unauthorized transaction)\b",
            lower,
        )
    )

    has_payment_fee_ask = bool(
        re.search(
            r"\b(?:unpaid customs|customs fee|registration fee|processing fee|clearance fee|verification fee|shipping fee|unpaid (?:motorway )?toll|late penalty|pay immediately|deposit .{0,20}balance|pay \$?\d+)\b",
            lower,
        )
    )

    has_prize_claim = bool(
        re.search(
            r"\b(?:congratulations|mubarak|you(?:'ve| have)? won|lucky draw|selected for|qualified for|cash prize|cash reward|unclaimed cash|claim your|claim funds|gift card|(?:gift|shopping|prize|cash|free)\s+voucher|10 tola|weekly cash competition)\b",
            lower,
        )
    )

    has_job_loan_bait = bool(
        re.search(
            r"\b(?:part-time online job|earn (?:rs|pkr|\$|£)\s*[\d,]+.{0,20}daily|liking (?:youtube|tiktok|instagram) videos|zero documents|instant cash loan|download apk|wa\.me/)\b",
            lower,
        )
    )

    has_legit_transactional = bool(
        re.search(
            r"\b(?:received\s+(?:pkr|rs|inr|\$|£)\s*[\d,]+|sent\s+(?:pkr|rs|inr|\$|£)\s*[\d,]+|new\s+balance:?|account\s+balance:?|debited from|credited to|avail(?:able)? bal|monthly statement|minimum payment|recharge successful|trx\s+id:?|ref\s+id:?|transaction\s+id:?|out for delivery|arriving today|ready for pickup|pickup pin|has arrived|boarding starts|dental appointment|reschedule|order #?\w+ is|payout of|scheduled fiber maintenance|(?:subscription|membership|plan|pass)\s+renews|fee\s+(?:voucher|challan|deadline)|contact\s+(?:accounts|registrar|clinic)\s+office)\b",
            lower,
        )
    )

    has_callback_number = bool(
        re.search(r"(?:\+?\d[\d\s().-]{7,14}\d|\b0\d{9,10}\b)", msg)
    )

    alpha_chars = [c for c in msg if c.isalpha()]
    upper_ratio = round(sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars), 4) if alpha_chars else 0.0
    exclam_count = msg.count("!")

    cleaned_msg = msg
    for u in urls:
        pu = parse_canonical_url(u)
        repl = f" __url_susp_tld__ " if pu.suspicious_tld else f" __url_shortener__ " if pu.is_shortener else " __url_link__ "
        cleaned_msg = cleaned_msg.replace(u, repl)
    model_input_text = re.sub(r"\s+", " ", cleaned_msg).strip()

    return SmsSignalInfo(
        sender_id=str(sender_id or ""),
        sender_is_alpha=is_alpha,
        sender_is_mobile=is_mobile,
        sender_is_premium_num=is_premium,
        sender_is_shortcode=is_shortcode,
        extracted_urls=tuple(urls),
        max_url_risk=round(max_url_risk, 4),
        flagged_urls=tuple(flagged_urls),
        has_shortener_url=has_shortener,
        has_otp_disclaimer=has_otp_disclaimer,
        asks_for_secret=asks_for_secret,
        has_opt_out=has_opt_out,
        has_urgency_suspension=has_urgency_suspension,
        has_payment_fee_ask=has_payment_fee_ask,
        has_prize_claim=has_prize_claim,
        has_job_loan_bait=has_job_loan_bait,
        has_legit_transactional=has_legit_transactional,
        has_callback_number=has_callback_number,
        upper_ratio=upper_ratio,
        exclam_count=exclam_count,
        model_input_text=model_input_text,
    )
