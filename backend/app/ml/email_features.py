"""Shared email parsing, sender-impersonation checks, link inspection, and text cleaning.

Used identically by ``retrain_email.py`` and ``app.ml.predictor.detect_email``
to eliminate 2000s corpus-artifact drift and unify ML + contextual signals.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from app.ml.url_features import parse_canonical_url

URL_IN_EMAIL_RE = re.compile(
    r"(?:https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
    re.IGNORECASE,
)
HTML_HREF_RE = re.compile(
    r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", re.IGNORECASE)

FREEMAIL_DOMAINS: Set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "aol.com", "icloud.com", "mail.com", "proton.me", "protonmail.com",
    "yandex.com", "zoho.com",
}

PROTECTED_EMAIL_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.co.uk", "paypal.me"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googlemail.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com", "amzn.com"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com", "jpmorgan.com", "jpmorganchase.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "wells fargo": {"wellsfargo.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "facebook": {"facebook.com", "meta.com", "fb.com"},
    "meta": {"meta.com", "facebook.com", "instagram.com", "whatsapp.com"},
    "geeksquad": {"bestbuy.com", "geeksquad.com"},
    "geek squad": {"bestbuy.com", "geeksquad.com"},
    "nayapay": {"nayapay.com"},
    "jazzcash": {"jazzcash.com.pk", "jazz.com.pk"},
    "github": {"github.com"},
    "stripe": {"stripe.com"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
}

EMAIL_META_FEATURE_NAMES: List[str] = [
    "p_text_ml",
    "sender_suspicious_tld",
    "sender_brand_domain_spoof",
    "display_name_spoof",
    "sender_digit_run",
    "reply_to_mismatch",
    "auth_failed",
    "auth_passed",
    "max_url_risk",
    "has_flagged_url",
    "has_anchor_href_mismatch",
    "links_match_sender_domain",
    "has_credential_harvest",
    "has_urgency_threat",
    "has_advance_fee_lure",
    "has_bec_giftcard",
    "has_remote_support_scam",
    "has_unsubscribe_marketing",
    "has_legit_transactional",
    "has_otp_disclaimer",
]


@dataclass(frozen=True)
class EmailSignalInfo:
    """Structured context extracted from email headers, links, and body."""

    subject: str
    sender: str
    body: str
    display_name: str
    sender_email: str
    sender_domain: str
    sender_registrable_domain: str
    sender_is_freemail: bool
    sender_suspicious_tld: bool
    sender_brand_domain_spoof: bool
    display_name_spoof: bool
    sender_digit_run: bool
    reply_to_mismatch: bool
    auth_failed: bool
    auth_passed: bool
    extracted_urls: Tuple[str, ...]
    max_url_risk: float
    flagged_urls: Tuple[str, ...]
    has_anchor_href_mismatch: bool
    links_match_sender_domain: bool
    has_credential_harvest: bool
    has_urgency_threat: bool
    has_advance_fee_lure: bool
    has_bec_giftcard: bool
    has_remote_support_scam: bool
    has_unsubscribe_marketing: bool
    has_legit_transactional: bool
    has_otp_disclaimer: bool
    cleaned_model_text: str

    def to_meta_vector(self, p_text_ml: float) -> List[float]:
        """Build numeric meta-vector aligned with EMAIL_META_FEATURE_NAMES."""
        return [
            float(p_text_ml),
            float(int(self.sender_suspicious_tld)),
            float(int(self.sender_brand_domain_spoof)),
            float(int(self.display_name_spoof)),
            float(int(self.sender_digit_run)),
            float(int(self.reply_to_mismatch)),
            float(int(self.auth_failed)),
            float(int(self.auth_passed)),
            float(self.max_url_risk),
            float(int(bool(self.flagged_urls))),
            float(int(self.has_anchor_href_mismatch)),
            float(int(self.links_match_sender_domain)),
            float(int(self.has_credential_harvest)),
            float(int(self.has_urgency_threat)),
            float(int(self.has_advance_fee_lure)),
            float(int(self.has_bec_giftcard)),
            float(int(self.has_remote_support_scam)),
            float(int(self.has_unsubscribe_marketing)),
            float(int(self.has_legit_transactional)),
            float(int(self.has_otp_disclaimer)),
        ]


def clean_email_text_for_model(subject: str, body: str) -> str:
    """Normalize text identically across corpus training and live emails.

    Strips raw HTML tags, raw email addresses, exact URLs, and 4-digit years
    so classifiers learn language intent rather than 2000s dataset artifacts.
    """
    raw = f"{subject or ''} {body or ''}"
    raw = html.unescape(raw)
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = URL_IN_EMAIL_RE.sub(" __url__ ", raw)
    raw = re.sub(r"\bhttps?\b", " __url__ ", raw, flags=re.IGNORECASE)
    raw = re.sub(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", " __email__ ", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\b(?:19|20)\d{2}\b", " __year__ ", raw)
    raw = re.sub(r"\b\d{4,}\b", " __num__ ", raw)
    # Neutralize legacy corpus markers if present in older texts.
    raw = re.sub(r"josemonkeyorg|monkeyorg|enron\s+com", " ", raw, flags=re.IGNORECASE)
    raw = re.sub(r"[^a-z0-9\s_%$£]", " ", raw.lower())
    return re.sub(r"\s+", " ", raw).strip()


def parse_email_sender(sender: str) -> Tuple[str, str, str, str]:
    """Return (display_name, email_addr, sender_domain, registrable_domain)."""
    raw = str(sender or "").strip()
    addr_match = re.search(r"([\w.+-]+@([\w.-]+\.[a-z]{2,}))", raw, re.IGNORECASE)
    if addr_match:
        email_addr = addr_match.group(1).lower()
        sender_domain = addr_match.group(2).lower()
        display_name = raw[:addr_match.start()].replace('"', "").replace("<", "").strip().lower()
    else:
        email_addr = ""
        sender_domain = ""
        display_name = raw.lower()

    if sender_domain:
        reg_domain = parse_canonical_url(f"http://{sender_domain}").registrable_domain
    else:
        reg_domain = ""

    return display_name, email_addr, sender_domain, reg_domain


def extract_email_links(
    subject: str,
    body: str,
    extra_html_links: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[List[str], bool]:
    """Extract unique URLs from text + HTML hrefs and flag deceptive anchor text."""
    seen: Set[str] = set()
    urls: List[str] = []
    anchor_mismatch = False

    def _add(url_str: str) -> None:
        cleaned = str(url_str or "").strip().rstrip(".,;:!?)\"'")
        if cleaned and cleaned.lower().startswith(("http://", "https://", "www.")) and cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)

    for href, anchor_html in HTML_HREF_RE.findall(body or ""):
        _add(href)
        anchor_text = re.sub(r"<[^>]+>", "", anchor_html or "").strip().lower()
        if re.match(r"^https?://", anchor_text):
            href_dom = parse_canonical_url(href).registrable_domain
            anch_dom = parse_canonical_url(anchor_text).registrable_domain
            if href_dom and anch_dom and href_dom != anch_dom:
                anchor_mismatch = True

    if extra_html_links:
        for href, anchor_text in extra_html_links:
            _add(href)
            a_low = str(anchor_text or "").strip().lower()
            if re.match(r"^https?://", a_low):
                href_dom = parse_canonical_url(href).registrable_domain
                anch_dom = parse_canonical_url(a_low).registrable_domain
                if href_dom and anch_dom and href_dom != anch_dom:
                    anchor_mismatch = True

    plain_text = re.sub(r"<[^>]+>", " ", f"{subject or ''} {body or ''}")
    for m in URL_IN_EMAIL_RE.findall(plain_text):
        _add(m)

    return urls[:8], anchor_mismatch


def extract_email_signals(
    subject: str,
    sender: str,
    body: str,
    url_risk_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> EmailSignalInfo:
    """Extract full contextual, sender, link, and behavioral email signals."""
    subj = str(subject or "").strip()
    sndr = str(sender or "").strip()
    bdy = str(body or "").strip()
    meta = metadata or {}

    display_name, email_addr, sender_domain, reg_domain = parse_email_sender(sndr)
    sender_is_freemail = reg_domain in FREEMAIL_DOMAINS

    sender_parsed = parse_canonical_url(f"http://{sender_domain}") if sender_domain else None
    sender_suspicious_tld = bool(sender_parsed and sender_parsed.suspicious_tld)
    sender_brand_domain_spoof = bool(
        sender_parsed
        and (
            sender_parsed.brand_subdomain_hits
            or sender_parsed.brand_squat_hits
            or sender_parsed.brand_typosquat_hits
        )
    )

    display_name_spoof = False
    if display_name and reg_domain:
        for brand, official_domains in PROTECTED_EMAIL_BRANDS.items():
            if brand in display_name and reg_domain not in official_domains:
                display_name_spoof = True
                break
        if not display_name_spoof and (sender_is_freemail or sender_suspicious_tld):
            if re.search(
                r"\b(?:fraud desk|security team|billing|tax refund|payroll|support|director|prize claims|copyright desk|bank verification)\b",
                display_name,
            ):
                display_name_spoof = True

    local_part = email_addr.split("@", 1)[0] if "@" in email_addr else ""
    sender_digit_run = bool(re.search(r"\d{5,}", local_part))

    reply_to = str(meta.get("reply_to") or "").strip()
    reply_to_mismatch = False
    if reply_to and reg_domain:
        _, _, _, reply_reg = parse_email_sender(reply_to)
        if reply_reg and reply_reg != reg_domain and reply_reg in FREEMAIL_DOMAINS:
            reply_to_mismatch = True

    auth_str = str(meta.get("authentication_results") or "").lower()
    auth_failed = bool(re.search(r"(?:spf|dkim|dmarc)=(?:fail|softfail|temperror)", auth_str))
    auth_passed = bool("dkim=pass" in auth_str or ("spf=pass" in auth_str and not auth_failed))

    urls, anchor_mismatch = extract_email_links(subj, bdy, meta.get("html_links"))
    max_url_risk = 0.0
    flagged_urls: List[str] = []
    link_domains: List[str] = []

    for u in urls:
        pu = parse_canonical_url(u)
        if pu.registrable_domain:
            link_domains.append(pu.registrable_domain)
        if url_risk_fn is not None:
            res = url_risk_fn(u)
            risk = float(res.get("confidence", 0.0)) / 100.0
            max_url_risk = max(max_url_risk, risk)
            if res.get("scam_level") in {"suspicious", "scam"}:
                flagged_urls.append(u)
        else:
            heur = 0.0
            if pu.suspicious_tld:
                heur = max(heur, 0.72)
            if pu.brand_subdomain_hits or pu.brand_squat_hits or pu.brand_typosquat_hits:
                heur = max(heur, 0.88)
            if pu.is_ip_host or pu.has_userinfo_at:
                heur = max(heur, 0.85)
            max_url_risk = max(max_url_risk, heur)
            if heur >= 0.45:
                flagged_urls.append(u)

    links_match_sender_domain = bool(
        reg_domain
        and link_domains
        and not flagged_urls
        and max_url_risk < 0.35
        and all(ld == reg_domain for ld in link_domains)
    )

    combined_plain = re.sub(r"<[^>]+>", " ", f"{subj} {bdy}").lower()

    has_credential_harvest = bool(
        re.search(
            r"(?:"
            r"(?:enter|submit|confirm|verify|reply with|send|authenticate with)\b[^.\n]{0,45}\b(?:debit card|credit card|card pin|card security code|card details|ssn|social security|routing number|2fa code|otp|seed phrase|metamask|bank details|corporate email password|your\s+(?:account\s+)?password)"
            r"|verify your identity\b[^.\n]{0,40}\b(?:24 hours|12 hours|hours|frozen|restricted)"
            r"|confirm your identity and password"
            r"|update your debit card pin"
            r"|update payment details immediately"
            r"|keep your current password and avoid mailbox lockout"
            r")",
            combined_plain,
        )
    )

    has_urgency_threat = bool(
        re.search(
            r"\b(?:temporarily limited|funds will be frozen|account has been suspended|account is locked|scheduled for deletion|mailbox lockout|access has been restricted|at risk of suspension|final warning|avoid suspension|within (?:12|24) hours|expires today)\b",
            combined_plain,
        )
    )

    has_advance_fee_lure = bool(
        re.search(
            r"\b(?:international sweepstakes|grand prize winner|randomly selected as|one time payment|processing fee|unclaimed estate|bitcoin giveaway|send [\d.]+\s*btc|wire transfer instructions|beneficiary)\b",
            combined_plain,
        )
    )

    has_bec_giftcard = bool(
        re.search(
            r"\b(?:buy \d+ .*gift cards|scratched pin codes|stuck in a board meeting|cannot take calls.*favor)\b",
            combined_plain,
        )
    )

    has_remote_support_scam = bool(
        re.search(
            r"\b(?:install remote support|remote desktop|cancellation desk immediately|claim your refund.*call)\b",
            combined_plain,
        )
    )

    has_unsubscribe_marketing = bool(
        re.search(
            r"(?:unsubscribe|manage[_ ]subscription[_ ]preferences|subscription preferences|manage email preferences|don't want to receive|do not want to receive|opt out|turn off group emails|terms apply|weekly .*digest|view online|email preferences|notification settings)",
            combined_plain,
        )
    )

    has_legit_transactional = bool(
        re.search(
            r"\b(?:available balance|monthly statement|automatic payment|cash on delivery|cash-on-delivery|has been dispatched|is out for delivery|thank you for your payment|thank you for using|for your records|posted to your account|payout of|has been initiated|was processed successfully|expected within \d+ business days)\b",
            combined_plain,
        )
    )

    has_otp_disclaimer = bool(
        re.search(
            r"\b(?:if this was not you|if this wasn't you|if you did not (?:request|authorize|make)|do not share|never share|never disclose|expires in \d+ minutes|ignore if already)\b",
            combined_plain,
        )
    )

    cleaned_model_text = clean_email_text_for_model(subj, bdy)

    return EmailSignalInfo(
        subject=subj,
        sender=sndr,
        body=bdy,
        display_name=display_name,
        sender_email=email_addr,
        sender_domain=sender_domain,
        sender_registrable_domain=reg_domain,
        sender_is_freemail=sender_is_freemail,
        sender_suspicious_tld=sender_suspicious_tld,
        sender_brand_domain_spoof=sender_brand_domain_spoof,
        display_name_spoof=display_name_spoof,
        sender_digit_run=sender_digit_run,
        reply_to_mismatch=reply_to_mismatch,
        auth_failed=auth_failed,
        auth_passed=auth_passed,
        extracted_urls=tuple(urls),
        max_url_risk=round(max_url_risk, 4),
        flagged_urls=tuple(flagged_urls),
        has_anchor_href_mismatch=anchor_mismatch,
        links_match_sender_domain=links_match_sender_domain,
        has_credential_harvest=has_credential_harvest,
        has_urgency_threat=has_urgency_threat,
        has_advance_fee_lure=has_advance_fee_lure,
        has_bec_giftcard=has_bec_giftcard,
        has_remote_support_scam=has_remote_support_scam,
        has_unsubscribe_marketing=has_unsubscribe_marketing,
        has_legit_transactional=has_legit_transactional,
        has_otp_disclaimer=has_otp_disclaimer,
        cleaned_model_text=cleaned_model_text,
    )


def explain_linear_text_pipeline(pipeline: Any, text: str, top_k: int = 5) -> Optional[str]:
    """Extract fast exact token contributions from a calibrated linear TF-IDF pipeline."""
    try:
        features = pipeline.named_steps["features"]
        clf = pipeline.named_steps["clf"]
        # CalibratedClassifierCV stores fitted calibrated_classifiers_ wrappers.
        cal_list = getattr(clf, "calibrated_classifiers_", None)
        if cal_list:
            coefs = sum(c.estimator.coef_[0] for c in cal_list) / len(cal_list)
        else:
            coefs = clf.coef_[0]
        feat_names = features.get_feature_names_out()
        vec = features.transform([text])
        indices = vec.nonzero()[1]
        if len(indices) == 0:
            return None
        scored = [
            (feat_names[i].split("__", 1)[-1], float(vec[0, i] * coefs[i]))
            for i in indices
        ]
        # Prefer readable word/word-bigram tokens over short char substrings when available.
        word_scored = [
            (tok, val) for tok, val in zip((feat_names[i] for i in indices), (float(vec[0, i] * coefs[i]) for i in indices))
            if tok.startswith("word__")
        ]
        items = word_scored if len(word_scored) >= 3 else scored
        cleaned_items = [
            (tok.replace("word__", "").replace("char__", ""), val)
            for tok, val in items
            if not tok.endswith(("__url__", "__email__", "__year__", "__num__"))
        ]
        cleaned_items.sort(key=lambda pair: abs(pair[1]), reverse=True)
        top = cleaned_items[:top_k]
        if not top:
            return None
        formatted = ", ".join(f"'{tok}' ({'+' if w > 0 else ''}{w:.3f})" for tok, w in top)
        return f"Key text factors: {formatted}"
    except Exception:
        return None

