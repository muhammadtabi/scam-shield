"""Shared URL canonicalization, structural feature extraction, and spoofing signals.

Used identically by both training (``retrain_url.py``) and inference
(``app.ml.predictor``) to prevent training-vs-serving feature skew.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
from urllib.parse import urlsplit

import tldextract

# Fully offline Public Suffix List lookup (never makes network requests).
_OFFLINE_TLD = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "win", "click",
    "cfd", "buzz", "work", "rest", "icu", "cam", "sbs", "cyou",
    "loan", "club", "vip", "online", "site", "website", "space",
}

TRUSTED_SUFFIXES: Set[str] = {
    "edu", "gov", "mil", "ac.uk", "gov.uk", "edu.pk", "gov.pk",
    "edu.au", "gov.au", "edu.in", "gov.in", "edu.cn", "edu.mx",
    "edu.br", "gov.br", "ac.jp", "ac.za",
}

URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "is.gd",
    "ow.ly", "cutt.ly", "shorturl.at", "q.gs", "adf.ly", "tiny.cc",
    "shorte.st", "wa.me",
}

STANDARD_FUNCTIONAL_SUBDOMAINS: Set[str] = {
    "login", "signin", "auth", "accounts", "account", "docs", "support",
    "help", "blog", "cloud", "portal", "lms", "mail", "app", "api",
    "dash", "status", "online", "id", "my", "shop", "store", "en",
    "track", "links", "link", "click", "clicks", "email", "emails",
    "e", "m", "em", "go", "url", "newsletter", "engage", "ship",
    "notify", "notifications", "updates", "send",
}

EXECUTABLE_EXTENSIONS: Tuple[str, ...] = (
    ".exe", ".apk", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".msi", ".sh", ".bin", ".elf", ".arm5", ".arm7",
)

AUTH_PATH_WORDS: Tuple[str, ...] = (
    "login", "signin", "verify", "secure", "account", "auth",
    "update", "confirm", "password", "wallet", "banking", "unlock",
    "billing", "clearance", "refund", "prize", "winner", "claim",
    "webscr", "cmd=", "cgi-bin",
)

TARGETED_BRANDS: Set[str] = {
    "paypal", "apple", "icloud", "google", "microsoft", "microsoftonline",
    "amazon", "netflix", "facebook", "instagram", "whatsapp", "chase",
    "bankofamerica", "wellsfargo", "citibank", "binance", "coinbase",
    "metamask", "docusign", "dropbox", "github", "adobe", "ebay",
    "stripe", "linkedin", "yahoo", "jazzcash", "easypaisa", "nayapay",
    "dhl", "fedex", "usps",
}

# Protected brand aliases that map subdomains/sub-brands back to canonical brand.
BRAND_DOMAIN_ALIASES: Dict[str, Set[str]] = {
    "apple": {"apple", "icloud", "itunes"},
    "icloud": {"icloud", "apple"},
    "google": {"google", "gmail", "youtube", "googleapis", "googleusercontent", "android"},
    "microsoft": {"microsoft", "microsoftonline", "office", "live", "outlook", "azure", "msn"},
    "microsoftonline": {"microsoftonline", "microsoft"},
    "facebook": {"facebook", "fb", "meta", "messenger", "instagram", "whatsapp"},
    "amazon": {"amazon", "aws", "amazonaws", "amzn"},
    "ebay": {"ebay"},
}

URL_FEATURE_NAMES: List[str] = [
    "host_len",
    "registrable_domain_len",
    "subdomain_len",
    "subdomain_depth",
    "host_dot_count",
    "host_hyphen_count",
    "host_digit_count",
    "host_digit_ratio",
    "host_entropy",
    "domain_label_entropy",
    "longest_host_label",
    "is_ip_host",
    "is_punycode",
    "has_userinfo_at",
    "has_nonstandard_port",
    "suspicious_tld",
    "trusted_suffix",
    "is_shortener",
    "path_len",
    "path_depth",
    "query_len",
    "query_param_count",
    "path_pct_count",
    "path_hyphen_count",
    "has_executable_ext",
    "brand_in_subdomain_not_domain",
    "brand_squat_in_domain",
    "brand_typosquat_in_domain",
    "has_phishing_kit_path",
    "has_long_hex_token",
    "auth_words_in_domain",
]


@dataclass(frozen=True)
class ParsedUrlInfo:
    """Canonical representation of a URL separated by authority and path."""

    raw_url: str
    scheme: str
    scheme_is_https: bool
    netloc: str
    host: str
    subdomain: str
    domain_label: str
    suffix: str
    registrable_domain: str
    path: str
    query: str
    canonical_host_text: str
    canonical_path_text: str
    has_userinfo_at: bool
    has_nonstandard_port: bool
    is_ip_host: bool
    is_punycode: bool
    suspicious_tld: bool
    trusted_suffix: bool
    is_shortener: bool
    brand_subdomain_hits: Tuple[str, ...]
    brand_squat_hits: Tuple[str, ...]
    brand_typosquat_hits: Tuple[str, ...]
    brand_path_hits: Tuple[str, ...]
    auth_domain_hits: Tuple[str, ...]
    auth_path_hits: Tuple[str, ...]
    host_entropy: float
    domain_label_entropy: float
    subdomain_depth: int
    has_executable_ext: bool
    has_phishing_kit_path: bool
    has_long_hex_token: bool
    features: Tuple[float, ...]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def _is_ip_address(host: str) -> bool:
    candidate = host.strip("[]")
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _fold_homoglyphs(token: str) -> Tuple[str, str]:
    """Return two common ASCII lookalike foldings (1->l and 1->i)."""
    base = (
        token.replace("0", "o")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("rn", "m")
        .replace("vv", "w")
    )
    return base.replace("1", "l"), base.replace("1", "i")


def _matches_official_domain(brand: str, domain_label: str, suffix: str) -> bool:
    if not suffix or suffix in SUSPICIOUS_TLDS:
        return False
    allowed_labels = BRAND_DOMAIN_ALIASES.get(brand, {brand})
    return domain_label in allowed_labels


def _detect_brand_signals(
    subdomain: str,
    domain_label: str,
    suffix: str,
    path_and_query: str,
) -> Tuple[Tuple[str, ...], Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    """Classify brand appearances across subdomain, registrable domain, and path."""
    sub_hits: List[str] = []
    squat_hits: List[str] = []
    typo_hits: List[str] = []
    path_hits: List[str] = []

    sub_tokens = [t for t in re.split(r"[.-]+", subdomain) if t and t != "www"]
    dom_tokens = [t for t in re.split(r"[-]+", domain_label) if t]

    # Decode punycode ASCII stem (e.g., xn--pypal-4ve -> pypal) for lookalike checks.
    puny_stems: List[str] = []
    for part in sub_tokens + [domain_label]:
        if part.startswith("xn--"):
            stem = part[4:].rsplit("-", 1)[0]
            if stem:
                puny_stems.append(stem)

    for brand in sorted(TARGETED_BRANDS):
        is_official = _matches_official_domain(brand, domain_label, suffix)
        if is_official:
            continue

        # 1. Brand embedded inside subdomain while registrable domain is unrelated.
        if any(brand in tok for tok in sub_tokens):
            sub_hits.append(brand)

        # 2. Brand combined with decoy tokens inside registrable domain (e.g. paypal-verify).
        if domain_label != brand and brand in domain_label and len(domain_label) > len(brand):
            squat_hits.append(brand)

        # 3. Homoglyph substitution (paypa1, micros0ft, arnazon) or near-edit on long brands.
        matched_typo = False
        for tok in dom_tokens + sub_tokens:
            if tok == brand or len(tok) < 4:
                continue
            f1, f2 = _fold_homoglyphs(tok)
            if (f1 != tok and f1 == brand) or (f2 != tok and f2 == brand):
                matched_typo = True
                break
            if len(brand) >= 6 and len(tok) >= 6 and (tok[0] == brand[0] or len(tok) == len(brand)):
                if _levenshtein(tok, brand) == 1:
                    matched_typo = True
                    break
        if not matched_typo:
            for stem in puny_stems:
                if len(brand) >= 5 and len(stem) >= 4 and _levenshtein(stem, brand) <= 1:
                    matched_typo = True
                    break
        if matched_typo:
            typo_hits.append(brand)

        # 4. Brand mentioned only inside path/query (low risk by itself).
        if brand in path_and_query and brand not in sub_hits and brand not in squat_hits:
            path_hits.append(brand)

    return tuple(sub_hits), tuple(squat_hits), tuple(typo_hits), tuple(path_hits)


def parse_canonical_url(url: str) -> ParsedUrlInfo:
    """Parse any URL or bare host string into scheme-invariant components and features."""
    raw = str(url or "").strip()
    lowered = raw.lower()
    has_explicit_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", lowered))
    parse_target = lowered if has_explicit_scheme else f"http://{lowered}"

    try:
        split = urlsplit(parse_target)
    except ValueError:
        split = urlsplit("http://invalid.local/")

    scheme = split.scheme if has_explicit_scheme else ""
    scheme_is_https = scheme == "https"
    netloc = split.netloc or ""
    has_userinfo_at = "@" in netloc

    # Strip userinfo and port cleanly to isolate the destination host.
    host_port = netloc.rsplit("@", 1)[-1]
    has_nonstandard_port = False
    if host_port.startswith("["):
        host = host_port.split("]", 1)[0].strip("[]")
        rest = host_port.split("]", 1)[1]
        if rest.startswith(":"):
            port_str = rest[1:]
            if port_str.isdigit() and int(port_str) not in (80, 443):
                has_nonstandard_port = True
    elif ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        if port_str.isdigit() and int(port_str) not in (80, 443):
            has_nonstandard_port = True
    else:
        host = host_port
    host = host.strip(".")

    is_ip_host = _is_ip_address(host)
    if is_ip_host:
        subdomain, domain_label, suffix = "", host, ""
        registrable_domain = host
    else:
        ext = _OFFLINE_TLD(host)
        subdomain = ext.subdomain.lower()
        domain_label = ext.domain.lower()
        suffix = ext.suffix.lower()
        registrable_domain = f"{domain_label}.{suffix}" if domain_label and suffix else host

    non_www_sub = re.sub(r"^www\.", "", subdomain) if subdomain != "www" else ""
    sub_labels = [lbl for lbl in non_www_sub.split(".") if lbl]
    subdomain_depth = len(sub_labels)

    path = split.path or ""
    query = split.query or ""
    path_and_query = f"{path}?{query}" if query else path

    is_punycode = "xn--" in host
    suspicious_tld = suffix in SUSPICIOUS_TLDS
    trusted_suffix = suffix in TRUSTED_SUFFIXES or suffix.endswith((".edu", ".gov", ".mil"))
    is_shortener = registrable_domain in URL_SHORTENERS

    sub_hits, squat_hits, typo_hits, path_hits = _detect_brand_signals(
        non_www_sub, domain_label, suffix, path_and_query
    )

    host_check_str = f"{non_www_sub}.{domain_label}" if non_www_sub else domain_label
    auth_domain_hits = tuple(w for w in AUTH_PATH_WORDS if w in host_check_str)
    auth_path_hits = tuple(w for w in AUTH_PATH_WORDS if w in path_and_query)

    host_alnum = re.sub(r"[^a-z0-9]", "", host_check_str)
    domain_alnum = re.sub(r"[^a-z0-9]", "", domain_label)
    host_entropy = round(_shannon_entropy(host_alnum), 4)
    domain_label_entropy = round(_shannon_entropy(domain_alnum), 4)

    if non_www_sub in STANDARD_FUNCTIONAL_SUBDOMAINS and not sub_hits:
        canonical_host_text = registrable_domain
    else:
        canonical_host_text = f"{non_www_sub}.{registrable_domain}".strip(".") if non_www_sub else registrable_domain
    canonical_path_text = path_and_query.lstrip("/")

    host_digits = sum(c.isdigit() for c in canonical_host_text)
    host_len = len(canonical_host_text)
    host_labels = [p for p in canonical_host_text.split(".") if p]
    longest_host_label = max((len(p) for p in host_labels), default=0)

    clean_path = path.rstrip("/")
    path_segments = [s for s in clean_path.split("/") if s]
    has_executable_ext = clean_path.lower().endswith(EXECUTABLE_EXTENSIONS)
    has_phishing_kit_path = bool(
        re.search(
            r"(?:webscr|cmd=_|cgi-bin/|/wp-includes/|/wp-content/uploads/|/\.well-known/.+\.php)",
            path_and_query,
        )
    )
    # Match long hex folder/file segments in path only (not standard ?token= query strings).
    has_long_hex_token = bool(re.search(r"/[0-9a-f]{24,}(?:/|$)", clean_path))

    features = (
        float(host_len),
        float(len(registrable_domain)),
        float(len(non_www_sub)),
        float(subdomain_depth),
        float(canonical_host_text.count(".")),
        float(canonical_host_text.count("-")),
        float(host_digits),
        round(host_digits / host_len, 4) if host_len else 0.0,
        host_entropy,
        domain_label_entropy,
        float(longest_host_label),
        float(int(is_ip_host)),
        float(int(is_punycode)),
        float(int(has_userinfo_at)),
        float(int(has_nonstandard_port)),
        float(int(suspicious_tld)),
        float(int(trusted_suffix)),
        float(int(is_shortener)),
        float(len(clean_path)),
        float(len(path_segments)),
        float(len(query)),
        float(query.count("=")),
        float(path_and_query.count("%")),
        float(path_and_query.count("-")),
        float(int(has_executable_ext)),
        float(int(bool(sub_hits))),
        float(int(bool(squat_hits))),
        float(int(bool(typo_hits))),
        float(int(has_phishing_kit_path)),
        float(int(has_long_hex_token)),
        float(len(auth_domain_hits)),
    )

    return ParsedUrlInfo(
        raw_url=raw,
        scheme=scheme,
        scheme_is_https=scheme_is_https,
        netloc=netloc,
        host=host,
        subdomain=non_www_sub,
        domain_label=domain_label,
        suffix=suffix,
        registrable_domain=registrable_domain,
        path=path,
        query=query,
        canonical_host_text=canonical_host_text,
        canonical_path_text=canonical_path_text,
        has_userinfo_at=has_userinfo_at,
        has_nonstandard_port=has_nonstandard_port,
        is_ip_host=is_ip_host,
        is_punycode=is_punycode,
        suspicious_tld=suspicious_tld,
        trusted_suffix=trusted_suffix,
        is_shortener=is_shortener,
        brand_subdomain_hits=sub_hits,
        brand_squat_hits=squat_hits,
        brand_typosquat_hits=typo_hits,
        brand_path_hits=path_hits,
        auth_domain_hits=auth_domain_hits,
        auth_path_hits=auth_path_hits,
        host_entropy=host_entropy,
        domain_label_entropy=domain_label_entropy,
        subdomain_depth=subdomain_depth,
        has_executable_ext=has_executable_ext,
        has_phishing_kit_path=has_phishing_kit_path,
        has_long_hex_token=has_long_hex_token,
        features=features,
    )


def extract_url_features(url: str) -> List[float]:
    """Return scheme-invariant structural URL features as a flat numeric list."""
    return list(parse_canonical_url(url).features)


def predict_url_bundle(model_bundle: object, urls: List[str] | Tuple[str, ...]) -> List[Dict[str, float]]:
    """Score URLs using either the canonical hybrid bundle dict or a legacy estimator."""
    import numpy as np

    parsed_list = [parse_canonical_url(u) for u in urls]
    if isinstance(model_bundle, dict) and model_bundle.get("version") == 2:
        host_texts = [p.canonical_host_text for p in parsed_list]
        path_texts = [p.canonical_path_text for p in parsed_list]

        host_vec = model_bundle["host_vectorizer"]
        host_clf = model_bundle["host_clf"]
        path_vec = model_bundle["path_vectorizer"]
        path_clf = model_bundle["path_clf"]
        meta_clf = model_bundle["meta_clf"]

        p_host = host_clf.predict_proba(host_vec.transform(host_texts))[:, 1]
        p_path = path_clf.predict_proba(path_vec.transform(path_texts))[:, 1]
        # Neutralize path classifier bias when URL has no path/query.
        has_path = np.array([1.0 if p.canonical_path_text else 0.0 for p in parsed_list], dtype=float)
        p_path_adj = np.where(has_path > 0.0, p_path, 0.25)

        X_struct = np.array([p.features for p in parsed_list], dtype=float)
        X_meta = np.column_stack([X_struct, p_host, p_path_adj])
        p_final = meta_clf.predict_proba(X_meta)[:, 1]
        return [
            {
                "prob": float(pf),
                "p_host": float(ph),
                "p_path": float(pp),
            }
            for pf, ph, pp in zip(p_final, p_host, p_path_adj)
        ]

    # Legacy fallback for older pickled pipeline expecting numeric features.
    X_legacy = np.array([p.features for p in parsed_list], dtype=float)
    probs = model_bundle.predict_proba(X_legacy)[:, 1]
    return [{"prob": float(pf), "p_host": float(pf), "p_path": float(pf)} for pf in probs]
