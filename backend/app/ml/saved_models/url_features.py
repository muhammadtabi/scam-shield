
import re
import numpy as np

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
        int(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url))),
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
