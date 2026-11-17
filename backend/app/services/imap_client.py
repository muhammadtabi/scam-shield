"""Read-only IMAP-over-TLS client for App Password mailbox connections.

Allows any user (Gmail, Google Workspace, Outlook, Yahoo, Zoho) to connect a
mailbox without Google OAuth verification while enforcing:
  - strict provider host allowlist (preventing SSRF against internal hosts)
  - TLS-verified port 993 connections (`IMAP4_SSL`)
  - `readonly=True` INBOX selection and `BODY.PEEK[]` fetches so messages are
    never altered or marked read.
"""

from __future__ import annotations

import email as py_email
import email.policy
import html as html_lib
import imaplib
import re
import ssl
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Tuple

IMAP_PROVIDERS: Dict[str, Tuple[str, int]] = {
    "gmail": ("imap.gmail.com", 993),
    "outlook": ("outlook.office365.com", 993),
    "yahoo": ("imap.mail.yahoo.com", 993),
    "zoho": ("imap.zoho.com", 993),
}

IMAP_TIMEOUT_SECONDS = 15


def resolve_imap_endpoint(provider: str = "gmail") -> Tuple[str, int]:
    key = (provider or "gmail").strip().lower()
    if key not in IMAP_PROVIDERS:
        raise ValueError(f"Unsupported mail provider '{provider}'. Choose gmail, outlook, yahoo, or zoho.")
    return IMAP_PROVIDERS[key]


def clean_app_password(raw_password: str) -> str:
    """Normalize App Passwords (Google displays them as 4-char space-separated groups)."""
    return re.sub(r"[\s\u200b-\u200d\uFEFF]+", "", str(raw_password or "")).strip().lower()


def _open_readonly_inbox(email_address: str, app_password: str, host: str, port: int = 993) -> imaplib.IMAP4_SSL:
    context = ssl.create_default_context()
    client = imaplib.IMAP4_SSL(host, port, ssl_context=context, timeout=IMAP_TIMEOUT_SECONDS)
    try:
        client.login(email_address.strip().lower(), clean_app_password(app_password))
    except imaplib.IMAP4.error as exc:
        try:
            client.logout()
        except Exception:
            pass
        raw_err = str(exc).lower()
        if "application-specific password" in raw_err:
            msg = "Google requires an App Password. Do not use your standard Google account password."
        elif "authenticationfailed" in raw_err:
            msg = (
                "Mailbox login failed. Please ensure: 1) IMAP is enabled in Gmail Settings (under 'Forwarding and POP/IMAP' tab), "
                "2) 2-Step Verification is enabled on your Google account, and 3) the 16-character App Password was generated for this exact email."
            )
        else:
            msg = f"Mailbox login failed: {exc}"
        raise ValueError(msg) from exc

    status, _ = client.select("INBOX", readonly=True)
    if status != "OK":
        try:
            client.logout()
        except Exception:
            pass
        raise ConnectionError("Connected to mail server, but could not open INBOX in read-only mode.")
    return client


def imap_verify_connection(email_address: str, app_password: str, provider: str = "gmail") -> Tuple[str, int]:
    """Verify credentials against an allowlisted IMAP-over-TLS server in read-only mode."""
    host, port = resolve_imap_endpoint(provider)
    client = _open_readonly_inbox(email_address, app_password, host, port)
    try:
        client.noop()
    finally:
        try:
            client.close()
        except Exception:
            pass
        try:
            client.logout()
        except Exception:
            pass
    return host, port


def _extract_email_bodies(msg: py_email.message.Message) -> Tuple[str, str]:
    plain_parts: List[str] = []
    html_parts: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition") or "").lower()
            if "attachment" in disposition:
                continue
            ctype = (part.get_content_type() or "").lower()
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True)
                content = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else ""
            if not isinstance(content, str):
                continue
            if ctype == "text/plain":
                plain_parts.append(content)
            elif ctype == "text/html":
                html_parts.append(content)
    else:
        ctype = (msg.get_content_type() or "").lower()
        try:
            content = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            content = payload.decode("utf-8", errors="ignore") if isinstance(payload, bytes) else ""
        if isinstance(content, str):
            if ctype == "text/html":
                html_parts.append(content)
            else:
                plain_parts.append(content)

    return "\n".join(p.strip() for p in plain_parts if p.strip()), "\n".join(h.strip() for h in html_parts if h.strip())


def _strip_html(raw_html: str) -> str:
    if not raw_html:
        return ""
    text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", raw_html, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html_lib.unescape(text)).strip()


def _extract_html_links(raw_html: str) -> List[Tuple[str, str]]:
    if not raw_html:
        return []
    matches = re.findall(
        r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
        raw_html,
        re.IGNORECASE | re.DOTALL,
    )
    return [(href, re.sub(r"<[^>]+>", "", anchor).strip()) for href, anchor in matches[:12]]


def parse_rfc822_message(raw_bytes: bytes, message_id: str) -> Dict[str, Any]:
    """Parse raw RFC822 email bytes into the shared Scam Shield normalized structure."""
    msg = py_email.parser.BytesParser(policy=email.policy.default).parsebytes(raw_bytes)
    subject = str(msg.get("Subject") or "").strip()
    sender = str(msg.get("From") or "").strip()
    reply_to = str(msg.get("Reply-To") or "").strip()
    auth_headers = msg.get_all("Authentication-Results", []) or []
    auth_results = "; ".join(str(v).strip() for v in auth_headers if v)
    date_header = str(msg.get("Date") or "").strip()
    internal_date_ms = ""
    if date_header:
        try:
            internal_date_ms = str(int(parsedate_to_datetime(date_header).timestamp() * 1000))
        except Exception:
            internal_date_ms = ""

    plain_body, html_body = _extract_email_bodies(msg)
    body = plain_body or _strip_html(html_body)
    snippet = re.sub(r"\s+", " ", body).strip()[:160]
    html_links = _extract_html_links(html_body)

    return {
        "id": message_id,
        "threadId": None,
        "historyId": None,
        "internalDate": internal_date_ms,
        "date": internal_date_ms or date_header,
        "snippet": snippet,
        "subject": subject or snippet[:120] or "No subject",
        "sender": sender or "Unknown sender",
        "body": body or snippet,
        "metadata": {
            "reply_to": reply_to,
            "authentication_results": auth_results,
            "html_links": html_links,
        },
    }


def _parse_uid_from_message_id(message_id: str) -> str:
    raw = str(message_id or "").strip()
    if raw.startswith("imap:"):
        raw = raw.split(":", 1)[1]
    if not raw.isdigit():
        raise ValueError("Invalid IMAP message identifier")
    return raw


def imap_list_recent_headers(
    email_address: str,
    app_password: str,
    host: str,
    port: int = 993,
    max_results: int = 30,
) -> List[Dict[str, Any]]:
    """Fetch headers for the newest `max_results` INBOX messages via a single batch UID FETCH."""
    client = _open_readonly_inbox(email_address, app_password, host, port)
    try:
        status, data = client.uid("search", None, "ALL")
        if status != "OK" or not data or not data[0]:
            return []
        all_uids = [u for u in data[0].decode("ascii", errors="ignore").split() if u.isdigit()]
        recent_uids = list(reversed(all_uids[-max_results:]))
        if not recent_uids:
            return []

        uid_set = ",".join(recent_uids)
        status, fetch_data = client.uid(
            "fetch",
            uid_set,
            "(UID BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])",
        )
        if status != "OK" or not fetch_data:
            return []

        by_uid: Dict[str, Dict[str, Any]] = {}
        for item in fetch_data:
            if not isinstance(item, tuple) or len(item) < 2:
                continue
            meta_bytes, header_bytes = item[0], item[1]
            meta_str = meta_bytes.decode("ascii", errors="ignore") if isinstance(meta_bytes, bytes) else str(meta_bytes)
            uid_match = re.search(r"\bUID\s+(\d+)\b", meta_str)
            if not uid_match or not isinstance(header_bytes, bytes):
                continue
            uid = uid_match.group(1)
            parsed = py_email.parser.BytesParser(policy=email.policy.default).parsebytes(header_bytes)
            date_hdr = str(parsed.get("Date") or "").strip()
            internal_ms = ""
            if date_hdr:
                try:
                    internal_ms = str(int(parsedate_to_datetime(date_hdr).timestamp() * 1000))
                except Exception:
                    internal_ms = ""
            by_uid[uid] = {
                "id": f"imap:{uid}",
                "subject": str(parsed.get("Subject") or "").strip() or "No subject",
                "sender": str(parsed.get("From") or "").strip() or "Unknown sender",
                "date": internal_ms or date_hdr,
                "snippet": "",
            }

        return [by_uid[uid] for uid in recent_uids if uid in by_uid]
    finally:
        try:
            client.close()
        except Exception:
            pass
        try:
            client.logout()
        except Exception:
            pass


def imap_fetch_normalized_message(
    email_address: str,
    app_password: str,
    host: str,
    port: int,
    message_id: str,
) -> Dict[str, Any]:
    """Fetch a single RFC822 message with BODY.PEEK[] in read-only mode."""
    uid = _parse_uid_from_message_id(message_id)
    client = _open_readonly_inbox(email_address, app_password, host, port)
    try:
        status, fetch_data = client.uid("fetch", uid, "(BODY.PEEK[])")
        if status != "OK" or not fetch_data:
            raise ValueError("Requested message was not found in INBOX")
        raw_bytes = b""
        for item in fetch_data:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
                raw_bytes = item[1]
                break
        if not raw_bytes:
            raise ValueError("Requested message has no readable content")
        return parse_rfc822_message(raw_bytes, f"imap:{uid}")
    finally:
        try:
            client.close()
        except Exception:
            pass
        try:
            client.logout()
        except Exception:
            pass

