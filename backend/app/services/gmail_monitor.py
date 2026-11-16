from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from app.core.config import settings
from app.core.security import decrypt_secret, encrypt_secret
from app.db.database import get_db
from app.ml.predictor import detect_email
from app.services.imap_client import (
    clean_app_password,
    imap_fetch_normalized_message,
    imap_list_recent_headers,
    imap_verify_connection,
)


GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
DETECTION_POLICY_VERSION = 5


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def build_google_auth_url(state: str) -> str:
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(GMAIL_SCOPES),
        "access_type": "offline",
        "prompt": "consent select_account",
        "state": state,
        "include_granted_scopes": "true",
    }
    from urllib.parse import urlencode

    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


def _refresh_access_token(refresh_token: str) -> Dict[str, Any]:
    response = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def exchange_code_for_tokens(code: str) -> Dict[str, Any]:
    response = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _gmail_headers(access_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def _gmail_get(path: str, access_token: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    response = requests.get(
        f"{GMAIL_API_BASE}{path}",
        headers=_gmail_headers(access_token),
        params=params,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _decode_header_value(headers: List[Dict[str, str]], name: str) -> str:
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def _decode_base64_part(data: str) -> str:
    import base64

    padded = data.replace("-", "+").replace("_", "/")
    padded += "=" * (-len(padded) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_parts_by_mime(payload: Dict[str, Any], target_prefix: str) -> str:
    mime_type = payload.get("mimeType", "") or ""
    body = payload.get("body", {}) or {}
    data = body.get("data")
    if data and (mime_type.startswith(target_prefix) or not payload.get("parts")):
        return _decode_base64_part(data)

    for part in payload.get("parts", []) or []:
        part_mime = part.get("mimeType", "") or ""
        if part_mime.startswith(target_prefix):
            part_data = (part.get("body", {}) or {}).get("data")
            if part_data:
                text = _decode_base64_part(part_data)
                if text:
                    return text
        if part.get("parts"):
            nested = _extract_parts_by_mime(part, target_prefix)
            if nested:
                return nested
    return ""


def _extract_text_from_payload(payload: Dict[str, Any]) -> str:
    plain = _extract_parts_by_mime(payload, "text/plain")
    if plain:
        return plain
    html_body = _extract_parts_by_mime(payload, "text/html")
    if html_body:
        import html as _html
        import re as _re

        stripped = _re.sub(r"<[^>]+>", " ", html_body)
        return _re.sub(r"\s+", " ", _html.unescape(stripped)).strip()
    return ""


def _extract_html_links_from_payload(payload: Dict[str, Any]) -> List[tuple[str, str]]:
    import re as _re

    html_body = _extract_parts_by_mime(payload, "text/html")
    if not html_body:
        return []
    matches = _re.findall(
        r"<a\b[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
        html_body,
        _re.IGNORECASE | _re.DOTALL,
    )
    return [(href, _re.sub(r"<[^>]+>", "", anchor).strip()) for href, anchor in matches[:12]]


def _normalize_message(message: Dict[str, Any]) -> Dict[str, Any]:
    payload = message.get("payload", {}) or {}
    headers = payload.get("headers", []) or []
    subject = _decode_header_value(headers, "Subject")
    sender = _decode_header_value(headers, "From")
    reply_to = _decode_header_value(headers, "Reply-To")
    auth_results = _decode_header_value(headers, "Authentication-Results")
    body = _extract_text_from_payload(payload)
    snippet = message.get("snippet", "")
    html_links = _extract_html_links_from_payload(payload)
    return {
        "subject": subject or snippet[:120],
        "sender": sender,
        "body": body or snippet,
        "metadata": {
            "reply_to": reply_to,
            "authentication_results": auth_results,
            "html_links": html_links,
        },
    }


def _serialize_detection_for_json(detection: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not detection:
        return None

    cleaned = dict(detection)
    cleaned.pop("_id", None)
    if "id" not in cleaned and "_id" in detection:
        cleaned["id"] = str(detection["_id"])
    elif "id" in cleaned and not isinstance(cleaned["id"], str):
        cleaned["id"] = str(cleaned["id"])
    return cleaned


async def save_gmail_connection(user_id: str, tokens: Dict[str, Any], profile: Dict[str, Any]) -> None:
    db = get_db()
    expires_in = int(tokens.get("expires_in", 0) or 0)
    expires_at = _utc_now().timestamp() + expires_in if expires_in else None
    connection_fields = {
        "user_id": user_id,
        "auth_type": "oauth",
        "gmail_email": profile.get("emailAddress"),
        "access_token": tokens.get("access_token"),
        "scope": tokens.get("scope") or " ".join(GMAIL_SCOPES),
        "token_type": tokens.get("token_type"),
        "expires_in": tokens.get("expires_in"),
        "expires_at": expires_at,
        "enabled": True,
        "last_error": None,
        "last_checked_at": None,
        "last_synced_message_id": None,
        "processed_message_ids": [],
        "updated_at": _utc_now(),
    }
    if tokens.get("refresh_token"):
        connection_fields["refresh_token"] = tokens["refresh_token"]

    await db.gmail_connections.update_one(
        {"user_id": user_id},
        {
            "$set": connection_fields,
            "$unset": {"imap_secret": "", "imap_host": "", "imap_port": "", "imap_provider": ""},
            "$setOnInsert": {"created_at": _utc_now()},
        },
        upsert=True,
    )


async def save_imap_connection(
    user_id: str,
    email_address: str,
    app_password: str,
    provider: str = "gmail",
) -> None:
    """Verify read-only IMAP credentials and store encrypted App Password per user_id."""
    normalized_email = str(email_address or "").strip().lower()
    cleaned_secret = clean_app_password(app_password)
    host, port = await asyncio.to_thread(imap_verify_connection, normalized_email, cleaned_secret, provider)

    db = get_db()
    connection_fields = {
        "user_id": user_id,
        "auth_type": "imap",
        "gmail_email": normalized_email,
        "imap_provider": provider,
        "imap_host": host,
        "imap_port": port,
        "imap_secret": encrypt_secret(cleaned_secret),
        "scope": "imap.readonly",
        "enabled": True,
        "last_error": None,
        "last_checked_at": None,
        "last_synced_message_id": None,
        "processed_message_ids": [],
        "updated_at": _utc_now(),
    }
    await db.gmail_connections.update_one(
        {"user_id": user_id},
        {
            "$set": connection_fields,
            "$unset": {"access_token": "", "refresh_token": "", "expires_at": "", "expires_in": ""},
            "$setOnInsert": {"created_at": _utc_now()},
        },
        upsert=True,
    )


def _is_imap_connection(connection: Dict[str, Any]) -> bool:
    return (connection or {}).get("auth_type") == "imap"


def _imap_credentials(connection: Dict[str, Any]) -> tuple[str, str, str, int]:
    email_addr = str(connection.get("gmail_email") or "").strip()
    encrypted = str(connection.get("imap_secret") or "")
    host = str(connection.get("imap_host") or "imap.gmail.com")
    port = int(connection.get("imap_port") or 993)
    if not email_addr or not encrypted:
        raise ValueError("IMAP credentials missing. Please reconnect your mailbox.")
    return email_addr, decrypt_secret(encrypted), host, port


async def get_gmail_connection(user_id: str) -> Optional[Dict[str, Any]]:
    db = get_db()
    return await db.gmail_connections.find_one({"user_id": user_id})


async def disconnect_gmail(user_id: str) -> None:
    db = get_db()
    await db.gmail_connections.update_one(
        {"user_id": user_id},
        {
            "$set": {"enabled": False, "updated_at": _utc_now()},
            "$unset": {"imap_secret": "", "access_token": "", "refresh_token": ""},
        },
    )


async def fetch_gmail_profile(access_token: str) -> Dict[str, Any]:
    return _gmail_get("/users/me/profile", access_token)


async def _ensure_access_token(connection: Dict[str, Any]) -> str:
    access_token = connection.get("access_token") or ""
    expires_at = connection.get("expires_at")
    refresh_token = connection.get("refresh_token")

    if refresh_token and (not expires_at or _utc_now().timestamp() >= float(expires_at) - 60):
        token_data = _refresh_access_token(refresh_token)
        access_token = token_data.get("access_token", access_token)
        if access_token:
            db = get_db()
            expires_in = int(token_data.get("expires_in", 0) or 0)
            await db.gmail_connections.update_one(
                {"user_id": connection["user_id"]},
                {
                    "$set": {
                        "access_token": access_token,
                        "expires_in": token_data.get("expires_in"),
                        "expires_at": _utc_now().timestamp() + expires_in if expires_in else None,
                        "updated_at": _utc_now(),
                    }
                },
            )

    return access_token


def _list_recent_message_ids(access_token: str, max_results: int = 25) -> List[Dict[str, Any]]:
    result = _gmail_get(
        "/users/me/messages",
        access_token,
        params={"maxResults": max_results, "labelIds": "INBOX"},
    )
    return result.get("messages", []) or []


def _fetch_message(access_token: str, message_id: str) -> Dict[str, Any]:
    return _gmail_get(
        f"/users/me/messages/{message_id}",
        access_token,
        params={"format": "full"},
    )


def _fetch_message_metadata(access_token: str, message_id: str) -> Dict[str, Any]:
    return _gmail_get(
        f"/users/me/messages/{message_id}",
        access_token,
        params={
            "format": "metadata",
            "metadataHeaders": ["Subject", "From", "Date"],
        },
    )


async def sync_gmail_account(user_id: str, max_messages: int = 25) -> Dict[str, Any]:
    connection = await get_gmail_connection(user_id)
    if not connection or not connection.get("enabled"):
        return {"processed": 0, "stored_detection_ids": []}

    is_imap = _is_imap_connection(connection)
    access_token = ""
    imap_creds: Optional[tuple[str, str, str, int]] = None
    if is_imap:
        imap_creds = _imap_credentials(connection)
        items = await asyncio.to_thread(
            imap_list_recent_headers,
            imap_creds[0],
            imap_creds[1],
            imap_creds[2],
            imap_creds[3],
            max_messages,
        )
    else:
        access_token = await _ensure_access_token(connection)
        if not access_token:
            return {"processed": 0, "stored_detection_ids": []}
        items = _list_recent_message_ids(access_token, max_results=max_messages)

    db = get_db()
    processed_ids = set(connection.get("processed_message_ids", []))
    stored_detection_ids: List[str] = []
    processed = 0

    for item in items:
        message_id = item.get("id")
        if not message_id or message_id in processed_ids:
            continue

        if is_imap and imap_creds is not None:
            normalized = await asyncio.to_thread(
                imap_fetch_normalized_message,
                imap_creds[0],
                imap_creds[1],
                imap_creds[2],
                imap_creds[3],
                message_id,
            )
            thread_id = None
            history_id = None
        else:
            message = _fetch_message(access_token, message_id)
            normalized = _normalize_message(message)
            thread_id = message.get("threadId")
            history_id = message.get("historyId")

        result = await asyncio.to_thread(
            detect_email,
            normalized["subject"],
            normalized["sender"],
            normalized["body"],
            metadata=normalized.get("metadata"),
        )
        if "error" in result:
            continue

        result["input_data"] = {
            "subject": normalized["subject"][:160],
            "sender": normalized["sender"][:120],
        }
        result.update(
            {
                "gmail_message_id": message_id,
                "gmail_thread_id": thread_id,
                "gmail_history_id": history_id,
                "source": "gmail_auto",
                "is_auto_synced": True,
                "detector_version": DETECTION_POLICY_VERSION,
            }
        )
        detection_filter = {"user_id": user_id, "gmail_message_id": message_id}
        existing = await db.detections.find_one(detection_filter)
        detection_document = {**result, "user_id": user_id, "timestamp": _utc_now()}
        if existing:
            await db.detections.update_many(detection_filter, {"$set": detection_document})
            result["id"] = str(existing["_id"])
        else:
            result["id"] = str((await db.detections.insert_one(detection_document)).inserted_id)
        stored_detection_ids.append(result["id"])
        processed_ids.add(message_id)
        processed += 1

    await db.gmail_connections.update_one(
        {"user_id": user_id},
        {
            "$set": {
                "processed_message_ids": list(processed_ids)[-200:],
                "last_checked_at": _utc_now(),
                "updated_at": _utc_now(),
                "enabled": True,
            }
        },
    )

    return {"processed": processed, "stored_detection_ids": stored_detection_ids}


async def sync_all_gmail_accounts() -> List[Dict[str, Any]]:
    db = get_db()
    results: List[Dict[str, Any]] = []
    cursor = db.gmail_connections.find({"enabled": True})
    async for connection in cursor:
        user_id = connection.get("user_id")
        if not user_id:
            continue
        try:
            sync_result = await sync_gmail_account(user_id)
            results.append({"user_id": user_id, **sync_result})
        except Exception as exc:
            await db.gmail_connections.update_one(
                {"user_id": user_id},
                {"$set": {"last_error": str(exc), "last_checked_at": _utc_now(), "updated_at": _utc_now()}},
            )
    return results


async def list_gmail_inbox(user_id: str, max_results: int = 30) -> List[Dict[str, Any]]:
    """Return a lightweight inbox list using metadata only.

    We intentionally avoid fetching each message body here because that makes the
    inbox extremely slow when there are many recent emails. Full message content
    is loaded on demand when the user clicks Open.
    """
    connection = await get_gmail_connection(user_id)
    if not connection or not connection.get("enabled"):
        return []

    db = get_db()
    out: List[Dict[str, Any]] = []

    if _is_imap_connection(connection):
        email_addr, app_pw, host, port = _imap_credentials(connection)
        imap_items = await asyncio.to_thread(
            imap_list_recent_headers, email_addr, app_pw, host, port, max_results
        )
        for item in imap_items:
            mid = item.get("id")
            if not mid:
                continue
            detection = await db.detections.find_one(
                {
                    "user_id": user_id,
                    "gmail_message_id": mid,
                    "detector_version": DETECTION_POLICY_VERSION,
                }
            )
            if detection and detection.get("detector_version") != DETECTION_POLICY_VERSION:
                detection = None
            detection_json = _serialize_detection_for_json(detection)
            out.append({
                "id": mid,
                "subject": (detection_json or {}).get("subject") or item.get("subject") or "No subject",
                "sender": (detection_json or {}).get("sender") or item.get("sender") or "Unknown sender",
                "date": item.get("date"),
                "snippet": item.get("snippet") or "",
                "scan": detection_json,
            })
        return out

    access_token = await _ensure_access_token(connection)
    if not access_token:
        return []

    ids = _list_recent_message_ids(access_token, max_results=max_results)

    metadata_ids = [item.get("id") for item in ids if item.get("id")]
    metadata_results = await asyncio.gather(
        *[asyncio.to_thread(_fetch_message_metadata, access_token, message_id) for message_id in metadata_ids],
        return_exceptions=True,
    ) if metadata_ids else []
    metadata_by_id: Dict[str, Dict[str, Any]] = {}

    for message_id, metadata in zip(metadata_ids, metadata_results):
        if isinstance(metadata, Exception):
            continue
        metadata_by_id[message_id] = metadata

    for item in ids:
        mid = item.get("id")
        if not mid:
            continue

        detection = await db.detections.find_one(
            {
                "user_id": user_id,
                "gmail_message_id": mid,
                "detector_version": DETECTION_POLICY_VERSION,
            }
        )
        if detection and detection.get("detector_version") != DETECTION_POLICY_VERSION:
            detection = None
        detection_json = _serialize_detection_for_json(detection)
        snippet = item.get("snippet") or ""
        metadata = metadata_by_id.get(mid, {})
        payload = metadata.get("payload", {}) or {}
        headers = payload.get("headers", []) or []

        subject = _decode_header_value(headers, "Subject")
        sender = _decode_header_value(headers, "From")
        date_value = _decode_header_value(headers, "Date")

        out.append({
            "id": mid,
            "subject": (detection_json or {}).get("subject") or subject or "No subject",
            "sender": (detection_json or {}).get("sender") or sender or "Unknown sender",
            "date": item.get("internalDate") or metadata.get("internalDate") or date_value,
            "snippet": snippet,
            "scan": detection_json,
        })

    return out


async def fetch_gmail_message(user_id: str, message_id: str) -> Dict[str, Any]:
    connection = await get_gmail_connection(user_id)
    if not connection or not connection.get("enabled"):
        raise Exception("Gmail not connected")
    if _is_imap_connection(connection):
        email_addr, app_pw, host, port = _imap_credentials(connection)
        norm = await asyncio.to_thread(
            imap_fetch_normalized_message, email_addr, app_pw, host, port, message_id
        )
    else:
        access_token = await _ensure_access_token(connection)
        msg = _fetch_message(access_token, message_id)
        norm = _normalize_message(msg)
    db = get_db()
    detection = await db.detections.find_one(
        {
            "user_id": user_id,
            "gmail_message_id": message_id,
            "detector_version": DETECTION_POLICY_VERSION,
        }
    )
    if detection and detection.get("detector_version") != DETECTION_POLICY_VERSION:
        detection = None
    return {"body": norm.get("body"), "scan": _serialize_detection_for_json(detection)}


async def scan_gmail_message(user_id: str, message_id: str) -> Dict[str, Any]:
    """Fetch full message, run detection, store detection, and return result."""
    connection = await get_gmail_connection(user_id)
    if not connection or not connection.get("enabled"):
        raise Exception("Gmail not connected")
    if _is_imap_connection(connection):
        email_addr, app_pw, host, port = _imap_credentials(connection)
        norm = await asyncio.to_thread(
            imap_fetch_normalized_message, email_addr, app_pw, host, port, message_id
        )
        thread_id = None
    else:
        access_token = await _ensure_access_token(connection)
        msg = _fetch_message(access_token, message_id)
        norm = _normalize_message(msg)
        thread_id = msg.get("threadId")
    result = await asyncio.to_thread(
        detect_email,
        norm["subject"],
        norm["sender"],
        norm["body"],
        metadata=norm.get("metadata"),
    )
    if "error" in result:
        raise Exception(result["error"])

    result["input_data"] = {
        "subject": norm["subject"][:160],
        "sender": norm["sender"][:120],
    }

    db = get_db()
    result.update({
        "gmail_message_id": message_id,
        "gmail_thread_id": thread_id,
        "source": "gmail_auto",
        "is_auto_synced": False,
        "detector_version": DETECTION_POLICY_VERSION,
    })
    detection_filter = {"user_id": user_id, "gmail_message_id": message_id}
    existing = await db.detections.find_one(detection_filter)
    detection_document = {**result, "user_id": user_id, "timestamp": _utc_now()}
    if existing:
        await db.detections.update_many(detection_filter, {"$set": detection_document})
        result["id"] = str(existing["_id"])
    else:
        result["id"] = str((await db.detections.insert_one(detection_document)).inserted_id)
    return result


async def gmail_monitor_loop(stop_event: asyncio.Event) -> None:
    """
    Background loop that runs while the FastAPI app is alive. It polls all enabled
    Gmail connections and syncs new messages. When a connection is first enabled
    (user connects Gmail), the polling will pick it up on the next interval.

    This loop is started in `main.py` during app startup.
    """

    while not stop_event.is_set():
        try:
            await sync_all_gmail_accounts()
        except Exception:
            # swallow per-iteration exceptions so the loop continues
            pass

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=settings.GMAIL_POLL_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue