from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.dependencies import get_current_user
from app.core.security import create_access_token, decode_token
from app.schemas.gmail import (
    GmailCallbackRequest,
    GmailConnectResponse,
    GmailConnectionStatus,
    GmailImapConnectRequest,
    GmailSyncResponse,
)
from app.services.gmail_monitor import (
    build_google_auth_url,
    disconnect_gmail,
    exchange_code_for_tokens,
    fetch_gmail_profile,
    get_gmail_connection,
    save_gmail_connection,
    save_imap_connection,
    sync_gmail_account,
    list_gmail_inbox,
    fetch_gmail_message,
    scan_gmail_message,
)

router = APIRouter()


def _status_from_connection(connection: dict | None, *, force_connected: bool | None = None) -> GmailConnectionStatus:
    conn = connection or {}
    enabled = bool(conn.get("enabled", False)) if force_connected is None else bool(force_connected)
    last_checked = conn.get("last_checked_at")
    if isinstance(last_checked, datetime) and last_checked.tzinfo is None:
        last_checked = last_checked.replace(tzinfo=timezone.utc)
    return GmailConnectionStatus(
        connected=enabled,
        email_address=conn.get("gmail_email"),
        enabled=enabled,
        auth_type=conn.get("auth_type") if enabled else None,
        last_checked_at=last_checked,
        last_synced_message_id=conn.get("last_synced_message_id"),
        error=conn.get("last_error"),
    )


async def _finish_gmail_connection(code: str, user_id: str):
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code is required")

    tokens = exchange_code_for_tokens(code)
    profile = await fetch_gmail_profile(tokens["access_token"])
    await save_gmail_connection(user_id, tokens, profile)
    connection = await get_gmail_connection(user_id)
    return connection


@router.get("/connect", response_model=GmailConnectResponse)
async def get_connect_url(current_user: dict = Depends(get_current_user)):
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="Google OAuth is not configured")

    state = create_access_token(
        {"sub": current_user["sub"], "purpose": "gmail_connect"},
        expires_delta=timedelta(minutes=10),
    )
    return GmailConnectResponse(auth_url=build_google_auth_url(state))


def _frontend_redirect_url(params: dict[str, str]) -> str:
    base = settings.FRONTEND_URL.rstrip("/")
    return f"{base}/?{urlencode(params)}"


@router.get("/callback")
async def gmail_callback(
    code: str = Query(default=""),
    state: str | None = Query(default=None),
    error: str | None = Query(default=None),
):
    if error:
        message = (
            "Google access was denied or cancelled. If this app is still in Testing mode, add this Gmail to Google Cloud test users or publish the app."
            if error == "access_denied"
            else "Google cancelled the Gmail connection."
        )
        return RedirectResponse(url=_frontend_redirect_url({"gmail": "error", "message": message}))

    payload = decode_token(state) if state else None
    if not payload or payload.get("purpose") != "gmail_connect" or not payload.get("sub"):
        return RedirectResponse(
            url=_frontend_redirect_url(
                {"gmail": "error", "message": "Gmail connection session expired. Please try connecting again."}
            )
        )

    try:
        await _finish_gmail_connection(code, payload["sub"])
    except Exception as exc:
        err_text = str(exc)
        message = err_text if err_text else "Gmail connection failed. Check OAuth settings and try again."
        return RedirectResponse(url=_frontend_redirect_url({"gmail": "error", "message": message}))

    return RedirectResponse(url=_frontend_redirect_url({"gmail": "connected"}))


@router.post("/callback", response_model=GmailConnectionStatus)
async def gmail_callback_manual(payload: GmailCallbackRequest, current_user: dict = Depends(get_current_user)):
    connection = await _finish_gmail_connection(payload.code, current_user["sub"])
    return _status_from_connection(connection, force_connected=True)


@router.post("/connect-imap", response_model=GmailConnectionStatus)
async def connect_gmail_via_imap(
    payload: GmailImapConnectRequest,
    current_user: dict = Depends(get_current_user),
):
    try:
        await save_imap_connection(
            current_user["sub"],
            str(payload.email),
            payload.app_password,
            payload.provider,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not reach the mail server over TLS. Verify your provider and try again.",
        ) from exc

    connection = await get_gmail_connection(current_user["sub"])
    return _status_from_connection(connection)


@router.get("/status", response_model=GmailConnectionStatus)
async def gmail_status(current_user: dict = Depends(get_current_user)):
    connection = await get_gmail_connection(current_user["sub"])
    return _status_from_connection(connection)


@router.post("/sync", response_model=GmailSyncResponse)
async def gmail_sync(current_user: dict = Depends(get_current_user)):
    sync_result = await sync_gmail_account(current_user["sub"])
    return GmailSyncResponse(**sync_result)


@router.get('/inbox')
async def gmail_inbox(current_user: dict = Depends(get_current_user)):
    """Return a list of recent messages (sender, subject, snippet, date, id)
    and any existing scan data for those messages."""
    try:
        return await list_gmail_inbox(current_user['sub'])
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Gmail session expired or access was revoked. Please reconnect your Gmail account.",
        ) from exc


@router.get('/message/{message_id}')
async def gmail_fetch_message(message_id: str, current_user: dict = Depends(get_current_user)):
    try:
        return await fetch_gmail_message(current_user['sub'], message_id)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Gmail session expired or access was revoked. Please reconnect your Gmail account.",
        ) from exc


@router.post('/message/{message_id}/scan')
async def gmail_scan_message(message_id: str, current_user: dict = Depends(get_current_user)):
    try:
        return await scan_gmail_message(current_user['sub'], message_id)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Gmail session expired or access was revoked. Please reconnect your Gmail account.",
        ) from exc


@router.delete("/disconnect", response_model=GmailConnectionStatus)
async def gmail_disconnect(current_user: dict = Depends(get_current_user)):
    await disconnect_gmail(current_user["sub"])
    connection = await get_gmail_connection(current_user["sub"])
    return _status_from_connection(connection, force_connected=False)