from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.core.dependencies import get_current_user, get_optional_current_user
from app.schemas.sms import (
    SMSBatchImportRequest,
    SMSBatchImportResponse,
    SMSConnectRequest,
    SMSConnectionStatus,
    SMSInboxItem,
    SMSInboxResponse,
    SMSIngestRequest,
    SMSSimulateRequest,
)
from app.services.sms_service import (
    connect_sms_phone,
    delete_sms_message,
    disconnect_sms_phone,
    get_single_sms,
    get_sms_status,
    import_sms_batch,
    ingest_sms_message,
    list_sms_messages,
    resolve_user_by_sync_token,
    simulate_sms_message,
)

router = APIRouter()


@router.get("/status", response_model=SMSConnectionStatus)
async def get_status(current_user: dict = Depends(get_current_user)):
    """Fetch the current user's phone connection status and sync token."""
    return await get_sms_status(current_user["sub"])


@router.post("/connect", response_model=SMSConnectionStatus)
async def connect_phone(
    request: SMSConnectRequest,
    current_user: dict = Depends(get_current_user),
):
    """Link a mobile phone number to the user's Scam Shield inbox."""
    return await connect_sms_phone(current_user["sub"], request.phone_number)


@router.post("/disconnect", response_model=SMSConnectionStatus)
async def disconnect_phone(current_user: dict = Depends(get_current_user)):
    """Disconnect phone number from active inbox monitoring."""
    return await disconnect_sms_phone(current_user["sub"])


@router.get("/inbox", response_model=SMSInboxResponse)
async def get_inbox(
    scam_level: Optional[str] = Query(default=None, description="Filter by safe, suspicious, or scam"),
    search: Optional[str] = Query(default=None, description="Search sender or message content"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    """List received SMS messages with scam analysis and pagination."""
    return await list_sms_messages(
        user_id=current_user["sub"],
        scam_level=scam_level,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.get("/messages/{message_id}", response_model=SMSInboxItem)
async def get_message(
    message_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Fetch single SMS message details and mark as read."""
    item = await get_single_sms(current_user["sub"], message_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SMS message not found")
    return item


@router.delete("/messages/{message_id}")
async def delete_message(
    message_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete an SMS message from the inbox."""
    deleted = await delete_sms_message(current_user["sub"], message_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SMS message not found")
    return {"status": "success", "message": "SMS deleted"}


@router.post("/receive", response_model=SMSInboxItem)
async def receive_sms(
    request: SMSIngestRequest,
    token: Optional[str] = Query(default=None),
    x_sync_token: Optional[str] = Header(default=None, alias="X-Sync-Token"),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Ingest an incoming SMS message.
    Accepts authentication either via user JWT session or via phone sync token.
    """
    user_id: Optional[str] = None

    if current_user and "sub" in current_user:
        user_id = current_user["sub"]
    else:
        sync_token = x_sync_token or token
        if sync_token:
            user_id = await resolve_user_by_sync_token(sync_token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid JWT session or phone sync token.",
        )

    return await ingest_sms_message(
        user_id=user_id,
        sender_id=request.sender_id,
        message=request.message,
        timestamp=request.timestamp,
    )


@router.post("/simulate", response_model=SMSInboxItem)
async def simulate_sms(
    request: SMSSimulateRequest,
    current_user: dict = Depends(get_current_user),
):
    """Simulate a realistic incoming SMS (safe or scam) for testing the inbox."""
    return await simulate_sms_message(
        user_id=current_user["sub"],
        preset=request.preset,
        sender_id=request.sender_id,
        message=request.message,
    )


@router.post("/sync-batch", response_model=SMSBatchImportResponse)
async def sync_batch_sms(
    request: SMSBatchImportRequest,
    token: Optional[str] = Query(default=None),
    x_sync_token: Optional[str] = Header(default=None, alias="X-Sync-Token"),
    current_user: Optional[dict] = Depends(get_optional_current_user),
):
    """
    Import and scan a batch of historical SMS messages.
    Accepts authentication either via user JWT session or phone sync token.
    """
    user_id: Optional[str] = None

    if current_user and "sub" in current_user:
        user_id = current_user["sub"]
    else:
        sync_token = x_sync_token or token
        if sync_token:
            user_id = await resolve_user_by_sync_token(sync_token)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid JWT session or phone sync token.",
        )

    res = await import_sms_batch(
        user_id=user_id,
        items=[msg.model_dump() for msg in request.messages],
    )
    return res


