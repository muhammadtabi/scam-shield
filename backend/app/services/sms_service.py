import asyncio
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from bson import ObjectId

from app.db.database import get_db
from app.ml.predictor import detect_sms
from app.schemas.sms import (
    SMSConnectionStatus,
    SMSInboxItem,
    SMSInboxResponse,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _doc_to_inbox_item(doc: Dict[str, Any]) -> SMSInboxItem:
    doc_id = str(doc.get("_id", ""))
    return SMSInboxItem(
        id=doc_id,
        sender_id=doc.get("sender_id", "Unknown"),
        message=doc.get("message", ""),
        timestamp=doc.get("timestamp") or doc.get("created_at") or _utc_now(),
        scam_level=doc.get("scam_level", "safe"),
        confidence=float(doc.get("confidence", 0.0)),
        reasons=doc.get("reasons") or [],
        explanation=doc.get("explanation"),
        is_read=bool(doc.get("is_read", False)),
    )


async def get_sms_connection(user_id: str) -> Optional[Dict[str, Any]]:
    db = get_db()
    return await db.sms_connections.find_one({"user_id": user_id})


async def get_sms_status(user_id: str) -> SMSConnectionStatus:
    db = get_db()
    conn = await db.sms_connections.find_one({"user_id": user_id})
    enabled = bool(conn and conn.get("enabled", False))

    if not enabled:
        return SMSConnectionStatus(connected=False)

    total = await db.sms_messages.count_documents({"user_id": user_id})
    scam_count = await db.sms_messages.count_documents({"user_id": user_id, "scam_level": "scam"})
    suspicious_count = await db.sms_messages.count_documents({"user_id": user_id, "scam_level": "suspicious"})
    safe_count = await db.sms_messages.count_documents({"user_id": user_id, "scam_level": "safe"})

    return SMSConnectionStatus(
        connected=True,
        phone_number=conn.get("phone_number"),
        sync_token=conn.get("sync_token"),
        total_messages=total,
        scam_count=scam_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        updated_at=conn.get("updated_at"),
    )


async def connect_sms_phone(user_id: str, phone_number: str) -> SMSConnectionStatus:
    db = get_db()
    existing = await db.sms_connections.find_one({"user_id": user_id})

    # Preserve existing sync token if user already has one, or generate a fresh one
    sync_token = (existing and existing.get("sync_token")) or f"scam_sms_{secrets.token_urlsafe(18)}"

    payload = {
        "user_id": user_id,
        "phone_number": phone_number.strip(),
        "sync_token": sync_token,
        "enabled": True,
        "updated_at": _utc_now(),
    }

    await db.sms_connections.update_one(
        {"user_id": user_id},
        {
            "$set": payload,
            "$setOnInsert": {"created_at": _utc_now()},
        },
        upsert=True,
    )

    return await get_sms_status(user_id)


async def disconnect_sms_phone(user_id: str) -> SMSConnectionStatus:
    db = get_db()
    await db.sms_connections.update_one(
        {"user_id": user_id},
        {
            "$set": {"enabled": False, "updated_at": _utc_now()},
        },
    )
    return SMSConnectionStatus(connected=False)


async def resolve_user_by_sync_token(token: str) -> Optional[str]:
    """Find the user_id that owns an active sync token."""
    if not token or not isinstance(token, str):
        return None
    db = get_db()
    conn = await db.sms_connections.find_one({"sync_token": token.strip(), "enabled": True})
    return conn.get("user_id") if conn else None


async def ingest_sms_message(
    user_id: str,
    sender_id: str,
    message: str,
    timestamp: Optional[datetime] = None,
) -> SMSInboxItem:
    """Analyze an incoming SMS with Scam Shield ML and persist to inbox."""
    db = get_db()
    detection = await asyncio.to_thread(detect_sms, sender_id=sender_id, message=message)

    scam_level = detection.get("scam_level", "safe")
    confidence = float(detection.get("confidence", 0.0))
    reasons = detection.get("reasons", [])
    explanation = detection.get("explanation", "")

    doc = {
        "user_id": user_id,
        "sender_id": sender_id,
        "message": message,
        "timestamp": timestamp or _utc_now(),
        "scam_level": scam_level,
        "confidence": confidence,
        "reasons": reasons,
        "explanation": explanation,
        "is_read": False,
        "created_at": _utc_now(),
    }

    result = await db.sms_messages.insert_one(doc)
    doc["_id"] = result.inserted_id

    # Also log to detections collection for analytics if user dashboard tracks it
    await db.detections.insert_one({
        "user_id": user_id,
        "detection_type": "sms",
        "input_data": {"sender_id": sender_id, "message": message[:200]},
        "scam_level": scam_level,
        "confidence": confidence,
        "reasons": reasons,
        "explanation": explanation,
        "timestamp": _utc_now(),
    })

    return _doc_to_inbox_item(doc)


async def list_sms_messages(
    user_id: str,
    scam_level: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 20,
) -> SMSInboxResponse:
    db = get_db()
    query: Dict[str, Any] = {"user_id": user_id}

    if scam_level and scam_level.lower() in {"scam", "suspicious", "safe"}:
        query["scam_level"] = scam_level.lower()

    if search:
        s = search.strip()
        # In-memory and mongo regex search on sender or message
        query["$or"] = [
            {"sender_id": {"$regex": re.escape(s), "$options": "i"}},
            {"message": {"$regex": re.escape(s), "$options": "i"}},
        ]

    total = await db.sms_messages.count_documents(query)
    scam_count = await db.sms_messages.count_documents({"user_id": user_id, "scam_level": "scam"})
    suspicious_count = await db.sms_messages.count_documents({"user_id": user_id, "scam_level": "suspicious"})
    safe_count = await db.sms_messages.count_documents({"user_id": user_id, "scam_level": "safe"})

    skip = max(0, (page - 1) * page_size)
    cursor = db.sms_messages.find(query).sort("timestamp", -1).skip(skip).limit(page_size)

    messages: List[SMSInboxItem] = []
    async for doc in cursor:
        messages.append(_doc_to_inbox_item(doc))

    pages = max(1, (total + page_size - 1) // page_size) if total > 0 else 1

    return SMSInboxResponse(
        messages=messages,
        total=total,
        page=page,
        pages=pages,
        scam_count=scam_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
    )


async def get_single_sms(user_id: str, message_id: str) -> Optional[SMSInboxItem]:
    db = get_db()
    try:
        oid = ObjectId(message_id)
    except Exception:
        return None

    doc = await db.sms_messages.find_one({"_id": oid, "user_id": user_id})
    if not doc:
        return None

    # Mark as read when fetched individually
    if not doc.get("is_read"):
        await db.sms_messages.update_one({"_id": oid}, {"$set": {"is_read": True}})
        doc["is_read"] = True

    return _doc_to_inbox_item(doc)


async def delete_sms_message(user_id: str, message_id: str) -> bool:
    db = get_db()
    try:
        oid = ObjectId(message_id)
    except Exception:
        return False

    res = await db.sms_messages.delete_one({"_id": oid, "user_id": user_id})
    return res.deleted_count > 0


PRESET_SIMULATIONS = {
    "bank_otp_safe": {
        "sender_id": "8558",
        "message": "Your Chase online banking OTP is 492011. Valid for 10 minutes. Do NOT share this code with anyone. Chase will never call you to ask for this code.",
    },
    "carrier_notice_safe": {
        "sender_id": "3737",
        "message": "Your monthly plan renewal of $45 is scheduled for tomorrow. Reply STOP to cancel auto-pay or manage your account in the official app.",
    },
    "package_delivery_scam": {
        "sender_id": "+14159821102",
        "message": "USPS: Your package could not be delivered due to an incomplete address. Update your info immediately at http://usps-address-update-help.com or your parcel will be returned.",
    },
    "bank_suspension_scam": {
        "sender_id": "+19293021944",
        "message": "URGENT: Wells Fargo account locked due to suspicious activity. Verify your identity right now to avoid permanent suspension: http://wellsfargo-secure-login.xyz/verify",
    },
    "lottery_prize_scam": {
        "sender_id": "+447911123456",
        "message": "Congratulations! Your mobile number won $2,500,000 in the International Mobile Promo. Send your bank account details to claim-dept@promowinners.org to release funds.",
    },
    "job_offer_scam": {
        "sender_id": "+17025550199",
        "message": "We have an urgent remote job opening paying $300-$500/day. No experience needed. Contact WhatsApp +18005550123 immediately to start today!",
    },
}


async def simulate_sms_message(
    user_id: str,
    preset: Optional[str] = None,
    sender_id: Optional[str] = None,
    message: Optional[str] = None,
) -> SMSInboxItem:
    """Ingest a realistic simulated SMS into the user's inbox for testing."""
    if preset and preset in PRESET_SIMULATIONS:
        p = PRESET_SIMULATIONS[preset]
        s_id = p["sender_id"]
        msg = p["message"]
    else:
        s_id = sender_id or "8558"
        msg = message or "Your verification code is 123456."

    return await ingest_sms_message(user_id=user_id, sender_id=s_id, message=msg)


async def import_sms_batch(
    user_id: str,
    items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Batch ingest and scan historical SMS messages into user inbox."""
    imported: List[SMSInboxItem] = []
    scam_count = 0
    suspicious_count = 0
    safe_count = 0

    for item in items:
        s_id = str(item.get("sender_id", "")).strip()
        msg = str(item.get("message", "")).strip()
        ts = item.get("timestamp")
        if not s_id or not msg:
            continue

        res = await ingest_sms_message(
            user_id=user_id,
            sender_id=s_id,
            message=msg,
            timestamp=ts,
        )
        imported.append(res)
        if res.scam_level == "scam":
            scam_count += 1
        elif res.scam_level == "suspicious":
            suspicious_count += 1
        else:
            safe_count += 1

    return {
        "imported_count": len(imported),
        "scam_count": scam_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "messages": imported,
    }


