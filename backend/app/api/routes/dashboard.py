from fastapi import APIRouter, Depends
from datetime import datetime, timedelta
from app.core.dependencies import get_current_user
from app.db.database import get_db

router = APIRouter()

@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    db = get_db()
    uid = current_user["sub"]

    # Total counts
    total       = await db.detections.count_documents({"user_id": uid})
    scam_count  = await db.detections.count_documents({"user_id": uid, "scam_level": "scam"})
    susp_count  = await db.detections.count_documents({"user_id": uid, "scam_level": "suspicious"})
    safe_count  = await db.detections.count_documents({"user_id": uid, "scam_level": "safe"})

    # By type
    email_count = await db.detections.count_documents({"user_id": uid, "detection_type": "email"})
    sms_count   = await db.detections.count_documents({"user_id": uid, "detection_type": "sms"})
    url_count   = await db.detections.count_documents({"user_id": uid, "detection_type": "url"})

    # Last 7 days trend with threat breakdown
    trend = []
    for i in range(6, -1, -1):
        day_start = datetime.utcnow().replace(hour=0, minute=0, second=0) - timedelta(days=i)
        day_end   = day_start + timedelta(days=1)
        base_filter = {
            "user_id": uid,
            "timestamp": {"$gte": day_start, "$lt": day_end}
        }
        count = await db.detections.count_documents(base_filter)
        scams = await db.detections.count_documents({**base_filter, "scam_level": "scam"})
        suspicious = await db.detections.count_documents({**base_filter, "scam_level": "suspicious"})
        safe = await db.detections.count_documents({**base_filter, "scam_level": "safe"})

        trend.append({
            "date": day_start.strftime("%b %d"),
            "day_name": day_start.strftime("%a"),
            "day_num": day_start.strftime("%d"),
            "full_date": day_start.strftime("%A, %b %d"),
            "is_today": (i == 0),
            "count": count,
            "scams": scams,
            "suspicious": suspicious,
            "safe": safe,
        })

    # Recent 5 detections
    recent = []
    cursor = db.detections.find({"user_id": uid}).sort("timestamp", -1).limit(5)
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        recent.append(doc)

    return {
        "total": total,
        "scam_count": scam_count,
        "suspicious_count": susp_count,
        "safe_count": safe_count,
        "by_type": {
            "email": email_count,
            "sms": sms_count,
            "url": url_count
        },
        "trend": trend,
        "recent": recent,
        "security_score": round((safe_count / total * 100) if total > 0 else 100, 1)
    }
