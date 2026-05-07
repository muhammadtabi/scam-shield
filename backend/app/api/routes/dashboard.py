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

    # Last 7 days trend
    trend = []
    for i in range(6, -1, -1):
        day_start = datetime.utcnow().replace(hour=0, minute=0, second=0) - timedelta(days=i)
        day_end   = day_start + timedelta(days=1)
        count = await db.detections.count_documents({
            "user_id": uid,
            "timestamp": {"$gte": day_start, "$lt": day_end}
        })
        trend.append({
            "date": day_start.strftime("%b %d"),
            "count": count
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
