from typing import Any, Dict, List
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from app.core.dependencies import get_current_user
from app.db.database import get_db

router = APIRouter()

@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    db = get_db()
    uid = current_user["sub"]

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = today_start - timedelta(days=6)

    # Use a single MongoDB $facet aggregation pipeline for high-performance retrieval
    try:
        pipeline = [
            {"$match": {"user_id": uid}},
            {
                "$facet": {
                    "by_level": [
                        {"$group": {"_id": "$scam_level", "count": {"$sum": 1}}}
                    ],
                    "by_type": [
                        {"$group": {"_id": "$detection_type", "count": {"$sum": 1}}}
                    ],
                    "trend": [
                        {"$match": {"timestamp": {"$gte": seven_days_ago}}},
                        {
                            "$group": {
                                "_id": {
                                    "day": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                                    "level": "$scam_level"
                                },
                                "count": {"$sum": 1}
                            }
                        }
                    ],
                    "recent": [
                        {"$sort": {"timestamp": -1}},
                        {"$limit": 5}
                    ]
                }
            }
        ]

        facet_results = await db.detections.aggregate(pipeline).to_list(length=1)
        facet_data = facet_results[0] if facet_results else {}

        level_counts = {item["_id"]: item["count"] for item in facet_data.get("by_level", []) if item.get("_id")}
        scam_count = level_counts.get("scam", 0)
        susp_count = level_counts.get("suspicious", 0)
        safe_count = level_counts.get("safe", 0)
        total = scam_count + susp_count + safe_count

        type_counts = {item["_id"]: item["count"] for item in facet_data.get("by_type", []) if item.get("_id")}
        email_count = type_counts.get("email", 0)
        sms_count = type_counts.get("sms", 0)
        url_count = type_counts.get("url", 0)

        trend_map: Dict[tuple[str, str], int] = {}
        for item in facet_data.get("trend", []):
            group_id = item.get("_id") or {}
            day = group_id.get("day")
            level = group_id.get("level")
            if day and level:
                trend_map[(day, level)] = item.get("count", 0)

        trend: List[Dict[str, Any]] = []
        for i in range(6, -1, -1):
            day_dt = today_start - timedelta(days=i)
            day_key = day_dt.strftime("%Y-%m-%d")
            scams = trend_map.get((day_key, "scam"), 0)
            suspicious = trend_map.get((day_key, "suspicious"), 0)
            safe = trend_map.get((day_key, "safe"), 0)
            day_total = scams + suspicious + safe

            trend.append({
                "date": day_dt.strftime("%b %d"),
                "day_name": day_dt.strftime("%a"),
                "day_num": day_dt.strftime("%d"),
                "full_date": day_dt.strftime("%A, %b %d"),
                "is_today": (i == 0),
                "count": day_total,
                "scams": scams,
                "suspicious": suspicious,
                "safe": safe,
            })

        recent: List[Dict[str, Any]] = []
        for doc in facet_data.get("recent", []):
            d = dict(doc)
            if "_id" in d:
                d["id"] = str(d.pop("_id"))
            recent.append(d)

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
    except Exception:
        # Fallback to direct queries if database implementation does not support aggregation
        total = await db.detections.count_documents({"user_id": uid})
        scam_count = await db.detections.count_documents({"user_id": uid, "scam_level": "scam"})
        susp_count = await db.detections.count_documents({"user_id": uid, "scam_level": "suspicious"})
        safe_count = await db.detections.count_documents({"user_id": uid, "scam_level": "safe"})

        email_count = await db.detections.count_documents({"user_id": uid, "detection_type": "email"})
        sms_count = await db.detections.count_documents({"user_id": uid, "detection_type": "sms"})
        url_count = await db.detections.count_documents({"user_id": uid, "detection_type": "url"})

        trend = []
        for i in range(6, -1, -1):
            day_start = today_start - timedelta(days=i)
            day_end = day_start + timedelta(days=1)
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
