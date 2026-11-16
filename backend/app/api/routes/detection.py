from fastapi import APIRouter, Depends, HTTPException, status
from datetime import datetime
from typing import Optional
from bson import ObjectId
from app.schemas.detection import EmailDetectRequest, SMSDetectRequest, URLDetectRequest
from app.core.dependencies import get_current_user, get_optional_current_user
from app.db.database import get_db
from app.ml.predictor import detect_email, detect_sms, detect_url

router = APIRouter()

async def save_detection(result: dict, user_id: str):
    """Save detection result to MongoDB"""
    db = get_db()
    doc = {**result, "user_id": user_id, "timestamp": datetime.utcnow()}
    inserted = await db.detections.insert_one(doc)
    return str(inserted.inserted_id)

@router.post("/email")
async def detect_email_route(
    request: EmailDetectRequest,
    current_user: dict = Depends(get_current_user)
):
    result = detect_email(request.subject, request.sender, request.body)
    if "error" not in result:
        result["id"] = await save_detection(result, current_user["sub"])
    return result

@router.post("/sms")
async def detect_sms_route(
    request: SMSDetectRequest,
    current_user: dict = Depends(get_current_user)
):
    result = detect_sms(request.sender_id, request.message)
    if "error" not in result:
        result["id"] = await save_detection(result, current_user["sub"])
    return result

@router.post("/url")
async def detect_url_route(
    request: URLDetectRequest,
    current_user: Optional[dict] = Depends(get_optional_current_user)
):
    result = detect_url(request.url)
    if "error" not in result and current_user:
        result["id"] = await save_detection(result, current_user["sub"])
    return result

@router.get("/history")
async def get_history(
    limit: int = 20,
    skip: int = 0,
    current_user: dict = Depends(get_current_user)
):
    db = get_db()
    cursor = db.detections.find(
        {"user_id": current_user["sub"]}
    ).sort("timestamp", -1).skip(skip).limit(limit)

    results = []
    async for doc in cursor:
        doc["id"] = str(doc.pop("_id"))
        results.append(doc)

    total = await db.detections.count_documents({"user_id": current_user["sub"]})
    return {"total": total, "results": results}

@router.delete("/history/{detection_id}")
async def delete_detection(
    detection_id: str,
    current_user: dict = Depends(get_current_user)
):
    if not ObjectId.is_valid(detection_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid detection ID format"
        )
    db = get_db()
    result = await db.detections.delete_one({
        "_id": ObjectId(detection_id),
        "user_id": current_user["sub"]
    })
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Detection not found"
        )
    return {"message": "Deleted successfully"}
