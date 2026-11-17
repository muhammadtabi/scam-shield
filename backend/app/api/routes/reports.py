from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from datetime import datetime, timezone
from typing import Optional
import io
import csv
import zoneinfo
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from app.core.dependencies import get_current_user_flexible
from app.db.database import get_db

router = APIRouter()


def _resolve_timezone(tz_name: Optional[str]):
    if tz_name:
        try:
            return zoneinfo.ZoneInfo(tz_name.strip())
        except Exception:
            pass
    local_tz = datetime.now().astimezone().tzinfo
    return local_tz or timezone.utc


def _format_local_timestamp(ts, target_tz) -> str:
    if not ts:
        return ""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(target_tz).strftime("%Y-%m-%d %I:%M:%S %p")
    return str(ts)


@router.get("/csv")
async def download_csv(
    tz: Optional[str] = Query(None, description="Client timezone, e.g. Asia/Karachi"),
    current_user: dict = Depends(get_current_user_flexible),
):
    target_tz = _resolve_timezone(tz)
    db = get_db()
    cursor = db.detections.find(
        {"user_id": current_user["sub"]}
    ).sort("timestamp", -1)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Type", "Scam Level", "Confidence %",
                     "Sender Number/ID", "Reasons", "Timestamp"])

    async for doc in cursor:
        input_data = doc.get("input_data") or {}
        sender_number = ""
        if doc.get("detection_type") == "sms":
            sender_number = input_data.get("sender_id", "")

        writer.writerow([
            str(doc["_id"]),
            doc.get("detection_type", ""),
            doc.get("scam_level", ""),
            doc.get("confidence", ""),
            sender_number,
            " | ".join(doc.get("reasons", [])),
            _format_local_timestamp(doc.get("timestamp"), target_tz),
        ])

    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scam_report.csv"}
    )


@router.get("/pdf")
async def download_pdf(
    tz: Optional[str] = Query(None, description="Client timezone, e.g. Asia/Karachi"),
    current_user: dict = Depends(get_current_user_flexible),
):
    target_tz = _resolve_timezone(tz)
    db = get_db()

    # Get user
    user = None
    try:
        from bson import ObjectId
        user = await db.users.find_one({"_id": ObjectId(current_user["sub"])})
    except Exception:
        pass
    if not user:
        try:
            user = await db.users.find_one({"_id": current_user["sub"]})
        except Exception:
            pass

    user_display = (user.get("full_name") if user and isinstance(user, dict) else "") or current_user.get("sub", "User")

    # Get detections
    detections = []
    cursor = db.detections.find(
        {"user_id": current_user["sub"]}
    ).sort("timestamp", -1).limit(50)
    async for doc in cursor:
        detections.append(doc)

    # Stats
    total      = len(detections)
    scam_count = sum(1 for d in detections if d.get("scam_level") == "scam")
    safe_count = sum(1 for d in detections if d.get("scam_level") == "safe")
    susp_count = sum(1 for d in detections if d.get("scam_level") == "suspicious")

    # Build PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                             rightMargin=72, leftMargin=72,
                             topMargin=72, bottomMargin=72)

    styles = getSampleStyleSheet()
    story  = []

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                  textColor=colors.HexColor("#0ea5e9"),
                                  spaceAfter=6)
    story.append(Paragraph("🛡️ Scam Shield — Detection Report", title_style))

    now_local = datetime.now(timezone.utc).astimezone(target_tz)
    tz_label = now_local.strftime("%Z") or now_local.strftime("%z")
    story.append(Paragraph(
        f"Generated: {now_local.strftime('%Y-%m-%d %I:%M:%S %p')} ({tz_label}) | "
        f"User: {user_display}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.3 * inch))

    # Summary table
    story.append(Paragraph("Summary", styles["Heading2"]))
    summary_data = [
        ["Metric", "Count"],
        ["Total Scans", str(total)],
        ["Scams Detected", str(scam_count)],
        ["Suspicious", str(susp_count)],
        ["Safe", str(safe_count)],
    ]
    t = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#f0f9ff"), colors.white]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROUNDEDCORNERS", [5]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.3 * inch))

    # Detection list
    story.append(Paragraph("Recent Detections", styles["Heading2"]))
    for det in detections[:20]:
        level = det.get("scam_level", "").upper()
        color = "#ef4444" if level == "SCAM" else "#f59e0b" if level == "SUSPICIOUS" else "#22c55e"
        input_data = det.get("input_data") or {}
        story.append(Paragraph(
            f"<font color='{color}'>[{level}]</font> "
            f"<b>{det.get('detection_type', '').upper()}</b> — "
            f"{det.get('confidence', 0):.1f}% confidence",
            styles["Normal"]
        ))
        if det.get("detection_type") == "sms" and input_data.get("sender_id"):
            story.append(Paragraph(
                f"  <b>Sender Number/ID:</b> {input_data.get('sender_id')}",
                styles["Normal"]
            ))
        for reason in det.get("reasons", []):
            story.append(Paragraph(f"  • {reason}", styles["Normal"]))
        time_str = _format_local_timestamp(det.get("timestamp"), target_tz)
        if time_str:
            story.append(Paragraph(
                f"  <i>{time_str}</i>",
                styles["Normal"]
            ))
        story.append(Spacer(1, 0.1 * inch))

    doc.build(story)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=scam_report.pdf"}
    )
