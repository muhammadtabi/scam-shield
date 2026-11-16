from datetime import datetime, timezone
from typing import List, Optional, Dict
from app.db.database import get_db
from app.schemas.training import (
    ScenarioType,
    DifficultyLevel,
    TrainingScenarioPublic,
    TrainingSubmissionRequest,
    TrainingEvaluationResult,
    TrainingUserStats
)
from app.ml.predictor import detect_email, detect_sms, detect_url

# Curated training scenarios for security awareness
SCENARIOS: List[Dict] = [
    {
        "id": "scn_email_netflix_scam",
        "type": ScenarioType.email,
        "title": "Urgent Subscription Renewal Notice",
        "difficulty": DifficultyLevel.beginner,
        "sender": "Netflix Billing <support@netflx-account-renew.xyz>",
        "subject": "Important: Your account has been temporarily placed on hold",
        "content": "Dear Customer,\n\nWe were unable to validate your billing details for the next subscription cycle. Your access will be terminated within 24 hours unless you confirm your payment card.\n\nVerify immediately: https://netflx-account-renew.xyz/update-billing\n\nNetflix Customer Care Team",
        "url": "https://netflx-account-renew.xyz/update-billing",
        "actual_verdict": "scam",
        "clue_options": [
            "Mismatched sender domain (netflx-account-renew.xyz instead of netflix.com)",
            "Artificial 24-hour urgency deadline",
            "Generic salutation ('Dear Customer')",
            "Request for payment details via external link"
        ],
        "correct_clues": [
            "Mismatched sender domain (netflx-account-renew.xyz instead of netflix.com)",
            "Artificial 24-hour urgency deadline",
            "Generic salutation ('Dear Customer')",
            "Request for payment details via external link"
        ],
        "key_takeaway": "Legitimate streaming providers never use hyphenated .xyz domains or threaten 24-hour account termination."
    },
    {
        "id": "scn_sms_chase_otp_safe",
        "type": ScenarioType.sms,
        "title": "Bank Login Verification Code",
        "difficulty": DifficultyLevel.beginner,
        "sender": "8558",
        "subject": None,
        "content": "8558: 492011 is your Chase online banking code. We will never call or text asking for this code. Do not share it with anyone.",
        "url": None,
        "actual_verdict": "safe",
        "clue_options": [
            "Official 4-digit carrier shortcode (8558)",
            "Explicit instruction not to share the code with anyone",
            "No external links requesting login credentials",
            "Standard multi-factor authentication format"
        ],
        "correct_clues": [
            "Official 4-digit carrier shortcode (8558)",
            "Explicit instruction not to share the code with anyone",
            "No external links requesting login credentials",
            "Standard multi-factor authentication format"
        ],
        "key_takeaway": "Genuine bank OTPs come from registered shortcodes, include explicit confidentiality warnings, and never ask you to click a link."
    },
    {
        "id": "scn_url_userinfo_auth_scam",
        "type": ScenarioType.url,
        "title": "Payment Verification Link",
        "difficulty": DifficultyLevel.intermediate,
        "sender": None,
        "subject": None,
        "content": "A link sent via chat asking you to verify a PayPal transaction: https://paypal.com@verify-identity-billing.com/signin",
        "url": "https://paypal.com@verify-identity-billing.com/signin",
        "actual_verdict": "scam",
        "clue_options": [
            "Basic Authentication '@' trick pointing to 'verify-identity-billing.com'",
            "Deceptive brand name placed before the '@' symbol",
            "Non-official PayPal hostname",
            "Unsolicited payment resolution link"
        ],
        "correct_clues": [
            "Basic Authentication '@' trick pointing to 'verify-identity-billing.com'",
            "Deceptive brand name placed before the '@' symbol",
            "Non-official PayPal hostname",
            "Unsolicited payment resolution link"
        ],
        "key_takeaway": "In a URL, text before '@' is treated as a username/credential; the actual destination domain is what appears AFTER the '@'."
    },
    {
        "id": "scn_email_cloudflare_safe",
        "type": ScenarioType.email,
        "title": "Security Advisory Digest",
        "difficulty": DifficultyLevel.intermediate,
        "sender": "Cloudflare Radar <radar-reports@cloudflare.com>",
        "subject": "Monthly Internet Disruption Summary - October",
        "content": "Hello,\n\nOur October Internet Disruption report is now published on Cloudflare Radar. This edition covers recent subsea cable maintenance and regional traffic shifts.\n\nRead the full report on our blog: https://blog.cloudflare.com/securing-paypal-and-apple-payments\n\nYou can manage your subscription preferences at any time.",
        "url": "https://blog.cloudflare.com/securing-paypal-and-apple-payments",
        "actual_verdict": "safe",
        "clue_options": [
            "Authenticated official corporate domain (cloudflare.com)",
            "Informational digest with no credential requests",
            "Legitimate blog URL path on primary domain",
            "Standard unsubscribe options"
        ],
        "correct_clues": [
            "Authenticated official corporate domain (cloudflare.com)",
            "Informational digest with no credential requests",
            "Legitimate blog URL path on primary domain",
            "Standard unsubscribe options"
        ],
        "key_takeaway": "Legitimate security newsletters direct users to verified corporate subdomains without demanding passwords or urgency."
    },
    {
        "id": "scn_sms_usps_delivery_scam",
        "type": ScenarioType.sms,
        "title": "Postal Package Delivery Notice",
        "difficulty": DifficultyLevel.intermediate,
        "sender": "+14159821102",
        "subject": None,
        "content": "USPS: Your package could not be delivered due to an incomplete street address. Please update your address within 12 hours or item will be returned: http://usps-parcel-track.xyz",
        "url": "http://usps-parcel-track.xyz",
        "actual_verdict": "scam",
        "clue_options": [
            "Unofficial 10-digit mobile number instead of USPS shortcode",
            "Fake .xyz domain spoofing postal service",
            "Artificial 12-hour urgency deadline",
            "Unsolicited tracking link"
        ],
        "correct_clues": [
            "Unofficial 10-digit mobile number instead of USPS shortcode",
            "Fake .xyz domain spoofing postal service",
            "Artificial 12-hour urgency deadline",
            "Unsolicited tracking link"
        ],
        "key_takeaway": "Postal services never send tracking links from standard mobile phone numbers or third-party .xyz domains."
    },
    {
        "id": "scn_url_subdomain_spoof_scam",
        "type": ScenarioType.url,
        "title": "Corporate Single Sign-On Portal",
        "difficulty": DifficultyLevel.advanced,
        "sender": None,
        "subject": None,
        "content": "URL received for enterprise portal login: https://login.microsoftonline.com.account-update.info/auth",
        "url": "https://login.microsoftonline.com.account-update.info/auth",
        "actual_verdict": "scam",
        "clue_options": [
            "Multi-level subdomain spoofing microsoftonline.com",
            "Actual registrable domain is 'account-update.info'",
            "Deceptive hostname nesting designed to fool visual inspection",
            "Suspicious TLD (.info) for enterprise identity services"
        ],
        "correct_clues": [
            "Multi-level subdomain spoofing microsoftonline.com",
            "Actual registrable domain is 'account-update.info'",
            "Deceptive hostname nesting designed to fool visual inspection",
            "Suspicious TLD (.info) for enterprise identity services"
        ],
        "key_takeaway": "Always look at the domain right before the first single slash '/'. Subdomains can say anything, but the registrable domain is what counts."
    },
    {
        "id": "scn_sms_carrier_renewal_safe",
        "type": ScenarioType.sms,
        "title": "Mobile Plan Monthly Renewal",
        "difficulty": DifficultyLevel.advanced,
        "sender": "3737",
        "subject": None,
        "content": "Your mobile plan auto-pay of $45 will process on Nov 16. To review your billing statement or payment methods, log in to your account app.",
        "url": None,
        "actual_verdict": "safe",
        "clue_options": [
            "Carrier standard shortcode (3737)",
            "Advises logging in via official app rather than clicking a link",
            "No sensitive personal info requested",
            "Standard periodic billing reminder"
        ],
        "correct_clues": [
            "Carrier standard shortcode (3737)",
            "Advises logging in via official app rather than clicking a link",
            "No sensitive personal info requested",
            "Standard periodic billing reminder"
        ],
        "key_takeaway": "Safe corporate notifications recommend logging into your existing mobile app instead of providing external web links."
    },
    {
        "id": "scn_email_ceo_wire_scam",
        "type": ScenarioType.email,
        "title": "Executive Urgent Wire Transfer",
        "difficulty": DifficultyLevel.advanced,
        "sender": "David Miller (CEO) <david.miller.office1@gmail.com>",
        "subject": "Quick task - Confidential Acquisition",
        "content": "Hi,\n\nI am currently in an all-day board meeting and cannot take calls. We are finalizing an urgent vendor deposit for a confidential acquisition. Please process an expedited wire of $18,400 to the attached account today.\n\nKeep this strictly confidential until the press release tomorrow.\n\nBest,\nDavid Miller\nChief Executive Officer",
        "url": None,
        "actual_verdict": "scam",
        "clue_options": [
            "CEO display name paired with a free personal Gmail address",
            "High-pressure urgency coupled with phone/call unavailability",
            "Circumvention of standard finance approval procedures",
            "Demand for strict secrecy and confidential wire transfer"
        ],
        "correct_clues": [
            "CEO display name paired with a free personal Gmail address",
            "High-pressure urgency coupled with phone/call unavailability",
            "Circumvention of standard finance approval procedures",
            "Demand for strict secrecy and confidential wire transfer"
        ],
        "key_takeaway": "Business Email Compromise (BEC) often uses executive display-name spoofing on free email providers to bypass approval processes."
    }
]

def calculate_rank_tier(accuracy: float, total: int) -> str:
    if total < 3:
        return "Security Cadet"
    if accuracy >= 90:
        return "Threat Guardian"
    if accuracy >= 75:
        return "Phishing Specialist"
    if accuracy >= 60:
        return "Threat Scout"
    return "Security Cadet"

def get_all_scenarios_public() -> List[TrainingScenarioPublic]:
    result = []
    for s in SCENARIOS:
        result.append(TrainingScenarioPublic(
            id=s["id"],
            type=s["type"],
            title=s["title"],
            difficulty=s["difficulty"],
            sender=s["sender"],
            subject=s["subject"],
            content=s["content"],
            url=s["url"],
            clue_options=s["clue_options"]
        ))
    return result

async def get_user_training_stats(user_id: str) -> TrainingUserStats:
    db = get_db()
    cursor = db.training_records.find({"user_id": user_id})
    records = []
    async for r in cursor:
        records.append(r)

    total = len(records)
    if total == 0:
        return TrainingUserStats(
            total_attempted=0,
            total_correct=0,
            accuracy_percent=0.0,
            current_streak=0,
            rank_tier="Security Cadet"
        )

    correct_count = sum(1 for r in records if r.get("is_correct", False))
    accuracy = round((correct_count / total) * 100, 1)

    # Calculate streak (most recent consecutive correct answers)
    records.sort(key=lambda x: x.get("timestamp", datetime.min), reverse=True)
    streak = 0
    for r in records:
        if r.get("is_correct", False):
            streak += 1
        else:
            break

    tier = calculate_rank_tier(accuracy, total)
    return TrainingUserStats(
        total_attempted=total,
        total_correct=correct_count,
        accuracy_percent=accuracy,
        current_streak=streak,
        rank_tier=tier
    )

async def evaluate_user_submission(user_id: str, submission: TrainingSubmissionRequest) -> TrainingEvaluationResult:
    scenario = next((s for s in SCENARIOS if s["id"] == submission.scenario_id), None)
    if not scenario:
        raise ValueError("Scenario not found")

    user_verdict = submission.user_verdict.strip().lower()
    actual_verdict = scenario["actual_verdict"].strip().lower()
    is_correct = (user_verdict == actual_verdict)

    # Run ML model to compare ground truth with ML prediction
    if scenario["type"] == ScenarioType.email:
        ml_eval = detect_email(scenario["subject"] or "", scenario["sender"] or "", scenario["content"])
    elif scenario["type"] == ScenarioType.sms:
        ml_eval = detect_sms(scenario["sender"] or "Unknown", scenario["content"])
    else: # url
        ml_eval = detect_url(scenario["url"] or scenario["content"])

    ml_conf = float(ml_eval.get("confidence", 95.0))
    ml_reasons = ml_eval.get("reasons", [])
    explanation = ml_eval.get("explanation", scenario["key_takeaway"])

    # Score calculation: 100 points for correct verdict + 25 for each valid clue detected
    base_points = 100 if is_correct else 0
    clue_points = sum(25 for c in submission.selected_clues if c in scenario["correct_clues"])
    total_score = base_points + clue_points

    # Save training record
    db = get_db()
    await db.training_records.update_one(
        {"user_id": user_id, "scenario_id": scenario["id"]},
        {"$set": {
            "user_id": user_id,
            "scenario_id": scenario["id"],
            "user_verdict": user_verdict,
            "is_correct": is_correct,
            "score": total_score,
            "timestamp": datetime.now(timezone.utc)
        }},
        upsert=True
    )

    stats = await get_user_training_stats(user_id)

    return TrainingEvaluationResult(
        scenario_id=scenario["id"],
        user_verdict=user_verdict,
        actual_verdict=actual_verdict,
        is_correct=is_correct,
        ml_confidence=ml_conf,
        ml_reasons=ml_reasons,
        explanation=explanation,
        key_takeaway=scenario["key_takeaway"],
        correct_clues=scenario["correct_clues"],
        total_score=total_score,
        user_stats=stats.model_dump()
    )

async def reset_user_training(user_id: str):
    db = get_db()
    await db.training_records.delete_many({"user_id": user_id})
    return {"message": "Training progress reset successfully"}

