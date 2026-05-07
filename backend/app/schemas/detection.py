import re
from urllib.parse import urlparse
from pydantic import BaseModel, field_validator, model_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum

class ScamLevel(str, Enum):
    SAFE       = "safe"
    SUSPICIOUS = "suspicious"
    SCAM       = "scam"

class EmailDetectRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    body: str = ""

    @model_validator(mode="before")
    @classmethod
    def validate_email_fields(cls, data):
        if isinstance(data, dict):
            subj = data.get("subject", "").strip()
            sndr = data.get("sender", "").strip()
            bdy = data.get("body", "").strip()

            if not subj and not sndr and not bdy:
                raise ValueError("At least one email field (subject, sender, or body) must be provided")

            return {**data, "subject": subj, "sender": sndr, "body": bdy}
        return data

class SMSDetectRequest(BaseModel):
    sender_id: str
    message: str

    @field_validator("sender_id")
    @classmethod
    def validate_sender_id(cls, value: str) -> str:
        sender = value.strip()
        if not sender:
            raise ValueError("Sender number or ID is required")

        compact = re.sub(r"\s+", "", sender)
        if not (3 <= len(compact) <= 20):
            raise ValueError("Sender must be between 3 and 20 characters")

        # Alphanumeric sender IDs are used globally (e.g. BANKALERT, VK-ICICIB).
        if re.search(r"[A-Za-z]", compact):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,19}", compact):
                raise ValueError("Sender ID must start with a letter and contain only letters, numbers, _ or -")
            return compact

        # Numeric sender values must be full 11-digit phone numbers.
        if not re.fullmatch(r"^[+\d\s().-]+$", sender):
            raise ValueError("Invalid sender number format")

        digits_only = re.sub(r"\D", "", sender)
        if len(digits_only) != 11:
            raise ValueError("Sender number must contain exactly 11 digits")

        return sender

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        message = value.strip()
        if not message:
            raise ValueError("Message content is required")
        return message

class URLDetectRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        url_str = value.strip()
        if not url_str:
            raise ValueError("URL is required")

        if re.search(r"\s", url_str):
            raise ValueError("Please enter only a URL here (not full text or SMS)")
        
        # Add http:// if no schema is provided to let it parse as a proper URL pattern
        if not url_str.lower().startswith(("http://", "https://", "ftp://")):
            url_str = "http://" + url_str

        try:
            parsed = urlparse(url_str)
            host = (parsed.hostname or "").strip().lower()
        except Exception:
            host = ""

        if not host:
            raise ValueError("Please enter a valid URL (example.com or https://example.com)")

        # Accept normal domains and IPv4 hosts, reject plain sentences.
        is_domain = bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}", host))
        is_ipv4 = bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))
        if not (is_domain or is_ipv4):
            raise ValueError("Please enter a valid URL (example.com or https://example.com)")
            
        return url_str

class DetectionResult(BaseModel):
    id: Optional[str] = None
    detection_type: str
    input_data: dict
    scam_level: ScamLevel
    confidence: float
    reasons: List[str]
    explanation: Optional[str] = None
    timestamp: datetime = datetime.utcnow()
    user_id: Optional[str] = None
