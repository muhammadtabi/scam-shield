from datetime import datetime
from typing import List, Optional
import re
from pydantic import BaseModel, Field, field_validator


class SMSConnectRequest(BaseModel):
    phone_number: str

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        phone = value.strip()
        if not phone:
            raise ValueError("Phone number is required")

        cleaned = re.sub(r"[\s().-]", "", phone)
        # Accept international format (+1234567890) or standard 7-15 digit phone numbers
        if not re.fullmatch(r"^\+?\d{7,15}$", cleaned):
            raise ValueError("Enter a valid phone number with 7 to 15 digits (e.g. +14155552671)")
        return phone


class SMSConnectionStatus(BaseModel):
    connected: bool
    phone_number: Optional[str] = None
    sync_token: Optional[str] = None
    total_messages: int = 0
    scam_count: int = 0
    suspicious_count: int = 0
    safe_count: int = 0
    updated_at: Optional[datetime] = None


class SMSIngestRequest(BaseModel):
    sender_id: str
    message: str
    timestamp: Optional[datetime] = None

    @field_validator("sender_id")
    @classmethod
    def validate_sender(cls, value: str) -> str:
        s = value.strip()
        if not s:
            raise ValueError("Sender number or shortcode is required")
        return s

    @field_validator("message")
    @classmethod
    def validate_body(cls, value: str) -> str:
        m = value.strip()
        if not m:
            raise ValueError("Message body cannot be empty")
        return m


class SMSInboxItem(BaseModel):
    id: str
    sender_id: str
    message: str
    timestamp: datetime
    scam_level: str
    confidence: float
    reasons: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None
    is_read: bool = False


class SMSInboxResponse(BaseModel):
    messages: List[SMSInboxItem]
    total: int
    page: int
    pages: int
    scam_count: int = 0
    suspicious_count: int = 0
    safe_count: int = 0


class SMSSimulateRequest(BaseModel):
    preset: Optional[str] = None
    sender_id: Optional[str] = None
    message: Optional[str] = None


class SMSBatchImportRequest(BaseModel):
    messages: List[SMSIngestRequest] = Field(..., max_length=200)


class SMSBatchImportResponse(BaseModel):
    imported_count: int
    scam_count: int = 0
    suspicious_count: int = 0
    safe_count: int = 0
    messages: List[SMSInboxItem] = Field(default_factory=list)


