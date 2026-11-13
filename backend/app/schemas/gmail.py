from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, field_validator


class GmailConnectionStatus(BaseModel):
    connected: bool
    email_address: Optional[EmailStr] = None
    enabled: bool = False
    auth_type: Optional[str] = None
    last_checked_at: Optional[datetime] = None
    last_synced_message_id: Optional[str] = None
    error: Optional[str] = None


class GmailImapConnectRequest(BaseModel):
    email: EmailStr
    app_password: str
    provider: Literal["gmail", "outlook", "yahoo", "zoho"] = "gmail"

    @field_validator("app_password")
    @classmethod
    def validate_app_password(cls, value: str) -> str:
        compact = "".join(str(value or "").split())
        if len(compact) < 8 or len(compact) > 64:
            raise ValueError("App Password must be between 8 and 64 non-space characters")
        return compact


class GmailConnectResponse(BaseModel):
    auth_url: str


class GmailCallbackRequest(BaseModel):
    code: str
    state: Optional[str] = None


class GmailSyncResponse(BaseModel):
    processed: int
    stored_detection_ids: list[str]