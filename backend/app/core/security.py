import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

def _pre_hash_password(password: str) -> str:
    """Pre-hash password with SHA-256 to produce a constant 64-char hex digest,
    preventing multi-byte UTF-8 crashes and bcrypt 72-byte truncation."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def hash_password(password: str) -> str:
    return pwd_context.hash(_pre_hash_password(password))

def verify_password(plain: str, hashed: str) -> bool:
    if not plain or not hashed:
        return False
    try:
        # 1. Check modern SHA-256 pre-hashed format (Fix 8)
        if pwd_context.verify(_pre_hash_password(plain), hashed):
            return True
    except Exception:
        pass

    try:
        # 2. Check direct plaintext bcrypt (standard legacy accounts)
        if pwd_context.verify(plain, hashed):
            return True
    except Exception:
        pass

    try:
        # 3. Check legacy 72-byte truncated plain
        return pwd_context.verify(plain.encode("utf-8")[:72].decode("utf-8", errors="ignore"), hashed)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None


def _secret_fernet() -> Fernet:
    digest = hashlib.sha256(f"{settings.SECRET_KEY}:scamshield-imap-v1".encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str) -> str:
    """Encrypt sensitive third-party credentials (such as IMAP App Passwords) at rest."""
    return _secret_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored credential encrypted via encrypt_secret."""
    try:
        return _secret_fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise ValueError("Stored mailbox credential could not be decrypted. Please reconnect.") from exc