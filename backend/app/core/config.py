from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings


BACKEND_ROOT = Path(__file__).resolve().parents[2]

class Settings(BaseSettings):
    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "scamshield"
    SECRET_KEY: str = "change-this-secret-key-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10080 # 7 days
    ALLOWED_ORIGINS: List[str] = ["http://localhost:5173"]
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    class Config:
        env_file = BACKEND_ROOT / ".env"

settings = Settings()
