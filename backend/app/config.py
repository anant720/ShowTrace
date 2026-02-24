from pydantic_settings import BaseSettings
from typing import List
import json

class Settings(BaseSettings):
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "shadowtrace"
    API_KEY: str = "st_api_kG9vX2mN8pL4wR5tZ1yQ7jS4nB0hF3d_"
    CORS_ORIGINS: str = '["http://localhost:3000"]'
    JWT_SECRET: str = "shadowtrace-jwt-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "shadowtrace-admin"
    RATE_LIMIT_RPM: int = 60
    LOG_LEVEL: str = "INFO"
    GOOGLE_CLIENT_ID: str = "661283807918-7m7u6942b6q91u80lvvshmgp1emnacfu.apps.googleusercontent.com"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ANOMALY_INTERVAL_MINUTES: int = 15
    ANOMALY_ZSCORE_THRESHOLD: float = 2.0
    DEVICE_OFFLINE_MINUTES: int = 30
    EXPORT_SIGNING_KEY: str = "shadowtrace-export-signing-key-change-in-production"

    # Email (SendGrid)
    SENDGRID_API_KEY: str = ""
    MAIL_FROM: str = ""
    DASHBOARD_BASE_URL: str = "http://localhost:3000"

    # Email (SMTP) - easiest: Gmail + App Password
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""

    @property
    def cors_origins_list(self) -> List[str]:
        try:
            # Expect CORS_ORIGINS as a JSON array string, e.g.
            # '["https://shadow-trace-eight.vercel.app", "http://localhost:3000"]'
            return json.loads(self.CORS_ORIGINS)
        except Exception:
            # Safe fallback during misconfiguration
            return ["*"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
