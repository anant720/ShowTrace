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

    @property
    def cors_origins_list(self) -> List[str]:
        return ["*"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
