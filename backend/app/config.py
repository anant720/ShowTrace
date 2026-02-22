from pydantic_settings import BaseSettings
from typing import List
import json

class Settings(BaseSettings):
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "shadowtrace"
    API_KEY: str = "shadowtrace-dev-key"
    CORS_ORIGINS: str = '["http://localhost:3000"]'
    JWT_SECRET: str = "shadowtrace-jwt-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "shadowtrace-admin"
    RATE_LIMIT_RPM: int = 60
    LOG_LEVEL: str = "INFO"
    GOOGLE_CLIENT_ID: str = ""
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ANOMALY_INTERVAL_MINUTES: int = 15
    ANOMALY_ZSCORE_THRESHOLD: float = 2.0

    @property
    def cors_origins_list(self) -> List[str]:
        # Default local origins for development
        defaults = ["http://localhost:3000", "http://127.0.0.1:3000"]
        
        if not self.CORS_ORIGINS:
            return defaults
            
        try:
            # Try to parse as JSON array
            origins = json.loads(self.CORS_ORIGINS)
            if isinstance(origins, list):
                # Merge with defaults and remove duplicates
                return list(set(origins + defaults))
        except:
            # Fallback to comma-separated string
            origins = [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]
            if origins:
                return list(set(origins + defaults))
        
        return defaults

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
