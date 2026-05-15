"""
Mr. Robot Scanner - Configuration Settings
"""

import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from typing import Optional

load_dotenv()


class Settings(BaseSettings):
    """Application settings"""
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./mr_robot.db")
    
    # JWT
    SECRET_KEY: str = os.getenv("SECRET_KEY", "mr-robot-secret-key-change-this")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
    
    # Scanner
    SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "300"))
    MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))
    
    # API
    API_V1_PREFIX: str = "/api/v1"

    class Config:
        env_file = ".env"
        extra = "ignore"  # ← THIS FIXES THE ERROR


settings = Settings()
