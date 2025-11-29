"""
Application configuration settings
"""
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "SBOM Security Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # API Keys for external services
    NVD_API_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None  # Free tier: 30 req/min, get key at https://console.groq.com
    
    # JWT Authentication
    JWT_SECRET_KEY: str = "your-super-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    
    # Database (SQLite for MVP, can be PostgreSQL in production)
    DATABASE_URL: str = "sqlite:///./sbom_platform.db"
    
    # Rate Limiting
    NVD_RATE_LIMIT_DELAY: float = 6.0  # seconds between NVD API calls
    
    # AI Settings (Groq)
    AI_MODEL: str = "llama-3.1-8b-instant"  # Fast & powerful Groq model
    AI_MAX_TOKENS: int = 8000  # Increased to avoid truncation
    
    # CORS
    CORS_ORIGINS: list = ["http://localhost:3000", "http://127.0.0.1:3000"]
    
    # File Upload
    MAX_UPLOAD_SIZE: int = 10 * 1024 * 1024  # 10MB
    
    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

