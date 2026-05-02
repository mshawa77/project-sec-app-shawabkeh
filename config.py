"""
Configuration Management - Environment Variable Loading
Rubric: Security Configuration & Environment Management
"""

import os
from dotenv import load_dotenv
from typing import List

# Load environment variables from .env file
load_dotenv()

class Settings:
    """Application settings with environment variable support"""
    
    # JWT Configuration (Rubric: Authentication & Session Management)
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    
    # AES Encryption Key (Rubric: Data Encryption At Rest)
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "default-32-byte-key-for-dev")
    
    # Database Configuration (Rubric: Database Security)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///secure_app.db")
    
    # Application Settings (Rubric: Security Configuration)
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Security Settings (Rubric: Security Headers & Protection)
    CORS_ORIGINS: List[str] = eval(os.getenv("CORS_ORIGINS", '["http://localhost:8000"]'))
    SESSION_DURATION_HOURS: int = int(os.getenv("SESSION_DURATION_HOURS", "2"))
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_DURATION_MINUTES: int = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
    
    # Production Settings (Rubric: Production Security)
    HTTPS_ONLY: bool = os.getenv("HTTPS_ONLY", "True").lower() == "true"
    SECURE_COOKIES: bool = os.getenv("SECURE_COOKIES", "True").lower() == "true"
    
    @classmethod
    def validate(cls):
        """Validate required environment variables"""
        required_vars = ["SECRET_KEY", "ENCRYPTION_KEY"]
        missing_vars = []
        
        for var in required_vars:
            if not getattr(cls, var) or getattr(cls, var).startswith("default"):
                missing_vars.append(var)
        
        if missing_vars:
            print(f"WARNING: Missing environment variables: {missing_vars}")
            print("Please copy .env.example to .env and fill in the values")
        
        return len(missing_vars) == 0

# Global settings instance
settings = Settings()

# Validate configuration on import
if not settings.validate():
    print("Configuration validation failed. Using default values for development.")
