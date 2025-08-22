# backend/api-gateway/config/settings.py
"""
CyberShield AI Platform - API Gateway Settings
Configuration management with environment variables
"""

from pydantic import BaseSettings, validator
from typing import List, Optional
import os
from pathlib import Path

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application settings
    APP_NAME: str = "CyberShield AI Platform - API Gateway"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    
    # Security settings
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS settings
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",  # SOC Dashboard
        "http://localhost:3001",  # Admin Panel
        "http://localhost:3002",  # Executive Dashboard
        "https://cybershield.local",
        "https://*.cybershield.ai"
    ]
    ALLOWED_HOSTS: List[str] = ["*"]
    
    # Redis settings (for caching and rate limiting)
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    
    # Database settings
    DATABASE_URL: str = "postgresql://cybershield:password@localhost:5432/cybershield_main"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    
    # Microservices endpoints
    SOC_SERVICE_HOST: str = "localhost"
    SOC_SERVICE_PORT: int = 8001
    
    THREAT_SERVICE_HOST: str = "localhost"
    THREAT_SERVICE_PORT: int = 8002
    
    VULN_SERVICE_HOST: str = "localhost"
    VULN_SERVICE_PORT: int = 8003
    
    PHISHING_SERVICE_HOST: str = "localhost"
    PHISHING_SERVICE_PORT: int = 8004
    
    HONEYPOT_SERVICE_HOST: str = "localhost"
    HONEYPOT_SERVICE_PORT: int = 8005
    
    INCIDENT_SERVICE_HOST: str = "localhost"
    INCIDENT_SERVICE_PORT: int = 8006
    
    INTEL_SERVICE_HOST: str = "localhost"
    INTEL_SERVICE_PORT: int = 8007
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Monitoring
    METRICS_ENABLED: bool = True
    HEALTH_CHECK_INTERVAL: int = 30
    
    # JWT Settings
    JWT_SECRET_KEY: str = "your-jwt-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_EXPIRE_DAYS: int = 30
    
    # API Documentation
    DOCS_ENABLED: bool = True
    OPENAPI_URL: str = "/api/v1/openapi.json"
    DOCS_URL: str = "/api/v1/docs"
    REDOC_URL: str = "/api/v1/redoc"
    
    # SSL/TLS
    USE_SSL: bool = False
    SSL_CERT_PATH: Optional[str] = None
    SSL_KEY_PATH: Optional[str] = None
    
    # Email settings (for alerts)
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    
    # Admin settings
    ADMIN_EMAIL: str = "admin@cybershield.local"
    ADMIN_PASSWORD: str = "admin123"  # Change in production!
    
    # Feature flags
    ENABLE_SOC_MODULE: bool = True
    ENABLE_THREAT_DETECTION: bool = True
    ENABLE_VULNERABILITY_MANAGEMENT: bool = True
    ENABLE_ANTI_PHISHING: bool = True
    ENABLE_HONEYPOT_NETWORK: bool = True
    ENABLE_INCIDENT_RESPONSE: bool = True
    ENABLE_THREAT_INTELLIGENCE: bool = True
    
    # External integrations
    VIRUS_TOTAL_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    MITRE_ATTACK_DATA_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    # File upload settings
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_FILE_EXTENSIONS: List[str] = [".pcap", ".log", ".json", ".csv", ".txt"]
    UPLOAD_DIR: str = "/tmp/cybershield/uploads"
    
    # Cache settings
    CACHE_ENABLED: bool = True
    CACHE_TTL: int = 300  # 5 minutes
    CACHE_MAX_SIZE: int = 1000
    
    @validator("ALLOWED_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("ALLOWED_HOSTS", pre=True)  
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    @validator("ALLOWED_FILE_EXTENSIONS", pre=True)
    def parse_file_extensions(cls, v):
        if isinstance(v, str):
            return [ext.strip() for ext in v.split(",")]
        return v
    
    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        if not v.startswith(("postgresql://", "sqlite:///")):
            raise ValueError("Database URL must be PostgreSQL or SQLite")
        return v
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode"""
        return self.DEBUG
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode"""
        return not self.DEBUG
    
    def get_service_url(self, service_name: str) -> str:
        """Get full URL for a microservice"""
        service_mapping = {
            "soc-intelligence": f"http://{self.SOC_SERVICE_HOST}:{self.SOC_SERVICE_PORT}",
            "threat-detection": f"http://{self.THREAT_SERVICE_HOST}:{self.THREAT_SERVICE_PORT}",
            "vulnerability-management": f"http://{self.VULN_SERVICE_HOST}:{self.VULN_SERVICE_PORT}",
            "anti-phishing": f"http://{self.PHISHING_SERVICE_HOST}:{self.PHISHING_SERVICE_PORT}",
            "honeypot-network": f"http://{self.HONEYPOT_SERVICE_HOST}:{self.HONEYPOT_SERVICE_PORT}",
            "incident-response": f"http://{self.INCIDENT_SERVICE_HOST}:{self.INCIDENT_SERVICE_PORT}",
            "threat-intelligence": f"http://{self.INTEL_SERVICE_HOST}:{self.INTEL_SERVICE_PORT}",
        }
        return service_mapping.get(service_name, "")
    
    def get_redis_url(self) -> str:
        """Get Redis connection URL"""
        auth_part = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth_part}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        
        # Environment variable prefixes
        env_prefix = "CYBERSHIELD_"
        
        @classmethod
        def customise_sources(
            cls,
            init_settings,
            env_settings,
            file_secret_settings,
        ):
            """Customize settings sources priority"""
            return (
                init_settings,
                env_settings,
                file_secret_settings,
            )

# Create global settings instance
settings = Settings()

# Validate critical settings on import
def validate_critical_settings():
    """Validate critical settings that must be set"""
    critical_settings = []
    
    if settings.SECRET_KEY == "your-super-secret-key-change-in-production":
        critical_settings.append("SECRET_KEY must be changed in production")
    
    if settings.JWT_SECRET_KEY == "your-jwt-secret-key-change-in-production":
        critical_settings.append("JWT_SECRET_KEY must be changed in production")
    
    if settings.is_production and settings.ADMIN_PASSWORD == "admin123":
        critical_settings.append("ADMIN_PASSWORD must be changed in production")
    
    if critical_settings:
        print("⚠️  CRITICAL SECURITY WARNINGS:")
        for warning in critical_settings:
            print(f"   - {warning}")
        print()

# Run validation on import
validate_critical_settings()