"""
Application configuration.

Settings are loaded from environment variables (see backend/.env.example).
Nothing here contains real secrets -- values are safe placeholders that
must be overridden in a real deployment.
"""
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Core ---
    APP_NAME: str = "MalLens"
    SECRET_KEY: str = "change-me-in-production"
    DEBUG: bool = False
    ENV: str = "development"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://mallens:mallens_pass@db:5432/mallens_db"

    # --- Queue ---
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    # --- Storage ---
    UPLOAD_DIR: str = "/app/uploads"
    MAX_UPLOAD_SIZE_MB: int = 100
    RETENTION_DAYS: int = 30

    # --- Auth ---
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    JWT_ALGORITHM: str = "HS256"
    REQUIRE_AUTH: bool = False  # if False, endpoints are usable without a login (demo mode)

    # --- Dynamic sandbox ---
    # "stub"   -> safe, deterministic, no code from the sample is ever executed (default, no extra infra needed)
    # "cuckoo" -> talk to a real Cuckoo Sandbox REST API you provide (requires you to run Cuckoo yourself)
    DYNAMIC_SANDBOX_PROVIDER: str = "stub"
    CUCKOO_API_URL: Optional[str] = None
    CUCKOO_API_TOKEN: Optional[str] = None
    DYNAMIC_ANALYSIS_TIMEOUT_SECONDS: int = 180

    # --- Threat intel (all optional; features degrade gracefully without keys) ---
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None

    # --- AI report summaries (optional) ---
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:3000"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def broker_url(self) -> str:
        return self.CELERY_BROKER_URL or self.REDIS_URL

    @property
    def result_backend(self) -> str:
        return self.CELERY_RESULT_BACKEND or self.REDIS_URL

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
