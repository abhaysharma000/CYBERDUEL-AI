"""Central application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application Settings
    APP_NAME: str = "CyberDuel AI"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "staging", "production", "test"] = "development"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False

    @field_validator("DEBUG", mode="before")
    @classmethod
    def parse_debug_flag(cls, v: object) -> bool:
        if isinstance(v, str):
            clean = v.strip().lower()
            if clean in ["true", "1", "t", "yes", "debug", "dev"]:
                return True
            if clean in ["false", "0", "f", "no", "release", "prod", "production"]:
                return False
        return bool(v)

    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"
    SECRET_KEY: str = Field(default="dev_secret_key_at_least_32_characters_long_for_security")
    REQUEST_TIMEOUT_SECONDS: int = 30
    MAX_REQUEST_BODY_BYTES: int = 1_048_576  # 1 MB default limit

    # CORS Configuration
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 120

    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///cyberduel_dev.db",
        description="Async database connection string (asyncpg or aiosqlite)",
    )
    DATABASE_URL_SYNC: str = Field(
        default="sqlite:///cyberduel_dev.db",
        description="Synchronous database connection string for Alembic migrations",
    )

    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_URL: str = "redis://localhost:6379/0"

    # AI Provider Settings
    AI_PROVIDER_TYPE: Literal["mock", "qwen", "local", "openai", "anthropic"] = "mock"
    AI_API_KEY: str = ""
    AI_MODEL_NAME: str = "deterministic-mock-v1"
    AI_REASONING_TEMPERATURE: float = 0.2

    # Qwen Open-Source LLM Configuration
    QWEN_API_BASE: str = Field(
        default="https://api.deepinfra.com/v1/openai",
        description="Base URL for OpenAI-compatible Qwen endpoint (e.g. DeepInfra or http://localhost:11434/v1 for Ollama)",
    )
    QWEN_API_KEY: str = Field(
        default="",
        description="API key for hosted Qwen inference; optional for local Ollama/vLLM",
    )
    QWEN_MODEL_NAME: str = Field(
        default="Qwen/Qwen2.5-Coder-7B-Instruct",
        description="Identifies the Qwen model variant to invoke",
    )
    QWEN_TEMPERATURE: float = 0.2
    QWEN_TIMEOUT_SECONDS: float = 15.0

    # Laboratory Worker Configuration
    LAB_WORKER_ENABLED: bool = True
    LAB_SANDBOX_STRICT: bool = True
    LAB_MAX_CONCURRENT_EXPERIMENTS: int = 2
    LAB_EXECUTION_TIMEOUT_SECONDS: int = 60
    LAB_ALLOW_EXTERNAL_NETWORK: bool = False

    # Release Management
    RELEASE_VERIFICATION_KEY_ID: str = "dev-master-key-01"
    RELEASE_VERIFICATION_PUBLIC_KEY: str = ""

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == "test"


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
