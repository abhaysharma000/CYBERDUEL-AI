"""Laboratory Worker configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class LabWorkerSettings(BaseSettings):
    """Configuration for sandboxed laboratory worker."""

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    WORKER_NAME: str = "CyberDuel Lab Worker"
    WORKER_VERSION: str = "0.1.0"
    REDIS_URL: str = "redis://localhost:6379/0"
    SANDBOX_STRICT: bool = True
    ALLOW_EXTERNAL_NETWORK: bool = False
    MAX_CONCURRENT_EXPERIMENTS: int = 2
    EXECUTION_TIMEOUT_SECONDS: int = 60
    POLL_INTERVAL_SECONDS: float = 2.0


worker_settings = LabWorkerSettings()
