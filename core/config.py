from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Splunk
    splunk_url: str = "https://localhost:8089"
    splunk_token: str = ""
    splunk_username: str = "admin"
    splunk_password: str = "changeme"
    splunk_verify_ssl: bool = False

    # MCP
    mcp_endpoint: str = "http://localhost:8765"
    mcp_token: str = ""

    # Industry
    industry_profile: str = "healthcare"

    # Anthropic
    anthropic_api_key: str = ""

    # Database
    database_url: str = "sqlite:///./detectforge.db"

    # App tuning
    log_level: str = "INFO"
    drift_monitor_interval_hours: int = 6
    max_spl_generation_attempts: int = 3
    max_tuning_rounds: int = 3
    hits_per_day_good_threshold: int = 50
    hits_per_day_very_noisy_threshold: int = 500
    confidence_mandatory_review_threshold: float = 0.75
    confidence_generation_min: float = 0.70


@lru_cache
def get_settings() -> Settings:
    return Settings()
