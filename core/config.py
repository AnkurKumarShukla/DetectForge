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

    # Splunk HEC — agent activity logger ("DetectForge — Agent Activity" view).
    # Ships every agent action to a `detectforge` index so the live reasoning/
    # actions are visible inside Splunk itself (the "agentic ops" story).
    hec_url: str = "https://localhost:8088"
    hec_token: str = ""
    hec_index: str = "detectforge"
    hec_sourcetype: str = "detectforge:agent"
    hec_enabled: bool = True

    # Industry
    industry_profile: str = "healthcare"

    # Together AI — primary model for NL interface and SPL generation
    together_api_key: str = ""
    together_model: str = "meta-llama/Llama-3.3-70B-Instruct-Turbo"

    # Fine-tuned SPL model (optional — set both to activate)
    # After fine-tuning on spl_finetune.jsonl, set to your Together AI model ID
    # e.g. FINETUNED_MODEL_ID=ankur/foundation-sec-spl-v1  USE_FINETUNED_SPL=true
    finetuned_model_id: str = ""
    use_finetuned_spl: bool = False

    # Splunk Hosted Models via Together AI (for ATT&CK classification + SPL review)
    # GPT-OSS is an official Splunk hosted model, available via Together AI
    splunk_hosted_model: str = "openai/gpt-oss-20b"
    splunk_hosted_model_large: str = "openai/gpt-oss-120b"

    # Database
    database_url: str = "sqlite:///./detectforge.db"

    # App tuning
    log_level: str = "INFO"
    drift_monitor_interval_hours: int = 6
    # Real-time drift checks (rule-fired-recently, data-freshness) require LIVE
    # data. Disable them when running against a static/historical dataset like
    # BOTS v3 so schema-drift (field-existence) is the clean health signal.
    drift_silent_check_enabled: bool = True
    drift_freshness_check_enabled: bool = True
    # Self-healing: on drift, regenerate + redeploy the detection automatically
    drift_auto_regenerate: bool = True
    max_spl_generation_attempts: int = 3
    max_tuning_rounds: int = 3
    hits_per_day_good_threshold: int = 50
    hits_per_day_very_noisy_threshold: int = 500
    confidence_mandatory_review_threshold: float = 0.75
    confidence_generation_min: float = 0.70


@lru_cache
def get_settings() -> Settings:
    return Settings()
