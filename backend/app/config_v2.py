"""
AIPAM V2 configuration — consolidated environment variables (§1.6).

All AIPAM_* env vars are defined here as a single Pydantic Settings class.
Loaded once at startup; injected via FastAPI dependency or direct import.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field, model_validator


class SensorPaths(BaseSettings):
    """Non-secret handler configuration; child processes never need API credentials."""
    aipam_suricata_rules_dir: Path = Path("/opt/aipam/rules/suricata")
    aipam_yara_rules_dir: Path = Path("/opt/aipam/rules/yara")
    model_config = {"env_file": None, "extra": "ignore"}


class Settings(BaseSettings):
    """AIPAM V2 settings from environment variables."""

    # --- Auth ---
    aipam_api_token: str  # Required — no default
    # Optional: when set, curating the global KB library (create/delete/re-index)
    # requires this token via the X-KB-Admin-Token header, so sensitive shared
    # material (e.g. exploit guides) can't be added or removed by every operator.
    # Unset (default) = library management is open to any valid API token.
    aipam_kb_admin_token: str | None = None

    # --- Concurrency ---
    aipam_max_concurrent_jobs: int = Field(default=1, ge=1, le=1)
    aipam_sensor_parallelism: int = 1

    # Runtime safety: SQLite remains a single whole-job writer.
    aipam_heartbeat_seconds: int = Field(default=15, gt=0, le=15)
    aipam_stale_seconds: int = Field(default=120, ge=120)
    aipam_cancel_poll_seconds: int = Field(default=2, gt=0, le=2)
    aipam_reconcile_seconds: int = Field(default=15, gt=0, le=15)
    aipam_undispatched_grace_seconds: int = Field(default=30, ge=30)
    aipam_task_soft_time_limit: int = Field(default=21300, gt=0)
    aipam_task_time_limit: int = Field(default=21600, gt=0)
    aipam_visibility_timeout: int = Field(default=25200, gt=0)

    @model_validator(mode="after")
    def runtime_limits(self):
        if not self.aipam_task_soft_time_limit < self.aipam_task_time_limit < self.aipam_visibility_timeout:
            raise ValueError("Require soft time limit < hard time limit < visibility timeout")
        return self

    # --- Disk Guardrails ---
    aipam_max_job_disk_bytes: int = 53_687_091_200  # 50 GB
    aipam_max_extracted_bytes: int = 10_737_418_240  # 10 GB
    aipam_preflight_multiplier: int = 4

    # --- Retention ---
    aipam_job_retention_days: int = 30
    aipam_log_retention_days: int = 30
    aipam_log_max_mb: int = 500

    # --- Disk Thresholds ---
    aipam_disk_warn_pct: int = 80
    aipam_disk_critical_pct: int = 95

    # --- Service URLs ---
    aipam_ollama_url: str = "http://127.0.0.1:11434"
    # Optional bootstrap selection. A validated SettingsDB selection takes
    # precedence, allowing operators to switch models without rebuilding.
    aipam_embedding_model: str | None = None
    aipam_redis_url: str = "redis://redis:6379/0"

    # --- MNEMOS forensic memory (optional during staged rollout) ---
    # Docker uses the service hostname, never the host's MNEMOS port, so this
    # AIPAM deployment remains isolated from other local MNEMOS instances.
    mnemos_enabled: bool = False
    mnemos_base_url: str = "http://mnemos-service:8700"
    mnemos_token: str | None = None
    mnemos_evidence_receipt_dir: Path = Path("/opt/aipam/logs/evidence_receipts")
    mnemos_evidence_receipt_max_files: int = 500

    # --- Local adapter runtime (optional) ---
    llm_local_adapter_path: str | None = None
    llm_local_adapter_model_name: str | None = None
    llm_local_adapter_quantization: str | None = None

    # --- Paths ---
    aipam_job_root: Path = Path("/jobs")
    aipam_upload_root: Path = Path("/uploads")
    aipam_db_path: Path = Path("/data/aipam.db")
    aipam_sensor_config_dir: Path = Path("/opt/aipam/sensor-config")
    aipam_suricata_rules_dir: Path = Path("/opt/aipam/rules/suricata")
    aipam_yara_rules_dir: Path = Path("/opt/aipam/rules/yara")

    # --- Security Onion (optional — external SO instance) ---
    security_onion_enabled: bool = False
    security_onion_api_url: Optional[str] = None       # e.g. https://so-standalone
    security_onion_username: Optional[str] = None
    security_onion_password: Optional[str] = None

    # --- Arkime (optional — enabled via Compose profile) ---
    arkime_enabled: bool = False
    arkime_api_url: Optional[str] = None          # Internal: http://arkime-viewer:8005
    arkime_public_url: Optional[str] = None        # Analyst browser: http://<host>:8005
    arkime_api_username: Optional[str] = None
    arkime_api_password: Optional[str] = None
    arkime_opensearch_url: str = "http://opensearch:9200"
    arkime_node_name: str = "aipam-node"
    arkime_import_enabled: bool = True
    arkime_auto_import: bool = False
    arkime_raw_dir: Path = Path("/opt/arkime/raw")
    arkime_import_queue_dir: Path = Path("/import-queue")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }

    @property
    def database_url(self) -> str:
        """SQLAlchemy connection string for SQLite."""
        return f"sqlite:///{self.aipam_db_path}"


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton. Call once at startup."""
    return Settings()
