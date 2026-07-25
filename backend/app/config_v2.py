"""
AIPAM V2 configuration — consolidated environment variables (§1.6).

All AIPAM_* env vars are defined here as a single Pydantic Settings class.
Loaded once at startup; injected via FastAPI dependency or direct import.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


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
    aipam_max_concurrent_jobs: int = 1
    aipam_sensor_parallelism: int = 1

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
    aipam_ollama_url: str = "http://ollama:11434"
    aipam_redis_url: str = "redis://redis:6379/0"

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

