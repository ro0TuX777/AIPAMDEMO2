from __future__ import annotations

"""Helpers for loading effective runtime settings.

These functions merge persisted SettingsDB values with environment
fallbacks so the rest of the backend can depend on a single source
of truth without coupling directly to FastAPI request handlers.
"""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

from .database import get_session
from .db_models import SettingsDB


@dataclass
class EffectiveSettings:
    # LLM
    llm_endpoint: str
    llm_model_name: str
    llm_max_tokens: int
    llm_temperature: float
    llm_timeout_seconds: float

    # Storage
    file_storage_path: Path
    reports_path: Path

    # Dataset Storage (Phase 6)
    dataset_storage_path: Path
    finetuning_backend: str

    # Security Onion
    security_onion_mode: str
    security_onion_base_pcap_path: Path
    security_onion_zeek_log_path: Path
    security_onion_suricata_log_path: Path
    security_onion_api_url: Optional[str]
    security_onion_api_token: Optional[str]

    # Arkime
    arkime_enabled: bool
    arkime_api_url: Optional[str]
    arkime_public_url: Optional[str]
    arkime_api_username: Optional[str]
    arkime_api_password: Optional[str]
    arkime_opensearch_url: str
    arkime_node_name: str
    arkime_import_enabled: bool
    arkime_auto_import: bool
    arkime_raw_dir: Path
    arkime_import_queue_dir: Path
    
    # RAG / Embeddings (Phase 1 Chat)
    embedding_model_name: str
    embedding_model_path: Optional[Path]  # Local path for air-gapped environments
    vector_store_path: Path


def _load_settings_row() -> dict:
    """Return raw settings dict from SettingsDB (or empty dict)."""

    with get_session() as session:
        row = session.get(SettingsDB, 1)
        return dict(row.values or {}) if row else {}


def get_effective_settings() -> EffectiveSettings:
    """Compute the effective runtime settings.
    
    Resolution order per field:
    1. SettingsDB value (if present and non-empty)
    2. Environment variable
    3. Hard-coded default
    """

    raw = _load_settings_row()

    # LLM
    llm_endpoint = raw.get("llm_endpoint") or os.getenv(
        "LLM_ENDPOINT", "http://localhost:11434/v1/chat/completions"
    )
    # Default to the latest recommended local model; override via env or SettingsDB as needed.
    llm_model_name = raw.get("llm_model_name") or os.getenv("LLM_MODEL_NAME", "aipam-trafficllm-v10")
    llm_max_tokens = int(
        raw.get("llm_max_tokens") or os.getenv("LLM_MAX_TOKENS", "2000")
    )
    llm_temperature = float(
        raw.get("llm_temperature") or os.getenv("LLM_TEMPERATURE", "0.1")
    )
    llm_timeout_seconds = float(
        raw.get("llm_timeout_seconds") or os.getenv("LLM_TIMEOUT_SECONDS", "600")
    )

    # Storage
    file_storage_base = raw.get("file_storage_path") or os.getenv(
        "FILE_STORAGE_PATH", "/tmp/aipam_storage"
    )
    file_storage_path = Path(file_storage_base)
    reports_path = Path(os.getenv("REPORTS_PATH") or (file_storage_path / "reports"))

    # Dataset Storage
    dataset_storage_base = raw.get("dataset_storage_path") or os.getenv(
        "DATASET_STORAGE_PATH", str(Path(__file__).resolve().parents[2] / "finetuning/data")
    )
    dataset_storage_path = Path(dataset_storage_base)
    
    finetuning_backend = raw.get("finetuning_backend") or os.getenv("FINETUNING_BACKEND", "mlx")

    # Security Onion
    so_mode = raw.get("security_onion_mode") or os.getenv(
        "SECURITY_ONION_MODE", "filesystem"
    )
    so_base = raw.get("security_onion_base_pcap_path") or os.getenv(
        "SECURITY_ONION_PCAP_PATH", "/opt/so/pcap"
    )
    so_zeek = raw.get("security_onion_zeek_log_path") or os.getenv(
        "SECURITY_ONION_ZEEK_LOG_PATH", "/opt/so/zeek"
    )
    so_suricata = raw.get("security_onion_suricata_log_path") or os.getenv(
        "SECURITY_ONION_SURICATA_LOG_PATH", "/opt/so/suricata"
    )
    so_api_url = raw.get("security_onion_api_url") or os.getenv("SECURITY_ONION_API_URL")
    so_api_token = raw.get("security_onion_api_token") or os.getenv(
        "SECURITY_ONION_API_TOKEN"
    )

    # Arkime
    ark_enabled = (raw.get("arkime_enabled") or os.getenv("ARKIME_ENABLED", "false")).lower() in ("true", "1", "yes")
    ark_url = raw.get("arkime_api_url") or os.getenv("ARKIME_API_URL")
    ark_public_url = raw.get("arkime_public_url") or os.getenv("ARKIME_PUBLIC_URL")
    ark_user = raw.get("arkime_api_username") or os.getenv("ARKIME_API_USERNAME")
    ark_pass = raw.get("arkime_api_password") or os.getenv("ARKIME_API_PASSWORD")
    ark_os_url = raw.get("arkime_opensearch_url") or os.getenv("ARKIME_OPENSEARCH_URL", "http://opensearch:9200")
    ark_node = raw.get("arkime_node_name") or os.getenv("ARKIME_NODE_NAME", "aipam-node")
    ark_import_enabled = (raw.get("arkime_import_enabled") or os.getenv("ARKIME_IMPORT_ENABLED", "true")).lower() in ("true", "1", "yes")
    ark_auto_import = (raw.get("arkime_auto_import") or os.getenv("ARKIME_AUTO_IMPORT", "false")).lower() in ("true", "1", "yes")
    ark_raw_dir = raw.get("arkime_raw_dir") or os.getenv("ARKIME_RAW_DIR", "/opt/arkime/raw")
    ark_import_queue_dir = raw.get("arkime_import_queue_dir") or os.getenv("ARKIME_IMPORT_QUEUE_DIR", "/import-queue")

    # RAG / Embeddings
    embedding_model_name = raw.get("embedding_model_name") or os.getenv(
        "EMBEDDING_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
    )
    embedding_model_path_str = raw.get("embedding_model_path") or os.getenv("EMBEDDING_MODEL_PATH")
    embedding_model_path = Path(embedding_model_path_str) if embedding_model_path_str else None

    vector_store_path_str = raw.get("vector_store_path") or os.getenv("VECTOR_STORE_PATH")
    vector_store_path = Path(vector_store_path_str) if vector_store_path_str else (file_storage_path / "vector_store")

    return EffectiveSettings(
        llm_endpoint=llm_endpoint,
        llm_model_name=llm_model_name,
        llm_max_tokens=llm_max_tokens,
        llm_temperature=llm_temperature,
        llm_timeout_seconds=llm_timeout_seconds,
        file_storage_path=file_storage_path,
        reports_path=reports_path,
        dataset_storage_path=dataset_storage_path,
        finetuning_backend=finetuning_backend,
        security_onion_mode=so_mode,
        security_onion_base_pcap_path=Path(so_base),
        security_onion_zeek_log_path=Path(so_zeek),
        security_onion_suricata_log_path=Path(so_suricata),
        security_onion_api_url=so_api_url,
        security_onion_api_token=so_api_token,
        arkime_enabled=ark_enabled,
        arkime_api_url=ark_url,
        arkime_public_url=ark_public_url,
        arkime_api_username=ark_user,
        arkime_api_password=ark_pass,
        arkime_opensearch_url=ark_os_url,
        arkime_node_name=ark_node,
        arkime_import_enabled=ark_import_enabled,
        arkime_auto_import=ark_auto_import,
        arkime_raw_dir=Path(ark_raw_dir),
        arkime_import_queue_dir=Path(ark_import_queue_dir),
        embedding_model_name=embedding_model_name,
        embedding_model_path=embedding_model_path,
        vector_store_path=vector_store_path,
    )

