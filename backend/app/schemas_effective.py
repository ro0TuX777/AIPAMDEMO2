from __future__ import annotations

from pydantic import BaseModel


class EffectiveSettingsResponse(BaseModel):
    # LLM
    llm_endpoint: str
    llm_model_name: str
    llm_max_tokens: int
    llm_temperature: float

    # Storage
    file_storage_path: str
    reports_path: str

    # Security Onion
    security_onion_mode: str
    security_onion_base_pcap_path: str
    security_onion_zeek_log_path: str
    security_onion_suricata_log_path: str
    security_onion_api_url: str | None = None
    security_onion_api_token: str | None = None

    # Arkime
    arkime_api_url: str | None = None
    arkime_api_username: str | None = None
    arkime_api_password: str | None = None

