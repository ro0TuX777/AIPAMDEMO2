from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, List

import httpx


class SecurityOnionConnector:
    """Connector for Security Onion PCAP/log retrieval.

    This is a v1 skeleton that supports a simple filesystem mode and a
    placeholder API mode. The exact directory layout / API filters should
    be configured via environment variables, matching the spec.
    """

    def __init__(self) -> None:
        self.mode = os.getenv("SECURITY_ONION_MODE", "filesystem")
        self.base_pcap_path = Path(os.getenv("SECURITY_ONION_PCAP_PATH", "/opt/so/pcap"))
        self.zeek_log_path = Path(os.getenv("SECURITY_ONION_ZEEK_LOG_PATH", "/opt/so/zeek"))
        self.suricata_log_path = Path(os.getenv("SECURITY_ONION_SURICATA_LOG_PATH", "/opt/so/suricata"))
        self.api_url = os.getenv("SECURITY_ONION_API_URL")
        self.api_token = os.getenv("SECURITY_ONION_API_TOKEN")

    def find_pcaps(self, time_range: Dict[str, str], sensors: List[str]) -> List[Path]:
        # Minimal placeholder: return all pcaps under base path.
        if self.mode != "filesystem":
            return []
        return sorted(self.base_pcap_path.glob("*.pcap"))

    async def fetch_pcaps_via_api(self, time_range: Dict[str, str], sensors: List[str]) -> List[bytes]:
        if not self.api_url or not self.api_token:
            return []
        async with httpx.AsyncClient(timeout=60) as client:
            # Placeholder; real implementation would send proper filters.
            resp = await client.get(self.api_url, headers={"Authorization": f"Bearer {self.api_token}"})
            resp.raise_for_status()
            return [resp.content]


class ArkimeConnector:
    def __init__(self) -> None:
        self.api_url = os.getenv("ARKIME_API_URL")
        self.username = os.getenv("ARKIME_API_USERNAME")
        self.password = os.getenv("ARKIME_API_PASSWORD")

    async def export_pcap(self, flt: str, time_range: Dict[str, str]) -> bytes:
        if not self.api_url:
            return b""
        params = {"expression": flt}
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(f"{self.api_url}/api/sessions.pcap", params=params, auth=auth)
            resp.raise_for_status()
            return resp.content

