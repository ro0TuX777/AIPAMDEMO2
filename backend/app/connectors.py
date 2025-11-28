from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import httpx

from .settings_runtime import EffectiveSettings, get_effective_settings


class SecurityOnionConnector:
    """Connector for Security Onion PCAP/log retrieval.

    Filesystem mode
    ----------------
    Expects a base directory (``SECURITY_ONION_PCAP_PATH``) that contains
    per-sensor subdirectories, e.g.::

        /opt/so/pcap/
          sensor1/
            *.pcap
          sensor2/
            *.pcap

    ``find_pcaps`` will:
    * Restrict to the requested ``sensors`` if provided, otherwise scan all
      immediate subdirectories and the base directory itself.
    * Filter PCAPs by file modification time overlapping the requested
      ``time_range`` (start/end ISO8601 strings).

    API mode
    --------
    ``fetch_pcaps_via_api`` issues one or more GET requests to
    ``SECURITY_ONION_API_URL`` with query parameters derived from time
    range and sensors. It follows RFC 5988-style ``Link: ... rel="next"``
    headers for pagination, returning the raw bytes for each page.
    """

    def __init__(self, settings: Optional[EffectiveSettings] = None) -> None:
        # Allow explicit injection (tests) or fall back to global effective settings.
        settings = settings or get_effective_settings()
        self.mode = settings.security_onion_mode
        self.base_pcap_path = settings.security_onion_base_pcap_path
        self.zeek_log_path = settings.security_onion_zeek_log_path
        self.suricata_log_path = settings.security_onion_suricata_log_path
        self.api_url = settings.security_onion_api_url
        self.api_token = settings.security_onion_api_token

    def _parse_iso8601(self, value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            # Support "Z" suffix and offset-aware strings.
            if value.endswith("Z"):
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def find_pcaps(self, time_range: Dict[str, str], sensors: List[str]) -> List[Path]:
        """Locate PCAP files matching the requested time range and sensors.

        * If running in non-filesystem mode, returns an empty list.
        * If ``sensors`` is non-empty, only those per-sensor subdirectories
          are searched (if they exist).
        * If ``sensors`` is empty, all immediate subdirectories under the
          base path and the base path itself are searched.
        * Files are filtered by modification time (mtime) falling within the
          inclusive [start, end] interval, if provided.
        """
        if self.mode != "filesystem":
            return []

        start = self._parse_iso8601(time_range.get("start")) if time_range else None
        end = self._parse_iso8601(time_range.get("end")) if time_range else None

        search_roots: List[Path] = []

        # If specific sensors were requested, prefer matching subdirectories.
        if sensors:
            for sensor in sensors:
                sensor_dir = self.base_pcap_path / sensor
                if sensor_dir.is_dir():
                    search_roots.append(sensor_dir)
        # Fallback: scan all immediate subdirectories and base path itself.
        if not search_roots:
            if self.base_pcap_path.is_dir():
                search_roots.append(self.base_pcap_path)
                for child in self.base_pcap_path.iterdir():
                    if child.is_dir():
                        search_roots.append(child)

        results: List[Path] = []
        for root in search_roots:
            for pcap in root.rglob("*.pcap"):
                try:
                    mtime = datetime.fromtimestamp(pcap.stat().st_mtime, tz=timezone.utc)
                except OSError:
                    continue
                if start and mtime < start:
                    continue
                if end and mtime > end:
                    continue
                results.append(pcap)

        return sorted(results)

    async def fetch_pcaps_via_api(self, time_range: Dict[str, str], sensors: List[str]) -> List[bytes]:
        """Fetch PCAP bytes from the Security Onion API.

        Query parameters:
        * ``start`` / ``end``: raw ISO8601 strings from ``time_range``.
        * ``sensor``: repeated query parameter for each requested sensor.

        Pagination:
        * Follows RFC 5988-style ``Link`` headers and iterates ``rel="next"``
          links until none remain.
        """
        if not self.api_url or not self.api_token:
            return []

        params: Dict[str, object] = {}
        if time_range:
            if "start" in time_range:
                params["start"] = time_range["start"]
            if "end" in time_range:
                params["end"] = time_range["end"]
        if sensors:
            params["sensor"] = sensors

        headers = {"Authorization": f"Bearer {self.api_token}"}
        blobs: List[bytes] = []
        url = self.api_url

        async with httpx.AsyncClient(timeout=60) as client:
            while url:
                resp = await client.get(url, params=params, headers=headers)
                resp.raise_for_status()
                if resp.content:
                    blobs.append(resp.content)

                # After the first request, allow the server-provided next link
                # to carry any required pagination parameters.
                params = {}
                next_link = getattr(resp, "links", None) or {}
                next_info = next_link.get("next") if isinstance(next_link, dict) else None
                url = next_info.get("url") if isinstance(next_info, dict) else None

        return blobs


class ArkimeConnector:
    def __init__(self, settings: Optional[EffectiveSettings] = None) -> None:
        # Allow explicit injection (tests) or fall back to global effective settings.
        settings = settings or get_effective_settings()
        self.api_url = settings.arkime_api_url
        self.username = settings.arkime_api_username
        self.password = settings.arkime_api_password

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

