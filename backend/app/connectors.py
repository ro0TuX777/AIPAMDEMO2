from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from .settings_runtime import EffectiveSettings, get_effective_settings

_logger = logging.getLogger("aipam.connectors")


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
    ``export_pcap`` authenticates via the SOC API (Kratos-based login),
    then requests a PCAP stream for the given time range and optional
    sensor filter.
    """

    def __init__(self, settings: Optional[EffectiveSettings] = None) -> None:
        # Allow explicit injection (tests) or fall back to global effective settings.
        settings = settings or get_effective_settings()
        self.mode = settings.security_onion_mode
        self.enabled = settings.security_onion_enabled
        self.base_pcap_path = settings.security_onion_base_pcap_path
        self.zeek_log_path = settings.security_onion_zeek_log_path
        self.suricata_log_path = settings.security_onion_suricata_log_path
        self.api_url = settings.security_onion_api_url
        self.api_token = settings.security_onion_api_token
        self.username = settings.security_onion_username
        self.password = settings.security_onion_password

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

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        """Authenticate to Security Onion Console via Kratos browser login flow.

        SO 2.4+ uses Ory Kratos for identity management.  The flow is:
        1. Initiate a browser-style login flow to get CSRF token and action URL.
        2. Submit credentials (with CSRF token) to the action URL.
        3. Fetch ``/api/info`` to obtain the ``srvToken`` required by all
           mutating API calls (sent as ``X-Srv-Token`` header).

        Returns the ``srvToken`` string.
        """
        base = self.api_url.rstrip("/")

        # Step 1 – initiate login flow (request JSON to parse CSRF token)
        init_resp = await client.get(
            f"{base}/auth/self-service/login/browser",
            headers={"Accept": "application/json"},
        )
        if init_resp.status_code >= 400:
            _logger.warning("Kratos login init returned %s: %s", init_resp.status_code, init_resp.text[:300])
            raise RuntimeError(f"SO login init failed: HTTP {init_resp.status_code}")

        flow_data = init_resp.json()

        # Extract CSRF token from the UI nodes
        csrf_token = ""
        for node in flow_data.get("ui", {}).get("nodes", []):
            attrs = node.get("attributes", {})
            if attrs.get("name") == "csrf_token":
                csrf_token = attrs.get("value", "")
                break

        action_url = flow_data.get("ui", {}).get("action", "")
        if not action_url:
            raise RuntimeError(f"SO login flow missing action URL: {init_resp.text[:300]}")

        # Step 2 – submit password credentials to the action URL
        submit_resp = await client.post(
            action_url,
            json={
                "method": "password",
                "identifier": self.username,
                "password": self.password,
                "csrf_token": csrf_token,
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        if submit_resp.status_code >= 400:
            _logger.error("SO login failed: %s %s", submit_resp.status_code, submit_resp.text[:500])
            raise RuntimeError(f"SO authentication failed: HTTP {submit_resp.status_code}")

        _logger.info("Authenticated to Security Onion as %s", self.username)

        # Step 3 – obtain srvToken from /api/info
        info_resp = await client.get(f"{base}/api/info")
        if info_resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch /api/info: HTTP {info_resp.status_code}")

        srv_token = info_resp.json().get("srvToken", "")
        if not srv_token:
            _logger.warning("srvToken not found in /api/info response")

        return srv_token

    async def export_pcap(self, time_range: Dict[str, str], sensors: List[str], filter_fields: Optional[Dict[str, Any]] = None) -> bytes:
        """Export PCAP from Security Onion for the given time range.

        Authenticates via the SOC Kratos flow, creates a PCAP job via
        ``POST /api/job/``, polls until completion, and downloads the
        result via ``GET /api/stream?jobId=<id>&unwrap=true&ext=pcap``.
        Returns raw PCAP bytes.

        ``filter_fields`` may contain: protocol, srcIp, dstIp, srcPort, dstPort.
        """
        import asyncio as _asyncio

        if not self.api_url:
            raise RuntimeError("SECURITY_ONION_API_URL is not configured")
        if not self.username or not self.password:
            raise RuntimeError("Security Onion credentials are not configured")

        base = self.api_url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=300, write=30, pool=15),
            verify=False,
            follow_redirects=True,
        ) as client:
            # Authenticate and get the srvToken
            srv_token = await self._authenticate(client)
            api_headers: Dict[str, str] = {}
            if srv_token:
                api_headers["X-Srv-Token"] = srv_token

            # Build filter payload (mirrors SOC UI addJob logic)
            start_iso = time_range.get("start", "")
            end_iso = time_range.get("end", "")
            node_id = sensors[0] if sensors else "so-standalone"

            job_filter: Dict[str, Any] = {
                "beginTime": start_iso,
                "endTime": end_iso,
            }
            # Apply optional packet-level filters (protocol, srcIp, dstIp, srcPort, dstPort)
            if filter_fields:
                for key in ("protocol", "srcIp", "dstIp", "srcPort", "dstPort"):
                    if key in filter_fields and filter_fields[key] not in (None, "", 0):
                        job_filter[key] = filter_fields[key]
            if sensors and len(sensors) > 1:
                job_filter["importId"] = ""

            job_payload = {
                "nodeId": node_id,
                "filter": job_filter,
            }

            _logger.info("Creating SO PCAP job: %s", json.dumps(job_payload, default=str))

            job_resp = await client.post(
                f"{base}/api/job/",
                json=job_payload,
                headers=api_headers,
            )

            if job_resp.status_code not in (200, 201):
                _logger.error("SO PCAP job creation failed: %s %s", job_resp.status_code, job_resp.text[:500])
                raise RuntimeError(f"SO PCAP job creation failed: HTTP {job_resp.status_code}")

            job_data = job_resp.json()
            job_id = job_data.get("id")
            if not job_id:
                raise RuntimeError(f"SO PCAP job response missing job id: {job_resp.text[:300]}")

            _logger.info("Created SO PCAP job: %s", job_id)

            # Poll for job completion.
            # SO uses integer statuses: 0=pending, 1=processing, 2=completed, 3=incomplete.
            # On standalone nodes the status may stay at 1 even after processing
            # finishes; in that case completeTime is set and size > 0.
            for attempt in range(120):  # Up to ~10 minutes
                await _asyncio.sleep(3 if attempt < 10 else 5)
                status_resp = await client.get(
                    f"{base}/api/job/{job_id}",
                    headers=api_headers,
                )
                if status_resp.status_code != 200:
                    continue
                status_data = status_resp.json()
                so_status = status_data.get("status")
                complete_time = status_data.get("completeTime", "")
                size = status_data.get("size", 0)
                _logger.debug("SO job %s poll #%d: status=%s size=%s", job_id, attempt + 1, so_status, size)

                if so_status == 2:  # officially completed
                    # status 2 with a failure message means the job errored
                    failure = status_data.get("failure", "")
                    if failure:
                        raise RuntimeError(f"SO PCAP job failed: {failure}")
                    break
                if so_status == 3:  # incomplete / failed
                    failure = status_data.get("failure", "unknown")
                    raise RuntimeError(f"SO PCAP job failed: {failure}")
                # Standalone nodes may mark completeTime without changing status
                if (complete_time and not complete_time.startswith("0001")
                        and size and size > 0):
                    _logger.info("SO job %s has data (size=%d) despite status=%s, treating as complete", job_id, size, so_status)
                    break
            else:
                raise RuntimeError("SO PCAP job timed out after 10 minutes")

            # Verify job produced data before attempting download
            final_size = status_data.get("size", 0)
            if not final_size or final_size <= 0:
                raise RuntimeError(
                    "SO PCAP job completed but produced no data — "
                    "no matching packets for the given time range/filters"
                )

            # Download the PCAP stream
            dl_resp = await client.get(
                f"{base}/api/stream",
                params={"jobId": job_id, "unwrap": "true", "ext": "pcap"},
                headers=api_headers,
            )
            if dl_resp.status_code != 200:
                raise RuntimeError(f"SO PCAP download failed: HTTP {dl_resp.status_code}")

            _logger.info("Downloaded SO PCAP: %d bytes", len(dl_resp.content))
            return dl_resp.content

    async def _get_grid_member_id(self, client: httpx.AsyncClient, api_headers: Dict[str, str]) -> str:
        """Fetch the first grid member ID from the SO API.

        The import endpoint needs the full node ID (e.g. ``manager_standalone``).
        Falls back to ``"so-standalone"`` if the API call fails.
        """
        base = self.api_url.rstrip("/")
        try:
            resp = await client.get(f"{base}/api/gridmembers", headers=api_headers)
            if resp.status_code == 200:
                members = resp.json()
                if isinstance(members, list) and members:
                    # Prefer standalone / sensor nodes; fall back to first member
                    for m in members:
                        mid = m.get("id", "")
                        if mid:
                            return mid
        except Exception as exc:
            _logger.warning("Failed to fetch grid members: %s", exc)
        return "so-standalone"

    async def import_pcap(self, pcap_bytes: bytes, filename: str, node_id: Optional[str] = None) -> Dict[str, Any]:
        """Upload a PCAP file into Security Onion for analysis.

        Uses the SOC Grid import endpoint:
        ``POST /api/gridmembers/{nodeId}/import`` with multipart/form-data.

        Returns a dict with ``status`` and ``message`` keys.
        """
        if not self.api_url:
            raise RuntimeError("SECURITY_ONION_API_URL is not configured")
        if not self.username or not self.password:
            raise RuntimeError("Security Onion credentials are not configured")

        base = self.api_url.rstrip("/")

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=15, read=120, write=120, pool=15),
            verify=False,
            follow_redirects=True,
        ) as client:
            srv_token = await self._authenticate(client)
            api_headers: Dict[str, str] = {}
            if srv_token:
                api_headers["X-Srv-Token"] = srv_token

            # Resolve node ID
            target_node = node_id or await self._get_grid_member_id(client, api_headers)
            _logger.info("Importing PCAP '%s' (%d bytes) into SO node '%s'", filename, len(pcap_bytes), target_node)

            # Multipart upload
            files = {
                "attachment": (filename, pcap_bytes, "application/vnd.tcpdump.pcap"),
            }
            resp = await client.post(
                f"{base}/api/gridmembers/{target_node}/import",
                files=files,
                headers=api_headers,
            )

            if resp.status_code in (200, 202):
                _logger.info("SO PCAP import accepted: %s", resp.text[:300])
                return {
                    "status": "accepted",
                    "message": f"PCAP '{filename}' uploaded to Security Onion node '{target_node}'. Import is processing asynchronously.",
                    "node_id": target_node,
                }
            else:
                _logger.error("SO PCAP import failed: HTTP %s %s", resp.status_code, resp.text[:500])
                raise RuntimeError(f"SO PCAP import failed: HTTP {resp.status_code} — {resp.text[:300]}")

    async def fetch_pcaps_via_api(self, time_range: Dict[str, str], sensors: List[str]) -> List[bytes]:
        """Legacy method — wraps export_pcap for backward compatibility."""
        try:
            data = await self.export_pcap(time_range, sensors)
            return [data] if data else []
        except Exception as exc:
            _logger.error("fetch_pcaps_via_api failed: %s", exc)
            return []


class ArkimeConnector:
    """Connector for Arkime viewer / import operations.

    Supports:
    - PCAP export from Arkime sessions
    - Queuing PCAP imports via manifest files
    - Reading import status from sidecar JSON
    - Building pivot URLs for community_id or 5-tuple queries
    """

    # Import status sidecar filename (stored in job directory)
    _STATUS_FILENAME = "arkime_import_status.json"

    def __init__(self, settings: Optional[EffectiveSettings] = None) -> None:
        # Allow explicit injection (tests) or fall back to global effective settings.
        settings = settings or get_effective_settings()
        self.enabled = settings.arkime_enabled
        self.api_url = settings.arkime_api_url
        self.public_url = settings.arkime_public_url
        self.username = settings.arkime_api_username
        self.password = settings.arkime_api_password
        self.import_enabled = settings.arkime_import_enabled
        self.import_queue_dir = settings.arkime_import_queue_dir

    # ── PCAP export (existing) ────────────────────────────────────────

    @staticmethod
    def _iso_to_epoch(iso_str: str) -> int:
        """Convert ISO 8601 timestamp to Unix epoch seconds for Arkime API."""
        from datetime import datetime, timezone
        try:
            dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
            return int(dt.timestamp())
        except (ValueError, AttributeError):
            return 0

    async def export_pcap(self, flt: str, time_range: Dict[str, str]) -> bytes:
        if not self.api_url:
            return b""
        # Build query params.  Arkime treats "*" as an invalid expression;
        # an empty / omitted expression matches all sessions.
        effective_filter = flt.strip() if flt else ""
        if effective_filter == "*":
            effective_filter = ""
        params: Dict[str, Any] = {"date": -1}
        if effective_filter:
            params["expression"] = effective_filter
        start_epoch = self._iso_to_epoch(time_range.get("start", ""))
        stop_epoch = self._iso_to_epoch(time_range.get("end", ""))
        if start_epoch and stop_epoch:
            params["startTime"] = start_epoch
            params["stopTime"] = stop_epoch
        auth = None
        if self.username and self.password:
            # Arkime uses Digest authentication
            auth = httpx.DigestAuth(self.username, self.password)
        async with httpx.AsyncClient(timeout=120) as client:
            # Arkime 5.x/6.x uses GET /api/sessions/pcap for bulk export
            resp = await client.get(
                f"{self.api_url}/api/sessions/pcap", params=params, auth=auth,
            )
            resp.raise_for_status()
            return resp.content

    # ── Import queue ──────────────────────────────────────────────────

    def queue_import(self, job_id: str, pcap_paths: List[Path], job_dir: Path) -> str:
        """Write an import manifest so the arkime-importer picks up PCAPs.

        Returns the import state written (``queued``).
        """
        queue_dir = Path(self.import_queue_dir)
        queue_dir.mkdir(parents=True, exist_ok=True)

        for pcap_path in pcap_paths:
            manifest = {
                "job_id": job_id,
                "pcap_path": str(pcap_path),
                "queued_at": datetime.now(timezone.utc).isoformat(),
            }
            manifest_file = queue_dir / f"{job_id}_{pcap_path.stem}.json"
            manifest_file.write_text(json.dumps(manifest, indent=2))
            _logger.info("Arkime import manifest written: %s", manifest_file)

        # Write sidecar status in job directory
        self._write_status(job_dir, {
            "status": "queued",
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "pcap_count": len(pcap_paths),
        })
        return "queued"

    # ── Import status ─────────────────────────────────────────────────

    def get_import_status(self, job_dir: Path) -> Dict[str, Any]:
        """Read the Arkime import status sidecar for a job."""
        status_file = job_dir / self._STATUS_FILENAME
        if not status_file.exists():
            return {"status": "not_imported"}
        try:
            return json.loads(status_file.read_text())
        except (json.JSONDecodeError, OSError):
            return {"status": "not_imported"}

    def _write_status(self, job_dir: Path, data: Dict[str, Any]) -> None:
        status_file = job_dir / self._STATUS_FILENAME
        try:
            status_file.write_text(json.dumps(data, indent=2))
        except OSError as exc:
            _logger.warning("Failed to write Arkime status sidecar: %s", exc)

    # ── Pivot URL builder ─────────────────────────────────────────────

    def build_pivot_url(
        self,
        *,
        community_id: Optional[str] = None,
        src_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dest_ip: Optional[str] = None,
        dest_port: Optional[int] = None,
        proto: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> tuple[Optional[str], str]:
        """Build an Arkime viewer search URL.

        Returns ``(url, basis)`` where basis is ``community_id``,
        ``five_tuple``, or ``none``.
        """
        base = (self.public_url or self.api_url or "").rstrip("/")
        if not base:
            return None, "none"

        # date=-1 tells Arkime to search across ALL time, not just the
        # default last-hour window.  PCAPs can be from any date.
        time_param = "date=-1"

        # Primary: community_id
        if community_id:
            expr = f"communityId == {quote(community_id)}"
            return f"{base}/sessions?{time_param}&expression={quote(expr)}", "community_id"

        # Fallback: direction-agnostic IP/port matching.
        # Suricata and Arkime may disagree on src vs dst, so we use
        # the direction-agnostic ``ip ==`` and ``port ==`` expressions
        # which match regardless of which side is source/destination.
        parts: List[str] = []
        if src_ip:
            parts.append(f"ip == {src_ip}")
        if dest_ip:
            parts.append(f"ip == {dest_ip}")
        if src_port is not None:
            parts.append(f"port == {src_port}")
        if dest_port is not None:
            parts.append(f"port == {dest_port}")
        if proto:
            parts.append(f"protocols == {proto}")

        if parts:
            expr = " && ".join(parts)
            url = f"{base}/sessions?{time_param}&expression={quote(expr)}"
            return url, "five_tuple"

        return None, "none"

