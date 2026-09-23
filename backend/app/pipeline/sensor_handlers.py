"""
In-process sensor handlers for the V2 pipeline.

Each handler runs inside the Celery worker process instead of launching
a Docker container.  They wrap the existing V1 analysis logic (parsers,
anomaly detector, etc.) and write results to the standard sensor output
directory layout so downstream pipeline stages can consume them.

Handler signature::

    def handle_<name>(
        input_root: Path,
        sensor_output_dir: Path,
        job_id: str,
        execution_profile: str,
    ) -> None

Raise any exception on failure — the caller (sensor_runner) converts it
into a ``SensorResult(status="failed")``.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from backend.app.config_v2 import get_settings
from backend.app.pipeline.job_dir import load_pcap_labels
from backend.app.suricata_rules import build_runtime_suricata_bundle

logger = logging.getLogger("aipam.sensor_handlers")

# How often the stall watchdog samples progress, and how long a capture-parsing
# process may make no progress at all before it is treated as wedged.
_WATCHDOG_POLL_SECONDS = 5.0
_DEFAULT_STALL_SECONDS = 300.0


# ---------------------------------------------------------------------------
# Helper: find the PCAP inside the job directory
# ---------------------------------------------------------------------------

def _find_pcap(input_root: Path) -> Path:
    """Locate the PCAP file inside ``input_root/input/``."""
    input_dir = input_root / "input"
    for ext in ("*.pcap", "*.pcapng"):
        matches = list(input_dir.glob(ext))
        if matches:
            return matches[0]
    raise FileNotFoundError(f"No PCAP found in {input_dir}")


def _find_all_pcaps(input_root: Path) -> list[Path]:
    """Locate all PCAP files inside ``input_root/input/``.

    Returns a list of Paths. Skips symlinks to avoid double-processing
    the backward-compat ``pcap.pcap`` symlink.
    """
    input_dir = input_root / "input"
    results = []
    for ext in ("*.pcap", "*.pcapng"):
        for p in sorted(input_dir.glob(ext)):
            if not p.is_symlink():
                results.append(p)
    if not results:
        raise FileNotFoundError(f"No PCAP found in {input_dir}")
    return results


def _find_all_pcaps_labeled(input_root: Path) -> list[tuple[Path, str]]:
    """Pair each staged PCAP with its phase label.

    Filenames carry an ordinal so captures sharing a label don't collide, so the
    label can no longer be read off the stem — it comes from the input manifest.
    Jobs staged before that manifest existed fall back to the stem, which is
    exactly what they were named with.
    """
    labels = load_pcap_labels(input_root)
    return [(p, labels.get(p.name) or p.stem) for p in _find_all_pcaps(input_root)]


def _sensor_timeout(name: str, default: int) -> int:
    """Read a sensor's configured ceiling from the registry."""
    # Local import: the registry imports this module to resolve handlers.
    from backend.app.sensors.registry import SENSORS

    sensor_def = SENSORS.get(name)
    return sensor_def.timeout_seconds if sensor_def else default


def _dir_bytes(path: Path) -> int:
    """Total size of files directly produced under *path* (best effort)."""
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    continue
    except OSError:
        return total
    return total


def _read_progress(pid: int, output_dir: Path) -> int:
    """A monotonically-rising measure of work done, for stall detection.

    Prefers bytes the process has read (it climbs steadily as the capture is
    consumed, even while nothing is being written yet) and falls back to output
    size where ``/proc`` is unavailable. Either advancing counts as progress.
    """
    read_bytes = 0
    try:
        with open(f"/proc/{pid}/io", encoding="utf-8") as f:
            for line in f:
                if line.startswith("rchar:"):
                    read_bytes = int(line.split()[1])
                    break
    except (OSError, ValueError, IndexError):
        pass
    return read_bytes + _dir_bytes(output_dir)


def run_capture_tool(
    cmd: list[str],
    cwd: Path,
    *,
    label: str,
    ceiling_seconds: int,
    stall_seconds: float = _DEFAULT_STALL_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    """Run a capture-parsing tool under a stall watchdog rather than a fixed clock.

    How long Zeek or Suricata needs is driven by connection count, not file
    size — a 1.4 GB capture of a few large flows finishes in seconds while a
    600 MB capture of 200k short connections runs for half an hour. Any fixed
    wall-clock limit is therefore either too tight for a dense capture or too
    slack to catch a genuine hang, and the old fixed limit killed healthy runs.

    So the process is killed only when it stops making progress for
    *stall_seconds*, with *ceiling_seconds* as an absolute backstop. Progress is
    logged as it goes, so a long run reads as slow rather than hung.

    Raises ``subprocess.TimeoutExpired`` when either limit trips, leaving
    whatever the tool already wrote in place for inspection.
    """
    stdout_path = cwd / "stdout.log"
    stderr_path = cwd / "stderr.log"

    started = time.monotonic()
    last_advance = started
    best_progress = -1

    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        # Redirect to files rather than PIPE: a chatty tool can fill a pipe
        # buffer and deadlock while we are polling instead of reading.
        proc = subprocess.Popen(cmd, cwd=str(cwd), stdout=out, stderr=err)

        while True:
            try:
                proc.wait(timeout=_WATCHDOG_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                pass

            now = time.monotonic()
            progress = _read_progress(proc.pid, cwd)
            if progress > best_progress:
                best_progress = progress
                last_advance = now

            elapsed = now - started
            stalled_for = now - last_advance

            if stalled_for >= stall_seconds:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(
                    cmd, elapsed,
                    output=(
                        f"No progress for {stalled_for:.0f}s while processing "
                        f"{label} ({best_progress / 1048576:.0f} MB processed in "
                        f"{elapsed / 60:.1f} min) — treating as stalled"
                    ).encode(),
                )

            if elapsed >= ceiling_seconds:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(
                    cmd, elapsed,
                    output=(
                        f"Hit the {ceiling_seconds}s ceiling on {label} while "
                        f"still progressing ({best_progress / 1048576:.0f} MB in "
                        f"{elapsed / 60:.1f} min) — raise the sensor timeout to "
                        f"finish this capture"
                    ).encode(),
                )

            if int(elapsed) % 60 < _WATCHDOG_POLL_SECONDS:
                logger.info(
                    "%s still running: %.1f min elapsed, %.0f MB processed",
                    label, elapsed / 60, best_progress / 1048576,
                )

    return subprocess.CompletedProcess(
        cmd, proc.returncode,
        stdout=b"",
        stderr=stderr_path.read_bytes()[-4096:] if stderr_path.exists() else b"",
    )


def _zeek_ts_to_iso(value: object) -> str | None:
    """Convert a Zeek timestamp value into an ISO-8601 UTC string."""
    if value in (None, ""):
        return None
    try:
        dt = datetime.fromtimestamp(float(value), timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError, OSError, OverflowError):
        return str(value)


def _normalize_host_indicator(value: str | None) -> str:
    """Normalize host-like indicators such as domains and SNI values."""
    return str(value or "").strip().lower().rstrip(".")


def _normalize_text_indicator(value: str | None) -> str:
    """Normalize exact-match text indicators such as hashes and JA3 strings."""
    return str(value or "").strip().lower()


# ---------------------------------------------------------------------------
# Stage: Zeek
# ---------------------------------------------------------------------------

def handle_zeek(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Run Zeek on each job PCAP and store parsed logs.

    For multi-PCAP jobs, each PCAP is processed independently into its own
    raw subdirectory, and every result record is tagged with ``pcap_label``
    so downstream stages can group evidence by capture phase.
    """
    pcaps = _find_all_pcaps_labeled(input_root)
    zeek_bin = shutil.which("zeek")
    if not zeek_bin:
        raise RuntimeError("Zeek binary not found on PATH")

    timeout_seconds = _sensor_timeout("zeek", 1800)

    # Records stream straight to disk rather than accumulating: a dense capture
    # yields hundreds of thousands of them, and holding all of them (plus the
    # raw log lines they came from) was several GB and minutes of stall. Written
    # via a temp file so the results only appear once every capture succeeded.
    out = sensor_output_dir / "sensor.results.jsonl"
    tmp_out = out.with_suffix(".jsonl.partial")
    total = 0

    with open(tmp_out, "w") as sink:
        for pcap, pcap_label in pcaps:
            # Keyed on the staged filename, not the label — several captures can
            # share a phase label and would otherwise overwrite each other's logs.
            if len(pcaps) == 1:
                raw_dir = sensor_output_dir / "raw"
            else:
                raw_dir = sensor_output_dir / "raw" / pcap.stem
            raw_dir.mkdir(parents=True, exist_ok=True)

            cmd = [zeek_bin, "-C", "-r", str(pcap), "LogAscii::use_json=T"]

            # Enable file extraction — Zeek will carve transferred files
            # into an extract_files/ subdirectory in the cwd.
            extract_script = Path("/opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek")
            if extract_script.exists():
                cmd.append(str(extract_script))
                logger.info("Zeek file extraction enabled via %s", extract_script)

            logger.info("Running Zeek on %s: %s (cwd=%s)", pcap.name, " ".join(cmd), raw_dir)
            result = run_capture_tool(
                cmd, raw_dir,
                label=f"zeek/{pcap.name}",
                ceiling_seconds=timeout_seconds,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")[:2000]
                logger.warning("Zeek exited %d for %s: %s", result.returncode, pcap.name, stderr)

            count = 0
            for rec in _iter_zeek_results(raw_dir):
                rec["pcap_label"] = pcap_label
                sink.write(json.dumps(rec) + "\n")
                count += 1
            total += count
            logger.info("Zeek: %d records from %s (%s)", count, pcap.name, pcap_label)

    tmp_out.replace(out)
    logger.info("Zeek: wrote %d total result records across %d PCAP(s)", total, len(pcaps))


def _iter_zeek_log(path: Path) -> Iterator[dict]:
    """Yield JSON records from a Zeek log one line at a time.

    Streaming matters here: a connection-dense capture produces a conn.log with
    hundreds of thousands of lines, and materialising them as a Python list cost
    multiple GB and minutes of wall-clock before anything was written out.
    """
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue


def _parse_zeek_results(raw_dir: Path) -> list[dict]:
    """Parse Zeek logs from a raw directory and return result records.

    Materialising wrapper around :func:`_iter_zeek_results`, kept for callers
    that genuinely want the whole list. The Zeek handler streams instead.
    """
    return list(_iter_zeek_results(raw_dir))


def _iter_zeek_results(raw_dir: Path) -> Iterator[dict]:
    """Stream result records parsed from a Zeek raw output directory."""
    from backend.app.parsers import parse_zeek_conn

    # conn.log → flows
    conn_log = raw_dir / "conn.log"
    if conn_log.exists():
        flow_count = 0
        for rec in _iter_zeek_log(conn_log):
            # One record at a time keeps the normalization logic in one place
            # without holding every flow in memory.
            for flow in parse_zeek_conn((rec,)):
                flow_count += 1
                yield {"type": "flow", "data": _flow_to_dict(flow)}
        logger.info("Zeek: parsed %d flows from conn.log", flow_count)

    # dns.log, http.log, ssl.log → normalized protocol events
    protocol_logs = {
        "dns.log": "dns",
        "http.log": "http",
        "ssl.log": "tls",
    }
    for log_name, event_type in protocol_logs.items():
        log_path = raw_dir / log_name
        if log_path.exists():
            for idx, rec in enumerate(_iter_zeek_log(log_path)):
                if event_type == "dns":
                    details = {
                        "query": rec.get("query", ""),
                        "qtype": rec.get("qtype_name", ""),
                        "qclass": rec.get("qclass_name", ""),
                        "rcode": rec.get("rcode_name", ""),
                        "answers": rec.get("answers", []),
                    }
                elif event_type == "http":
                    details = {
                        "host": rec.get("host", ""),
                        "uri": rec.get("uri", ""),
                        "method": rec.get("method", ""),
                        "status_code": rec.get("status_code"),
                        "user_agent": rec.get("user_agent", ""),
                        "referrer": rec.get("referrer", ""),
                    }
                else:
                    details = {
                        "server_name": rec.get("server_name", ""),
                        "ja3": rec.get("ja3", ""),
                        "ja3s": rec.get("ja3s", ""),
                        "version": rec.get("version", ""),
                        "cipher": rec.get("cipher", ""),
                        "established": rec.get("established", ""),
                        "subject": rec.get("subject", ""),
                        "issuer": rec.get("issuer", ""),
                    }

                yield {
                    "type": "event",
                    "data": {
                        "id": str(rec.get("uid") or rec.get("fuid") or rec.get("ts") or f"{event_type}-{idx}"),
                        "event_type": event_type,
                        "timestamp": _zeek_ts_to_iso(rec.get("ts")),
                        "src_ip": rec.get("id.orig_h", ""),
                        "src_port": rec.get("id.orig_p", 0),
                        "dst_ip": rec.get("id.resp_h", ""),
                        "dst_port": rec.get("id.resp_p", 0),
                        "transport_proto": str(rec.get("proto", "OTHER")).upper(),
                        "details": details,
                    },
                }

    # x509.log is kept raw for TLS enrichment downstream
    x509_log = raw_dir / "x509.log"
    if x509_log.exists():
        for rec in _iter_zeek_log(x509_log):
            yield {"type": "x509", "data": rec}


def _flow_to_dict(flow) -> dict:
    return {
        "id": flow.id, "src_ip": flow.src_ip, "src_port": flow.src_port,
        "dst_ip": flow.dst_ip, "dst_port": flow.dst_port,
        "transport_proto": flow.transport_proto, "app_proto": flow.app_proto,
        "start_time": flow.start_time.isoformat() if getattr(flow, "start_time", None) else None,
        "end_time": flow.end_time.isoformat() if getattr(flow, "end_time", None) else None,
        "duration_sec": flow.duration_sec,
        "bytes_from_src": flow.bytes_from_src, "bytes_from_dst": flow.bytes_from_dst,
        "packets_from_src": flow.packets_from_src, "packets_from_dst": flow.packets_from_dst,
        "state": flow.state,
    }


def _event_to_dict(event) -> dict:
    return {
        "id": event.id, "event_type": event.event_type,
        "src_ip": event.src_ip, "dst_ip": event.dst_ip,
        "details": event.details,
    }


# ---------------------------------------------------------------------------
# Stage: Suricata
# ---------------------------------------------------------------------------

def handle_suricata(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Run Suricata on each job PCAP and store parsed alerts.

    For multi-PCAP jobs, each PCAP is processed independently and every
    result record is tagged with ``pcap_label``.
    """
    pcaps = _find_all_pcaps_labeled(input_root)
    suricata_bin = shutil.which("suricata")
    if not suricata_bin:
        raise RuntimeError("Suricata binary not found on PATH")

    timeout_seconds = _sensor_timeout("suricata", 1800)

    settings = get_settings()
    runtime_rules_bundle = build_runtime_suricata_bundle(settings.aipam_suricata_rules_dir)
    if runtime_rules_bundle:
        logger.info("Suricata: using managed rules bundle %s", runtime_rules_bundle)
    else:
        logger.warning(
            "Suricata: no managed rules bundle available in %s; continuing with default rule loading",
            settings.aipam_suricata_rules_dir,
        )

    all_results: list[dict] = []

    for pcap, pcap_label in pcaps:
        # Keyed on the staged filename, not the label — see handle_zeek.
        if len(pcaps) == 1:
            raw_dir = sensor_output_dir / "raw"
        else:
            raw_dir = sensor_output_dir / "raw" / pcap.stem
        raw_dir.mkdir(parents=True, exist_ok=True)

        cmd = [suricata_bin, "-r", str(pcap), "-l", str(raw_dir),
               "--set", "community-id.enabled=true"]
        if runtime_rules_bundle:
            cmd.extend(["-S", str(runtime_rules_bundle)])
        logger.info("Running Suricata on %s: %s", pcap.name, " ".join(cmd))
        result = run_capture_tool(
            cmd, raw_dir,
            label=f"suricata/{pcap.name}",
            ceiling_seconds=timeout_seconds,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")[:2000]
            logger.warning("Suricata exited %d for %s: %s", result.returncode, pcap.name, stderr)

        # Parse results and tag with pcap_label
        records = _parse_suricata_results(raw_dir)
        for rec in records:
            rec["pcap_label"] = pcap_label
        all_results.extend(records)
        logger.info("Suricata: %d records from %s", len(records), pcap_label)

    # Write unified sensor.results.jsonl
    out = sensor_output_dir / "sensor.results.jsonl"
    with open(out, "w") as f:
        for r in all_results:
            f.write(json.dumps(r) + "\n")
    logger.info("Suricata: wrote %d total result records across %d PCAP(s)", len(all_results), len(pcaps))


def _parse_suricata_results(raw_dir: Path) -> list[dict]:
    """Parse Suricata eve.json from a raw directory and return result records."""
    from backend.app.parsers import parse_suricata_eve

    eve_json = raw_dir / "eve.json"
    results: list[dict] = []
    if eve_json.exists():
        with open(eve_json) as f:
            raw = [json.loads(line) for line in f if line.strip()]
        alerts = parse_suricata_eve(raw)
        for alert in alerts:
            results.append({"type": "alert", "data": _alert_to_dict(alert)})
        logger.info("Suricata: parsed %d alerts from eve.json", len(alerts))

    return results


def _alert_to_dict(alert) -> dict:
    d = {
        "id": alert.id, "timestamp": str(alert.timestamp),
        "src_ip": alert.src_ip, "dst_ip": alert.dst_ip,
        "src_port": alert.src_port, "dst_port": alert.dst_port,
        "signature_id": alert.signature_id,
        "signature_name": alert.signature_name,
        "severity": alert.severity, "category": alert.category,
    }
    if alert.community_id:
        d["community_id"] = alert.community_id
    return d


# ---------------------------------------------------------------------------
# Sensor: TLS Enrichment
# ---------------------------------------------------------------------------

def handle_tls_enrich(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Enrich TLS data from Zeek ssl.log / x509.log.

    For multi-PCAP jobs, reads from per-label raw subdirectories and
    tags each result with ``pcap_label``.
    """
    zeek_raw = run_output_dir / "sensors" / "zeek" / "raw"
    results: list[dict] = []

    # Determine raw directories: either direct (single PCAP) or per-label subdirs
    raw_dirs: list[tuple[Path, str]] = []
    if zeek_raw.exists():
        subdirs = [d for d in zeek_raw.iterdir() if d.is_dir() and d.name != "extract_files"]
        if subdirs and any((d / "ssl.log").exists() or (d / "x509.log").exists() for d in subdirs):
            # Multi-PCAP: per-label subdirs
            for d in sorted(subdirs):
                raw_dirs.append((d, d.name))
        else:
            # Single PCAP: logs directly in raw/
            raw_dirs.append((zeek_raw, "primary"))

    for raw_dir, pcap_label in raw_dirs:
        # Parse ssl.log for TLS session info
        ssl_log = raw_dir / "ssl.log"
        if ssl_log.exists():
            with open(ssl_log) as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        rec = json.loads(line)
                        results.append({
                            "type": "tls_session",
                            "pcap_label": pcap_label,
                            "data": {
                                "src_ip": rec.get("id.orig_h", ""),
                                "dst_ip": rec.get("id.resp_h", ""),
                                "server_name": rec.get("server_name", ""),
                                "ja3": rec.get("ja3", ""),
                                "ja3s": rec.get("ja3s", ""),
                                "version": rec.get("version", ""),
                                "cipher": rec.get("cipher", ""),
                                "established": rec.get("established", ""),
                                "subject": rec.get("subject", ""),
                                "issuer": rec.get("issuer", ""),
                            },
                        })

        # Parse x509.log for certificate details
        x509_log = raw_dir / "x509.log"
        if x509_log.exists():
            with open(x509_log) as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        rec = json.loads(line)
                        results.append({
                            "type": "x509_cert",
                            "pcap_label": pcap_label,
                            "data": {
                                "serial": rec.get("certificate.serial", ""),
                                "subject": rec.get("certificate.subject", ""),
                                "issuer": rec.get("certificate.issuer", ""),
                                "not_valid_before": rec.get("certificate.not_valid_before", ""),
                                "not_valid_after": rec.get("certificate.not_valid_after", ""),
                                "san_dns": rec.get("san.dns", []),
                            },
                        })

    out = sensor_output_dir / "sensor.results.jsonl"
    with open(out, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    logger.info("tls_enrich: wrote %d TLS records", len(results))


# ---------------------------------------------------------------------------
# Sensor: Beaconing Detection
# ---------------------------------------------------------------------------

def handle_beaconing(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Detect C2 beaconing patterns using the V1 AnomalyDetector."""
    from backend.app.anomaly_detector import AnomalyDetector
    from backend.app.parsers import parse_zeek_conn
    
    grouped_inputs: dict[str, dict[str, object]] = {}

    def _group_for(label: str | None) -> dict[str, object]:
        key = label or ""
        return grouped_inputs.setdefault(
            key,
            {"pcap_label": label, "flows": [], "dns_queries": [], "alerts": []},
        )

    # Read flows and DNS queries from zeek sensor output
    zeek_results = run_output_dir / "sensors" / "zeek" / "sensor.results.jsonl"
    if zeek_results.exists():
        with open(zeek_results) as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    group = _group_for(rec.get("pcap_label"))
                    if rec.get("type") == "flow":
                        group["flows"].append(rec["data"])
                    elif rec.get("type") == "event" and rec.get("data", {}).get("event_type") == "dns":
                        data = rec.get("data", {})
                        details = data.get("details", {}) or {}
                        query = details.get("query") or data.get("query")
                        if query:
                            group["dns_queries"].append({
                                "query": query,
                                "src_ip": data.get("src_ip", ""),
                                "dst_ip": data.get("dst_ip", ""),
                                "timestamp": data.get("timestamp"),
                                "qtype": details.get("qtype", ""),
                                "answers": details.get("answers", []),
                            })

    # Also try raw Zeek logs directly if flow records were not available yet.
    have_flows = any(group["flows"] for group in grouped_inputs.values())
    if not have_flows:
        zeek_raw = run_output_dir / "sensors" / "zeek" / "raw"
        raw_dirs: list[tuple[Path, str | None]] = []
        if zeek_raw.exists():
            # Zeek's per-capture subdirectories are named for the staged file,
            # which is no longer the phase label — translate back via the manifest.
            try:
                stem_to_label = {p.stem: lbl for p, lbl in _find_all_pcaps_labeled(input_root)}
            except FileNotFoundError:
                stem_to_label = {}

            subdirs = [d for d in zeek_raw.iterdir() if d.is_dir() and d.name != "extract_files"]
            if subdirs and any((d / "conn.log").exists() or (d / "dns.log").exists() for d in subdirs):
                raw_dirs = [
                    (d, stem_to_label.get(d.name, d.name)) for d in sorted(subdirs)
                ]
            else:
                fallback_label = None
                if len(stem_to_label) == 1:
                    fallback_label = next(iter(stem_to_label.values()))
                raw_dirs = [(zeek_raw, fallback_label)]

        for raw_dir, pcap_label in raw_dirs:
            group = _group_for(pcap_label)
            conn_log = raw_dir / "conn.log"
            if conn_log.exists():
                with open(conn_log) as f:
                    raw = [json.loads(line) for line in f
                           if line.strip() and not line.startswith("#")]
                parsed = parse_zeek_conn(raw)
                group["flows"].extend(_flow_to_dict(fl) for fl in parsed)

            dns_log = raw_dir / "dns.log"
            if dns_log.exists():
                with open(dns_log) as f:
                    raw_dns = [json.loads(line) for line in f
                               if line.strip() and not line.startswith("#")]
                for rec in raw_dns:
                    query = rec.get("query")
                    if query:
                        group["dns_queries"].append({
                            "query": query,
                            "src_ip": rec.get("id.orig_h", ""),
                            "dst_ip": rec.get("id.resp_h", ""),
                            "timestamp": _zeek_ts_to_iso(rec.get("ts")),
                            "qtype": rec.get("qtype_name", ""),
                            "answers": rec.get("answers", []),
                        })

    if not any(group["flows"] for group in grouped_inputs.values()):
        logger.info("beaconing: no flows available, writing empty results")
        (sensor_output_dir / "sensor.results.jsonl").write_text("")
        return

    # Re-parse into FlowRecord objects for the anomaly detector
    from backend.app.domain_models import FlowRecord, AlertRecord
    from datetime import datetime, timezone
    _now = datetime.now(timezone.utc)

    # Read alerts from suricata sensor output
    suri_results = run_output_dir / "sensors" / "suricata" / "sensor.results.jsonl"
    if suri_results.exists():
        with open(suri_results) as f:
            for line in f:
                if line.strip():
                    try:
                        rec = json.loads(line)
                        if rec.get("type") == "alert":
                            ad = rec["data"]
                            group = _group_for(rec.get("pcap_label"))
                            group["alerts"].append(ad)
                    except Exception:
                        continue

    results = []
    for group in grouped_inputs.values():
        flows = group["flows"]
        if not flows:
            continue

        flow_objects = []
        for fd in flows:
            try:
                flow_objects.append(FlowRecord(
                    id=fd.get("id", ""),
                    src_ip=fd.get("src_ip", ""),
                    src_port=int(fd.get("src_port", 0)),
                    dst_ip=fd.get("dst_ip", ""),
                    dst_port=int(fd.get("dst_port", 0)),
                    transport_proto=fd.get("transport_proto", "TCP"),
                    app_proto=fd.get("app_proto", "UNKNOWN"),
                    start_time=fd.get("start_time", _now),
                    end_time=fd.get("end_time", _now),
                    duration_sec=float(fd.get("duration_sec", 0) or 0),
                    bytes_from_src=int(fd.get("bytes_from_src", 0)),
                    bytes_from_dst=int(fd.get("bytes_from_dst", 0)),
                    packets_from_src=int(fd.get("packets_from_src", 0)),
                    packets_from_dst=int(fd.get("packets_from_dst", 0)),
                    state=fd.get("state"),
                ))
            except Exception:
                continue

        alert_objects: list[AlertRecord] = []
        for ad in group["alerts"]:
            try:
                alert_objects.append(AlertRecord(
                    id=ad.get("id", ""),
                    timestamp=ad.get("timestamp", _now),
                    src_ip=ad.get("src_ip", ""),
                    src_port=int(ad.get("src_port", 0)),
                    dst_ip=ad.get("dst_ip", ""),
                    dst_port=int(ad.get("dst_port", 0)),
                    alert_source=ad.get("alert_source", "suricata"),
                    severity=str(ad.get("severity", "medium")),
                    signature_name=ad.get("signature_name", ad.get("signature", "")),
                    category=ad.get("category", ""),
                ))
            except Exception:
                continue

        detector = AnomalyDetector()
        report = detector.analyze(
            flow_objects,
            alert_objects,
            dns_queries=group["dns_queries"] or None,
        )

        for finding in report.findings:
            result = {
                "type": "anomaly",
                "data": finding.to_dict(),
            }
            if group["pcap_label"]:
                result["pcap_label"] = group["pcap_label"]
            results.append(result)

    out = sensor_output_dir / "sensor.results.jsonl"
    with open(out, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    logger.info("beaconing: wrote %d anomaly findings (score=%.2f)",
                len(results), report.overall_anomaly_score)


# ---------------------------------------------------------------------------
# Sensor: File Triage
# ---------------------------------------------------------------------------

# Magic-byte signatures for file type identification (no python-magic needed)
_MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    # (header_bytes, mime_type, human_label)
    (b"MZ", "application/x-dosexec", "Windows PE executable"),
    (b"\x7fELF", "application/x-elf", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary", "Mach-O fat binary"),
    (b"\xfe\xed\xfa", "application/x-mach-binary", "Mach-O binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "Mach-O 64-bit binary"),
    (b"PK\x03\x04", "application/zip", "ZIP archive"),
    (b"PK\x05\x06", "application/zip", "ZIP archive (empty)"),
    (b"\x1f\x8b", "application/gzip", "Gzip archive"),
    (b"Rar!\x1a\x07", "application/x-rar", "RAR archive"),
    (b"\x89PNG", "image/png", "PNG image"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG image"),
    (b"GIF8", "image/gif", "GIF image"),
    (b"%PDF", "application/pdf", "PDF document"),
    (b"{\rt", "application/rtf", "RTF document"),
    (b"\xd0\xcf\x11\xe0", "application/x-ole-storage", "OLE/MS Office document"),
    (b"<script", "text/javascript", "JavaScript"),
    (b"<!DOCTYPE", "text/html", "HTML document"),
    (b"<html", "text/html", "HTML document"),
]

# File types considered suspicious in network traffic
_SUSPICIOUS_TYPES = {
    "application/x-dosexec",
    "application/x-elf",
    "application/x-mach-binary",
    "application/x-ole-storage",
    "text/javascript",
}


def _detect_file_type(data: bytes) -> tuple[str, str]:
    """Identify file type using magic bytes. Returns (mime, label)."""
    header = data[:16]
    for sig, mime, label in _MAGIC_SIGNATURES:
        if header.startswith(sig):
            return mime, label
    # Heuristic: check if it looks like ASCII text
    try:
        sample = data[:512]
        sample.decode("utf-8")
        return "text/plain", "Text file"
    except (UnicodeDecodeError, ValueError):
        pass
    return "application/octet-stream", "Unknown binary"


def _find_extracted_files(run_output_dir: Path) -> list[Path]:
    """Search all possible locations for Zeek-extracted files."""
    search_dirs = [
        run_output_dir / "extracted_files" / "files",
        run_output_dir / "sensors" / "zeek" / "raw" / "extract_files",
    ]
    # Also check per-PCAP subdirs under zeek raw
    zeek_raw = run_output_dir / "sensors" / "zeek" / "raw"
    if zeek_raw.exists():
        for sub in zeek_raw.iterdir():
            if sub.is_dir() and sub.name != "extract_files":
                ef = sub / "extract_files"
                if ef.exists():
                    search_dirs.append(ef)

    found: list[Path] = []
    for d in search_dirs:
        if d.exists():
            found.extend(f for f in d.iterdir() if f.is_file())
    return found



def _build_zeek_files_lookup(run_output_dir: Path) -> dict[str, dict]:
    """Parse all Zeek files.log files and build a lookup from extracted filename → metadata.

    Returns a dict keyed by the ``extracted`` filename (e.g.
    ``extract-1447987831.266072-HTTP-FkxFpx33QaaUZ7Bakc``) with values containing
    source/dest IPs, protocol, timestamp, connection UID, and pcap_label.
    """
    from datetime import datetime, timezone

    lookup: dict[str, dict] = {}
    zeek_raw = run_output_dir / "sensors" / "zeek" / "raw"
    if not zeek_raw.exists():
        return lookup

    # Collect all files.log paths: either directly in raw/ or in per-PCAP subdirs
    files_logs: list[tuple[Path, str]] = []
    direct_files_log = zeek_raw / "files.log"
    if direct_files_log.exists():
        files_logs.append((direct_files_log, "primary"))

    for sub in sorted(zeek_raw.iterdir()):
        if sub.is_dir() and sub.name != "extract_files":
            fl = sub / "files.log"
            if fl.exists():
                files_logs.append((fl, sub.name))

    for files_log_path, pcap_label in files_logs:
        try:
            with open(files_log_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    extracted_name = rec.get("extracted")
                    if not extracted_name:
                        continue

                    # Convert Zeek epoch timestamp to ISO string
                    ts_val = rec.get("ts")
                    ts_iso = None
                    if isinstance(ts_val, (int, float)):
                        ts_iso = datetime.fromtimestamp(ts_val, timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        )

                    lookup[extracted_name] = {
                        "src_ip": rec.get("id.orig_h"),
                        "src_port": rec.get("id.orig_p"),
                        "dst_ip": rec.get("id.resp_h"),
                        "dst_port": rec.get("id.resp_p"),
                        "protocol": rec.get("source"),  # e.g. "HTTP", "SSL"
                        "zeek_mime": rec.get("mime_type"),
                        "uid": rec.get("uid"),
                        "fuid": rec.get("fuid"),
                        "ts": ts_iso,
                        "pcap_label": pcap_label,
                        "seen_bytes": rec.get("seen_bytes"),
                    }
        except Exception as e:
            logger.warning("file_triage: failed to parse %s: %s", files_log_path, e)

    logger.info("file_triage: built Zeek files.log lookup with %d entries", len(lookup))
    return lookup



def handle_file_triage(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Triage extracted files from Zeek's file extraction."""
    from backend.app.config_v2 import get_settings
    settings = get_settings()

    files = _find_extracted_files(run_output_dir)
    logger.info("file_triage: found %d extracted files to triage", len(files))

    # --- Build Zeek files.log lookup for enrichment ---
    zeek_lookup = _build_zeek_files_lookup(run_output_dir)

    # --- Compile YARA rules if available ---
    rules = None
    try:
        import yara
        yara_dir = settings.aipam_yara_rules_dir
        if yara_dir.exists():
            rule_files = {}
            for p in yara_dir.glob("*.yar*"):
                rule_files[p.stem] = str(p)

            if rule_files:
                try:
                    rules = yara.compile(filepaths=rule_files)
                    logger.info("file_triage: compiled %d YARA rule files", len(rule_files))
                except yara.Error as e:
                    logger.error("file_triage: failed to compile YARA rules: %s", e)
    except ImportError:
        logger.warning("file_triage: yara-python not installed — skipping YARA scan")

    results = []
    import hashlib
    for fpath in files:
        file_bytes = fpath.read_bytes()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        size = len(file_bytes)
        mime, file_label = _detect_file_type(file_bytes)
        suspicious = mime in _SUSPICIOUS_TYPES

        # Scan with YARA
        yara_matches = []
        if rules:
            try:
                matches = rules.match(data=file_bytes)
                yara_matches = [m.rule for m in matches]
            except Exception as e:
                logger.warning("file_triage: YARA match failed for %s: %s", fpath.name, e)

        # Enrich with Zeek files.log metadata
        zeek_meta = zeek_lookup.get(fpath.name, {})

        # Build a human-readable filename from network context
        display_name = fpath.name
        if zeek_meta:
            parts = []
            proto = zeek_meta.get("protocol", "")
            src = zeek_meta.get("src_ip", "")
            dst = zeek_meta.get("dst_ip", "")
            dst_port = zeek_meta.get("dst_port", "")
            if proto:
                parts.append(proto)
            if src and dst:
                parts.append(f"{src}->{dst}:{dst_port}")
            elif dst:
                parts.append(f"->{dst}:{dst_port}")
            # Append a short type hint from the MIME
            ext_hint = file_label.split("/")[-1].split(";")[0][:10] if file_label else ""
            if ext_hint:
                parts.append(ext_hint)
            if parts:
                display_name = " | ".join(parts)

        # Build connection context string for extracted_path
        conn_ctx = None
        if zeek_meta.get("src_ip") and zeek_meta.get("dst_ip"):
            conn_ctx = (
                f"{zeek_meta.get('src_ip')}:{zeek_meta.get('src_port', '?')}"
                f" → {zeek_meta.get('dst_ip')}:{zeek_meta.get('dst_port', '?')}"
                f" ({zeek_meta.get('protocol', '?')})"
            )

        res_item_data = {
            "file_id": fpath.name,
            "filename": display_name,
            "sha256": sha256,
            "size_bytes": size,
            "mime": mime,
            "file_type": file_label,
            "suspicious": suspicious,
            "yara_matches": yara_matches,
            # Network context from Zeek files.log
            "src_ip": zeek_meta.get("src_ip"),
            "dst_ip": zeek_meta.get("dst_ip"),
            "src_port": zeek_meta.get("src_port"),
            "dst_port": zeek_meta.get("dst_port"),
            "source": zeek_meta.get("protocol"),  # e.g. "HTTP", "SSL" — maps to File.source
            "ts": zeek_meta.get("ts"),
            "pcap_label": zeek_meta.get("pcap_label"),
            "host_ip": zeek_meta.get("src_ip"),  # source host that transferred the file
            "uid": zeek_meta.get("uid"),
            "extracted_path": conn_ctx,  # connection context
        }

        if suspicious or yara_matches:
            logger.warning(
                "file_triage: SUSPICIOUS file %s type=%s size=%d sha256=%s yara=%s",
                fpath.name, file_label, size, sha256, yara_matches,
            )

        results.append({
            "type": "extracted_file",
            "data": res_item_data,
        })

    out = sensor_output_dir / "sensor.results.jsonl"
    with open(out, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    suspicious_count = sum(1 for r in results if r["data"].get("suspicious"))
    yara_count = sum(1 for r in results if r["data"].get("yara_matches"))
    logger.info(
        "file_triage: triaged %d files, %d suspicious, %d YARA matches",
        len(results), suspicious_count, yara_count,
    )


# ---------------------------------------------------------------------------
# Sensor: CAPA Enrichment
# ---------------------------------------------------------------------------

_CAPA_EXECUTABLE_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-elf",
    "application/x-mach-binary",
}

_CAPA_DEFAULT_RULES_DIR = Path("/opt/aipam/rules/capa")
_CAPA_DEFAULT_SIGNATURES_DIR = Path("/opt/aipam/signatures/capa")


def _load_file_triage_records(run_output_dir: Path) -> list[dict]:
    """Read extracted-file records emitted by the file_triage sensor."""
    results_file = run_output_dir / "sensors" / "file_triage" / "sensor.results.jsonl"
    if not results_file.exists():
        return []

    records: list[dict] = []
    with open(results_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if raw.get("type") != "extracted_file":
                continue
            data = raw.get("data")
            if isinstance(data, dict):
                records.append(data)
    return records



def _format_capa_framework_entry(entry: object) -> str | None:
    """Normalize ATT&CK/MBC metadata entries from CAPA JSON output."""
    if isinstance(entry, str):
        text = entry.strip()
        return text or None
    if not isinstance(entry, dict):
        return None

    title_parts = [
        str(entry.get(key, "")).strip()
        for key in ("tactic", "technique", "behavior", "objective", "method", "name")
        if str(entry.get(key, "")).strip()
    ]
    identifier = str(entry.get("id") or entry.get("ID") or "").strip()

    title = " / ".join(title_parts)
    if title and identifier:
        return f"{title} ({identifier})"
    return title or identifier or None


def _extract_capa_capabilities(payload: dict) -> list[dict]:
    """Return normalized capability metadata from CAPA JSON output."""
    rules = payload.get("rules")
    if not isinstance(rules, dict):
        return []

    capabilities: list[dict] = []
    for rule_name, rule_payload in rules.items():
        if not isinstance(rule_payload, dict):
            continue
        meta = rule_payload.get("meta")
        if not isinstance(meta, dict):
            meta = {}

        name = str(meta.get("name") or rule_name or "").strip()
        if not name:
            continue

        attack_entries = meta.get("att&ck") or meta.get("attack") or []
        mbc_entries = meta.get("mbc") or []

        attack = [
            text for text in (_format_capa_framework_entry(entry) for entry in attack_entries)
            if text
        ]
        mbc = [
            text for text in (_format_capa_framework_entry(entry) for entry in mbc_entries)
            if text
        ]

        capabilities.append({
            "name": name,
            "namespace": str(meta.get("namespace") or "").strip(),
            "attack": attack,
            "mbc": mbc,
        })

    capabilities.sort(key=lambda item: (item.get("namespace", ""), item.get("name", "")))
    return capabilities


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            results.append(value)
    return results


def handle_capa(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Run CAPA against extracted executable-like files and emit findings."""
    capa_bin = shutil.which("capa")
    out = sensor_output_dir / "sensor.results.jsonl"
    if not capa_bin:
        logger.info("capa: binary not found on PATH — writing empty results")
        out.write_text("")
        return

    triage_records = _load_file_triage_records(run_output_dir)
    if not triage_records:
        logger.info("capa: no file_triage records available, writing empty results")
        out.write_text("")
        return

    extracted_paths = {path.name: path for path in _find_extracted_files(run_output_dir)}
    candidates = [
        record for record in triage_records
        if str(record.get("mime") or "") in _CAPA_EXECUTABLE_MIME_TYPES
    ]
    if not candidates:
        logger.info("capa: no executable extracted files available, writing empty results")
        out.write_text("")
        return

    cmd_base = [capa_bin]
    configured_rules_dir = os.getenv("AIPAM_CAPA_RULES_DIR")
    rules_dir = Path(configured_rules_dir) if configured_rules_dir else _CAPA_DEFAULT_RULES_DIR
    if rules_dir.exists():
        cmd_base.extend(["-r", str(rules_dir)])
    elif configured_rules_dir:
        logger.warning(
            "capa: configured rules directory missing (%s=%s) — writing empty results",
            "AIPAM_CAPA_RULES_DIR",
            rules_dir,
        )
        out.write_text("")
        return
    else:
        logger.info(
            "capa: rules directory %s not present; relying on embedded/default rules if available",
            rules_dir,
        )

    configured_signatures_dir = os.getenv("AIPAM_CAPA_SIGNATURES_DIR")
    signatures_dir = (
        Path(configured_signatures_dir)
        if configured_signatures_dir else _CAPA_DEFAULT_SIGNATURES_DIR
    )
    if signatures_dir.exists():
        cmd_base.extend(["-s", str(signatures_dir)])
    elif configured_signatures_dir:
        logger.warning(
            "capa: configured signatures directory missing (%s=%s) — continuing without signatures",
            "AIPAM_CAPA_SIGNATURES_DIR",
            signatures_dir,
        )

    results: list[dict] = []
    analyzed_count = 0
    for record in candidates:
        file_id = str(record.get("file_id") or "").strip()
        if not file_id:
            continue
        file_path = extracted_paths.get(file_id)
        if not file_path:
            logger.warning("capa: extracted file path missing for %s", file_id)
            continue

        analyzed_count += 1
        try:
            completed = subprocess.run(
                [*cmd_base, "-j", str(file_path)],
                timeout=300,
                capture_output=True,
                text=True,
            )
        except subprocess.TimeoutExpired:
            logger.warning("capa: timed out while analyzing %s", file_id)
            continue
        except Exception as exc:
            logger.warning("capa: failed to execute against %s: %s", file_id, exc)
            continue

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()[:1000]
            logger.warning(
                "capa: exited %d for %s: %s",
                completed.returncode,
                file_id,
                stderr,
            )
            continue

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            logger.warning("capa: invalid JSON for %s: %s", file_id, exc)
            continue

        capabilities = _extract_capa_capabilities(payload)
        if not capabilities:
            continue

        capability_names = [str(item.get("name") or "") for item in capabilities if item.get("name")]
        attack = _dedupe_preserve_order([
            value
            for item in capabilities
            for value in item.get("attack", [])
            if isinstance(value, str)
        ])
        mbc = _dedupe_preserve_order([
            value
            for item in capabilities
            for value in item.get("mbc", [])
            if isinstance(value, str)
        ])
        namespaces = _dedupe_preserve_order([
            str(item.get("namespace") or "")
            for item in capabilities
            if str(item.get("namespace") or "")
        ])

        display_name = str(record.get("filename") or file_id)
        summary_parts = [
            f"capa identified {len(capabilities)} capability rule(s) in extracted executable {display_name}."
        ]
        if capability_names:
            summary_parts.append(
                "Top capabilities: " + ", ".join(capability_names[:5]) + "."
            )
        if attack:
            summary_parts.append("ATT&CK: " + "; ".join(attack[:5]) + ".")

        results.append({
            "event_type": "finding",
            "sensor": "capa",
            "severity": "high" if attack or len(capabilities) >= 5 else "medium",
            "category": "malware_capability",
            "title": f"CAPA identified capabilities in {display_name}",
            "summary": " ".join(summary_parts),
            "host_ip": record.get("host_ip") or record.get("src_ip"),
            "pcap_label": record.get("pcap_label"),
            "ts": record.get("ts"),
            "evidence": {
                "file_id": file_id,
                "filename": display_name,
                "sha256": record.get("sha256"),
                "mime": record.get("mime"),
                "file_type": record.get("file_type"),
                "source": record.get("source"),
                "src_ip": record.get("src_ip"),
                "dst_ip": record.get("dst_ip"),
                "pcap_label": record.get("pcap_label"),
                "capability_count": len(capabilities),
                "capabilities": capability_names[:20],
                "namespaces": namespaces[:20],
                "attack": attack[:20],
                "mbc": mbc[:20],
            },
        })

    with open(out, "w") as f:
        for item in results:
            f.write(json.dumps(item) + "\n")

    logger.info(
        "capa: analyzed %d executable file(s), produced %d findings",
        analyzed_count,
        len(results),
    )


# ---------------------------------------------------------------------------
# Sensor: Threat Intelligence Matcher
# ---------------------------------------------------------------------------

def handle_ti_matcher(
    input_root: Path,
    sensor_output_dir: Path,
    job_id: str,
    execution_profile: str,
    *, run_output_dir: Path,
) -> None:
    """Match observed artifacts against threat intelligence feeds.

    Checks IPs, domains/SNI values, file hashes, and TLS JA3 fingerprints
    against local TI bundle files if available.

    Falls back to flagging only IPs that triggered Suricata alerts as IOCs
    (i.e. corroborated by IDS signatures — not every public IP).
    """
    import ipaddress

    # ── Load TI feeds if available ───────────────────────────────────
    ti_ips: set[str] = set()
    ti_domains: set[str] = set()
    ti_hashes: set[str] = set()
    ti_ja3: set[str] = set()
    ti_ja3s: set[str] = set()

    ti_base = Path(os.getenv("AIPAM_TI_BUNDLE_DIR", "/opt/aipam/ti/bundles"))
    # The TI bundle dir is often a mounted volume. Reading it (exists/iterdir/
    # read_text) can raise OSError if that mount is unavailable — a stale NFS
    # handle or "No such device". Degrade to "no TI feeds" rather than letting
    # the whole handler crash, which would also drop the Suricata alert
    # correlation below (it needs no TI bundle).
    try:
        if ti_base.exists():
            for bundle_dir in ti_base.iterdir():
                if not bundle_dir.is_dir():
                    continue
                for fname, target_set, normalizer in [
                    ("ips.txt", ti_ips, _normalize_text_indicator),
                    ("domains.txt", ti_domains, _normalize_host_indicator),
                    ("hashes_sha256.txt", ti_hashes, _normalize_text_indicator),
                    ("ja3.txt", ti_ja3, _normalize_text_indicator),
                    ("ja3s.txt", ti_ja3s, _normalize_text_indicator),
                ]:
                    fp = bundle_dir / fname
                    if fp.exists():
                        for line in fp.read_text().splitlines():
                            val = line.strip()
                            if val and not val.startswith("#"):
                                target_set.add(normalizer(val))
            logger.info(
                "ti_matcher: loaded %d IPs, %d domains, %d hashes, %d JA3, %d JA3S from TI bundles",
                len(ti_ips), len(ti_domains), len(ti_hashes), len(ti_ja3), len(ti_ja3s),
            )
    except OSError as exc:
        logger.warning(
            "ti_matcher: TI bundle dir %s unavailable (%s) — continuing with alert "
            "correlation only", ti_base, exc,
        )

    has_ti_feeds = bool(ti_ips or ti_domains or ti_hashes or ti_ja3 or ti_ja3s)

    # ── Collect observed IPs and alert-corroborated IPs ──────────────
    observed_ips: set[str] = set()
    alert_ips: set[str] = set()          # IPs that triggered Suricata alerts
    alert_sigs: dict[str, list[str]] = {}  # ip -> list of signature names
    observed_domains: set[str] = set()
    observed_hashes: set[str] = set()
    observed_snis: set[str] = set()
    observed_ja3: set[str] = set()
    observed_ja3s: set[str] = set()

    zeek_results = run_output_dir / "sensors" / "zeek" / "sensor.results.jsonl"
    if zeek_results.exists():
        with open(zeek_results) as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    rtype = rec.get("type")
                    d = rec.get("data", {})
                    if rtype == "flow":
                        observed_ips.add(d.get("src_ip", ""))
                        observed_ips.add(d.get("dst_ip", ""))
                    elif rtype == "event":
                        details = d.get("details", {})
                        if not isinstance(details, dict):
                            details = {}
                        query = details.get("query") or d.get("query")
                        host = details.get("host") or d.get("host")
                        if query:
                            observed_domains.add(_normalize_host_indicator(query))
                        if host:
                            observed_domains.add(_normalize_host_indicator(host))

    tls_results = run_output_dir / "sensors" / "tls_enrich" / "sensor.results.jsonl"
    if tls_results.exists():
        with open(tls_results) as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    if rec.get("type") != "tls_session":
                        continue
                    d = rec.get("data", {})
                    server_name = _normalize_host_indicator(d.get("server_name"))
                    ja3 = _normalize_text_indicator(d.get("ja3"))
                    ja3s = _normalize_text_indicator(d.get("ja3s"))
                    if server_name:
                        observed_snis.add(server_name)
                    if ja3:
                        observed_ja3.add(ja3)
                    if ja3s:
                        observed_ja3s.add(ja3s)

    file_results = run_output_dir / "sensors" / "file_triage" / "sensor.results.jsonl"
    if file_results.exists():
        with open(file_results) as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    if rec.get("type") != "extracted_file":
                        continue
                    d = rec.get("data", {})
                    sha256 = _normalize_text_indicator(d.get("sha256"))
                    if sha256:
                        observed_hashes.add(sha256)

    suri_results = run_output_dir / "sensors" / "suricata" / "sensor.results.jsonl"
    if suri_results.exists():
        with open(suri_results) as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    if rec.get("type") == "alert":
                        d = rec.get("data", {})
                        sig = d.get("signature_name") or d.get("signature", "")
                        for ip_key in ("src_ip", "dst_ip"):
                            ip = d.get(ip_key, "")
                            if ip:
                                alert_ips.add(ip)
                                alert_sigs.setdefault(ip, [])
                                if sig and sig not in alert_sigs[ip]:
                                    alert_sigs[ip].append(sig)

    observed_ips.discard("")

    # ── Build IOC results ────────────────────────────────────────────
    results = []
    seen_iocs: set[tuple[str, str]] = set()

    def _append_ioc(
        ioc_type: str,
        value: str,
        *,
        matched_feed: str,
        confidence: str,
        alert_signatures: list[str] | None = None,
    ) -> None:
        normalized_value = (
            _normalize_host_indicator(value)
            if ioc_type in {"domain", "sni"}
            else _normalize_text_indicator(value)
        )
        if not normalized_value or (ioc_type, normalized_value) in seen_iocs:
            return

        data = {
            "ioc_type": ioc_type,
            "value": normalized_value,
            "matched_feed": matched_feed,
            "confidence": confidence,
        }
        if ioc_type == "ip":
            data["ip"] = normalized_value
        if alert_signatures:
            data["alert_signatures"] = alert_signatures[:5]

        results.append({"type": "ti_indicator", "data": data})
        seen_iocs.add((ioc_type, normalized_value))

    for ip_str in observed_ips:
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_private or addr.is_loopback:
                continue
        except ValueError:
            continue

        # Check against TI feed
        if has_ti_feeds and ip_str.lower() in ti_ips:
            _append_ioc("ip", ip_str, matched_feed="ti_bundle", confidence="high")
        # Check if corroborated by Suricata alert
        elif ip_str in alert_ips:
            sigs = alert_sigs.get(ip_str, [])
            _append_ioc(
                "ip",
                ip_str,
                matched_feed="suricata_correlated",
                confidence="medium",
                alert_signatures=sigs,
            )

    # Domain matches against TI feeds
    if has_ti_feeds:
        for domain in observed_domains:
            if domain in ti_domains:
                _append_ioc("domain", domain, matched_feed="ti_bundle", confidence="high")

        for sha256 in observed_hashes:
            if sha256 in ti_hashes:
                _append_ioc("hash", sha256, matched_feed="ti_bundle", confidence="high")

        for sni in observed_snis:
            if sni in ti_domains:
                _append_ioc("sni", sni, matched_feed="ti_bundle", confidence="high")

        for ja3 in observed_ja3:
            if ja3 in ti_ja3:
                _append_ioc("ja3", ja3, matched_feed="ti_bundle", confidence="high")

        for ja3s in observed_ja3s:
            if ja3s in ti_ja3s:
                _append_ioc("ja3s", ja3s, matched_feed="ti_bundle", confidence="high")

    out = sensor_output_dir / "sensor.results.jsonl"
    with open(out, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    logger.info("ti_matcher: produced %d IOCs (%d from TI feeds, %d from alert correlation)",
                len(results),
                sum(1 for r in results if r["data"].get("matched_feed") == "ti_bundle"),
                sum(1 for r in results if r["data"].get("matched_feed") == "suricata_correlated"))

