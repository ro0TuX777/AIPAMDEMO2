"""
Phase 2 tests — Sensor Registry, Job Directory, Preflight, SensorRunner, Orchestrator, Recovery.
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")

from backend.app.models.job import Job
from backend.app.pipeline.job_dir import (
    cleanup_job_directory,
    compute_pcap_sha256,
    create_job_directory,
    create_sensor_output_dir,
    get_job_disk_usage,
    link_pcap,
    read_input_meta,
    write_input_meta,
)
from backend.app.pipeline.preflight import (
    PreflightResult,
    check_disk_space,
    check_disk_thresholds,
    check_extracted_quota,
    check_job_quota,
)
from backend.app.pipeline.recovery import recover_interrupted_jobs
from backend.app.pipeline.sensor_handlers import _parse_zeek_results, handle_beaconing, handle_capa, handle_ti_matcher
from backend.app.pipeline.sensor_runner import run_sensor
from backend.app.sensors.registry import (
    SENSORS,
    SensorDef,
    get_all_for_profile,
    get_sensors_for_profile,
    get_stages_for_profile,
    validate_image_allowlist,
)


def _uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ========================================================================
# Sensor Registry Tests
# ========================================================================

class TestSensorRegistry:
    def test_all_sensors_defined(self):
        expected = {"zeek", "suricata", "beaconing", "file_triage", "capa", "ti_matcher", "tls_enrich"}
        assert set(SENSORS.keys()) == expected

    def test_stages_are_stage_type(self):
        for name in ("zeek", "suricata"):
            assert SENSORS[name].type == "stage"

    def test_sensors_are_sensor_type(self):
        for name in ("beaconing", "file_triage", "capa", "ti_matcher", "tls_enrich"):
            assert SENSORS[name].type == "sensor"
            # Sensors now use in-process handlers instead of Docker images
            assert SENSORS[name].handler is not None

    def test_triage_profile(self):
        sensors = get_sensors_for_profile("triage")
        names = [s.name for s in sensors]
        assert "tls_enrich" in names
        assert "ti_matcher" in names
        assert "beaconing" not in names  # standard/deep only

    def test_standard_profile(self):
        sensors = get_sensors_for_profile("standard")
        names = [s.name for s in sensors]
        assert len(names) == 5
        assert names == ["tls_enrich", "beaconing", "file_triage", "capa", "ti_matcher"]

    def test_deep_profile_includes_all(self):
        all_items = get_all_for_profile("deep")
        assert len(all_items) == 7  # 2 stages + 5 sensors

    def test_stages_order(self):
        stages = get_stages_for_profile("standard")
        names = [s.name for s in stages]
        assert names == ["zeek", "suricata"]

    def test_image_allowlist_valid(self):
        # All sensors now use in-process handlers, so no images in allowlist.
        # The function still works — it just checks the registry.
        # With no Docker images registered, all images are rejected.
        assert validate_image_allowlist("aipam/sensor-beaconing:1.0.0") is False

    def test_image_allowlist_invalid(self):
        assert validate_image_allowlist("evil/image:latest") is False

    def test_sensor_resource_limits(self):
        b = SENSORS["beaconing"]
        assert b.timeout_seconds == 900
        assert b.mem_limit == "2g"
        assert b.pids_limit == 256


# ========================================================================
# Job Directory Tests
# ========================================================================

class TestJobDirectory:
    def test_create_job_directory(self, tmp_path):
        job_id = _uuid()
        job_dir = _legacy_job_directory(tmp_path, job_id)
        assert (job_dir / "input").is_dir()
        assert (job_dir / "runtime").is_dir()
        assert (job_dir / "sensors").is_dir()
        assert (job_dir / "normalized").is_dir()
        assert (job_dir / "report").is_dir()
        assert (job_dir / "extracted_files" / "files").is_dir()

    def test_create_sensor_output_dir(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        sensor_dir = create_sensor_output_dir(job_dir, "beaconing")
        assert sensor_dir.is_dir()
        assert (sensor_dir / "raw").is_dir()

    def test_link_pcap(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        pcap = tmp_path / "source.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
        dest = link_pcap(job_dir, pcap)
        assert dest.exists()
        assert dest.name == "pcap.pcap"
        assert dest.stat().st_size == pcap.stat().st_size

    def test_write_and_read_input_meta(self, tmp_path):
        job_id = _uuid()
        job_dir = _legacy_job_directory(tmp_path, job_id)
        write_input_meta(
            job_dir,
            job_id=job_id,
            pcap_filename="test.pcap",
            pcap_sha256="abc123",
            execution_profile="standard",
        )
        meta = read_input_meta(job_dir)
        assert meta["job_id"] == job_id
        assert meta["pcap_filename"] == "test.pcap"
        assert meta["execution_profile"] == "standard"

    def test_compute_pcap_sha256(self, tmp_path):
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"hello world")
        sha = compute_pcap_sha256(pcap)
        assert len(sha) == 64  # SHA-256 hex length

    def test_get_job_disk_usage(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        (job_dir / "input" / "pcap.pcap").write_bytes(b"\x00" * 1000)
        usage = get_job_disk_usage(job_dir)
        assert usage >= 1000

    def test_cleanup_job_directory(self, tmp_path):
        job_id = _uuid()
        _legacy_job_directory(tmp_path, job_id)
        assert (tmp_path / job_id).is_dir()
        assert cleanup_job_directory(tmp_path, job_id) is True
        assert not (tmp_path / job_id).exists()



# ========================================================================
# Preflight / Disk Guardrails Tests
# ========================================================================

class TestPreflight:
    @patch("backend.app.pipeline.preflight.shutil.disk_usage")
    def test_check_disk_space_sufficient(self, mock_usage, tmp_path):
        mock_usage.return_value = MagicMock(free=500_000_000, total=1_000_000_000)
        result = check_disk_space(10_000_000, tmp_path, preflight_multiplier=4)
        assert result.ok is True
        assert result.required_bytes == 40_000_000

    @patch("backend.app.pipeline.preflight.shutil.disk_usage")
    def test_check_disk_space_insufficient(self, mock_usage, tmp_path):
        mock_usage.return_value = MagicMock(free=10_000_000, total=1_000_000_000)
        result = check_disk_space(100_000_000, tmp_path, preflight_multiplier=4)
        assert result.ok is False
        assert "Insufficient disk" in result.message

    @patch("backend.app.pipeline.preflight.shutil.disk_usage")
    def test_check_disk_thresholds(self, mock_usage, tmp_path):
        # 90% usage: warn=True, critical=False
        mock_usage.return_value = MagicMock(free=100, total=1000)
        warn, crit, pct = check_disk_thresholds(tmp_path, warn_pct=80, critical_pct=95)
        assert warn is True
        assert crit is False
        assert pct == 90.0

    def test_check_job_quota_under(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        (job_dir / "input" / "pcap.pcap").write_bytes(b"\x00" * 100)
        assert check_job_quota(job_dir, 1_000_000) is False

    def test_check_job_quota_over(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        (job_dir / "input" / "pcap.pcap").write_bytes(b"\x00" * 1000)
        assert check_job_quota(job_dir, 500) is True

    def test_check_extracted_quota_no_dir(self, tmp_path):
        job_dir = tmp_path / "empty_job"
        job_dir.mkdir()
        assert check_extracted_quota(job_dir, 1_000_000) is False

    def test_check_extracted_quota_over(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        ef_dir = job_dir / "extracted_files" / "files"
        (ef_dir / "big.bin").write_bytes(b"\x00" * 2000)
        assert check_extracted_quota(job_dir, 500) is True


# ========================================================================
# Sensor Runner Tests (mocked Docker)
# ========================================================================

def _make_mock_docker(exit_code=0, logs=b"sensor output"):
    """Create a mock Docker client."""
    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": exit_code}
    mock_container.logs.return_value = logs
    mock_container.kill = MagicMock()
    mock_container.remove = MagicMock()

    mock_client = MagicMock()
    mock_client.images.get.return_value = MagicMock()
    mock_client.containers.run.return_value = mock_container
    return mock_client


def _make_docker_sensor_def(name="test_docker_sensor", **overrides):
    """Create a SensorDef that uses Docker (no handler) for testing Docker path.

    Also registers it in SENSORS so the allowlist check passes.
    """
    defaults = dict(
        name=name, type="sensor", image="aipam/sensor-test:1.0.0",
        handler=None, timeout_seconds=600, mem_limit="2g",
    )
    defaults.update(overrides)
    sd = SensorDef(**defaults)
    # Temporarily add to registry so allowlist passes
    SENSORS[sd.name] = sd
    return sd


class TestSensorRunner:
    def test_parse_zeek_results_emits_protocol_event_details(self, tmp_path):
        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()
        (raw_dir / "dns.log").write_text(
            json.dumps({
                "ts": 1710000000.0,
                "uid": "C1",
                "id.orig_h": "10.0.0.5",
                "id.resp_h": "8.8.8.8",
                "id.orig_p": 53321,
                "id.resp_p": 53,
                "proto": "udp",
                "query": "bad.example",
                "qtype_name": "A",
                "answers": ["1.2.3.4"],
            }) + "\n"
        )

        records = _parse_zeek_results(raw_dir)

        assert len(records) == 1
        assert records[0]["type"] == "event"
        assert records[0]["data"]["event_type"] == "dns"
        assert records[0]["data"]["details"]["query"] == "bad.example"
        assert records[0]["data"]["details"]["qtype"] == "A"
        assert records[0]["data"]["timestamp"].endswith("Z")

    def test_parse_zeek_results_preserves_flow_timing(self, tmp_path):
        raw_dir = tmp_path / "raw"
        raw_dir.mkdir()
        (raw_dir / "conn.log").write_text(
            json.dumps({
                "ts": 1710000000.0,
                "uid": "C-flow-1",
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 40000,
                "id.resp_h": "1.2.3.4",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "duration": 15.0,
                "orig_bytes": 120,
                "resp_bytes": 240,
                "orig_pkts": 2,
                "resp_pkts": 3,
                "conn_state": "SF",
            }) + "\n"
        )

        records = _parse_zeek_results(raw_dir)

        assert len(records) == 1
        assert records[0]["type"] == "flow"
        assert records[0]["data"]["start_time"].endswith("+00:00")
        assert records[0]["data"]["end_time"].endswith("+00:00")

    def test_run_sensor_handler_success(self, tmp_path):
        """Sensors with handlers run in-process."""
        sensor_def = SENSORS["ti_matcher"]
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        # Create required inputs so the handler doesn't fail
        zeek_dir = job_dir / "sensors" / "zeek"
        zeek_dir.mkdir(parents=True, exist_ok=True)
        (zeek_dir / "sensor.results.jsonl").write_text("")
        suri_dir = job_dir / "sensors" / "suricata"
        suri_dir.mkdir(parents=True, exist_ok=True)
        (suri_dir / "sensor.results.jsonl").write_text("")

        result = run_sensor(sensor_def, job_dir, "job-1", "standard", run_output_dir=job_dir)
        assert result.status == "completed"
        assert result.exit_code == 0
        assert result.sensor == "ti_matcher"
        # sensor.meta.json should be written
        meta_path = job_dir / "sensors" / "ti_matcher" / "sensor.meta.json"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["status"] == "completed"

    def test_handle_ti_matcher_matches_domain_hash_and_tls_iocs(self, tmp_path, monkeypatch):
        job_dir = _legacy_job_directory(tmp_path, _uuid())

        zeek_dir = job_dir / "sensors" / "zeek"
        zeek_dir.mkdir(parents=True, exist_ok=True)
        (zeek_dir / "sensor.results.jsonl").write_text(
            "\n".join([
                json.dumps({
                    "type": "flow",
                    "data": {"src_ip": "10.0.0.5", "dst_ip": "5.6.7.8"},
                }),
                json.dumps({
                    "type": "event",
                    "data": {
                        "event_type": "dns",
                        "details": {"query": "bad.example."},
                    },
                }),
            ]) + "\n"
        )

        suri_dir = job_dir / "sensors" / "suricata"
        suri_dir.mkdir(parents=True, exist_ok=True)
        (suri_dir / "sensor.results.jsonl").write_text("")

        tls_dir = job_dir / "sensors" / "tls_enrich"
        tls_dir.mkdir(parents=True, exist_ok=True)
        (tls_dir / "sensor.results.jsonl").write_text(
            json.dumps({
                "type": "tls_session",
                "data": {
                    "server_name": "evil.test",
                    "ja3": "ja3-fingerprint",
                    "ja3s": "ja3s-fingerprint",
                },
            }) + "\n"
        )

        file_dir = job_dir / "sensors" / "file_triage"
        file_dir.mkdir(parents=True, exist_ok=True)
        (file_dir / "sensor.results.jsonl").write_text(
            json.dumps({
                "type": "extracted_file",
                "data": {"sha256": "DEADBEEF"},
            }) + "\n"
        )

        ti_root = tmp_path / "ti" / "bundles" / "demo"
        ti_root.mkdir(parents=True)
        (ti_root / "domains.txt").write_text("bad.example\nevil.test\n")
        (ti_root / "hashes_sha256.txt").write_text("deadbeef\n")
        (ti_root / "ja3.txt").write_text("ja3-fingerprint\n")
        (ti_root / "ja3s.txt").write_text("ja3s-fingerprint\n")
        monkeypatch.setenv("AIPAM_TI_BUNDLE_DIR", str(tmp_path / "ti" / "bundles"))

        output_dir = create_sensor_output_dir(job_dir, "ti_matcher")
        handle_ti_matcher(job_dir, output_dir, "job-ti", "standard", run_output_dir=job_dir)

        results = [json.loads(line) for line in (output_dir / "sensor.results.jsonl").read_text().splitlines()]
        by_type = {item["data"]["ioc_type"]: item["data"] for item in results}

        assert by_type["domain"]["value"] == "bad.example"
        assert "ip" not in by_type["domain"]
        assert by_type["hash"]["value"] == "deadbeef"
        assert by_type["sni"]["value"] == "evil.test"
        assert by_type["ja3"]["value"] == "ja3-fingerprint"
        assert by_type["ja3s"]["value"] == "ja3s-fingerprint"

    def test_handle_beaconing_emits_dns_findings_with_pcap_label(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())

        zeek_dir = job_dir / "sensors" / "zeek"
        zeek_dir.mkdir(parents=True, exist_ok=True)
        long_query = "a" * 60 + ".suspicious.example"
        (zeek_dir / "sensor.results.jsonl").write_text(
            "\n".join([
                json.dumps({
                    "type": "flow",
                    "pcap_label": "capture-a",
                    "data": {
                        "id": "flow-1",
                        "src_ip": "10.0.0.5",
                        "src_port": 50000,
                        "dst_ip": "8.8.8.8",
                        "dst_port": 53,
                        "transport_proto": "UDP",
                        "app_proto": "DNS",
                        "start_time": "2024-01-01T00:00:00Z",
                        "end_time": "2024-01-01T00:00:01Z",
                        "duration_sec": 1.0,
                        "bytes_from_src": 80,
                        "bytes_from_dst": 120,
                        "packets_from_src": 1,
                        "packets_from_dst": 1,
                        "state": "SF",
                    },
                }),
                json.dumps({
                    "type": "event",
                    "pcap_label": "capture-a",
                    "data": {
                        "event_type": "dns",
                        "timestamp": "2024-01-01T00:00:00Z",
                        "src_ip": "10.0.0.5",
                        "dst_ip": "8.8.8.8",
                        "details": {
                            "query": long_query,
                            "qtype": "TXT",
                            "answers": [],
                        },
                    },
                }),
            ]) + "\n"
        )

        suri_dir = job_dir / "sensors" / "suricata"
        suri_dir.mkdir(parents=True, exist_ok=True)
        (suri_dir / "sensor.results.jsonl").write_text("")

        output_dir = create_sensor_output_dir(job_dir, "beaconing")
        handle_beaconing(job_dir, output_dir, "job-beacon", "standard", run_output_dir=job_dir)

        results = [json.loads(line) for line in (output_dir / "sensor.results.jsonl").read_text().splitlines()]

        assert len(results) == 1
        assert results[0]["type"] == "anomaly"
        assert results[0]["pcap_label"] == "capture-a"
        assert results[0]["data"]["category"] == "dns"
        assert "long DNS queries" in results[0]["data"]["description"]

    def test_handle_capa_skips_cleanly_when_binary_missing(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        extracted = job_dir / "extracted_files" / "files" / "sample.exe"
        extracted.write_bytes(b"MZ" + b"\x00" * 32)

        triage_dir = job_dir / "sensors" / "file_triage"
        triage_dir.mkdir(parents=True, exist_ok=True)
        (triage_dir / "sensor.results.jsonl").write_text(
            json.dumps({
                "type": "extracted_file",
                "data": {
                    "file_id": "sample.exe",
                    "filename": "sample.exe",
                    "sha256": "abc123",
                    "mime": "application/x-dosexec",
                    "file_type": "Windows PE executable",
                    "pcap_label": "capture-a",
                },
            }) + "\n"
        )

        output_dir = create_sensor_output_dir(job_dir, "capa")
        with patch("backend.app.pipeline.sensor_handlers.shutil.which", return_value=None):
            handle_capa(job_dir, output_dir, "job-capa", "standard", run_output_dir=job_dir)

        assert (output_dir / "sensor.results.jsonl").read_text() == ""

    def test_handle_capa_emits_findings_for_executable_triage_records(self, tmp_path, monkeypatch):
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        extracted = job_dir / "extracted_files" / "files" / "sample.exe"
        extracted.write_bytes(b"MZ" + b"\x00" * 64)

        rules_dir = tmp_path / "capa-rules"
        signatures_dir = tmp_path / "capa-sigs"
        rules_dir.mkdir()
        signatures_dir.mkdir()
        monkeypatch.setenv("AIPAM_CAPA_RULES_DIR", str(rules_dir))
        monkeypatch.setenv("AIPAM_CAPA_SIGNATURES_DIR", str(signatures_dir))

        triage_dir = job_dir / "sensors" / "file_triage"
        triage_dir.mkdir(parents=True, exist_ok=True)
        (triage_dir / "sensor.results.jsonl").write_text(
            json.dumps({
                "type": "extracted_file",
                "data": {
                    "file_id": "sample.exe",
                    "filename": "sample.exe",
                    "sha256": "deadbeef",
                    "mime": "application/x-dosexec",
                    "file_type": "Windows PE executable",
                    "source": "HTTP",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "8.8.8.8",
                    "host_ip": "10.0.0.5",
                    "pcap_label": "capture-a",
                    "ts": "2024-01-01T00:00:00Z",
                },
            }) + "\n"
        )

        capa_json = {
            "rules": {
                "create TCP socket": {
                    "meta": {
                        "name": "create TCP socket",
                        "namespace": "communication/socket/tcp",
                        "att&ck": [
                            {
                                "tactic": "Execution",
                                "technique": "Command and Scripting Interpreter",
                                "id": "T1059",
                            }
                        ],
                    }
                },
                "encode data using XOR": {
                    "meta": {
                        "name": "encode data using XOR",
                        "namespace": "data-manipulation/encoding/xor",
                    }
                },
            }
        }

        output_dir = create_sensor_output_dir(job_dir, "capa")
        with patch("backend.app.pipeline.sensor_handlers.shutil.which", return_value="/usr/bin/capa"), \
             patch("backend.app.pipeline.sensor_handlers.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps(capa_json),
                stderr="",
            )
            handle_capa(job_dir, output_dir, "job-capa", "standard", run_output_dir=job_dir)

        results = [json.loads(line) for line in (output_dir / "sensor.results.jsonl").read_text().splitlines()]

        assert len(results) == 1
        finding = results[0]
        assert finding["event_type"] == "finding"
        assert finding["sensor"] == "capa"
        assert finding["category"] == "malware_capability"
        assert finding["pcap_label"] == "capture-a"
        assert finding["host_ip"] == "10.0.0.5"
        assert "create TCP socket" in finding["summary"]
        assert finding["evidence"]["file_id"] == "sample.exe"
        assert finding["evidence"]["capability_count"] == 2
        assert "create TCP socket" in finding["evidence"]["capabilities"]
        assert "Execution / Command and Scripting Interpreter (T1059)" in finding["evidence"]["attack"]
        mock_run.assert_called_once()
        assert mock_run.call_args.args[0] == [
            "/usr/bin/capa",
            "-r",
            str(rules_dir),
            "-s",
            str(signatures_dir),
            "-j",
            str(extracted),
        ]

    def test_run_sensor_handler_failure(self, tmp_path):
        """Handler that raises should produce failed status."""
        def bad_handler(**kwargs):
            raise RuntimeError("analysis crashed")
        sensor_def = SensorDef(name="bad", type="sensor", handler=bad_handler)
        job_dir = _legacy_job_directory(tmp_path, _uuid())

        result = run_sensor(sensor_def, job_dir, "job-2", "standard", run_output_dir=job_dir)
        assert result.status == "failed"
        assert result.exit_code == 1
        assert result.error == "Analysis stage failed."

    def test_run_sensor_docker_success(self, tmp_path):
        """Docker-based sensors (no handler) use Docker client."""
        sensor_def = _make_docker_sensor_def()
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        docker = _make_mock_docker(exit_code=0, logs=b"all good")

        result = run_sensor(sensor_def, job_dir, "job-3", "standard", docker, run_output_dir=job_dir)
        assert result.status == "completed"
        assert result.exit_code == 0

    def test_run_sensor_docker_timeout(self, tmp_path):
        sensor_def = _make_docker_sensor_def()
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        docker = _make_mock_docker()
        mock_container = docker.containers.run.return_value
        mock_container.wait.side_effect = Exception("Read timed out")

        result = run_sensor(sensor_def, job_dir, "job-4", "standard", docker, run_output_dir=job_dir)
        assert result.status == "timeout"
        assert result.exit_code is None
        mock_container.kill.assert_called_once()

    def test_run_sensor_skipped_no_image_no_handler(self, tmp_path):
        """SensorDef with no image and no handler should be skipped."""
        sensor_def = SensorDef(name="empty", type="stage")
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        docker = _make_mock_docker()

        result = run_sensor(sensor_def, job_dir, "job-5", "standard", docker, run_output_dir=job_dir)
        assert result.status == "skipped"

    def test_run_sensor_image_not_found(self, tmp_path):
        sensor_def = _make_docker_sensor_def()
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        docker = _make_mock_docker()
        docker.images.get.side_effect = Exception("Image not found")

        result = run_sensor(sensor_def, job_dir, "job-6", "standard", docker, run_output_dir=job_dir)
        assert result.status == "failed"
        assert "Image not found" in result.error

    def test_run_sensor_container_log_saved(self, tmp_path):
        sensor_def = _make_docker_sensor_def(name="test_logger")
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        docker = _make_mock_docker(exit_code=0, logs=b"matched 3 IOCs")

        run_sensor(sensor_def, job_dir, "job-7", "standard", docker, run_output_dir=job_dir)
        log_path = job_dir / "sensors" / "test_logger" / "container.log"
        assert log_path.exists()
        assert "matched 3 IOCs" in log_path.read_text()

    def test_run_sensor_docker_kwargs(self, tmp_path):
        """Verify Docker security hardening kwargs are passed."""
        sensor_def = _make_docker_sensor_def()
        job_dir = _legacy_job_directory(tmp_path, _uuid())
        docker = _make_mock_docker()

        run_sensor(sensor_def, job_dir, "job-8", "standard", docker, run_output_dir=job_dir)
        call_kwargs = docker.containers.run.call_args[1]
        assert call_kwargs["network_mode"] == "none"
        assert call_kwargs["read_only"] is True
        assert call_kwargs["pids_limit"] == 256
        assert call_kwargs["detach"] is True
        assert call_kwargs["mem_limit"] == "2g"


# ========================================================================
# Recovery Tests
# ========================================================================

class TestRecovery:
    @pytest.mark.parametrize("stale", [False, True])
    @patch("backend.app.worker._emit_complete")
    def test_recover_running_jobs(self, mock_emit, db_session, stale):
        """Recovery fails only expired leases, preserving healthy running jobs."""
        started = datetime.now(timezone.utc) - timedelta(minutes=10 if stale else 0)
        job = Job(
            job_id=_uuid(),
            job_name="Running Job",
            status="running",
            execution_profile="standard",
            priority="normal",
            created_at=_now_iso(),
            started_at=started.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
        db_session.add(job)
        db_session.commit()

        recovered = recover_interrupted_jobs(db_session)
        assert recovered == int(stale)

        db_session.refresh(job)
        assert job.status == ("failed" if stale else "running")
        assert job.error_summary == ("Worker heartbeat expired" if stale else None)
        assert (job.completed_at is not None) == stale
        assert mock_emit.call_count == int(stale)

    def test_queued_jobs_left_alone(self, db_session):
        """Queued jobs should NOT be marked failed."""
        job = Job(
            job_id=_uuid(),
            job_name="Queued Job",
            status="queued",
            execution_profile="triage",
            priority="normal",
            created_at=_now_iso(),
        )
        db_session.add(job)
        db_session.commit()

        recovered = recover_interrupted_jobs(db_session)
        assert recovered == 0

        db_session.refresh(job)
        assert job.status == "queued"

    def test_no_interrupted_jobs(self, db_session):
        """No running jobs — recovery should return 0."""
        assert recover_interrupted_jobs(db_session) == 0


# ========================================================================
# Pipeline Orchestrator Tests (integration with mocked Docker)
# ========================================================================

class TestOrchestrator:
    def _setup_job(self, db_session, tmp_path, profile="standard"):
        """Helper: create a job + upload directory with a PCAP."""

        job_id = _uuid()
        upload_id = _uuid()

        # Create upload dir with PCAP
        upload_dir = tmp_path / "uploads" / upload_id
        upload_dir.mkdir(parents=True)
        pcap = upload_dir / "test.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 500)

        # Insert job in DB
        job = Job(
            job_id=job_id,
            job_name="Test Pipeline Job",
            artifact_layout_version=1,
            status="queued",
            execution_profile=profile,
            priority="normal",
            upload_id=upload_id,
            pcap_filename="test.pcap",
            pcap_size_bytes=504,
            created_at=_now_iso(),
        )
        db_session.add(job)
        db_session.commit()

        return job_id, upload_id

    @pytest.mark.parametrize("separate_output", [False, True])
    @patch("backend.app.pipeline.orchestrator.check_disk_space")
    def test_pipeline_happy_path(self, mock_preflight, db_session, tmp_path, separate_output):
        from backend.app.models.partial_result import PartialResult
        from backend.app.pipeline.orchestrator import run_pipeline

        mock_preflight.return_value = PreflightResult(
            ok=True, required_bytes=2000, available_bytes=999_999_999
        )

        job_id, upload_id = self._setup_job(db_session, tmp_path)
        docker = _make_mock_docker(exit_code=0, logs=b"ok")
        input_root = tmp_path / "jobs" / job_id
        run_output_dir = input_root / ".runs" / _uuid() if separate_output else input_root

        # Mock the process boundary: parent-process handler patches cannot
        # affect the child interpreter used by the runtime.
        def noop_handler(sensor_def, **kwargs):
            out = kwargs.get("sensor_output_dir")
            if out:
                (out / "sensor.results.jsonl").write_text("")

        with patch("backend.app.pipeline.sensor_process.run_handler_process", noop_handler), \
             patch("backend.app.pipeline.orchestrator.publish_job_event"):
            status = run_pipeline(
                job_id,
                db_session,
                docker_client=docker,
                job_root=tmp_path / "jobs",
                upload_root=tmp_path / "uploads",
                input_root=input_root,
                run_output_dir=run_output_dir,
            )

        assert status.status in ("completed", "completed_with_errors")
        job = db_session.get(Job, job_id)
        assert job.status == "queued"
        assert job.started_at is None
        # Final results replace the progressive snapshot at pipeline completion.
        assert db_session.get(PartialResult, job_id) is None
        assert (run_output_dir / "metrics" / "job_metrics.json").is_file()
        assert (input_root / "input" / "pcap.pcap").is_file()
        if separate_output:
            assert not (input_root / "sensors").exists()
            assert not (input_root / "metrics").exists()

    @patch("backend.app.pipeline.orchestrator.check_disk_space")
    def test_pipeline_preflight_fails(self, mock_preflight, db_session, tmp_path):
        from backend.app.pipeline.orchestrator import run_pipeline

        mock_preflight.return_value = PreflightResult(
            ok=False, required_bytes=99999, available_bytes=100,
            message="Insufficient disk"
        )

        job_id, _ = self._setup_job(db_session, tmp_path)
        docker = _make_mock_docker()

        status = run_pipeline(
            job_id,
            db_session,
            docker_client=docker,
            job_root=tmp_path / "jobs",
            upload_root=tmp_path / "uploads",
        )

        assert status.status == "failed"
        job = db_session.get(Job, job_id)
        assert job.status == "queued"
        assert "Insufficient disk" in status.required_failures[0].error

    def test_pipeline_missing_job(self, db_session, tmp_path):
        from backend.app.pipeline.orchestrator import run_pipeline

        with pytest.raises(ValueError, match="not found"):
            run_pipeline(
                "nonexistent-id",
                db_session,
                docker_client=_make_mock_docker(),
                job_root=tmp_path / "jobs",
                upload_root=tmp_path / "uploads",
            )


def _legacy_job_directory(job_root, job_id):
    return create_job_directory(job_root, job_id, run_output_dir=job_root / job_id)
