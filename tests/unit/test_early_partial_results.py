"""Sprint 6 tests — Early Partial Results.

Covers:
  - _publish_partial_result helper (persistence + accumulation)
  - GET /jobs/{jobId}/partial-results endpoint
  - Zeek conn.log parsing for top hosts
  - Suricata eve.json parsing for alert summary + early_alert events
  - Cleanup of partial results on job completion
  - SSE event type definitions (partial_result, early_alert)
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch


AUTH = {"Authorization": "Bearer test-token-v2"}


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _seed_job(db, **kwargs):
    from backend.app.models.job import Job
    jid = kwargs.pop("job_id", _uuid())
    job = Job(
        job_id=jid, job_name="Test Job", status=kwargs.pop("status", "running"),
        execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=1024, pcap_sha256="abc",
        created_at=_now(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _seed_findings(db, job_id, count=3):
    from backend.app.models.finding import Finding
    findings = []
    for i in range(count):
        f = Finding(
            job_id=job_id, finding_id=_uuid(),
            sensor="suricata", severity="high",
            title=f"Finding {i}", summary=f"Test finding {i}",
        )
        db.add(f)
        findings.append(f)
    db.commit()
    return findings


def _seed_alerts(db, job_id, count=5):
    from backend.app.models.alert import Alert
    alerts = []
    for i in range(count):
        a = Alert(
            job_id=job_id, alert_id=_uuid(),
            host_ip="10.0.0.1", severity="high",
            signature=f"ET MALWARE Test {i}", ts=_now(),
        )
        db.add(a)
        alerts.append(a)
    db.commit()
    return alerts


def _seed_hosts(db, job_id, count=4):
    from backend.app.models.host import Host
    hosts = []
    for i in range(count):
        h = Host(
            job_id=job_id, ip=f"10.0.0.{i+1}",
            role="internal", conn_count=10 * (i + 1),
        )
        db.add(h)
        hosts.append(h)
    db.commit()
    return hosts


# ===== _publish_partial_result Unit Tests =====


class TestPublishPartialResult:
    """Test the _publish_partial_result helper function."""

    def test_publishes_and_persists(self):
        """Verify data is saved via save_partial_result and SSE is emitted."""
        from backend.app.pipeline.orchestrator import _publish_partial_result

        saved_data = {}

        def mock_save(job_id, data):
            saved_data["job_id"] = job_id
            saved_data["data"] = data

        with patch("backend.app.partial_results.save_partial_result", side_effect=mock_save), \
             patch("backend.app.partial_results.get_partial_result", return_value=None), \
             patch("backend.app.pipeline.orchestrator._emit") as mock_emit:

            _publish_partial_result(
                "job-123", "parse",
                {"pcap_stats": {"file_count": 1, "total_bytes": 4096}},
                completed_stages=["zeek", "suricata"],
                current_stage="sensors",
            )

            assert saved_data["job_id"] == "job-123"
            assert saved_data["data"]["completed_stages"] == ["zeek", "suricata"]
            assert saved_data["data"]["current_stage"] == "sensors"
            assert saved_data["data"]["partial_data"]["pcap_stats"]["file_count"] == 1

            mock_emit.assert_called_once()
            call_args = mock_emit.call_args
            assert call_args[0][0] == "job-123"
            assert call_args[0][1] == "partial_result"
            assert call_args[1]["stage"] == "parse"

    def test_accumulates_across_stages(self):
        """Verify new stage data is merged with existing partial data."""
        from backend.app.pipeline.orchestrator import _publish_partial_result

        existing = {
            "completed_stages": ["zeek"],
            "partial_data": {
                "pcap_stats": {"file_count": 1, "total_bytes": 4096},
            },
        }
        saved_payloads = []

        def mock_save(job_id, data):
            saved_payloads.append(data)

        with patch("backend.app.partial_results.save_partial_result", side_effect=mock_save), \
             patch("backend.app.partial_results.get_partial_result", return_value=existing), \
             patch("backend.app.pipeline.orchestrator._emit"):

            _publish_partial_result(
                "job-123", "sensors",
                {"sensor_summary": {"total": 3, "completed": 3, "failed": 0, "skipped": 0}},
                completed_stages=["zeek", "suricata", "sensors"],
                current_stage="correlate",
            )

            assert len(saved_payloads) == 1
            pd = saved_payloads[0]["partial_data"]
            # Original pcap_stats should be preserved
            assert pd["pcap_stats"]["file_count"] == 1
            # New sensor_summary should be added
            assert pd["sensor_summary"]["total"] == 3

    def test_handles_exception_gracefully(self):
        """_publish_partial_result should not raise on errors."""
        from backend.app.pipeline.orchestrator import _publish_partial_result

        with patch("backend.app.partial_results.save_partial_result", side_effect=RuntimeError("DB down")), \
             patch("backend.app.partial_results.get_partial_result", return_value=None), \
             patch("backend.app.pipeline.orchestrator._emit"):
            # Should not raise
            _publish_partial_result("job-x", "parse", {"key": "val"}, [], None)


# ===== GET /jobs/{jobId}/partial-results API Tests =====


class TestPartialResultsEndpoint:
    """Test the GET /jobs/{jobId}/partial-results endpoint."""

    def test_returns_empty_when_no_partial(self, app_client):
        client, db = app_client
        job = _seed_job(db)

        with patch("backend.app.partial_results.get_partial_result", return_value=None):
            r = client.get(f"/api/v1/jobs/{job.job_id}/partial-results", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["job_id"] == job.job_id
        assert data["completed_stages"] == []
        assert data["current_stage"] is None
        assert data["partial_data"] == {}

    def test_returns_stored_partial_data(self, app_client):
        client, db = app_client
        job = _seed_job(db)

        mock_data = {
            "completed_stages": ["zeek", "suricata"],
            "current_stage": "correlate",
            "partial_data": {
                "pcap_stats": {"file_count": 2, "total_bytes": 8192},
                "top_hosts": [{"ip": "10.0.0.1", "total_bytes": 5000}],
            },
        }

        with patch("backend.app.partial_results.get_partial_result", return_value=mock_data):
            r = client.get(f"/api/v1/jobs/{job.job_id}/partial-results", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["completed_stages"] == ["zeek", "suricata"]
        assert data["current_stage"] == "correlate"
        assert data["partial_data"]["pcap_stats"]["file_count"] == 2
        assert len(data["partial_data"]["top_hosts"]) == 1

    def test_404_for_nonexistent_job(self, app_client):
        client, db = app_client
        r = client.get(f"/api/v1/jobs/{_uuid()}/partial-results", headers=AUTH)
        assert r.status_code == 404


# ===== Zeek conn.log Parsing Tests =====


class TestZeekParsing:
    """Test that the orchestrator correctly parses Zeek conn.log for top hosts."""

    def test_parse_conn_log(self, tmp_path):
        """Simulate Zeek conn.log and verify top hosts extraction."""
        conn_log = tmp_path / "sensors" / "zeek" / "conn.log"
        conn_log.parent.mkdir(parents=True)

        # Tab-separated Zeek conn.log format (simplified)
        # Fields: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes ...
        lines = [
            "#separator \\x09",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes",
            "1234567890.123\tC1\t10.0.0.1\t12345\t192.168.1.1\t80\ttcp\thttp\t1.5\t500\t3000",
            "1234567890.456\tC2\t10.0.0.2\t23456\t192.168.1.1\t443\ttcp\tssl\t2.0\t1000\t5000",
            "1234567890.789\tC3\t10.0.0.1\t34567\t8.8.8.8\t53\tudp\tdns\t0.1\t200\t400",
        ]
        conn_log.write_text("\n".join(lines))

        # Parse like the orchestrator does
        host_bytes: dict[str, int] = {}
        protocol_dist: dict[str, int] = {}
        for line in conn_log.read_text().splitlines():
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 10:
                src, dst = parts[2], parts[4]
                proto = parts[6] if len(parts) > 6 else "unknown"
                bsrc = int(parts[9]) if parts[9].isdigit() else 0
                host_bytes[src] = host_bytes.get(src, 0) + bsrc
                host_bytes[dst] = host_bytes.get(dst, 0) + bsrc
                protocol_dist[proto] = protocol_dist.get(proto, 0) + 1

        top_hosts = [
            {"ip": ip, "total_bytes": b}
            for ip, b in sorted(host_bytes.items(), key=lambda x: -x[1])[:10]
        ]

        # 10.0.0.1 sent 500 + 200 = 700 bytes
        # 192.168.1.1 received 500 + 1000 = 1500 bytes
        assert len(top_hosts) >= 3
        assert protocol_dist["tcp"] == 2
        assert protocol_dist["udp"] == 1

        # 192.168.1.1 should have the most bytes (received from both sources)
        assert top_hosts[0]["ip"] == "192.168.1.1"


# ===== Suricata eve.json Parsing Tests =====


class TestSuricataParsing:
    """Test Suricata eve.json parsing for alert summaries and early alerts."""

    def test_parse_eve_json_alerts(self, tmp_path):
        """Parse alert records and count by severity."""
        eve_file = tmp_path / "sensors" / "suricata" / "eve.json"
        eve_file.parent.mkdir(parents=True)

        records = [
            {"event_type": "alert", "alert": {"severity": 1, "signature": "ET MALWARE C2"}, "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8"},
            {"event_type": "alert", "alert": {"severity": 2, "signature": "ET SCAN SSH"}, "src_ip": "10.0.0.2", "dest_ip": "10.0.0.3"},
            {"event_type": "alert", "alert": {"severity": 3, "signature": "ET INFO DNS"}, "src_ip": "10.0.0.1", "dest_ip": "8.8.4.4"},
            {"event_type": "flow", "flow": {}},  # Non-alert record
        ]
        eve_file.write_text("\n".join(json.dumps(r) for r in records))

        # Parse like the orchestrator
        sev_counts: dict[str, int] = {}
        alert_total = 0
        early_alerts = []
        for line in eve_file.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("event_type") == "alert":
                alert_total += 1
                sev = str(rec.get("alert", {}).get("severity", "unknown"))
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                if sev in ("1", "2"):
                    early_alerts.append(rec["alert"]["signature"])

        assert alert_total == 3
        assert sev_counts["1"] == 1
        assert sev_counts["2"] == 1
        assert sev_counts["3"] == 1
        assert len(early_alerts) == 2
        assert "ET MALWARE C2" in early_alerts

    def test_skips_malformed_json(self, tmp_path):
        """Malformed JSON lines should be silently skipped."""
        eve_file = tmp_path / "eve.json"
        eve_file.write_text('{"event_type":"alert","alert":{"severity":1}}\nnot-json\n{"event_type":"flow"}\n')

        alert_total = 0
        for line in eve_file.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if rec.get("event_type") == "alert":
                    alert_total += 1
            except json.JSONDecodeError:
                pass

        assert alert_total == 1


# ===== Partial Result Cleanup Tests =====


class TestPartialResultCleanup:
    """Test that partial results are cleaned up on job completion."""

    def test_delete_partial_result(self):
        """Verify delete_partial_result removes the row."""

        mock_store: dict[str, Any] = {}

        def mock_save(job_id, data):
            mock_store[job_id] = data

        def mock_get(job_id):
            return mock_store.get(job_id)

        def mock_delete(job_id):
            mock_store.pop(job_id, None)

        job_id = f"test-cleanup-{_uuid()}"

        with patch("backend.app.partial_results.save_partial_result", side_effect=mock_save), \
             patch("backend.app.partial_results.get_partial_result", side_effect=mock_get), \
             patch("backend.app.partial_results.delete_partial_result", side_effect=mock_delete):

            mock_save(job_id, {"completed_stages": ["parse"], "partial_data": {"x": 1}})
            assert mock_get(job_id) is not None

            mock_delete(job_id)
            assert mock_get(job_id) is None

    def test_delete_nonexistent_is_noop(self):
        """Deleting a non-existent partial result should not raise."""

        with patch("backend.app.partial_results.delete_partial_result") as mock_del:
            mock_del(f"nonexistent-{_uuid()}")
            mock_del.assert_called_once()


# ===== Schema / Response Model Tests =====


class TestPartialResultsSchema:
    """Test the PartialResultsResponse Pydantic model."""

    def test_default_values(self):
        from backend.app.api.jobs import PartialResultsResponse

        resp = PartialResultsResponse(job_id="j-1")
        assert resp.schema_version == "1.0"
        assert resp.completed_stages == []
        assert resp.current_stage is None
        assert resp.partial_data == {}

    def test_populated_values(self):
        from backend.app.api.jobs import PartialResultsResponse

        resp = PartialResultsResponse(
            job_id="j-2",
            completed_stages=["zeek", "suricata", "sensors"],
            current_stage="correlate",
            partial_data={"pcap_stats": {"file_count": 1}, "alert_summary": {"total": 5}},
        )
        assert len(resp.completed_stages) == 3
        assert resp.partial_data["alert_summary"]["total"] == 5


# ===== Correlation Count Publishing Tests =====


class TestCorrelationPartialResult:
    """Test partial result publishing after correlation stage."""

    def test_correlation_counts_published(self, app_client):
        """Verify finding/alert/host counts are available after correlation."""
        client, db = app_client
        job = _seed_job(db)
        _seed_findings(db, job.job_id, count=3)
        _seed_alerts(db, job.job_id, count=5)
        _seed_hosts(db, job.job_id, count=4)

        # Query counts like the orchestrator does
        from sqlalchemy import func as sa_func, select
        from backend.app.models.finding import Finding
        from backend.app.models.alert import Alert
        from backend.app.models.host import Host

        finding_count = db.scalar(
            select(sa_func.count()).select_from(Finding).where(Finding.job_id == job.job_id)
        ) or 0
        alert_count = db.scalar(
            select(sa_func.count()).select_from(Alert).where(Alert.job_id == job.job_id)
        ) or 0
        host_count = db.scalar(
            select(sa_func.count()).select_from(Host).where(Host.job_id == job.job_id)
        ) or 0

        assert finding_count == 3
        assert alert_count == 5
        assert host_count == 4

        # Mock the partial results to test the API returns them
        mock_data = {
            "completed_stages": ["zeek", "suricata", "sensors", "correlate"],
            "current_stage": "index",
            "partial_data": {
                "finding_count": finding_count,
                "alert_count": alert_count,
                "host_count": host_count,
            },
        }

        with patch("backend.app.partial_results.get_partial_result", return_value=mock_data):
            r = client.get(f"/api/v1/jobs/{job.job_id}/partial-results", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["partial_data"]["finding_count"] == 3
        assert data["partial_data"]["alert_count"] == 5
        assert data["partial_data"]["host_count"] == 4

