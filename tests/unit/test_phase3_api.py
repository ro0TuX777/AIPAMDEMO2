"""Phase 3 tests — Correlation & API Expansion.

Covers:
  - Job management endpoints (cancel, delete, rerun, batch)
  - Job data endpoints (summary, sensors, timeline, iocs)
  - Host endpoints (list, detail, sub-resources)
  - Findings endpoints (list, explain)
  - Artifacts endpoints (list, evidence-package)
  - SSE events stream
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

AUTH = {"Authorization": "Bearer test-token-v2"}
_EXPLAIN_GOLDEN_FIXTURES_PATH = Path(__file__).parent.parent / "fixtures" / "golden" / "expected_explanations.json"


def _load_explain_golden_cases():
    return json.loads(_EXPLAIN_GOLDEN_FIXTURES_PATH.read_text())["cases"]


def _section_snapshot(section: dict) -> dict:
    return {
        "id": section["id"],
        "title": section["title"],
        "body": section.get("body"),
        "bullets": list(section.get("bullets", [])),
        "citations": list(section.get("citations", [])),
    }


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Helpers to seed data via the DB session from app_client
# ---------------------------------------------------------------------------

def _seed_job(db, status="completed", **kwargs):
    from backend.app.models.job import Job
    jid = kwargs.pop("job_id", _uuid())
    job = Job(
        job_id=jid, job_name=kwargs.get("job_name", "Test Job"),
        status=status, execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=1024, pcap_sha256="abc",
        created_at=kwargs.get("created_at", _now()), **{k: v for k, v in kwargs.items() if k not in ("job_name", "created_at")},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _seed_host(db, job_id, ip="10.0.0.1", **kwargs):
    from backend.app.models.host import Host
    host = Host(job_id=job_id, ip=ip, role="internal", conn_count=10,
                alert_count=2, finding_count=1, first_seen=_now(), last_seen=_now(), **kwargs)
    db.add(host)
    db.commit()
    return host


def _seed_alert(db, job_id, host_ip="10.0.0.1", severity="high", **kwargs):
    from backend.app.models.alert import Alert
    a = Alert(job_id=job_id, alert_id=_uuid(), host_ip=host_ip, severity=severity,
              signature="ET MALWARE Test", ts=_now(), **kwargs)
    db.add(a)
    db.commit()
    return a


def _seed_finding(db, job_id, severity="high", **kwargs):
    from backend.app.models.finding import Finding
    payload = {
        "job_id": job_id,
        "finding_id": _uuid(),
        "sensor": "suricata",
        "severity": severity,
        "title": "Suspicious traffic",
        "summary": "Test finding",
    }
    payload.update(kwargs)
    f = Finding(**payload)
    db.add(f)
    db.commit()
    return f


def _seed_ioc(db, job_id, **kwargs):
    from backend.app.models.ioc import Ioc
    payload = {
        "job_id": job_id,
        "ioc_id": _uuid(),
        "ioc_type": "ip",
        "value": "192.168.1.100",
        "confidence": 0.9,
        "sources_json": '["suricata"]',
    }
    payload.update(kwargs)
    i = Ioc(**payload)
    db.add(i)
    db.commit()
    return i


def _seed_connection(db, job_id, host_ip="10.0.0.1"):
    from backend.app.models.connection import Connection
    c = Connection(job_id=job_id, connection_id=_uuid(), host_ip=host_ip,
                   src_ip=host_ip, dest_ip="8.8.8.8", src_port=12345, dest_port=443,
                   proto="tcp", ts=_now())
    db.add(c)
    db.commit()
    return c


def _seed_timeline(db, job_id, **kwargs):
    from backend.app.models.timeline import TimelineEvent
    evt_type = kwargs.pop("type", "alert")
    t = TimelineEvent(job_id=job_id, ts=_now(), type=evt_type,
                      title="Alert fired", details_json='{"description": "test"}', **kwargs)
    db.add(t)
    db.commit()
    return t


def _seed_sensor(db, job_id, sensor="suricata", status="completed"):
    from backend.app.models.sensor import JobSensor
    s = JobSensor(job_id=job_id, sensor=sensor, status=status,
                  started_at=_now(), completed_at=_now())
    db.add(s)
    db.commit()
    return s


# ===== Job Management Tests =====

class TestJobCancel:
    def test_cancel_queued_job(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="queued")
        r = client.post(f"/api/v1/jobs/{job.job_id}/cancel", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["job"]["status"] == "canceled"

    def test_cancel_completed_job_409(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="completed")
        r = client.post(f"/api/v1/jobs/{job.job_id}/cancel", headers=AUTH)
        assert r.status_code == 409


class TestJobDelete:
    def test_delete_completed_job(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="completed")
        r = client.delete(f"/api/v1/jobs/{job.job_id}", headers=AUTH)
        assert r.status_code == 204

    def test_delete_running_job_409(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="running")
        r = client.delete(f"/api/v1/jobs/{job.job_id}", headers=AUTH)
        assert r.status_code == 409


class TestJobBatch:
    def test_batch_cancel(self, app_client):
        client, db = app_client
        j1 = _seed_job(db, status="queued")
        j2 = _seed_job(db, status="completed")
        r = client.post("/api/v1/jobs/batch", headers=AUTH, json={
            "action": "cancel", "job_ids": [j1.job_id, j2.job_id]
        })
        assert r.status_code == 200
        data = r.json()
        assert j1.job_id in data["accepted"]
        assert len(data["rejected"]) == 1

    def test_batch_delete(self, app_client):
        client, db = app_client
        j1 = _seed_job(db, status="failed")
        r = client.post("/api/v1/jobs/batch", headers=AUTH, json={
            "action": "delete", "job_ids": [j1.job_id]
        })
        assert r.status_code == 200
        assert j1.job_id in r.json()["accepted"]


# ===== Job Data Endpoint Tests =====

class TestJobSummary:
    def test_summary_returns_counts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id)
        _seed_alert(db, job.job_id)
        _seed_finding(db, job.job_id)
        _seed_ioc(db, job.job_id)

        r = client.get(f"/api/v1/jobs/{job.job_id}/summary", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["alert_count"] == 1
        assert data["finding_count"] == 1
        assert data["ioc_count"] == 1
        assert data["host_count"] == 1
        assert "headline" in data

    def test_summary_404(self, app_client):
        client, db = app_client
        r = client.get(f"/api/v1/jobs/{_uuid()}/summary", headers=AUTH)
        assert r.status_code == 404


class TestJobSensors:
    def test_list_sensors(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_sensor(db, job.job_id, "suricata")
        _seed_sensor(db, job.job_id, "zeek")

        r = client.get(f"/api/v1/jobs/{job.job_id}/sensors", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 2
        sensors = [i["sensor"] for i in items]
        assert "suricata" in sensors
        assert "zeek" in sensors


class TestJobTimeline:
    def test_list_timeline(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_timeline(db, job.job_id)

        r = client.get(f"/api/v1/jobs/{job.job_id}/timeline", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1
        assert r.json()["items"][0]["type"] == "alert"

    def test_timeline_type_filter(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_timeline(db, job.job_id, type="alert")
        _seed_timeline(db, job.job_id, type="connection")

        r = client.get(f"/api/v1/jobs/{job.job_id}/timeline?type=alert", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1


class TestJobIocs:
    def test_list_iocs(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_ioc(db, job.job_id)

        r = client.get(f"/api/v1/jobs/{job.job_id}/iocs", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["type"] == "ip"
        assert items[0]["value"] == "192.168.1.100"

    def test_list_iocs_type_filter_uses_alias(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_ioc(db, job.job_id, ioc_type="ip", value="192.168.1.100")
        _seed_ioc(db, job.job_id, ioc_type="domain", value="bad.example")

        r = client.get(f"/api/v1/jobs/{job.job_id}/iocs?type=domain", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["type"] == "domain"
        assert items[0]["value"] == "bad.example"


# ===== Host Endpoint Tests =====

class TestHostEndpoints:
    def test_list_hosts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.1")
        _seed_host(db, job.job_id, ip="10.0.0.2")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 2

    def test_host_detail(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.5")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.5", headers=AUTH)
        assert r.status_code == 200
        host = r.json()["host"]
        assert host["ip"] == "10.0.0.5"
        assert "dns_summary" in host
        assert "tls_summary" in host

    def test_host_not_found(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/99.99.99.99", headers=AUTH)
        assert r.status_code == 404

    def test_host_connections(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.1")
        _seed_connection(db, job.job_id, host_ip="10.0.0.1")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.1/connections", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1

    def test_host_alerts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, ip="10.0.0.1")
        _seed_alert(db, job.job_id, host_ip="10.0.0.1")

        r = client.get(f"/api/v1/jobs/{job.job_id}/hosts/10.0.0.1/alerts", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1


# ===== Findings Endpoint Tests =====

class TestFindingsEndpoints:
    def test_list_findings(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, severity="high")
        _seed_finding(db, job.job_id, severity="low")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 2

    def test_findings_severity_filter(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, severity="high")
        _seed_finding(db, job.job_id, severity="low")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings?severity=high", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1

    def test_findings_include_metadata_and_category_filter(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(
            db,
            job.job_id,
            sensor="beaconing",
            category="dns",
            pcap_label="capture-a",
            title="DNS tunneling suspected",
        )
        _seed_finding(db, job.job_id, sensor="suricata", category="alert_group", title="Other finding")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings?category=dns", headers=AUTH)
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["category"] == "dns"
        assert items[0]["sensor"] == "beaconing"
        assert items[0]["pcap_label"] == "capture-a"

    def test_findings_q_filter_searches_title_summary_and_metadata(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(
            db,
            job.job_id,
            sensor="beaconing",
            category="tls_anomaly",
            pcap_label="capture-b",
            title="TLS on high port",
            summary="Potential C2 over alternate TLS port",
        )
        _seed_finding(db, job.job_id, title="Benign finding", summary="Nothing to see")

        r = client.get(f"/api/v1/jobs/{job.job_id}/findings?q=capture-b", headers=AUTH)
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1
        assert r.json()["items"][0]["pcap_label"] == "capture-b"

    def test_explain_finding_returns_grounded_markdown_with_evidence(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(
            db,
            job.job_id,
            title="ET MALWARE AlphaCrypt CnC Beacon 5",
            summary="Alert fired multiple times for suspicious outbound traffic.",
            category="alert_group",
            pcap_label="capture-a",
            evidence_json=json.dumps({
                "alert_count": 4,
                "affected_hosts": ["192.168.122.249", "79.96.20.98"],
                "sample_ts": "2026-03-11T10:15:00Z",
            }),
        )

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["format"] == "markdown"
        assert body["duration_ms"] >= 0
        assert body["source"] == "deterministic"
        assert body["warning"] is None
        assert body["explanation_feedback"] is None
        assert [section["id"] for section in body["sections"]] == [
            "assessment",
            "why_it_matters",
            "recommended_next_steps",
        ]
        assert body["sections"][0]["title"] == "Assessment"
        assert body["sections"][0]["citations"] == [
            "finding.severity",
            "finding.sensor",
            "finding.category",
            "finding.summary",
        ]
        assert body["sections"][1]["citations"] == [
            "finding.evidence.alert_count",
            "finding.evidence.affected_hosts",
        ]
        assert body["sections"][2]["citations"] == [
            "finding.evidence.affected_hosts",
            "finding.evidence.sample_ts",
            "finding.evidence.alert_count",
            "finding.pcap_label",
        ]
        assert body["sections"][2]["bullets"]
        assert body["evidence_items"] == [
            {
                "label": "Alert count",
                "value": "4",
                "citation": "finding.evidence.alert_count",
            },
            {
                "label": "Affected hosts",
                "value": "192.168.122.249, 79.96.20.98",
                "citation": "finding.evidence.affected_hosts",
            },
            {
                "label": "Sample ts",
                "value": "2026-03-11T10:15:00Z",
                "citation": "finding.evidence.sample_ts",
            },
        ]
        assert body["content"].startswith("# ET MALWARE AlphaCrypt CnC Beacon 5")
        assert "## Assessment" in body["content"]
        assert "## Supporting evidence" in body["content"]
        assert "Alert count: 4" in body["content"]
        assert "Affected hosts: 192.168.122.249, 79.96.20.98" in body["content"]
        assert "capture-a" in body["content"]

    def test_explain_finding_text_format(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(
            db,
            job.job_id,
            sensor="capa",
            severity="medium",
            title="Suspicious PE capability cluster",
            summary="Capability overlap suggests staged execution behavior.",
        )

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "text"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["format"] == "text"
        assert body["source"] == "deterministic"
        assert len(body["sections"]) == 3
        assert body["sections"][0]["citations"] == ["finding.severity", "finding.sensor", "finding.summary"]
        assert body["sections"][1]["citations"] == ["finding.summary"]
        assert body["sections"][2]["citations"] == ["finding.title"]
        assert body["evidence_items"] == []
        assert body["content"].startswith("Finding: Suspicious PE capability cluster")
        assert "Assessment:" in body["content"]
        assert "Supporting evidence:" in body["content"]

    def test_explain_finding_uses_llm_when_enabled(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(db, job.job_id, title="LLM-backed finding")

        class _FakeClient:
            async def chat_completion(self, messages, temperature=None):
                return json.dumps({
                    "assessment": "This is an LLM-grounded assessment based on the saved finding bundle.",
                    "why_it_matters": "The evidence suggests suspicious behavior that merits analyst review.",
                    "recommended_next_steps": [
                        "Review correlated job telemetry for the same time window.",
                        "Inspect the hosts referenced by the finding for follow-on activity.",
                    ],
                })

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "llm"
        assert body["warning"] is None
        assert len(body["sections"]) == 3
        assert body["evidence_items"] == []
        assert body["sections"][0]["body"] == "This is an LLM-grounded assessment based on the saved finding bundle."
        assert body["sections"][0]["citations"] == ["finding.severity", "finding.sensor", "finding.summary"]
        assert body["sections"][1]["body"] == "The evidence suggests suspicious behavior that merits analyst review."
        assert body["sections"][1]["citations"] == ["finding.summary"]
        assert body["sections"][2]["bullets"] == [
            "Review correlated job telemetry for the same time window.",
            "Inspect the hosts referenced by the finding for follow-on activity.",
        ]
        assert body["sections"][2]["citations"] == ["finding.title"]
        assert "## Assessment" in body["content"]
        assert "This is an LLM-grounded assessment based on the saved finding bundle." in body["content"]

    def test_explain_finding_uses_validated_llm_section_citations_when_provided(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(
            db,
            job.job_id,
            title="LLM-cited finding",
            pcap_label="capture-llm",
            evidence_json=json.dumps({
                "affected_hosts": ["10.10.10.10"],
                "sample_ts": "2026-03-12T12:00:00Z",
            }),
        )

        class _FakeClient:
            async def chat_completion(self, messages, temperature=None):
                return json.dumps({
                    "assessment": "This explanation stays within the stored finding bundle.",
                    "why_it_matters": "The recorded host and timestamp provide concrete pivot points.",
                    "recommended_next_steps": [
                        "Pivot into the affected host for surrounding activity.",
                        "Use the capture label and timestamp to inspect nearby traffic.",
                    ],
                    "section_citations": {
                        "assessment": ["finding.summary", "finding.sensor"],
                        "why_it_matters": ["finding.evidence.affected_hosts"],
                        "recommended_next_steps": ["finding.pcap_label", "finding.evidence.sample_ts"],
                    },
                })

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "llm"
        assert body["warning"] is None
        assert body["sections"][0]["citations"] == ["finding.summary", "finding.sensor"]
        assert body["sections"][1]["citations"] == ["finding.evidence.affected_hosts"]
        assert body["sections"][2]["citations"] == ["finding.pcap_label", "finding.evidence.sample_ts"]

    def test_explain_finding_llm_prompt_budgets_large_evidence_payload(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        finding = _seed_finding(
            db,
            job.job_id,
            title="Budgeted prompt finding",
            evidence_json=json.dumps({
                "alpha": 1,
                "bravo": 2,
                "charlie": 3,
                "delta": 4,
                "echo": 5,
                "foxtrot": 6,
                "golf": 7,
            }),
        )
        captured_prompt = {"text": None}

        class _FakeClient:
            async def chat_completion(self, messages, temperature=None):
                captured_prompt["text"] = "\n\n".join(message["content"] for message in messages)
                return json.dumps({
                    "assessment": "Bounded prompt produced a valid explanation.",
                    "why_it_matters": "The listed evidence preview is sufficient for a concise explanation.",
                    "recommended_next_steps": ["Review the surfaced evidence preview."],
                })

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{finding.finding_id}/explain",
            headers=AUTH,
            json={"format": "markdown"},
        )
        assert r.status_code == 200
        assert r.json()["source"] == "llm"
        assert captured_prompt["text"] is not None
        assert "- Alpha: 1 (citation: finding.evidence.alpha)" in captured_prompt["text"]
        assert "- Echo: 5 (citation: finding.evidence.echo)" in captured_prompt["text"]
        assert "Additional evidence fields omitted from prompt: 2" in captured_prompt["text"]
        assert "Base the explanation only on the listed evidence and metadata." in captured_prompt["text"]
        assert "- Foxtrot: 6 (citation: finding.evidence.foxtrot)" not in captured_prompt["text"]
        assert "- Golf: 7 (citation: finding.evidence.golf)" not in captured_prompt["text"]

    def test_explain_finding_falls_back_when_llm_returns_invalid_citations(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(
            db,
            job.job_id,
            title="Invalid citation finding",
            evidence_json=json.dumps({"alert_count": 2}),
        )

        class _FakeClient:
            async def chat_completion(self, messages, temperature=None):
                return json.dumps({
                    "assessment": "Assessment from model.",
                    "why_it_matters": "Why this matters from model.",
                    "recommended_next_steps": ["Review the related alerts."],
                    "section_citations": {
                        "assessment": ["finding.summary"],
                        "why_it_matters": ["finding.evidence.nonexistent"],
                        "recommended_next_steps": ["finding.title"],
                    },
                })

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "fallback"
        assert "invalid structured content" in body["warning"]
        assert body["sections"][0]["citations"] == ["finding.severity", "finding.sensor", "finding.summary"]
        assert body["sections"][1]["citations"] == ["finding.evidence.alert_count"]

    def test_explain_finding_falls_back_when_llm_returns_invalid_structure(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(db, job.job_id, title="Invalid structured finding")

        class _FakeClient:
            async def chat_completion(self, messages, temperature=None):
                return '{"assessment": "Only one field"}'

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "fallback"
        assert "invalid structured content" in body["warning"]
        assert body["sections"][0]["title"] == "Assessment"
        assert body["sections"][0]["citations"] == ["finding.severity", "finding.sensor", "finding.summary"]
        assert body["content"].startswith("# Invalid structured finding")

    def test_explain_finding_falls_back_when_llm_errors(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(db, job.job_id, title="Fallback finding")

        class _BrokenClient:
            async def chat_completion(self, messages, temperature=None):
                raise RuntimeError("backend unavailable")

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _BrokenClient())

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "fallback"
        assert "deterministic grounded explanation" in body["warning"]
        assert len(body["sections"]) == 3
        assert body["sections"][1]["citations"] == ["finding.summary"]
        assert body["content"].startswith("# Fallback finding")

    def test_explain_finding_not_found(self, app_client):
        client, db = app_client
        job = _seed_job(db)

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{_uuid()}/explain",
            headers=AUTH, json={"format": "markdown"},
        )
        assert r.status_code == 404

    def test_update_explain_feedback_persists_for_explain_response(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        f = _seed_finding(db, job.job_id, title="Feedback-enabled finding")

        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain/feedback",
            headers=AUTH,
            json={"explanation_feedback": "useful"},
        )
        assert r.status_code == 200
        assert r.json()["explanation_feedback"] == "useful"

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain",
            headers=AUTH,
            json={"format": "markdown"},
        )
        assert r.status_code == 200
        assert r.json()["explanation_feedback"] == "useful"

        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/findings/{f.finding_id}/explain/feedback",
            headers=AUTH,
            json={"explanation_feedback": None},
        )
        assert r.status_code == 200
        assert r.json()["explanation_feedback"] is None

    def test_update_explain_feedback_not_found(self, app_client):
        client, db = app_client
        job = _seed_job(db)

        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/findings/{_uuid()}/explain/feedback",
            headers=AUTH,
            json={"explanation_feedback": "not_useful"},
        )
        assert r.status_code == 404

    @pytest.mark.parametrize(
        "case",
        _load_explain_golden_cases(),
        ids=lambda case: case["name"],
    )
    def test_explain_finding_matches_golden_fixture(self, app_client, monkeypatch, case):
        from backend.app.api import findings as findings_api

        client, db = app_client
        job = _seed_job(db)
        finding = _seed_finding(db, job.job_id, **case["finding"])
        captured_prompt = {"text": None}

        llm_response = case.get("llm_response")
        if llm_response is not None:
            class _FakeClient:
                async def chat_completion(self, messages, temperature=None):
                    captured_prompt["text"] = "\n\n".join(message["content"] for message in messages)
                    return json.dumps(llm_response)

            monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
            monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())
        else:
            monkeypatch.delenv("AIPAM_EXPLAIN_FINDING_USE_LLM", raising=False)

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/findings/{finding.finding_id}/explain",
            headers=AUTH,
            json=case["request"],
        )
        assert r.status_code == 200

        body = r.json()
        expected = case["expected"]
        assert body["format"] == case["request"]["format"]
        assert body["source"] == expected["source"]
        if expected["warning_contains"] is None:
            assert body["warning"] is None
        else:
            assert expected["warning_contains"] in body["warning"]
        assert [_section_snapshot(section) for section in body["sections"]] == expected["sections"]
        assert body["evidence_items"] == expected["evidence_items"]
        if expected.get("content_startswith"):
            assert body["content"].startswith(expected["content_startswith"])
        for snippet in expected.get("content_contains", []):
            assert snippet in body["content"]
        for snippet in case.get("prompt_contains", []):
            assert captured_prompt["text"] is not None
            assert snippet in captured_prompt["text"]


class TestSystemTelemetry:
    def test_system_config_includes_explain_configuration(self, app_client, monkeypatch):
        client, db = app_client
        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setenv("LLM_MODEL_NAME", "demo-model:latest")
        monkeypatch.setenv("LLM_ENDPOINT", "http://ollama.internal/v1/chat/completions")

        r = client.get("/api/v1/system/config", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["explain_configuration"] == {
            "mode": "llm",
            "llm_enabled": True,
            "llm_model_name": "demo-model:latest",
            "llm_endpoint": "http://ollama.internal/v1/chat/completions",
        }

    def test_explain_telemetry_endpoint_returns_counts(self, app_client):
        from backend.app.api._state import reset_explain_response_counts

        client, db = app_client
        reset_explain_response_counts()

        r = client.get("/api/v1/system/explain-telemetry", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert body["explain_response_counts"] == {
            "deterministic": 0,
            "llm": 0,
            "fallback": 0,
        }
        assert body["explain_latency_ms"] == {
            "count": 0,
            "average_ms": 0,
            "min_ms": 0,
            "max_ms": 0,
            "last_ms": 0,
        }

    def test_explain_telemetry_counts_increment_by_source(self, app_client, monkeypatch):
        from backend.app.api import findings as findings_api
        from backend.app.api._state import reset_explain_response_counts

        client, db = app_client
        reset_explain_response_counts()

        deterministic_job = _seed_job(db)
        deterministic_finding = _seed_finding(db, deterministic_job.job_id, title="Deterministic telemetry")

        class _FakeClient:
            async def chat_completion(self, messages, temperature=None):
                return json.dumps({
                    "assessment": "LLM telemetry assessment.",
                    "why_it_matters": "LLM telemetry why.",
                    "recommended_next_steps": ["Review the related evidence."],
                })

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _FakeClient())
        llm_job = _seed_job(db)
        llm_finding = _seed_finding(db, llm_job.job_id, title="LLM telemetry")

        class _BrokenClient:
            async def chat_completion(self, messages, temperature=None):
                raise RuntimeError("backend unavailable")

        fallback_job = _seed_job(db)
        fallback_finding = _seed_finding(db, fallback_job.job_id, title="Fallback telemetry")

        perf_counter_values = iter([1.0, 1.010, 2.0, 2.020, 3.0, 3.030])
        monkeypatch.setattr(findings_api, "perf_counter", lambda: next(perf_counter_values))

        r = client.post(
            f"/api/v1/jobs/{deterministic_job.job_id}/findings/{deterministic_finding.finding_id}/explain",
            headers=AUTH,
            json={"format": "markdown"},
        )
        assert r.status_code == 200
        assert r.json()["source"] == "llm"

        monkeypatch.delenv("AIPAM_EXPLAIN_FINDING_USE_LLM", raising=False)
        r = client.post(
            f"/api/v1/jobs/{llm_job.job_id}/findings/{llm_finding.finding_id}/explain",
            headers=AUTH,
            json={"format": "markdown"},
        )
        assert r.status_code == 200
        assert r.json()["source"] == "deterministic"

        monkeypatch.setenv("AIPAM_EXPLAIN_FINDING_USE_LLM", "1")
        monkeypatch.setattr(findings_api, "_make_llm_client", lambda settings: _BrokenClient())
        r = client.post(
            f"/api/v1/jobs/{fallback_job.job_id}/findings/{fallback_finding.finding_id}/explain",
            headers=AUTH,
            json={"format": "markdown"},
        )
        assert r.status_code == 200
        assert r.json()["source"] == "fallback"

        r = client.get("/api/v1/system/explain-telemetry", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert body["explain_response_counts"] == {
            "deterministic": 1,
            "llm": 1,
            "fallback": 1,
        }
        assert body["explain_latency_ms"] == {
            "count": 3,
            "average_ms": 20,
            "min_ms": 10,
            "max_ms": 30,
            "last_ms": 30,
        }

    def test_explain_telemetry_reset_endpoint_clears_counts(self, app_client):
        from backend.app.api._state import increment_explain_response_count, reset_explain_response_counts

        client, db = app_client
        reset_explain_response_counts()
        increment_explain_response_count("deterministic", duration_ms=11)
        increment_explain_response_count("llm", duration_ms=22)
        increment_explain_response_count("fallback", duration_ms=33)

        r = client.post("/api/v1/system/explain-telemetry/reset", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert body["explain_response_counts"] == {
            "deterministic": 0,
            "llm": 0,
            "fallback": 0,
        }
        assert body["explain_latency_ms"] == {
            "count": 0,
            "average_ms": 0,
            "min_ms": 0,
            "max_ms": 0,
            "last_ms": 0,
        }

        r = client.get("/api/v1/system/explain-telemetry", headers=AUTH)
        assert r.status_code == 200
        body = r.json()
        assert body["explain_response_counts"] == {
            "deterministic": 0,
            "llm": 0,
            "fallback": 0,
        }
        assert body["explain_latency_ms"] == {
            "count": 0,
            "average_ms": 0,
            "min_ms": 0,
            "max_ms": 0,
            "last_ms": 0,
        }


# ===== Artifacts Endpoint Tests =====

class TestArtifactsEndpoints:
    def test_list_artifacts_empty(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/artifacts", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_create_evidence_package(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.post(f"/api/v1/jobs/{job.job_id}/artifacts/evidence-package", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "available"
        assert "artifact_id" in data

        # Verify it shows in list
        r2 = client.get(f"/api/v1/jobs/{job.job_id}/artifacts", headers=AUTH)
        assert len(r2.json()["items"]) == 1


# ===== SSE Events Test =====

class TestSSEEvents:
    def test_events_stream_completed_job(self, app_client):
        client, db = app_client
        job = _seed_job(db, status="completed")
        r = client.get(f"/api/v1/jobs/{job.job_id}/events", headers=AUTH)
        assert r.status_code == 200
        assert "text/event-stream" in r.headers["content-type"]
        # Should contain a status event and a done event
        text = r.text
        assert "event: status" in text
        assert "event: done" in text

    def test_events_stream_not_found(self, app_client):
        client, db = app_client
        r = client.get(f"/api/v1/jobs/{_uuid()}/events", headers=AUTH)
        assert r.status_code == 404

