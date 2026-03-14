"""Tests for Phase 1D — Report Composer engine, API, and evidence bundles."""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.report import Report
from backend.app.models.slice import IncidentSlice
from backend.app.models.theory import Theory
from backend.app.services.report_composer import (
    _fmt_bytes,
    _generate_recommendations,
    _parse_json_list,
    _report_confidence,
    _threat_level,
    generate_report,
)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid():
    return str(uuid.uuid4())


def _make_job(db):
    job = Job(job_id=_uid(), job_name="test", status="completed",
              execution_profile="standard", priority="normal",
              pcap_filename="test.pcap", pcap_size_bytes=10000,
              pcap_sha256="abc", created_at=_now())
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _make_alert(db, job_id, severity="medium", **kw):
    a = Alert(job_id=job_id, alert_id=f"A-{_uid()[:8]}",
              host_ip=kw.pop("host_ip", "10.0.0.1"),
              severity=severity, signature="Test alert signature",
              ts=_now(), **kw)
    db.add(a)
    return a


def _make_finding(db, job_id, severity="medium", confidence=0.7, **kw):
    f = Finding(job_id=job_id, finding_id=f"F-{_uid()[:8]}", sensor="zeek",
                severity=severity, title="Test finding", confidence=confidence, **kw)
    db.add(f)
    return f


def _make_theory(db, job_id, hypothesis_type="c2", score=0.8, rank=1, **kw):
    t = Theory(job_id=job_id, theory_id=f"TH-{_uid()[:8]}",
               label=f"Test {hypothesis_type}", hypothesis_type=hypothesis_type,
               score=score, rank=rank, created_at=_now(), **kw)
    db.add(t)
    return t


def _make_slice(db, job_id, severity="medium", rank=1, **kw):
    s = IncidentSlice(job_id=job_id, slice_id=f"SLC-{_uid()[:8]}",
                      label="Test slice", severity=severity, rank=rank,
                      created_at=_now(), **kw)
    db.add(s)
    return s


def _make_host(db, job_id, ip="10.0.0.1", **kw):
    h = Host(job_id=job_id, ip=ip, role="internal",
             conn_count=kw.get("conn_count", 10),
             first_seen=_now(), last_seen=_now(), **{k: v for k, v in kw.items() if k != "conn_count"})
    db.add(h)
    return h


def _make_ioc(db, job_id, ioc_type="ip", value="1.2.3.4", severity="high", **kw):
    ioc = Ioc(job_id=job_id, ioc_id=f"IOC-{_uid()[:8]}", ioc_type=ioc_type,
              value=value, severity=severity, **kw)
    db.add(ioc)
    return ioc


def _seed_full_job(db):
    """Create a job with theories, slices, findings, alerts, hosts, IOCs."""
    job = _make_job(db)
    jid = job.job_id
    _make_theory(db, jid, "c2", score=0.85, rank=1)
    _make_theory(db, jid, "exfiltration", score=0.6, rank=2)
    _make_slice(db, jid, severity="high", rank=1)
    _make_alert(db, jid, severity="high")
    _make_alert(db, jid, severity="medium")
    _make_finding(db, jid, severity="critical", confidence=0.9)
    _make_finding(db, jid, severity="medium", confidence=0.5)
    _make_host(db, jid, ip="10.0.0.1", conn_count=50)
    _make_host(db, jid, ip="10.0.0.2", conn_count=20)
    _make_ioc(db, jid, ioc_type="ip", value="evil.example.com", severity="high")
    db.commit()
    return job


# ═══════════════════════════════════════════════════════════════════════════
#  Unit Tests — Pure functions
# ═══════════════════════════════════════════════════════════════════════════


class TestThreatLevel:
    def test_info_when_empty(self):
        assert _threat_level([], []) == "info"

    def test_takes_worst_alert(self):
        a1 = MagicMock(severity="medium")
        a2 = MagicMock(severity="critical")
        assert _threat_level([a1, a2], []) == "critical"

    def test_takes_worst_finding(self):
        f1 = MagicMock(severity="low")
        f2 = MagicMock(severity="high")
        assert _threat_level([], [f1, f2]) == "high"

    def test_worst_across_alerts_and_findings(self):
        a = MagicMock(severity="medium")
        f = MagicMock(severity="critical")
        assert _threat_level([a], [f]) == "critical"


class TestReportConfidence:
    def test_empty_returns_zero(self):
        assert _report_confidence([], []) == 0.0

    def test_averages_theory_scores(self):
        t1 = MagicMock(score=0.8)
        t2 = MagicMock(score=0.6)
        result = _report_confidence([t1, t2], [])
        assert abs(result - 0.7) < 0.01



class TestFmtBytes:
    def test_bytes(self):
        assert _fmt_bytes(500) == "500 B"

    def test_kilobytes(self):
        assert "KB" in _fmt_bytes(2048)

    def test_megabytes(self):
        assert "MB" in _fmt_bytes(5_000_000)

    def test_gigabytes(self):
        assert "GB" in _fmt_bytes(2_000_000_000)

    def test_zero(self):
        assert _fmt_bytes(0) == "0 B"

    def test_none(self):
        assert _fmt_bytes(None) == "0 B"


class TestParseJsonList:
    def test_valid_list(self):
        assert _parse_json_list('["a", "b"]') == ["a", "b"]

    def test_none(self):
        assert _parse_json_list(None) == []

    def test_empty_string(self):
        assert _parse_json_list("") == []

    def test_invalid_json(self):
        assert _parse_json_list("not json") == []

    def test_non_list_json(self):
        assert _parse_json_list('{"key": "val"}') == []


class TestGenerateRecommendations:
    def test_critical_threat(self):
        recs = _generate_recommendations("critical", [], [], [])
        assert any("isolate" in r.lower() for r in recs)

    def test_c2_theory(self):
        t = MagicMock(hypothesis_type="c2")
        recs = _generate_recommendations("medium", [t], [], [])
        assert any("c2" in r.lower() for r in recs)

    def test_iocs_present(self):
        ioc = MagicMock()
        recs = _generate_recommendations("low", [], [], [ioc])
        assert any("block" in r.lower() for r in recs)

    def test_no_actions_needed(self):
        recs = _generate_recommendations("info", [], [], [])
        assert any("monitoring" in r.lower() for r in recs)

    def test_always_includes_preserve(self):
        recs = _generate_recommendations("info", [], [], [])
        assert any("preserve" in r.lower() for r in recs)


# ═══════════════════════════════════════════════════════════════════════════
#  Integration Tests — DB-backed
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateReport:
    def test_analyst_report_basic(self, db_session):
        job = _seed_full_job(db_session)
        report = generate_report(db_session, job.job_id, mode="analyst")
        assert report.report_id.startswith("RPT-")
        assert report.mode == "analyst"
        assert report.theory_count == 2
        assert report.slice_count == 1
        assert report.finding_count == 2
        assert report.alert_count == 2
        assert report.ioc_count == 1
        assert report.host_count == 2
        assert report.threat_level == "critical"  # finding has critical severity
        assert report.confidence > 0.0
        assert len(report.content_markdown) > 0

    def test_executive_report_basic(self, db_session):
        job = _seed_full_job(db_session)
        report = generate_report(db_session, job.job_id, mode="executive")
        assert report.mode == "executive"
        assert "Executive" in report.title
        assert report.threat_level == "critical"
        assert len(report.content_markdown) > 0

    def test_report_content_json_valid(self, db_session):
        job = _seed_full_job(db_session)
        report = generate_report(db_session, job.job_id, mode="analyst")
        sections = json.loads(report.content_json)
        assert isinstance(sections, dict)
        assert len(sections) > 0

    def test_evidence_refs_populated(self, db_session):
        job = _seed_full_job(db_session)
        report = generate_report(db_session, job.job_id, mode="analyst")
        refs = json.loads(report.evidence_refs_json)
        assert isinstance(refs, list)
        assert any(r.startswith("TH-") for r in refs)
        assert any(r.startswith("F-") for r in refs)
        assert any(r.startswith("IOC-") for r in refs)

    def test_regeneration_replaces_same_mode(self, db_session):
        job = _seed_full_job(db_session)
        r1 = generate_report(db_session, job.job_id, mode="analyst")
        r2 = generate_report(db_session, job.job_id, mode="analyst")
        assert r1.report_id != r2.report_id
        # Only latest should remain
        from sqlalchemy import select
        remaining = db_session.execute(
            select(Report).where(Report.job_id == job.job_id, Report.mode == "analyst")
        ).scalars().all()
        assert len(remaining) == 1
        assert remaining[0].report_id == r2.report_id

    def test_different_modes_coexist(self, db_session):
        job = _seed_full_job(db_session)
        generate_report(db_session, job.job_id, mode="analyst")
        generate_report(db_session, job.job_id, mode="executive")
        from sqlalchemy import select
        all_reports = db_session.execute(
            select(Report).where(Report.job_id == job.job_id)
        ).scalars().all()
        assert len(all_reports) == 2
        modes = {r.mode for r in all_reports}
        assert modes == {"analyst", "executive"}

    def test_empty_job_produces_report(self, db_session):
        job = _make_job(db_session)
        report = generate_report(db_session, job.job_id, mode="analyst")
        assert report.report_id.startswith("RPT-")
        assert report.theory_count == 0
        assert report.threat_level == "info"
        assert report.confidence == 0.0

    def test_invalid_job_raises(self, db_session):
        with pytest.raises(ValueError, match="not found"):
            generate_report(db_session, "nonexistent-job-id", mode="analyst")


class TestReportAPI:
    def _seed(self, db):
        job = _make_job(db)
        _make_alert(db, job.job_id, severity="high")
        _make_finding(db, job.job_id, severity="medium", confidence=0.6)
        _make_theory(db, job.job_id, "c2", score=0.8)
        db.commit()
        return job

    def test_generate_and_list(self, app_client):
        client, db = app_client
        job = self._seed(db)
        # Generate
        resp = client.post(
            f"/api/v1/jobs/{job.job_id}/reports/generate",
            json={"mode": "analyst"},
            headers={"Authorization": "Bearer test-token-v2"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["item"]["mode"] == "analyst"
        assert data["item"]["report_id"].startswith("RPT-")

        # List
        resp = client.get(
            f"/api/v1/jobs/{job.job_id}/reports",
            headers={"Authorization": "Bearer test-token-v2"},
        )
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1

    def test_get_single_report(self, app_client):
        client, db = app_client
        job = self._seed(db)
        gen_resp = client.post(
            f"/api/v1/jobs/{job.job_id}/reports/generate",
            json={"mode": "executive"},
            headers={"Authorization": "Bearer test-token-v2"},
        )
        report_id = gen_resp.json()["item"]["report_id"]
        resp = client.get(
            f"/api/v1/jobs/{job.job_id}/reports/{report_id}",
            headers={"Authorization": "Bearer test-token-v2"},
        )
        assert resp.status_code == 200
        assert resp.json()["item"]["report_id"] == report_id

    def test_404_nonexistent_job(self, app_client):
        client, db = app_client
        resp = client.get(
            "/api/v1/jobs/fake-job/reports",
            headers={"Authorization": "Bearer test-token-v2"},
        )
        assert resp.status_code == 404

    def test_404_nonexistent_report(self, app_client):
        client, db = app_client
        job = self._seed(db)
        resp = client.get(
            f"/api/v1/jobs/{job.job_id}/reports/fake-report",
            headers={"Authorization": "Bearer test-token-v2"},
        )
        assert resp.status_code == 404


class TestReportBundle:
    def test_bundle_with_reports(self, db_session):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        job = _seed_full_job(db_session)
        generate_report(db_session, job.job_id, mode="analyst")
        bundle = build_scoped_bundle(db_session, job.job_id, "report", None)
        ctx = bundle.to_context()
        assert "RPT-" in ctx
        assert "REPORT" in ctx.upper()

    def test_bundle_empty(self, db_session):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        job = _make_job(db_session)
        bundle = build_scoped_bundle(db_session, job.job_id, "report", None)
        ctx = bundle.to_context()
        assert "no" in ctx.lower() or "No" in ctx

