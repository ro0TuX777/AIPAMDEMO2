"""Tests for Phase 1C — Contextualizer (Why Unusual?) engine, API, and evidence bundles."""

import uuid
from datetime import datetime, timezone


from backend.app.models.host import Host
from backend.app.models.job import Job
from backend.app.services.contextualizer import (
    _compute_baselines,
    _deviation_confidence,
    _deviation_severity,
    _find_outliers,
    _format_value,
    _HostMetrics,
    generate_annotations,
)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid():
    return str(uuid.uuid4())


def _make_job(db):
    job = Job(job_id=_uid(), job_name="test", status="completed",
              execution_profile="standard", priority="normal",
              pcap_filename="t.pcap", pcap_size_bytes=100,
              pcap_sha256="abc", created_at=_now())
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _make_hosts(db, job_id, specs):
    """specs: list of dicts with host fields (ip required)."""
    hosts = []
    for s in specs:
        h = Host(job_id=job_id, ip=s["ip"], role="internal",
                 conn_count=s.get("conn_count", 0),
                 bytes_sent=s.get("bytes_sent", 0),
                 bytes_recv=s.get("bytes_recv", 0),
                 alert_count=s.get("alert_count", 0),
                 finding_count=s.get("finding_count", 0),
                 dns_query_count=s.get("dns_query_count", 0),
                 first_seen=_now(), last_seen=_now())
        db.add(h)
        hosts.append(h)
    db.commit()
    return hosts


# ── Unit tests: helper functions ─────────────────────────────────────────────

class TestDeviationSeverity:
    def test_critical(self):
        assert _deviation_severity(10.0) == "critical"

    def test_high(self):
        assert _deviation_severity(5.0) == "high"

    def test_medium(self):
        assert _deviation_severity(3.0) == "medium"

    def test_low(self):
        assert _deviation_severity(2.5) == "low"

    def test_info(self):
        assert _deviation_severity(1.5) == "info"


class TestDeviationConfidence:
    def test_high_deviation_large_pop(self):
        c = _deviation_confidence(5.0, 10)
        assert c >= 0.8

    def test_low_deviation_small_pop(self):
        c = _deviation_confidence(1.0, 2)
        assert c < 0.6

    def test_caps_at_one(self):
        c = _deviation_confidence(100.0, 100)
        assert c <= 1.0


class TestFormatValue:
    def test_bytes_gb(self):
        assert "GB" in _format_value("bytes_sent", 2_000_000_000)

    def test_bytes_mb(self):
        assert "MB" in _format_value("bytes_sent", 2_000_000)

    def test_bytes_kb(self):
        assert "KB" in _format_value("bytes_sent", 2_000)

    def test_bytes_b(self):
        assert "B" in _format_value("bytes_sent", 500)

    def test_non_bytes(self):
        assert _format_value("conn_count", 42) == "42"


class TestComputeBaselines:
    def test_basic_baselines(self):
        metrics = {
            "a": _HostMetrics(ip="a", conn_count=10),
            "b": _HostMetrics(ip="b", conn_count=20),
            "c": _HostMetrics(ip="c", conn_count=30),
        }
        baselines = _compute_baselines(metrics)
        assert "conn_count" in baselines
        b = baselines["conn_count"]
        assert b.mean == 20.0
        assert b.median == 20.0
        assert b.population_size == 3

    def test_empty_metrics(self):
        baselines = _compute_baselines({})
        assert len(baselines) == 0


class TestFindOutliers:
    def test_detects_outlier(self):
        metrics = {
            "a": _HostMetrics(ip="a", conn_count=10),
            "b": _HostMetrics(ip="b", conn_count=12),
            "c": _HostMetrics(ip="c", conn_count=11),
            "d": _HostMetrics(ip="d", conn_count=100),  # outlier
        }
        baselines = _compute_baselines(metrics)
        outliers = _find_outliers(metrics, baselines)
        outlier_ips = [o["host_ip"] for o in outliers]
        assert "d" in outlier_ips

    def test_no_outliers_similar_values(self):
        metrics = {
            "a": _HostMetrics(ip="a", conn_count=10),
            "b": _HostMetrics(ip="b", conn_count=11),
            "c": _HostMetrics(ip="c", conn_count=12),
        }
        baselines = _compute_baselines(metrics)
        outliers = _find_outliers(metrics, baselines)
        assert len(outliers) == 0

    def test_skips_small_population(self):
        metrics = {
            "a": _HostMetrics(ip="a", conn_count=10),
            "b": _HostMetrics(ip="b", conn_count=1000),
        }
        baselines = _compute_baselines(metrics)
        outliers = _find_outliers(metrics, baselines)
        assert len(outliers) == 0  # only 2 hosts < MIN_POPULATION


# ── Integration tests: full pipeline ─────────────────────────────────────────

class TestGenerateAnnotations:
    def test_generates_for_outlier_host(self, db_session):
        job = _make_job(db_session)
        # 3 normal hosts + 1 outlier
        _make_hosts(db_session, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10, "bytes_sent": 100},
            {"ip": "10.0.0.2", "conn_count": 12, "bytes_sent": 110},
            {"ip": "10.0.0.3", "conn_count": 11, "bytes_sent": 105},
            {"ip": "10.0.0.4", "conn_count": 500, "bytes_sent": 50000},  # outlier
        ])

        anns = generate_annotations(db_session, job.job_id)
        assert len(anns) > 0
        outlier_hosts = {a.host_ip for a in anns}
        assert "10.0.0.4" in outlier_hosts

    def test_skips_too_few_hosts(self, db_session):
        job = _make_job(db_session)
        _make_hosts(db_session, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10},
            {"ip": "10.0.0.2", "conn_count": 1000},
        ])
        anns = generate_annotations(db_session, job.job_id)
        assert len(anns) == 0

    def test_regeneration_replaces(self, db_session):
        job = _make_job(db_session)
        _make_hosts(db_session, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10},
            {"ip": "10.0.0.2", "conn_count": 12},
            {"ip": "10.0.0.3", "conn_count": 11},
            {"ip": "10.0.0.4", "conn_count": 500},
        ])
        anns1 = generate_annotations(db_session, job.job_id)
        ids1 = {a.annotation_id for a in anns1}
        assert len(ids1) > 0
        anns2 = generate_annotations(db_session, job.job_id)
        ids2 = {a.annotation_id for a in anns2}
        # Old annotations deleted, new ones created with new IDs
        assert len(ids2) > 0
        assert ids1.isdisjoint(ids2)

    def test_annotation_fields_populated(self, db_session):
        job = _make_job(db_session)
        _make_hosts(db_session, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10},
            {"ip": "10.0.0.2", "conn_count": 12},
            {"ip": "10.0.0.3", "conn_count": 11},
            {"ip": "10.0.0.4", "conn_count": 500},
        ])
        anns = generate_annotations(db_session, job.job_id)
        a = next(x for x in anns if x.host_ip == "10.0.0.4")
        assert a.annotation_id.startswith("CTX-")
        assert a.title
        assert a.description
        assert a.why_unusual
        assert a.deviation_factor > 0
        assert a.baseline_value is not None
        assert a.observed_value is not None
        assert a.population_size == 4

    def test_empty_job(self, db_session):
        job = _make_job(db_session)
        anns = generate_annotations(db_session, job.job_id)
        assert len(anns) == 0

    def test_no_outliers_uniform_hosts(self, db_session):
        job = _make_job(db_session)
        _make_hosts(db_session, job.job_id, [
            {"ip": f"10.0.0.{i}", "conn_count": 10} for i in range(5)
        ])
        anns = generate_annotations(db_session, job.job_id)
        assert len(anns) == 0

    def test_multiple_metrics_flagged(self, db_session):
        job = _make_job(db_session)
        _make_hosts(db_session, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10, "alert_count": 1},
            {"ip": "10.0.0.2", "conn_count": 12, "alert_count": 2},
            {"ip": "10.0.0.3", "conn_count": 11, "alert_count": 1},
            {"ip": "10.0.0.4", "conn_count": 500, "alert_count": 50},
        ])
        anns = generate_annotations(db_session, job.job_id)
        metrics = {a.metric_name for a in anns if a.host_ip == "10.0.0.4"}
        assert "conn_count" in metrics
        assert "alert_count" in metrics


# ── API tests ────────────────────────────────────────────────────────────────

class TestAnnotationsAPI:
    def _seed(self, db):
        job = _make_job(db)
        _make_hosts(db, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10},
            {"ip": "10.0.0.2", "conn_count": 12},
            {"ip": "10.0.0.3", "conn_count": 11},
            {"ip": "10.0.0.4", "conn_count": 500},
        ])
        return job

    def test_list_empty(self, app_client):
        client, db = app_client
        job = _make_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/annotations",
                       headers={"Authorization": "Bearer test-token-v2"})
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_generate_and_list(self, app_client):
        client, db = app_client
        job = self._seed(db)
        r = client.post(f"/api/v1/jobs/{job.job_id}/annotations/generate",
                        headers={"Authorization": "Bearer test-token-v2"})
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) > 0
        assert any(i["host_ip"] == "10.0.0.4" for i in items)

    def test_list_filter_by_host(self, app_client):
        client, db = app_client
        job = self._seed(db)
        client.post(f"/api/v1/jobs/{job.job_id}/annotations/generate",
                    headers={"Authorization": "Bearer test-token-v2"})
        r = client.get(f"/api/v1/jobs/{job.job_id}/annotations?host_ip=10.0.0.4",
                       headers={"Authorization": "Bearer test-token-v2"})
        assert r.status_code == 200
        items = r.json()["items"]
        assert all(i["host_ip"] == "10.0.0.4" for i in items)

    def test_404_missing_job(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nonexistent/annotations",
                       headers={"Authorization": "Bearer test-token-v2"})
        assert r.status_code == 404


# ── Evidence Bundle tests ────────────────────────────────────────────────────

class TestAnnotationBundle:
    def test_bundle_with_annotations(self, db_session):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        job = _make_job(db_session)
        _make_hosts(db_session, job.job_id, [
            {"ip": "10.0.0.1", "conn_count": 10},
            {"ip": "10.0.0.2", "conn_count": 12},
            {"ip": "10.0.0.3", "conn_count": 11},
            {"ip": "10.0.0.4", "conn_count": 500},
        ])
        generate_annotations(db_session, job.job_id)
        bundle = build_scoped_bundle(db_session, job.job_id, "annotation", "10.0.0.4")
        ctx = bundle.to_context()
        assert "10.0.0.4" in ctx
        assert "ANNOTATION" in ctx

    def test_bundle_empty(self, db_session):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        job = _make_job(db_session)
        bundle = build_scoped_bundle(db_session, job.job_id, "annotation", "10.0.0.99")
        ctx = bundle.to_context()
        assert "No context annotations" in ctx

