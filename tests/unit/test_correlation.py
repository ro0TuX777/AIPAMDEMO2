"""Sprint 8 tests — Cross-Job Correlation.

Covers:
  - Host matching across jobs
  - IOC matching across jobs
  - MITRE technique (category) matching across jobs
  - Campaign candidate detection
  - Single-job / self-exclusion edge cases
  - Related-jobs endpoint
  - Correlation API endpoints
"""

import uuid
from datetime import datetime, timezone


AUTH = {"Authorization": "Bearer test-token-v2"}


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _seed_job(db, **kwargs):
    from backend.app.models.job import Job
    jid = kwargs.pop("job_id", _uuid())
    job = Job(
        job_id=jid, job_name=kwargs.pop("job_name", "Test Job"), status="completed",
        execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=1024, pcap_sha256="abc",
        created_at=_now(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _seed_host(db, job_id, ip, **kwargs):
    from backend.app.models.host import Host
    h = Host(job_id=job_id, ip=ip, alert_count=kwargs.get("alert_count", 0),
             finding_count=kwargs.get("finding_count", 0))
    db.add(h)
    db.commit()
    db.refresh(h)
    return h


def _seed_ioc(db, job_id, value, ioc_type="ip", severity="high", **kwargs):
    from backend.app.models.ioc import Ioc
    i = Ioc(job_id=job_id, ioc_id=_uuid(), ioc_type=ioc_type,
            value=value, severity=severity)
    db.add(i)
    db.commit()
    db.refresh(i)
    return i


def _seed_finding(db, job_id, **kwargs):
    from backend.app.models.finding import Finding
    payload = {
        "job_id": job_id, "finding_id": _uuid(),
        "sensor": "suricata", "severity": "high",
        "title": "Test finding", "summary": "Test",
    }
    payload.update(kwargs)
    f = Finding(**payload)
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def _seed_alert(db, job_id, **kwargs):
    from backend.app.models.alert import Alert
    payload = {
        "job_id": job_id, "alert_id": _uuid(),
        "host_ip": "10.0.0.1", "severity": "high",
        "signature": "ET MALWARE Test", "ts": _now(),
    }
    payload.update(kwargs)
    a = Alert(**payload)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


# ===== Host Matching =====


class TestHostCorrelation:
    """find_host_matches"""

    def test_same_host_correlation(self, app_client):
        """Two jobs sharing a host produce a correlation match."""
        client, db = app_client
        job_a = _seed_job(db, job_name="Job A")
        job_b = _seed_job(db, job_name="Job B")
        _seed_host(db, job_a.job_id, "192.168.1.100", alert_count=3, finding_count=1)
        _seed_host(db, job_b.job_id, "192.168.1.100", alert_count=5, finding_count=2)

        from backend.app.services.correlation import find_host_matches
        matches = find_host_matches(db, job_a.job_id, ["192.168.1.100"])

        assert len(matches) == 1
        m = matches[0]
        assert m.match_type == "same_host"
        assert m.matched_entity == "192.168.1.100"
        assert m.job_id == job_b.job_id
        assert m.similarity_score > 0

    def test_no_host_match_for_unique_ip(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        _seed_host(db, job_a.job_id, "10.10.10.10")

        from backend.app.services.correlation import find_host_matches
        matches = find_host_matches(db, job_a.job_id, ["10.10.10.10"])
        assert len(matches) == 0

    def test_excludes_current_job(self, app_client):
        """Current job's own hosts should not appear in results."""
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, "1.2.3.4")

        from backend.app.services.correlation import find_host_matches
        matches = find_host_matches(db, job.job_id, ["1.2.3.4"])
        assert len(matches) == 0


# ===== IOC Matching =====


class TestIocCorrelation:
    """find_ioc_matches"""

    def test_same_ioc_correlation(self, app_client):
        client, db = app_client
        job_a = _seed_job(db, job_name="Job A")
        job_b = _seed_job(db, job_name="Job B")
        _seed_ioc(db, job_a.job_id, "evil.com", ioc_type="domain", severity="critical")
        _seed_ioc(db, job_b.job_id, "evil.com", ioc_type="domain", severity="critical")



class TestMitreCorrelation:
    """find_mitre_matches"""

    def test_mitre_technique_correlation(self, app_client):
        client, db = app_client
        job_a = _seed_job(db, job_name="Job A")
        job_b = _seed_job(db, job_name="Job B")
        _seed_finding(db, job_a.job_id, category="Command and Control")
        _seed_finding(db, job_b.job_id, category="Command and Control", title="C2 beacon")

        from backend.app.services.correlation import find_mitre_matches
        matches = find_mitre_matches(db, job_a.job_id)

        assert len(matches) >= 1
        m = matches[0]
        assert m.match_type == "same_mitre"
        assert m.matched_entity == "Command and Control"
        assert m.job_id == job_b.job_id

    def test_no_mitre_match_for_unique_category(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        _seed_finding(db, job_a.job_id, category="Unique Category XYZ")

        from backend.app.services.correlation import find_mitre_matches
        matches = find_mitre_matches(db, job_a.job_id)
        assert len(matches) == 0


# ===== Campaign Detection =====


class TestCampaignDetection:
    """detect_campaigns"""

    def test_campaign_candidate_detection(self, app_client):
        """3+ jobs sharing IOCs produce a campaign candidate."""
        client, db = app_client
        job_a = _seed_job(db, job_name="Job A")
        job_b = _seed_job(db, job_name="Job B")
        job_c = _seed_job(db, job_name="Job C")

        # All three share 2 IOCs (meeting _MIN_CAMPAIGN_OVERLAP=2)
        for jid in [job_a.job_id, job_b.job_id, job_c.job_id]:
            _seed_ioc(db, jid, "malware-c2.evil.com", ioc_type="domain", severity="critical")
            _seed_ioc(db, jid, "dropper.bad.org", ioc_type="domain", severity="high")

        from backend.app.services.correlation import find_ioc_matches, detect_campaigns
        matches = find_ioc_matches(db, job_a.job_id)
        campaigns = detect_campaigns(db, job_a.job_id, matches)

        assert len(campaigns) == 1
        c = campaigns[0]
        assert len(c.job_ids) >= 3
        assert job_a.job_id in c.job_ids
        assert job_b.job_id in c.job_ids
        assert job_c.job_id in c.job_ids
        assert c.confidence > 0

    def test_no_campaign_with_two_jobs(self, app_client):
        """Only 2 jobs shouldn't produce a campaign (need 3+)."""
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        for jid in [job_a.job_id, job_b.job_id]:
            _seed_ioc(db, jid, "shared-ioc.com", severity="high")

        from backend.app.services.correlation import find_ioc_matches, detect_campaigns
        matches = find_ioc_matches(db, job_a.job_id)
        campaigns = detect_campaigns(db, job_a.job_id, matches)
        assert len(campaigns) == 0

    def test_no_campaign_with_single_overlap(self, app_client):
        """Jobs sharing only 1 entity don't form a campaign (need _MIN_CAMPAIGN_OVERLAP=2)."""
        client, db = app_client
        jobs = [_seed_job(db) for _ in range(4)]
        for j in jobs:
            _seed_ioc(db, j.job_id, "single-shared.com")

        from backend.app.services.correlation import find_ioc_matches, detect_campaigns
        matches = find_ioc_matches(db, jobs[0].job_id)
        campaigns = detect_campaigns(db, jobs[0].job_id, matches)
        # Each related job only shares 1 entity, below _MIN_CAMPAIGN_OVERLAP
        assert len(campaigns) == 0


# ===== Full Correlations =====


class TestGetCorrelations:
    """get_correlations — full aggregator"""

    def test_no_correlation_for_single_job(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, "10.0.0.1")
        _seed_ioc(db, job.job_id, "only-here.com")

        from backend.app.services.correlation import get_correlations
        result = get_correlations(db, job.job_id)
        assert result.total_matches == 0
        assert result.matches == []
        assert result.campaigns == []

    def test_scoped_by_host_param(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        _seed_host(db, job_a.job_id, "1.1.1.1")
        _seed_host(db, job_a.job_id, "2.2.2.2")
        _seed_host(db, job_b.job_id, "1.1.1.1")

        from backend.app.services.correlation import get_correlations
        result = get_correlations(db, job_a.job_id, host="1.1.1.1")
        assert result.total_matches >= 1
        for m in result.matches:
            if m.match_type == "same_host":
                assert m.matched_entity == "1.1.1.1"

    def test_scoped_by_ioc_param(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        _seed_ioc(db, job_a.job_id, "target-ioc.com")
        _seed_ioc(db, job_a.job_id, "other-ioc.com")
        _seed_ioc(db, job_b.job_id, "target-ioc.com")

        from backend.app.services.correlation import get_correlations
        result = get_correlations(db, job_a.job_id, ioc="target-ioc.com")
        assert result.total_matches >= 1
        ioc_matches = [m for m in result.matches if m.match_type == "same_ioc"]
        assert all(m.matched_entity == "target-ioc.com" for m in ioc_matches)


# ===== Related Jobs =====


class TestRelatedJobs:
    """get_related_jobs"""

    def test_related_jobs_via_hosts(self, app_client):
        client, db = app_client
        job_a = _seed_job(db, job_name="Job A")
        job_b = _seed_job(db, job_name="Job B")
        _seed_host(db, job_a.job_id, "192.168.1.1")
        _seed_host(db, job_b.job_id, "192.168.1.1")

        from backend.app.services.correlation import get_related_jobs
        result = get_related_jobs(db, job_a.job_id)
        assert len(result.related_jobs) == 1
        rj = result.related_jobs[0]
        assert rj.job_id == job_b.job_id
        assert rj.overlap_type == "shared_hosts"
        assert "192.168.1.1" in rj.shared_entities

    def test_related_jobs_via_iocs(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        _seed_ioc(db, job_a.job_id, "malicious.domain")
        _seed_ioc(db, job_b.job_id, "malicious.domain")

        from backend.app.services.correlation import get_related_jobs
        result = get_related_jobs(db, job_a.job_id)
        assert len(result.related_jobs) == 1
        rj = result.related_jobs[0]
        assert rj.overlap_type == "shared_iocs"

    def test_related_jobs_via_mitre(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        _seed_finding(db, job_a.job_id, category="Lateral Movement")
        _seed_finding(db, job_b.job_id, category="Lateral Movement")

        from backend.app.services.correlation import get_related_jobs
        result = get_related_jobs(db, job_a.job_id)
        assert len(result.related_jobs) >= 1
        rj = result.related_jobs[0]
        assert rj.overlap_type == "shared_mitre"

    def test_no_related_for_isolated_job(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_host(db, job.job_id, "unique-ip-99.99.99.99")

        from backend.app.services.correlation import get_related_jobs
        result = get_related_jobs(db, job.job_id)
        assert len(result.related_jobs) == 0


# ===== API Endpoint Tests =====


class TestCorrelationAPI:
    """GET /jobs/{job_id}/correlations"""

    def test_correlation_endpoint_returns_matches(self, app_client):
        client, db = app_client
        job_a = _seed_job(db, job_name="API Job A")
        job_b = _seed_job(db, job_name="API Job B")
        _seed_host(db, job_a.job_id, "10.0.0.50", alert_count=2)
        _seed_host(db, job_b.job_id, "10.0.0.50", alert_count=3)

        r = client.get(f"/api/v1/jobs/{job_a.job_id}/correlations", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert "matches" in data
        assert "campaigns" in data
        assert data["total_matches"] >= 1
        assert data["query"]["job_id"] == job_a.job_id

    def test_correlation_by_host(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        _seed_host(db, job_a.job_id, "5.5.5.5")
        _seed_host(db, job_b.job_id, "5.5.5.5")

        r = client.get(f"/api/v1/jobs/{job_a.job_id}/correlations?host=5.5.5.5", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["total_matches"] >= 1
        assert data["query"]["host"] == "5.5.5.5"

    def test_correlation_by_ioc(self, app_client):
        client, db = app_client
        job_a = _seed_job(db)
        job_b = _seed_job(db)
        _seed_ioc(db, job_a.job_id, "api-test-ioc.com")
        _seed_ioc(db, job_b.job_id, "api-test-ioc.com")

        r = client.get(f"/api/v1/jobs/{job_a.job_id}/correlations?ioc=api-test-ioc.com", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["total_matches"] >= 1
        assert data["query"]["ioc"] == "api-test-ioc.com"

    def test_empty_correlation_response(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/correlations", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["total_matches"] == 0
        assert data["matches"] == []


class TestRelatedJobsAPI:
    """GET /jobs/{job_id}/related-jobs"""

    def test_related_jobs_endpoint(self, app_client):
        client, db = app_client
        job_a = _seed_job(db, job_name="RJ API A")
        job_b = _seed_job(db, job_name="RJ API B")
        _seed_host(db, job_a.job_id, "172.16.0.1")
        _seed_host(db, job_b.job_id, "172.16.0.1")

        r = client.get(f"/api/v1/jobs/{job_a.job_id}/related-jobs", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["job_id"] == job_a.job_id
        assert len(data["related_jobs"]) >= 1
        rj = data["related_jobs"][0]
        assert rj["job_id"] == job_b.job_id
        assert "shared_entities" in rj
        assert "relevance_score" in rj

    def test_empty_related_jobs(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.get(f"/api/v1/jobs/{job.job_id}/related-jobs", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["related_jobs"] == []

