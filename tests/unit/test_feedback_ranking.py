"""Sprint 7 tests — Feedback-Driven Ranking & Noise Reduction.

Covers:
  - Sensor trust computation
  - Signature noise detection
  - Ranking adjustments (sensor & signature)
  - Feedback-adjusted rank_score formula
  - Overall stats aggregation
  - Daily review time-series
  - Admin feedback-metrics API endpoint
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
        job_id=jid, job_name="Test Job", status="completed",
        execution_profile="standard", priority="normal",
        pcap_filename="test.pcap", pcap_size_bytes=1024, pcap_sha256="abc",
        created_at=_now(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _seed_finding(db, job_id, **kwargs):
    from backend.app.models.finding import Finding
    payload = {
        "job_id": job_id, "finding_id": _uuid(),
        "sensor": "suricata", "severity": "high",
        "title": "Suspicious traffic", "summary": "Test finding",
        "confidence": 0.8,
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
        "engine": "suricata",
    }
    payload.update(kwargs)
    a = Alert(**payload)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _seed_theory(db, job_id, **kwargs):
    from backend.app.models.theory import Theory
    payload = {
        "job_id": job_id, "theory_id": _uuid(),
        "hypothesis_type": "c2_beacon", "label": "C2 beacon test",
        "explanation": "Test theory", "score": 0.8,
        "created_at": _now(),
    }
    payload.update(kwargs)
    t = Theory(**payload)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


# ===== Sensor Trust Tests =====


class TestSensorTrust:
    """compute_sensor_trust aggregation."""

    def test_single_sensor_all_confirmed(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        for _ in range(5):
            _seed_finding(db, job.job_id, sensor="zeek", analyst_status="confirmed",
                          reviewed_at=_now())
        from backend.app.services.feedback_analytics import compute_sensor_trust
        profiles = compute_sensor_trust(db)
        zeek = [p for p in profiles if p.sensor_name == "zeek"]
        assert len(zeek) == 1
        assert zeek[0].confirmed == 5
        assert zeek[0].false_positive == 0
        assert zeek[0].confirmation_rate == 1.0

    def test_mixed_sensors(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        # suricata: 3 confirmed, 2 FP
        for _ in range(3):
            _seed_finding(db, job.job_id, sensor="suricata", analyst_status="confirmed",
                          reviewed_at=_now())
        for _ in range(2):
            _seed_finding(db, job.job_id, sensor="suricata", analyst_status="false_positive",
                          reviewed_at=_now())
        # zeek: 1 confirmed, 4 FP
        for _ in range(1):
            _seed_finding(db, job.job_id, sensor="zeek", analyst_status="confirmed",
                          reviewed_at=_now())
        for _ in range(4):
            _seed_finding(db, job.job_id, sensor="zeek", analyst_status="false_positive",
                          reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_sensor_trust
        profiles = compute_sensor_trust(db)
        sur = [p for p in profiles if p.sensor_name == "suricata"][0]
        zeek = [p for p in profiles if p.sensor_name == "zeek"][0]
        assert sur.confirmation_rate == 0.6  # 3/5
        assert zeek.confirmation_rate == 0.2  # 1/5

    def test_alerts_count_as_sensor(self, app_client):
        """Alert.engine is treated as a sensor for trust purposes."""
        client, db = app_client
        job = _seed_job(db)
        for _ in range(4):
            _seed_alert(db, job.job_id, engine="snort", analyst_status="confirmed",
                        reviewed_at=_now())
        _seed_alert(db, job.job_id, engine="snort", analyst_status="false_positive",
                    reviewed_at=_now())
        from backend.app.services.feedback_analytics import compute_sensor_trust
        profiles = compute_sensor_trust(db)
        snort = [p for p in profiles if p.sensor_name == "snort"]
        assert len(snort) == 1
        assert snort[0].confirmation_rate == 0.8  # 4/5


# ===== Signature Noise Tests =====


class TestSignatureNoise:
    """compute_signature_noise detection."""

    def test_noisy_signature_detected(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        # Signature with 4 FP and 1 confirmed = 80% FP rate
        for _ in range(4):
            _seed_alert(db, job.job_id, signature="ET INFO Bogus Alert",
                        analyst_status="false_positive", reviewed_at=_now())
        _seed_alert(db, job.job_id, signature="ET INFO Bogus Alert",
                    analyst_status="confirmed", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_signature_noise
        noisy = compute_signature_noise(db)
        assert len(noisy) >= 1
        bogus = [n for n in noisy if n.signature_name == "ET INFO Bogus Alert"]
        assert len(bogus) == 1
        assert bogus[0].false_positive_rate == 0.8
        assert bogus[0].false_positive_count == 4

    def test_below_threshold_not_returned(self, app_client):
        """Signatures with fewer than _MIN_REVIEWED reviews are excluded."""
        client, db = app_client
        job = _seed_job(db)
        # Only 2 reviews (below threshold of 3)
        _seed_alert(db, job.job_id, signature="Rare Alert",
                    analyst_status="false_positive", reviewed_at=_now())
        _seed_alert(db, job.job_id, signature="Rare Alert",
                    analyst_status="confirmed", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_signature_noise
        noisy = compute_signature_noise(db)
        rare = [n for n in noisy if n.signature_name == "Rare Alert"]
        assert len(rare) == 0

    def test_no_alerts(self, app_client):
        client, db = app_client
        from backend.app.services.feedback_analytics import compute_signature_noise
        assert compute_signature_noise(db) == []


# ===== Ranking Adjustment Tests =====


class TestRankingAdjustments:
    """compute_ranking_adjustments and compute_signature_adjustments."""

    def test_high_trust_sensor_gets_positive_adjustment(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        for _ in range(5):
            _seed_finding(db, job.job_id, sensor="trusted_sensor",
                          analyst_status="confirmed", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_ranking_adjustments
        adj = compute_ranking_adjustments(db)
        assert adj["trusted_sensor"] == 0.5  # 100% confirm → +0.5

    def test_noisy_sensor_gets_negative_adjustment(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        for _ in range(5):
            _seed_finding(db, job.job_id, sensor="noisy_sensor",
                          analyst_status="false_positive", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_ranking_adjustments
        adj = compute_ranking_adjustments(db)
        assert adj["noisy_sensor"] == -0.5  # 0% confirm → -0.5

    def test_insufficient_reviews_neutral(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, sensor="new_sensor",
                      analyst_status="confirmed", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_ranking_adjustments
        adj = compute_ranking_adjustments(db)
        assert adj["new_sensor"] == 0.0

    def test_signature_penalty(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        for _ in range(4):
            _seed_alert(db, job.job_id, signature="Noisy Sig",
                        analyst_status="false_positive", reviewed_at=_now())
        _seed_alert(db, job.job_id, signature="Noisy Sig",
                    analyst_status="confirmed", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_signature_adjustments
        adj = compute_signature_adjustments(db)
        assert "Noisy Sig" in adj
        assert adj["Noisy Sig"] < 0  # Should be negative penalty

    def test_empty_db_adjustments(self, app_client):
        client, db = app_client
        from backend.app.services.feedback_analytics import compute_ranking_adjustments
        assert compute_ranking_adjustments(db) == {}


# ===== Rank Score Formula Tests =====


class TestRankScoreFormula:
    """compute_rank_score with feedback_adj parameter."""

    def test_default_feedback_neutral(self):
        from backend.app.services.ranking import compute_rank_score
        # Default feedback_adj=0.5 should give 10% * 0.5 = 0.05 contribution
        score = compute_rank_score("critical", 1.0, 1.0, 1.0, 1.0)
        # All maxed: 0.25*1 + 0.20*1 + 0.20*1 + 0.15*1 + 0.10*1 + 0.10*0.5 = 0.95
        assert abs(score - 0.95) < 0.01

    def test_max_feedback_boost(self):
        from backend.app.services.ranking import compute_rank_score
        score = compute_rank_score("critical", 1.0, 1.0, 1.0, 1.0, feedback_adj=1.0)
        # 0.25 + 0.20 + 0.20 + 0.15 + 0.10 + 0.10 = 1.0
        assert abs(score - 1.0) < 0.01

    def test_zero_feedback_penalty(self):
        from backend.app.services.ranking import compute_rank_score
        score = compute_rank_score("critical", 1.0, 1.0, 1.0, 1.0, feedback_adj=0.0)
        # 0.25 + 0.20 + 0.20 + 0.15 + 0.10 + 0.0 = 0.90
        assert abs(score - 0.90) < 0.01

    def test_feedback_adj_clamped(self):
        from backend.app.services.ranking import compute_rank_score
        # Even with feedback_adj > 1.0, should be clamped
        score_high = compute_rank_score("info", 0.0, 0.0, 0.0, 0.0, feedback_adj=2.0)
        score_max = compute_rank_score("info", 0.0, 0.0, 0.0, 0.0, feedback_adj=1.0)
        assert score_high == score_max


class TestComputeFeedbackAdjustment:
    """compute_feedback_adjustment helper."""

    def test_neutral_when_no_data(self):
        from backend.app.services.ranking import compute_feedback_adjustment
        result = compute_feedback_adjustment(None, None, None)
        assert abs(result - 0.5) < 0.01  # All neutral

    def test_trusted_sensor_boosts(self):
        from backend.app.services.ranking import compute_feedback_adjustment
        result = compute_feedback_adjustment(
            sensor="suricata", signature=None, category=None,
            sensor_adjustments={"suricata": 0.5},
        )
        # sensor_factor = 0.5 + 0.5 = 1.0
        # 50%*1.0 + 30%*0.5 + 20%*0.5 = 0.5 + 0.15 + 0.1 = 0.75
        assert abs(result - 0.75) < 0.01

    def test_noisy_signature_penalizes(self):
        from backend.app.services.ranking import compute_feedback_adjustment
        result = compute_feedback_adjustment(
            sensor=None, signature="ET BAD SIG", category=None,
            signature_adjustments={"ET BAD SIG": -0.4},
        )
        # sig_factor = 0.5 + (-0.4) = 0.1
        # 50%*0.5 + 30%*0.1 + 20%*0.5 = 0.25 + 0.03 + 0.1 = 0.38
        assert abs(result - 0.38) < 0.01


# ===== Overall Stats Tests =====


class TestOverallStats:
    """compute_overall_stats aggregation."""

    def test_stats_across_all_types(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, analyst_status="confirmed", reviewed_at=_now())
        _seed_finding(db, job.job_id, analyst_status="false_positive", reviewed_at=_now())
        _seed_alert(db, job.job_id, analyst_status="confirmed", reviewed_at=_now())
        _seed_theory(db, job.job_id, analyst_status="confirmed", reviewed_at=_now())

        from backend.app.services.feedback_analytics import compute_overall_stats
        stats = compute_overall_stats(db)
        assert stats.total_items == 4
        assert stats.total_reviewed == 4  # 3 confirmed + 1 FP
        assert stats.confirmation_rate == 0.75  # 3/4

    def test_empty_stats(self, app_client):
        client, db = app_client
        from backend.app.services.feedback_analytics import compute_overall_stats
        stats = compute_overall_stats(db)
        assert stats.total_items == 0
        assert stats.total_reviewed == 0
        assert stats.confirmation_rate == 0.0


# ===== Daily Reviews Tests =====


class TestDailyReviews:
    """compute_daily_reviews time-series."""

    def test_groups_by_date(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, analyst_status="confirmed",
                      reviewed_at="2025-06-01T10:00:00Z")
        _seed_finding(db, job.job_id, analyst_status="false_positive",
                      reviewed_at="2025-06-01T11:00:00Z")
        _seed_finding(db, job.job_id, analyst_status="confirmed",
                      reviewed_at="2025-06-02T09:00:00Z")

        from backend.app.services.feedback_analytics import compute_daily_reviews
        daily = compute_daily_reviews(db)
        assert len(daily) == 2
        day1 = [d for d in daily if d.date == "2025-06-01"][0]
        assert day1.confirmed == 1
        assert day1.false_positive == 1
        day2 = [d for d in daily if d.date == "2025-06-02"][0]
        assert day2.confirmed == 1

    def test_empty_reviews(self, app_client):
        client, db = app_client
        from backend.app.services.feedback_analytics import compute_daily_reviews
        assert compute_daily_reviews(db) == []



# ===== Admin API Endpoint Tests =====


class TestAdminFeedbackAPI:
    """GET /admin/feedback-metrics endpoint."""

    def test_empty_response(self, app_client):
        client, db = app_client
        r = client.get("/api/v1/admin/feedback-metrics", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["sensor_trust"] == []
        assert data["noisy_signatures"] == []
        assert data["overall_stats"]["total_items"] == 0
        assert data["time_series"]["daily_reviews"] == []

    def test_populated_response(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        for _ in range(4):
            _seed_finding(db, job.job_id, sensor="zeek", analyst_status="confirmed",
                          reviewed_at="2025-06-01T12:00:00Z")
        _seed_finding(db, job.job_id, sensor="zeek", analyst_status="false_positive",
                      reviewed_at="2025-06-01T12:00:00Z")
        for _ in range(3):
            _seed_alert(db, job.job_id, signature="Noisy Sig", engine="suricata",
                        analyst_status="false_positive", reviewed_at="2025-06-02T10:00:00Z")
        _seed_alert(db, job.job_id, signature="Good Sig", engine="suricata",
                    analyst_status="confirmed", reviewed_at="2025-06-02T10:00:00Z")

        r = client.get("/api/v1/admin/feedback-metrics", headers=AUTH)
        assert r.status_code == 200
        data = r.json()

        # Sensor trust
        assert len(data["sensor_trust"]) >= 1
        sensors = {s["sensor_name"] for s in data["sensor_trust"]}
        assert "zeek" in sensors
        assert "suricata" in sensors

        # Overall stats
        assert data["overall_stats"]["total_items"] == 9
        assert data["overall_stats"]["total_reviewed"] == 9

        # Time series
        assert len(data["time_series"]["daily_reviews"]) >= 1

    def test_response_schema_structure(self, app_client):
        """Verify the response has the expected top-level keys."""
        client, db = app_client
        r = client.get("/api/v1/admin/feedback-metrics", headers=AUTH)
        data = r.json()
        assert "sensor_trust" in data
        assert "noisy_signatures" in data
        assert "overall_stats" in data
        assert "time_series" in data
        # overall_stats subfields
        stats = data["overall_stats"]
        assert "total_reviewed" in stats
        assert "total_items" in stats
        assert "confirmation_rate" in stats
        assert "false_positive_rate" in stats
        assert "most_trusted_sensor" in stats
        assert "noisiest_sensor" in stats


# ===== Integration: Ranking with Feedback =====


class TestRankingIntegration:
    """Verify feedback adjustments flow through to build_investigation_queue."""

    def test_trusted_sensor_items_rank_higher(self, app_client):
        """Items from a trusted sensor should rank higher than a noisy one."""
        client, db = app_client
        job = _seed_job(db)

        # Build trust: trusted_sensor gets 5 confirms
        for _ in range(5):
            _seed_finding(db, job.job_id, sensor="trusted_sensor",
                          analyst_status="confirmed", reviewed_at=_now(),
                          title="Old confirmed", severity="medium")
        # Build distrust: noisy_sensor gets 5 FPs
        for _ in range(5):
            _seed_finding(db, job.job_id, sensor="noisy_sensor",
                          analyst_status="false_positive", reviewed_at=_now(),
                          title="Old FP", severity="medium")

        # Now create two NEW unreviewed items — same severity/confidence
        _seed_finding(db, job.job_id, sensor="trusted_sensor",
                      severity="medium", confidence=0.5,
                      title="Trusted finding")
        _seed_finding(db, job.job_id, sensor="noisy_sensor",
                      severity="medium", confidence=0.5,
                      title="Noisy finding")

        from backend.app.services.ranking import build_investigation_queue
        items, summary = build_investigation_queue(db, job.job_id)

        # Find our two items
        trusted_queue = [i for i in items if i.title == "Trusted finding"]
        noisy_queue = [i for i in items if i.title == "Noisy finding"]
        assert len(trusted_queue) == 1
        assert len(noisy_queue) == 1

        # Trusted sensor item should have higher rank_score
        assert trusted_queue[0].rank_score > noisy_queue[0].rank_score

