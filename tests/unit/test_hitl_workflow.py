"""Sprint 4 tests — HITL Review Workflow.

Covers:
  - Investigation queue status transitions (PATCH)
  - Bulk status updates (POST)
  - Review queue endpoint (GET)
  - Forensic Memory confirmation gate
  - reviewer_id propagation
"""

import uuid
from datetime import datetime, timezone

import pytest

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


# ===== Status Transition Tests =====


class TestStatusUpdate:
    """PATCH /jobs/{jobId}/investigation-queue/{itemId}/status"""

    def test_update_finding_status_to_confirmed(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        finding = _seed_finding(db, job.job_id)
        item_id = f"finding:{finding.finding_id}"

        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/{item_id}/status",
            json={"analyst_status": "confirmed", "analyst_notes": "True positive", "reviewer_id": "analyst-1"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["analyst_status"] == "confirmed"
        assert data["analyst_notes"] == "True positive"
        assert data["reviewer_id"] == "analyst-1"
        assert data["reviewed_at"] is not None

    def test_update_alert_status_to_false_positive(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        alert = _seed_alert(db, job.job_id)
        item_id = f"alert:{alert.alert_id}"

        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/{item_id}/status",
            json={"analyst_status": "false_positive"},
            headers=AUTH,
        )
        assert r.status_code == 200
        assert r.json()["analyst_status"] == "false_positive"

    def test_update_theory_status_to_needs_review(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        theory = _seed_theory(db, job.job_id)
        item_id = f"theory:{theory.theory_id}"

        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/{item_id}/status",
            json={"analyst_status": "needs_review", "reviewer_id": "analyst-2"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["analyst_status"] == "needs_review"
        assert data["reviewer_id"] == "analyst-2"

    def test_invalid_item_id_returns_400(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/badformat/status",
            json={"analyst_status": "confirmed"},
            headers=AUTH,
        )
        assert r.status_code == 400


    def test_status_persists_in_db(self, app_client):
        """Verify DB row is updated after status change."""
        client, db = app_client
        job = _seed_job(db)
        finding = _seed_finding(db, job.job_id)
        item_id = f"finding:{finding.finding_id}"

        client.patch(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/{item_id}/status",
            json={"analyst_status": "confirmed", "reviewer_id": "analyst-1"},
            headers=AUTH,
        )

        # Re-fetch from DB
        from backend.app.models.finding import Finding
        db.expire_all()
        row = db.query(Finding).filter_by(finding_id=finding.finding_id).first()
        assert row.analyst_status == "confirmed"
        assert row.reviewer_id == "analyst-1"
        assert row.reviewed_at is not None


# ===== Bulk Status Update Tests =====


class TestBulkStatusUpdate:
    """POST /jobs/{jobId}/investigation-queue/bulk-status"""

    def test_bulk_confirm_multiple_items(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        f1 = _seed_finding(db, job.job_id)
        f2 = _seed_finding(db, job.job_id)
        a1 = _seed_alert(db, job.job_id)

        item_ids = [f"finding:{f1.finding_id}", f"finding:{f2.finding_id}", f"alert:{a1.alert_id}"]

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/bulk-status",
            json={"item_ids": item_ids, "analyst_status": "confirmed", "reviewer_id": "bulk-analyst"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["updated"]) == 3
        assert len(data["failed"]) == 0

    def test_bulk_with_invalid_ids(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        f1 = _seed_finding(db, job.job_id)

        item_ids = [f"finding:{f1.finding_id}", f"finding:{_uuid()}"]

        r = client.post(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/bulk-status",
            json={"item_ids": item_ids, "analyst_status": "false_positive"},
            headers=AUTH,
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["updated"]) == 1
        assert len(data["failed"]) == 1


# ===== Review Queue Tests =====


class TestReviewQueue:
    """GET /jobs/{jobId}/review-queue"""

    def test_review_queue_returns_stats(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        f1 = _seed_finding(db, job.job_id, analyst_status="confirmed")
        f2 = _seed_finding(db, job.job_id, analyst_status="unreviewed")
        f3 = _seed_finding(db, job.job_id, analyst_status="needs_review")

        r = client.get(f"/api/v1/jobs/{job.job_id}/review-queue", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert "stats" in data
        assert "items" in data
        stats = data["stats"]
        assert stats["total"] >= 3
        assert stats["confirmed"] >= 1
        assert stats["needs_review"] >= 1

    def test_review_queue_404_for_bad_job(self, app_client):
        client, db = app_client
        r = client.get(f"/api/v1/jobs/{_uuid()}/review-queue", headers=AUTH)
        assert r.status_code == 404


# ===== Investigation Queue Summary Tests =====


class TestInvestigationQueueSummary:
    """Verify summary bar counts reflect statuses correctly."""

    def test_summary_counts(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        _seed_finding(db, job.job_id, analyst_status="confirmed")
        _seed_finding(db, job.job_id, analyst_status="confirmed")
        _seed_finding(db, job.job_id, analyst_status="false_positive")
        _seed_finding(db, job.job_id, analyst_status="unreviewed")
        _seed_alert(db, job.job_id, analyst_status="needs_review")

        r = client.get(f"/api/v1/jobs/{job.job_id}/investigation-queue", headers=AUTH)
        assert r.status_code == 200
        summary = r.json()["summary"]
        assert summary["total"] == 5
        assert summary["confirmed"] == 2
        assert summary["false_positive"] == 1
        assert summary["unreviewed"] == 1
        assert summary["needs_review"] == 1
        # review_rate = (total - unreviewed) / total = 4/5 = 0.8
        assert abs(summary["review_rate"] - 0.8) < 0.01


# ===== Forensic Memory Confirmation Gate =====


class TestForensicMemoryGate:
    """Verify that only confirmed findings are indexed into forensic memory."""

    def test_only_confirmed_findings_indexed(self):
        from backend.app.forensic_memory import store_findings

        findings = [
            {"title": "C2 Beacon", "analyst_status": "confirmed", "severity": "high", "confidence_score": 0.9},
            {"title": "DNS Exfil", "analyst_status": "unreviewed", "severity": "medium", "confidence_score": 0.7},
            {"title": "Lateral Move", "analyst_status": "false_positive", "severity": "high", "confidence_score": 0.6},
            {"title": "Crypto Mining", "analyst_status": "confirmed", "severity": "low", "confidence_score": 0.5},
        ]

        # store_findings should only index the 2 confirmed ones
        # We mock the collection to avoid needing ChromaDB
        from unittest.mock import MagicMock, patch

        mock_collection = MagicMock()
        mock_collection.count.return_value = 0

        with patch("backend.app.forensic_memory.get_memory_collection", return_value=mock_collection):
            count = store_findings("job-test", "proj-test", findings)

        assert count == 2
        assert mock_collection.upsert.call_count == 2

    def test_no_confirmed_findings_returns_zero(self):
        from backend.app.forensic_memory import store_findings
        from unittest.mock import MagicMock, patch

        findings = [
            {"title": "FP1", "analyst_status": "false_positive"},
            {"title": "Unrev", "analyst_status": "unreviewed"},
        ]

        mock_collection = MagicMock()
        with patch("backend.app.forensic_memory.get_memory_collection", return_value=mock_collection):
            count = store_findings("job-test", "proj-test", findings)

        assert count == 0
        assert mock_collection.upsert.call_count == 0

    def test_empty_findings_list(self):
        from backend.app.forensic_memory import store_findings
        from unittest.mock import MagicMock, patch

        mock_collection = MagicMock()
        with patch("backend.app.forensic_memory.get_memory_collection", return_value=mock_collection):
            count = store_findings("job-test", "proj-test", [])

        assert count == 0

    def test_nonexistent_item_returns_404(self, app_client):
        client, db = app_client
        job = _seed_job(db)
        r = client.patch(
            f"/api/v1/jobs/{job.job_id}/investigation-queue/finding:{_uuid()}/status",
            json={"analyst_status": "confirmed"},
            headers=AUTH,
        )
        assert r.status_code == 404

