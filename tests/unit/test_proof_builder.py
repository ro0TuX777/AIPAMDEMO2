"""Tests for Phase 2B — Proof Builder service, API, and chat bundle."""

import json
import uuid
from datetime import datetime, timezone

import pytest

from backend.app.models.alert import Alert
from backend.app.models.finding import Finding
from backend.app.models.host import Host
from backend.app.models.ioc import Ioc
from backend.app.models.job import Job
from backend.app.models.theory import Theory
from backend.app.services.proof_builder import (
    add_item,
    create_proof,
    delete_proof,
    export_proof,
    get_proof,
    list_items,
    list_proofs,
    remove_item,
    render_narrative,
    update_item,
    update_proof,
    proof_summary,
    _resolve_entity,
)

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def rich_job(db_session, sample_job, sample_host):
    """Populate a job with a few evidence entities for proof testing."""
    jid = sample_job.job_id

    db_session.add(Alert(
        job_id=jid, alert_id="A-001", host_ip="10.0.0.5",
        severity="high", signature="ET MALWARE CobaltStrike",
        community_id="1:abc", category="malware", ts=_now(),
    ))

    db_session.add(Finding(
        job_id=jid, finding_id="F-001", sensor="suricata",
        severity="critical", title="C2 Beaconing Detected",
        community_id="1:abc", confidence=0.9,
    ))

    db_session.add(Ioc(
        job_id=jid, ioc_id="IOC-001", ioc_type="ip",
        value="10.0.0.5", severity="high", confidence=0.85,
    ))

    db_session.add(Theory(
        job_id=jid, theory_id="TH-001", label="C2 Hypothesis",
        hypothesis_type="c2", score=0.85, confidence="high",
        scope_type="host", scope_id="10.0.0.5",
        supporting_evidence_json=json.dumps(["F-001", "A-001"]),
        rank=1, created_at=_now(),
    ))

    db_session.commit()
    return sample_job


# ---------------------------------------------------------------------------
# Unit: _resolve_entity
# ---------------------------------------------------------------------------


class TestResolveEntity:
    def test_resolve_host(self, db_session, rich_job):
        label, sev = _resolve_entity(db_session, "host", "10.0.0.5")
        assert label == "10.0.0.5"

    def test_resolve_alert(self, db_session, rich_job):
        label, sev = _resolve_entity(db_session, "alert", "A-001")
        assert "CobaltStrike" in label
        assert sev == "high"

    def test_resolve_finding(self, db_session, rich_job):
        label, sev = _resolve_entity(db_session, "finding", "F-001")
        assert "C2 Beaconing" in label
        assert sev == "critical"

    def test_resolve_unknown_type(self, db_session):
        label, sev = _resolve_entity(db_session, "bogus", "X-1")
        assert label == "X-1"
        assert sev == "info"

    def test_resolve_missing_entity(self, db_session):
        label, sev = _resolve_entity(db_session, "alert", "NONEXISTENT")
        assert label == "NONEXISTENT"
        assert sev == "info"


# ---------------------------------------------------------------------------
# Unit: CRUD operations
# ---------------------------------------------------------------------------


class TestProofCRUD:
    def test_create_proof(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="C2 Proof")
        assert p.proof_id.startswith("PRF-")
        assert p.title == "C2 Proof"
        assert p.status == "draft"
        assert p.item_count == 0

    def test_create_proof_invalid_job(self, db_session):
        with pytest.raises(ValueError, match="not found"):
            create_proof(db_session, "nonexistent", title="Fail")

    def test_update_proof(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Draft")
        p2 = update_proof(db_session, p.proof_id, title="Final Title",
                          status="final", confidence=0.9)
        assert p2.title == "Final Title"
        assert p2.status == "final"
        assert p2.confidence == 0.9

    def test_delete_proof(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="To delete")
        delete_proof(db_session, p.proof_id)
        assert get_proof(db_session, p.proof_id) is None

    def test_list_proofs(self, db_session, rich_job):
        create_proof(db_session, rich_job.job_id, title="P1")
        create_proof(db_session, rich_job.job_id, title="P2")
        proofs = list_proofs(db_session, rich_job.job_id)
        assert len(proofs) == 2




# ---------------------------------------------------------------------------
# Unit: Item management
# ---------------------------------------------------------------------------


class TestProofItems:
    def test_add_item(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        item = add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        assert item.item_id.startswith("PI-")
        assert item.entity_type == "alert"
        assert item.role == "supports"
        assert "CobaltStrike" in item.label
        assert item.severity == "high"
        # Proof item_count incremented
        p2 = get_proof(db_session, p.proof_id)
        assert p2.item_count == 1

    def test_add_item_contradicts(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        item = add_item(db_session, p.proof_id, entity_type="finding", entity_id="F-001",
                        role="contradicts", analyst_note="Maybe false positive")
        assert item.role == "contradicts"
        assert item.analyst_note == "Maybe false positive"

    def test_add_item_invalid_type(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        with pytest.raises(ValueError, match="Invalid entity_type"):
            add_item(db_session, p.proof_id, entity_type="bogus", entity_id="X")

    def test_add_item_invalid_role(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        with pytest.raises(ValueError, match="Invalid role"):
            add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001",
                     role="unknown")

    def test_remove_item(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        item = add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        remove_item(db_session, item.item_id)
        assert len(list_items(db_session, p.proof_id)) == 0
        p2 = get_proof(db_session, p.proof_id)
        assert p2.item_count == 0

    def test_update_item(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        item = add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        updated = update_item(db_session, item.item_id, role="context",
                              analyst_note="Updated note")
        assert updated.role == "context"
        assert updated.analyst_note == "Updated note"

    def test_item_ordering(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Test")
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        add_item(db_session, p.proof_id, entity_type="finding", entity_id="F-001")
        items = list_items(db_session, p.proof_id)
        assert items[0].order < items[1].order


# ---------------------------------------------------------------------------
# Unit: Narrative rendering
# ---------------------------------------------------------------------------


class TestNarrative:
    def test_render_narrative(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="C2 Proof",
                         conclusion="Host was compromised")
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001",
                 role="supports")
        add_item(db_session, p.proof_id, entity_type="finding", entity_id="F-001",
                 role="supports", analyst_note="High confidence beacon")
        add_item(db_session, p.proof_id, entity_type="ioc", entity_id="IOC-001",
                 role="context")

        result = render_narrative(db_session, p.proof_id)
        assert isinstance(result, dict)
        narrative = result["narrative"]
        assert "# C2 Proof" in narrative
        assert "Host was compromised" in narrative
        assert "Supporting Evidence" in narrative
        assert "Contextual Evidence" in narrative
        assert "ALERT" in narrative
        assert "IOC" in narrative
        # Persisted
        p2 = get_proof(db_session, p.proof_id)
        assert p2.narrative_markdown == narrative

    def test_render_empty_proof(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Empty")
        result = render_narrative(db_session, p.proof_id)
        narrative = result["narrative"]
        assert "# Empty" in narrative
        assert "Supporting Evidence" not in narrative

    def test_render_returns_warnings_for_unconfirmed(self, db_session, rich_job):
        """Unconfirmed evidence items should produce warnings."""
        p = create_proof(db_session, rich_job.job_id, title="Warn Test")
        # Alert A-001 has analyst_status=None (unreviewed default)
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        result = render_narrative(db_session, p.proof_id)
        assert "warnings" in result
        # Should warn about unconfirmed items
        assert any("not yet confirmed" in w for w in result["warnings"])

    def test_render_no_warnings_for_confirmed(self, db_session, rich_job):
        """Confirmed evidence should not produce warnings."""
        # Set alert as confirmed
        from backend.app.models.alert import Alert
        alert = db_session.query(Alert).filter_by(alert_id="A-001").first()
        alert.analyst_status = "confirmed"
        db_session.commit()

        p = create_proof(db_session, rich_job.job_id, title="No Warn")
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        result = render_narrative(db_session, p.proof_id)
        assert not any("not yet confirmed" in w for w in result.get("warnings", []))

    def test_render_warns_empty_items(self, db_session, rich_job):
        """A proof with no items should warn."""
        p = create_proof(db_session, rich_job.job_id, title="Empty Warn")
        result = render_narrative(db_session, p.proof_id)
        assert any("No evidence" in w for w in result.get("warnings", []))

    def test_mode_is_used_in_create(self, db_session, rich_job):
        """Verify mode parameter is stored."""
        for mode in ["soc_handoff", "ir_technical", "executive_summary"]:
            p = create_proof(db_session, rich_job.job_id, title=f"Mode {mode}", mode=mode)
            assert p.mode == mode


# ---------------------------------------------------------------------------
# Unit: Export
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_markdown(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="Export Test",
                         conclusion="Confirmed C2")
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        # Generate narrative first
        render_narrative(db_session, p.proof_id)

        result = export_proof(db_session, p.proof_id, fmt="markdown")
        assert "content" in result
        assert "filename" in result
        assert result["filename"].endswith(".md")
        assert "# Export Test" in result["content"]

    def test_export_html(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="HTML Export")
        render_narrative(db_session, p.proof_id)

        result = export_proof(db_session, p.proof_id, fmt="html")
        assert result["filename"].endswith(".html")
        assert "<h" in result["content"] or "<p" in result["content"] or "HTML Export" in result["content"]

    def test_export_auto_generates_narrative(self, db_session, rich_job):
        """Export should generate narrative if not yet rendered."""
        p = create_proof(db_session, rich_job.job_id, title="Auto Gen")
        result = export_proof(db_session, p.proof_id, fmt="markdown")
        assert len(result["content"]) > 0


# ---------------------------------------------------------------------------
# Unit: proof_summary (chat bundle)
# ---------------------------------------------------------------------------


class TestProofSummary:
    def test_summary_with_proofs(self, db_session, rich_job):
        p = create_proof(db_session, rich_job.job_id, title="C2 Proof",
                         conclusion="Confirmed C2")
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        summary = proof_summary(db_session, rich_job.job_id)
        assert "1 proof(s)" in summary
        assert "C2 Proof" in summary
        assert "Confirmed C2" in summary

    def test_summary_no_proofs(self, db_session, rich_job):
        summary = proof_summary(db_session, rich_job.job_id)
        assert "No analyst proofs" in summary


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------


class TestProofAPI:
    def test_create_and_list(self, app_client, db_session):
        client, db = app_client
        # Create a job first
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        # Create proof
        resp = client.post(
            f"/api/v1/jobs/{job.job_id}/proofs",
            json={"title": "API Proof"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["item"]["title"] == "API Proof"
        proof_id = data["item"]["proof_id"]

        # List proofs
        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs", headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 1

        # Get single proof
        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}",
                          headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json()["item"]["proof_id"] == proof_id

    def test_update_proof(self, app_client, db_session):
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "Draft"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        resp = client.patch(
            f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}",
            json={"title": "Updated", "status": "final"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200
        assert resp.json()["item"]["title"] == "Updated"
        assert resp.json()["item"]["status"] == "final"

    def test_delete_proof(self, app_client, db_session):
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "Delete me"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        resp = client.delete(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}",
                             headers=AUTH_HEADER)
        assert resp.status_code == 204

        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}",
                          headers=AUTH_HEADER)
        assert resp.status_code == 404

    def test_add_and_list_items(self, app_client, db_session):
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        # Create host + alert for label resolution
        db.add(Host(job_id=job.job_id, ip="10.0.0.1", role="internal",
                    conn_count=1, alert_count=1, finding_count=0,
                    first_seen=_now(), last_seen=_now()))
        db.add(Alert(job_id=job.job_id, alert_id="A-T1", host_ip="10.0.0.1",
                     severity="high", signature="Test alert sig",
                     community_id="1:x", category="test", ts=_now()))
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "Items test"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        # Add item
        resp = client.post(
            f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/items",
            json={"entity_type": "alert", "entity_id": "A-T1", "role": "supports"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 201
        assert resp.json()["item"]["entity_type"] == "alert"

        # List items
        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/items",
                          headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 1

    def test_render_narrative_api(self, app_client, db_session):
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "Narr test"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/narrative",
                           headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert "# Narr test" in data["narrative_markdown"]
        assert "warnings" in data
        assert isinstance(data["warnings"], list)

    def test_narrative_api_includes_warnings(self, app_client, db_session):
        """Narrative API should return warnings for empty proofs."""
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "Empty proof"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/narrative",
                           headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert any("No evidence" in w for w in resp.json()["warnings"])

    def test_export_api(self, app_client, db_session):
        """GET /jobs/{jobId}/proofs/{proofId}/export"""
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "Export API"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        # Generate narrative first
        client.post(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/narrative",
                    headers=AUTH_HEADER)

        # Export as markdown
        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/export?fmt=markdown",
                          headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert "content" in data
        assert "filename" in data
        assert data["filename"].endswith(".md")

    def test_export_html_api(self, app_client, db_session):
        """Export as HTML."""
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "HTML Export"}, headers=AUTH_HEADER)
        proof_id = resp.json()["item"]["proof_id"]

        client.post(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/narrative",
                    headers=AUTH_HEADER)

        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs/{proof_id}/export?fmt=html",
                          headers=AUTH_HEADER)
        assert resp.status_code == 200
        assert resp.json()["filename"].endswith(".html")

    def test_create_proof_with_mode(self, app_client, db_session):
        """Create proof with specific mode."""
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.post(f"/api/v1/jobs/{job.job_id}/proofs",
                           json={"title": "IR Report", "mode": "ir_technical"},
                           headers=AUTH_HEADER)
        assert resp.status_code == 201
        assert resp.json()["item"]["mode"] == "ir_technical"

    def test_proof_404(self, app_client, db_session):
        client, db = app_client
        job = Job(job_id=_uid(), job_name="test", status="completed",
                  execution_profile="standard", priority="normal",
                  pcap_filename="test.pcap", pcap_size_bytes=10000,
                  pcap_sha256="abc", created_at=_now())
        db.add(job)
        db.commit()

        resp = client.get(f"/api/v1/jobs/{job.job_id}/proofs/nonexistent",
                          headers=AUTH_HEADER)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Chat bundle integration
# ---------------------------------------------------------------------------


class TestProofBundle:
    def test_bundle_contains_summary(self, db_session, rich_job):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        p = create_proof(db_session, rich_job.job_id, title="Bundle Test")
        add_item(db_session, p.proof_id, entity_type="alert", entity_id="A-001")
        bundle = build_scoped_bundle(db_session, rich_job.job_id, "proof")
        text = bundle.to_context()
        assert "1 proof(s)" in text
        assert "Bundle Test" in text

    def test_bundle_empty(self, db_session, rich_job):
        from backend.app.services.evidence_bundles import build_scoped_bundle
        bundle = build_scoped_bundle(db_session, rich_job.job_id, "proof")
        text = bundle.to_context()
        assert "No analyst proofs" in text
