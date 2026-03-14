"""Tests for the Incident Slicer: grouping, merging, classification, API, and evidence bundles."""

import json
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.finding import Finding
from backend.app.models.ioc import Ioc
from backend.app.models.slice import IncidentSlice
from backend.app.services.slicer import (
    _ProtoSlice,
    _classify_slice,
    _compute_confidence,
    _generate_label,
    _generate_summary,
    _merge_proto_slices,
    _overall_severity,
    _parse_ts,
    _seed_from_community_ids,
    _time_overlap,
    _attach_findings,
    _attach_iocs,
    generate_slices,
)

AUTH_HEADER = {"Authorization": "Bearer test-token-v2"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ts_offset(minutes: int = 0) -> str:
    dt = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Unit: helper functions
# ---------------------------------------------------------------------------

class TestParseTs:
    def test_valid_iso(self):
        assert _parse_ts("2024-01-01T00:00:00Z") > 0

    def test_none(self):
        assert _parse_ts(None) == 0.0

    def test_invalid(self):
        assert _parse_ts("not-a-date") == 0.0


class TestTimeOverlap:
    def test_overlapping(self):
        t1 = ["2024-01-01T00:00:00Z", "2024-01-01T00:05:00Z"]
        t2 = ["2024-01-01T00:03:00Z", "2024-01-01T00:08:00Z"]
        assert _time_overlap(t1, t2, 600) is True

    def test_non_overlapping(self):
        t1 = ["2024-01-01T00:00:00Z"]
        t2 = ["2024-01-01T01:00:00Z"]
        assert _time_overlap(t1, t2, 600) is False

    def test_within_window(self):
        t1 = ["2024-01-01T00:00:00Z"]
        t2 = ["2024-01-01T00:09:00Z"]  # 9 min apart, within 10 min window
        assert _time_overlap(t1, t2, 600) is True

    def test_empty_timestamps_assumed_overlap(self):
        assert _time_overlap([], ["2024-01-01T00:00:00Z"], 600) is True


class TestClassifySlice:
    def test_c2(self):
        assert _classify_slice(["beacon detected callback"]) == "c2_session"

    def test_recon(self):
        assert _classify_slice(["port scan detected"]) == "recon_phase"

    def test_lateral(self):
        assert _classify_slice(["lateral movement via smb"]) == "lateral"

    def test_exfil(self):
        assert _classify_slice(["data exfiltration tunnel"]) == "exfil"

    def test_default(self):
        assert _classify_slice(["normal http traffic"]) == "attack_thread"


class TestOverallSeverity:
    def test_highest_wins(self):
        assert _overall_severity(["low", "critical", "medium"]) == "critical"

    def test_empty(self):
        assert _overall_severity([]) == "info"

    def test_single(self):
        assert _overall_severity(["high"]) == "high"


class TestComputeConfidence:
    def test_high_confidence(self):
        p = _ProtoSlice(community_ids={"cid1", "cid2"}, alert_ids=["a1", "a2"], finding_ids=["f1"], connection_ids=["c1"])
        assert _compute_confidence(p) == 0.9

    def test_medium_confidence(self):
        p = _ProtoSlice(community_ids={"cid1"}, alert_ids=["a1", "a2"], connection_ids=["c1"])
        assert _compute_confidence(p) == 0.7

    def test_low_confidence(self):
        p = _ProtoSlice(alert_ids=["a1"])
        assert _compute_confidence(p) == 0.3


class TestGenerateLabel:
    def test_includes_host_ips(self):
        p = _ProtoSlice(host_ips={"10.0.0.1", "10.0.0.2"}, texts=["port scan"])
        label = _generate_label(p)
        assert "10.0.0.1" in label
        assert "Reconnaissance" in label


class TestGenerateSummary:
    def test_includes_counts(self):
        p = _ProtoSlice(
            alert_ids=["a1", "a2"], finding_ids=["f1"],
            community_ids={"cid1"}, host_ips={"10.0.0.1"},
            severities=["high"],
        )
        summary = _generate_summary(p)
        assert "2 alert(s)" in summary
        assert "1 finding(s)" in summary
        assert "HIGH" in summary


# ---------------------------------------------------------------------------
# Unit: seeding and merging
# ---------------------------------------------------------------------------

class TestSeedFromCommunityIds:
    def test_groups_by_community_id(self):
        alerts = [
            Alert(job_id="j1", alert_id="A-1", host_ip="10.0.0.1", src_ip="10.0.0.1",
                  dest_ip="192.168.1.1", severity="high", signature="sig1",
                  community_id="cid-1", ts=_now()),
            Alert(job_id="j1", alert_id="A-2", host_ip="10.0.0.1", src_ip="10.0.0.1",
                  dest_ip="192.168.1.1", severity="medium", signature="sig2",
                  community_id="cid-1", ts=_now()),
            Alert(job_id="j1", alert_id="A-3", host_ip="10.0.0.2", src_ip="10.0.0.2",
                  dest_ip="192.168.1.2", severity="low", signature="sig3",
                  community_id="cid-2", ts=_now()),
        ]
        cid_map = _seed_from_community_ids(alerts, [])
        assert len(cid_map) == 2
        assert "A-1" in cid_map["cid-1"].alert_ids
        assert "A-2" in cid_map["cid-1"].alert_ids
        assert "A-3" in cid_map["cid-2"].alert_ids

    def test_includes_connections(self):
        conns = [
            Connection(job_id="j1", connection_id="C-1", community_id="cid-1",
                       host_ip="10.0.0.1", src_ip="10.0.0.1", dest_ip="192.168.1.1",
                       proto="tcp", ts=_now()),
        ]
        cid_map = _seed_from_community_ids([], conns)
        assert "cid-1" in cid_map
        assert "C-1" in cid_map["cid-1"].connection_ids

    def test_skips_none_community_id(self):
        alerts = [
            Alert(job_id="j1", alert_id="A-orphan", host_ip="10.0.0.1",
                  severity="low", signature="orphan", ts=_now()),
        ]
        cid_map = _seed_from_community_ids(alerts, [])
        assert len(cid_map) == 0


class TestMergeProtoSlices:
    def test_merges_shared_host_in_time_window(self):
        a = _ProtoSlice(
            host_ips={"10.0.0.1"}, alert_ids=["A-1"],
            timestamps=["2024-01-01T00:00:00Z"], community_ids={"cid-1"},
        )
        b = _ProtoSlice(
            host_ips={"10.0.0.1"}, alert_ids=["A-2"],
            timestamps=["2024-01-01T00:05:00Z"], community_ids={"cid-2"},
        )
        result = _merge_proto_slices([a, b])
        assert len(result) == 1
        assert "A-1" in result[0].alert_ids
        assert "A-2" in result[0].alert_ids
        assert "cid-1" in result[0].community_ids
        assert "cid-2" in result[0].community_ids

    def test_no_merge_different_hosts(self):
        a = _ProtoSlice(
            host_ips={"10.0.0.1"}, alert_ids=["A-1"],
            timestamps=["2024-01-01T00:00:00Z"],
        )
        b = _ProtoSlice(
            host_ips={"10.0.0.2"}, alert_ids=["A-2"],
            timestamps=["2024-01-01T00:05:00Z"],
        )
        result = _merge_proto_slices([a, b])
        assert len(result) == 2

    def test_no_merge_outside_time_window(self):
        a = _ProtoSlice(
            host_ips={"10.0.0.1"}, alert_ids=["A-1"],
            timestamps=["2024-01-01T00:00:00Z"],
        )
        b = _ProtoSlice(
            host_ips={"10.0.0.1"}, alert_ids=["A-2"],
            timestamps=["2024-01-01T02:00:00Z"],  # 2 hours later
        )
        result = _merge_proto_slices([a, b])
        assert len(result) == 2

    def test_single_proto_returned_unchanged(self):
        a = _ProtoSlice(host_ips={"10.0.0.1"}, alert_ids=["A-1"])
        result = _merge_proto_slices([a])
        assert len(result) == 1


class TestAttachFindings:
    def test_attaches_by_community_id(self):
        proto = _ProtoSlice(community_ids={"cid-1"}, host_ips={"10.0.0.1"})
        finding = Finding(
            job_id="j1", finding_id="F-1", sensor="zeek",
            severity="medium", title="Test", community_id="cid-1",
            confidence=0.5,
        )
        _attach_findings([proto], [finding])
        assert "F-1" in proto.finding_ids

    def test_attaches_by_ip_mention(self):
        proto = _ProtoSlice(host_ips={"10.0.0.1"})
        finding = Finding(
            job_id="j1", finding_id="F-2", sensor="zeek",
            severity="medium", title="Activity from 10.0.0.1",
            confidence=0.5,
        )
        _attach_findings([proto], [finding])
        assert "F-2" in proto.finding_ids

    def test_no_match_not_attached(self):
        proto = _ProtoSlice(host_ips={"10.0.0.99"})
        finding = Finding(
            job_id="j1", finding_id="F-3", sensor="zeek",
            severity="medium", title="Unrelated finding",
            confidence=0.5,
        )
        _attach_findings([proto], [finding])
        assert "F-3" not in proto.finding_ids


class TestAttachIocs:
    def test_attaches_by_text_match(self):
        proto = _ProtoSlice(texts=["traffic to 198.51.100.1 detected"])
        ioc = Ioc(job_id="j1", ioc_id="IOC-1", ioc_type="ip",
                   value="198.51.100.1", severity="high", confidence=0.9)
        _attach_iocs([proto], [ioc])
        assert "IOC-1" in proto.ioc_ids

    def test_attaches_by_host_ip(self):
        proto = _ProtoSlice(host_ips={"198.51.100.1"}, texts=[])
        ioc = Ioc(job_id="j1", ioc_id="IOC-2", ioc_type="ip",
                   value="198.51.100.1", severity="high", confidence=0.9)
        _attach_iocs([proto], [ioc])
        assert "IOC-2" in proto.ioc_ids


# ---------------------------------------------------------------------------
# Integration: generate_slices
# ---------------------------------------------------------------------------

@pytest.fixture()
def sliceable_job(db_session, sample_job):
    """Job with alerts and connections sharing community IDs for slicing."""
    job_id = sample_job.job_id
    ts_base = "2024-06-15T12:00:00Z"
    ts_later = "2024-06-15T12:05:00Z"

    # Two alerts sharing community_id
    db_session.add(Alert(
        job_id=job_id, alert_id="A-S1", host_ip="10.0.0.1", src_ip="10.0.0.1",
        dest_ip="192.168.1.100", severity="high", community_id="cid-abc",
        signature="ET MALWARE CobaltStrike Beacon", category="c2", ts=ts_base,
    ))
    db_session.add(Alert(
        job_id=job_id, alert_id="A-S2", host_ip="10.0.0.1", src_ip="10.0.0.1",
        dest_ip="192.168.1.100", severity="medium", community_id="cid-abc",
        signature="Suspicious HTTPS callback", category="c2", ts=ts_later,
    ))
    # A different community_id alert
    db_session.add(Alert(
        job_id=job_id, alert_id="A-S3", host_ip="10.0.0.2", src_ip="10.0.0.2",
        dest_ip="192.168.1.200", severity="medium", community_id="cid-xyz",
        signature="Port scan detected", category="scan", ts=ts_base,
    ))
    # Connection sharing cid-abc
    db_session.add(Connection(
        job_id=job_id, connection_id="C-S1", community_id="cid-abc",
        host_ip="10.0.0.1", src_ip="10.0.0.1", dest_ip="192.168.1.100",
        proto="tcp", ts=ts_base,
    ))
    # Finding that mentions the host IP
    db_session.add(Finding(
        job_id=job_id, finding_id="F-S1", sensor="suricata",
        severity="high", title="C2 beacon from 10.0.0.1",
        summary="Periodic callback detected", community_id="cid-abc",
        confidence=0.9,
    ))
    # IOC matching an IP in the slice
    db_session.add(Ioc(
        job_id=job_id, ioc_id="IOC-S1", ioc_type="ip",
        value="192.168.1.100", severity="high", confidence=0.85,
        context="Known C2 server",
    ))
    db_session.commit()
    return sample_job


class TestGenerateSlices:
    def test_creates_slices(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        assert len(slices) >= 1

    def test_groups_by_community_id(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        # Find the slice containing cid-abc alerts
        abc_slice = None
        for s in slices:
            if s.alert_ids_json and "A-S1" in s.alert_ids_json:
                abc_slice = s
                break
        assert abc_slice is not None
        alert_ids = json.loads(abc_slice.alert_ids_json)
        assert "A-S1" in alert_ids
        assert "A-S2" in alert_ids

    def test_attaches_findings(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        # Find the slice with community_id cid-abc
        abc_slice = next(s for s in slices if s.alert_ids_json and "A-S1" in s.alert_ids_json)
        finding_ids = json.loads(abc_slice.finding_ids_json) if abc_slice.finding_ids_json else []
        assert "F-S1" in finding_ids

    def test_attaches_iocs(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        abc_slice = next(s for s in slices if s.alert_ids_json and "A-S1" in s.alert_ids_json)
        ioc_ids = json.loads(abc_slice.ioc_ids_json) if abc_slice.ioc_ids_json else []
        assert "IOC-S1" in ioc_ids

    def test_ranks_by_severity(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        if len(slices) >= 2:
            assert slices[0].rank < slices[1].rank

    def test_regeneration_replaces(self, db_session, sliceable_job):
        s1 = generate_slices(db_session, sliceable_job.job_id)
        ids1 = {s.slice_id for s in s1}  # capture before regeneration
        s2 = generate_slices(db_session, sliceable_job.job_id)
        ids2 = {s.slice_id for s in s2}
        # New UUIDs should be generated
        assert ids1 != ids2
        # Same number of slices
        assert len(s1) == len(s2)

    def test_empty_job_returns_empty(self, db_session, sample_job):
        slices = generate_slices(db_session, sample_job.job_id)
        assert slices == []

    def test_slice_has_time_range(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        abc_slice = next(s for s in slices if s.alert_ids_json and "A-S1" in s.alert_ids_json)
        assert abc_slice.time_start is not None
        assert abc_slice.time_end is not None

    def test_slice_has_correct_type(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        abc_slice = next(s for s in slices if s.alert_ids_json and "A-S1" in s.alert_ids_json)
        # Should be c2_session given the beacon/c2 text
        assert abc_slice.slice_type == "c2_session"


# ---------------------------------------------------------------------------
# API tests
# ---------------------------------------------------------------------------

class TestSlicesAPI:
    def test_list_slices_empty(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="Slice API Test", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="slice-abc1", created_at=_now(),
        )
        db.add(job)
        db.commit()
        r = client.get(f"/api/v1/jobs/{job.job_id}/slices", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []
        assert body["schema_version"] == "1.0"

    def test_list_slices_with_data(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="Slice Data Test", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="slice-abc2", created_at=_now(),
        )
        db.add(job)
        db.commit()
        sl = IncidentSlice(
            job_id=job.job_id, slice_id="SL-test001", label="Test Slice",
            slice_type="attack_thread", severity="high", confidence=0.7,
            rank=1, created_at=_now(),
            alert_ids_json=json.dumps(["A-1"]),
            host_ips_json=json.dumps(["10.0.0.1"]),
        )
        db.add(sl)
        db.commit()
        r = client.get(f"/api/v1/jobs/{job.job_id}/slices", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert len(body["items"]) == 1
        assert body["items"][0]["slice_id"] == "SL-test001"
        assert body["items"][0]["alert_ids"] == ["A-1"]

    def test_list_slices_404_bad_job(self, app_client):
        client, _ = app_client
        r = client.get("/api/v1/jobs/nonexistent/slices", headers=AUTH_HEADER)
        assert r.status_code == 404

    def test_generate_slices_endpoint(self, app_client):
        client, db = app_client
        from backend.app.models.job import Job
        job = Job(
            job_id=_uid(), job_name="Slice Gen Test", status="completed",
            execution_profile="standard", priority="normal",
            pcap_filename="test.pcap", pcap_size_bytes=1024,
            pcap_sha256="slice-abc3", created_at=_now(),
        )
        db.add(job)
        db.commit()
        r = client.post(f"/api/v1/jobs/{job.job_id}/slices/generate", headers=AUTH_HEADER)
        assert r.status_code == 200
        body = r.json()
        assert body["items"] == []  # no alerts/connections → no slices


# ---------------------------------------------------------------------------
# Evidence bundle: slice scope
# ---------------------------------------------------------------------------

class TestSliceEvidenceBundle:
    def test_slice_bundle_with_valid_id(self, db_session, sliceable_job):
        slices = generate_slices(db_session, sliceable_job.job_id)
        assert len(slices) >= 1
        from backend.app.services.evidence_bundles import build_scoped_bundle
        bundle = build_scoped_bundle(db_session, sliceable_job.job_id, "slice", slices[0].slice_id)
        ctx = bundle.to_context()
        assert "Slice:" in ctx or "slice" in ctx.lower()

    def test_parse_context_hint_slice(self):
        from backend.app.services.evidence_bundles import parse_context_hint
        scope_type, scope_id = parse_context_hint("slice:SL-abc12345")
        assert scope_type == "slice"
        assert scope_id == "SL-abc12345"

