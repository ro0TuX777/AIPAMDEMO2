"""Tests for the enhanced cross-source temporal correlator.

Covers multi-key matching (community_id, 5-tuple, IP fallback), label-aware
scoring, clock-offset estimation, and idempotent re-runs. Runs against
in-memory SQLite with the V2 schema.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import Session

from backend.app.database_v2 import Base, _set_sqlite_pragmas
from backend.app.models.alert import Alert
from backend.app.models.connection import Connection
from backend.app.models.finding import Finding
from backend.app.models.job import Job
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.temporal_correlation import TemporalCorrelation
from backend.app.normalize.network_events import PCAP_NORMALIZER_PARSER
from backend.app.services.temporal_correlator import (
    MIN_SCORE_FOR_CONFIRMATION,
    correlate_temporal,
)

BASE = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)


def _uid() -> str:
    return str(uuid.uuid4())


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    Base.metadata.create_all(bind=engine)
    session = Session(bind=engine)
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def job(db):
    j = Job(
        job_id=_uid(), job_name="TC Test", status="queued",
        execution_profile="standard", priority="normal",
        pcap_filename="t.pcap", pcap_size_bytes=0, pcap_sha256="x", created_at=_iso(BASE),
    )
    db.add(j)
    db.commit()
    return j


def _add_log(db, job_id, *, offset_s=0.0, source="sysmon", **kw):
    evt = NormalizedEvent(
        event_id=f"NE-{uuid.uuid4().hex[:10]}", job_id=job_id,
        event_type=kw.pop("event_type", "network"), timestamp=_iso(BASE + timedelta(seconds=offset_s)),
        source_type="log_bundle", source_system=source, evidence_status="observed",
        corroboration_score=0.0, **kw,
    )
    db.add(evt)
    db.flush()
    return evt


def _add_conn(db, job_id, *, offset_s=0.0, **kw):
    kw.setdefault("host_ip", kw.get("src_ip", "10.0.0.5"))
    kw.setdefault("dest_ip", "8.8.8.8")
    kw.setdefault("proto", "tcp")
    c = Connection(
        job_id=job_id, connection_id=f"C-{uuid.uuid4().hex[:10]}",
        ts=_iso(BASE + timedelta(seconds=offset_s)), **kw,
    )
    db.add(c)
    db.flush()
    return c


def _add_alert(db, job_id, *, offset_s=0.0, **kw):
    kw.setdefault("host_ip", kw.get("src_ip", "10.0.0.5"))
    kw.setdefault("severity", "high")
    kw.setdefault("signature", "Test Sig")
    a = Alert(
        job_id=job_id, alert_id=f"A-{uuid.uuid4().hex[:10]}",
        ts=_iso(BASE + timedelta(seconds=offset_s)), **kw,
    )
    db.add(a)
    db.flush()
    return a


def _rows(db, job_id):
    return db.execute(
        select(TemporalCorrelation).where(TemporalCorrelation.job_id == job_id)
    ).scalars().all()


# ── IP-only fallback ────────────────────────────────────────────────────────

def test_ip_only_fallback(db, job):
    _add_log(db, job.job_id, src_ip="10.0.0.5", offset_s=2)
    _add_alert(db, job.job_id, src_ip="10.0.0.5", dest_ip="8.8.8.8", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    rows = _rows(db, job.job_id)
    assert result["matches"] == 1
    assert rows[0].match_type == "ip_temporal"
    assert rows[0].match_keys == ["ip"]
    assert rows[0].shared_ip == "10.0.0.5"


def test_ip_only_outside_window_skipped(db, job):
    _add_log(db, job.job_id, src_ip="10.0.0.5", offset_s=120)  # >30s, no strong key
    _add_alert(db, job.job_id, src_ip="10.0.0.5", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["matches"] == 0


# ── community_id (strongest) ────────────────────────────────────────────────

def test_community_id_match_is_strongest(db, job):
    _add_log(db, job.job_id, src_ip="10.0.0.5", dest_ip="8.8.8.8",
             community_id="1:abc", offset_s=1)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", dest_ip="8.8.8.8",
              community_id="1:abc", offset_s=0)
    db.commit()

    correlate_temporal(db, job.job_id)
    rows = _rows(db, job.job_id)
    assert len(rows) == 1
    assert rows[0].match_type == "community_id"
    assert rows[0].community_id == "1:abc"
    assert "community_id" in rows[0].match_keys
    assert rows[0].confidence_band == "high"


def test_community_id_uses_wide_window(db, job):
    # 120s apart: outside the 30s IP window but inside the 300s strong-key window.
    _add_log(db, job.job_id, src_ip="10.0.0.5", dest_ip="8.8.8.8",
             community_id="1:wide", offset_s=120)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", dest_ip="8.8.8.8",
              community_id="1:wide", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["matches"] == 1
    assert _rows(db, job.job_id)[0].match_type == "community_id"


# ── 5-tuple ─────────────────────────────────────────────────────────────────

def test_five_tuple_match_direction_agnostic(db, job):
    # Log records the reverse direction; the direction-agnostic key still matches.
    _add_log(db, job.job_id, src_ip="8.8.8.8", src_port=443,
             dest_ip="10.0.0.5", dest_port=51000, proto="tcp", offset_s=3)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", src_port=51000,
              dest_ip="8.8.8.8", dest_port=443, proto="tcp", offset_s=0)
    db.commit()

    correlate_temporal(db, job.job_id)
    rows = _rows(db, job.job_id)
    assert len(rows) == 1
    assert rows[0].match_type == "five_tuple"
    assert "five_tuple" in rows[0].match_keys


# ── Label-aware scoring ─────────────────────────────────────────────────────

def test_label_mismatch_lowers_score(db, job):
    job_match, job_mismatch = job.job_id, _uid()
    db.add(Job(job_id=job_mismatch, job_name="mm", status="queued",
               execution_profile="standard", priority="normal",
               pcap_filename="t.pcap", pcap_size_bytes=0, pcap_sha256="y",
               created_at=_iso(BASE)))
    db.flush()

    # Identical timing/keys; only the label agreement differs.
    for jid, llabel, plabel in ((job_match, "during", "during"), (job_mismatch, "before", "after")):
        _add_log(db, jid, src_ip="10.0.0.5", community_id="1:lbl", offset_s=1, pcap_label=llabel)
        _add_conn(db, jid, src_ip="10.0.0.5", community_id="1:lbl", offset_s=0, pcap_label=plabel)
    db.commit()

    correlate_temporal(db, job_match)
    correlate_temporal(db, job_mismatch)
    agree = _rows(db, job_match)[0]
    disagree = _rows(db, job_mismatch)[0]
    assert disagree.match_score < agree.match_score
    assert agree.log_label == "during" and agree.pcap_label == "during"
    assert disagree.log_label == "before" and disagree.pcap_label == "after"


# ── Clock-offset estimation ─────────────────────────────────────────────────

def test_clock_offset_aligns_distant_event(db, job):
    # 3 community_id anchors establish a consistent +100s log clock offset.
    for i in range(3):
        cid = f"1:anchor{i}"
        _add_log(db, job.job_id, src_ip=f"10.0.0.{i}", community_id=cid, offset_s=100)
        _add_conn(db, job.job_id, src_ip=f"10.0.0.{i}", community_id=cid, offset_s=0)
    # IP-only event 100s after its alert: only matchable once the offset is applied.
    _add_log(db, job.job_id, src_ip="10.0.0.99", offset_s=100)
    _add_alert(db, job.job_id, src_ip="10.0.0.99", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert abs(result["clock_offsets"]["sysmon"] - 100.0) < 1.0
    ip_row = next(r for r in _rows(db, job.job_id) if r.shared_ip == "10.0.0.99")
    assert ip_row.match_type == "ip_temporal"
    assert abs(ip_row.clock_offset_seconds - 100.0) < 1.0
    assert ip_row.adjusted_time_delta_seconds < 5.0


def test_insufficient_anchors_no_offset(db, job):
    # Only one anchor → below MIN_ANCHORS_FOR_OFFSET, so no offset is trusted.
    _add_log(db, job.job_id, src_ip="10.0.0.1", community_id="1:solo", offset_s=100)
    _add_conn(db, job.job_id, src_ip="10.0.0.1", community_id="1:solo", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert "sysmon" not in result.get("clock_offsets", {})


# ── Idempotency + evidence upgrade ──────────────────────────────────────────

def test_rerun_is_idempotent(db, job):
    _add_log(db, job.job_id, src_ip="10.0.0.5", community_id="1:abc", offset_s=1)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", community_id="1:abc", offset_s=0)
    db.commit()

    correlate_temporal(db, job.job_id)
    first = len(_rows(db, job.job_id))
    correlate_temporal(db, job.job_id)
    second = len(_rows(db, job.job_id))
    assert first == second == 1


def test_matched_event_is_corroborated(db, job):
    evt = _add_log(db, job.job_id, src_ip="10.0.0.5", community_id="1:abc", offset_s=1)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", community_id="1:abc", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["upgraded_events"] == 1
    db.refresh(evt)
    assert evt.evidence_status == "corroborated"
    assert evt.corroboration_score > 0.0


# ── PCAP-derived events must not correlate with themselves ──────────────────

def test_pcap_normalized_events_excluded_from_log_side(db, job):
    """zeek/suricata rows in normalized_events are not "logs" for this stage.

    ``normalize_network_events`` mirrors the same sensor records that build
    Connection/Alert, so leaving them on the log side makes every flow match
    itself on an exact community_id at zero delta — perfect scores that bury
    the real uploaded-log matches.
    """
    _add_log(db, job.job_id, src_ip="10.0.0.5", community_id="1:zeek",
             source="zeek",
             parser_name=PCAP_NORMALIZER_PARSER, offset_s=0)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", community_id="1:zeek", offset_s=0)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["log_events"] == 0
    assert result["matches"] == 0


def test_uploaded_logs_still_correlate_alongside_pcap_events(db, job):
    """The uploaded-log match survives even when zeek mirrors dominate the table."""
    # 50 zeek mirror rows, each a perfect self-match if not filtered out.
    for i in range(50):
        _add_log(db, job.job_id, src_ip="10.0.0.5", community_id=f"1:z{i}",
                 source="zeek",
                 parser_name=PCAP_NORMALIZER_PARSER, offset_s=i)
        _add_conn(db, job.job_id, src_ip="10.0.0.5", community_id=f"1:z{i}", offset_s=i)

    uploaded = _add_log(db, job.job_id, src_ip="10.0.0.5", community_id="1:user",
                        source="sysmon", parser_name="sysmon", offset_s=1)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", community_id="1:user", offset_s=0)
    db.commit()

    correlate_temporal(db, job.job_id)
    rows = _rows(db, job.job_id)
    assert rows, "uploaded log produced no correlations"
    assert {r.log_source for r in rows} == {"sysmon"}
    assert all(r.log_event_id == uploaded.event_id for r in rows)


# ── Findings as a correlation counterparty ──────────────────────────────────

def _add_finding(db, job_id, *, offset_s=0.0, **kw):
    kw.setdefault("severity", "high")
    kw.setdefault("title", "Suspicious beaconing")
    kw.setdefault("sensor", "beaconing")
    f = Finding(
        job_id=job_id, finding_id=f"F-{uuid.uuid4().hex[:10]}",
        ts=_iso(BASE + timedelta(seconds=offset_s)), **kw,
    )
    db.add(f)
    db.flush()
    return f


def test_uploaded_log_corroborates_a_finding(db, job):
    """An EVTX/router log lining up with a finding marks it corroborated."""
    finding = _add_finding(db, job.job_id, src_ip="10.0.0.5", offset_s=0)
    _add_log(db, job.job_id, src_ip="10.0.0.5", source="windows_evtx", offset_s=3)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["supported_findings"] == 1
    assert result["confirmed_findings"] == 0
    db.refresh(finding)
    assert finding.evidence_status == "corroborated"
    assert finding.corroborating_sources == ["windows_evtx"]
    assert finding.corroboration_score > 0.0


def test_c2_log_confirms_a_finding_as_ground_truth(db, job):
    """A C2 operator log is ground truth: the detection is confirmed outright."""
    finding = _add_finding(db, job.job_id, src_ip="10.0.0.5", offset_s=0, confidence=0.6)
    _add_log(db, job.job_id, src_ip="10.0.0.5", source="cobaltstrike",
             event_type="c2_callback", offset_s=4)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["confirmed_findings"] == 1
    db.refresh(finding)
    assert finding.evidence_status == "confirmed"
    assert finding.confidence == 1.0
    assert finding.corroborating_sources == ["cobaltstrike"]

    rows = [r for r in _rows(db, job.job_id) if r.pcap_entity_type == "finding"]
    assert len(rows) == 1
    assert rows[0].pcap_entity_id == finding.finding_id


def test_finding_matches_a_host_named_only_in_its_evidence(db, job):
    """Alert-group findings list affected hosts in evidence, not on the row."""
    finding = _add_finding(
        db, job.job_id, offset_s=0,
        evidence_json=json.dumps({"affected_hosts": ["10.0.0.9"], "alert_count": 3}),
    )
    _add_log(db, job.job_id, src_ip="10.0.0.9", source="firewall", offset_s=5)
    db.commit()

    correlate_temporal(db, job.job_id)
    db.refresh(finding)
    assert finding.evidence_status == "corroborated"


def test_finding_without_timestamp_is_skipped(db, job):
    _add_finding(db, job.job_id, src_ip="10.0.0.5")
    db.execute(update(Finding).where(Finding.job_id == job.job_id).values(ts=None))
    _add_log(db, job.job_id, src_ip="10.0.0.5", offset_s=1)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["pcap_events"] == 0
    assert result["matches"] == 0


def test_finding_window_is_wider_than_a_connection_window(db, job):
    """Findings are aggregates, so an IP-only match survives past ±30 s."""
    finding = _add_finding(db, job.job_id, src_ip="10.0.0.5", offset_s=0)
    _add_conn(db, job.job_id, src_ip="10.0.0.5", offset_s=0)
    _add_log(db, job.job_id, src_ip="10.0.0.5", source="firewall", offset_s=100)
    db.commit()

    correlate_temporal(db, job.job_id)
    matched = {r.pcap_entity_type for r in _rows(db, job.job_id)}
    assert matched == {"finding"}, "connection should fall outside the ±30s IP window"
    db.refresh(finding)
    assert finding.evidence_status == "corroborated"


def test_ground_truth_matches_outrank_ordinary_ones(db, job):
    _add_alert(db, job.job_id, src_ip="10.0.0.5", offset_s=0)
    _add_log(db, job.job_id, src_ip="10.0.0.5", source="firewall", offset_s=1)
    _add_log(db, job.job_id, src_ip="10.0.0.5", source="sliver",
             event_type="c2_callback", offset_s=1)
    db.commit()

    correlate_temporal(db, job.job_id)
    rows = sorted(_rows(db, job.job_id), key=lambda r: -r.match_score)
    assert rows[0].log_source == "sliver"
    assert rows[0].match_score > rows[1].match_score


def test_weak_ground_truth_match_corroborates_but_does_not_confirm(db, job):
    """Sharing a host IP somewhere in the window is not proof.

    On a busy victim host every uploaded event overlaps every finding, so a
    ground-truth log has to actually score well before it promotes a finding
    to "confirmed" — otherwise everything is confirmed and nothing is.
    """
    finding = _add_finding(db, job.job_id, src_ip="10.0.0.5", offset_s=0, confidence=0.5)
    # IP-only match at the far edge of the widened finding window → low score.
    _add_log(db, job.job_id, src_ip="10.0.0.5", source="cobaltstrike",
             event_type="c2_callback", offset_s=170)
    db.commit()

    result = correlate_temporal(db, job.job_id)
    assert result["supported_findings"] == 1
    assert result["confirmed_findings"] == 0
    db.refresh(finding)
    assert finding.evidence_status == "corroborated"
    assert finding.corroboration_score < MIN_SCORE_FOR_CONFIRMATION
    assert finding.confidence < 1.0
