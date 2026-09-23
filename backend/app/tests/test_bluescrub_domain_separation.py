"""AIPAM analyses traffic. BlueScrub analyses code. The two must not blur.

The risk is not that BlueScrub writes to a network table — it does not, and a
test below pins that. The risk is subtler: several vendored analyzers use
AIPAM's own vocabulary for source patterns. "beacon_patterns" here means a
hardcoded sleep interval in a file; AIPAM's `beaconing` sensor means beaconing
observed in captured traffic. Side by side in one findings list they read the
same and mean nothing alike.

A code finding that acquired an src_ip would be worse still: it would enter
correlation as though something had been seen on the wire.
"""

import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import service as bs_service
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.bluescrub.scanners.base import ScannerOutcome, ScannerSpec
from backend.app.bluescrub.scanners.vendored_analyzers import (
    _AMBIGUOUS_WITH_NETWORK_DOMAIN,
    specialised_to_raw_findings,
)
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding

#: Columns that mean "this was observed on the wire". A BlueScrub finding that
#: populates any of them is claiming evidence it does not have.
NETWORK_EVIDENCE_COLUMNS = ("community_id", "src_ip", "dest_ip", "ts", "pcap_label")


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'d.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture()
def job_dir(tmp_path):
    root = tmp_path / "jobs" / "j"
    src = root / "input" / "source"
    src.mkdir(parents=True)
    (src / "agent.py").write_text("import socket\nC2='10.0.0.1:4444'\n")
    return root


@pytest.fixture()
def stub(monkeypatch):
    """A scanner that reports the most network-looking finding it can."""
    def _run(source_root, output_dir):
        return ScannerOutcome(
            sensor="bluescrub_analyzers", status="completed", version="v",
            findings=[RawFinding(
                sensor="bluescrub_analyzers", sensor_version="v",
                rule_id="NetworkTrafficAnalyzer.c2_references.c2_reference",
                issue_family=IssueFamily.hardcoded_c2, pillar_hint=Pillar.co_optability,
                detector_class=DetectorClass.regex_pattern, raw_severity="HIGH",
                confidence=0.6, matched_tokens="10.0.0.1:4444", source_facet="source",
                title="C2 reference",
                location=Location(kind="source", file="agent.py",
                                  start_line=2, start_column=0),
            )],
        )

    spec = ScannerSpec(
        name="bluescrub_analyzers", run=_run,
        pillars=(Pillar.co_optability,),
        risk_class=__import__(
            "backend.app.bluescrub.pillars", fromlist=["RiskClass"]
        ).RiskClass.parse_only,
    )
    monkeypatch.setattr(bs_service, "scanners_for", lambda p: [spec])
    monkeypatch.setattr(bs_service, "required_for", lambda p, prof: ["bluescrub_analyzers"])


# ── the structural guarantee ──────────────────────────────────────────────

def test_code_findings_never_populate_network_evidence_columns(db, job_dir, stub):
    """An IP literal in source is not an observed connection.

    A code finding carrying src_ip would enter host and connection views, and
    the IOC bridge, as though something had been seen on the wire.
    """
    bs_service.analyze_and_persist(db, "j", job_dir, profile="standard", run_output_dir=job_dir)

    row = db.scalars(select(Finding).where(Finding.job_id == "j")).one()
    for column in NETWORK_EVIDENCE_COLUMNS:
        assert getattr(row, column) is None, (
            f"BlueScrub finding populated {column} — it is claiming network "
            "evidence it does not have"
        )


def test_every_finding_declares_the_code_domain(db, job_dir, stub):
    bs_service.analyze_and_persist(db, "j", job_dir, profile="standard", run_output_dir=job_dir)
    row = db.scalars(select(Finding)).one()
    assert json.loads(row.evidence_json)["analysis_domain"] == "code"


def test_bluescrub_package_references_no_network_model():
    """Enforced against the source, not just against one run's output."""
    from pathlib import Path

    root = Path(bs_service.__file__).resolve().parent
    network_models = (
        "models.connection", "models.dns", "models.tls", "models.alert",
        "models.host", "models.global_host", "models.normalized_event",
        "models.job_pcap", "models.timeline",
    )
    offenders = []
    for path in root.rglob("*.py"):
        if "vendored" in path.parts:
            continue
        text = path.read_text()
        for model in network_models:
            if model in text:
                offenders.append(f"{path.name}: {model}")
    assert not offenders, offenders


def test_sensor_names_do_not_collide_with_aipam_sensors():
    """Finding.sensor is a filter facet; a shared name merges two domains."""
    from backend.app.bluescrub.registry import SCANNERS
    from backend.app.sensors.registry import SENSORS

    collisions = set(SCANNERS) & set(SENSORS)
    assert not collisions, (
        f"sensor name(s) used by both domains: {sorted(collisions)} — a shared "
        "name makes the findings filter mix traffic and code evidence"
    )


# ── the presentational guarantee ──────────────────────────────────────────

def test_network_vocabulary_titles_say_they_came_from_source():
    """'Fixed sleep interval' beside AIPAM's beaconing findings is ambiguous."""
    record = [{
        "file": "/tmp/a.py",
        "beacon_patterns": {
            "found": True, "risk": "HIGH", "explanation": "x",
            "beacons": [{"pattern": "Sleep(60000)", "type": "Fixed sleep interval",
                         "line": 6, "risk": "HIGH"}],
        },
    }]
    from pathlib import Path

    finding = specialised_to_raw_findings("NetworkTrafficAnalyzer", record, Path("/tmp"))[0]
    assert "in source" in finding.title.lower()


@pytest.mark.parametrize("category", sorted(_AMBIGUOUS_WITH_NETWORK_DOMAIN))
def test_each_ambiguous_category_is_annotated(category):
    hint = _AMBIGUOUS_WITH_NETWORK_DOMAIN[category]
    assert "source" in hint, f"{category} hint does not say where the evidence came from"


def test_ambiguous_list_covers_aipam_sensor_vocabulary():
    """If AIPAM gains a sensor whose name a vendored category reuses, catch it."""
    from backend.app.sensors.registry import SENSORS

    vocabulary = {name.replace("_", "") for name in SENSORS}
    annotated = {c.replace("_", "") for c in _AMBIGUOUS_WITH_NETWORK_DOMAIN}
    # Every AIPAM sensor whose name appears inside a vendored category label
    # must have that label annotated.
    for sensor in vocabulary:
        overlapping = [c for c in annotated if sensor[:5] in c]
        if sensor.startswith("beacon"):
            assert overlapping, "beaconing vocabulary must be annotated"
