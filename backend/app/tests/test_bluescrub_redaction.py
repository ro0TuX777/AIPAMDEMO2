"""Secret redaction.

The policy is unconditional: the database, API, UI, logs, and exports never
hold a complete secret. Before this existed, a scan of a repository containing
a live AWS key copied that key verbatim into AIPAM's database and from there
into every export.

The canary tests below plant a distinctive value and then hunt for it in every
place it could survive — including log output, which the policy names and
nothing previously checked.
"""

import json
import logging

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import redaction, service as bs_service
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar, RiskClass
from backend.app.bluescrub.scanners.base import ScannerOutcome, ScannerSpec
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding

CANARY = "AKIAIOSFODNN7CANARY"
KEY = "unit-test-key-not-a-real-one"


def _secret_finding(token=f'AWS_SECRET = "{CANARY}"', family=IssueFamily.hardcoded_secret):
    return RawFinding(
        sensor="bluescrub_analyzers", sensor_version="v",
        rule_id="CryptoVulnerabilityAnalyzer.hardcoded_keys", issue_family=family,
        pillar_hint=Pillar.attribution, detector_class=DetectorClass.regex_pattern,
        raw_severity="HIGH", confidence=0.6, matched_tokens=token,
        description=f"credential found: {token}",
        location=Location(kind="source", file="cfg.py", start_line=1, start_column=0),
    )


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv(redaction.KEY_ENV, KEY)


# ── masking ───────────────────────────────────────────────────────────────

def test_long_secret_keeps_only_its_ends():
    assert redaction.mask(CANARY) == "AKIA…NARY"


def test_short_secret_is_masked_entirely():
    """First-and-last-four would reveal most of a short value."""
    assert redaction.mask("abcdefgh") == "*" * 8
    assert CANARY[:4] not in redaction.mask("short")


def test_fingerprint_is_keyed():
    """An unkeyed digest of a structured 20-character secret is reversible."""
    a = redaction.fingerprint(CANARY, b"key-one")
    b = redaction.fingerprint(CANARY, b"key-two")
    assert a != b
    assert a.startswith("hmac-sha256:")
    # Same key, same value, same fingerprint — dedup depends on it.
    assert a == redaction.fingerprint(CANARY, b"key-one")


def test_fingerprint_ignores_surrounding_quotes():
    assert redaction.fingerprint(CANARY, b"k") == redaction.fingerprint(f'"{CANARY}"', b"k")


# ── what gets redacted ────────────────────────────────────────────────────

def test_credential_families_are_redacted():
    result = redaction.redact([_secret_finding()])
    finding = result.findings[0]

    assert CANARY not in (finding.matched_tokens or "")
    assert CANARY not in (finding.description or "")
    assert finding.secret and finding.secret.masked_value == "AKIA…NARY"
    assert result.redacted == 1


def test_attribution_findings_are_not_masked():
    """An operator's email is the finding. Masking it destroys its purpose."""
    finding = _secret_finding("jsmith@corp.internal", IssueFamily.attribution_identity)
    out = redaction.redact([finding]).findings[0]

    assert out.matched_tokens == "jsmith@corp.internal"
    assert out.secret is None


def test_unextractable_credential_is_dropped_not_gambled_on():
    """The family says a credential is in there; if it cannot be located, the
    whole fragment goes rather than risk leaking part of it."""
    finding = _secret_finding("something opaque with spaces and no assignment")
    out = redaction.redact([finding]).findings[0]
    assert out.matched_tokens == "*" * 8


def test_no_key_means_no_fingerprint_rather_than_an_unkeyed_one(monkeypatch):
    """An unkeyed hash of a low-entropy secret looks like protection and is not."""
    monkeypatch.delenv(redaction.KEY_ENV, raising=False)
    result = redaction.redact([_secret_finding()])

    finding = result.findings[0]
    assert CANARY not in (finding.matched_tokens or ""), "must still mask"
    assert finding.secret.fingerprint == "", "must not write an unkeyed digest"
    assert result.unkeyed == 1


# ── fingerprint collisions ────────────────────────────────────────────────

def test_two_secrets_masking_alike_stay_distinct():
    """AKIA1111NARY and AKIA2222NARY both render as AKIA…NARY.

    Fingerprinting the mask would collapse two different leaked credentials
    into one finding — and, given the unique constraint, could fail the job.
    """
    from backend.app.bluescrub.canonicalize import canonicalize

    a = _secret_finding('K = "AKIA1111111111NARY"')
    b = _secret_finding('K = "AKIA2222222222NARY"')
    b.location = Location(kind="source", file="cfg.py", start_line=2, start_column=0)

    findings = redaction.redact([a, b]).findings
    assert findings[0].secret.masked_value == findings[1].secret.masked_value

    groups = canonicalize(findings, project_id="p").groups
    assert len({g.canonical_id for g in groups}) == 2, "distinct secrets merged"


# ── end to end: the canary must not survive anywhere ──────────────────────

@pytest.fixture()
def scanned(tmp_path, monkeypatch):
    def _run(source_root, output_dir):
        return ScannerOutcome(sensor="bluescrub_analyzers", status="completed",
                              version="v", findings=[_secret_finding()])

    spec = ScannerSpec(name="bluescrub_analyzers", run=_run,
                       pillars=(Pillar.attribution,), risk_class=RiskClass.parse_only)
    monkeypatch.setattr(bs_service, "scanners_for", lambda p: [spec])
    monkeypatch.setattr(bs_service, "required_for", lambda p, prof: ["bluescrub_analyzers"])

    engine = create_engine(f"sqlite:///{tmp_path/'r.db'}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    job = tmp_path / "job"
    (job / "input" / "source").mkdir(parents=True)
    (job / "input" / "source" / "cfg.py").write_text("x = 1\n")
    metrics = bs_service.analyze_and_persist(db, "j", job, profile="deep", run_output_dir=job)
    yield db, metrics, job
    db.close()


def test_canary_never_reaches_the_database(scanned):
    db, _metrics, _job = scanned
    rows = db.scalars(select(Finding)).all()
    assert rows

    for row in rows:
        blob = json.dumps({
            "title": row.title, "summary": row.summary,
            "evidence": row.evidence_json,
        })
        assert CANARY not in blob, "plaintext secret persisted"


def test_canary_never_reaches_the_sensor_output_file(scanned):
    _db, _metrics, job = scanned
    for path in (job / "sensors").rglob("*"):
        if path.is_file():
            assert CANARY not in path.read_text(errors="ignore"), path


def test_canary_never_reaches_the_logs(tmp_path, monkeypatch, caplog):
    """The policy names logs specifically, and nothing checked them."""
    monkeypatch.setenv(redaction.KEY_ENV, KEY)
    with caplog.at_level(logging.DEBUG, logger="backend.app.bluescrub"):
        redaction.redact([_secret_finding()])

    assert CANARY not in caplog.text


def test_metrics_report_the_redaction(scanned):
    _db, metrics, _job = scanned
    assert metrics["dacv"]["secrets_redacted"] == 1
    assert metrics["dacv"]["secrets_without_fingerprint"] == 0


def test_evidence_carries_the_masked_value_and_fingerprint(scanned):
    db, _metrics, _job = scanned
    row = db.scalars(select(Finding)).first()
    secret = json.loads(row.evidence_json)["secret"]

    assert secret["masked_value"] == "AKIA…NARY"
    assert secret["fingerprint"].startswith("hmac-sha256:")
    assert CANARY not in json.dumps(secret)
