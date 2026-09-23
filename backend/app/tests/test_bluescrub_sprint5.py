"""Sprint 5 acceptance, and the code-similarity mapping that closes it.

The plan states three criteria for Attribution:

    a planted codename in a binary surfaces with category and offset context;
    a critical Attribution hit sets grade F and `disqualified: true`;
    no plaintext secret appears anywhere in DB, API, logs, or exports.

Each is asserted here end to end rather than in pieces. The third is asserted
through the real Gitleaks adapter driven by recorded output, because that is
the first scanner in this pipeline whose *matches are the credential* — the
existing redaction tests drive a synthetic scanner, which cannot show that the
adapter, the on-disk artefact and the API all hold the line together.

Exports are named in the criterion and do not exist yet; the export surface
lands in Sprint 9 and is built from the persisted evidence asserted here, so
what it can contain is bounded by what the database holds.
"""

import json
import logging
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import redaction, service as bs_service, wordlists as wl
from backend.app.bluescrub.isolation import AnalyzerResult, AnalyzerStatus
from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.scanners import external, secrets
from backend.app.bluescrub.severity_table import canonical_severity
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding

CANARY = "ghp_CANARY000000000000000000000000000000"
KEY = "sprint5-acceptance-key"


@pytest.fixture(autouse=True)
def _sandbox(monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    monkeypatch.setenv(redaction.KEY_ENV, KEY)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'s5.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def elf_with(payload: bytes, *, pad: int = 4096) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * (pad - 7) + payload + b"\x00" * 64


# ── criterion 1 ───────────────────────────────────────────────────────────

def test_a_planted_codename_in_a_binary_surfaces_with_category_and_offset(db, tmp_path):
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL"))
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])

    bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)

    hits = [
        json.loads(r.evidence_json)
        for r in db.scalars(select(Finding)).all() if r.sensor == "dirty_word"
    ]
    planted = next(h for h in hits if h["rule_id"] == "dirty_word.codename")

    # Category: the rule id is the declared category, never the term itself.
    assert planted["rule_id"] == "dirty_word.codename"
    # Offset context: a position in the artifact an analyst can seek to.
    assert planted["location"]["kind"] == "binary"
    assert planted["location"]["offset"] == 4096 + len("OPERATION ")
    assert planted["location"]["artifact_sha256"]
    assert planted["location"]["format"] == "elf"

    data = (src / "loader").read_bytes()
    at = planted["location"]["offset"]
    assert data[at:at + 9] == b"NIGHTFALL", "the offset does not point at the term"


def test_the_binary_case_was_previously_unreportable():
    """A `source` location with no line number is rejected by the contract, and
    nothing validates raw findings at runtime — so it reached the database."""
    from backend.app.bluescrub.models import Location, RawFinding
    from backend.app.tests._bluescrub_schemas import validator

    broken = RawFinding(
        sensor="dirty_word", sensor_version="v", rule_id="dirty_word.codename",
        issue_family=IssueFamily.attribution_marking, confidence=0.9,
        location=Location(kind="source", file="loader", start_column=0, offset=4096),
    )
    with pytest.raises(Exception):
        validator("raw-finding.schema.json").validate(broken.to_dict())


# ── criterion 2 ───────────────────────────────────────────────────────────

def test_a_critical_attribution_hit_sets_grade_f_and_disqualified(db, tmp_path):
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL"))
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])

    dacv = bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)["dacv"]

    assert dacv["disqualified"] is True
    assert dacv["scoped"]["grade"] == "F"


def test_the_disqualifying_hit_must_be_a_reviewed_critical(db, tmp_path):
    """Disqualification has to mean something. The detectors that can trigger it
    are the ones told what to look for, not the ones guessing."""
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "notes.py").write_text("# TODO: finish this\nprint('DEBUG: here')\n")

    dacv = bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)["dacv"]
    assert dacv["disqualified"] is False


@pytest.mark.parametrize("rule,family,expected", [
    ("dirty_word.codename", IssueFamily.attribution_marking, "critical"),
    ("gitmeta.declared_identity", IssueFamily.attribution_identity, "critical"),
    ("gitmeta.author_identity", IssueFamily.attribution_identity, "high"),
    ("build_paths.operator_path", IssueFamily.build_path_leak, "high"),
    ("build_paths.build_environment", IssueFamily.metadata_leak, "medium"),
    ("gitleaks.github-pat", IssueFamily.hardcoded_secret, "high"),
])
def test_only_declared_terms_reach_the_disqualifying_tier(rule, family, expected):
    from backend.app.bluescrub.pillars import DetectorClass

    assert canonical_severity(rule, family, DetectorClass.regex_pattern) == expected


# ── criterion 3 ───────────────────────────────────────────────────────────

GITLEAKS_REPORT = [{
    "Description": "GitHub Personal Access Token",
    "StartLine": 7, "StartColumn": 12,
    "Match": f'token = "{CANARY}"', "Secret": CANARY,
    "File": "uploader.py", "RuleID": "github-pat",
    "Commit": "9f2c1ab77e0d4b3a", "Email": "ada@redcell.internal",
}]


@pytest.fixture()
def gitleaks_job(db, tmp_path, monkeypatch):
    """Run a real job with the real Gitleaks adapter over recorded output."""
    real_which = external.shutil.which
    monkeypatch.setattr(
        external.shutil, "which",
        lambda name: "/usr/bin/gitleaks" if name == "gitleaks" else real_which(name),
    )

    def _fake(argv, **_kw):
        if "version" in argv[-1] or argv[-1] == "version":
            return AnalyzerResult(status=AnalyzerStatus.completed, stdout=b"8.18.0",
                                  exit_code=0)
        return AnalyzerResult(
            status=AnalyzerStatus.completed,
            stdout=json.dumps(GITLEAKS_REPORT).encode(), exit_code=0,
        )

    monkeypatch.setattr(external, "run_analyzer", _fake)

    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "uploader.py").write_text("token = 'placeholder'\n")

    metrics = bs_service.analyze_and_persist(db, "j", tmp_path, profile="standard", run_output_dir=tmp_path)
    return db, metrics, tmp_path


def test_the_adapter_actually_ran(gitleaks_job):
    db, _metrics, _job = gitleaks_job
    rows = [r for r in db.scalars(select(Finding)).all() if r.sensor == "gitleaks"]
    assert rows, "the acceptance sweep would pass vacuously without a finding"


def test_no_plaintext_secret_reaches_the_database(gitleaks_job):
    db, _metrics, _job = gitleaks_job
    dumped = json.dumps([
        {c.name: str(getattr(row, c.name)) for c in Finding.__table__.columns}
        for row in db.scalars(select(Finding)).all()
    ])
    assert CANARY not in dumped


def test_no_plaintext_secret_reaches_a_file_outside_quarantine(gitleaks_job):
    """`quarantine/` is the one place the policy permits plaintext, bounded at
    72 hours. Everywhere else in the job is under the platform's 30-day clock.

    This originally asserted *no* file in the job, which is stricter than the
    policy and passed only because nothing was writing raw output. With real
    scanners installed a parser failure quarantined a tool's stdout, and the
    assertion was measuring the absence of a code path rather than a rule."""
    _db, _metrics, job = gitleaks_job
    checked = 0
    for path in job.rglob("*"):
        if not path.is_file() or "quarantine" in path.parts:
            continue
        checked += 1
        assert CANARY not in path.read_text(errors="ignore"), path
    assert checked, "no artefacts were written, so nothing was checked"


def test_unreadable_raw_output_is_quarantined_not_left_beside_the_findings(
    gitleaks_job,
):
    """The tier is "plaintext secrets in raw scanner output" — not "output of a
    secret scanner". Semgrep's raw report carries matched source lines, and a
    matched line can be a credential whatever rule found it."""
    _db, _metrics, job = gitleaks_job

    stray = [p for p in (job / "sensors").rglob("*.unparseable.raw")]
    assert stray == [], f"raw output left under the job's 30-day clock: {stray}"


def test_the_secret_scanners_artefacts_are_in_the_quarantine_tier(gitleaks_job):
    _db, _metrics, job = gitleaks_job
    quarantined = list((job / "quarantine").glob("gitleaks*"))

    assert quarantined, "gitleaks output was written under the job's own clock"
    assert not list((job / "sensors" / "gitleaks").glob("sensor.results.jsonl"))


def test_no_plaintext_secret_reaches_the_api_payload(gitleaks_job):
    """`/report/{job_id}` returns the metrics blob verbatim, so whatever the
    scorer put in it is served."""
    _db, metrics, _job = gitleaks_job
    assert CANARY not in json.dumps(metrics)


def test_no_plaintext_secret_reaches_the_logs(tmp_path, caplog):
    with caplog.at_level(logging.DEBUG, logger="backend.app.bluescrub"):
        redaction.redact(secrets.parse_gitleaks(GITLEAKS_REPORT, tmp_path))
    assert CANARY not in caplog.text


def test_what_the_analyst_sees_instead(gitleaks_job):
    db, _metrics, _job = gitleaks_job
    row = next(r for r in db.scalars(select(Finding)).all() if r.sensor == "gitleaks")
    secret = json.loads(row.evidence_json)["secret"]

    assert secret["masked_value"] == "ghp_…0000"
    assert secret["fingerprint"].startswith("hmac-sha256:")
    assert CANARY not in json.dumps(secret)


# ── code-similarity fingerprinting ────────────────────────────────────────

@pytest.mark.parametrize("category,family", [
    ("fingerprint_patterns", IssueFamily.metadata_leak),
    ("library_fingerprints", IssueFamily.metadata_leak),
    ("compiler_artifacts", IssueFamily.metadata_leak),
    ("function_similarity", IssueFamily.signature_known),
    ("known_tool_similarity", IssueFamily.signature_known),
    ("code_reuse", IssueFamily.attribution_identity),
])
def test_every_similarity_category_is_mapped(category, family):
    """Four of these were `unmapped` — persisted, displayed, and excluded from
    the grade, which is what that state is *for*: review, then map. Reviewed."""
    from backend.app.bluescrub.rulemap import resolve_family

    assert resolve_family("bluescrub_analyzers", category) is family


def test_no_similarity_finding_is_left_unmapped(tmp_path):
    from backend.app.bluescrub.rulemap import resolve_family
    from backend.app.bluescrub.vendored.scanners.analyzers import (
        analyze_directory_for_attribution,
    )

    (tmp_path / "agent.py").write_text(
        "# Author: ada\n"
        '"""Adapted from Cobalt Strike beacon staging."""\n'
        "import requests\n\n"
        "def beacon():  # TODO: finish\n"
        '    print("DEBUG: start")\n'
    )
    records = analyze_directory_for_attribution(str(tmp_path))
    categories = {
        key for record in records for key, value in record.items()
        if isinstance(value, dict) and value.get("found")
    }

    assert categories, "the fixture produced nothing to map"
    for category in categories:
        assert resolve_family("bluescrub_analyzers", category) is not IssueFamily.unmapped


def test_a_habit_marker_does_not_outweigh_a_byline():
    """A codebase of any size holds hundreds of TODO comments. Scoring each at
    the family default is volume standing in for significance — the same shape
    as the failure that produced the critical ceiling."""
    from backend.app.bluescrub.pillars import DetectorClass

    def severity(rule):
        return canonical_severity(
            f"CodeSimilarityDetector.fingerprint_patterns.{rule}",
            IssueFamily.metadata_leak, DetectorClass.regex_pattern,
        )

    assert severity("code_quality_markers") == "info"
    assert severity("developer_note_comments_developer_habit") == "info"
    assert severity("debug_print_statements") == "low"
    assert severity("author_attribution") == "high"


def test_an_author_tag_is_not_disqualifying():
    """The pattern finds the tag, not the name in it. Naming the person is what
    the dirty-word and gitmeta detectors are for."""
    from backend.app.bluescrub.pillars import DetectorClass

    assert canonical_severity(
        "CodeSimilarityDetector.fingerprint_patterns.author_attribution",
        IssueFamily.metadata_leak, DetectorClass.regex_pattern,
    ) != "critical"


def test_similarity_findings_are_attribution_or_detectability():
    """The detector serves two questions — who wrote this, and what will match
    it — and the split has to survive the mapping."""
    from backend.app.bluescrub.pillars import FAMILY_PILLAR
    from backend.app.bluescrub.rulemap import resolve_family

    for category in ("fingerprint_patterns", "library_fingerprints",
                     "compiler_artifacts", "code_reuse"):
        assert FAMILY_PILLAR[resolve_family("bluescrub_analyzers", category)] \
            is Pillar.attribution, category
    for category in ("function_similarity", "known_tool_similarity"):
        assert FAMILY_PILLAR[resolve_family("bluescrub_analyzers", category)] \
            is Pillar.detectability, category


# ── the sprint's scanners are all declared ────────────────────────────────

def test_every_sprint_5_scanner_is_registered_and_manifested():
    from backend.app.bluescrub.registry import SCANNERS

    manifest = json.loads(
        (Path(__file__).resolve().parents[3] / "deploy" / "bluescrub"
         / "tool-manifest.json").read_text()
    )
    declared = {t["name"] for t in manifest["tools"]}

    for name in ("dirty_word", "gitmeta", "gitleaks", "trufflehog", "build_paths"):
        assert name in SCANNERS, name
        assert name in declared, name


def test_the_repo_history_class_declares_how_verification_is_disabled():
    """§G10 requires the flag to be recorded, not assumed."""
    manifest = json.loads(
        (Path(__file__).resolve().parents[3] / "deploy" / "bluescrub"
         / "tool-manifest.json").read_text()
    )
    by_name = {t["name"]: t for t in manifest["tools"]}

    for name in ("gitmeta", "gitleaks", "trufflehog"):
        assert by_name[name]["risk_class"] == "repo_history", name
        assert by_name[name].get("network_verification_flag"), name
    assert by_name["trufflehog"]["network_verification_flag"] == "--no-verification"
