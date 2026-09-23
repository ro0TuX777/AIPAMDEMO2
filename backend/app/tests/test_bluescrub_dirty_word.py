"""Dirty-word scanning.

Every other detector guesses what matters; this one is told. That is why these
findings are promoted past the detector-precision ceiling, and why the wordlist
itself needs handling — it holds the codenames and markings being hunted.
"""

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import service as bs_service, wordlists as wl
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.bluescrub.scanners import dirty_word as dw
from backend.app.bluescrub.severity_table import canonical_severity
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'d.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture()
def leaky_job(tmp_path):
    job = tmp_path / "job"
    src = job / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader.c").write_text(
        '/* OPERATION NIGHTFALL, build 3 */\nchar *op = "NIGHTFALL";\n'
    )
    return job


# ── the wordlist is itself sensitive ──────────────────────────────────────

def test_wordlist_is_written_owner_only(tmp_path):
    """It contains the classification markings being hunted."""
    path = dw.write_wordlist(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])
    assert path and (path.stat().st_mode & 0o777) == 0o600


def test_no_terms_writes_no_file(tmp_path):
    assert dw.write_wordlist(tmp_path, []) is None


def test_terms_never_travel_as_argv(monkeypatch, tmp_path):
    """`ps` output is world-readable, so a codename passed as an argument is
    published to every user on the box."""
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env_extra") or {}
        raise RuntimeError("stop here")

    monkeypatch.setattr(dw, "run_analyzer", _fake_run)
    path = dw.write_wordlist(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])
    monkeypatch.setenv(dw.WORDLIST_ENV, str(path))

    with pytest.raises(RuntimeError):
        dw.run(tmp_path, tmp_path / "out")

    assert "NIGHTFALL" not in " ".join(captured["argv"])
    assert "NIGHTFALL" not in json.dumps(captured["env"]), "term passed by value"
    assert captured["env"][dw.WORDLIST_ENV] == str(path), "should be handed by path"


def test_pipeline_removes_the_staged_wordlist(db, leaky_job, monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    wl.create(db, "Ops", [{"term": "NIGHTFALL", "category": "codename"}])
    bs_service.analyze_and_persist(db, "j", leaky_job, profile="triage", run_output_dir=leaky_job)

    assert not (leaky_job / "runtime" / "wordlist.json").exists()
    assert dw.WORDLIST_ENV not in os.environ


# ── absence is not a clean result ─────────────────────────────────────────

def test_no_wordlist_reports_unavailable(tmp_path, monkeypatch):
    """Nothing declared sensitive means the pillar was not assessed against
    operator knowledge — reporting zero findings would imply it had been."""
    monkeypatch.delenv(dw.WORDLIST_ENV, raising=False)
    outcome = dw.run(tmp_path, tmp_path / "out")

    assert outcome.status == "unavailable"
    assert "no dirty-word list" in outcome.reason


# ── category drives family and severity ───────────────────────────────────

@pytest.mark.parametrize("category,family", [
    ("marking", IssueFamily.attribution_marking),
    ("identity", IssueFamily.attribution_identity),
    ("hostname", IssueFamily.attribution_infrastructure),
    ("path", IssueFamily.build_path_leak),
    ("tooling", IssueFamily.signature_known),
])
def test_category_selects_the_family(category, family):
    hits = {"matches": [{"file": "/s/a.c", "word": "X", "line": 1, "context": "X"}]}
    terms = [{"term": "X", "category": category, "list": "L"}]
    finding = dw.parse_hits(hits, terms, Path("/s"))[0]
    assert finding.issue_family is family


def test_tooling_is_a_detectability_problem_not_an_attribution_one():
    """A framework signature is matched by defenders, not traced to an author."""
    from backend.app.bluescrub.pillars import FAMILY_PILLAR

    assert FAMILY_PILLAR[dw.CATEGORY_FAMILY["tooling"]] is Pillar.detectability
    assert FAMILY_PILLAR[dw.CATEGORY_FAMILY["identity"]] is Pillar.attribution


def test_declared_terms_are_promoted_past_the_precision_ceiling():
    """A literal match on a term the operator declared sensitive is the most
    precise signal here — unlike a generic regex matching "C2"."""
    for rule in ("dirty_word.marking", "dirty_word.identity", "dirty_word.codename"):
        assert canonical_severity(
            rule, IssueFamily.attribution_marking, DetectorClass.regex_pattern
        ) == "critical"


def test_weaker_categories_are_not_disqualifying():
    for rule, expected in (("dirty_word.mutex", "medium"),
                           ("dirty_word.ticket", "medium"),
                           ("dirty_word.hostname", "high")):
        assert canonical_severity(
            rule, IssueFamily.forensic_artifact, DetectorClass.regex_pattern
        ) == expected


# ── the term must not leak through rule_id ────────────────────────────────

def test_rule_id_does_not_contain_the_matched_term():
    """rule_id reaches logs, metric keys, and fingerprints. A classification
    marking must not ride along into all three."""
    hits = {"matches": [{"file": "/s/a.c", "word": "NIGHTFALL", "line": 1,
                         "context": "NIGHTFALL"}]}
    finding = dw.parse_hits(hits, [{"term": "NIGHTFALL", "category": "marking"}],
                            Path("/s"))[0]

    assert finding.rule_id == "dirty_word.marking"
    assert "NIGHTFALL" not in finding.rule_id


def test_distinct_terms_in_one_file_stay_distinct():
    hits = {"matches": [
        {"file": "/s/a.c", "word": "NIGHTFALL", "line": 1, "context": "a NIGHTFALL"},
        {"file": "/s/a.c", "word": "RT-2411", "line": 9, "context": "b RT-2411"},
    ]}
    terms = [{"term": "NIGHTFALL", "category": "marking"},
             {"term": "RT-2411", "category": "ticket"}]
    from backend.app.bluescrub.canonicalize import canonicalize

    findings = dw.parse_hits(hits, terms, Path("/s"))
    groups = canonicalize(findings, project_id="p").groups
    assert len(groups) == 2


# ── end to end ────────────────────────────────────────────────────────────

def test_quick_scan_catches_a_leaked_codename(db, leaky_job, monkeypatch):
    """Attribution is in the Quick profile on purpose: a fast scan that finds a
    buffer overflow while missing a classification marking has the priority
    backwards."""
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])

    dacv = bs_service.analyze_and_persist(db, "j", leaky_job, profile="triage", run_output_dir=leaky_job)["dacv"]

    rows = db.scalars(select(Finding).where(Finding.sensor == "dirty_word")).all()
    assert rows, "declared term not found"
    assert all(r.severity == "critical" for r in rows)
    assert dacv["disqualified"] is True
    assert dacv["scoped"]["grade"] == "F"


def test_attribution_is_in_scope_for_quick():
    from backend.app.bluescrub.registry import pillars_in_scope

    assert Pillar.attribution in pillars_in_scope("triage")
