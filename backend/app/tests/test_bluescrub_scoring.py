"""Coverage-aware scoring.

Covers plan §15 acceptance #1, #4, #5, #16, #20 and the scoring-spec acceptance
list. The invariant under test throughout: an unchanged artifact must score
identically regardless of which *optional* tooling happens to be installed.
"""

import hashlib

import pytest

from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar, PillarStatus
from backend.app.bluescrub.scoring import (
    RE_SIGNAL_WEIGHTS,
    ReSignal,
    ScannerRun,
    score_job,
)
from backend.app.tests._bluescrub_schemas import validator as _schema

PROJECT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CTX = hashlib.sha1(b"ctx").hexdigest()

ALL_PILLARS = (
    Pillar.detectability, Pillar.attribution,
    Pillar.co_optability, Pillar.vulnerability,
)


def _f(*, sensor="semgrep", rule_id="R.1", family=IssueFamily.memory_safety,
       pillar=Pillar.vulnerability, severity="high", confidence=0.8,
       detector=DetectorClass.ast_pattern, file="src/a.c", line=10,
       symbol=None, tokens="memcpy(a,b,n)"):
    return RawFinding(
        sensor=sensor, sensor_version="1.0", rule_id=rule_id, issue_family=family,
        confidence=confidence, raw_severity=severity, detector_class=detector,
        pillar_hint=pillar, matched_tokens=tokens, context_hash=CTX,
        location=Location(kind="source", file=file, start_line=line,
                          start_column=0, symbol=symbol),
    )


def _runs(*sensors, pillars=ALL_PILLARS, status="completed", optional=False):
    return [
        ScannerRun(sensor=s, status=status, required_for=tuple(pillars), optional=optional)
        for s in sensors
    ]


def _score(findings, runs, **kw):
    optional = frozenset(r.sensor for r in runs if r.optional)
    result = canonicalize(findings, project_id=PROJECT, optional_sensors=optional)
    return score_job(
        result.groups, runs, profile=kw.pop("profile", "deep"),
        unmapped=result.unmapped, collisions=result.collisions, **kw,
    )["dacv"]


# ── coverage semantics ────────────────────────────────────────────────────

def test_unassessed_pillar_scores_null_not_zero():
    """Acceptance #20 — zero means 'measured, nothing found'."""
    dacv = _score([_f()], _runs("semgrep", pillars=(Pillar.vulnerability,)))

    assert dacv["pillars"]["Attribution"]["status"] == "not_assessed"
    assert dacv["pillars"]["Attribution"]["score"] is None
    assert dacv["pillars"]["Vulnerability"]["score"] is not None


def test_incomplete_coverage_yields_no_overall_grade():
    """Acceptance #4 — a Quick scan must not present an artifact-level grade."""
    dacv = _score([_f()], _runs("semgrep", pillars=(Pillar.vulnerability,)),
                  profile="triage")

    assert dacv["overall"]["status"] == "incomplete"
    assert dacv["overall"]["score"] is None
    assert dacv["overall"]["grade"] is None
    # but the scoped grade is still there, and labelled.
    assert dacv["scoped"]["grade"] in "ABCDF"
    assert dacv["scoped"]["pillars_assessed"] < 5
    assert "of 5 pillars assessed" in dacv["scoped"]["label"]


def test_failed_required_scanner_degrades_pillar():
    runs = [
        ScannerRun("semgrep", "completed", required_for=ALL_PILLARS),
        ScannerRun("codeql", "timeout", required_for=(Pillar.vulnerability,)),
    ]
    dacv = _score([_f()], runs)

    assert dacv["pillars"]["Vulnerability"]["status"] == "degraded"
    assert dacv["pillars"]["Vulnerability"]["coverage"] < 1.0
    assert dacv["partial"] is True
    assert dacv["partial_reasons"][0]["sensor"] == "codeql"


def test_truncated_output_degrades_but_still_scores():
    runs = [ScannerRun("semgrep", "completed_truncated", required_for=ALL_PILLARS)]
    dacv = _score([_f()], runs)

    assert dacv["pillars"]["Vulnerability"]["status"] == "degraded"
    assert dacv["pillars"]["Vulnerability"]["score"] is not None


def test_stale_rules_degrade_the_pillar():
    runs = [ScannerRun("semgrep", "completed", required_for=ALL_PILLARS,
                       ruleset_state="database_stale")]
    dacv = _score([_f()], runs)
    assert dacv["pillars"]["Vulnerability"]["status"] == "degraded"


# ── the machine-independence invariant ────────────────────────────────────

def test_optional_scanner_does_not_change_the_score():
    """Acceptance #16 — the property the whole scoring design protects."""
    base = [_f(sensor="semgrep", rule_id="sg.1", symbol="parse")]
    corroborated = base + [
        _f(sensor="codeql", rule_id="ql.1", symbol="parse",
           detector=DetectorClass.semantic_dataflow, confidence=0.95),
    ]
    runs = _runs("semgrep")
    runs_with_optional = runs + [
        ScannerRun("codeql", "completed", required_for=(), optional=True)
    ]

    without = _score(base, runs)
    with_extra = _score(corroborated, runs_with_optional)

    assert without["pillars"]["Vulnerability"]["score"] == \
        with_extra["pillars"]["Vulnerability"]["score"]
    assert without["scoped"]["score"] == with_extra["scoped"]["score"]


def test_optional_detector_corroborates_but_never_becomes_primary():
    """The mechanism behind the invariant above.

    A higher-authority, higher-confidence optional detector must not take over
    severity or confidence from the required detector that also found the
    issue.
    """
    findings = [
        _f(sensor="semgrep", rule_id="sg.1", symbol="parse", confidence=0.8),
        _f(sensor="codeql", rule_id="ql.1", symbol="parse",
           detector=DetectorClass.semantic_dataflow, confidence=0.95),
    ]
    result = canonicalize(findings, project_id=PROJECT,
                          optional_sensors=frozenset({"codeql"}))

    group = result.groups[0]
    assert group.primary_sensor == "semgrep"
    assert group.scoring_confidence == 0.8
    assert [c.sensor for c in group.corroborating] == ["codeql"]


def test_optional_only_group_still_gets_a_primary():
    """A finding no required scanner saw is new information, not corroboration.

    The invariant covers overlapping detections; a genuinely new finding from an
    optional tool legitimately affects the score.
    """
    findings = [_f(sensor="codeql", rule_id="ql.only",
                   detector=DetectorClass.semantic_dataflow, confidence=0.9)]
    result = canonicalize(findings, project_id=PROJECT,
                          optional_sensors=frozenset({"codeql"}))

    assert result.groups[0].primary_sensor == "codeql"
    assert result.groups[0].scoring_confidence == 0.9


def test_corroboration_is_recorded_but_not_scored():
    findings = [
        _f(sensor="semgrep", rule_id="sg.1", symbol="parse"),
        _f(sensor="gitleaks", rule_id="gl.1", symbol="parse",
           detector=DetectorClass.regex_pattern),
    ]
    result = canonicalize(findings, project_id=PROJECT)
    assert len(result.groups) == 1
    group = result.groups[0]

    assert len(group.corroborating) == 1
    # Confidence comes from the primary detector alone.
    assert group.scoring_confidence == 0.8


# ── caps ──────────────────────────────────────────────────────────────────

def test_noisy_rule_scores_below_severe_distinct_rules():
    """Acceptance #2 of the scoring spec — volume must not beat severity."""
    noisy = [
        _f(rule_id="noisy", severity="low", file=f"src/f{i}.c", line=i,
           symbol=f"fn{i}")
        for i in range(200)
    ]
    severe = [
        _f(rule_id=f"crit.{i}", severity="critical", file=f"src/c{i}.c",
           line=i, symbol=f"cfn{i}")
        for i in range(20)
    ]
    runs = _runs("semgrep")

    noisy_score = _score(noisy, runs)["pillars"]["Vulnerability"]["score"]
    severe_score = _score(severe, runs)["pillars"]["Vulnerability"]["score"]

    assert noisy_score < severe_score


def test_capped_groups_are_reported():
    findings = [
        _f(rule_id="same", file=f"src/f{i}.c", line=i, symbol=f"fn{i}")
        for i in range(12)
    ]
    dacv = _score(findings, _runs("semgrep"))
    assert dacv["caps_applied"]["rule_cap"] > 0


# ── RE-Feasibility signal model ───────────────────────────────────────────

def test_missing_re_signal_changes_coverage_not_other_signals():
    """Acceptance #5 — weights are reported when absent, never redistributed."""
    full = [ReSignal(name, 1.0) for name in RE_SIGNAL_WEIGHTS]
    without_ghidra = [
        ReSignal(name, 1.0) for name in RE_SIGNAL_WEIGHTS if name != "decompilation"
    ] + [ReSignal("decompilation", None, "ghidra_not_installed")]

    a = _score([], _runs("semgrep"), re_signals=full)["pillars"]["RE-Feasibility"]
    b = _score([], _runs("semgrep"),
               re_signals=without_ghidra)["pillars"]["RE-Feasibility"]

    assert a["coverage"] == pytest.approx(1.0)
    assert b["coverage"] == pytest.approx(0.85)
    assert b["status"] == "degraded"
    assert b["unavailable_signals"][0]["signal"] == "decompilation"
    assert b["unavailable_signals"][0]["weight"] == 0.15
    # All-1.0 signals normalise to 100 either way: the absent weight is not
    # handed to the signals that happen to be installed.
    assert a["score"] == b["score"] == 100


def test_re_effort_bands():
    cases = {0.0: "Weeks", 0.4: "Days", 0.7: "Hours", 1.0: "Trivial"}
    for value, expected in cases.items():
        signals = [ReSignal(name, value) for name in RE_SIGNAL_WEIGHTS]
        pillar = _score([], _runs("semgrep"), re_signals=signals)["pillars"]["RE-Feasibility"]
        assert pillar["effort_band"] == expected, value


def test_no_re_signals_is_not_assessed():
    pillar = _score([], _runs("semgrep"), re_signals=[])["pillars"]["RE-Feasibility"]
    assert pillar["status"] == "not_assessed"
    assert pillar["score"] is None


# ── disqualification ──────────────────────────────────────────────────────

def test_critical_attribution_disqualifies_even_a_quick_scan():
    """A classification marking must not report 'Quick profile: B'."""
    findings = [
        _f(sensor="dirty_word", rule_id="DW.CODENAME",
           family=IssueFamily.attribution_marking, pillar=Pillar.attribution,
           severity="critical", confidence=0.95),
    ]
    dacv = _score(findings, _runs("dirty_word", pillars=(Pillar.attribution,)),
                  profile="triage")

    assert dacv["disqualified"] is True
    assert dacv["scoped"]["grade"] == "F"
    assert dacv["grade_override"]["reason"] == "critical_attribution_exposure"


def test_no_disqualification_without_critical_attribution():
    dacv = _score([_f(severity="critical")], _runs("semgrep"))
    assert dacv["disqualified"] is False
    assert "grade_override" not in dacv


# ── schema conformance ────────────────────────────────────────────────────

def test_metrics_match_schema():
    findings = [_f(), _f(sensor="gitleaks", rule_id="gl.1",
                         family=IssueFamily.hardcoded_secret,
                         pillar=Pillar.attribution, file="cfg.py", symbol="load")]
    runs = _runs("semgrep", "gitleaks")
    signals = [ReSignal(name, 0.5) for name in RE_SIGNAL_WEIGHTS]

    result = canonicalize(findings, project_id=PROJECT)
    metrics = score_job(result.groups, runs, profile="deep",
                        re_signals=signals, project_id=PROJECT, files_scanned=42)

    _schema("dacv-metrics.schema.json").validate(metrics)


def test_unmapped_findings_counted_and_excluded():
    findings = [
        _f(),
        _f(sensor="mystery", rule_id="??", family=IssueFamily.unmapped,
           pillar=None, file="src/z.c", symbol="zz"),
    ]
    dacv = _score(findings, _runs("semgrep"))
    assert dacv["unmapped_findings"] == 1
