"""Canonical severity — tier 1, and the calibration it encodes.

Before this table existed every finding fell through to the scanner's own
severity string, which is calibrated for services rather than offensive
tooling. The measured result on the sample corpus was a hardcoded C2 address
at "low" and an operator's real email address at "high". These tests pin the
corrected judgements so a future edit has to argue with them.
"""

import json
import pathlib
import tempfile

import pytest

from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import (
    FAMILY_PILLAR,
    SEVERITY_ORDER,
    DetectorClass,
    IssueFamily,
    Pillar,
)
from backend.app.bluescrub.severity_table import (
    SEVERITY_BY_FAMILY,
    SEVERITY_BY_RULE,
    build_impact_modifiers,
    build_rule_mapping,
    canonical_severity,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "bluescrub"


def _f(rule_id, family, sensor="bluescrub_analyzers", raw="LOW", line=1, file="a.py"):
    return RawFinding(
        sensor=sensor, sensor_version="v", rule_id=rule_id, issue_family=family,
        pillar_hint=FAMILY_PILLAR.get(family), detector_class=DetectorClass.regex_pattern,
        raw_severity=raw, confidence=0.6, matched_tokens="x",
        location=Location(kind="source", file=file, start_line=line, start_column=0),
    )


# ── the two judgements that motivated the table ───────────────────────────

def test_hardcoded_c2_outranks_the_scanner_that_called_it_low():
    """Whoever seizes that address inherits every implant pointing at it."""
    raw = [_f("NetworkTrafficAnalyzer.c2_references.x", IssueFamily.hardcoded_c2, raw="LOW")]
    group = canonicalize(raw, project_id="p", rule_mapping=build_rule_mapping(raw)).groups[0]

    assert group.severity == "critical"
    assert group.severity_source == "rule_mapping"


def test_operator_identity_is_disqualifying():
    """A real name or address in shipped code ends deniability."""
    assert canonical_severity("x", IssueFamily.attribution_identity) == "critical"
    assert canonical_severity("x", IssueFamily.attribution_marking) == "critical"


def test_scanner_severity_is_never_used_when_a_mapping_exists():
    """Tier 1 wins outright; the scanner's own string is audit data only."""
    for raw_sev in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raw = [_f("r", IssueFamily.memory_safety, raw=raw_sev)]
        group = canonicalize(raw, project_id="p",
                             rule_mapping=build_rule_mapping(raw)).groups[0]
        assert group.severity == "high", raw_sev
        assert group.members[0].raw_severity == raw_sev  # preserved for audit


# ── table integrity ───────────────────────────────────────────────────────

def test_every_scored_family_has_a_severity():
    """An unmapped family silently falls back to the scanner's guess."""
    missing = [
        f.value for f in IssueFamily
        if f is not IssueFamily.unmapped and f not in SEVERITY_BY_FAMILY
    ]
    assert not missing, f"families with no canonical severity: {missing}"


def test_all_severities_are_on_the_ladder():
    for family, sev in SEVERITY_BY_FAMILY.items():
        assert sev in SEVERITY_ORDER, f"{family.value} -> {sev}"
    for rule, sev in SEVERITY_BY_RULE.items():
        assert sev in SEVERITY_ORDER, f"{rule} -> {sev}"


def test_rule_overrides_beat_their_family():
    rule = "AntiAnalysisValidator.sandbox_evasion.sleep_based_evasion"
    assert SEVERITY_BY_RULE[rule] == "low"
    assert SEVERITY_BY_FAMILY[IssueFamily.anti_analysis] == "medium"
    assert canonical_severity(rule, IssueFamily.anti_analysis) == "low"


def test_only_attribution_and_co_optability_reach_critical():
    """Critical drives disqualification, so the set must stay deliberate."""
    critical = {f for f, s in SEVERITY_BY_FAMILY.items() if s == "critical"}
    pillars = {FAMILY_PILLAR[f] for f in critical}
    assert pillars <= {Pillar.attribution, Pillar.co_optability}, pillars


# ── impact modifiers (tier 2) ─────────────────────────────────────────────

def test_no_modifiers_on_an_ordinary_source_audit():
    raw = [_f("r", IssueFamily.build_path_leak)]
    assert build_impact_modifiers(raw, analysis_kind="source_audit") == {}


def test_captured_artifact_escalates_attribution():
    """A binary recovered from traffic has already shipped: the leak occurred."""
    raw = [_f("r", IssueFamily.build_path_leak)]
    mods = build_impact_modifiers(raw, analysis_kind="re_assessment")

    assert mods["r"] == "critical"
    group = canonicalize(raw, project_id="p", rule_mapping=build_rule_mapping(raw),
                         impact_modifiers=mods).groups[0]
    assert group.severity_source == "impact_modifier"


def test_modifier_does_not_touch_other_pillars():
    raw = [_f("r", IssueFamily.memory_safety)]
    assert build_impact_modifiers(raw, analysis_kind="re_assessment") == {}


def test_modifier_is_clamped_to_one_level():
    """resolve() bounds tier 2 movement; medium cannot jump straight to critical."""
    raw = [_f("r", IssueFamily.forensic_artifact)]          # family default: medium
    mods = build_impact_modifiers(raw, analysis_kind="re_assessment")
    group = canonicalize(raw, project_id="p", rule_mapping=build_rule_mapping(raw),
                         impact_modifiers=mods).groups[0]

    assert group.severity == "high", "medium should step to high, not to critical"


# ── calibration against the real corpus ───────────────────────────────────

@pytest.fixture(scope="module")
def corpus_groups():
    import os
    os.environ["AIPAM_BLUESCRUB_REQUIRE_UID_DROP"] = "false"
    from backend.app.bluescrub.scanners import vendored_analyzers as va

    spec = json.loads((FIXTURES / "sample_repo_spec.json").read_text())
    root = pathlib.Path(tempfile.mkdtemp()) / "repo"
    for rel, content in spec["files"].items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    outcome = va.run(root, root.parent / "out")
    return canonicalize(
        outcome.findings, project_id="calibration",
        rule_mapping=build_rule_mapping(outcome.findings),
    ).groups


def test_whole_corpus_resolves_at_tier_one(corpus_groups):
    """No finding from the shipped corpus should need the fallback tier.

    A fallback means the scanner's own judgement decided, which is exactly what
    this table exists to stop.
    """
    fell_through = {
        g.primary_rule_id for g in corpus_groups
        if g.severity_source in ("precedence", "fallback")
    }
    assert not fell_through, (
        "these rules need an entry in the severity table: " + ", ".join(sorted(fell_through))
    )


def test_corpus_severity_distribution_is_plausible(corpus_groups):
    """A deliberately leaky sample must not grade as mostly-low."""
    severities = [g.severity for g in corpus_groups]
    assert "critical" in severities
    low_or_info = sum(1 for s in severities if s in ("low", "info"))
    assert low_or_info < len(severities) / 2, "most of a leaky corpus rated low"
