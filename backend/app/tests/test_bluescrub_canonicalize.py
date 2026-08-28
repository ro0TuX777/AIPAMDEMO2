"""Canonicalization and fingerprint stability.

Covers plan §15 acceptance #1, #2, #3, #6, #8, #9 and the data-contract
acceptance list.
"""

from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.fingerprint import (
    context_hash,
    normalize_tokens,
    source_fingerprint,
)
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.tests._bluescrub_schemas import validator as _schema

PROJECT = "11111111-2222-3333-4444-555555555555"


def _finding(
    *, sensor="semgrep", rule_id="R.001", family=IssueFamily.memory_safety,
    file="src/a.c", line=10, symbol=None, tokens="memcpy(dst, src, n)",
    ctx="4024700fd9f055274c529971e23ba54c20b0907c", severity="high", confidence=0.8,
    detector=DetectorClass.ast_pattern, pillar=Pillar.vulnerability,
) -> RawFinding:
    return RawFinding(
        sensor=sensor, sensor_version="1.0", rule_id=rule_id, issue_family=family,
        confidence=confidence, raw_severity=severity, detector_class=detector,
        pillar_hint=pillar, matched_tokens=tokens, context_hash=ctx,
        location=Location(kind="source", file=file, start_line=line,
                          start_column=0, symbol=symbol),
    )


# ── grouping ──────────────────────────────────────────────────────────────

def test_two_scanners_one_bug_collapses_to_one_group():
    """Acceptance #1 — otherwise the score counts installed tools, not risk."""
    findings = [
        _finding(sensor="semgrep", rule_id="sg.overflow", symbol="parse"),
        _finding(sensor="codeql", rule_id="ql.overflow", symbol="parse",
                 detector=DetectorClass.semantic_dataflow),
        _finding(sensor="weggli", rule_id="wg.overflow", symbol="parse",
                 detector=DetectorClass.regex_pattern),
    ]
    result = canonicalize(findings, project_id=PROJECT)

    assert len(result.groups) == 1
    group = result.groups[0]
    assert len(group.members) == 3
    # Highest-authority detector wins, not highest confidence or first seen.
    assert group.primary_sensor == "codeql"
    assert {c.sensor for c in group.corroborating} == {"semgrep", "weggli"}


def test_different_families_never_merge():
    findings = [
        _finding(rule_id="a", family=IssueFamily.memory_safety, symbol="f"),
        _finding(rule_id="b", family=IssueFamily.weak_crypto, symbol="f"),
    ]
    assert len(canonicalize(findings, project_id=PROJECT).groups) == 2


def test_identical_statements_in_one_scope_stay_distinct():
    """Acceptance #2 — and a correctness requirement, given the unique constraint."""
    findings = [
        _finding(line=10, symbol=None, ctx="828d03fb009b2a4057711a54df8b76a1df7074dd"),
        _finding(line=20, symbol=None, ctx="35c5f9719f23b47706ef87e61bf8137d2e9ce8f6"),
    ]
    groups = canonicalize(findings, project_id=PROJECT).groups

    assert len(groups) == 2
    assert len({g.canonical_id for g in groups}) == 2


def test_grouping_is_order_independent():
    """Acceptance #6 — membership must not depend on scanner completion order."""
    findings = [
        _finding(sensor="semgrep", rule_id="a", file="src/x.c", line=1, ctx="2f22765d04931a078909145ca628d2264c852d7d"),
        _finding(sensor="codeql", rule_id="b", file="src/y.c", line=2, ctx="6b1f53303a732ccc8c6aae6640399827c15250e3"),
        _finding(sensor="joern", rule_id="c", file="src/z.c", line=3, ctx="a625406f6977d45c1391b078f4d3656e0b75bfcb"),
    ]
    forward = canonicalize(findings, project_id=PROJECT).groups
    reverse = canonicalize(list(reversed(findings)), project_id=PROJECT).groups

    assert [g.canonical_id for g in forward] == [g.canonical_id for g in reverse]


def test_unmapped_rules_persist_but_are_not_scored():
    findings = [
        _finding(family=IssueFamily.unmapped, pillar=None, rule_id="unknown.rule"),
    ]
    result = canonicalize(findings, project_id=PROJECT)

    assert result.unmapped == 1
    assert len(result.groups) == 1
    assert result.groups[0].scored is False


# ── fingerprint stability ─────────────────────────────────────────────────

def test_unrelated_line_insertion_does_not_change_fingerprint():
    """Acceptance #3 — line numbers are deliberately not part of the key."""
    common = dict(
        project_id=PROJECT, rule_namespace="ns", rule_id="R.1",
        relative_path="src/a.c", enclosing_symbol="parse", node_kind="call",
        normalized_tokens=normalize_tokens("memcpy(dst, src, n)", ".c"),
        context_digest="4024700fd9f055274c529971e23ba54c20b0907c",
    )
    assert source_fingerprint(**common) == source_fingerprint(**common)


def test_changed_literal_does_not_change_fingerprint():
    """Acceptance #4 — literals normalise, so tuning a constant keeps triage."""
    a = normalize_tokens('connect("10.0.0.1", 4444)', ".c")
    b = normalize_tokens('connect("10.0.0.2", 8080)', ".c")
    assert a == b == "connect(<str>, <num>)"


def test_comment_change_does_not_change_tokens():
    a = normalize_tokens("x = 1;  // old note", ".c")
    b = normalize_tokens("x = 1;  // completely different note", ".c")
    assert a == b


def test_unknown_language_keeps_comment_text():
    """Guessing a comment syntax wrong would destabilise the key."""
    text = normalize_tokens("value # not-a-comment-here", ".unknownext")
    assert "not-a-comment-here" in text


def test_case_folding_is_ascii_only():
    """str.lower() is locale-sensitive at the edges; the same file must not
    fingerprint differently on two hosts."""
    assert normalize_tokens("ABC", ".c") == "abc"
    # Non-ASCII uppercase is left alone rather than folded by Unicode rules.
    assert normalize_tokens("İSTANBUL", ".c") == "İstanbul"


def test_context_hash_uses_surrounding_lines_only():
    lines = ["a = 1", "b = 2", "TARGET", "c = 3", "d = 4"]
    changed = ["a = 1", "b = 2", "DIFFERENT TARGET", "c = 3", "d = 4"]
    assert context_hash(lines, 3) == context_hash(changed, 3)


def test_context_hash_changes_when_neighbours_change():
    lines = ["a = 1", "TARGET", "c = 3"]
    moved = ["a = 999", "TARGET", "c = 3"]
    assert context_hash(lines, 2) != context_hash(moved, 2)


def test_binary_fingerprint_survives_rebuild():
    """Acceptance #5 — the artifact SHA is deliberately absent from the key."""
    from backend.app.bluescrub.fingerprint import binary_fingerprint

    common = dict(
        project_id=PROJECT, rule_id="B.1", binary_format="PE32+",
        architecture="x86_64", section=".text", nearest_symbol="sub_401000",
        normalized_value="VirtualAllocEx",
    )
    assert binary_fingerprint(**common) == binary_fingerprint(**common)


# ── schema conformance ────────────────────────────────────────────────────

def test_raw_finding_matches_schema():
    validator = _schema("raw-finding.schema.json")
    validator.validate(_finding().to_dict())


def test_canonical_group_matches_schema():
    validator = _schema("canonical-group.schema.json")
    groups = canonicalize([_finding(), _finding(sensor="codeql", rule_id="q")],
                          project_id=PROJECT).groups
    for group in groups:
        validator.validate(group.to_dict())


def test_canonical_id_shape():
    group = canonicalize([_finding()], project_id=PROJECT).groups[0]
    assert group.canonical_id.startswith("bs-vulnerability-semgrep-")
    assert len(group.canonical_id.rsplit("-", 1)[-1]) == 16
