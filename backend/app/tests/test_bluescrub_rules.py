"""The shipped rule pack must be loadable and correctly mapped.

A malformed rule file makes Semgrep report unavailable, which is
indistinguishable from a clean scan unless something checks.
"""

from pathlib import Path

import pytest
import yaml

from backend.app.bluescrub.pillars import FAMILY_PILLAR, IssueFamily, Pillar
from backend.app.bluescrub.scanners.semgrep import DEFAULT_RULES

RULE_FILES = sorted(DEFAULT_RULES.glob("*.yaml"))


def test_rule_pack_exists():
    assert RULE_FILES, "no rule pack shipped; Semgrep would always report unavailable"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_file_parses(path: Path):
    doc = yaml.safe_load(path.read_text())
    assert doc and doc.get("rules"), f"{path.name} has no rules"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rules_declare_a_known_family(path: Path):
    """Every shipped rule must map to a pillar — none may land in 'unmapped'."""
    for rule in yaml.safe_load(path.read_text())["rules"]:
        family = (rule.get("metadata") or {}).get("bluescrub_family")
        assert family, f"{rule['id']} declares no bluescrub_family"
        parsed = IssueFamily(family)
        assert parsed is not IssueFamily.unmapped
        assert parsed in FAMILY_PILLAR, f"{family} has no pillar"


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_rule_ids_are_namespaced(path: Path):
    for rule in yaml.safe_load(path.read_text())["rules"]:
        assert rule["id"].startswith("bluescrub."), rule["id"]


def test_pack_covers_the_profile_pillars():
    """Sprint 1 profiles claim Vulnerability and Co-Optability; the pack must
    actually reach both, or coverage is a lie."""
    covered = set()
    for path in RULE_FILES:
        for rule in yaml.safe_load(path.read_text())["rules"]:
            family = IssueFamily((rule["metadata"])["bluescrub_family"])
            covered.add(FAMILY_PILLAR[family])

    assert Pillar.vulnerability in covered
    assert Pillar.co_optability in covered


# ── the unmapped backlog ──────────────────────────────────────────────────
#
# `unmapped` is persisted, displayed, and never scored, so a rule sitting in it
# is invisible to the grade while looking like a finding. Measured on a
# 414-file corpus the counter held 287 findings across 20 rules; these pin the
# review that cleared them.

from backend.app.bluescrub.rulemap import (  # noqa: E402
    VENDORED_CATEGORY_FAMILY,
    resolve_family,
)

SENSOR = "bluescrub_analyzers"


@pytest.mark.parametrize("rule,family", [
    # Operator hygiene
    ("hardcoded_username", IssueFamily.attribution_identity),
    ("sensitive_info_in_print_statements", IssueFamily.metadata_leak),
    ("developer_note_with_sensitive_info", IssueFamily.metadata_leak),
    ("sensitive_info_in_logs", IssueFamily.metadata_leak),
    ("hardcoded_log_file_paths", IssueFamily.forensic_artifact),
    ("hardcoded_service_url", IssueFamily.attribution_infrastructure),
    ("network_info", IssueFamily.attribution_infrastructure),
    ("internal_info", IssueFamily.metadata_leak),
    # Exploit construction
    ("bypass_techniques", IssueFamily.signature_known),
    ("heap_sprays", IssueFamily.shellcode_pattern),
    ("stack_pivots", IssueFamily.shellcode_pattern),
    ("predictable_patterns", IssueFamily.signature_trivial),
    # The one that really is a defect in the tool
    ("custom_crypto", IssueFamily.weak_crypto),
])
def test_every_reviewed_rule_is_mapped(rule, family):
    assert resolve_family(SENSOR, rule) is family


def test_exploit_construction_is_detectability_not_vulnerability():
    """A stack pivot in your own exploit is not a bug in your tool; it is a
    pattern a defender writes a rule for. EDR hooks the DEP-override APIs by
    name, and 0x0C0C0C0C is in every heap-spray signature ever written."""
    for rule in ("bypass_techniques", "heap_sprays", "stack_pivots",
                 "predictable_patterns"):
        assert FAMILY_PILLAR[resolve_family(SENSOR, rule)] is Pillar.detectability, rule
    assert FAMILY_PILLAR[resolve_family(SENSOR, "custom_crypto")] is Pillar.vulnerability


def test_a_subtype_resolves_to_its_category():
    """The two normalisation paths disagree about what they pass here:
    specialised analyzers hand over a bare category, pattern analyzers hand
    over the whole label. 125 findings were unmapped because
    `information_disclosure_in_logs` arrived with a subtype glued on."""
    assert resolve_family(SENSOR, "information_disclosure_in_logs") is \
        resolve_family(SENSOR, "information_disclosure_in_logs_f_string_formatting")


def test_the_prefix_match_is_anchored_on_a_separator():
    """Otherwise `system_info` claims `system_information_leak`, and a prefix
    fallback becomes the guess the module docstring refuses to make."""
    assert "system_info" in VENDORED_CATEGORY_FAMILY
    assert resolve_family(SENSOR, "system_informationistic") is IssueFamily.unmapped


def test_the_longest_matching_category_wins():
    """A more specific category must not be shadowed by a shorter one that
    happens to be a prefix of it."""
    keys = sorted(VENDORED_CATEGORY_FAMILY, key=len)
    nested = [
        (short, long) for short in keys for long in keys
        if long.startswith(f"{short}_") and short != long
    ]
    for short, long in nested:
        assert resolve_family(SENSOR, f"{long}_variant") is \
            VENDORED_CATEGORY_FAMILY[long], (short, long)


def test_an_unknown_rule_is_still_unmapped_rather_than_guessed():
    """Clearing the backlog must not turn the counter off."""
    assert resolve_family(SENSOR, "zzz_no_such_category_anywhere") is IssueFamily.unmapped
