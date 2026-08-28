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
