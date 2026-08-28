"""The shipped Semgrep pack must actually match something.

`semgrep --validate` only checks syntax. Both of the rules that shipped broken
in Sprint 1 validated cleanly and matched nothing: each had a `pattern-not`
containing a bare metavariable, which matches any expression and therefore
excluded every result. A rule that never fires is worse than a missing rule,
because coverage looks present.

Each rule has one piece of bait in fixtures/bluescrub/semgrep_bait/. If a rule
stops matching its own bait, this fails.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from backend.app.bluescrub.scanners.semgrep import DEFAULT_RULES, parse_output

BAIT = Path(__file__).parent / "fixtures" / "bluescrub" / "semgrep_bait"

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep not installed — the rule pack cannot be exercised",
)


def _rule_ids() -> set[str]:
    ids = set()
    for path in sorted(DEFAULT_RULES.glob("*.yaml")):
        for rule in yaml.safe_load(path.read_text())["rules"]:
            ids.add(rule["id"])
    return ids


@pytest.fixture(scope="module")
def staged_bait(tmp_path_factory) -> Path:
    """Stage the bait outside the repository, as the pipeline stages artifacts.

    Semgrep resolves its project root to the enclosing git repo and applies its
    default ignore list from there, so anything under `backend/app/tests/`
    matches the built-in `tests/` rule and is skipped no matter what sits
    beside it. The real adapter scans a staged job directory outside the repo,
    so the test has to as well or it measures the wrong thing.
    """
    staged = tmp_path_factory.mktemp("bait") / "source"
    shutil.copytree(BAIT, staged)
    return staged


@pytest.fixture(scope="module")
def semgrep_output(staged_bait) -> dict:
    from backend.app.bluescrub.scanners.semgrep import _neutralise_default_ignores

    _neutralise_default_ignores(staged_bait)
    result = subprocess.run(
        ["semgrep", "--json", "--quiet", "--no-git-ignore", "--metrics", "off",
         "--disable-version-check", "--config", str(DEFAULT_RULES), str(staged_bait)],
        capture_output=True, text=True, timeout=600,
    )
    assert result.stdout, f"semgrep produced no output: {result.stderr[-500:]}"
    payload = json.loads(result.stdout)
    assert payload.get("paths", {}).get("scanned"), (
        "semgrep scanned no files — the bait was skipped, not cleared"
    )
    return payload


def test_rule_pack_validates():
    result = subprocess.run(
        ["semgrep", "--validate", "--config", str(DEFAULT_RULES)],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stderr[-500:]


def test_semgrep_reports_no_errors(semgrep_output):
    errors = [e.get("message", "") for e in semgrep_output.get("errors") or []]
    assert not errors, errors[:3]


def test_every_shipped_rule_matches_its_bait(semgrep_output):
    """The regression that motivated this module."""
    from backend.app.bluescrub.scanners.semgrep import normalize_check_id

    fired = {
        normalize_check_id(r["check_id"], str(DEFAULT_RULES))
        for r in semgrep_output.get("results") or []
    }
    silent = sorted(_rule_ids() - fired)
    assert not silent, (
        "these rules matched nothing on their own bait — a rule that never "
        "fires makes coverage look present: " + ", ".join(silent)
    )


def test_no_pattern_not_uses_a_bare_metavariable():
    """The specific defect, caught structurally rather than only by outcome.

    `pattern-not: f($A, $B, $C)` where $C is unconstrained excludes every match
    of the positive pattern. Semgrep validates it happily.
    """
    offenders = []
    for path in sorted(DEFAULT_RULES.glob("*.yaml")):
        for rule in yaml.safe_load(path.read_text())["rules"]:
            for clause in rule.get("patterns") or []:
                expr = clause.get("pattern-not") or clause.get("pattern-not-inside")
                if not expr or not isinstance(expr, str):
                    continue
                # A bare metavariable argument with no accompanying constraint.
                bare = [
                    tok.strip(" ()")
                    for tok in expr.replace(",", " ").split()
                    if tok.strip(" ()").startswith("$")
                ]
                constrained = json.dumps(rule)
                for meta in bare:
                    if f'"{meta}"' not in constrained.replace('"pattern-not"', ""):
                        continue
                if bare and "sizeof" not in expr and "..." not in expr:
                    offenders.append(f"{rule['id']}: {expr.strip()[:60]}")
    assert not offenders, (
        "pattern-not containing an unconstrained metavariable excludes "
        "everything: " + "; ".join(offenders)
    )


def test_adapter_normalises_real_semgrep_output(semgrep_output, staged_bait):
    """The adapter is exercised against genuine output, not a hand-written fixture."""
    findings = parse_output(semgrep_output, staged_bait, str(DEFAULT_RULES))

    assert findings, "adapter dropped every finding"
    assert all(f.sensor == "semgrep" for f in findings)
    assert all(f.location.file and not f.location.file.startswith("/") for f in findings)
    assert all(f.location.start_line for f in findings)

    families = {f.issue_family.value for f in findings}
    assert "unmapped" not in families, f"shipped rules must map: {families}"


def test_bait_covers_every_rule():
    """Bait and rules must not drift apart."""
    bait_text = "\n".join(p.read_text() for p in BAIT.iterdir())
    for rule_id in _rule_ids():
        short = rule_id.rsplit(".", 1)[-1]
        assert short in bait_text, f"no bait comment references {short}"


def test_rule_id_is_independent_of_where_the_pack_lives():
    """rule_id feeds the fingerprint; a path-derived id would orphan triage."""
    from backend.app.bluescrub.scanners.semgrep import normalize_check_id

    reported = ("backend.app.bluescrub.rules.bluescrub."
                "bluescrub.vuln.unchecked-memcpy")
    assert normalize_check_id(reported, "backend/app/bluescrub/rules/bluescrub") == \
        "bluescrub.vuln.unchecked-memcpy"
    # Same answer if the pack moves and the config path is not supplied.
    assert normalize_check_id(reported) == "bluescrub.vuln.unchecked-memcpy"
    # A third-party id with no bluescrub namespace is left alone.
    assert normalize_check_id("python.lang.security.audit.exec") == \
        "python.lang.security.audit.exec"
