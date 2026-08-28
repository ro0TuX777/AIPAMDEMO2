"""Sprint 2 acceptance: the vendored engine matches upstream.

Layer 1 of the five-layer differential design — raw parity, the only layer
that is an upstream-fidelity gate. The later layers are expected to differ:
canonicalization deliberately produces a *smaller* set, so comparing there
would be comparing against the wrong thing.

The baseline was captured by running upstream's own ``scanners/`` package,
outside this repository, against the same fixture. A diff here means the
vendored engine's behaviour changed — from a re-sync, an accidental edit
inside ``vendored/``, or damage from the import rewrite.
"""

import json
from pathlib import Path

import pytest

from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.pillars import IssueFamily
from backend.app.bluescrub.scanners import vendored_analyzers as va

FIXTURES = Path(__file__).parent / "fixtures" / "bluescrub"
BASELINE = json.loads((FIXTURES / "upstream_baseline.json").read_text())
SPEC = json.loads((FIXTURES / "sample_repo_spec.json").read_text())


@pytest.fixture(scope="module")
def sample_repo(tmp_path_factory):
    root = tmp_path_factory.mktemp("differential") / "repo"
    for rel, content in SPEC["files"].items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root


def _vendored_signature(analyzer: str, directory: Path) -> list[list[str]]:
    """Same shape the baseline records: (label, line) pairs, sorted."""
    from backend.app.bluescrub.vendored.scanners import analyzers as A

    findings = getattr(A, analyzer)().run(str(directory))
    return sorted(
        [f.get("category") or f.get("issue") or "", str(f.get("line") or "")]
        for f in findings
    )


@pytest.mark.parametrize("analyzer", sorted(BASELINE["analyzers"]))
def test_raw_parity_with_upstream(analyzer, sample_repo):
    expected = BASELINE["analyzers"][analyzer]
    if isinstance(expected, str):
        pytest.skip(f"upstream itself errored for {analyzer}: {expected}")

    actual = _vendored_signature(analyzer, sample_repo)
    assert actual == [list(pair) for pair in expected], (
        f"{analyzer} diverged from upstream @ {BASELINE['upstream_commit'][:12]}. "
        "Either the pin moved and the baseline needs regenerating with a reviewed "
        "diff, or something edited vendored/ in place."
    )


def test_baseline_is_not_empty():
    """A baseline of nothing would pass forever without testing anything."""
    total = sum(len(v) for v in BASELINE["analyzers"].values() if isinstance(v, list))
    assert total >= 10, f"baseline has only {total} findings; the fixture stopped biting"


def test_baseline_pin_matches_vendor_record():
    """The baseline and VENDOR.md must describe the same upstream commit."""
    vendor = (Path(__file__).resolve().parents[1] / "bluescrub" / "VENDOR.md").read_text()
    assert BASELINE["upstream_commit"] in vendor, (
        "baseline was captured from a different commit than VENDOR.md records"
    )


# ── layer 3: canonicalization is expected to differ, in one direction ──────

def test_canonicalization_reduces_and_never_invents(sample_repo, monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    outcome = va.run(sample_repo, sample_repo.parent / "out")
    result = canonicalize(outcome.findings, project_id="differential")

    assert result.groups, "the fixture should produce findings"
    assert len(result.groups) <= len(outcome.findings), (
        "canonicalization may only collapse; it must never create findings"
    )
    assert result.collisions == 0
    assert not [g for g in result.groups if g.issue_family is IssueFamily.unmapped]


def test_planted_issues_are_all_found(sample_repo, monkeypatch):
    """The fixture plants one of each; a silent regression drops one."""
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    outcome = va.run(sample_repo, sample_repo.parent / "out2")
    families = {f.issue_family for f in outcome.findings}

    for expected in (
        IssueFamily.hardcoded_secret,        # AKIA... in tasks.py
        IssueFamily.memory_safety,           # strcpy in beacon.c
        IssueFamily.weak_crypto,             # md5 in tasks.py
        IssueFamily.anti_analysis,           # IsDebuggerPresent in evade.py
        IssueFamily.attribution_identity,    # jsmith@corp.internal
    ):
        assert expected in families, f"planted {expected.value} was not found"
