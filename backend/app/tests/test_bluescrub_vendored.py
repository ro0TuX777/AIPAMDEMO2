"""The vendored BlueScrub engine, and its adapter.

Port fidelity plus the property the port exists to demonstrate: several
analyzers reporting one issue must collapse to one scored finding.
"""

import json
from pathlib import Path

import pytest

from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.rulemap import normalize_label, resolve_family
from backend.app.bluescrub.scanners import vendored_analyzers as va

PROJECT = "vendored-test-project"


@pytest.fixture()
def offensive_repo(tmp_path):
    """A deliberately leaky sample: one planted secret, one planted CWE."""
    root = tmp_path / "src"
    root.mkdir()
    (root / "agent.py").write_text(
        "import os, hashlib\n"
        "API_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "C2 = '10.20.30.40:4444'\n"
        "h = hashlib.md5(data).hexdigest()\n"
    )
    (root / "stager.c").write_text(
        "char buf[64];\nstrcpy(buf, argv[1]);\n"
    )
    return root


# ── the vendored corpus itself ────────────────────────────────────────────

def test_all_declared_analyzers_exist():
    from backend.app.bluescrub.vendored.scanners import analyzers

    for name in va.ANALYZERS:
        assert hasattr(analyzers, name), f"{name} missing from the vendored corpus"
    for cls_name, fn_name in va.SPECIALISED:
        assert hasattr(analyzers, cls_name), f"{cls_name} missing"
        assert hasattr(analyzers, fn_name), f"{fn_name} missing"


def test_only_seven_analyzers_are_baseanalyzer_subclasses():
    """Upstream's README describes ten BaseAnalyzer subclasses. There are seven.

    The other nine expose per-file methods plus module-level directory
    functions, which is why the adapter has two normalisation paths rather than
    one. Pinned so a future re-sync that unifies them is noticed.
    """
    from backend.app.bluescrub.vendored.scanners import analyzers
    from backend.app.bluescrub.vendored.scanners.analyzers.base import BaseAnalyzer

    subclasses = [n for n in va.ANALYZERS
                  if issubclass(getattr(analyzers, n), BaseAnalyzer)]
    standalone = [c for c, _ in va.SPECIALISED
                  if not issubclass(getattr(analyzers, c), BaseAnalyzer)]

    assert len(subclasses) == 7
    assert len(standalone) == 9


def test_vendored_corpus_imports_nothing_excluded():
    """The property scripts/vendor_bluescrub.sh enforces, re-asserted here."""
    root = Path(va.__file__).resolve().parents[1] / "vendored"
    forbidden = ("from flask", "import flask", "from config import",
                 "import config", "from job_manager", "from api.")

    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text()
        for token in forbidden:
            if token in text:
                offenders.append(f"{path.name}: {token}")
    assert not offenders, offenders


def test_analyzers_find_the_planted_issues(offensive_repo):
    from backend.app.bluescrub.vendored.scanners import analyzers

    secrets = analyzers.SecretsAnalyzer().run(str(offensive_repo))
    memory = analyzers.MemorySafetyAnalyzer().run(str(offensive_repo))

    assert secrets, "planted API key not found"
    assert memory, "planted strcpy not found"


# ── adapter normalisation ─────────────────────────────────────────────────

def test_adapter_maps_heterogeneous_shapes(offensive_repo):
    """OpsecAnalyzer uses 'issue'; the others use 'category'."""
    opsec = va.to_raw_findings("OpsecAnalyzer", [
        {"file": str(offensive_repo / "agent.py"), "line": 2,
         "issue": "Hardcoded API key", "pattern": "API_KEY = ...", "severity": "HIGH"},
    ], offensive_repo)
    secrets = va.to_raw_findings("SecretsAnalyzer", [
        {"file": str(offensive_repo / "agent.py"), "line": 2, "category": "api_keys",
         "match": "API_KEY = ...", "severity": "HIGH", "recommended_fix": "use env"},
    ], offensive_repo)

    assert opsec[0].issue_family is IssueFamily.hardcoded_secret
    assert secrets[0].issue_family is IssueFamily.hardcoded_secret
    assert opsec[0].location.file == "agent.py"       # relative to the source root
    assert secrets[0].recommendation == "use env"


def test_adapter_marks_every_analyzer_as_regex_authority():
    """A regex matcher must not outrank a dataflow detector on severity."""
    from backend.app.bluescrub.pillars import DetectorClass

    out = va.to_raw_findings("SecretsAnalyzer", [
        {"file": "/tmp/x.py", "line": 1, "category": "api_keys", "severity": "CRITICAL"},
    ], Path("/tmp"))
    assert out[0].detector_class is DetectorClass.regex_pattern


def test_unknown_label_becomes_unmapped_not_a_guess():
    out = va.to_raw_findings("OpsecAnalyzer", [
        {"file": "/tmp/x.py", "line": 1, "issue": "Some Novel Thing", "severity": "LOW"},
    ], Path("/tmp"))
    assert out[0].issue_family is IssueFamily.unmapped
    assert out[0].pillar_hint is None


def test_findings_without_a_label_are_dropped():
    assert va.to_raw_findings("OpsecAnalyzer", [{"file": "/tmp/x.py"}], Path("/tmp")) == []


# ── the reason canonicalization exists ────────────────────────────────────

def test_three_analyzers_one_secret_collapses_to_one_finding():
    """Real duplication from the real corpus.

    OpsecAnalyzer, SecretsAnalyzer, and CryptoVulnerabilityAnalyzer all report
    the same hardcoded key. Scored raw, it would count three times and the
    pillar would triple for a single leak.
    """
    root = Path("/tmp")
    raw = []
    for analyzer, item in (
        ("OpsecAnalyzer", {"issue": "Hardcoded API key"}),
        ("SecretsAnalyzer", {"category": "api_keys"}),
        ("CryptoVulnerabilityAnalyzer", {"category": "hardcoded_keys"}),
    ):
        item |= {"file": "/tmp/agent.py", "line": 2, "severity": "HIGH",
                 "match": "API_KEY = 'AKIA...'"}
        raw += va.to_raw_findings(analyzer, [item], root)

    assert len(raw) == 3
    result = canonicalize(raw, project_id=PROJECT)

    assert len(result.groups) == 1, "three reports of one secret must be one finding"
    group = result.groups[0]
    # Co-Optability: a credential says what someone else can do, not who wrote
    # the artifact. See FAMILY_PILLAR.
    assert group.pillar is Pillar.co_optability
    assert len(group.members) == 3
    assert len(group.corroborating) == 2


def test_distinct_issues_do_not_collapse():
    root = Path("/tmp")
    raw = (
        va.to_raw_findings("SecretsAnalyzer", [
            {"file": "/tmp/a.py", "line": 2, "category": "api_keys", "severity": "HIGH"},
        ], root)
        + va.to_raw_findings("MemorySafetyAnalyzer", [
            {"file": "/tmp/a.py", "line": 2, "category": "buffer_overflow",
             "severity": "HIGH"},
        ], root)
    )
    # Same file and line, different families — grouping never crosses family.
    assert len(canonicalize(raw, project_id=PROJECT).groups) == 2


# ── isolation ─────────────────────────────────────────────────────────────

def test_analyzers_run_behind_the_process_boundary(offensive_repo, monkeypatch):
    """Contract G1: no analyzer parses attacker source in the worker process."""
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")

    outcome = va.run(offensive_repo, offensive_repo.parent / "out")

    assert outcome.status in ("completed", "completed_truncated"), outcome.reason
    assert outcome.findings, "the sample repo should produce findings"
    families = {f.issue_family for f in outcome.findings}
    assert IssueFamily.hardcoded_secret in families

    written = (offensive_repo.parent / "out" / "sensor.results.jsonl").read_text()
    assert written.strip(), "results must be written to the sensor output dir"
    json.loads(written.splitlines()[0])


def test_analyzer_subprocess_reports_unknown_analyzer_without_raising():
    from backend.app.bluescrub.isolation import analyzer_main
    import io, contextlib

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = analyzer_main.main(["prog", "NoSuchAnalyzer", "/tmp"])

    assert code == 2
    assert json.loads(buf.getvalue())["ok"] is False


# ── specialised scanners ──────────────────────────────────────────────────

SPECIALISED_RECORD = [{
    "file": "/tmp/agent.py",
    "type": "source",
    "embedded_paths": {
        "found": True, "risk": "HIGH",
        "explanation": "Embedded paths reveal the development environment",
        "paths": [{"path": "C:\\Users\\jsmith\\", "type": "Windows username",
                   "risk": "HIGH"}],
        "count": 1,
    },
    "compiler_references": {"found": False, "references": []},
    "contact_info": {
        "found": True, "risk": "HIGH",
        "contact": [{"contact": "jsmith@corp.internal", "type": "Email address",
                     "line": 4, "risk": "HIGH"}],
    },
    # Scalar summary fields are not findings.
    "artifact_risk": "HIGH",
    "obfuscation_score": 0.42,
}]


def test_specialised_records_normalise_to_findings():
    out = va.specialised_to_raw_findings(
        "MetadataLeakageScanner", SPECIALISED_RECORD, Path("/tmp"))

    families = {f.issue_family for f in out}
    assert families == {IssueFamily.build_path_leak, IssueFamily.attribution_identity}
    assert all(f.location.file == "agent.py" for f in out)
    assert any(f.location.start_line == 4 for f in out)


def test_specialised_skips_not_found_and_scalar_fields():
    out = va.specialised_to_raw_findings(
        "MetadataLeakageScanner", SPECIALISED_RECORD, Path("/tmp"))
    # compiler_references is found:False; artifact_risk and obfuscation_score
    # are scalars, not categories.
    assert len(out) == 2
    assert not any("compiler" in f.rule_id for f in out)
    assert not any("artifact_risk" in f.rule_id for f in out)


def test_specialised_prefers_item_severity_over_category_severity():
    record = [{
        "file": "/tmp/a.py",
        "sandbox_evasion": {
            "found": True, "risk": "HIGH",
            "techniques": [{"technique": "Sleep(60000)", "type": "Sleep-based evasion",
                            "line": 6, "effectiveness": "LOW"}],
        },
    }]
    out = va.specialised_to_raw_findings("AntiAnalysisValidator", record, Path("/tmp"))
    assert out[0].raw_severity == "LOW"      # the item's own assessment wins
    assert out[0].issue_family is IssueFamily.anti_analysis


def test_specialised_tolerates_malformed_records():
    junk = ["not a dict", {"file": "/tmp/a.py"}, {"file": "/tmp/a.py", "x": {"found": True}}]
    assert va.specialised_to_raw_findings("X", junk, Path("/tmp")) == []


def test_full_corpus_maps_everything_it_finds(offensive_repo, monkeypatch):
    """No finding from the shipped corpus may land in 'unmapped'.

    An unmapped finding is persisted but never scored, so a growing count is
    silent coverage loss. This holds the mapping table to the corpus.
    """
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    (offensive_repo / "leaky.py").write_text(
        "IsDebuggerPresent()\n"
        "# built by jsmith@corp.internal at C:\\Users\\jsmith\\proj\n"
        "s.connect(('10.1.2.3', 4444))\n"
        "GetTickCount(); Sleep(60000)\n"
    )

    outcome = va.run(offensive_repo, offensive_repo.parent / "out2")
    unmapped = [f for f in outcome.findings if f.issue_family is IssueFamily.unmapped]

    assert not unmapped, (
        "unmapped categories need a reviewed entry in VENDORED_CATEGORY_FAMILY: "
        + ", ".join(sorted({f.rule_id for f in unmapped}))
    )


def test_full_corpus_deduplicates_across_analyzers(offensive_repo, monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    outcome = va.run(offensive_repo, offensive_repo.parent / "out3")
    result = canonicalize(outcome.findings, project_id=PROJECT)

    assert result.collisions == 0
    assert len(result.groups) < len(outcome.findings), (
        "the corpus overlaps heavily; canonicalization should collapse some of it"
    )
    multi = [g for g in result.groups if len({m.rule_namespace for m in g.members}) > 1]
    assert multi, "expected at least one cross-analyzer collapse"
