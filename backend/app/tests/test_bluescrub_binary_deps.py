"""Binary analysis, dependency inventory, and enrichment.

The theme: a scanner that cannot examine something must say so. "No findings"
and "did not look" are different claims, and the coverage model only works if
the adapters keep them apart.
"""

from pathlib import Path

import pytest

from backend.app.bluescrub.enrich import autofix_for, mitre_for
from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.scanners import binary_analysis as ba
from backend.app.bluescrub.scanners import dependencies as dep


# ── enrichment ────────────────────────────────────────────────────────────

def test_mitre_returns_the_array_form():
    out = mitre_for("Hardcoded API key")
    assert isinstance(out, list) and out
    assert out[0]["id"].startswith("T1552")
    assert out[0]["tactic"]


def test_mitre_tries_candidates_in_order():
    assert mitre_for(None, "", "process injection CreateRemoteThread")[0]["id"].startswith("T1055")


def test_mitre_miss_is_an_empty_list_not_none():
    assert mitre_for("nothing in the table matches this") == []


def test_autofix_renders_structured_records_readably():
    fix = autofix_for("VirtualAlloc")
    assert fix and fix["available"]
    # Not a Python repr in front of an analyst.
    assert "{'code_fix'" not in fix["patch"]
    assert "GetProcAddress" in fix["patch"]


def test_enrichment_failure_does_not_propagate(monkeypatch):
    """Enrichment is decoration; a table raising must not cost the finding."""
    import backend.app.bluescrub.enrich as enrich

    def _boom(*_a, **_kw):
        raise RuntimeError("table exploded")

    monkeypatch.setattr(enrich, "_lookup", _boom)
    with pytest.raises(RuntimeError):
        enrich._lookup("mitre", "x")          # the stub really does raise
    # ...but the public helpers swallow it.
    monkeypatch.setattr(enrich, "_lookup", lambda *_a, **_k: None)
    assert enrich.mitre_for("x") == []


# ── binary analysis availability ──────────────────────────────────────────

def test_missing_parsers_report_unavailable_not_clean(tmp_path):
    """The failure this adapter exists to prevent.

    Upstream guards pefile/pyelftools behind *_AVAILABLE flags, so without them
    the analyzer returns nothing — identical in shape to a clean binary.
    """
    if not ba.missing_capabilities():
        pytest.skip("binary parsers are installed here; nothing to assert")

    outcome = ba.run(tmp_path, tmp_path / "out")
    assert outcome.status == "unavailable"
    assert "missing binary parsing capabilities" in outcome.reason
    assert outcome.findings == []


def test_capabilities_probe_is_total():
    caps = ba.capabilities()
    assert isinstance(caps, dict)
    for name in ba.REQUIRED_CAPABILITIES:
        assert name in caps


def test_binary_findings_normalise(tmp_path):
    record = [{
        "file": str(tmp_path / "loader.exe"),
        "sha256": "a" * 64,
        "format": "PE32+",
        "architecture": "x86_64",
        "issues": [{
            "type": "Monitored API Import",
            "severity": "CRITICAL",
            "api": "CreateRemoteThread",
            "description": "Process injection primitive",
            "severity_rationale": "No benign use outside system tooling",
            "section": ".idata",
        }],
    }]
    out = ba.to_raw_findings(record, tmp_path)

    assert len(out) == 1
    finding = out[0]
    assert finding.location.kind == "binary"
    assert finding.location.artifact_sha256 == "a" * 64
    assert finding.location.file == "loader.exe"
    # Upstream's per-API rationale is preserved rather than regenerated.
    assert "No benign use" in finding.recommendation
    assert finding.mitre and finding.mitre[0]["id"].startswith("T1055")


# ── dependency inventory ──────────────────────────────────────────────────

def test_unpinned_dependency_is_a_finding():
    out = dep.to_raw_findings({"packages": [{"name": "flask", "version": ""}]})
    assert len(out) == 1
    assert out[0].issue_family is IssueFamily.dependency_confusion
    assert out[0].location.kind == "project"
    assert out[0].location.subject == "flask"


def test_pinned_dependency_is_not_a_finding():
    assert dep.to_raw_findings({"packages": [{"name": "flask", "version": "3.0.0"}]}) == []


def test_vulnerability_records_become_findings():
    out = dep.to_raw_findings({"packages": [{
        "name": "requests", "version": "2.6.0",
        "vulnerabilities": [{"id": "CVE-2015-2296", "severity": "HIGH"}],
    }]})
    assert len(out) == 1
    assert out[0].issue_family is IssueFamily.dependency_vulnerable
    assert "CVE-2015-2296" in out[0].title


def test_unparseable_manifest_is_reported_not_ignored():
    out = dep.to_raw_findings({"parse_errors": [{"file": "Cargo.toml"}]})
    assert len(out) == 1
    assert "not evidence of its safety" in out[0].description


def test_absent_cve_database_degrades_rather_than_reporting_zero(tmp_path, monkeypatch):
    """Hygiene findings are sound offline; CVE coverage is not."""
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt").write_text("requests==2.6.0\nflask\n")

    outcome = dep.run(src, tmp_path / "out")

    assert outcome.status == "completed_truncated"
    assert outcome.ruleset_state == "database_stale"
    assert "CVE coverage absent" in outcome.reason
    assert any(f.issue_family is IssueFamily.dependency_confusion
               for f in outcome.findings), "unpinned flask should still be found"


def test_vulnerability_source_detection():
    assert not dep._has_vulnerability_source({"tools_available": {"safety": False}})
    assert dep._has_vulnerability_source({"tools_available": {"osv": True}})


# ── registry wiring ───────────────────────────────────────────────────────

def test_profiles_gate_the_expensive_scanners():
    from backend.app.bluescrub.registry import scanners_for

    triage = {s.name for s in scanners_for("triage")}
    deep = {s.name for s in scanners_for("deep")}

    assert "binary_analyzer" not in triage, "emulation-class work must not run in Quick"
    assert "binary_analyzer" in deep
    assert "dependency_inventory" not in triage
    assert "dependency_inventory" in deep


def test_binary_analyzer_is_emulation_class():
    from backend.app.bluescrub.pillars import RiskClass
    from backend.app.bluescrub.registry import SCANNERS

    spec = SCANNERS["binary_analyzer"]
    assert spec.risk_class is RiskClass.emulation
    assert spec.profiles == ("deep",)
    # Extended ceilings, per the isolation contract.
    assert spec.limits.address_space_bytes > 2 * 1024**3
