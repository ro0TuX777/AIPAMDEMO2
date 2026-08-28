"""External analysis tools: OSV-Scanner, Grype, Syft.

None of them are installed here, and writing adapters that can only report
`unavailable` would test nothing. The parsers are pure functions, so they are
exercised against recorded tool output instead — which is where the Semgrep
adapter's three defects actually lived.
"""

from pathlib import Path

import pytest

from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.scanners import deps_cve, sbom
from backend.app.bluescrub.scanners.external import ExternalTool, run_external

ROOT = Path("/srv/artifact")


# ── OSV-Scanner ───────────────────────────────────────────────────────────

OSV_OUTPUT = {
    "results": [{
        "source": {"path": "/srv/artifact/requirements.txt", "type": "lockfile"},
        "packages": [{
            "package": {"name": "requests", "version": "2.6.0", "ecosystem": "PyPI"},
            "groups": [{"ids": ["GHSA-x"], "max_severity": "8.1"}],
            "vulnerabilities": [{
                "id": "GHSA-x", "aliases": ["CVE-2015-2296"],
                "summary": "Session fixation via crafted Set-Cookie",
                "severity": [{"type": "CVSS_V3", "score": "8.1"}],
            }],
        }],
    }],
}


def test_osv_parses_a_vulnerability():
    findings = deps_cve.parse_osv(OSV_OUTPUT, ROOT)

    assert len(findings) == 1
    f = findings[0]
    assert f.sensor == "osv"
    assert f.rule_id == "osv.GHSA-x"
    assert f.issue_family is IssueFamily.dependency_vulnerable
    assert f.pillar_hint is Pillar.co_optability
    assert f.location.kind == "project"
    assert f.location.subject == "requests@2.6.0"
    assert "CVE-2015-2296" in f.description


def test_osv_severity_comes_from_the_group_not_the_vulnerability():
    """max_severity lives on groups[]. Reading it off the vulnerability yields
    "" for every finding and silently flattens the report to MEDIUM."""
    payload = {"results": [{"packages": [{
        "package": {"name": "p", "version": "1"},
        "groups": [{"max_severity": "9.5"}],
        "vulnerabilities": [{"id": "V-1", "summary": "s"}],   # no severity here
    }]}]}
    assert deps_cve.parse_osv(payload, ROOT)[0].raw_severity == "CRITICAL"


def test_cvss_vector_string_is_not_mistaken_for_a_score():
    """A vector string parses as a float only if you do not check."""
    assert deps_cve._cvss_band("CVSS:3.1/AV:N/AC:L") == "MEDIUM"
    assert deps_cve._cvss_band("9.8") == "critical"
    assert deps_cve._cvss_band("") == "MEDIUM"


def test_osv_skips_entries_with_no_package_or_id():
    payload = {"results": [{"packages": [
        {"package": {"version": "1"}, "vulnerabilities": [{"id": "V"}]},   # no name
        {"package": {"name": "p"}, "vulnerabilities": [{"summary": "x"}]},  # no id
    ]}]}
    assert deps_cve.parse_osv(payload, ROOT) == []


def test_osv_tolerates_an_empty_report():
    assert deps_cve.parse_osv({}, ROOT) == []
    assert deps_cve.parse_osv({"results": []}, ROOT) == []


# ── Grype ─────────────────────────────────────────────────────────────────

GRYPE_OUTPUT = {
    "matches": [{
        "vulnerability": {
            "id": "CVE-2018-1000656", "severity": "High",
            "description": "Flask denial of service",
            "fix": {"versions": ["0.12.3"], "state": "fixed"},
        },
        "artifact": {"name": "flask", "version": "0.12", "type": "python"},
    }],
}


def test_grype_parses_a_match_and_surfaces_the_fix():
    findings = deps_cve.parse_grype(GRYPE_OUTPUT, ROOT)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "grype.CVE-2018-1000656"
    assert f.raw_severity == "HIGH"
    assert f.location.subject == "flask@0.12"
    assert "Fixed in 0.12.3" in f.description


def test_grype_severity_words_map_onto_the_ladder():
    for word, expected in (("Critical", "CRITICAL"), ("Negligible", "LOW"),
                           ("Unknown", "MEDIUM"), ("", "MEDIUM")):
        payload = {"matches": [{"vulnerability": {"id": "V", "severity": word},
                                "artifact": {"name": "p", "version": "1"}}]}
        assert deps_cve.parse_grype(payload, ROOT)[0].raw_severity == expected, word


def test_osv_and_grype_findings_for_one_cve_collapse():
    """Both tools are run deliberately; canonicalization absorbs the overlap."""
    from backend.app.bluescrub.canonicalize import canonicalize

    raw = (deps_cve.parse_osv(
               {"results": [{"packages": [{
                   "package": {"name": "flask", "version": "0.12"},
                   "groups": [{"max_severity": "7.5"}],
                   "vulnerabilities": [{"id": "CVE-2018-1000656", "summary": "dos"}]}]}]},
               ROOT)
           + deps_cve.parse_grype(GRYPE_OUTPUT, ROOT))

    assert len(raw) == 2
    groups = canonicalize(raw, project_id="p").groups
    assert len(groups) == 1, "same CVE on the same package must be one finding"
    assert {m.sensor for m in groups[0].members} == {"osv", "grype"}


# ── Syft ──────────────────────────────────────────────────────────────────

SYFT_OUTPUT = {
    "artifacts": [
        {"name": "requests", "version": "2.6.0", "type": "python",
         "locations": [{"path": "/srv/artifact/requirements.txt"}]},
        {"name": "vendored-thing", "version": "0.1", "type": "python",
         "locations": [{"path": "/srv/artifact/third_party/vendored_thing/__init__.py"}]},
        {"name": "libssl", "version": "1.1", "type": "binary",
         "locations": [{"path": "/srv/artifact/libssl.so"}]},
    ],
}


def test_syft_flags_only_the_undeclared_package():
    """An inventory finding per package would bury the report."""
    findings = sbom.parse_syft(SYFT_OUTPUT, ROOT)

    assert len(findings) == 1
    assert findings[0].location.subject == "vendored-thing@0.1"
    assert findings[0].issue_family is IssueFamily.dependency_confusion


def test_syft_ignores_ecosystems_with_no_manifest_concept():
    """A bare .so has no manifest to be absent from."""
    payload = {"artifacts": [{"name": "libc", "version": "2.3", "type": "binary",
                              "locations": [{"path": "/x/libc.so"}]}]}
    assert sbom.parse_syft(payload, ROOT) == []


def test_syft_writes_the_sbom_as_a_report_artifact(tmp_path):
    written = sbom.write_sbom(SYFT_OUTPUT, tmp_path / "report")
    assert written and written.exists()
    assert "vendored-thing" in written.read_text()


# ── the shared harness ────────────────────────────────────────────────────

def test_missing_binary_reports_unavailable_not_clean(tmp_path):
    tool = ExternalTool(sensor="ghost", binary="definitely-not-installed-xyz",
                        argv=lambda r: [], parse=lambda p, r: [])
    outcome = run_external(tool, tmp_path, tmp_path / "out")

    assert outcome.status == "unavailable"
    assert "not on PATH" in outcome.reason
    assert outcome.findings == []


def test_finding_exit_codes_are_not_read_as_a_crash():
    """osv-scanner and grype exit 1 when they find something. Treating that as
    a crash would degrade the pillar every time the tool worked."""
    assert 1 in deps_cve.OSV.finding_exit_codes
    assert 1 in deps_cve.GRYPE.finding_exit_codes
    assert 1 not in sbom.SYFT.finding_exit_codes   # syft has no findings to signal


def test_parser_failure_is_contained_and_quarantined(tmp_path, monkeypatch):
    """A parser bug degrades one scanner; it must not fail the job."""
    import shutil as _shutil
    from backend.app.bluescrub.isolation import AnalyzerResult, AnalyzerStatus

    def _boom(payload, root):
        raise ValueError("parser exploded")

    tool = ExternalTool(sensor="boomer", binary="sh", argv=lambda r: ["-c", "echo {}"],
                        parse=_boom)
    monkeypatch.setattr(_shutil, "which", lambda n: "/bin/sh")
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")

    out = tmp_path / "out"
    outcome = run_external(tool, tmp_path, out)

    assert outcome.status == "unparseable"
    assert "parser exploded" in outcome.reason
    assert (out / "boomer.unparseable.raw").exists(), "raw output must be kept"


# ── registry wiring ───────────────────────────────────────────────────────

def test_cve_scanners_are_optional_so_installing_one_cannot_move_the_score():
    from backend.app.bluescrub.registry import SCANNERS, required_for

    for name in ("osv", "grype", "syft"):
        assert SCANNERS[name].optional, f"{name} must not gate coverage"
    assert "osv" not in required_for(Pillar.co_optability, "deep")


def test_syft_is_deep_only():
    from backend.app.bluescrub.registry import SCANNERS

    assert SCANNERS["syft"].profiles == ("deep",)


# ── the offline tool manifest (G10) ───────────────────────────────────────

def test_tool_manifest_validates():
    import json

    from backend.app.tests._bluescrub_schemas import validator

    manifest = json.loads(
        (Path(__file__).resolve().parents[3] / "deploy" / "bluescrub"
         / "tool-manifest.json").read_text()
    )
    validator("tool-manifest.schema.json").validate(manifest)


def test_every_registered_scanner_has_a_manifest_entry():
    """A registry entry with no manifest entry is how a tool reaches an
    air-gapped deployment with no recorded provenance."""
    import json

    from backend.app.bluescrub.registry import SCANNERS

    manifest = json.loads(
        (Path(__file__).resolve().parents[3] / "deploy" / "bluescrub"
         / "tool-manifest.json").read_text()
    )
    declared = {t["name"] for t in manifest["tools"]}
    # The manifest names the binary; the registry names the scanner.
    aliases = {"osv": "osv-scanner"}
    missing = [
        name for name in SCANNERS
        if aliases.get(name, name) not in declared
    ]
    assert not missing, f"scanners with no manifest entry: {missing}"


def test_no_manifest_entry_has_unknown_redistribution():
    """The bundle build fails on 'unknown'; catch it before the build does."""
    import json

    manifest = json.loads(
        (Path(__file__).resolve().parents[3] / "deploy" / "bluescrub"
         / "tool-manifest.json").read_text()
    )
    unknown = [t["name"] for t in manifest["tools"]
               if t["redistribution"] == "unknown"]
    assert not unknown, unknown


def test_optional_flags_agree_between_registry_and_manifest():
    """Disagreement means the score depends on a tool the bundle calls optional."""
    import json

    from backend.app.bluescrub.registry import SCANNERS

    manifest = json.loads(
        (Path(__file__).resolve().parents[3] / "deploy" / "bluescrub"
         / "tool-manifest.json").read_text()
    )
    aliases = {"osv-scanner": "osv"}
    for entry in manifest["tools"]:
        name = aliases.get(entry["name"], entry["name"])
        if name not in SCANNERS:
            continue
        assert bool(entry.get("optional", False)) == SCANNERS[name].optional, (
            f"{name}: manifest optional={entry.get('optional', False)}, "
            f"registry optional={SCANNERS[name].optional}"
        )
