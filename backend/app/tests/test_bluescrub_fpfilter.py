"""False-positive suppression.

The measured problem at scale was noise, not missing detection. The measured
danger of fixing it is over-suppression, so most of these tests assert what
must survive rather than what must go.
"""

import pytest

from backend.app.bluescrub import fpfilter
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily


def _f(family, path, token, kind="source"):
    loc = (
        Location(kind="source", file=path, start_line=1, start_column=0)
        if kind == "source"
        else Location(kind="project", subject=path)
    )
    return RawFinding(
        sensor="s", sensor_version="v", rule_id="r", issue_family=family,
        pillar_hint=None, detector_class=DetectorClass.regex_pattern,
        raw_severity="HIGH", confidence=0.6, matched_tokens=token, location=loc,
    )


# ── what must survive ─────────────────────────────────────────────────────

def test_real_operator_identity_survives():
    kept = fpfilter.apply([
        _f(IssueFamily.attribution_identity, "src/agent.py", "jsmith@corp.internal")
    ]).kept
    assert len(kept) == 1


def test_home_directory_leak_survives():
    """The vendored is_false_positive_path helper would suppress this.

    It treats anything under /home/ as noise, which is right for defensive
    appsec and exactly wrong here — /home/<username>/ in source is the
    attribution leak. It found a real one in AIPAM's own training_routes.py.
    """
    kept = fpfilter.apply([
        _f(IssueFamily.build_path_leak, "src/train.py", "/home/bc/")
    ]).kept
    assert len(kept) == 1


def test_test_directories_are_not_suppressed():
    """Semgrep's default ignore skips tests/; the adapter disables that on
    purpose, because in offensive tooling the test directory is where real C2
    addresses and operator credentials live. Suppressing it here would
    reintroduce by the back door what was removed at the front.
    """
    findings = [
        _f(IssueFamily.hardcoded_c2, "tests/test_beacon.py", "10.20.30.40:4444"),
        _f(IssueFamily.attribution_identity, "tests/conftest.py", "op@corp.internal"),
    ]
    assert len(fpfilter.apply(findings).kept) == 2


def test_vulnerabilities_in_vendored_code_survive():
    """A CVE in a vendored dependency ships in your binary. Only *attribution*
    is somebody else's in somebody else's code."""
    findings = [
        _f(IssueFamily.dependency_vulnerable, "node_modules/x/pkg.json", "CVE-1"),
        _f(IssueFamily.memory_safety, "third_party/lib/a.c", "strcpy("),
    ]
    assert len(fpfilter.apply(findings).kept) == 2


def test_real_secret_is_not_mistaken_for_a_placeholder():
    kept = fpfilter.apply([
        _f(IssueFamily.hardcoded_secret, "src/a.py", 'AWS = "AKIAIOSFODNN7EXAMPLE"')
    ]).kept
    assert len(kept) == 1


# ── what must go ──────────────────────────────────────────────────────────

def test_third_party_attribution_is_suppressed():
    """user@example.com inside a bundled swagger build is not the operator."""
    result = fpfilter.apply([
        _f(IssueFamily.attribution_identity, "vendor/swagger.js", "someone@corp.io")
    ])
    assert result.kept == []
    assert result.by_filter["third_party_attribution"] == 1


def test_generated_output_is_suppressed():
    for path in ("__pycache__/x.py", ".git/config", "analysis_results/report.json"):
        result = fpfilter.apply([_f(IssueFamily.memory_safety, path, "strcpy(")])
        assert result.kept == [], path
        assert result.by_filter["non_artifact_path"] == 1


@pytest.mark.parametrize("token", [
    'password = "changeme"',
    'key = "change-me"',
    'pw = "letmein"',
    'api_key = "test"',
    'email = "user@example.com"',
])
def test_placeholders_are_suppressed(token):
    result = fpfilter.apply([_f(IssueFamily.hardcoded_secret, "src/a.py", token)])
    assert result.kept == [], token


def test_placeholder_matching_ignores_separators():
    """The vendored list holds change_me but not changeme."""
    assert fpfilter._normalise_placeholder('"CHANGE_ME"') == "changeme"
    assert fpfilter._normalise_placeholder("change-me") == "changeme"


# ── path segment matching ─────────────────────────────────────────────────

def test_segment_matching_does_not_catch_substrings():
    """A file named vendorlist.py is not a vendor directory."""
    assert fpfilter._is_third_party("src/vendor/x.py")
    assert not fpfilter._is_third_party("src/vendorlist.py")
    assert not fpfilter._is_third_party("src/my_external_api.py")


def test_windows_separators_are_handled():
    assert fpfilter._is_third_party(r"src\node_modules\x\y.js")


# ── reporting ─────────────────────────────────────────────────────────────

def test_suppression_is_counted_not_silent():
    """A scorecard that quietly discards evidence is the failure being avoided."""
    result = fpfilter.apply([
        _f(IssueFamily.attribution_identity, "vendor/a.js", "x@y.io"),
        _f(IssueFamily.memory_safety, "__pycache__/b.py", "strcpy("),
        _f(IssueFamily.hardcoded_secret, "src/c.py", 'k = "changeme"'),
        _f(IssueFamily.memory_safety, "src/d.c", "memcpy(a,b,n)"),
    ])

    assert len(result.kept) == 1
    assert result.suppressed == 3
    metrics = result.as_metrics()
    assert metrics["suppressed_findings"] == 3
    assert set(metrics["suppressed_by_filter"]) == {
        "third_party_attribution", "non_artifact_path", "placeholder_value",
    }


def test_filters_are_individually_disablable(monkeypatch):
    finding = _f(IssueFamily.attribution_identity, "vendor/a.js", "x@corp.io")
    monkeypatch.setenv("AIPAM_BLUESCRUB_FILTER_THIRD_PARTY", "false")
    assert len(fpfilter.apply([finding]).kept) == 1


def test_pipeline_reports_suppression_in_metrics(tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.app.bluescrub import service as bs_service
    from backend.app.bluescrub.pillars import Pillar, RiskClass
    from backend.app.bluescrub.scanners.base import ScannerOutcome, ScannerSpec
    from backend.app.database_v2 import Base

    def _run(source_root, output_dir):
        return ScannerOutcome(
            sensor="bluescrub_analyzers", status="completed", version="v",
            findings=[
                _f(IssueFamily.hardcoded_secret, "src/a.py", 'k = "changeme"'),
                _f(IssueFamily.memory_safety, "src/b.c", "memcpy(a,b,n)"),
            ],
        )

    spec = ScannerSpec(name="bluescrub_analyzers", run=_run,
                       pillars=(Pillar.vulnerability,), risk_class=RiskClass.parse_only)
    monkeypatch.setattr(bs_service, "scanners_for", lambda p: [spec])
    monkeypatch.setattr(bs_service, "required_for", lambda p, prof: ["bluescrub_analyzers"])

    engine = create_engine(f"sqlite:///{tmp_path/'x.db'}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    job = tmp_path / "job"
    (job / "input" / "source").mkdir(parents=True)
    (job / "input" / "source" / "a.py").write_text("x = 1\n")

    dacv = bs_service.analyze_and_persist(db, "j", job, profile="triage")["dacv"]
    assert dacv["suppressed_findings"] == 1
    assert dacv["suppressed_by_filter"]["placeholder_value"] == 1
    db.close()
