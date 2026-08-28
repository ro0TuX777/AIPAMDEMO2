"""Gitleaks and TruffleHog — history-scale secret scanning.

Neither binary is installed here, so the argv for each is a documented decision
and the parsers are what get exercised, against recorded tool output. That is
where adapter bugs actually live: Gitleaks reports a bare JSON array with
TitleCase fields, and TruffleHog streams one object per line — read either one
wrongly and the adapter reports zero findings without erroring, which is
indistinguishable from a clean artifact.
"""

import json
from pathlib import Path

import pytest

from backend.app.bluescrub import redaction
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.bluescrub.scanners import secrets
from backend.app.bluescrub.scanners.external import (
    decode_payload,
    results_path,
    write_results,
)
from backend.app.tests._bluescrub_schemas import validator

ROOT = Path("/srv/artifact")


# ── Gitleaks ──────────────────────────────────────────────────────────────

GITLEAKS_OUTPUT = [
    {
        "Description": "GitHub Personal Access Token",
        "StartLine": 12, "EndLine": 12, "StartColumn": 15, "EndColumn": 55,
        "Match": 'token = "ghp_liveTOKENvalue0000000000000000000000"',
        "Secret": "ghp_liveTOKENvalue0000000000000000000000",
        "File": "config/settings.py", "RuleID": "github-pat",
        "Commit": "9f2c1ab77e0d4b3a", "Author": "Ada", "Email": "ada@redcell.internal",
        "Date": "2024-03-01T09:15:00Z", "Message": "wire up the uploader",
        "Fingerprint": "config/settings.py:github-pat:12", "Entropy": 4.2,
    },
    {
        "Description": "Basic auth credentials",
        "StartLine": 3, "StartColumn": 1,
        "Secret": "admin:hunter2hunter2", "File": "deploy/.netrc",
        "RuleID": "basic-auth-credentials",
    },
]


def test_gitleaks_parses_a_bare_array():
    """The report is an array, not an object with a findings key. Reading it as
    a dict yields zero findings and no error."""
    findings = secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)

    assert len(findings) == 2
    first = findings[0]
    assert first.sensor == "gitleaks"
    assert first.rule_id == "gitleaks.github-pat"
    assert first.location.file == "config/settings.py"
    assert first.location.start_line == 12
    assert first.pillar_hint is Pillar.attribution


def test_a_history_finding_says_it_is_in_every_clone():
    """"Delete this line" and "rotate it" are different instructions, and the
    commit is what tells the analyst which one applies."""
    finding = secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)[0]

    assert "9f2c1ab77e0d" in finding.description
    assert "every clone" in finding.description
    assert "Rotate" in finding.recommendation


def test_a_login_is_a_different_family_from_a_machine_key():
    families = {f.rule_id: f.issue_family for f in secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)}

    assert families["gitleaks.github-pat"] is IssueFamily.hardcoded_secret
    assert families["gitleaks.basic-auth-credentials"] is IssueFamily.credential_exposure


def test_a_generic_rule_is_less_confident_than_a_shaped_one():
    shaped = secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)[0]
    generic = secrets.parse_gitleaks(
        [dict(GITLEAKS_OUTPUT[0], RuleID="generic-api-key")], ROOT)[0]

    assert generic.confidence < shaped.confidence


def test_gitleaks_findings_validate_against_the_raw_contract():
    check = validator("raw-finding.schema.json")
    for finding in secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT):
        check.validate(finding.to_dict())


def test_a_record_with_no_secret_is_skipped():
    assert secrets.parse_gitleaks([{"RuleID": "x", "File": "a"}], ROOT) == []


def test_gitleaks_scans_history_when_there_is_one(tmp_path):
    (tmp_path / ".git").mkdir()
    argv = secrets.gitleaks_argv(tmp_path)

    assert "--no-git" not in argv, "a repository's history is the point"
    assert "detect" in argv


def test_gitleaks_falls_back_to_files_without_a_repository(tmp_path):
    """`detect` fails outright on a plain directory, which would report the
    commonest case — an uploaded archive — as a crashed scanner."""
    assert "--no-git" in secrets.gitleaks_argv(tmp_path)


def test_gitleaks_is_not_asked_to_redact():
    """Redaction is central. Redacting at the tool destroys the value before
    the keyed fingerprint is computed, so two scans of the same secret stop
    deduplicating."""
    argv = secrets.gitleaks_argv(Path("/srv"))
    assert "--redact=0" in argv
    assert "--redact" not in argv


# ── TruffleHog ────────────────────────────────────────────────────────────

TRUFFLEHOG_LINES = b"""\
2024-03-01T09:15:00Z\tinfo\ttrufflehog\tstarting
{"SourceMetadata":{"Data":{"Filesystem":{"file":"/srv/artifact/uploader.go","line":88}}},\
"SourceName":"trufflehog - filesystem","DetectorName":"Github","DecoderName":"PLAIN",\
"Verified":false,"Raw":"ghp_anotherLIVEtoken000000000000000000","RawV2":"","Redacted":""}
{"SourceMetadata":{"Data":{"Git":{"file":"old/creds.yml","line":4,"commit":"deadbeef"}}},\
"DetectorName":"AWS","DecoderName":"PLAIN","Verified":false,\
"Raw":"AKIAIOSFODNN7EXAMPLE","RawV2":""}
"""


def test_json_lines_are_wrapped_not_concatenated():
    """`json.loads` over the whole stream fails on the second object, which
    presents as a tool that found nothing."""
    payload = decode_payload(TRUFFLEHOG_LINES, json_lines=True)

    assert len(payload["results"]) == 2, "log preamble or second record lost"


def test_a_malformed_record_still_raises():
    """Skipping unparseable lines silently is how a broken adapter comes to
    look like a clean scan."""
    with pytest.raises(json.JSONDecodeError):
        decode_payload(b'{"a": 1}\n{"b": ', json_lines=True)


def test_trufflehog_parses_both_source_metadata_shapes():
    """The metadata is nested by source type. Reading only `Filesystem` drops
    every finding from a git scan, which is most of them."""
    payload = decode_payload(TRUFFLEHOG_LINES, json_lines=True)
    findings = secrets.parse_trufflehog(payload, ROOT)

    assert len(findings) == 2
    files = {f.location.file: f.location.start_line for f in findings}
    assert files == {"uploader.go": 88, "old/creds.yml": 4}


def test_trufflehog_findings_validate_against_the_raw_contract():
    payload = decode_payload(TRUFFLEHOG_LINES, json_lines=True)
    check = validator("raw-finding.schema.json")
    for finding in secrets.parse_trufflehog(payload, ROOT):
        check.validate(finding.to_dict())


def test_verification_is_disabled_in_the_argv(tmp_path):
    """A defence enforced only by configuration is enforced until somebody
    edits the configuration. Verification authenticates to the issuing service
    — an outbound connection carrying somebody else's secret."""
    for setup in (lambda: None, lambda: (tmp_path / ".git").mkdir()):
        setup()
        argv = secrets.trufflehog_argv(tmp_path)
        assert secrets.verification_disabled(argv), argv
        assert "--verification" not in argv


def test_a_verified_result_is_reported_as_a_boundary_failure(caplog):
    """It means verification ran despite the flag: the analyzer reached the
    network. The finding is kept — suppressing it would hide the evidence."""
    payload = {"results": [{
        "DetectorName": "Github", "Raw": "ghp_x0000000000000000", "Verified": True,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "/srv/artifact/a.py", "line": 1}}},
    }]}
    findings = secrets.parse_trufflehog(payload, ROOT)

    assert len(findings) == 1
    assert "reached the network" in caplog.text


def test_trufflehog_uses_the_git_source_when_there_is_a_repository(tmp_path):
    (tmp_path / ".git").mkdir()
    argv = secrets.trufflehog_argv(tmp_path)

    assert argv[0] == "git" and argv[1].startswith("file://")


def test_both_tools_are_optional_corroborators():
    """Neither is authoritative and they disagree constantly. Installing either
    one must not move a score — the same argument OSV and Grype are wired on."""
    from backend.app.bluescrub.registry import optional_sensors

    assert {"gitleaks", "trufflehog"} <= optional_sensors()


def test_both_tools_declare_the_repo_history_risk_class():
    from backend.app.bluescrub.pillars import RiskClass
    from backend.app.bluescrub.registry import SCANNERS

    for name in ("gitleaks", "trufflehog"):
        assert SCANNERS[name].risk_class is RiskClass.repo_history


# ── plaintext handling ────────────────────────────────────────────────────

def _secret_finding() -> RawFinding:
    return RawFinding(
        sensor="gitleaks", sensor_version="external", rule_id="gitleaks.github-pat",
        issue_family=IssueFamily.hardcoded_secret, confidence=0.8,
        detector_class=DetectorClass.regex_pattern,
        matched_tokens="ghp_liveTOKENvalue0000000000000000000000",
        description="GitHub Personal Access Token",
        location=Location(kind="source", file="a.py", start_line=1, start_column=0),
    )


def test_a_secret_scanners_artefacts_go_to_the_quarantine_tier(tmp_path):
    """Findings age out with the job at 30 days. A plaintext credential is
    governed by the 72-hour quarantine clock instead."""
    output_dir = tmp_path / "sensors" / "gitleaks"
    path = results_path(output_dir, "gitleaks", secret_bearing=True)

    assert path.parent == tmp_path / "quarantine"
    assert results_path(output_dir, "osv", secret_bearing=False).parent == output_dir


def test_the_evidence_is_withheld_from_the_on_disk_artefact(tmp_path):
    """This file is written before central redaction runs, so it would be the
    one place a plaintext credential lands on disk and stays."""
    output_dir = tmp_path / "sensors" / "gitleaks"
    output_dir.mkdir(parents=True)
    path = write_results(output_dir, [_secret_finding()], secret_bearing=True)

    blob = path.read_text()
    assert "ghp_liveTOKENvalue" not in blob
    assert "withheld" in blob


def test_a_non_secret_scanner_still_writes_its_evidence(tmp_path):
    output_dir = tmp_path / "sensors" / "osv"
    output_dir.mkdir(parents=True)
    finding = _secret_finding()
    finding.sensor = "osv"
    path = write_results(output_dir, [finding], secret_bearing=False)

    assert "ghp_liveTOKENvalue" in path.read_text()


def test_central_redaction_masks_and_fingerprints_what_the_parser_carried(monkeypatch):
    """The plaintext is carried on the finding so exactly one stage can turn it
    into a mask and a keyed fingerprint — rather than each adapter being
    trusted to remember."""
    monkeypatch.setenv(redaction.KEY_ENV, "test-key")
    findings = secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)

    result = redaction.redact(findings)
    blob = json.dumps([f.to_dict() for f in result.findings])

    assert "ghp_liveTOKENvalue0000000000000000000000" not in blob
    assert "hunter2hunter2" not in blob
    assert all(f.secret.fingerprint.startswith("hmac-sha256:")
               for f in result.findings if f.secret)


def test_two_scans_of_one_secret_produce_one_finding(monkeypatch):
    """The reason `--redact` is refused at the tool: the fingerprint is
    computed from the plaintext, and a masked value collides distinct secrets."""
    monkeypatch.setenv(redaction.KEY_ENV, "test-key")
    from backend.app.bluescrub.canonicalize import canonicalize

    first = redaction.redact(secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)).findings
    second = redaction.redact(secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)).findings

    ids_a = {g.canonical_id for g in canonicalize(first, project_id="p").groups}
    ids_b = {g.canonical_id for g in canonicalize(second, project_id="p").groups}
    assert ids_a == ids_b and len(ids_a) == 2


def test_two_different_secrets_do_not_collide(monkeypatch):
    monkeypatch.setenv(redaction.KEY_ENV, "test-key")
    a = secrets.parse_gitleaks(GITLEAKS_OUTPUT, ROOT)[0]
    b = secrets.parse_gitleaks(
        [dict(GITLEAKS_OUTPUT[0], Secret="ghp_DIFFERENTvalue00000000000000000000")],
        ROOT)[0]

    redaction.redact([a, b])
    assert a.secret.fingerprint != b.secret.fingerprint
    assert a.secret.masked_value == b.secret.masked_value, (
        "the masks collide, which is exactly why the fingerprint is keyed"
    )
