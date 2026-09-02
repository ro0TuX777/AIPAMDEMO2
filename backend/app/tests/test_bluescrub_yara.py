"""YARA — the detection performed, rather than estimated.

Every other Detectability signal infers how catchable an artifact is. This one
runs the signatures a defender would run. That makes the failure mode sharper
than usual: an empty rules directory returns zero matches, and so does an
artifact no signature catches. Those are opposite conclusions and they look
identical, so the absence of rules has to be reported as absence.

`yara-python` is installed here, so these compile real rules and match real
bytes rather than stubbing the engine.
"""

import json

from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.bluescrub.scanners import yara_scan
from backend.app.database_v2 import Base
from backend.app.tests._bluescrub_schemas import validator

yara = pytest.importorskip("yara", reason="yara-python not installed")

RULE = """
rule Nightfall_Loader
{
    meta:
        description = "Test signature for the BlueScrub suite"
        family = "NIGHTFALL"
    strings:
        $codename = "OPERATION NIGHTFALL"
        $mutex = "Global\\\\RC-NIGHTFALL"
    condition:
        any of them
}
"""

TAGGED_RULE = """
rule Packed_Thing : packer apt
{
    strings:
        $a = "UPX0"
    condition:
        $a
}
"""


@pytest.fixture()
def rules(tmp_path, monkeypatch):
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "nightfall.yar").write_text(RULE)
    (directory / "packed.yar").write_text(TAGGED_RULE)
    monkeypatch.setenv(yara_scan.RULES_ENV, str(directory))
    return directory


@pytest.fixture()
def artifact(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "loader").write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 500
        + b"OPERATION NIGHTFALL\x00" + b"\x00" * 64
    )
    return src


# ── absence of rules is absence, not cleanliness ──────────────────────────

def test_no_rules_directory_is_unavailable(tmp_path, monkeypatch, artifact):
    """Zero matches from an empty rule set and zero matches from an artifact no
    signature catches are opposite conclusions that look identical."""
    monkeypatch.setenv(yara_scan.RULES_ENV, str(tmp_path / "nope"))
    outcome = yara_scan.run(artifact, tmp_path / "out")

    assert outcome.status == "unavailable"
    assert "rules" in outcome.reason


def test_an_empty_rules_directory_is_unavailable(tmp_path, monkeypatch, artifact):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv(yara_scan.RULES_ENV, str(empty))

    assert yara_scan.run(artifact, tmp_path / "out").status == "unavailable"


def test_missing_rules_is_real_coverage_loss(tmp_path, monkeypatch, artifact):
    from backend.app.bluescrub.scoring import ScannerRun, coverage_for

    monkeypatch.setenv(yara_scan.RULES_ENV, str(tmp_path / "nope"))
    outcome = yara_scan.run(artifact, tmp_path / "out")
    coverage, _, missing = coverage_for(Pillar.detectability, [ScannerRun(
        sensor="yara", status=outcome.status,
        required_for=(Pillar.detectability,))])

    assert coverage == 0.0 and missing == ["yara"]


# ── a match is the detection, performed ───────────────────────────────────

def test_a_planted_signature_matches(rules, artifact, tmp_path):
    outcome = yara_scan.run(artifact, tmp_path / "out")

    assert outcome.status == "completed"
    assert [f.rule_id for f in outcome.findings] == ["yara.Nightfall_Loader"]


def test_a_match_is_detectability(rules, artifact, tmp_path):
    finding = yara_scan.run(artifact, tmp_path / "out").findings[0]

    assert finding.issue_family is IssueFamily.signature_known
    assert finding.pillar_hint is Pillar.detectability
    assert finding.detector_class is DetectorClass.regex_pattern


def test_the_family_is_evidence_and_not_a_decision(rules, artifact, tmp_path):
    """A signature says a defender will catch this, not who wrote it: families
    are assigned by whoever authored the rule, from behaviour that is
    frequently shared, copied, or deliberately imitated."""
    finding = yara_scan.run(artifact, tmp_path / "out").findings[0]

    assert finding.typed_evidence == [
        {"kind": "yara_family", "value": "NIGHTFALL"}]
    assert finding.pillar_hint is not Pillar.attribution
    assert finding.issue_family is not IssueFamily.attribution_marking


def test_the_rule_name_is_the_rule_id_not_the_family(rules, artifact, tmp_path):
    """Two rules for one family are two signatures, and an analyst silencing
    one must not silence both."""
    finding = yara_scan.run(artifact, tmp_path / "out").findings[0]
    assert finding.rule_id == "yara.Nightfall_Loader"
    assert "NIGHTFALL" not in finding.rule_id.split(".", 1)[1]


def test_findings_carry_a_binary_location_and_validate(rules, artifact, tmp_path):
    check = validator("raw-finding.schema.json")
    for finding in yara_scan.run(artifact, tmp_path / "out").findings:
        check.validate(finding.to_dict())
        assert finding.location.kind == "binary"
        assert len(finding.location.artifact_sha256) == 64
        assert finding.location.format == "elf"


def test_the_matched_strings_are_the_evidence(rules, artifact, tmp_path):
    finding = yara_scan.run(artifact, tmp_path / "out").findings[0]
    assert "$codename" in finding.matched_tokens


def test_rule_tags_are_shown_without_opening_the_rule(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "packed.bin").write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 200 + b"UPX0" + b"\x00" * 64)
    directory = tmp_path / "rules"
    directory.mkdir()
    (directory / "packed.yar").write_text(TAGGED_RULE)
    monkeypatch.setenv(yara_scan.RULES_ENV, str(directory))

    finding = yara_scan.run(src, tmp_path / "out").findings[0]
    assert "packer" in finding.title and "apt" in finding.title


def test_an_artifact_no_signature_catches_is_a_clean_result(rules, tmp_path):
    """Distinct from "no rules": here the question was asked and answered."""
    src = tmp_path / "clean"
    src.mkdir()
    (src / "loader").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 600)

    outcome = yara_scan.run(src, tmp_path / "out")
    assert outcome.status == "completed" and outcome.findings == []


def test_no_binaries_is_reported(rules, tmp_path):
    src = tmp_path / "srconly"
    src.mkdir()
    (src / "main.c").write_text("int main(void){return 0;}\n")

    outcome = yara_scan.run(src, tmp_path / "out")
    assert outcome.status == "completed"
    assert "no binary artifacts" in outcome.reason


def test_a_flood_of_matches_is_capped_and_says_so(tmp_path, monkeypatch, caplog):
    class _Match:
        def __init__(self, n):
            self.rule = f"Rule_{n}"
            self.tags: list[str] = []
            self.meta: dict = {}
            self.strings = ["$a"]

    findings = yara_scan.to_findings(
        "loader", "a" * 64, "elf",
        [_Match(n) for n in range(yara_scan.MAX_MATCHES_PER_ARTIFACT + 20)],
    )
    assert len(findings) == yara_scan.MAX_MATCHES_PER_ARTIFACT
    assert "reporting the first" in caplog.text


# ── it reuses the platform engine ─────────────────────────────────────────

def test_it_does_not_compile_its_own_rules():
    """A second compiler would mean two rule paths, two failure modes, and two
    places for "YARA is unavailable" to come from."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(yara_scan.__file__).read_text())
    imported = {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "yara" not in imported, "compile through binalysis.engine, not directly"


def test_bundled_rules_are_used_when_nothing_is_configured(monkeypatch, tmp_path):
    """A default install shipped rules and declined to run them.

    `aipam_yara_rules_dir` defaults to /opt/aipam/rules/yara, a path nobody has
    until they provision it, so every developer machine and fresh install
    reported Detectability `degraded` with `missing: yara` while a ruleset sat
    unused in the source tree.
    """
    from backend.app.binalysis.service import default_rules_dir

    monkeypatch.delenv(yara_scan.RULES_ENV, raising=False)
    monkeypatch.setattr(
        "backend.app.config_v2.get_settings",
        lambda: SimpleNamespace(aipam_yara_rules_dir=tmp_path / "unprovisioned"),
    )
    assert yara_scan.rules_dir() == default_rules_dir()


def test_the_configured_directory_still_wins_over_the_bundled_one(
    monkeypatch, tmp_path
):
    provisioned = tmp_path / "provisioned"
    provisioned.mkdir()
    monkeypatch.delenv(yara_scan.RULES_ENV, raising=False)
    monkeypatch.setattr(
        "backend.app.config_v2.get_settings",
        lambda: SimpleNamespace(aipam_yara_rules_dir=provisioned),
    )
    assert yara_scan.rules_dir() == provisioned


def test_an_explicit_empty_override_is_still_unavailable(monkeypatch, tmp_path):
    """The fallback must not override someone deliberately running no rules."""
    monkeypatch.setenv(yara_scan.RULES_ENV, str(tmp_path / "missing"))
    assert yara_scan.rules_dir() is None


def test_the_bundled_rules_actually_compile():
    """A fallback pointing at rules that do not compile is worse than none."""
    from backend.app.binalysis.engine import compile_yara_rules, yara_available

    if not yara_available():
        pytest.skip("yara-python is not installed")
    assert compile_yara_rules(yara_scan.rules_dir()) is not None


def test_the_configured_rules_path_is_the_platform_setting(monkeypatch):
    """An operator should not have to learn a second setting."""
    monkeypatch.delenv(yara_scan.RULES_ENV, raising=False)
    from backend.app.config_v2 import get_settings

    assert hasattr(get_settings(), "aipam_yara_rules_dir")


@pytest.mark.parametrize("meta,expected", [
    ({"family": "NIGHTFALL"}, "NIGHTFALL"),
    ({"malware_family": "Emotet"}, "Emotet"),
    ({"actor": "APT-X"}, "APT-X"),
    ({"description": "no family here"}, None),
])
def test_family_extraction(meta, expected):
    assert yara_scan.family_of(meta) == expected


# ── end to end ────────────────────────────────────────────────────────────

def test_a_signature_hit_reaches_the_database(rules, tmp_path, monkeypatch):
    from sqlalchemy import select

    from backend.app.bluescrub import service as bs_service
    from backend.app.models.finding import Finding

    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    job = tmp_path / "job"
    src = job / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader").write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 500 + b"OPERATION NIGHTFALL\x00")

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    bs_service.analyze_and_persist(db, "j", job, profile="deep")

    rows = [r for r in db.scalars(select(Finding)).all() if r.sensor == "yara"]
    assert rows, "the planted signature did not reach the database"
    assert json.loads(rows[0].evidence_json)["rule_id"] == "yara.Nightfall_Loader"
    assert rows[0].category == "Detectability"
    db.close()
