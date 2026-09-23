"""Hardcoded build and PDB paths in compiled artifacts.

`C:\\Users\\ada.chen\\source\\repos\\loader\\obj\\Release\\loader.pdb` is a
complete attribution package — account name, project name, toolchain, build
configuration — written into the artifact by default. Nothing here was reading
it, because nothing was reading compiled artifacts' strings at all.

The calibration these tests pin is the split between a path that names a person
and one that names a compiler. Every Rust binary contains `/rustc/<hash>/`, and
reporting those at Attribution severity would bury the one path that does name
somebody under a hundred that do not.
"""

import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import binstrings, service as bs_service
from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.scanners import buildpaths as bp
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding
from backend.app.tests._bluescrub_schemas import validator

PDB = r"C:\Users\ada.chen\source\repos\loader\obj\Release\loader.pdb"


@pytest.fixture(autouse=True)
def _no_uid_drop(monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    monkeypatch.delenv(binstrings.PROFILE_ENV, raising=False)


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'d.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def elf_with(payload: bytes, *, pad: int = 512) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * (pad - 7) + payload + b"\x00" * 64


# ── a person, or a compiler ───────────────────────────────────────────────

@pytest.mark.parametrize("path,rule,user", [
    (PDB, "pdb_path", "ada.chen"),
    (r"C:\Users\ada\Documents\proj\x.cpp", "operator_path", "ada"),
    ("/home/ada/implant/src/main.rs", "operator_path", "ada"),
    ("/root/build/loader.c", "operator_path", None),
    (r"C:\proj\obj\Release\loader.exe", "operator_path", None),
])
def test_a_path_that_names_a_developer_is_attribution(path, rule, user):
    verdict = bp.classify(path)
    assert verdict is not None, path
    assert (verdict[0], verdict[2]) == (rule, user)


@pytest.mark.parametrize("path", [
    "/rustc/9b00956e56009bab2aa15d7bff10916599e3d6d6/library/core/src/panic.rs",
    "/usr/local/go/src/runtime/proc.go",
    "/go/pkg/mod/github.com/x/y@v1.2.3/z.go",
    "/builddir/build/BUILD/openssl-3.0.7",
    "/.cargo/registry/src/index.crates.io/serde-1.0.0",
])
def test_a_toolchain_path_names_nobody(path):
    """Every artifact built the same way carries it. At Attribution severity it
    would bury the one path that does name somebody."""
    rule, kind, user = bp.classify(path)
    assert rule == "build_environment" and user is None and kind == "build_path"


@pytest.mark.parametrize("account", ["runner", "jenkins", "vagrant", "ec2-user"])
def test_a_ci_service_account_is_a_build_system_not_a_person(account):
    """`/home/runner/work/` is on every GitHub Actions build there has ever
    been. It identifies the build system, not its operator."""
    rule, _kind, user = bp.classify(f"/home/{account}/work/repo/main.go")
    assert rule == "build_environment" and user is None


def test_a_pdb_under_a_user_profile_is_reported_once_as_the_pdb():
    """It is both a PDB path and a user path. The PDB is the stronger statement
    about how the artifact was built, and two findings would be one fact."""
    hits = bp.extract_paths(f"prefix {PDB} suffix")

    assert [h.rule for h in hits] == ["pdb_path"]
    assert hits[0].username == "ada.chen"


def test_a_pdb_from_a_ci_account_is_still_a_pdb():
    """The debug path carries the project and configuration even when the
    account name is worthless."""
    rule, kind, user = bp.classify(r"C:\Users\runner\work\p\p\obj\Release\p.pdb")
    assert (rule, kind, user) == ("pdb_path", "pdb_path", None)


def test_ordinary_text_is_not_a_build_path():
    for text in ("nothing here", "https://example.com/home/page", "int main(void)"):
        assert bp.extract_paths(text) == [], text


# ── offsets and encodings ─────────────────────────────────────────────────

def test_the_offset_points_at_the_path():
    hits = bp.extract_paths("junk " + PDB, base_offset=1000)
    assert hits[0].offset == 1005


def test_a_wide_string_offset_counts_two_bytes_per_character():
    hits = bp.extract_paths("ab" + PDB, base_offset=2048, width=2)
    assert hits[0].offset == 2048 + 2 * 2


def test_a_giant_blob_is_not_run_through_the_alternations():
    """These regexes run over attacker-authored bytes by definition."""
    assert bp.extract_paths("x" * (bp.MAX_STRING_LENGTH + 1)) == []


# ── finding shape ─────────────────────────────────────────────────────────

def test_a_build_path_is_typed_evidence_not_an_observable(tmp_path):
    """Two build paths cannot be said to be equal without partial-match and
    normalization semantics the IOC pipeline does not have (plan §7)."""
    (tmp_path / "loader.exe").write_bytes(elf_with(PDB.encode(), pad=1024))
    finding = bp.scan(tmp_path)[0]

    assert finding.typed_evidence == [{"kind": "pdb_path", "value": PDB}]
    assert finding.observables == []


def test_findings_carry_a_binary_location_and_validate(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(b"/home/ada/implant/src/main.rs", pad=768))
    check = validator("raw-finding.schema.json")
    findings = bp.scan(tmp_path)

    assert findings
    for finding in findings:
        check.validate(finding.to_dict())
        assert finding.location.kind == "binary"
        assert finding.location.format == "elf"
        assert finding.source_facet == "binary"


def test_the_offset_is_seekable_in_the_artifact(tmp_path):
    path = tmp_path / "loader"
    path.write_bytes(elf_with(b"/home/ada/implant/src/main.rs", pad=768))
    finding = bp.scan(tmp_path)[0]

    data = path.read_bytes()
    assert data[finding.location.offset:].startswith(b"/home/ada/")


def test_the_two_tiers_land_in_different_families(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(
        b"/home/ada/implant/main.rs\x00/usr/local/go/src/runtime/proc.go", pad=512
    ))
    families = {f.rule_id: f.issue_family for f in bp.scan(tmp_path)}

    assert families["build_paths.operator_path"] is IssueFamily.build_path_leak
    assert families["build_paths.build_environment"] is IssueFamily.metadata_leak
    assert all(
        f.pillar_hint is Pillar.attribution for f in bp.scan(tmp_path)
    ), "both tiers are Attribution; only the severity differs"


def test_the_operator_tier_outranks_the_toolchain_tier():
    from backend.app.bluescrub.severity_table import canonical_severity
    from backend.app.bluescrub.pillars import DetectorClass

    assert canonical_severity("build_paths.operator_path",
                              IssueFamily.build_path_leak,
                              DetectorClass.regex_pattern) == "high"
    assert canonical_severity("build_paths.build_environment",
                              IssueFamily.metadata_leak,
                              DetectorClass.regex_pattern) == "medium"


def test_a_username_is_named_in_the_description(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(b"/home/ada/implant/main.rs"))
    finding = bp.scan(tmp_path)[0]

    assert "'ada'" in finding.description
    assert "identity, not a formatting slip" in finding.description


# ── scope: binaries only ──────────────────────────────────────────────────

def test_source_files_are_left_to_the_vendored_scanner(tmp_path):
    """`MetadataLeakageScanner.embedded_paths.linux_username` already covers
    this in source. A second regex detector over the same text is noise, not
    coverage."""
    (tmp_path / "main.c").write_text('const char *p = "/home/ada/implant/main.c";\n')
    assert bp.scan(tmp_path) == []


def test_one_path_repeated_is_one_finding(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(
        (PDB + "\x00").encode() * 5, pad=256
    ))
    assert len(bp.scan(tmp_path)) == 1


def test_a_flooded_artifact_is_capped_and_says_so(tmp_path, caplog):
    blob = b"\x00".join(
        f"/home/dev{n}/proj/main.rs".encode()
        for n in range(bp.MAX_PATHS_PER_FILE + 20)
    )
    (tmp_path / "loader").write_bytes(elf_with(blob, pad=64))
    findings = bp.scan(tmp_path)

    assert len(findings) == bp.MAX_PATHS_PER_FILE
    assert "cap" in caplog.text, "a silent cap reads as full coverage"


def test_an_unreadable_artifact_degrades_rather_than_raising(tmp_path, monkeypatch):
    (tmp_path / "loader").write_bytes(elf_with(b"/home/ada/x.rs"))
    monkeypatch.setattr(
        binstrings, "recover",
        lambda *a, **k: binstrings.Recovery(sha256="", reason="unreadable: nope"),
    )
    assert bp.scan(tmp_path) == []


def test_the_scan_runs_behind_a_process_boundary(tmp_path, monkeypatch):
    """It opens attacker-authored bytes and runs alternations over them. The
    isolation contract admits no in-process exception for that, however pure
    the Python is — a thread spinning in a regex cannot be interrupted."""
    captured = {}

    def _record(argv, **kwargs):
        captured["argv"] = argv
        raise RuntimeError("stop here")

    monkeypatch.setattr(bp, "run_analyzer", _record)
    with pytest.raises(RuntimeError):
        bp.run(tmp_path, tmp_path / "out")

    assert "backend.app.bluescrub.isolation.analyzer_main" in captured["argv"]
    assert "build_paths" in captured["argv"]


@pytest.mark.parametrize("result,expected", [
    (("timeout", b""), "timeout"),
    (("crashed", b""), "crashed"),
])
def test_a_failure_inside_the_boundary_is_classified_not_raised(
    tmp_path, monkeypatch, result, expected
):
    """A scanner failure degrades its pillar; it never fails the job."""
    from backend.app.bluescrub.isolation import AnalyzerResult, AnalyzerStatus

    status, stdout = result
    monkeypatch.setattr(bp, "run_analyzer", lambda *a, **k: AnalyzerResult(
        status=AnalyzerStatus(status), stdout=stdout, reason="x"))
    outcome = bp.run(tmp_path, tmp_path / "out")

    assert outcome.status == expected and outcome.findings == []


def test_unreadable_output_is_reported_as_unparseable(tmp_path, monkeypatch):
    from backend.app.bluescrub.isolation import AnalyzerResult, AnalyzerStatus

    monkeypatch.setattr(bp, "run_analyzer", lambda *a, **k: AnalyzerResult(
        status=AnalyzerStatus.completed, stdout=b"not json", exit_code=0))
    assert bp.run(tmp_path, tmp_path / "out").status == "unparseable"


def test_an_analyzer_error_envelope_is_reported_as_a_crash(tmp_path, monkeypatch):
    from backend.app.bluescrub.isolation import AnalyzerResult, AnalyzerStatus

    monkeypatch.setattr(bp, "run_analyzer", lambda *a, **k: AnalyzerResult(
        status=AnalyzerStatus.completed, exit_code=0,
        stdout=b'{"ok": false, "error": "MemoryError: no"}'))
    outcome = bp.run(tmp_path, tmp_path / "out")

    assert outcome.status == "crashed" and "MemoryError" in outcome.reason


def test_records_survive_the_boundary_intact(tmp_path):
    """The subprocess returns JSON records, not objects; everything the binary
    location needs has to make the crossing."""
    (tmp_path / "loader.exe").write_bytes(elf_with(PDB.encode(), pad=1024))
    records = bp.collect(tmp_path)
    rebuilt = bp.to_findings(json.loads(json.dumps(records)))

    assert len(rebuilt) == 1
    location = rebuilt[0].location
    assert location.kind == "binary" and location.offset == 1024
    assert location.format == "elf" and len(location.artifact_sha256) == 64
    validator("raw-finding.schema.json").validate(rebuilt[0].to_dict())


# ── end to end ────────────────────────────────────────────────────────────

def test_a_pdb_path_in_a_shipped_binary_reaches_the_database(db, tmp_path):
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader.exe").write_bytes(elf_with(PDB.encode(), pad=2048))

    bs_service.analyze_and_persist(db, "j", tmp_path, profile="standard", run_output_dir=tmp_path)

    rows = [r for r in db.scalars(select(Finding)).all() if r.sensor == "build_paths"]
    evidence = [json.loads(r.evidence_json) for r in rows]
    assert any(e.get("rule_id") == "build_paths.pdb_path" for e in evidence), evidence
    assert all(r.severity == "high" for r in rows)


def test_build_paths_is_not_in_the_quick_profile():
    """It re-reads every binary's strings, and Quick's Attribution budget is
    spent on the declared terms over the same bytes."""
    from backend.app.bluescrub.registry import required_for

    assert "build_paths" not in required_for(Pillar.attribution, "triage")
    assert "build_paths" in required_for(Pillar.attribution, "standard")
