"""Binary string recovery, and the dirty-word binary path it feeds.

Sprint 5's acceptance criterion is that a planted codename in a binary
surfaces with category and offset context. Before this module it could not:
the vendored matcher classified files by extension, so a stripped ELF named
`loader` was read as text, and when it did take the binary branch the adapter
wrote the byte offset into a `source` location — which the raw-finding contract
rejects, because a source location must carry a line number. The offset was
computed and then thrown away.
"""

import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import binstrings, service as bs_service, wordlists as wl
from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.pillars import Pillar
from backend.app.bluescrub.scanners import dirty_word as dw
from backend.app.bluescrub.scoring import ScannerRun, coverage_for
from backend.app.bluescrub.severity_table import build_rule_mapping
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding
from backend.app.tests._bluescrub_schemas import validator


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
    """A synthetic ELF. Deterministic, so offsets are assertable."""
    return b"\x7fELF\x02\x01\x01" + b"\x00" * (pad - 7) + payload + b"\x00" * 64


# ── classification is by content, not extension ───────────────────────────

@pytest.mark.parametrize("head,binary", [
    (b"\x7fELF\x02\x01\x01\x00", True),
    (b"MZ\x90\x00\x03\x00\x00\x00", True),
    (b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", True),
    (b"int main(void) { return 0; }\n", False),
    (b"a" * 100 + b"\x00", True),           # a NUL settles it
    (b"\xff\xfe\xfd\xfc" * 40, True),       # no magic, but almost no text
    (b"# comment\nvalue = 1\n" * 5, False),
])
def test_binary_detection_reads_the_bytes(head, binary):
    """Extension-based classification is why a stripped ELF called `loader`
    was read as text: the codename was still found, at a line number and column
    that mean nothing in a file with no lines."""
    assert binstrings.looks_binary(head) is binary


def test_an_empty_file_is_not_a_binary():
    assert binstrings.looks_binary(b"") is False


@pytest.mark.parametrize("head,fmt", [
    (b"\x7fELF\x02", "elf"), (b"MZ\x90\x00", "pe"),
    (b"\x00asm\x01\x00", "wasm"), (b"nothing", None),
])
def test_format_is_named_for_the_location(head, fmt):
    assert binstrings.detect_format(head) == fmt


# ── static extraction ─────────────────────────────────────────────────────

def test_ascii_offsets_are_real_file_offsets():
    data = elf_with(b"OPERATION NIGHTFALL", pad=512)
    found = [s for s in binstrings.extract_static(data) if "NIGHTFALL" in s.value]

    assert len(found) == 1
    assert found[0].offset == 512
    assert data[512:512 + 19] == b"OPERATION NIGHTFALL"


def test_utf16le_is_recovered_and_not_double_reported():
    """`N\\0I\\0G\\0H\\0T\\0` is also a stream of one-character ASCII runs. A
    duplicate from the same bytes is indistinguishable from two occurrences."""
    wide = "NIGHTFALL".encode("utf-16-le")
    data = elf_with(wide, pad=256)
    found = [s for s in binstrings.extract_static(data) if "NIGHTFALL" in s.value]

    assert len(found) == 1
    assert found[0].encoding == "utf-16le"
    assert found[0].offset == 256


def test_short_runs_are_not_strings():
    assert not [s for s in binstrings.extract_static(b"\x00ab\x00cd\x00") if s.value]


def test_recovery_caps_the_read_and_says_so(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(elf_with(b"NIGHTFALL", pad=64) + b"\x00" * 4096)
    recovery = binstrings.recover(path, max_bytes=128)

    assert recovery.truncated and "capped" in recovery.reason
    assert recovery.sha256, "a truncated read still identifies what was read"


def test_an_unreadable_artifact_is_reported_not_raised(tmp_path):
    recovery = binstrings.recover(tmp_path / "absent.bin")
    assert recovery.sha256 == "" and "unreadable" in recovery.reason


# ── FLOSS is the deep tier, and only the deep tier ────────────────────────

def test_floss_is_confined_to_the_deep_profile(monkeypatch):
    """It emulates the sample, and the isolation contract puts emulation in
    `deep` only. That is the contract, not a performance preference."""
    monkeypatch.setattr(binstrings.shutil, "which", lambda _n: "/usr/bin/floss")

    assert binstrings.floss_enabled("deep") is True
    for profile in ("triage", "standard", ""):
        assert binstrings.floss_enabled(profile) is False


def test_floss_absent_means_no_floss_even_on_deep(monkeypatch):
    monkeypatch.setattr(binstrings.shutil, "which", lambda _n: None)
    assert binstrings.floss_enabled("deep") is False


FLOSS_OUTPUT = {
    "strings": {
        "static_strings": [{"string": "OPERATION NIGHTFALL", "offset": 4096,
                            "encoding": "ASCII"}],
        "stack_strings": [{"string": "REDCELL", "program_counter": 4198400}],
        "tight_strings": [{"string": "beacon.internal"}],
        "decoded_strings": [{"string": "NIGHTFALL", "decoding_routine": 4198656}],
    },
}


def test_floss_runtime_strings_carry_no_file_offset():
    """A string assembled at runtime never existed on disk. Its program counter
    is an address in the emulated image; writing that into `offset` would give
    an analyst a position to seek to that is not there."""
    recovered = {s.method: s for s in binstrings.parse_floss(FLOSS_OUTPUT)}

    assert recovered["static"].offset == 4096
    for method in ("stack", "tight", "decoded"):
        assert recovered[method].offset is None, method
        assert recovered[method].value


def test_floss_output_that_is_a_bare_string_list_still_parses():
    """Older FLOSS builds emit plain strings rather than records."""
    parsed = binstrings.parse_floss({"strings": {"stack_strings": ["NIGHTFALL"]}})
    assert [s.value for s in parsed] == ["NIGHTFALL"]


def test_floss_adds_to_the_static_pass_rather_than_replacing_it(tmp_path):
    path = tmp_path / "loader"
    path.write_bytes(elf_with(b"OPERATION NIGHTFALL", pad=128))
    recovery = binstrings.recover(path, run_floss=lambda _p: FLOSS_OUTPUT)

    values = {s.value for s in recovery.strings}
    assert "OPERATION NIGHTFALL" in values, "static pass lost"
    assert "REDCELL" in values, "stack string lost"
    assert recovery.method == "floss"


def test_a_floss_failure_keeps_the_static_pass(tmp_path):
    path = tmp_path / "loader"
    path.write_bytes(elf_with(b"NIGHTFALL", pad=64))

    def _boom(_p):
        raise RuntimeError("emulation failed")

    recovery = binstrings.recover(path, run_floss=_boom)
    assert any("NIGHTFALL" in s.value for s in recovery.strings)
    assert recovery.method == "static"


def test_floss_is_not_asked_to_repeat_the_static_pass():
    assert "--no" in binstrings.floss_argv(Path("/a")), "static pass not disabled"


# ── a shallow deep scan is partial coverage ───────────────────────────────

def test_deep_without_floss_reports_a_shallow_recovery_tier(monkeypatch):
    monkeypatch.setattr(binstrings.shutil, "which", lambda _n: None)

    assert binstrings.recovery_state("deep") == "strings_static_only"
    assert binstrings.recovery_state("triage") is None, "not asked for, not missing"


def test_a_shallow_recovery_tier_degrades_attribution():
    """A deep scan is a request for emulation-grade recovery. Getting only what
    was already on disk is partial coverage, not a clean result."""
    runs = [ScannerRun(sensor="dirty_word", status="completed",
                       required_for=(Pillar.attribution,),
                       ruleset_state="strings_static_only")]
    coverage, degraded, _ = coverage_for(Pillar.attribution, runs)

    assert coverage == 1.0 and degraded is True


# ── the location a binary hit gets ────────────────────────────────────────

BINARY_HIT = {
    "file": "loader", "word": "NIGHTFALL", "line": None, "offset": 8206,
    "context": "OPERATION NIGHTFALL", "type": "binary", "sha256": "a" * 64,
    "format": "elf", "encoding": "ascii", "recovery": "static",
}


def test_a_binary_hit_is_a_binary_location():
    finding = dw.parse_hits({"matches": [BINARY_HIT]},
                            [{"term": "NIGHTFALL", "category": "codename"}],
                            Path("/s"))[0]

    assert finding.source_facet == "binary"
    assert finding.location.kind == "binary"
    assert finding.location.artifact_sha256 == "a" * 64
    assert finding.location.offset == 8206
    assert finding.location.format == "elf"
    assert "0x200e" in finding.description


def test_a_binary_hit_validates_against_the_raw_contract():
    """It did not. `kind: source` with no `start_line` is a contract violation,
    and nothing at runtime validates raw findings — it reached the database."""
    finding = dw.parse_hits({"matches": [BINARY_HIT]},
                            [{"term": "NIGHTFALL", "category": "codename"}],
                            Path("/s"))[0]
    validator("raw-finding.schema.json").validate(finding.to_dict())


def test_a_binary_hit_without_a_digest_does_not_forge_a_location():
    """A binary location needs the artifact digest. Without one the honest
    answer is project scope, not a source location it cannot support."""
    hit = dict(BINARY_HIT, sha256="")
    finding = dw.parse_hits({"matches": [hit]},
                            [{"term": "NIGHTFALL", "category": "codename"}],
                            Path("/s"))[0]

    assert finding.location.kind == "project"
    assert finding.source_facet == "binary"
    validator("raw-finding.schema.json").validate(finding.to_dict())


def test_a_runtime_recovered_string_says_it_has_no_offset():
    hit = dict(BINARY_HIT, recovery="decoded", offset=None)
    finding = dw.parse_hits({"matches": [hit]},
                            [{"term": "NIGHTFALL", "category": "codename"}],
                            Path("/s"))[0]

    assert "reconstructed at runtime" in finding.description
    assert "offset" not in finding.description.split("reconstructed")[0][-30:]
    assert finding.location.offset is None


def test_two_offsets_in_one_binary_stay_two_findings():
    """The old source location bucketed on `line:None`, so every hit in a file
    collapsed into one group and the offsets were discarded."""
    hits = {"matches": [
        dict(BINARY_HIT, offset=4096),
        dict(BINARY_HIT, offset=65536),
    ]}
    findings = dw.parse_hits(hits, [{"term": "NIGHTFALL", "category": "codename"}],
                             Path("/s"))
    groups = canonicalize(findings, project_id="p").groups

    assert len(groups) == 2


# ── one owner per file ────────────────────────────────────────────────────

def test_an_extensionless_binary_is_scanned(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL"))
    assert dw.binary_paths(tmp_path) == {"loader"}


def test_a_source_file_is_not_claimed_as_a_binary(tmp_path):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    assert dw.binary_paths(tmp_path) == set()


def test_a_binary_extension_is_still_claimed(tmp_path):
    """Dropping extension classification would quietly lose the files the
    vendored matcher was already covering."""
    (tmp_path / "payload.bin").write_text("plain text with NIGHTFALL in it\n")
    assert dw.binary_paths(tmp_path) == {"payload.bin"}


def test_binary_matching_reports_a_seekable_offset(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL", pad=1024))
    matches = dw.scan_binaries(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])

    assert len(matches) == 1
    hit = matches[0]
    assert hit["offset"] == 1024 + len("OPERATION ")
    assert hit["type"] == "binary" and hit["format"] == "elf"
    assert len(hit["sha256"]) == 64


def test_a_wide_string_offset_counts_two_bytes_per_character(tmp_path):
    """A character index inside a recovered UTF-16LE string is not a byte
    offset into the file, and an offset an analyst cannot seek to is worse
    than none."""
    payload = "OPERATION NIGHTFALL".encode("utf-16-le")
    (tmp_path / "loader.exe").write_bytes(elf_with(payload, pad=2048))
    hit = dw.scan_binaries(
        tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])[0]

    assert hit["encoding"] == "utf-16le"
    assert hit["offset"] == 2048 + len("OPERATION ") * 2


def test_case_sensitivity_is_honoured_per_term(tmp_path):
    (tmp_path / "loader").write_bytes(elf_with(b"operation nightfall"))
    sensitive = dw.scan_binaries(
        tmp_path, [{"term": "NIGHTFALL", "category": "codename",
                    "case_sensitive": True}])
    insensitive = dw.scan_binaries(
        tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])

    assert sensitive == []
    assert len(insensitive) == 1


def test_a_flooded_binary_is_capped_not_unbounded(tmp_path, caplog):
    (tmp_path / "loader").write_bytes(
        elf_with(b" NIGHTFALL" * (dw.MAX_BINARY_HITS_PER_FILE + 50))
    )
    matches = dw.scan_binaries(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])

    assert len(matches) == dw.MAX_BINARY_HITS_PER_FILE
    assert "cap" in caplog.text, "a silent cap reads as full coverage"


# ── end to end: the Sprint 5 acceptance criterion ─────────────────────────

def test_a_planted_codename_in_a_binary_surfaces_with_category_and_offset(db, tmp_path):
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL", pad=4096))
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])

    dacv = bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)["dacv"]

    rows = [r for r in db.scalars(select(Finding)).all() if r.sensor == "dirty_word"]
    evidence = [json.loads(r.evidence_json) for r in rows]
    planted = [e for e in evidence if e.get("rule_id") == "dirty_word.codename"]

    assert planted, [e.get("rule_id") for e in evidence]
    location = planted[0]["location"]
    assert location["kind"] == "binary"
    assert location["offset"] == 4096 + len("OPERATION ")
    assert location["format"] == "elf"
    severities = {
        r.severity for r in rows
        if json.loads(r.evidence_json).get("rule_id") == "dirty_word.codename"
    }
    assert severities == {"critical"}
    assert dacv["disqualified"] is True
    assert dacv["scoped"]["grade"] == "F"


def test_the_binary_is_not_scanned_twice(db, tmp_path):
    """Two owners for one file would double the evidence and, with the family
    cap in play, change the score."""
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "payload.bin").write_bytes(elf_with(b"OPERATION NIGHTFALL", pad=512))
    wl.create(db, "Engagement", [{"term": "NIGHTFALL", "category": "codename"}])

    bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)

    codenames = [
        r for r in db.scalars(select(Finding)).all()
        if r.sensor == "dirty_word"
        and json.loads(r.evidence_json).get("rule_id") == "dirty_word.codename"
    ]
    assert len(codenames) == 1


def test_findings_from_a_real_compiled_binary_validate(tmp_path):
    """The synthetic ELF above proves the arithmetic; this proves the shape
    survives a file produced by a compiler rather than by the test."""
    import shutil
    import subprocess

    if not shutil.which("gcc"):
        pytest.skip("no compiler")

    src = tmp_path / "t.c"
    src.write_text('const char *o = "OPERATION NIGHTFALL";\nint main(void){return 0;}\n')
    subprocess.run(["gcc", "-o", str(tmp_path / "loader"), str(src)], check=True)
    src.unlink()

    matches = dw.scan_binaries(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])
    findings = dw.parse_hits({"matches": matches},
                             [{"term": "NIGHTFALL", "category": "codename"}], tmp_path)
    check = validator("raw-finding.schema.json")

    assert findings
    for finding in findings:
        check.validate(finding.to_dict())
        assert finding.location.kind == "binary"

    data = (tmp_path / "loader").read_bytes()
    offset = findings[0].location.offset
    assert data[offset:offset + 9] == b"NIGHTFALL", "offset is not seekable"


def test_the_rule_mapping_promotes_a_binary_codename_the_same_as_a_source_one():
    """The category ladder is about what was declared, not where it was found."""
    hits = {"matches": [BINARY_HIT]}
    findings = dw.parse_hits(hits, [{"term": "NIGHTFALL", "category": "codename"}],
                             Path("/s"))
    assert build_rule_mapping(findings)["dirty_word.codename"] == "critical"
