"""FLOSS — string recovery by emulation.

Two things are being pinned here. The first is what FLOSS uniquely reports: a
string recovered from a stack or a decoding routine is proof the author tried
to hide it and failed, which no pattern matcher can establish because the
evidence is that the code was run.

The second is the loop Sprint 5 left open. Dirty-word and build-path scanning
over binaries are both `parse_only`, so both see only what is already sitting
in the file; a codename assembled at runtime was invisible to them and a deep
scan admitted it by degrading Attribution coverage. FLOSS writes what it
recovered to a cache those scanners read. The test that matters is the one
where a declared term exists *only* in the cache.

FLOSS is not installed here, so `run` is exercised with a stubbed boundary and
the parsing and finding construction — where adapter bugs live — are pure.
"""

import json
from pathlib import Path

import pytest

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.isolation import AnalyzerResult, AnalyzerStatus
from backend.app.bluescrub.pillars import DetectorClass, IssueFamily, Pillar
from backend.app.bluescrub.scanners import dirty_word as dw
from backend.app.bluescrub.scanners import floss
from backend.app.bluescrub.scoring import ScannerRun, coverage_for
from backend.app.tests._bluescrub_schemas import validator


@pytest.fixture(autouse=True)
def _sandbox(monkeypatch):
    monkeypatch.setenv("AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "false")
    monkeypatch.delenv(binstrings.CACHE_ENV, raising=False)
    monkeypatch.delenv(binstrings.PROFILE_ENV, raising=False)


def elf_with(payload: bytes, *, pad: int = 512) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * (pad - 7) + payload + b"\x00" * 64


def pe_with(payload: bytes, *, pad: int = 512) -> bytes:
    """FLOSS decodes strings for PE only, so its fixtures have to be PE."""
    return b"MZ\x90\x00\x03" + b"\x00" * (pad - 5) + payload + b"\x00" * 64


FLOSS_OUTPUT = {
    "strings": {
        "static_strings": [{"string": "libc.so.6", "offset": 512, "encoding": "ASCII"}],
        "stack_strings": [{"string": "OPERATION NIGHTFALL", "program_counter": 4198400}],
        "tight_strings": [{"string": "beacon.redcell.internal"}],
        "decoded_strings": [{"string": "ghp_notarealtoken", "decoding_routine": 4198656}],
    },
}


def _stub_floss(monkeypatch, payload=FLOSS_OUTPUT, *, status=AnalyzerStatus.completed):
    monkeypatch.setattr(floss.shutil, "which", lambda _n: "/usr/bin/floss")

    def _fake(argv, **_kw):
        if "--version" in argv:
            return AnalyzerResult(status=AnalyzerStatus.completed, stdout=b"floss 3.1.1",
                                  exit_code=0)
        body = json.dumps(payload).encode() if payload is not None else b"not json"
        return AnalyzerResult(status=status, stdout=body,
                              exit_code=0 if status is AnalyzerStatus.completed else 1)

    monkeypatch.setattr(floss, "run_analyzer", _fake)


# ── what only emulation can establish ─────────────────────────────────────

def test_a_recovered_runtime_string_is_weak_obfuscation():
    recovery = binstrings.Recovery(sha256="a" * 64, binary_format="elf")
    findings = floss.to_findings("loader", recovery,
                                 binstrings.parse_floss(FLOSS_OUTPUT))

    assert {f.issue_family for f in findings} == {IssueFamily.obfuscation_weak}
    assert all(f.pillar_hint is Pillar.detectability for f in findings)
    assert {f.matched_tokens for f in findings} == {
        "OPERATION NIGHTFALL", "beacon.redcell.internal", "ghp_notarealtoken",
    }


def test_a_static_string_is_not_an_obfuscation_finding():
    """It was sitting in the file. Every consumer extracts those unaided, and
    reporting them would mean flagging every string in every binary."""
    findings = floss.to_findings(
        "loader", binstrings.Recovery(sha256="a" * 64),
        binstrings.parse_floss(FLOSS_OUTPUT))

    assert "libc.so.6" not in {f.matched_tokens for f in findings}


def test_the_evidence_is_that_the_code_was_run():
    """Not that a pattern resembled something. That is the strongest class of
    evidence this pipeline produces, and the precedence table should know."""
    finding = floss.to_findings("loader", binstrings.Recovery(sha256="a" * 64),
                                binstrings.parse_floss(FLOSS_OUTPUT))[0]

    assert finding.detector_class is DetectorClass.semantic_dataflow
    assert finding.confidence >= 0.9


def test_a_runtime_string_carries_no_offset():
    """It was never at one, and an offset an analyst cannot seek to is worse
    than an absent one."""
    for finding in floss.to_findings("loader",
                                     binstrings.Recovery(sha256="a" * 64, binary_format="elf"),
                                     binstrings.parse_floss(FLOSS_OUTPUT)):
        assert finding.location.kind == "binary"
        assert finding.location.offset is None
        assert finding.location.artifact_sha256 == "a" * 64


def test_findings_validate_against_the_raw_contract():
    check = validator("raw-finding.schema.json")
    for finding in floss.to_findings("loader",
                                     binstrings.Recovery(sha256="b" * 64, binary_format="pe"),
                                     binstrings.parse_floss(FLOSS_OUTPUT)):
        check.validate(finding.to_dict())


def test_one_string_from_a_loop_is_one_finding():
    repeated = [binstrings.RecoveredString("SAME", None, "ascii", "decoded")] * 12
    findings = floss.to_findings("loader", binstrings.Recovery(sha256="c" * 64), repeated)

    assert len(findings) == 1


def test_a_flooded_artifact_is_capped_and_says_so(caplog):
    many = [
        binstrings.RecoveredString(f"s{n}", None, "ascii", "decoded")
        for n in range(floss.MAX_FINDINGS_PER_ARTIFACT + 25)
    ]
    findings = floss.to_findings("loader", binstrings.Recovery(sha256="d" * 64), many)

    assert len(findings) == floss.MAX_FINDINGS_PER_ARTIFACT
    assert "cap" in caplog.text


# ── the loop Sprint 5 left open ───────────────────────────────────────────

def test_a_declared_term_that_exists_only_in_the_cache_is_found(tmp_path, monkeypatch):
    """The whole point. The term is assembled at runtime, so it is nowhere in
    the file — a `parse_only` scanner reading bytes cannot see it, and before
    the cache existed the dirty-word scanner simply missed it."""
    artifact = tmp_path / "loader"
    artifact.write_bytes(elf_with(b"nothing interesting here"))
    digest = binstrings.recover(artifact).sha256
    assert b"NIGHTFALL" not in artifact.read_bytes(), "the fixture gives it away"

    cache = tmp_path / "strings.cache.json"
    cache.write_text(json.dumps(binstrings.cache_payload({
        digest: binstrings.Recovery(
            sha256=digest, binary_format="elf", method="floss",
            strings=[binstrings.RecoveredString(
                "OPERATION NIGHTFALL", None, "ascii", "stack")],
        ),
    })))
    monkeypatch.setenv(binstrings.CACHE_ENV, str(cache))

    hits = dw.scan_binaries(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}])

    assert len(hits) == 1
    assert hits[0]["recovery"] == "stack"
    assert hits[0]["offset"] is None
    assert hits[0]["sha256"] == digest


def test_without_the_cache_the_same_term_is_invisible(tmp_path):
    artifact = tmp_path / "loader"
    artifact.write_bytes(elf_with(b"nothing interesting here"))

    assert dw.scan_binaries(tmp_path, [{"term": "NIGHTFALL", "category": "codename"}]) == []


def test_the_cache_is_keyed_on_the_artifact_not_its_path(tmp_path):
    """The same binary staged twice under different names is one recovery, and
    a path that changed between scanners is not a cache miss."""
    (tmp_path / "a").write_bytes(elf_with(b"payload"))
    (tmp_path / "b").write_bytes(elf_with(b"payload"))
    digest = binstrings.recover(tmp_path / "a").sha256

    cache = tmp_path / "c.json"
    cache.write_text(json.dumps(binstrings.cache_payload({
        digest: binstrings.Recovery(sha256=digest, strings=[
            binstrings.RecoveredString("NIGHTFALL", None, "ascii", "decoded")]),
    })))

    for name in ("a", "b"):
        assert binstrings.read_cache(
            binstrings.recover(tmp_path / name).sha256, str(cache))


def test_a_cache_problem_costs_depth_not_correctness(tmp_path):
    """Every consumer still has its own static pass, so a missing or corrupt
    cache must degrade rather than fail."""
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert binstrings.read_cache("a" * 64, str(broken)) == []

    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"schema": "something/9", "artifacts": {}}))
    assert binstrings.read_cache("a" * 64, str(wrong)) == []

    assert binstrings.read_cache("a" * 64, str(tmp_path / "absent.json")) == []
    assert binstrings.read_cache("", str(broken)) == []


def test_only_runtime_strings_are_cached(tmp_path, monkeypatch):
    """A large binary yields tens of thousands of static strings. Caching them
    would write megabytes the consumers already derive for themselves."""
    (tmp_path / "loader.exe").write_bytes(pe_with(b"libc.so.6"))
    _stub_floss(monkeypatch)

    floss.run(tmp_path, tmp_path / "out")
    payload = json.loads((tmp_path / "out" / floss.CACHE_FILENAME).read_text())

    cached = [s for a in payload["artifacts"].values() for s in a["strings"]]
    assert {s["method"] for s in cached} <= floss.RUNTIME_METHODS
    assert "libc.so.6" not in {s["value"] for s in cached}


# ── coverage ──────────────────────────────────────────────────────────────

def test_floss_missing_is_real_coverage_loss(tmp_path, monkeypatch):
    """Whether the obfuscation holds cannot be answered without emulating it."""
    (tmp_path / "loader.exe").write_bytes(pe_with(b"x"))
    monkeypatch.setattr(floss.shutil, "which", lambda _n: None)
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "unavailable"
    coverage, _, missing = coverage_for(Pillar.detectability, [ScannerRun(
        sensor="floss", status=outcome.status, required_for=(Pillar.detectability,))])
    assert coverage == 0.0 and missing == ["floss"]


def test_no_binaries_is_a_measured_result(tmp_path, monkeypatch):
    (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
    _stub_floss(monkeypatch)
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "completed"
    assert "no binary artifacts" in outcome.reason


def test_a_deep_scan_stops_degrading_once_a_cache_exists(tmp_path, monkeypatch):
    """`strings_static_only` reports that the deep profile asked for
    emulation-grade recovery and got the static pass. A cache means it did
    not."""
    monkeypatch.setattr(binstrings.shutil, "which", lambda _n: None)
    assert binstrings.recovery_state("deep") == "strings_static_only"

    cache = tmp_path / "c.json"
    cache.write_text(json.dumps(binstrings.cache_payload({})))
    monkeypatch.setenv(binstrings.CACHE_ENV, str(cache))
    assert binstrings.recovery_state("deep") is None


def test_an_artifact_that_will_not_emulate_degrades_the_rest(tmp_path, monkeypatch):
    (tmp_path / "loader.exe").write_bytes(pe_with(b"x"))
    _stub_floss(monkeypatch, payload=None)          # unparseable output
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "completed_truncated"
    assert "could not emulate" in outcome.reason


def test_the_artifact_count_is_bounded_and_says_so(tmp_path, monkeypatch, caplog):
    for n in range(floss.MAX_ARTIFACTS + 5):
        (tmp_path / f"loader{n}.exe").write_bytes(pe_with(b"x"))
    _stub_floss(monkeypatch)
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "completed_truncated"
    assert str(floss.MAX_ARTIFACTS) in outcome.reason
    assert "emulating the first" in caplog.text


# ── ordering and class ────────────────────────────────────────────────────

def test_floss_runs_before_the_scanners_that_read_its_cache():
    """Alphabetically `floss` sorts after both. Leaving the dependency to the
    accident of a name makes it invisible and one rename from breaking."""
    from backend.app.bluescrub.registry import scanners_for

    order = [s.name for s in scanners_for("deep")]
    assert order.index("floss") < order.index("dirty_word")
    assert order.index("floss") < order.index("build_paths")


def test_floss_is_emulation_class_and_deep_only():
    """It interprets attacker-authored code. The isolation contract gives that
    its own ceilings and confines it to deep."""
    from backend.app.bluescrub.pillars import RiskClass
    from backend.app.bluescrub.registry import SCANNERS

    spec = SCANNERS["floss"]
    assert spec.risk_class is RiskClass.emulation
    assert spec.profiles == ("deep",)
    assert spec.limits.address_space_bytes == 8 * 1024 ** 3
    assert spec.limits.wall_clock_seconds == 900


def test_the_static_pass_is_not_repeated_by_floss():
    """It already ran in-process and already has the file offsets."""
    assert "--no" in binstrings.floss_argv(Path("/a"))
    assert "static" in binstrings.floss_argv(Path("/a"))


# ── the cache is job-scoped ───────────────────────────────────────────────

def test_the_cache_does_not_leak_between_jobs(tmp_path, monkeypatch):
    """Leaving the variable set would point the next job at the previous job's
    artifacts — and because the cache is keyed on digest, a collision would
    silently attribute one artifact's recovered strings to another."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.app.bluescrub import service as bs_service
    from backend.app.database_v2 import Base

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL"))

    monkeypatch.setenv(binstrings.CACHE_ENV, "/from/a/previous/job.json")
    bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)

    assert binstrings.CACHE_ENV not in __import__("os").environ
    db.close()


def test_a_stale_cache_path_is_cleared_before_the_scan(tmp_path, monkeypatch):
    """A job that died without cleaning up must not hand its cache to the next
    one. The variable is cleared going in as well as coming out."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from backend.app.bluescrub import service as bs_service
    from backend.app.database_v2 import Base

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL"))

    stale = tmp_path / "stale.json"
    digest = binstrings.recover(src / "loader").sha256
    stale.write_text(json.dumps(binstrings.cache_payload({
        digest: binstrings.Recovery(sha256=digest, strings=[
            binstrings.RecoveredString("GHOSTWRITER", None, "ascii", "decoded")]),
    })))
    monkeypatch.setenv(binstrings.CACHE_ENV, str(stale))

    from backend.app.bluescrub import wordlists as wl
    wl.create(db, "Ops", [{"term": "GHOSTWRITER", "category": "codename"}])
    bs_service.analyze_and_persist(db, "j", tmp_path, profile="triage", run_output_dir=tmp_path)

    from sqlalchemy import select

    from backend.app.models.finding import Finding
    rules = {json.loads(r.evidence_json).get("rule_id")
             for r in db.scalars(select(Finding)).all()}
    assert "dirty_word.codename" not in rules, (
        "a previous job's recovered strings were attributed to this artifact"
    )
    db.close()


# ── FLOSS decodes strings for PE only ─────────────────────────────────────

def test_an_elf_is_not_a_failed_emulation(tmp_path, monkeypatch):
    """Handed an ELF, FLOSS 3.1 answers "supports the following formats ...:
    PE" and exits 0. The adapter read that as a failed emulation and reported
    lost coverage on every Linux artifact — which would have degraded
    Attribution on a question no tool in the manifest can answer."""
    (tmp_path / "loader").write_bytes(elf_with(b"OPERATION NIGHTFALL"))
    _stub_floss(monkeypatch)
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "completed", "an inapplicable format is not a failure"
    assert "not PE" in outcome.reason
    assert "PE only" in outcome.reason


def test_a_pe_is_emulated(tmp_path, monkeypatch):
    (tmp_path / "loader.exe").write_bytes(pe_with(b"anything"))
    _stub_floss(monkeypatch)
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "completed"
    assert outcome.findings, "the stubbed payload should have produced findings"


def test_floss_is_never_asked_to_guess_shellcode():
    """`--format sc32|sc64` would let it read a raw blob, at the price of two
    guesses — that the blob is shellcode, and its bitness. Being wrong emulates
    nonsense rather than erroring."""
    assert floss.SUPPORTED_FORMATS == frozenset({"pe"})
    assert "--format" not in binstrings.floss_argv(Path("/a"))


def test_an_inapplicable_artifact_does_not_hide_a_real_failure(tmp_path, monkeypatch):
    """A PE that genuinely fails must still degrade, even alongside an ELF that
    was merely skipped."""
    (tmp_path / "skipped").write_bytes(elf_with(b"x"))
    (tmp_path / "broken.exe").write_bytes(pe_with(b"y"))
    _stub_floss(monkeypatch, payload=None)
    outcome = floss.run(tmp_path, tmp_path / "out")

    assert outcome.status == "completed_truncated"
    assert "could not emulate" in outcome.reason
