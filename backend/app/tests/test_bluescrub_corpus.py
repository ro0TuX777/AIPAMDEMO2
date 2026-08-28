"""Aggregate regression over the intended subject: a compiled artifact.

Every measurement that shaped this pipeline — the severity ladder, the
category tiers, the false-positive filters, the `K_P` constants — was taken
against **source trees**. BlueScrub grades offensive tooling artifacts, which
are compiled. The existing `sample_repo_spec.json` is source only, so nothing
exercised the pipeline against the thing it exists for.

Two defects found late in Sprint 5 were both invisible to 1500 unit tests and
both obvious the first time anyone looked at aggregate output: a `TODO` comment
disqualifying every artifact scanned, and 287 findings sitting unscored in the
unmapped counter. Neither is the kind of thing a per-function test catches.
This file is the counterpart to those tests — it asserts the *shape* of what
comes out, so a change that quietly degrades coverage fails here.

It also records what is **not** found. Those assertions are not endorsements;
they are a tripwire. A gap that is merely known gets forgotten, and a gap that
is asserted fails loudly the moment somebody fixes it, forcing the fix to be
acknowledged rather than absorbed.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import service as bs_service, wordlists as wl
from backend.app.bluescrub.pillars import Pillar
from backend.app.database_v2 import Base
from backend.app.models.finding import Finding

SPEC = (Path(__file__).resolve().parent / "fixtures" / "bluescrub"
        / "implant_spec.json")

pytestmark = pytest.mark.skipif(
    not shutil.which("gcc"), reason="no compiler for the artifact fixture"
)


@pytest.fixture(scope="module")
def implant(tmp_path_factory):
    """Compile the fixture once. Inert: strings and structure, no behaviour."""
    spec = json.loads(SPEC.read_text())
    root = tmp_path_factory.mktemp("implant")
    src = root / "input" / "source"
    src.mkdir(parents=True)

    source = src / spec["source_name"]
    source.write_text(spec["source"])
    subprocess.run(
        ["gcc", *spec["compile_args"], "-o", str(src / spec["binary_name"]),
         str(source)],
        check=True, capture_output=True,
    )
    # The artifact ships; its source does not. Leaving the .c behind would let
    # the source analyzers find everything and prove nothing about the binary.
    source.unlink()
    return root, spec


@pytest.fixture(scope="module")
def scanned(implant, tmp_path_factory):
    root, spec = implant
    engine = create_engine(f"sqlite:///{tmp_path_factory.mktemp('db')/'c.db'}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    import os
    os.environ["AIPAM_BLUESCRUB_REQUIRE_UID_DROP"] = "false"
    os.environ.setdefault("AIPAM_BLUESCRUB_SECRET_HMAC_KEY", "corpus-key")

    wl.create(db, "Engagement", [
        {"term": "NIGHTFALL", "category": "codename"},
        {"term": "redcell", "category": "org"},
    ])
    dacv = bs_service.analyze_and_persist(db, "j", root, profile="deep")["dacv"]
    rows = db.scalars(select(Finding)).all()
    evidence = [json.loads(r.evidence_json) for r in rows]
    yield dacv, rows, evidence, spec
    db.close()


def _rules(evidence) -> set[str]:
    return {e.get("rule_id") for e in evidence}


# ── what a compiled artifact must yield ───────────────────────────────────

def test_the_artifact_really_is_stripped_and_sourceless(implant):
    """Otherwise the source analyzers do the work and the test proves nothing
    about binary coverage."""
    root, spec = implant
    src = root / "input" / "source"

    assert not list(src.glob("*.c"))
    assert (src / spec["binary_name"]).exists()
    out = subprocess.run(["file", str(src / spec["binary_name"])],
                         capture_output=True, text=True)
    assert "stripped" in out.stdout, out.stdout


def test_a_declared_codename_in_a_compiled_artifact_disqualifies(scanned):
    dacv, _rows, evidence, _spec = scanned

    assert "dirty_word.codename" in _rules(evidence)
    assert dacv["disqualified"] is True
    assert dacv["scoped"]["grade"] == "F"


def test_every_binary_finding_carries_a_seekable_location(scanned):
    """The defect this replaced: an offset computed, then written into a
    `source` location the contract rejects, so it reached the database with the
    offset discarded."""
    _dacv, _rows, evidence, _spec = scanned

    binary = [e for e in evidence if e.get("location", {}).get("kind") == "binary"]
    assert binary, "nothing reported against the artifact itself"
    for finding in binary:
        location = finding["location"]
        assert len(location["artifact_sha256"]) == 64
        assert location.get("format") == "elf"


def test_the_operator_build_path_is_found(scanned):
    _dacv, _rows, evidence, spec = scanned
    paths = [e for e in evidence if e.get("rule_id") == "build_paths.operator_path"]

    assert paths, "the compiled-in build path was missed"
    assert spec["planted"]["operator_path"] in json.dumps(paths)


def test_the_toolchain_is_reported_below_the_operator(scanned):
    """A GCC version string names the build environment, not its operator, and
    must not compete with the path that names a person."""
    _dacv, rows, evidence, _spec = scanned
    by_rule = {e.get("rule_id"): r.severity for r, e in zip(rows, evidence)}

    assert by_rule.get("dirty_word.toolchain") == "medium"
    assert by_rule.get("build_paths.operator_path") == "high"


def test_attribution_is_fully_assessed(scanned):
    _dacv, _rows, _evidence, _spec = scanned
    attribution = _dacv["pillars"][Pillar.attribution.value]

    assert attribution["coverage"] == 1.0
    assert attribution["findings"] > 0


def test_nothing_lands_unmapped(scanned):
    """The counter reached 287 once because nobody was watching it."""
    dacv, _rows, _evidence, _spec = scanned
    assert dacv["unmapped_findings"] == 0


def test_no_fingerprint_collisions(scanned):
    dacv, _rows, _evidence, _spec = scanned
    assert dacv["fingerprint_collisions"] == 0


def test_hygiene_terms_do_not_flood_a_compiled_artifact(scanned):
    """The shipped packs used to contribute half of all findings."""
    _dacv, rows, _evidence, _spec = scanned
    info = [r for r in rows if r.severity == "info"]

    assert len(info) <= len(rows) // 4, f"{len(info)} of {len(rows)} are info"


# ── the tripwire: gaps asserted so a fix cannot pass unnoticed ────────────

def test_the_hardcoded_c2_is_reported(scanned):
    """This was a tripwire, and it fired. Kept as a positive assertion.

    A hardcoded C2 is the single finding the Co-Optability pillar exists for —
    whoever seizes that address inherits every implant pointing at it — and for
    five sprints nothing reported one. The capability was never missing: the
    vendored binary analyzer extracts addresses with regex over bytes and no
    third-party library, but sits behind
    `REQUIRED_CAPABILITIES = ("pe_analysis", "elf_analysis")` and so went dark
    on any host without `pefile`/`pyelftools`.
    """
    dacv, _rows, evidence, spec = scanned

    c2 = [e for e in evidence if e.get("issue_family") == "hardcoded-c2"]
    assert c2, "the compiled-in C2 address was missed"
    assert spec["planted"]["c2_address"].startswith(c2[0]["code"])
    assert dacv["pillars"][Pillar.co_optability.value]["findings"] > 0


def test_the_c2_offset_points_at_the_address(implant, scanned):
    """The address is recovered as `........10.20.30.40:8443` — surrounding
    binary junk includes dots, which is why matching the quad with a lookbehind
    silently dropped the one finding this detector exists for."""
    root, spec = implant
    _dacv, _rows, evidence, _spec = scanned

    c2 = next(e for e in evidence if e.get("issue_family") == "hardcoded-c2")
    artifact = (root / "input" / "source" / spec["binary_name"]).read_bytes()
    at = c2["location"]["offset"]

    assert artifact[at:at + 11] == b"10.20.30.40"


def test_the_internal_hostname_is_reported(scanned):
    _dacv, _rows, evidence, spec = scanned
    hosts = [e for e in evidence
             if e.get("rule_id") == "binary_indicators.internal_host"]

    assert spec["planted"]["hostname"] in {e["code"] for e in hosts}


def test_known_gap_the_mutex_is_found_only_because_it_holds_a_declared_term(scanned):
    """A mutex name is a `forensic_artifact` — a defender detects the implant
    by it — and nothing looks for mutex patterns in binaries. This one surfaces
    only because the operator happened to declare `NIGHTFALL`, which the mutex
    contains. Rename the mutex and it vanishes."""
    _dacv, _rows, evidence, _spec = scanned

    assert not [e for e in evidence if e.get("issue_family") == "forensic-artifact"]


def test_known_gap_the_hardcoded_user_agent_is_not_reported(scanned):
    """A fixed User-Agent is a signature a defender writes a rule against."""
    _dacv, _rows, evidence, spec = scanned
    assert spec["planted"]["user_agent"] not in json.dumps(evidence)


def test_the_pillars_that_need_absent_tooling_say_so(scanned):
    """The honest half of the picture: where coverage is missing it is
    reported as missing rather than scored zero."""
    dacv, _rows, _evidence, _spec = scanned

    for pillar in (Pillar.detectability, Pillar.vulnerability):
        result = dacv["pillars"][pillar.value]
        assert result["coverage"] < 1.0
        assert result["status"] in ("degraded", "not_assessed")


def test_without_a_wordlist_the_artifact_still_reports_something(implant,
                                                                tmp_path_factory):
    """How much of this rests on the operator having declared terms in
    advance. Two findings survive — the build path and the toolchain — and
    both come from detectors that need nothing declared."""
    root, _spec = implant
    engine = create_engine(f"sqlite:///{tmp_path_factory.mktemp('db2')/'n.db'}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    import os
    os.environ["AIPAM_BLUESCRUB_REQUIRE_UID_DROP"] = "false"
    dacv = bs_service.analyze_and_persist(db, "j", root, profile="deep")["dacv"]
    rules = _rules([json.loads(r.evidence_json)
                    for r in db.scalars(select(Finding)).all()])

    assert "build_paths.operator_path" in rules
    assert "binary_indicators.hardcoded_address" in rules, (
        "the C2 must not depend on somebody having declared a term"
    )
    assert dacv["disqualified"] is False, (
        "nothing was declared, so nothing should be decisive"
    )
    db.close()
