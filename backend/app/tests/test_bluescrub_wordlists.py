"""Dirty-word list management.

Validation refuses rather than corrects. A term quietly dropped on save looks
identical, later, to a term that matched nothing — and the whole point of an
operator-supplied list is that the operator knows what they put in it.
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import wordlists as wl
from backend.app.database_v2 import Base
from backend.app.models.bluescrub import BlueScrubWordlist


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'w.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


# ── validation ────────────────────────────────────────────────────────────

def test_bare_strings_are_accepted_and_normalised():
    out = wl.validate_entries(["OPERATION_NIGHTFALL", "rt-2411"])
    assert [e["term"] for e in out] == ["OPERATION_NIGHTFALL", "rt-2411"]
    assert all(e["kind"] == "literal" for e in out)


def test_two_character_terms_are_refused():
    """"C2" fired 67 times on a codebase that merely discusses C2."""
    with pytest.raises(wl.WordlistError) as exc:
        wl.validate_entries(["C2"])
    assert exc.value.reason == "term_too_short"


def test_regex_entries_are_refused_rather_than_silently_ignored():
    """The matcher is literal-only. A regex entry that can never match would
    present as coverage."""
    with pytest.raises(wl.WordlistError) as exc:
        wl.validate_entries([{"term": "op-.*", "kind": "regex"}])
    assert exc.value.reason == "regex_not_supported"


def test_unknown_category_is_refused():
    with pytest.raises(wl.WordlistError) as exc:
        wl.validate_entries([{"term": "nightfall", "category": "vibes"}])
    assert exc.value.reason == "unknown_category"


def test_duplicates_collapse_case_insensitively():
    out = wl.validate_entries(["Nightfall", "nightfall", "NIGHTFALL"])
    assert len(out) == 1


@pytest.mark.parametrize("bad,reason", [
    ([], "no_usable_terms"),
    ([""], "empty_term"),
    (["x" * 300], "term_too_long"),
    ("not a list", "entries_not_a_list"),
])
def test_malformed_input_is_refused(bad, reason):
    with pytest.raises(wl.WordlistError) as exc:
        wl.validate_entries(bad)
    assert exc.value.reason == reason


def test_term_ceiling():
    with pytest.raises(wl.WordlistError) as exc:
        wl.validate_entries([f"term{i:05d}" for i in range(wl.MAX_TERMS_PER_LIST + 1)])
    assert exc.value.reason == "too_many_terms"


# ── CRUD ──────────────────────────────────────────────────────────────────

def test_create_and_list(db):
    wl.create(db, "Engagement RT-2411", ["NIGHTFALL", "rt-2411"])
    rows = wl.all_lists(db)
    assert [r.name for r in rows] == ["Engagement RT-2411"]
    assert not rows[0].builtin


def test_update_replaces_entries(db):
    row = wl.create(db, "L", ["alpha"])
    wl.update(db, row.id, entries=["bravo", "charlie"])
    terms = [e["term"] for e in json.loads(db.get(BlueScrubWordlist, row.id).entries_json)]
    assert terms == ["bravo", "charlie"]


def test_update_validates_too(db):
    row = wl.create(db, "L", ["alpha"])
    with pytest.raises(wl.WordlistError):
        wl.update(db, row.id, entries=["C2"])


def test_delete(db):
    row = wl.create(db, "L", ["alpha"])
    wl.delete(db, row.id)
    assert wl.all_lists(db) == []


def test_unknown_list_is_reported(db):
    for op in (lambda: wl.update(db, "nope", entries=["a"]), lambda: wl.delete(db, "nope")):
        with pytest.raises(wl.WordlistError) as exc:
            op()
        assert exc.value.reason == "not_found"


# ── builtin packs ─────────────────────────────────────────────────────────

def test_seeding_is_idempotent(db):
    assert wl.seed_builtins(db) == 3
    assert wl.seed_builtins(db) == 0
    assert len(wl.all_lists(db)) == 3


def test_builtin_names_have_no_decoration(db):
    """Upstream prefixes pack names with emoji; lookups need stable names."""
    wl.seed_builtins(db)
    for row in wl.all_lists(db):
        assert row.name[0].isalnum(), row.name


def test_builtins_carry_a_category_so_severity_can_differ(db):
    """The packs are flat word lists upstream. A classification marking and a
    build-path fragment must not score alike."""
    wl.seed_builtins(db)
    categories = {r.name: r.category for r in wl.all_lists(db)}
    assert categories["Build Artifacts"] == "path"
    assert categories["Tool Signatures"] == "tooling"
    assert categories["Common Leaks (OPSEC)"] == "identity"


def test_builtins_are_read_only(db):
    wl.seed_builtins(db)
    builtin = next(r for r in wl.all_lists(db) if r.builtin)

    for op in (lambda: wl.update(db, builtin.id, entries=["x"]),
               lambda: wl.delete(db, builtin.id)):
        with pytest.raises(wl.WordlistError) as exc:
            op()
        assert exc.value.reason == "builtin_is_read_only"


def test_short_builtin_terms_are_dropped_on_seed(db):
    """The packs contain entries the validator would refuse from an operator."""
    wl.seed_builtins(db)
    for row in wl.all_lists(db):
        for entry in json.loads(row.entries_json):
            assert len(entry["term"]) >= 3, entry


# ── term aggregation ──────────────────────────────────────────────────────

def test_active_terms_deduplicate_across_lists(db):
    wl.create(db, "A", ["NIGHTFALL", "shared"])
    wl.create(db, "B", ["shared", "OTHER"])
    terms = [t["term"] for t in wl.active_terms(db)]
    assert sorted(terms) == ["NIGHTFALL", "OTHER", "shared"]


def test_active_terms_carry_category_and_origin(db):
    wl.create(db, "Ops", [{"term": "NIGHTFALL", "category": "codename"}])
    term = wl.active_terms(db)[0]
    assert term["category"] == "codename"
    assert term["list"] == "Ops"


def test_unreadable_list_is_skipped_not_fatal(db):
    good = wl.create(db, "Good", ["NIGHTFALL"])
    db.add(BlueScrubWordlist(id="broken", name="Broken", builtin=False,
                             entries_json="{not json", case_sensitive=False,
                             created_at="t"))
    db.commit()

    terms = wl.active_terms(db)
    assert [t["term"] for t in terms] == ["NIGHTFALL"]
    assert good is not None


# ── the shipped packs must not disqualify by themselves ───────────────────

def _pack_severity(category: str) -> str:
    from backend.app.bluescrub.pillars import DetectorClass
    from backend.app.bluescrub.scanners.dirty_word import CATEGORY_FAMILY
    from backend.app.bluescrub.severity_table import canonical_severity

    return canonical_severity(
        f"dirty_word.{category}", CATEGORY_FAMILY[category],
        DetectorClass.regex_pattern,
    )


def test_only_a_personal_mail_domain_disqualifies_from_the_builtin_packs(db):
    """A pack-level category put `TODO`, `DEBUG`, `admin`, `password` and
    `/home/` into the `identity` tier, so any tree containing a comment scored
    F with `disqualified: true` — from the builtin packs alone, with no
    operator input. Same shape as the "C2" failure, arriving through the input
    side instead of the detector side."""
    wl.seed_builtins(db)

    disqualifying = {
        t["term"] for t in wl.active_terms(db)
        if _pack_severity(t["category"]) == "critical"
    }
    assert disqualifying == {
        "@gmail.com", "@outlook.com", "@yahoo.com", "@protonmail.com",
    }


@pytest.mark.parametrize("term,category", [
    ("TODO", "hygiene"), ("DEBUG", "hygiene"), ("password", "hygiene"),
    ("admin", "hygiene"), ("root", "hygiene"), ("localhost", "hygiene"),
    ("/home/", "path"), ("C:\\Users\\", "path"),
    (".internal", "hostname"), ("@gmail.com", "identity"),
    ("gcc", "toolchain"), ("Makefile", "toolchain"),
])
def test_pack_terms_carry_a_reviewed_category(db, term, category):
    """One category per pack was not enough: "Common Leaks (OPSEC)" holds
    personal mail domains next to developer-note markers."""
    wl.seed_builtins(db)
    by_term = {t["term"]: t["category"] for t in wl.active_terms(db)}

    assert by_term[term] == category


def test_the_ladder_bottoms_out_below_medium():
    """Without a tier under `medium`, every weak-but-real term had to be filed
    somewhere that overstated it."""
    assert _pack_severity("hygiene") == "info"
    assert _pack_severity("toolchain") == "medium"
    assert _pack_severity("identity") == "critical"


def test_the_new_tiers_are_accepted_from_an_operator(db):
    row = wl.create(db, "Ops", [{"term": "internal-build", "category": "toolchain"},
                                {"term": "scratchpad", "category": "hygiene"}])
    assert row.id


def test_a_hygiene_term_is_still_attribution_not_nothing():
    """Weak is not absent. The operator asked to see these; they are shown,
    counted, and capped — the info cap bounds them at 10% of the pillar."""
    from backend.app.bluescrub.pillars import FAMILY_PILLAR, Pillar
    from backend.app.bluescrub.scanners.dirty_word import CATEGORY_FAMILY

    assert FAMILY_PILLAR[CATEGORY_FAMILY["hygiene"]] is Pillar.attribution
