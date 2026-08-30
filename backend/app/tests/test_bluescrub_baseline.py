"""Baselines, and refusing a comparison that would mislead.

The contract is specific about the failure case:

    A rejected comparison returns `incomparable` with the differing field
    named. "Incomparable" without a reason is an error message users cannot
    act on.  — SCORING_SPEC §6

That single sentence decides the design. A differing field cannot be recovered
from a SHA-256, so the baseline stores the signature's payload as well as its
digest; the digest still decides, the payload only explains.
"""

import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import baseline as bl
from backend.app.bluescrub.models import CanonicalGroup, Location, RawFinding
from backend.app.bluescrub.pillars import IssueFamily, Pillar
from backend.app.bluescrub.scoring import digest_payload, signature_payload
from backend.app.database_v2 import Base
from backend.app.models.bluescrub import BlueScrubBaseline


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'b.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def fields(**overrides):
    base = dict(
        profile="deep",
        scanner_manifest_digest="sha256:aa",
        ruleset_versions_digest="sha256:bb",
        required_scanners=["semgrep", "dirty_word"],
        pillar_scope=[Pillar.attribution, Pillar.vulnerability],
        config_hash="sha256:cc",
    )
    base.update(overrides)
    return signature_payload(**base)


def group(finding_id: str, severity: str = "high",
          rule: str = "dirty_word.codename",
          pillar: Pillar = Pillar.attribution) -> CanonicalGroup:
    member = RawFinding(
        sensor="dirty_word", sensor_version="v", rule_id=rule,
        issue_family=IssueFamily.attribution_marking, confidence=0.9,
        location=Location(kind="source", file="a.c", start_line=1, start_column=0),
    )
    return CanonicalGroup(
        canonical_id=finding_id, issue_family=IssueFamily.attribution_marking,
        pillar=pillar, severity=severity, severity_source="rule_mapping",
        scoring_confidence=0.9, primary_sensor="dirty_word", primary_rule_id=rule,
        occurrence_index=0, members=[member], location=member.location,
    )


def dacv(sig: dict) -> dict:
    return {"schema": "bluescrub/2", "compatibility_signature": digest_payload(sig)}


def set_it(db, groups, sig=None, **kw):
    sig = sig or fields()
    return bl.set_baseline(
        db, project_id="p", job_id="j1", dacv=dacv(sig),
        findings=bl.snapshot(groups), signature_fields=sig, **kw,
    )


def cmp(db, groups, sig=None):
    return bl.compare(db, project_id="p", findings=bl.snapshot(groups),
                      signature_fields=sig or fields())


# ── freezing a comparison point ───────────────────────────────────────────

def test_a_baseline_stores_what_the_diff_needs_and_no_more(db):
    """A baseline is kept indefinitely while job evidence expires at thirty
    days. Freezing snippets here would quietly recreate the retention the
    policy removed."""
    set_it(db, [group("bs-a"), group("bs-b", "medium")])
    stored = json.loads(db.scalar(select(BlueScrubBaseline)).findings_json)

    assert {f["finding_id"] for f in stored["findings"]} == {"bs-a", "bs-b"}
    for finding in stored["findings"]:
        assert set(finding) == {"finding_id", "rule_id", "pillar", "severity"}
        assert "code" not in finding and "matched_tokens" not in finding


def test_setting_a_baseline_stands_the_previous_one_down(db):
    """Superseded, not deleted: a previous comparison point is still evidence
    of what was accepted once."""
    set_it(db, [group("bs-a")], label="first")
    set_it(db, [group("bs-b")], label="second")

    rows = db.scalars(select(BlueScrubBaseline)).all()
    assert len(rows) == 2
    assert [r.label for r in rows if r.active] == ["second"]


def test_the_active_baseline_is_the_one_compared_against(db):
    set_it(db, [group("bs-a")], label="first")
    set_it(db, [group("bs-a"), group("bs-b")], label="second")

    result = cmp(db, [group("bs-a")])
    assert result.baseline_label == "second"
    assert [d.finding_id for d in result.fixed] == ["bs-b"]


def test_no_baseline_is_reported_rather_than_treated_as_empty(db):
    """An empty baseline would make every finding look new."""
    result = cmp(db, [group("bs-a")])

    assert result.comparable is False
    assert "no active baseline" in result.reason
    assert result.new == []


# ── the diff ──────────────────────────────────────────────────────────────

def test_new_fixed_and_regressed_are_three_separate_answers(db):
    """A net count cannot distinguish "three fixed, three appeared" from
    "nothing happened"."""
    set_it(db, [group("bs-keep"), group("bs-gone"), group("bs-worse", "low")])

    result = cmp(db, [group("bs-keep"), group("bs-worse", "critical"),
                      group("bs-fresh")])

    assert [d.finding_id for d in result.new] == ["bs-fresh"]
    assert [d.finding_id for d in result.fixed] == ["bs-gone"]
    assert [d.finding_id for d in result.regressed] == ["bs-worse"]
    assert result.unchanged == 1


def test_a_regression_reports_what_it_was(db):
    """The severity that rose on a finding nobody touched is the one an analyst
    most needs to see."""
    set_it(db, [group("bs-a", "low")])
    result = cmp(db, [group("bs-a", "critical")])

    regressed = result.regressed[0]
    assert (regressed.was, regressed.severity) == ("low", "critical")
    assert regressed.to_dict()["was"] == "low"


def test_a_severity_that_falls_is_not_a_regression(db):
    set_it(db, [group("bs-a", "critical")])
    result = cmp(db, [group("bs-a", "low")])

    assert result.regressed == [] and result.unchanged == 1


def test_the_diff_is_ordered_worst_first(db):
    set_it(db, [])
    result = cmp(db, [group("bs-1", "low"), group("bs-2", "critical"),
                      group("bs-3", "medium")])

    assert [d.severity for d in result.new] == ["critical", "medium", "low"]


def test_an_identical_scan_reports_nothing_changed(db):
    groups = [group("bs-a"), group("bs-b", "medium")]
    set_it(db, groups)
    result = cmp(db, groups)

    assert (result.new, result.fixed, result.regressed) == ([], [], [])
    assert result.unchanged == 2


# ── refusing a comparison, with a reason ──────────────────────────────────

@pytest.mark.parametrize("override,field", [
    ({"profile": "triage"}, "profile"),
    ({"config_hash": "sha256:different"}, "config_hash"),
    ({"required_scanners": ["semgrep"]}, "required_scanner_availability"),
    ({"pillar_scope": [Pillar.attribution]}, "pillar_scope"),
    ({"ruleset_versions_digest": "sha256:zz"}, "ruleset_versions_digest"),
])
def test_an_incomparable_scan_names_the_field(db, override, field):
    set_it(db, [group("bs-a")])
    result = cmp(db, [group("bs-a")], fields(**override))

    assert result.comparable is False
    assert field in result.reason
    assert [d["field"] for d in result.differing_fields] == [field]


def test_the_refusal_shows_both_values_and_why_it_matters(db):
    """"Incomparable" without a reason is an error message users cannot act
    on. A field name alone is barely better."""
    set_it(db, [group("bs-a")])
    result = cmp(db, [group("bs-a")], fields(profile="triage"))

    差 = result.differing_fields[0]
    assert 差["baseline"] == "deep" and 差["current"] == "triage"
    assert "different profiles" in 差["why"]


def test_quick_is_never_compared_to_deep(db):
    """The comparison table forbids it outright: the two scans looked for
    different things."""
    set_it(db, [group("bs-a")], sig=fields(profile="triage"))
    result = cmp(db, [group("bs-a")], fields(profile="deep"))

    assert result.comparable is False
    assert result.to_dict()["status"] == "incomparable"


def test_every_signature_field_can_be_explained():
    """A field with no explanation degrades to "something changed", which is
    the message the contract rejects."""
    from backend.app.bluescrub.baseline import _FIELD_EXPLANATIONS

    for key in fields():
        assert key in _FIELD_EXPLANATIONS, key


def test_a_refusal_carries_no_diff(db):
    """Reporting new/fixed counts alongside "incomparable" would invite
    reading them anyway."""
    set_it(db, [group("bs-a")])
    payload = cmp(db, [group("bs-b")], fields(profile="triage")).to_dict()

    assert set(payload) == {"status", "reason", "differing_fields"}


# ── the digest still decides ──────────────────────────────────────────────

def test_a_baseline_without_stored_fields_falls_back_to_the_digest(db):
    """Rows written before the payload was stored. If the digests match, the
    scans are comparable and the fields can be taken from the current scan."""
    row = set_it(db, [group("bs-a")])
    row.findings_json = json.dumps({"findings": [
        {"finding_id": "bs-a", "rule_id": "r", "pillar": "Attribution",
         "severity": "high"}]})
    db.commit()

    result = cmp(db, [group("bs-a")])
    assert result.comparable is True and result.unchanged == 1


def test_a_legacy_baseline_that_does_not_match_says_why_it_cannot_explain(db):
    """It must not guess at a field it never stored."""
    row = set_it(db, [group("bs-a")])
    row.findings_json = json.dumps({"findings": []})
    db.commit()

    result = cmp(db, [group("bs-a")], fields(profile="triage"))
    assert result.comparable is False
    assert "cannot be recovered from a digest" in result.reason


def test_unreadable_baseline_content_does_not_raise(db):
    row = set_it(db, [group("bs-a")])
    row.findings_json = "{not json"
    db.commit()

    result = cmp(db, [group("bs-a")])
    assert result.comparable is False


# ── the signature payload ─────────────────────────────────────────────────

def test_the_payload_and_the_digest_stay_in_step():
    from backend.app.bluescrub.scoring import compatibility_signature

    kwargs = dict(profile="deep", scanner_manifest_digest="a",
                  ruleset_versions_digest="b", required_scanners=["x"],
                  pillar_scope=[Pillar.attribution], config_hash="c")
    assert compatibility_signature(**kwargs) == digest_payload(
        signature_payload(**kwargs))


def test_the_baseline_survives_its_job(db):
    """`job_id` is SET NULL so the snapshot outlives the platform's 30-day job
    cleanup — which means the diff must never read back through it."""
    row = set_it(db, [group("bs-a")])
    row.job_id = None
    db.commit()

    result = cmp(db, [group("bs-a")])
    assert result.comparable is True and result.unchanged == 1
