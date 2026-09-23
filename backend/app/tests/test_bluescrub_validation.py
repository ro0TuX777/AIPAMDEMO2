"""Runtime contract validation.

Three violations were live at once when this landed, and none was found by the
1500 tests that existed. Each escaped for the same reason: the schema was
enforced only where a test happened to call it, and a test validates whatever
object it was handed rather than the one that ships.

- A binary dirty-word finding wrote a byte offset into a `source` location.
  No test exercised the binary path.
- `service` adds two keys to `dacv` *after* scoring, and the scoring test
  validated `score_job`'s return value.
- `strings_static_only` was added as a `ruleset_state` without extending the
  enum, so every deep scan without FLOSS produced invalid metrics.

The first two are regression-tested elsewhere. This file tests the net itself,
because a validator that silently does nothing passes every suite there is.
"""

import json
import logging

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.bluescrub import service as bs_service, validation
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import IssueFamily
from backend.app.database_v2 import Base


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path/'v.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _valid() -> RawFinding:
    return RawFinding(
        sensor="dirty_word", sensor_version="v", rule_id="dirty_word.codename",
        issue_family=IssueFamily.attribution_marking, confidence=0.9,
        location=Location(kind="source", file="a.c", start_line=1, start_column=0),
    )


def _invalid() -> RawFinding:
    """The exact defect this net exists for: a binary offset in a source
    location, which the contract rejects for want of a line number."""
    return RawFinding(
        sensor="dirty_word", sensor_version="v", rule_id="dirty_word.codename",
        issue_family=IssueFamily.attribution_marking, confidence=0.9,
        location=Location(kind="source", file="loader", start_column=0, offset=4096),
    )


# ── the net is armed, and it catches ──────────────────────────────────────

def test_validation_is_on_for_the_whole_suite():
    """Asserted rather than assumed: if the conftest fixture stops working,
    every other test in this file passes vacuously."""
    assert validation.enabled() is True


def test_a_contract_violating_finding_is_caught():
    violations = validation.check_raw_findings([_invalid()])

    assert len(violations) == 1
    assert "start_line" in violations[0]


def test_a_valid_finding_is_not():
    assert validation.check_raw_findings([_valid()]) == []


def test_the_schemas_actually_resolve():
    """The schemas cross-reference each other by filename. Without a resolver
    registry the refs fail silently and everything validates against nothing —
    which looks identical to everything being correct."""
    assert validation._validator("raw-finding.schema.json") is not None
    assert validation._validator("dacv-metrics.schema.json") is not None


def test_it_is_off_unless_asked(monkeypatch):
    """Validating thousands of findings per job costs real time."""
    monkeypatch.delenv(validation.ENV, raising=False)
    assert validation.enabled() is False
    assert validation.check_raw_findings([_invalid()]) == []


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("on", True), ("YES", True),
    ("0", False), ("false", False), ("", False),
])
def test_the_flag_is_read_the_way_the_others_are(monkeypatch, value, expected):
    monkeypatch.setenv(validation.ENV, value)
    assert validation.enabled() is expected


# ── it must never cost a scan ─────────────────────────────────────────────

def test_a_violation_is_reported_not_raised(caplog):
    """A contract violation is a defect to fix. The finding is still a
    finding, and losing the scan would be a worse outcome than the defect."""
    with caplog.at_level(logging.ERROR, logger="backend.app.bluescrub"):
        validation.check_raw_findings([_invalid()])

    assert "contract violation" in caplog.text
    assert "defect in whatever produced them" in caplog.text


def test_a_finding_that_cannot_even_be_serialised_is_survived():
    class Exploding:
        sensor = "broken"
        rule_id = "broken.rule"

        def to_dict(self):
            raise RuntimeError("nope")

    violations = validation.check_raw_findings([Exploding()])
    assert len(violations) == 1 and "could not validate" in violations[0]


def test_the_log_carries_the_rule_not_the_evidence(caplog):
    """A violating finding may hold a plaintext credential, and this goes to
    the log — which the data-handling policy names explicitly."""
    finding = _invalid()
    finding.matched_tokens = "ghp_liveTOKENvalue00000000000000000000"

    with caplog.at_level(logging.ERROR, logger="backend.app.bluescrub"):
        validation.check_raw_findings([finding])

    assert "dirty_word.codename" in caplog.text
    assert "ghp_liveTOKENvalue" not in caplog.text


def test_a_flood_of_violations_is_summarised(caplog):
    """One malformed adapter produces thousands of identical messages, which
    buries everything else in the log."""
    with caplog.at_level(logging.ERROR, logger="backend.app.bluescrub"):
        validation.check_raw_findings([_invalid()] * 40)

    assert "35 more" in caplog.text


# ── the three that were live ──────────────────────────────────────────────

@pytest.mark.parametrize("profile", ["triage", "standard", "deep"])
def test_the_metrics_the_api_serves_validate(db, tmp_path, profile):
    """`/report/{job_id}` returns `Job.metrics_json` verbatim. The scoring test
    validates `score_job`'s return value, which is a different object — the
    service adds two keys to it afterwards."""
    src = tmp_path / "input" / "source"
    src.mkdir(parents=True)
    (src / "main.c").write_text("int main(void){return 0;}\n")

    metrics = bs_service.analyze_and_persist(db, "j", tmp_path, profile=profile, run_output_dir=tmp_path)

    assert validation.check_metrics(metrics) == []
    assert {"findings_created", "findings_updated"} <= set(metrics["dacv"])


def test_the_persistence_counters_are_in_the_contract():
    """They are real data the API serves, so the fix was to declare them
    rather than to stop reporting them."""
    schema = json.loads(
        (validation.CONTRACTS / "dacv-metrics.schema.json").read_text()
    )
    props = schema["properties"]["dacv"]["properties"]

    assert schema["properties"]["dacv"]["additionalProperties"] is False
    assert "findings_created" in props and "findings_updated" in props


def test_the_recovery_tier_state_is_in_the_contract():
    """Added as a `ruleset_state` in Sprint 5 without extending the enum, so
    every deep scan without FLOSS produced metrics that failed their own
    schema."""
    schema = json.loads(
        (validation.CONTRACTS / "dacv-metrics.schema.json").read_text()
    )

    def find_enum(node):
        if isinstance(node, dict):
            enum = node.get("enum")
            if isinstance(enum, list) and "database_stale" in enum:
                return enum
            for value in node.values():
                found = find_enum(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = find_enum(value)
                if found:
                    return found
        return None

    assert "strings_static_only" in find_enum(schema)
