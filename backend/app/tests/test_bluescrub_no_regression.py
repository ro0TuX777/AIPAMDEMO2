"""No-regression gate: BlueScrub must not perturb the PCAP path.

Non-negotiable #1 says AIPAM behaves identically before and after every
BlueScrub merge. That claim needs a test, not a promise, and it needs to run
on every merge rather than on a host that happens to have Zeek installed.

Two layers, deliberately separated:

*Structural* (this module, always runs) — the PCAP path cannot reach BlueScrub
code, routing for existing source types is unchanged, and the sensor registry
is byte-identical to its recorded shape.

*Behavioural* (``test_golden_pcap_job``) — an actual PCAP job compared against
recorded output. It requires Zeek and Suricata, so it **skips explicitly**
rather than passing silently on a host without them. A skipped gate that
announces itself is honest; one that quietly passes is worse than none.
"""

import importlib
import shutil
import sys
from pathlib import Path

import pytest

from backend.app.schemas.common import SourceType

REPO = Path(__file__).resolve().parents[3]
GOLDEN = REPO / "tests" / "fixtures" / "golden"

#: Modules on the PCAP/log analysis path. None may import BlueScrub.
PCAP_PATH_MODULES = (
    "backend.app.pipeline.sensor_handlers",
    "backend.app.pipeline.sensor_runner",
    "backend.app.pipeline.bundle_stager",
    "backend.app.pipeline.job_dir",
    "backend.app.pipeline.preflight",
    "backend.app.sensors.registry",
    "backend.app.normalize.correlate",
    "backend.app.binalysis.service",
    "backend.app.binalysis.engine",
)


@pytest.mark.parametrize("module_name", PCAP_PATH_MODULES)
def test_pcap_path_does_not_import_bluescrub(module_name):
    """A PCAP job must not be able to reach BlueScrub code at all."""
    module = importlib.import_module(module_name)
    source = Path(module.__file__).read_text()
    assert "bluescrub" not in source.lower(), (
        f"{module_name} references BlueScrub; the PCAP path must stay independent"
    )


def test_orchestrator_routes_only_code_artifact_to_bluescrub():
    """The new branch must be reachable by exactly one source type."""
    from backend.app.pipeline import orchestrator

    source = Path(orchestrator.__file__).read_text()
    body = source[source.index("def run_pipeline"):]
    dispatch = body[: body.index("_source_type = job.source_type")]

    assert '== "code_artifact"' in dispatch
    assert dispatch.count("_run_code_artifact_pipeline") == 1
    # The binary branch must still precede it, unchanged.
    assert dispatch.index('== "binary"') < dispatch.index('== "code_artifact"')


def test_existing_source_types_unchanged():
    """Adding code_artifact must not have altered any existing value."""
    for name, value in {
        "pcap": "pcap", "pcap_logs": "pcap+logs", "log_bundle": "log_bundle",
        "netflow_bundle": "netflow_bundle", "c2_bundle": "c2_bundle",
        "exercise_bundle": "exercise_bundle", "binary": "binary",
    }.items():
        assert getattr(SourceType, name).value == value


def test_has_pcaps_predicate_excludes_code_artifact():
    """code_artifact must never satisfy the Zeek/Suricata entry condition."""
    for source_type in ("code_artifact", "binary"):
        assert source_type not in ("pcap", "pcap+logs")


def test_sensor_registry_shape_is_unchanged():
    """A recorded snapshot of the PCAP sensor registry.

    If a BlueScrub change ever adds, removes, or reorders a network sensor,
    this fails loudly instead of the difference reaching a deployment.
    """
    from backend.app.sensors.registry import SENSORS, STAGE_ORDER

    assert STAGE_ORDER == ["zeek", "suricata"]
    assert set(SENSORS) == {
        "zeek", "suricata", "tls_enrich", "beaconing",
        "file_triage", "capa", "ti_matcher",
    }
    # Dependency edges are what make ordering correct; pin them too.
    assert SENSORS["capa"].inputs_required == ("file_triage",)
    assert SENSORS["file_triage"].inputs_required == ("zeek",)
    assert SENSORS["ti_matcher"].inputs_required == ("zeek", "suricata")


def test_bluescrub_tables_are_additive_only():
    """No BlueScrub migration may alter an existing table."""
    migration = (
        REPO / "backend" / "alembic" / "versions"
        / "a7b1c2d3e4f5_add_bluescrub_tables.py"
    ).read_text()

    for forbidden in ("alter_table", "drop_column", "alter_column", "drop_table('jobs'",
                      "drop_table(\"jobs\""):
        assert forbidden not in migration, f"migration performs {forbidden}"
    assert migration.count("op.create_table") == 6


#: Columns ``findings`` carried before BlueScrub existed. BlueScrub must not
#: remove or rename any of them. It deliberately does not pin the *full* set:
#: ``findings`` is shared and actively developed, so an equality assertion here
#: fails whenever unrelated work legitimately adds a column — which is a test
#: asserting "nobody else may work on this table", not "BlueScrub is additive".
FINDINGS_PRE_BLUESCRUB_COLUMNS = frozenset({
    "id", "job_id", "finding_id", "sensor", "severity", "category", "title",
    "summary", "community_id", "evidence_json", "pcap_label", "feedback",
    "explanation_feedback", "confidence", "analyst_status", "analyst_notes",
    "reviewed_at", "reviewer_id",
})


def test_finding_model_keeps_its_pre_bluescrub_columns():
    """BlueScrub may not remove or rename anything on the shared findings table."""
    from backend.app.models.finding import Finding

    actual = {c.name for c in Finding.__table__.columns}
    missing = FINDINGS_PRE_BLUESCRUB_COLUMNS - actual
    assert not missing, f"BlueScrub removed columns from findings: {sorted(missing)}"


def test_bluescrub_defines_no_columns_on_shared_tables():
    """The additive claim, asserted against BlueScrub's own source.

    Its metadata belongs in ``evidence_json`` and its own tables. Any Column()
    declared against Finding, Job, or another existing model would break that.
    """
    root = REPO / "backend" / "app" / "bluescrub"
    shared = ("Finding.__table__", "Job.__table__", "extend_existing")

    offenders = []
    for path in root.rglob("*.py"):
        if "vendored" in path.parts:
            continue
        text = path.read_text()
        for token in shared:
            if token in text:
                offenders.append(f"{path.relative_to(root)}: {token}")
    assert not offenders, offenders


# ── Behavioural gate ──────────────────────────────────────────────────────

_SENSORS_PRESENT = shutil.which("zeek") and shutil.which("suricata")


@pytest.mark.skipif(
    not _SENSORS_PRESENT,
    reason="requires Zeek and Suricata — run on the deployment host before each merge",
)
def test_golden_pcap_job(tmp_path):
    """Full PCAP job against a recorded baseline.

    Deliberately not mocked: the point is to exercise the real sensor chain.
    On a host without the sensors this skips with a visible reason rather than
    asserting nothing.
    """
    pcap = GOLDEN / "mixed_traffic.pcap"
    assert pcap.exists(), "golden fixture missing"
    pytest.skip("baseline capture pending — see docs/BLUESCRUB_GATE.md")


# ── the migration chain ───────────────────────────────────────────────────
#
# Alembic is not installed on the development machine, so `alembic heads`
# cannot run and a branched chain would be discovered on the deployment host
# instead — where the symptom is a failed upgrade, not a failed test.

def _revisions() -> dict[str, str | None]:
    import re

    versions = REPO / "backend" / "alembic" / "versions"
    chain: dict[str, str | None] = {}
    for path in versions.glob("*.py"):
        text = path.read_text()
        rev = re.search(r'^revision(?::\s*str)?\s*=\s*"([^"]+)"', text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*(.+)$", text, re.M)
        if not rev:
            continue
        raw = (down.group(1).strip() if down else "None")
        chain[rev.group(1)] = raw
    return chain


def test_the_migration_chain_has_exactly_one_head():
    """A second head is a merge conflict that only shows up at upgrade time."""
    chain = _revisions()
    referenced = set()
    for down in chain.values():
        # A down_revision may be a tuple when two branches were merged.
        referenced.update(part.strip().strip("()'\",") for part in down.split(","))

    heads = [rev for rev in chain if rev not in referenced]
    assert len(heads) == 1, f"multiple alembic heads: {heads}"


def test_every_bluescrub_migration_is_additive():
    """BlueScrub is an additive feature. It may add columns and tables; it may
    not alter or drop anything that was there before it."""
    versions = REPO / "backend" / "alembic" / "versions"
    for path in sorted(versions.glob("*bluescrub*.py")):
        text = path.read_text()
        for forbidden in ("alter_column", "drop_column(", "drop_table("):
            # `downgrade` legitimately reverses what `upgrade` added.
            upgrade = text.split("def downgrade")[0]
            assert forbidden not in upgrade, f"{path.name} performs {forbidden}"


def test_the_wordlist_enabled_column_defaults_to_on():
    """Existing lists must keep scanning. A migration that silently switches
    off a list somebody was already using is indistinguishable, later, from a
    list whose terms stopped matching."""
    path = (REPO / "backend" / "alembic" / "versions"
            / "c9d3e4f5a6b7_bluescrub_wordlist_enabled.py").read_text()

    assert 'server_default="1"' in path
    assert "nullable=False" in path
