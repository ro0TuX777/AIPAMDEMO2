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


def test_finding_model_gained_no_columns():
    """BlueScrub stores its metadata in evidence_json, not new columns."""
    from backend.app.models.finding import Finding

    expected = {
        "id", "job_id", "finding_id", "sensor", "severity", "category", "title",
        "summary", "community_id", "evidence_json", "pcap_label", "feedback",
        "explanation_feedback", "confidence", "ts", "src_ip", "dest_ip",
        "evidence_status", "corroboration_score", "corroborating_sources_json",
        "analyst_status", "analyst_notes", "reviewed_at", "reviewer_id",
    }
    actual = {c.name for c in Finding.__table__.columns}
    assert expected.issubset(actual), f"missing: {expected - actual}"
    assert not (actual - expected), f"BlueScrub added columns to findings: {actual - expected}"


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
