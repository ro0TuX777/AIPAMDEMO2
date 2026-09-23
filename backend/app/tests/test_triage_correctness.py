"""Correctness regressions for triage/correlation edge cases.

Ported from the AIPAM-BETA fork's audit suite, keeping only the cases that
guard genuine current-main behaviour (each backs a fix in this repo). The
fork's remediation-wording assertions and a since-renamed temporal-label helper
were intentionally left behind — they encode fork-specific product decisions,
not shared correctness.
"""

import json
from pathlib import Path

from backend.app.pipeline import sensor_handlers
from backend.app.services.correlation import _is_correlatable_host, _resolve_job


def test_ti_matcher_continues_alert_correlation_when_bundle_mount_is_unavailable(
    tmp_path,
    monkeypatch,
):
    """An unavailable TI-bundle mount (OSError) must not sink alert correlation."""
    job_dir = tmp_path / "job"
    output_dir = job_dir / "sensors" / "ti_matcher"
    zeek_dir = job_dir / "sensors" / "zeek"
    suricata_dir = job_dir / "sensors" / "suricata"
    for directory in (output_dir, zeek_dir, suricata_dir):
        directory.mkdir(parents=True)

    (zeek_dir / "sensor.results.jsonl").write_text(
        json.dumps({
            "type": "flow",
            "data": {"src_ip": "8.8.8.8", "dst_ip": "10.0.0.1"},
        }) + "\n"
    )
    (suricata_dir / "sensor.results.jsonl").write_text(
        json.dumps({
            "type": "alert",
            "data": {"src_ip": "8.8.8.8", "dst_ip": "10.0.0.1", "signature": "ET TEST"},
        }) + "\n"
    )

    broken_path = tmp_path / "unavailable-ti"
    monkeypatch.setenv("AIPAM_TI_BUNDLE_DIR", str(broken_path))
    original_exists = Path.exists

    def unavailable_mount_exists(path):
        if path == broken_path:
            raise OSError(19, "No such device")
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", unavailable_mount_exists)

    sensor_handlers.handle_ti_matcher(job_dir, output_dir, "job-1", "triage", run_output_dir=job_dir)

    result = json.loads((output_dir / "sensor.results.jsonl").read_text().strip())
    assert result["data"]["value"] == "8.8.8.8"
    assert result["data"]["matched_feed"] == "suricata_correlated"


def test_unnamed_related_job_falls_back_to_job_id():
    """A known-but-unnamed job resolves to its id, not None."""
    assert _resolve_job({"job-1": (None, "2026-05-27")}, "job-1") == ("job-1", "2026-05-27")


def test_non_attributable_hosts_do_not_form_related_job_pivots():
    """Unspecified/multicast/broadcast IPs are not treated as shared-host pivots."""
    assert not _is_correlatable_host("0.0.0.0")
    assert not _is_correlatable_host("224.0.0.251")
    assert not _is_correlatable_host("255.255.255.255")
    assert _is_correlatable_host("192.168.3.29")
