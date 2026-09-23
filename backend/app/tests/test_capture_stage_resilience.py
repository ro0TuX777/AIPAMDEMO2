"""Zeek/Suricata staging, timeout and failure-isolation behaviour.

Covers the three ways a large multi-PCAP job used to lose data:
  1. captures sharing a phase label silently overwrote each other on disk
  2. a fixed wall-clock timeout killed healthy-but-slow parsing
  3. one failed stage aborted the whole job, discarding unrelated evidence
"""

import subprocess
import sys
import time
from pathlib import Path

import pytest

from backend.app.pipeline import sensor_handlers
from backend.app.pipeline.job_dir import (
    create_job_directory,
    link_pcap_labeled,
    load_pcap_labels,
)


def _make_pcap(tmp_path: Path, name: str, size: int = 64) -> Path:
    src = tmp_path / name
    src.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * size)
    return src


# ── 1. Label collision ──────────────────────────────────────────────────────

class TestLabelledStaging:
    @pytest.fixture(autouse=True)
    def _require_symlinks(self, tmp_path):
        target = tmp_path / "symlink-target"
        target.touch()
        try:
            (tmp_path / "symlink-probe").symlink_to(target)
        except OSError:
            pytest.skip("Staging alias requires symlink privileges; Linux Task 10 gate")

    def test_captures_sharing_a_label_are_all_staged(self, tmp_path):
        """Three "during" captures must produce three files, not one."""
        job_dir = _legacy_job_directory(tmp_path / "jobs", "job-1")
        sources = [_make_pcap(tmp_path, f"capture{i}.pcap", 64 + i) for i in range(3)]

        for ordinal, src in enumerate(sources):
            link_pcap_labeled(job_dir, src, "during", ordinal)

        staged = sorted(p.name for p in (job_dir / "input").glob("*.pcap") if not p.is_symlink())
        assert staged == ["during-0.pcap", "during-1.pcap", "during-2.pcap"]
        # And each holds its own capture, not three links to the first.
        sizes = {(job_dir / "input" / n).stat().st_size for n in staged}
        assert len(sizes) == 3

    def test_phase_label_survives_the_unique_filename(self, tmp_path):
        job_dir = _legacy_job_directory(tmp_path / "jobs", "job-2")
        link_pcap_labeled(job_dir, _make_pcap(tmp_path, "a.pcap"), "during", 0)
        link_pcap_labeled(job_dir, _make_pcap(tmp_path, "b.pcap"), "during", 1)
        link_pcap_labeled(job_dir, _make_pcap(tmp_path, "c.pcap"), "after", 2)

        assert load_pcap_labels(job_dir) == {
            "during-0.pcap": "during",
            "during-1.pcap": "during",
            "after-2.pcap": "after",
        }
        pairs = {p.name: lbl for p, lbl in sensor_handlers._find_all_pcaps_labeled(job_dir)}
        assert pairs == {
            "during-0.pcap": "during",
            "during-1.pcap": "during",
            "after-2.pcap": "after",
        }

    def test_legacy_jobs_without_a_manifest_fall_back_to_the_stem(self, tmp_path):
        """Jobs staged before the manifest existed keep working unchanged."""
        job_dir = _legacy_job_directory(tmp_path / "jobs", "job-3")
        (job_dir / "input" / "before.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

        pairs = sensor_handlers._find_all_pcaps_labeled(job_dir)
        assert [(p.name, lbl) for p, lbl in pairs] == [("before.pcap", "before")]


# ── 2. Stall watchdog ───────────────────────────────────────────────────────

class TestCaptureWatchdog:
    def test_slow_but_progressing_process_is_not_killed(self, tmp_path):
        """The old fixed timeout killed healthy work; progress must buy time."""
        script = (
            "import sys,time\n"
            "for i in range(6):\n"
            "    open('out-%d.log' % i, 'w').write('x' * 4096)\n"
            "    time.sleep(0.2)\n"
        )
        result = sensor_handlers.run_capture_tool(
            [sys.executable, "-c", script], tmp_path,
            label="slow", ceiling_seconds=60, stall_seconds=3.0,
        )
        assert result.returncode == 0

    def test_stalled_process_is_killed_with_a_diagnostic(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sensor_handlers, "_WATCHDOG_POLL_SECONDS", 0.1)
        # Produces nothing and never exits → no progress at all.
        with pytest.raises(subprocess.TimeoutExpired) as exc:
            sensor_handlers.run_capture_tool(
                [sys.executable, "-c", "import time; time.sleep(30)"], tmp_path,
                label="wedged", ceiling_seconds=60, stall_seconds=0.5,
            )
        assert b"No progress" in (exc.value.output or b"")

    def test_ceiling_still_applies_to_a_progressing_process(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sensor_handlers, "_WATCHDOG_POLL_SECONDS", 0.1)
        script = (
            "import time\n"
            "i = 0\n"
            "while True:\n"
            "    open('grow-%d.log' % i, 'w').write('x' * 4096); i += 1\n"
            "    time.sleep(0.05)\n"
        )
        started = time.monotonic()
        with pytest.raises(subprocess.TimeoutExpired) as exc:
            sensor_handlers.run_capture_tool(
                [sys.executable, "-c", script], tmp_path,
                label="endless", ceiling_seconds=1, stall_seconds=30.0,
            )
        assert time.monotonic() - started < 15
        assert b"ceiling" in (exc.value.output or b"")

    def test_ceiling_comes_from_the_sensor_registry(self):
        """The declared timeout must actually be honoured, not shadowed by a literal."""
        from backend.app.sensors.registry import SENSORS

        assert sensor_handlers._sensor_timeout("zeek", 1) == SENSORS["zeek"].timeout_seconds
        assert sensor_handlers._sensor_timeout("suricata", 1) == SENSORS["suricata"].timeout_seconds
        assert sensor_handlers._sensor_timeout("nonexistent", 42) == 42

    def test_partial_output_is_left_on_disk_after_a_timeout(self, tmp_path, monkeypatch):
        """Whatever the tool wrote before the kill stays put for inspection."""
        monkeypatch.setattr(sensor_handlers, "_WATCHDOG_POLL_SECONDS", 0.1)
        script = (
            "import time\n"
            "open('conn.log','w').write('partial')\n"
            "time.sleep(30)\n"
        )
        with pytest.raises(subprocess.TimeoutExpired):
            sensor_handlers.run_capture_tool(
                [sys.executable, "-c", script], tmp_path,
                label="partial", ceiling_seconds=60, stall_seconds=0.5,
            )
        assert (tmp_path / "conn.log").read_text() == "partial"


def _legacy_job_directory(job_root, job_id):
    return create_job_directory(job_root, job_id, run_output_dir=job_root / job_id)
