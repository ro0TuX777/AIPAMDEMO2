"""RE-Feasibility signal measurement.

The gauge runs opposite to every other pillar — 1.0 means *cheap to reverse* —
so the tests are written as comparisons between artifact shapes rather than
assertions about absolute numbers. A threshold that drifts during calibration
should not break a test whose real claim is "a debug build is easier to reverse
than a stripped one".
"""

from __future__ import annotations

import random
import struct
import subprocess
from pathlib import Path

import pytest

from backend.app.bluescrub import re_signals
from backend.app.bluescrub.models import CanonicalGroup, Location
from backend.app.bluescrub.pillars import FAMILY_PILLAR, IssueFamily
from backend.app.bluescrub.scoring import score_re_pillar

_SOURCE = """
#include <stdio.h>
const char *banner = "a readable banner string with real words in it";
const char *second = "another substantial string for the yield measurement";
int helper(int x) { return x * 2; }
int main(void) { printf("%s %s %d\\n", banner, second, helper(21)); return 0; }
"""


def _have_gcc() -> bool:
    return subprocess.run(["which", "gcc"], capture_output=True).returncode == 0


def _compile(dest: Path, *flags: str) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "app"
    subprocess.run(
        ["gcc", *flags, "-o", str(out), "-x", "c", "-"],
        input=_SOURCE, text=True, check=True, capture_output=True,
    )
    return out


@pytest.fixture
def shapes(tmp_path: Path) -> dict[str, Path]:
    """Three artifact shapes that should sit at different reversing costs."""
    if not _have_gcc():
        pytest.skip("gcc is required to build the comparison artifacts")

    _compile(tmp_path / "debug", "-g", "-O0")
    _compile(tmp_path / "stripped", "-O2", "-s")

    packed = tmp_path / "packed"
    packed.mkdir()
    rng = random.Random(7)
    (packed / "app").write_bytes(
        b"\x7fELF\x02\x01\x01" + bytes(rng.getrandbits(8) for _ in range(60000))
    )
    return {n: tmp_path / n for n in ("debug", "stripped", "packed")}


def _score(root: Path, groups: list | None = None) -> int:
    return score_re_pillar(re_signals.compute(root, groups or []), []).score


class TestDiscrimination:
    def test_debug_build_reverses_more_cheaply_than_stripped(self, shapes):
        assert _score(shapes["debug"]) > _score(shapes["stripped"])

    def test_stripped_reverses_more_cheaply_than_packed(self, shapes):
        assert _score(shapes["stripped"]) > _score(shapes["packed"])

    def test_the_three_shapes_land_in_different_effort_bands(self, shapes):
        bands = {
            name: score_re_pillar(re_signals.compute(p, []), []).effort_band
            for name, p in shapes.items()
        }
        assert len(set(bands.values())) == 3, bands


class TestStringYield:
    def test_short_accidental_runs_do_not_count_as_recoverable_text(self, tmp_path):
        """Random bytes throw off four-char ASCII runs prolifically.

        Before the length floor this made a block of noise score as the most
        readable artifact on the bench — a packed sample would have been graded
        trivially reversible.
        """
        root = tmp_path / "noise"
        root.mkdir()
        rng = random.Random(11)
        (root / "app").write_bytes(
            b"\x7fELF\x02\x01\x01" + bytes(rng.getrandbits(8) for _ in range(60000))
        )
        signal = next(
            s for s in re_signals.compute(root, []) if s.signal == "string_yield"
        )
        assert signal.normalized == pytest.approx(0.0, abs=0.05)

    def test_a_binary_full_of_real_text_scores_high(self):
        text = "configuration parameter unavailable\n" * 400
        assert re_signals.string_yield_signal(400, len(text) / 1024) > 0.8


class TestSignalPrimitives:
    @pytest.mark.parametrize("entropy,expected", [(4.0, 1.0), (7.5, 0.0)])
    def test_entropy_anchors(self, entropy, expected):
        assert re_signals.entropy_signal(entropy) == pytest.approx(expected)

    def test_entropy_between_anchors_is_graded_not_binary(self):
        assert 0.0 < re_signals.entropy_signal(6.85) < 1.0

    def test_debug_info_outranks_any_number_of_bare_symbols(self):
        assert re_signals.symbol_signal(True, 0) > re_signals.symbol_signal(False, 100000)

    def test_managed_runtime_reverses_more_cheaply_than_native(self):
        assert re_signals.runtime_signal("go build id: abc\nruntime.main") == 1.0
        assert re_signals.runtime_signal("no markers here") < 0.5

    def test_import_signal_saturates_rather_than_exceeding_one(self):
        assert re_signals.import_signal(100000) == 1.0


class TestFindingDerivedSignals:
    def _group(self, family: IssueFamily) -> CanonicalGroup:
        return CanonicalGroup(
            canonical_id="cid", issue_family=family, pillar=FAMILY_PILLAR[family],
            severity="high", severity_source="rule", scoring_confidence=1.0,
            primary_sensor="test", primary_rule_id="r", occurrence_index=0,
            members=[], location=Location(kind="binary", file="app"),
        )

    def test_anti_analysis_findings_make_the_artifact_harder(self, shapes):
        plain = _score(shapes["stripped"])
        resistant = _score(shapes["stripped"], [self._group(IssueFamily.anti_analysis)])
        assert resistant < plain

    def test_plaintext_config_makes_the_artifact_easier(self, shapes):
        plain = _score(shapes["stripped"])
        exposed = _score(shapes["stripped"], [self._group(IssueFamily.hardcoded_c2)])
        assert exposed > plain


class TestUnavailability:
    def test_decompilation_is_reported_unavailable_with_its_reason(self, shapes):
        signal = next(
            s for s in re_signals.compute(shapes["debug"], [])
            if s.signal == "decompilation"
        )
        assert signal.normalized is None
        assert "Ghidra" in signal.reason

    def test_an_unavailable_signal_costs_coverage_rather_than_being_redistributed(
        self, shapes
    ):
        result = score_re_pillar(re_signals.compute(shapes["debug"], []), [])
        assert result.coverage == pytest.approx(0.85)
        assert result.status.value == "degraded"
        assert [u["signal"] for u in result.unavailable_signals] == ["decompilation"]

    def test_no_binary_yields_all_signals_absent_not_zero(self, tmp_path):
        """Absent must not read as "maximally hard to reverse"."""
        (tmp_path / "notes.txt").write_text("no compiled artifact here")
        signals = re_signals.compute(tmp_path, [])
        assert signals and all(s.normalized is None for s in signals)
        assert score_re_pillar(signals, []).score is None


class TestMultipleArtifacts:
    def test_the_most_reversible_artifact_sets_the_cost(self, tmp_path, shapes):
        """An attacker reverses the easiest one and reads the rest from it."""
        mixed = tmp_path / "mixed"
        mixed.mkdir()
        for name in ("debug", "stripped"):
            (mixed / name).write_bytes((shapes[name] / "app").read_bytes())
        assert _score(mixed) == _score(shapes["debug"])


class TestRobustness:
    def test_an_unparseable_binary_does_not_abort_measurement(self, tmp_path):
        (tmp_path / "broken.exe").write_bytes(
            b"MZ" + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 4000
        )
        signals = re_signals.compute(tmp_path, [])
        assert any(s.normalized is not None for s in signals)
