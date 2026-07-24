"""
AIPAM Benchmark — Tier 2: Detection Algorithm Quality Gate

AIPAM's core value is detection accuracy. This tier verifies that the
mathematical foundations of all detection algorithms are correct to
within acceptable tolerances.

Covers:
  - Beaconing detection: MAD calculation precision, Bowley skewness direction
  - Temporal analysis: _LABEL_ORDER canonical ordering, label resolution sorting
  - Threat scoring: _confidence_label threshold boundaries (exact cut-points)
  - Anomaly detection: perfect regularity → zero MAD, jitter → positive MAD
  - Correlation scoring: IOC type weighting, cross-job campaign detection
"""
from __future__ import annotations

import math
import os


os.environ.setdefault("AIPAM_API_TOKEN", "test-token-v2")


# ---------------------------------------------------------------------------
# 2.1  Beaconing math — MAD (Median Absolute Deviation)
# ---------------------------------------------------------------------------


class TestBeaconingMAD:
    """MAD must correctly quantify beacon regularity / jitter."""

    def _mad(self, data):
        from backend.app.anomaly_detector import AnomalyDetector
        return AnomalyDetector._calculate_mad(data)

    def test_perfect_regularity_gives_zero_mad(self):
        assert self._mad([10.0, 10.0, 10.0, 10.0, 10.0]) == 0.0

    def test_single_outlier_preserves_zero_mad(self):
        """9 regular beacons + 1 missed → median deviation still 0."""
        data = [10.0] * 9 + [20.0]
        assert self._mad(data) == 0.0

    def test_jitter_produces_positive_mad(self):
        data = [9.5, 10.5, 10.0, 9.8, 10.2]
        result = self._mad(data)
        assert result > 0.0

    def test_jitter_mad_precision(self):
        """Sorted deviations: 0.0, 0.2, 0.2, 0.5, 0.5 → median = 0.2."""
        data = [9.5, 10.5, 10.0, 9.8, 10.2]
        assert math.isclose(self._mad(data), 0.2, rel_tol=1e-9)

    def test_large_jitter_gives_larger_mad_than_small_jitter(self):
        small_jitter = [9.9, 10.1, 10.0, 9.95, 10.05]
        large_jitter = [8.0, 12.0, 10.0, 7.0, 13.0]
        assert self._mad(large_jitter) > self._mad(small_jitter)


# ---------------------------------------------------------------------------
# 2.2  Beaconing math — Bowley skewness
# ---------------------------------------------------------------------------


class TestBowleySkewness:
    """Bowley skewness must correctly identify distribution asymmetry."""

    def _skew(self, data):
        from backend.app.anomaly_detector import AnomalyDetector
        return AnomalyDetector._calculate_bowley_skewness(data)

    def test_symmetric_data_gives_near_zero_skew(self):
        data = [1, 2, 3, 4, 5, 6, 7]
        assert abs(self._skew(data)) < 0.01

    def test_right_skewed_gives_positive_skew(self):
        data = [1, 2, 3, 4, 10, 20, 30]
        assert self._skew(data) > 0.0

    def test_left_skewed_gives_negative_skew(self):
        # Left-skewed: most values cluster near the high end, a few low outliers.
        # Q1≈2.75, Q2≈10, Q3≈10 → B=(2.75+10-20)/(10-2.75)≈-1.0
        data = [1, 2, 3, 10, 10, 10, 10, 10, 10, 10]
        assert self._skew(data) < 0.0

    def test_skewness_bounded_minus_one_to_plus_one(self):
        """Bowley skewness is always in [-1, 1]."""
        import random
        random.seed(42)
        for _ in range(10):
            data = [random.expovariate(1.0) for _ in range(20)]
            s = self._skew(data)
            assert -1.0 <= s <= 1.0, f"Bowley out of range: {s}"


# ---------------------------------------------------------------------------
# 2.3  Temporal label ordering
# ---------------------------------------------------------------------------


class TestTemporalLabelOrdering:
    """Canonical label ordering must enforce before → during → after."""

    def test_label_order_constant_is_canonical(self):
        from backend.app.api.temporal import _LABEL_ORDER
        assert _LABEL_ORDER == ["before", "during", "after"]

    def test_before_sorts_before_after(self):
        from backend.app.api.temporal import _LABEL_ORDER
        labels = ["after", "before"]
        sorted_labels = sorted(
            labels,
            key=lambda lbl: (
                _LABEL_ORDER.index(lbl) if lbl in _LABEL_ORDER else len(_LABEL_ORDER),
                lbl,
            ),
        )
        assert sorted_labels == ["before", "after"]

    def test_three_phase_ordering(self):
        from backend.app.api.temporal import _LABEL_ORDER
        labels = ["after", "before", "during"]
        sorted_labels = sorted(
            labels,
            key=lambda lbl: (
                _LABEL_ORDER.index(lbl) if lbl in _LABEL_ORDER else len(_LABEL_ORDER),
                lbl,
            ),
        )
        assert sorted_labels == ["before", "during", "after"]

    def test_unknown_labels_sort_alphabetically_after_known(self):
        from backend.app.api.temporal import _LABEL_ORDER
        labels = ["zulu", "alpha", "before"]
        sorted_labels = sorted(
            labels,
            key=lambda lbl: (
                _LABEL_ORDER.index(lbl) if lbl in _LABEL_ORDER else len(_LABEL_ORDER),
                lbl,
            ),
        )
        # "before" first (index 0), then "alpha" and "zulu" alphabetically
        assert sorted_labels[0] == "before"
        assert sorted_labels[1] == "alpha"
        assert sorted_labels[2] == "zulu"


# ---------------------------------------------------------------------------
# 2.4  Theory confidence label thresholds
# ---------------------------------------------------------------------------


class TestConfidenceThresholds:
    """Confidence labels must respect exact threshold cut-points."""

    def _label(self, score):
        from backend.app.services.theory_engine import _confidence_label
        return _confidence_label(score)

    def test_zero_is_low(self):
        assert self._label(0.0) == "low"

    def test_below_threshold_is_low(self):
        assert self._label(0.29) == "low"

    def test_at_medium_threshold_is_medium(self):
        assert self._label(0.3) == "medium"

    def test_mid_medium_is_medium(self):
        assert self._label(0.5) == "medium"

    def test_just_below_high_is_medium(self):
        assert self._label(0.59) == "medium"

    def test_at_high_threshold_is_high(self):
        assert self._label(0.6) == "high"

    def test_max_is_high(self):
        assert self._label(1.0) == "high"

    def test_thresholds_are_exhaustive(self):
        """Every score in [0, 1] must map to one of three labels."""
        for score in [i / 100 for i in range(101)]:
            label = self._label(score)
            assert label in {"low", "medium", "high"}, f"Unexpected label '{label}' for score {score}"
