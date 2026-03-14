from backend.app.anomaly_detector import AnomalyDetector

def test_calculate_mad_symmetric():
    data = [10.0, 10.0, 10.0, 10.0, 10.0]
    mad = AnomalyDetector._calculate_mad(data)
    assert mad == 0.0

def test_calculate_mad_with_outlier():
    # 9 legitimate beacon intervals and 1 outlier (missed beacon)
    data = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 20.0]
    # Median is 10.0
    # Deviations: 0, 0, 0, 0, 0, 0, 0, 0, 0, 10
    # Median of deviations is 0
    mad = AnomalyDetector._calculate_mad(data)
    assert mad == 0.0

import math

def test_calculate_mad_jitter():
    # 5 intervals with slight jitter
    data = [9.5, 10.5, 10.0, 9.8, 10.2]
    # Median is 10.0
    # Deviations: 0.5, 0.5, 0.0, 0.2, 0.2
    # Sorted deviations: 0.0, 0.2, 0.2, 0.5, 0.5
    # Median deviation is 0.2
    mad = AnomalyDetector._calculate_mad(data)
    assert math.isclose(mad, 0.2, rel_tol=1e-9)

def test_bowley_skewness_symmetric():
    # Symmetric data
    data = [1, 2, 3, 4, 5, 6, 7]
    skew = AnomalyDetector._calculate_bowley_skewness(data)
    # quantiles: Q1=2.5, Q2=4.0, Q3=5.5
    # (5.5 + 2.5 - 8.0) / (5.5 - 2.5) = 0.0
    assert abs(skew) < 0.01

def test_bowley_skewness_right_skew():
    data = [1, 2, 3, 4, 10, 20, 30]
    skew = AnomalyDetector._calculate_bowley_skewness(data)
    assert skew > 0.0

print("All math tests passed!")
