"""Domain models for AIPAM forensic analysis.

This package contains the core domain abstractions:
- ForensicData: Unified internal representation for forensic input data
- Finding: Atomic analysis result (one per technique/anomaly)
- FindingSeverity: Severity classification enum
"""

from .forensic_data import ForensicData
from .finding import Finding, FindingSeverity

__all__ = ["ForensicData", "Finding", "FindingSeverity"]
