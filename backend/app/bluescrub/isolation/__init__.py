"""Process boundaries for untrusted analysis.

Every component that parses attacker-authored bytes runs behind one of two
runners: the existing Docker sensor path for external tools, or the hardened
subprocess runner here for vendored Python analyzers.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md
"""

from __future__ import annotations

from backend.app.bluescrub.isolation.limits import ResourceLimits, require_privilege_drop
from backend.app.bluescrub.isolation.runner import AnalyzerResult, AnalyzerStatus, run_analyzer

__all__ = [
    "ResourceLimits", "AnalyzerResult", "AnalyzerStatus", "run_analyzer",
    "require_privilege_drop",
]
