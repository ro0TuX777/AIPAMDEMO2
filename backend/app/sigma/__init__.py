"""Lightweight Sigma detection engine for first-class log analysis."""

from backend.app.sigma.engine import (
    SigmaRule,
    SigmaMatch,
    load_rule,
    load_rules_from_dir,
    match_event,
    run_rules,
)

__all__ = [
    "SigmaRule",
    "SigmaMatch",
    "load_rule",
    "load_rules_from_dir",
    "match_event",
    "run_rules",
]
