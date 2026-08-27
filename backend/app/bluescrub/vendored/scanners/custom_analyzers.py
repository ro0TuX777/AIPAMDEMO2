"""
Custom Security Analyzers for BlueScrub — backward-compatibility shim.

Real implementations live in ``scanners.analyzers.*``.
This module re-exports the functional wrappers so existing callers
(``scanners/__init__.py``, ``defensive_security_scanner.py``) keep working.
"""

from backend.app.bluescrub.vendored.scanners.analyzers import (
    run_opsec_analysis,
    run_exploitation_tool_analysis,
    run_enhanced_secrets_detection,
    run_information_disclosure_analysis,
    run_memory_safety_analysis,
    run_crypto_vulnerability_analysis,
    run_supply_chain_analysis,
)
