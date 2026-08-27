"""BlueScrub — DACV+R code-artifact analysis.

Additive capability: a ``code_artifact`` job source-type that audits offensive
tooling source, binaries, and build config along five OPSEC pillars. No PCAP,
log, Zeek, or Suricata code path is affected.

Contracts governing this package live in ``docs/BLUESCRUB_*.md`` and the JSON
Schemas in ``contracts/``. The isolation contract is not advisory: every
component here that reads attacker-authored bytes runs behind a process
boundary (see ``isolation/``).
"""

from __future__ import annotations

__all__ = ["SCHEMA_VERSION", "SCORING_MODEL", "FINGERPRINT_SCHEME", "CANONICALIZATION_VERSION"]

SCHEMA_VERSION = "bluescrub/2"
SCORING_MODEL = "dacvr/1.1"
FINGERPRINT_SCHEME = "fp/2"
CANONICALIZATION_VERSION = "canon/1"
