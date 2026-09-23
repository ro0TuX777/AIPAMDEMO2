"""MITRE ATT&CK and auto-fix enrichment.

Thin wrappers over the vendored tables. Kept here rather than called directly
from adapters so that a lookup failure degrades a single finding's metadata
instead of aborting a scan, and so the tables have one entry point when they
are eventually replaced.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §2.6
"""

from __future__ import annotations

from backend.app.pipeline.outcomes import PROPAGATE_ERRORS, public_failure

import logging
from typing import Any

logger = logging.getLogger(__name__)

_MAX_FIX_BYTES = 2048


def _lookup(fn_name: str, text: str) -> Any:
    """Call a vendored enrichment function, swallowing its failures.

    Enrichment is decoration. A table miss, or a raise from a table entry, must
    not cost the finding it was decorating.
    """
    if not text:
        return None
    try:
        if fn_name == "mitre":
            from backend.app.bluescrub.vendored.enrichment.mitre import get_mitre_mapping

            return get_mitre_mapping(text)
        from backend.app.bluescrub.vendored.enrichment.auto_fix import get_auto_fix

        return get_auto_fix(text)
    except PROPAGATE_ERRORS:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("enrichment %s failed: %s", fn_name, public_failure(exc))
        return None


def mitre_for(*candidates: str | None) -> list[dict[str, str]]:
    """Resolve MITRE techniques, trying each candidate text in order.

    Returns the contract's array form. The vendored table returns at most one
    mapping, but the envelope models techniques as a list because a finding can
    legitimately carry several and the schema should not have to change when it
    does.
    """
    for text in candidates:
        mapping = _lookup("mitre", text or "")
        if not mapping:
            continue
        technique = mapping.get("technique") or mapping.get("id")
        if not technique:
            continue
        return [{
            "id": str(technique),
            "name": str(mapping.get("name") or ""),
            "tactic": str(mapping.get("tactic") or ""),
        }]
    return []


def autofix_for(*candidates: str | None) -> dict[str, Any] | None:
    """Resolve an auto-fix suggestion, trying each candidate text in order."""
    for text in candidates:
        fix = _lookup("auto_fix", text or "")
        if not fix:
            continue
        return {"available": True, "patch": _render_fix(fix)[:_MAX_FIX_BYTES]}
    return None


def _render_fix(fix: Any) -> str:
    """Flatten the vendored fix record into readable text.

    The table stores ``{code_fix, binary_fix, tools}``. Stringifying the dict
    would put a Python repr in front of an analyst, so each part is labelled
    and the empty ones are dropped.
    """
    if isinstance(fix, str):
        return fix
    if not isinstance(fix, dict):
        return str(fix)

    parts: list[str] = []
    if fix.get("code_fix"):
        parts.append(str(fix["code_fix"]).strip())
    if fix.get("binary_fix"):
        parts.append(f"Binary: {str(fix['binary_fix']).strip()}")
    tools = fix.get("tools")
    if tools:
        joined = ", ".join(str(t) for t in tools) if isinstance(tools, list) else str(tools)
        parts.append(f"Tools: {joined}")
    return "\n\n".join(parts) or str(fix)
