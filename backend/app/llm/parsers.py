"""LLM response parsers — JSON extraction and repair.

Extracted from the monolithic ``llm_client.py`` to create a testable,
standalone module for handling LLM output in all its messy glory.

Functions in this module:

- ``parse_llm_response``: Extract JSON from raw LLM text (handles
  markdown fences, partial JSON, etc.)
- ``repair_llm_output``: Fix schema mismatches in parsed JSON so it
  validates against the ``LLMOutput`` Pydantic model.
- ``extract_mitre_techniques``: Pull MITRE ATT&CK IDs from freetext.
- ``extract_ip_addresses``: Pull IPv4 addresses from freetext.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON Extraction
# ---------------------------------------------------------------------------


def parse_llm_response(content: str) -> Optional[Dict[str, Any]]:
    """Extract a JSON object from raw LLM response text.

    Handles these common formats:
    1. Pure JSON  (``{...}``)
    2. Markdown fenced  (`` ```json ... ``` ``)
    3. Markdown fenced without language tag  (`` ``` ... ``` ``)
    4. JSON embedded in surrounding prose

    Args:
        content: Raw string from the LLM API.

    Returns:
        Parsed dict, or None if no valid JSON could be extracted.
    """
    if not content or not content.strip():
        return None

    # 1. Direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # 2. Markdown code fences
    fence_patterns = [
        r'```json\s*([\s\S]*?)\s*```',   # ```json ... ```
        r'```\s*([\s\S]*?)\s*```',        # ``` ... ```
    ]
    for pattern in fence_patterns:
        for match in re.findall(pattern, content):
            try:
                return json.loads(match.strip())
            except json.JSONDecodeError:
                continue

    # 3. Largest JSON object in text
    brace_matches = re.findall(r'\{[\s\S]*\}', content)
    for match in brace_matches:
        try:
            return json.loads(match)
        except json.JSONDecodeError:
            continue

    return None


# ---------------------------------------------------------------------------
# Schema Repair
# ---------------------------------------------------------------------------


def repair_llm_output(
    raw: Dict[str, Any],
    content: str = "",
) -> Dict[str, Any]:
    """Repair malformed LLM JSON output into LLMOutput-compatible schema.

    Common repair operations:
    - Convert string attack_chain items to proper dicts
    - Convert dict host_findings to list of dicts
    - Convert dict anomalies to list of dicts
    - Convert string MITRE technique IDs to ``{"id": "...", "name": "..."}``
    - Fill in missing required fields with sensible defaults

    Args:
        raw: Parsed JSON dict from the LLM.
        content: Original content string for fallback extraction.

    Returns:
        Dict suitable for ``LLMOutput(**result)``.
    """
    repaired = dict(raw)

    # Ensure classification
    if "classification" not in repaired:
        repaired["classification"] = "unknown"

    # Ensure overall_severity
    if "overall_severity" not in repaired:
        repaired["overall_severity"] = _infer_severity(content)

    # Repair attack_chain
    repaired["attack_chain"] = _repair_list_of_dicts(
        repaired.get("attack_chain"),
        default_item=lambda text: {
            "stage": "unknown",
            "description": text,
            "evidence": [],
            "mitre_techniques": [],
        },
    )

    # Repair host_findings — can arrive as {ip: summary} dict
    hf = repaired.get("host_findings")
    if isinstance(hf, dict):
        repaired["host_findings"] = [
            {
                "ip": str(ip),
                "role_in_attack": "unknown",
                "summary": str(summary),
                "suspicious_behaviors": [],
            }
            for ip, summary in hf.items()
        ]
    else:
        repaired["host_findings"] = _repair_list_of_dicts(
            hf,
            default_item=lambda text: {
                "ip": "unknown",
                "role_in_attack": "unknown",
                "summary": text,
                "suspicious_behaviors": [],
            },
        )

    # Repair anomalies — can arrive as {description: confidence} dict
    an = repaired.get("anomalies")
    if isinstance(an, dict):
        repaired["anomalies"] = [
            {
                "description": str(desc),
                "related_hosts": [],
                "confidence": _safe_float(conf, 0.5),
                "reason": "Model reported anomaly",
            }
            for desc, conf in an.items()
        ]
    else:
        repaired["anomalies"] = _repair_list_of_dicts(
            an,
            default_item=lambda text: {
                "description": text,
                "related_hosts": [],
                "confidence": 0.5,
                "reason": "Model reported anomaly",
            },
        )

    # Repair mitre_techniques_overall
    mt = repaired.get("mitre_techniques_overall")
    if mt:
        repaired["mitre_techniques_overall"] = _repair_mitre_list(mt)
    else:
        repaired["mitre_techniques_overall"] = []

    return repaired


# ---------------------------------------------------------------------------
# Text Extraction Helpers
# ---------------------------------------------------------------------------


def extract_mitre_techniques(content: str) -> List[Dict[str, str]]:
    """Extract MITRE ATT&CK technique IDs from freetext.

    Finds patterns like ``T1071``, ``T1071.001``, etc.

    Args:
        content: Raw text to search.

    Returns:
        List of ``{"id": "T1XXX", "name": "..."}`` dicts.
    """
    ids = set(re.findall(r'T\d{4}(?:\.\d{3})?', content))
    return [{"id": tid, "name": _get_technique_name_safe(tid)} for tid in sorted(ids)]


def extract_ip_addresses(content: str) -> List[str]:
    """Extract IPv4 addresses from text.

    Args:
        content: Raw text to search.

    Returns:
        Deduplicated list of IPv4 address strings.
    """
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    return list(set(re.findall(pattern, content)))


def extract_flow_ids(content: str) -> List[str]:
    """Extract Zeek-style flow UIDs from text.

    Matches Zeek UIDs like ``CdhXbc2WnVWrx1hLXl`` and composite
    IDs like ``job-001:CdhXbc2WnVWrx1hLXl``.

    Args:
        content: Raw text to search.

    Returns:
        List of flow ID strings found in the text.
    """
    # Zeek UIDs are base62-ish, typically 15–20 chars
    pattern = r'(?:[\w-]+:)?[A-Za-z][A-Za-z0-9]{14,20}'
    return list(set(re.findall(pattern, content)))


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------


def _repair_list_of_dicts(
    value: Any,
    default_item=None,
) -> List[Dict[str, Any]]:
    """Normalize a field that should be a list of dicts."""
    if not value:
        return []
    if not isinstance(value, list):
        value = [value]

    result = []
    for item in value:
        if isinstance(item, dict):
            result.append(item)
        elif isinstance(item, str) and default_item:
            result.append(default_item(item))
    return result


def _repair_mitre_list(raw: Any) -> List[Dict[str, str]]:
    """Normalize MITRE technique list — handles strings, dicts, or mixed."""
    if not raw:
        return []
    if not isinstance(raw, list):
        raw = [raw]

    result = []
    for item in raw:
        if isinstance(item, str):
            result.append({"id": item, "name": _get_technique_name_safe(item)})
        elif isinstance(item, dict):
            result.append(item)
    return result


def _infer_severity(content: str) -> str:
    """Infer severity from freetext keywords."""
    lower = content.lower()
    if any(w in lower for w in ("critical", "severe", "ransomware", "active breach")):
        return "critical"
    if any(w in lower for w in ("high", "malware", "c2", "command and control", "exfiltration")):
        return "high"
    if any(w in lower for w in ("low", "benign", "normal", "legitimate")):
        return "low"
    return "medium"


def _safe_float(value: Any, default: float) -> float:
    """Safely convert to float."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _get_technique_name_safe(tech_id: str) -> str:
    """Best-effort technique name lookup."""
    try:
        from app.mitre_database import get_technique_name
        return get_technique_name(tech_id)
    except Exception:
        return tech_id
