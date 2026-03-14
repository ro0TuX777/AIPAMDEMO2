from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from .logging_config import get_logger

logger = get_logger(__name__)

_TECH_RE = re.compile(r"T\\d{4}(?:\\.\\d{3})?")


def bzar_enabled() -> bool:
    return os.getenv("BZAR_VALIDATOR_ENABLED", "false").lower() == "true"


def parse_notice_log(path: Path) -> Dict[str, Any]:
    """Extract ATT&CK technique IDs from Zeek notice.log (JSON)."""
    if not path.exists():
        return {"technique_ids": [], "notices": []}

    notices: List[Dict[str, Any]] = []
    technique_ids: set[str] = set()

    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            text_parts = []
            for key in ("note", "msg", "sub", "identifier"):
                val = rec.get(key)
                if val:
                    text_parts.append(str(val))
            text = " ".join(text_parts)
            techs = _extract_techniques(text)
            if techs:
                technique_ids.update(techs)

            notices.append(
                {
                    "ts": rec.get("ts"),
                    "note": rec.get("note"),
                    "msg": rec.get("msg"),
                    "sub": rec.get("sub"),
                    "identifier": rec.get("identifier"),
                    "src_ip": rec.get("id.orig_h"),
                    "dst_ip": rec.get("id.resp_h"),
                    "uid": rec.get("uid"),
                    "technique_ids": techs,
                }
            )

    return {"technique_ids": sorted(technique_ids), "notices": notices}


def _extract_techniques(text: str) -> List[str]:
    if not text:
        return []
    return sorted(set(_TECH_RE.findall(text)))
