from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx
from sqlmodel import Session

from ..db_models import MitreCtiBundleDB, MitreTechniqueDB


DEFAULT_SOURCES = {
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}

DOMAIN_SOURCE_NAMES = {
    "enterprise": {"mitre-attack"},
    "mobile": {"mitre-mobile"},
    "ics": {"mitre-ics"},
}


def load_bundle(source: str) -> Tuple[Dict[str, Any], str]:
    if source.startswith("http://") or source.startswith("https://"):
        resp = httpx.get(source, timeout=30.0)
        resp.raise_for_status()
        raw = resp.text
    else:
        with open(source, "r", encoding="utf-8") as f:
            raw = f.read()
    bundle = json.loads(raw)
    sha = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return bundle, sha


def _extract_external_id(obj: Dict[str, Any], domain: str) -> Optional[str]:
    refs = obj.get("external_references") or []
    wanted = DOMAIN_SOURCE_NAMES.get(domain, set())
    for ref in refs:
        if ref.get("source_name") in wanted and ref.get("external_id"):
            return ref["external_id"]
    for ref in refs:
        if ref.get("external_id", "").startswith("T"):
            return ref.get("external_id")
    return None


def _extract_tactics(obj: Dict[str, Any]) -> List[str]:
    phases = obj.get("kill_chain_phases") or []
    tactics = []
    for phase in phases:
        name = phase.get("phase_name")
        if name:
            tactics.append(name)
    return sorted(set(tactics))


def parse_bundle(
    bundle: Dict[str, Any],
    domain: str,
) -> Tuple[List[Dict[str, Any]], Optional[datetime], Optional[str]]:
    items: List[Dict[str, Any]] = []
    latest_modified: Optional[datetime] = None
    versions: List[str] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = _extract_external_id(obj, domain)
        if not technique_id:
            continue
        if obj.get("x_mitre_version"):
            versions.append(obj.get("x_mitre_version"))
        modified = _parse_dt(obj.get("modified"))
        if modified and (latest_modified is None or modified > latest_modified):
            latest_modified = modified
        items.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description"),
                "tactics": _extract_tactics(obj),
                "revoked": bool(obj.get("revoked", False)),
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "version": obj.get("x_mitre_version"),
                "created_at": _parse_dt(obj.get("created")),
                "modified_at": modified,
            }
        )
    return items, latest_modified, _max_version(versions)


def ingest_domain(
    session: Session,
    domain: str,
    source: str,
) -> Dict[str, Any]:
    bundle, bundle_sha = load_bundle(source)
    techniques, latest_modified, attack_version = parse_bundle(bundle, domain)
    ingested_at = datetime.now(timezone.utc)

    session.exec(MitreTechniqueDB.__table__.delete().where(MitreTechniqueDB.domain == domain))

    rows = []
    for t in techniques:
        rows.append(
            MitreTechniqueDB(
                id=f"{domain}:{t['technique_id']}",
                domain=domain,
                technique_id=t["technique_id"],
                name=t["name"],
                description=t.get("description"),
                tactics=t.get("tactics", []),
                revoked=t.get("revoked", False),
                deprecated=t.get("deprecated", False),
                is_subtechnique=t.get("is_subtechnique", False),
                version=t.get("version"),
                created_at=t.get("created_at"),
                modified_at=t.get("modified_at"),
                source_url=source,
                bundle_sha256=bundle_sha,
                ingested_at=ingested_at,
            )
        )

    session.add_all(rows)

    bundle_version = attack_version or bundle.get("spec_version")
    bundle_row = MitreCtiBundleDB(
        domain=domain,
        source_url=source,
        bundle_sha256=bundle_sha,
        bundle_version=bundle_version,
        bundle_modified=latest_modified,
        ingested_at=ingested_at,
    )
    session.merge(bundle_row)
    session.commit()

    return {
        "domain": domain,
        "count": len(rows),
        "bundle_sha256": bundle_sha,
        "bundle_version": bundle_version,
        "bundle_modified": latest_modified.isoformat() if latest_modified else None,
    }


def _max_version(values: Iterable[str]) -> Optional[str]:
    def _key(v: str) -> Tuple[int, ...]:
        try:
            return tuple(int(p) for p in v.split("."))
        except Exception:
            return (0,)

    values = list({v for v in values if v})
    if not values:
        return None
    return sorted(values, key=_key)[-1]


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
