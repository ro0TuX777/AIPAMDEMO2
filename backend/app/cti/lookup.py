from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from sqlmodel import Session, select

from ..db_models import MitreTechniqueDB


DOMAIN_PRIORITY = ["enterprise", "mobile", "ics"]


def get_technique(session: Session, technique_id: str) -> Optional[MitreTechniqueDB]:
    if not technique_id:
        return None
    for domain in DOMAIN_PRIORITY:
        row = session.exec(
            select(MitreTechniqueDB)
            .where(MitreTechniqueDB.domain == domain)
            .where(MitreTechniqueDB.technique_id == technique_id)
        ).first()
        if row:
            return row
    return None


def enrich_findings(session: Session, findings: Iterable[Any]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []
    for f in findings:
        data = _as_dict(f)
        tech_id = data.get("mitre_technique_id")
        if tech_id:
            tech = get_technique(session, tech_id)
            if tech:
                data.setdefault("mitre_technique_name", tech.name)
                data["mitre_description"] = tech.description
                data["mitre_tactics"] = tech.tactics or []
                data["mitre_version"] = tech.version
                data["mitre_domain"] = tech.domain
                data["mitre_deprecated"] = tech.deprecated
                data["mitre_revoked"] = tech.revoked
                data["mitre_is_subtechnique"] = tech.is_subtechnique
        enriched.append(data)
    return enriched


def _as_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    return dict(obj)
