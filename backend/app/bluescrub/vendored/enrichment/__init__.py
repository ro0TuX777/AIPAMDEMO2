"""Enrichment modules for BlueScrub findings."""
from backend.app.bluescrub.vendored.enrichment.mitre import get_mitre_mapping, enrich_issues_with_mitre, MITRE_ATTACK_MAP
from backend.app.bluescrub.vendored.enrichment.auto_fix import get_auto_fix, enrich_issues_with_fixes, AUTO_FIX_SUGGESTIONS

