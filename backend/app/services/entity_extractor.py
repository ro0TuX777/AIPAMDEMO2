"""
Entity extraction from user chat queries.

Detects structured identifiers (IPs, domains, hashes, finding IDs, alert SIDs,
MITRE technique IDs, JA3/JA3S fingerprints) so the retrieval router can perform
direct DB lookups instead of relying solely on vector search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Regex patterns ───────────────────────────────────────────────────────

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Domain: at least two labels, TLD 2-12 chars, no leading/trailing dash
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,12}\b"
)

# Hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Finding IDs: F-xxx or finding_id patterns
_FINDING_ID_RE = re.compile(r"\bF-[0-9a-fA-F-]{1,36}\b", re.IGNORECASE)

# Alert SIDs: numeric SIDs (typically 6-7 digits for Suricata)
_ALERT_SID_RE = re.compile(r"\bSID[:\s-]?([0-9]{4,8})\b", re.IGNORECASE)

# MITRE ATT&CK technique IDs: T1234 or T1234.001
_MITRE_RE = re.compile(r"\bT[0-9]{4}(?:\.[0-9]{3})?\b")

# JA3 / JA3S fingerprints (32 hex chars, same as MD5)
_JA3_RE = re.compile(r"\bja3s?[:\s]+([a-fA-F0-9]{32})\b", re.IGNORECASE)

# Community ID: 1:xxxx (base64-ish)
_COMMUNITY_ID_RE = re.compile(r"\b1:[A-Za-z0-9+/=]{10,30}\b")

# Common false-positive domains to exclude
_DOMAIN_STOPWORDS = {
    "example.com", "localhost.localdomain", "e.g", "i.e",
    "aka.ms", "et.al",
}


@dataclass
class ExtractedEntities:
    """Container for all entities extracted from a user query."""

    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    alert_sids: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    ja3_fingerprints: list[str] = field(default_factory=list)
    community_ids: list[str] = field(default_factory=list)

    @property
    def has_structured_entities(self) -> bool:
        """True if any structured entity was found (Route A candidate)."""
        return bool(
            self.ips or self.domains or self.hashes or self.finding_ids
            or self.alert_sids or self.mitre_ids or self.ja3_fingerprints
            or self.community_ids
        )

    @property
    def entity_count(self) -> int:
        return (
            len(self.ips) + len(self.domains) + len(self.hashes)
            + len(self.finding_ids) + len(self.alert_sids) + len(self.mitre_ids)
            + len(self.ja3_fingerprints) + len(self.community_ids)
        )

    def summary(self) -> str:
        """Human-readable summary for logging."""
        parts: list[str] = []
        if self.ips:
            parts.append(f"IPs={self.ips}")
        if self.domains:
            parts.append(f"domains={self.domains}")
        if self.hashes:
            parts.append(f"hashes={[h[:12]+'...' for h in self.hashes]}")
        if self.finding_ids:
            parts.append(f"findings={self.finding_ids}")
        if self.alert_sids:
            parts.append(f"SIDs={self.alert_sids}")
        if self.mitre_ids:
            parts.append(f"MITRE={self.mitre_ids}")
        if self.ja3_fingerprints:
            parts.append(f"JA3={self.ja3_fingerprints}")
        if self.community_ids:
            parts.append(f"community={self.community_ids}")
        return ", ".join(parts) if parts else "none"


def _unique(items: list[str]) -> list[str]:
    """Deduplicate preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalised = item.strip()
        if normalised and normalised not in seen:
            seen.add(normalised)
            result.append(normalised)
    return result


def extract_entities(text: str) -> ExtractedEntities:
    """Extract all structured entities from a user query string."""
    if not text:
        return ExtractedEntities()

    # Order matters: extract longer patterns first to avoid substring conflicts
    # SHA256 before SHA1 before MD5 (since MD5 is a substring of SHA1/SHA256)
    sha256 = _unique(_SHA256_RE.findall(text))
    # Remove SHA256 matches from text to avoid double-counting as SHA1/MD5
    remaining = _SHA256_RE.sub("", text)
    sha1 = _unique(_SHA1_RE.findall(remaining))
    remaining2 = _SHA1_RE.sub("", remaining)

    # JA3 fingerprints (extract before general MD5 to avoid overlap)
    ja3_matches = _unique([m for m in _JA3_RE.findall(text)])

    md5 = _unique([h for h in _MD5_RE.findall(remaining2) if h not in ja3_matches])
    all_hashes = _unique(sha256 + sha1 + md5)

    # IPs
    ips = _unique(_IPV4_RE.findall(text))

    # Domains — filter out IPs and stopwords
    ip_set = set(ips)
    raw_domains = _DOMAIN_RE.findall(text)
    domains = _unique([
        d.lower() for d in raw_domains
        if d not in ip_set
        and d.lower() not in _DOMAIN_STOPWORDS
        and not _IPV4_RE.fullmatch(d)
        and len(d.split(".")) >= 2
        and len(d) > 4
    ])

    # Finding IDs
    finding_ids = _unique(_FINDING_ID_RE.findall(text))

    # Alert SIDs
    alert_sids = _unique(_ALERT_SID_RE.findall(text))

    # MITRE technique IDs
    mitre_ids = _unique(_MITRE_RE.findall(text))

    # Community IDs
    community_ids = _unique(_COMMUNITY_ID_RE.findall(text))

    return ExtractedEntities(
        ips=ips,
        domains=domains,
        hashes=all_hashes,
        finding_ids=finding_ids,
        alert_sids=alert_sids,
        mitre_ids=mitre_ids,
        ja3_fingerprints=ja3_matches,
        community_ids=community_ids,
    )

