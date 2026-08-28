"""Secret redaction.

The data-handling policy is unconditional: the database, API, UI, logs, and
exports never hold a complete secret. Before this module, every secrets
detector wrote the plaintext straight into ``evidence_json.code`` — a scan of a
repository with a live AWS key copied that key into AIPAM's database, and from
there into every export.

Redaction is central rather than per-adapter for the same reason the isolation
boundary is: a new detector must not be able to leak by forgetting to opt in.

Reference: docs/BLUESCRUB_DATA_HANDLING_POLICY.md §3
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass, field

from backend.app.bluescrub.models import RawFinding, SecretRef
from backend.app.bluescrub.pillars import IssueFamily

logger = logging.getLogger(__name__)

KEY_ENV = "AIPAM_BLUESCRUB_SECRET_HMAC_KEY"

#: Families whose matched text is, by definition, a credential. Attribution
#: families are deliberately absent: an operator's email is the finding, and
#: masking it would destroy the thing the analyst needs to see.
SECRET_BEARING: frozenset[IssueFamily] = frozenset({
    IssueFamily.hardcoded_secret,
    IssueFamily.credential_exposure,
})

#: Below this length, first-and-last-four would reveal most of the value.
_MIN_LENGTH_FOR_PARTIAL_MASK = 12

_ASSIGNED = re.compile(
    r"""["']([^"']{4,512})["']|[:=]\s*([^\s"';,)]{4,512})"""
)


@dataclass
class RedactionResult:
    findings: list[RawFinding] = field(default_factory=list)
    redacted: int = 0
    unkeyed: int = 0

    def as_metrics(self) -> dict[str, object]:
        return {
            "secrets_redacted": self.redacted,
            "secrets_without_fingerprint": self.unkeyed,
        }


def secret_key() -> bytes | None:
    raw = os.getenv(KEY_ENV, "").strip()
    return raw.encode("utf-8") if raw else None


def mask(value: str) -> str:
    """First four and last four characters, or nothing recoverable at all."""
    value = value.strip().strip("\"'")
    if len(value) < _MIN_LENGTH_FOR_PARTIAL_MASK:
        return "*" * 8
    return f"{value[:4]}…{value[-4:]}"


def fingerprint(value: str, key: bytes) -> str:
    """Keyed MAC, never a bare digest.

    Many secret formats are structured and low-entropy — an AWS key is 20
    characters from a known alphabet with a known prefix — so a plain SHA-256
    is reversible by enumeration in minutes. The key is what makes the
    fingerprint safe to store, and is why an unkeyed fallback is never written.
    """
    return "hmac-sha256:" + hmac.new(
        key, value.strip().strip("\"'").encode("utf-8", "surrogatepass"),
        hashlib.sha256,
    ).hexdigest()


def extract_secret(token: str) -> str | None:
    """Pull the credential out of a matched fragment like ``KEY = "abc123"``."""
    if not token:
        return None
    match = _ASSIGNED.search(token)
    if match:
        return (match.group(1) or match.group(2) or "").strip()
    stripped = token.strip()
    # A detector may hand back the bare value with no assignment around it.
    return stripped if 4 <= len(stripped) <= 512 and " " not in stripped else None


def _secret_type(finding: RawFinding) -> str:
    label = f"{finding.rule_id} {finding.title or ''}".lower()
    for needle, name in (
        ("aws", "aws_key"), ("api", "api_key"), ("token", "token"),
        ("password", "password"), ("private", "private_key"),
        ("cert", "certificate"), ("ssh", "ssh_key"),
    ):
        if needle in label:
            return name
    return "credential"


def redact(findings: list[RawFinding]) -> RedactionResult:
    """Replace plaintext credentials with a mask and a keyed fingerprint.

    Runs after false-positive suppression, which needs the plaintext to tell a
    real credential from ``password = "changeme"``, and before canonicalization,
    so nothing downstream ever sees the original.
    """
    key = secret_key()
    result = RedactionResult()

    for finding in findings:
        result.findings.append(finding)
        if finding.issue_family not in SECRET_BEARING:
            continue

        value = extract_secret(finding.matched_tokens or "")
        if not value:
            # Nothing recognisable to redact, but the family says a credential
            # is in there somewhere. Drop the fragment rather than gamble.
            if finding.matched_tokens:
                finding.matched_tokens = "*" * 8
                result.redacted += 1
            continue

        masked = mask(value)
        finding.secret = SecretRef(
            secret_type=_secret_type(finding),
            masked_value=masked,
            # Without a key the field is omitted entirely. An unkeyed digest of
            # a low-entropy secret is reversible, so it is worse than nothing:
            # it looks like protection.
            fingerprint=fingerprint(value, key) if key else "",
        )
        if not key:
            result.unkeyed += 1

        # The fragment itself is what reaches evidence_json.code.
        finding.matched_tokens = (finding.matched_tokens or "").replace(value, masked)
        # Descriptions occasionally echo the match.
        if finding.description and value in finding.description:
            finding.description = finding.description.replace(value, masked)
        result.redacted += 1

    if result.unkeyed:
        logger.warning(
            "%s is unset — %d secret finding(s) carry no fingerprint, so they "
            "cannot be deduplicated across scans", KEY_ENV, result.unkeyed,
        )
    if result.redacted:
        logger.info("redacted %d secret finding(s)", result.redacted)
    return result
