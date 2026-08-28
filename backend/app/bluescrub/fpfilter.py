"""False-positive suppression.

Measured on 300 files of real code, most residual noise came from two places:
placeholder values that no scanner should have flagged, and third-party code
vendored into the tree. Two of the five email-address hits were
``user@example.com`` inside a bundled swagger-ui build.

Two rules, deliberately narrow.

**Value filters** apply everywhere. ``password = "changeme"`` is a placeholder
in any domain, and ``user@example.com`` is documentation.

**Third-party attribution filters** apply to the Attribution pillar only. An
email address inside a vendored dependency is somebody else's identity, not the
operator's — so it is not attribution of this artifact's author. Every other
pillar keeps those findings, because a CVE in a vendored dependency ships in
your binary and is entirely your problem.

Two things this module deliberately does **not** do:

- It does not suppress ``tests/``. Semgrep's built-in ignore list does, and the
  adapter disables that on purpose: in offensive tooling the test directory is
  where real C2 addresses and operator credentials live. Suppressing it here
  would reintroduce by the back door what was removed at the front.
- It does not use the vendored ``is_false_positive_path`` helper, which treats
  any path under ``/home/`` as noise. That is right for defensive appsec and
  exactly wrong here: ``/home/<username>/`` embedded in source is the
  attribution leak, not a false positive. It found a real one in AIPAM.

Suppressed findings are counted and reported rather than silently dropped. A
scorecard that quietly discards evidence is the failure this pipeline exists to
avoid.

Reference: docs/BLUESCRUB_DATA_CONTRACTS.md §2.3.2
"""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field

from backend.app.bluescrub.models import RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, Pillar

logger = logging.getLogger(__name__)

#: Path segments that mark code the artifact did not author. Matched as whole
#: path components so a file named "vendorlist.py" is not caught.
THIRD_PARTY_SEGMENTS: frozenset[str] = frozenset({
    "vendor", "vendored", "third_party", "thirdparty", "3rdparty",
    "node_modules", "site-packages", "dist-packages", "bower_components",
    "external", "externals", ".venv", "venv", "virtualenv",
})

#: Generated or tool-owned output that is not part of the artifact at all.
NON_ARTIFACT_SEGMENTS: frozenset[str] = frozenset({
    "__pycache__", ".git", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "analysis_results", ".tox", ".eggs", "build", "dist",
})

_SEG = re.compile(r"[\\/]+")


@dataclass
class SuppressionResult:
    kept: list[RawFinding] = field(default_factory=list)
    suppressed: int = 0
    by_filter: Counter = field(default_factory=Counter)

    def as_metrics(self) -> dict[str, object]:
        return {
            "suppressed_findings": self.suppressed,
            "suppressed_by_filter": dict(self.by_filter),
        }


def _segments(path: str | None) -> set[str]:
    if not path:
        return set()
    return {s.lower() for s in _SEG.split(path) if s}


def _is_non_artifact(path: str | None) -> bool:
    return bool(_segments(path) & NON_ARTIFACT_SEGMENTS)


def _is_third_party(path: str | None) -> bool:
    return bool(_segments(path) & THIRD_PARTY_SEGMENTS)


#: Placeholders the vendored list misses. Its entries are separator-specific —
#: it holds "change_me" but not "changeme" — so candidates are compared with
#: separators stripped, and these fill the remaining gaps.
_EXTRA_PLACEHOLDERS: frozenset[str] = frozenset({
    "changeme", "changethis", "yourpasswordhere", "insertkeyhere", "todo",
    "xxxxxxxx", "aaaaaaaa", "notarealkey", "redacted", "removed", "secret",
    "supersecret", "hunter2", "letmein", "s3cret", "correcthorsebatterystaple",
})

_SEPARATORS = str.maketrans("", "", "_-. ")


def _normalise_placeholder(value: str) -> str:
    return value.lower().strip("\"'").translate(_SEPARATORS)


def _is_placeholder_value(finding: RawFinding) -> bool:
    """Delegate to the vendored value filters, which are sound for any domain."""
    token = (finding.matched_tokens or "").strip()
    if not token:
        return False
    try:
        from backend.app.bluescrub.vendored.scanners.analyzers.helpers import (
            is_false_positive_credential,
            is_false_positive_email,
        )
    except ImportError:  # pragma: no cover - vendored tree always present
        return False

    if "@" in token and is_false_positive_email(_extract_email(token) or token):
        return True

    value = _extract_value(token) or token
    # Only the value filters, never is_false_positive_path — see the module
    # docstring for why that one would suppress a real attribution leak.
    if is_false_positive_credential(value):
        return True
    return _normalise_placeholder(value) in _EXTRA_PLACEHOLDERS


_EMAIL = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
_ASSIGNED = re.compile(r"""["']([^"']{1,64})["']\s*$|=\s*["']?([^"'\s]{1,64})""")


def _extract_email(token: str) -> str | None:
    match = _EMAIL.search(token)
    return match.group(0) if match else None


def _extract_value(token: str) -> str | None:
    match = _ASSIGNED.search(token)
    if not match:
        return None
    return match.group(1) or match.group(2)


def apply(findings: list[RawFinding]) -> SuppressionResult:
    """Filter findings, recording why each suppression happened."""
    result = SuppressionResult()
    third_party_enabled = _env_true("AIPAM_BLUESCRUB_FILTER_THIRD_PARTY", True)
    values_enabled = _env_true("AIPAM_BLUESCRUB_FILTER_PLACEHOLDERS", True)

    for finding in findings:
        path = finding.location.file or finding.location.subject
        reason: str | None = None

        if _is_non_artifact(path):
            reason = "non_artifact_path"
        elif (
            third_party_enabled
            and _is_third_party(path)
            and FAMILY_PILLAR.get(finding.issue_family) is Pillar.attribution
        ):
            # Someone else's identity in someone else's code.
            reason = "third_party_attribution"
        elif values_enabled and _is_placeholder_value(finding):
            reason = "placeholder_value"

        if reason:
            result.suppressed += 1
            result.by_filter[reason] += 1
            continue

        finding.fp_filters_applied = list(finding.fp_filters_applied)
        result.kept.append(finding)

    if result.suppressed:
        logger.info(
            "suppressed %d finding(s): %s",
            result.suppressed, dict(result.by_filter),
        )
    return result


def _env_true(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no")
