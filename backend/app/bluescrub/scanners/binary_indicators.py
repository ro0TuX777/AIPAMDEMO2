"""Network indicators compiled into an artifact.

Running the pipeline against its intended subject for the first time — a
stripped implant rather than a source tree — turned up one gap that mattered
more than the rest. The artifact had `10.20.30.40:8443` compiled into it and
**nothing reported it**. Co-Optability scored zero with zero findings, on an
implant with a hardcoded C2, which is the single finding that pillar exists
for: whoever seizes that address inherits every implant pointing at it.

The capability was not missing. The vendored binary analyzer extracts urls,
IPs and domains from binary content with regex over bytes and no third-party
library at all — but it sits behind
`REQUIRED_CAPABILITIES = ("pe_analysis", "elf_analysis")`, so on a host without
`pefile`/`pyelftools` it goes down with the parsers. A dependency-free
capability lost to the absence of libraries it never uses.

This module takes that extraction out from behind the gate. It reads the same
recovered strings the dirty-word and build-path scanners already read, so it
needs nothing installed and works on any host.

**Only what was measured is shipped.** Across six unrelated system binaries —
git, ls, bash, gcc, libc, python — the shipped rules produce two hits in total,
both genuine IP literals from CPython's own documentation. The rules that were
*not* shipped are as deliberate:

- **General domains and URLs.** Measured, they are almost entirely licence and
  bug-tracker boilerplate: gnu.org, python.org, mitre.org, launchpad.net. An
  allowlist to separate those from a real one would be endless and brittle.
  Only internal namespaces are reported, where there is nothing to separate.
- **Mutex names, registry paths, user-agents.** These are Windows-shaped and
  there is no Windows corpus here to calibrate against. Shipping them would be
  guessing at a threshold, which is the failure this project keeps finding.
  They stay as tripwire assertions in `test_bluescrub_corpus.py` until somebody
  has a corpus.

**On reading the binaries a third time.** Dirty-word and build-paths already
do their own extraction, and this makes three passes. That is a regex sweep
over bytes measured in milliseconds — not the argument that applies to FLOSS,
where a single pass costs 900 seconds and interprets attacker code, and where
the recovery is therefore done once and shared.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §3 (Co-Optability)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.isolation import (
    AnalyzerStatus,
    ResourceLimits,
    require_privilege_drop,
    run_analyzer,
)
from backend.app.bluescrub.models import Location, Observable, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "binary_indicators"
RULE_NAMESPACE = "BinaryIndicators"
DEFAULT_LIMITS = ResourceLimits(wall_clock_seconds=300, cpu_seconds=300)

MAX_PER_FILE = 100
MAX_STRING_LENGTH = 4096

#: A maximal run of digits and dots. Matching the quad directly fails on real
#: binaries: the C2 in the fixture is recovered as `........10.20.30.40:8443`,
#: and a lookbehind excluding a preceding dot silently dropped the one finding
#: this module exists for. Examining the whole run instead is what separates an
#: address from a version string — `1.2.3.4.5` has five parts, and rejecting it
#: needs the parts either side of the match, not a lookaround.
_DOTTED_RUN = re.compile(r"[0-9][0-9.]{5,}[0-9]")

#: Internal namespaces. `.local` is deliberately absent: measured, it is mDNS
#: and string-boundary noise — `thread.local`, `Setup.local` — not hosts.
_INTERNAL_HOST = re.compile(
    r"\b([a-z0-9][-a-z0-9]{0,60}(?:\.[a-z0-9][-a-z0-9]{0,60})*"
    r"\.(?:internal|corp|lan|intranet))\b",
    re.IGNORECASE,
)

#: Ranges that are never somebody's C2. Private space is *not* excluded —
#: `10.20.30.40` in a shipped implant is exactly the finding, and an internal
#: address additionally says where the thing was built or aimed.
_NEVER_C2 = (
    ipaddress.IPv4Network("0.0.0.0/8"),          # "this network"
    ipaddress.IPv4Network("192.0.2.0/24"),       # TEST-NET-1, documentation
    ipaddress.IPv4Network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.IPv4Network("255.255.255.255/32"),
)


@dataclass(frozen=True)
class Indicator:
    """One indicator found in one artifact."""

    value: str
    kind: str            # "ipv4" | "internal_host"
    offset: int | None


def is_reportable_address(candidate: str) -> bool:
    """Whether a dotted quad is worth reporting as a hardcoded address."""
    try:
        address = ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    if (address.is_loopback or address.is_unspecified or address.is_multicast
            or address.is_reserved or address.is_link_local):
        return False
    return not any(address in network for network in _NEVER_C2)


def extract_indicators(text: str, base_offset: int | None = None,
                       width: int = 1) -> list[Indicator]:
    """Pull indicators out of one recovered string. Pure.

    Offsets are carried the same way every other binary detector carries them:
    a character index inside a UTF-16LE string is not a byte offset.
    """
    if len(text) > MAX_STRING_LENGTH:
        return []

    found: list[Indicator] = []
    seen: set[str] = set()

    for match in _DOTTED_RUN.finditer(text):
        run = match.group(0)
        parts = run.strip(".").split(".")
        if len(parts) != 4:
            # Three parts is not an address; five is a version string.
            continue
        candidate = ".".join(parts)
        if candidate in seen or not is_reportable_address(candidate):
            continue
        seen.add(candidate)
        index = match.start() + run.index(parts[0])
        found.append(Indicator(
            value=candidate, kind="ipv4",
            offset=base_offset + index * width if base_offset is not None else None,
        ))

    for match in _INTERNAL_HOST.finditer(text):
        host = match.group(1).lower()
        if host in seen:
            continue
        seen.add(host)
        found.append(Indicator(
            value=host, kind="internal_host",
            offset=(base_offset + match.start(1) * width
                    if base_offset is not None else None),
        ))

    return found


def _finding(indicator: Indicator, rel: str,
             recovery: binstrings.Recovery) -> RawFinding:
    if indicator.kind == "ipv4":
        private = ipaddress.IPv4Address(indicator.value).is_private
        family = IssueFamily.hardcoded_c2
        rule = "binary_indicators.hardcoded_address"
        title = "Hardcoded network address in a compiled artifact"
        detail = (
            "Whoever takes this address inherits every artifact pointing at "
            "it, which is why it outranks an ordinary hardcoded-configuration "
            "smell."
        ) + (
            " The address is in private space, so it also says something about "
            "where the artifact was built or aimed."
            if private else ""
        )
        observable = Observable(type="ip", value=indicator.value,
                                normalized=indicator.value,
                                origin="recovered_string", confidence=0.85)
    else:
        family = IssueFamily.attribution_infrastructure
        rule = "binary_indicators.internal_host"
        title = "Internal hostname in a compiled artifact"
        detail = (
            "An internal namespace names infrastructure that is not supposed "
            "to be reachable from wherever this artifact ends up."
        )
        observable = Observable(type="domain", value=indicator.value,
                                normalized=indicator.value,
                                origin="recovered_string", confidence=0.85)

    return RawFinding(
        sensor=SENSOR, sensor_version="builtin", rule_namespace=RULE_NAMESPACE,
        rule_id=rule, issue_family=family, pillar_hint=FAMILY_PILLAR[family],
        # Regex over recovered strings. The canonical-severity ceiling caps
        # this class below `critical`, which is right: the address is certain,
        # what it is *for* is not.
        detector_class=DetectorClass.regex_pattern,
        raw_severity="HIGH", confidence=0.85, source_facet="binary",
        title=title,
        description=f"{rel} contains {indicator.value!r}. {detail}"[:4096],
        matched_tokens=indicator.value[:4096],
        observables=[observable],
        location=Location(
            kind="binary", file=rel, artifact_sha256=recovery.sha256,
            format=recovery.binary_format, offset=indicator.offset,
        ),
        recommendation=(
            "Move it to configuration delivered at run time. An address "
            "compiled in cannot be rotated without rebuilding every artifact "
            "that carries it."
        ),
    )


def collect(source_root: Path, *, profile: str | None = None) -> list[dict]:
    """Recover strings from every binary and read the indicators out of them.

    Runs inside the analyzer subprocess: it opens attacker-authored bytes and
    runs alternations over them.
    """
    from backend.app.bluescrub.scanners.dirty_word import binary_paths

    records: list[dict] = []
    for rel in sorted(binary_paths(source_root)):
        recovery = binstrings.recover(source_root / rel, profile=profile)
        if not recovery.sha256:
            logger.warning("binary_indicators: could not read %s: %s",
                           rel, recovery.reason)
            continue

        per_file = 0
        seen: set[str] = set()
        for entry in recovery.strings:
            width = 2 if entry.encoding == "utf-16le" else 1
            for indicator in extract_indicators(entry.value, entry.offset, width):
                if indicator.value in seen:
                    continue
                if per_file >= MAX_PER_FILE:
                    logger.warning(
                        "binary_indicators: %s hit the %d-indicator cap; the "
                        "rest were not reported", rel, MAX_PER_FILE,
                    )
                    break
                seen.add(indicator.value)
                per_file += 1
                records.append({
                    "file": rel, "value": indicator.value, "kind": indicator.kind,
                    "offset": indicator.offset, "sha256": recovery.sha256,
                    "format": recovery.binary_format,
                })
    return records


_SHA256 = re.compile(r"^[a-f0-9]{64}$")


def to_findings(records: list[dict]) -> list[RawFinding]:
    """Turn collected records into raw findings. Pure."""
    findings: list[RawFinding] = []
    for record in records:
        if not isinstance(record, dict) or not record.get("value"):
            continue
        digest = str(record.get("sha256") or "")
        if not _SHA256.match(digest):
            # A binary location needs the digest, and the contract rejects one
            # without it. Nothing validates raw findings in production.
            logger.warning("binary_indicators: dropping a record with no digest")
            continue
        offset = record.get("offset")
        findings.append(_finding(
            Indicator(value=str(record["value"]),
                      kind=str(record.get("kind") or "ipv4"),
                      offset=offset if isinstance(offset, int) else None),
            str(record.get("file") or "unknown"),
            binstrings.Recovery(sha256=digest, binary_format=record.get("format")),
        ))
    return findings


def scan(source_root: Path, *, profile: str | None = None) -> list[RawFinding]:
    """In-process convenience for tests; ``run`` goes through the boundary."""
    return to_findings(collect(source_root, profile=profile))


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    result = run_analyzer(
        [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
         "__binary_indicators__", str(source_root), "binary_indicators"],
        cwd=Path.cwd(),
        limits=limits or DEFAULT_LIMITS,
        require_privilege_drop=require_privilege_drop(),
        env_extra={
            "PYTHONPATH": os.getcwd(),
            binstrings.PROFILE_ENV: os.getenv(binstrings.PROFILE_ENV, ""),
        },
    )
    if not result.ok:
        return ScannerOutcome(sensor=SENSOR, status=result.status.value,
                              duration_ms=result.duration_ms, reason=result.reason)

    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError as exc:
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.unparseable.value,
                              duration_ms=result.duration_ms, reason=str(exc)[:256])
    if not payload.get("ok"):
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.crashed.value,
                              duration_ms=result.duration_ms,
                              reason=str(payload.get("error"))[:256])

    findings = to_findings(payload.get("findings") or [])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )
    return ScannerOutcome(
        sensor=SENSOR, status=AnalyzerStatus.completed.value, findings=findings,
        version="builtin", ruleset_version="2 measured patterns",
        duration_ms=result.duration_ms,
    )
