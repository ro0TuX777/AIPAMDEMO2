"""FLOSS — string recovery by emulation.

This scanner has two jobs, and the second is the reason it exists at all.

**It answers a question nothing else can.** A string that FLOSS recovers from a
stack, a tight loop, or a decoding routine is a string somebody deliberately
kept out of the binary's data section. Recovering it is proof that the
obfuscation was attempted and did not work — and "the author tried to hide
this and failed" is a Detectability finding of a kind no pattern matcher can
produce, because the evidence is that the code was *run*.

**It supplies the recovery the Attribution scanners cannot perform for
themselves.** Sprint 5 shipped dirty-word and build-path scanning over
binaries, both reading strings, both `parse_only`, and both therefore limited
to what is already sitting in the file. A codename assembled at runtime was
invisible to them, and a deep scan said so by reporting `strings_static_only`
and degrading Attribution coverage. FLOSS writes what it recovered to a
job-scoped cache keyed by artifact digest; those scanners merge it into their
own static pass, and the coverage loss clears because the recovery genuinely
happened.

That is why this scanner runs **first** — `ScannerSpec.order`, not the accident
that `floss` sorts after `build_paths` and `dirty_word` alphabetically.

**One emulation, not three.** Each artifact is emulated once here rather than
once per consumer. Emulation is the expensive, dangerous tier — 8 GiB and 900
seconds under the isolation contract, `deep` only — and running it three times
would triple both the cost and the exposure.

**What this scanner deliberately does not report.** An early draft flagged high
plaintext-string yield as "trivially signaturable". Measured across six
unrelated system binaries — git, ls, bash, gcc, libc, python — yield sat
between 5.9 and 9.1 strings per KiB with no separation at all. A rule that
fires on every unpacked binary ever built is the "C2 matched 67 times" failure
wearing a different hat, so it is not shipped. Low yield is the interesting
direction, and it belongs to the RE-Feasibility packing signal, not here.

Reference: docs/BLUESCRUB_ISOLATION_CONTRACT.md §3 (`emulation`) ·
docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §14 Sprint 6
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.isolation import (
    AnalyzerStatus,
    ResourceLimits,
    require_privilege_drop,
    run_analyzer,
)
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "floss"
RULE_NAMESPACE = "FLOSS"
CACHE_FILENAME = "strings.cache.json"

#: The emulation tier's ceilings, from the isolation contract.
DEFAULT_LIMITS = ResourceLimits.for_emulation()

#: Emulating every artifact in a large archive is how a deep scan becomes an
#: overnight job. The bound is reported, never silent.
MAX_ARTIFACTS = 32
#: One decoder in a loop produces the same string many times.
MAX_FINDINGS_PER_ARTIFACT = 50
#: Recovered strings are attacker-authored and go into evidence.
MAX_EVIDENCE_CHARS = 512

#: Recovery methods that mean the string was assembled at runtime. `static` is
#: excluded: those were in the file, and the consumers find them unaided.
RUNTIME_METHODS: frozenset[str] = frozenset({"stack", "tight", "decoded"})


def _run_floss(binary: str, path: Path, limits: ResourceLimits) -> dict | None:
    """Emulate one artifact. Returns the parsed payload, or None."""
    result = run_analyzer(
        [binary, *binstrings.floss_argv(path)],
        cwd=path.parent,
        limits=limits,
        require_privilege_drop=require_privilege_drop(),
    )
    if not result.ok:
        logger.info("floss on %s ended %s", path.name, result.status.value)
        return None
    try:
        return json.loads(result.stdout or b"{}")
    except json.JSONDecodeError as exc:
        logger.warning("floss output for %s was unparseable: %s", path.name, exc)
        return None


def to_findings(rel: str, recovery: binstrings.Recovery,
                recovered: list[binstrings.RecoveredString]) -> list[RawFinding]:
    """One finding per distinct runtime-assembled string. Pure."""
    findings: list[RawFinding] = []
    seen: set[str] = set()

    for entry in recovered:
        if entry.method not in RUNTIME_METHODS or not entry.value:
            continue
        if entry.value in seen:
            continue
        seen.add(entry.value)
        if len(findings) >= MAX_FINDINGS_PER_ARTIFACT:
            logger.warning(
                "floss: %s hit the %d-string cap; the rest were not reported",
                rel, MAX_FINDINGS_PER_ARTIFACT,
            )
            break

        findings.append(RawFinding(
            sensor=SENSOR, sensor_version="external",
            rule_namespace=RULE_NAMESPACE,
            rule_id="floss.recovered_obfuscated_string",
            issue_family=IssueFamily.obfuscation_weak,
            pillar_hint=FAMILY_PILLAR[IssueFamily.obfuscation_weak],
            # The evidence is that the decoding routine was executed and its
            # output observed, not that a pattern resembled something. That is
            # the strongest class of evidence this pipeline produces.
            detector_class=DetectorClass.semantic_dataflow,
            raw_severity="MEDIUM", confidence=0.95,
            source_facet="binary",
            title=f"Obfuscated string recovered by emulation ({entry.method})",
            description=(
                f"{rel} assembles this string at runtime rather than storing "
                f"it, and emulating the {entry.method} construction recovered "
                "it anyway. The obfuscation was attempted and did not work, so "
                "it buys nothing against an analyst and nothing against a "
                "signature."
            ),
            matched_tokens=entry.value[:MAX_EVIDENCE_CHARS],
            location=Location(
                kind="binary", file=rel,
                artifact_sha256=recovery.sha256,
                format=recovery.binary_format,
                # A string built at runtime was never at a file offset, and an
                # offset an analyst cannot seek to is worse than none.
                offset=None,
            ),
            recommendation=(
                "Either store the string in plain sight and accept it, or use "
                "a construction that does not survive emulation — a "
                "half-measure costs build complexity and hides nothing."
            ),
        ))

    return findings


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    from backend.app.bluescrub.scanners.dirty_word import binary_paths

    binary = shutil.which(binstrings.FLOSS_BINARY)
    if not binary:
        # Real coverage loss: whether the obfuscation holds is unanswerable
        # without emulating it, and the Attribution scanners keep reporting
        # `strings_static_only` because no cache is written.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason=f"{binstrings.FLOSS_BINARY} not on PATH",
        )

    artifacts = sorted(binary_paths(source_root))
    truncated = len(artifacts) > MAX_ARTIFACTS
    if truncated:
        logger.warning("floss: emulating the first %d of %d artifacts",
                       MAX_ARTIFACTS, len(artifacts))
        artifacts = artifacts[:MAX_ARTIFACTS]

    if not artifacts:
        # Measured, not missing: the artifact holds nothing to emulate.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.completed.value,
            version=_probe_version(binary), ruleset_version="0 artifacts",
            reason="no binary artifacts to emulate",
        )

    findings: list[RawFinding] = []
    cache: dict[str, binstrings.Recovery] = {}
    failures: list[str] = []

    for rel in artifacts:
        path = source_root / rel
        recovery = binstrings.recover(path)
        if not recovery.sha256:
            failures.append(rel)
            continue

        payload = _run_floss(binary, path, limits or DEFAULT_LIMITS)
        if payload is None:
            failures.append(rel)
            continue

        recovered = binstrings.parse_floss(payload)
        findings += to_findings(rel, recovery, recovered)
        # Only the runtime constructions go in the cache. The static ones were
        # in the file, and every consumer extracts those for itself.
        runtime = [s for s in recovered if s.method in RUNTIME_METHODS]
        if runtime:
            cache[recovery.sha256] = binstrings.Recovery(
                sha256=recovery.sha256, binary_format=recovery.binary_format,
                strings=runtime, method="floss",
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    cache_path = output_dir / CACHE_FILENAME
    cache_path.write_text(json.dumps(binstrings.cache_payload(cache)))
    # Handed on by path, like the wordlist: the consumers run behind their own
    # process boundaries and the payload is far too large for an argument.
    os.environ[binstrings.CACHE_ENV] = str(cache_path)

    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )

    degraded = bool(failures) or truncated
    reason = None
    if truncated:
        reason = f"emulated the first {MAX_ARTIFACTS} of {len(binary_paths(source_root))} artifacts"
    elif failures:
        reason = f"could not emulate {len(failures)} artifact(s): {', '.join(failures[:3])}"

    return ScannerOutcome(
        sensor=SENSOR,
        status=(AnalyzerStatus.completed_truncated.value if degraded
                else AnalyzerStatus.completed.value),
        findings=findings,
        version=_probe_version(binary),
        ruleset_version=f"{len(artifacts)} artifact(s), {len(cache)} with runtime strings",
        reason=reason,
    )


def _probe_version(binary: str) -> str | None:
    result = run_analyzer(
        [binary, "--version"],
        limits=ResourceLimits(wall_clock_seconds=60, cpu_seconds=60),
        require_privilege_drop=require_privilege_drop(),
    )
    if not result.ok:
        return None
    return (result.stdout or b"").decode("utf-8", "replace").strip()[:64] or None
