"""YARA — what a defender's signatures already catch.

This is the most direct question in the Detectability pillar, and the only one
answered by the defender's own tooling rather than by inference: run the
signatures a defender would run, and see whether the artifact trips them. A hit
is not a guess about how detectable something might be. It is the detection,
performed.

**Reuses AIPAM's engine rather than compiling its own rules.**
`binalysis.engine` already compiles a rules directory, runs matches, and
reports whether the `yara` module is importable at all. A second compiler here
would mean two rule paths, two failure modes, and two places for the answer
"YARA is unavailable" to come from — and §5.4 is explicit that BlueScrub is
additive and reuses existing seams.

**No rules is `unavailable`, not clean.** An empty rules directory produces
zero matches, which is indistinguishable from an artifact no signature catches
— and those are opposite conclusions. The same applies when `yara-python`
itself is missing.

**A match is Detectability, and only Detectability.** It is tempting to read a
malware-family hit as attribution, and the rule's own metadata often names a
family. But a signature says a defender will catch this, not who wrote it:
families are assigned by whoever authored the rule, from behaviour that is
frequently shared, copied, or deliberately imitated. The family name is carried
as typed evidence so an analyst can see it, and it decides nothing.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §14 Sprint 6 ·
docs/BLUESCRUB_SUPPLY_CHAIN.md (rule provenance)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from backend.app.bluescrub import binstrings
from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "yara"
RULE_NAMESPACE = "YARA"
DEFAULT_LIMITS = ResourceLimits(wall_clock_seconds=300, cpu_seconds=300)

#: Overrides the configured rules directory. Named for the platform setting it
#: shadows so an operator does not have to learn a second one.
RULES_ENV = "AIPAM_YARA_RULES_DIR"

#: One rule firing on a hundred artifacts is a hundred findings; one artifact
#: tripping a hundred rules is one artifact a defender will certainly catch.
MAX_MATCHES_PER_ARTIFACT = 50

#: Rule metadata keys that name a malware family. Carried as evidence, never
#: used to decide a family or a pillar.
_FAMILY_KEYS = ("family", "malware_family", "malware", "actor", "threat_name")


def rules_dir() -> Path | None:
    """Where the signatures live, or None if there are none anywhere.

    Three sources, most specific first: the environment override, the
    configured platform directory, then the rules bundled with the product.

    The bundled fallback exists because without it a default install reported
    Detectability as `degraded` with `missing: yara` while a ruleset sat
    unused in the source tree. `aipam_yara_rules_dir` defaults to
    ``/opt/aipam/rules/yara``, a deployment path that does not exist until
    someone provisions it, so every developer machine and every fresh install
    silently declined to run the signatures it already had. Reporting
    `unavailable` was correct given no rules; having no rules was not.
    """
    configured = os.getenv(RULES_ENV)
    if configured:
        path = Path(configured)
        return path if path.is_dir() else None
    try:
        from backend.app.config_v2 import get_settings

        path = Path(get_settings().aipam_yara_rules_dir)
        if path.is_dir():
            return path
    except Exception as exc:  # pragma: no cover - settings always load in tests
        logger.info("could not read the configured YARA rules dir: %s", exc)

    try:
        from backend.app.binalysis.service import default_rules_dir

        bundled = default_rules_dir()
    except Exception as exc:  # pragma: no cover - binalysis always imports
        logger.info("could not locate the bundled YARA rules: %s", exc)
        return None
    return bundled if bundled.is_dir() else None


def family_of(meta: dict) -> str | None:
    for key in _FAMILY_KEYS:
        value = meta.get(key)
        if value:
            return str(value)[:128]
    return None


def to_findings(rel: str, sha256: str, binary_format: str | None,
                matches) -> list[RawFinding]:
    """Turn YARA matches on one artifact into findings. Pure."""
    findings: list[RawFinding] = []

    for match in matches[:MAX_MATCHES_PER_ARTIFACT]:
        meta = dict(getattr(match, "meta", {}) or {})
        family = family_of(meta)
        tags = list(getattr(match, "tags", []) or [])
        strings = list(getattr(match, "strings", []) or [])

        evidence = ", ".join(str(s) for s in strings[:8]) or match.rule
        detail = meta.get("description") or meta.get("desc") or ""
        # Tags are how rule authors group signatures — `packer`, `apt`,
        # `webshell`. Shown because they tell an analyst what kind of thing
        # fired without opening the rule.
        labelled = f" [{', '.join(str(t) for t in tags[:6])}]" if tags else ""

        findings.append(RawFinding(
            sensor=SENSOR, sensor_version="yara-python",
            rule_namespace=RULE_NAMESPACE,
            # The rule name, not the family: two rules for one family are two
            # signatures, and an analyst silencing one must not silence both.
            rule_id=f"yara.{match.rule}",
            issue_family=IssueFamily.signature_known,
            pillar_hint=FAMILY_PILLAR[IssueFamily.signature_known],
            # Byte and string patterns with a boolean condition. Precise about
            # what it matched, and silent about what that means.
            detector_class=DetectorClass.regex_pattern,
            raw_severity="HIGH", confidence=0.9, source_facet="yara",
            title=f"Artifact matches YARA rule {match.rule}{labelled}",
            description=(
                f"{rel} matches {match.rule}"
                + (f" ({family})" if family else "")
                + ". A defender running this signature detects the artifact; "
                "this is the detection performed rather than an estimate of "
                "how detectable it might be."
                + (f" Rule notes: {detail}" if detail else "")
            )[:4096],
            matched_tokens=evidence[:4096],
            # The family is evidence for an analyst, not a decision. Whoever
            # authored the rule assigned it, often from behaviour that is
            # shared, copied, or deliberately imitated.
            typed_evidence=(
                [{"kind": "yara_family", "value": family}] if family else []
            ),
            location=Location(
                kind="binary", file=rel, artifact_sha256=sha256,
                format=binary_format,
            ),
            recommendation=(
                "Change what the rule matches, not just its name — the "
                "strings and structure it keys on are what ship."
            ),
        ))

    if len(matches) > MAX_MATCHES_PER_ARTIFACT:
        logger.warning(
            "yara: %s matched %d rules; reporting the first %d",
            rel, len(matches), MAX_MATCHES_PER_ARTIFACT,
        )
    return findings


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    from backend.app.binalysis.engine import (
        _run_yara,
        compile_yara_rules,
        yara_available,
    )

    from backend.app.bluescrub.scanners.dirty_word import binary_paths

    if not yara_available():
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason="yara-python is not installed",
        )

    directory = rules_dir()
    if directory is None:
        # Zero matches from an empty rule set and zero matches from an artifact
        # no signature catches are opposite conclusions that look identical.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason=(
                f"no YARA rules directory ({RULES_ENV} unset and the configured "
                "path does not exist)"
            ),
        )

    compiled = compile_yara_rules(directory)
    if compiled is None:
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason=f"no usable YARA rules compiled from {directory}",
        )

    artifacts = sorted(binary_paths(source_root))
    findings: list[RawFinding] = []
    for rel in artifacts:
        path = source_root / rel
        recovery = binstrings.recover(path)
        if not recovery.sha256:
            continue
        matches = _run_yara(compiled, path)
        if matches:
            findings += to_findings(rel, recovery.sha256,
                                    recovery.binary_format, matches)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )
    return ScannerOutcome(
        sensor=SENSOR, status=AnalyzerStatus.completed.value, findings=findings,
        version="yara-python",
        ruleset_version=f"{directory}",
        reason=None if artifacts else "no binary artifacts to match",
    )
