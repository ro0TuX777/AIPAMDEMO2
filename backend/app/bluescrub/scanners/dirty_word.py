"""Dirty-word scanning — the operator-declared side of Attribution.

Every other detector guesses what matters. This one is told: the operator names
the codenames, handles, markings, and internal hostnames that must not ship,
and a literal match on a declared term is about as precise as this pipeline
gets.

That precision is why these findings are promoted past the detector-precision
ceiling. The ceiling exists because a generic regex matching ``"C2"`` cannot
justify disqualifying an artifact; a term the operator explicitly declared
sensitive can.

**The wordlist is itself sensitive.** It contains the classification markings
and operation codenames being hunted, so it never travels as argv — ``ps``
output is world-readable — and never as an environment value. It is written to
the job's runtime directory at mode 0600, handed over by path, and deleted once
the scan finishes.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §Dirty Word search
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from backend.app.bluescrub.isolation import AnalyzerStatus, ResourceLimits, run_analyzer
from backend.app.bluescrub.models import Location, RawFinding
from backend.app.bluescrub.pillars import FAMILY_PILLAR, DetectorClass, IssueFamily
from backend.app.bluescrub.scanners.base import ScannerOutcome

logger = logging.getLogger(__name__)

SENSOR = "dirty_word"
WORDLIST_ENV = "AIPAM_BLUESCRUB_WORDLIST_FILE"

#: Term category → issue family. The category is what lets a classification
#: marking outrank a build-path fragment; upstream's packs are flat word lists
#: with no such distinction.
CATEGORY_FAMILY: dict[str, IssueFamily] = {
    "marking": IssueFamily.attribution_marking,
    "identity": IssueFamily.attribution_identity,
    "org": IssueFamily.attribution_identity,
    "codename": IssueFamily.attribution_marking,
    "hostname": IssueFamily.attribution_infrastructure,
    "ticket": IssueFamily.metadata_leak,
    "path": IssueFamily.build_path_leak,
    "mutex": IssueFamily.forensic_artifact,
    # A framework signature in your own tool is a detection problem, not an
    # attribution one — defenders match it, they do not trace it to you.
    "tooling": IssueFamily.signature_known,
}


def write_wordlist(job_dir: Path, terms: list[dict]) -> Path | None:
    """Persist terms for the sandboxed scanner. Owner-readable only."""
    if not terms:
        return None
    runtime = job_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    path = runtime / "wordlist.json"
    path.write_text(json.dumps(terms))
    path.chmod(0o600)
    return path


def parse_hits(payload: dict, terms: list[dict], source_root: Path) -> list[RawFinding]:
    """Turn scanner hits into findings, carrying each term's category through."""
    by_term = {t["term"]: t for t in terms}
    by_term_ci = {t["term"].casefold(): t for t in terms}
    findings: list[RawFinding] = []

    for hit in payload.get("matches") or payload.get("findings") or []:
        if not isinstance(hit, dict):
            continue
        term = str(hit.get("word") or hit.get("term") or hit.get("match") or "")
        if not term:
            continue

        meta = by_term.get(term) or by_term_ci.get(term.casefold()) or {}
        category = str(meta.get("category") or "codename")
        family = CATEGORY_FAMILY.get(category, IssueFamily.attribution_marking)

        raw_path = str(hit.get("file") or hit.get("path") or "")
        try:
            rel = str(Path(raw_path).resolve().relative_to(source_root.resolve()))
        except (ValueError, OSError):
            rel = raw_path

        line = hit.get("line") or hit.get("line_number")
        offset = hit.get("offset")

        findings.append(RawFinding(
            sensor=SENSOR, sensor_version="vendored",
            rule_namespace="DirtyWord",
            # Deliberately not per-term: the term can be a classification
            # marking, and rule_id reaches logs, metrics keys, and fingerprints.
            rule_id=f"dirty_word.{category}",
            issue_family=family, pillar_hint=FAMILY_PILLAR.get(family),
            detector_class=DetectorClass.regex_pattern,
            raw_severity="HIGH", confidence=0.9,
            source_facet="binary" if hit.get("binary") else "source",
            title=f"Declared term found ({category})",
            description=(
                f"The term {term!r} from the {meta.get('list', 'operator')} list "
                f"appears in {rel or 'the artifact'}. It was declared sensitive, "
                "so its presence in shipped material is a leak by definition."
            )[:4096],
            matched_tokens=str(hit.get("context") or term)[:4096],
            location=Location(
                kind="source", file=rel,
                start_line=int(line) if isinstance(line, int) else None,
                start_column=0,
                offset=int(offset) if isinstance(offset, int) else None,
            ),
        ))

    return findings


def run(source_root: Path, output_dir: Path, *,
        limits: ResourceLimits | None = None, **_kw) -> ScannerOutcome:
    wordlist_path = os.getenv(WORDLIST_ENV)
    if not wordlist_path or not Path(wordlist_path).exists():
        # No list means nothing was declared sensitive. That is a real state,
        # not a clean result: the pillar has not been assessed against operator
        # knowledge, and reporting zero findings would imply it had.
        return ScannerOutcome(
            sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
            reason="no dirty-word list configured for this job",
        )

    try:
        terms = json.loads(Path(wordlist_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.unavailable.value,
                              reason=f"unreadable wordlist: {exc}")

    result = run_analyzer(
        [sys.executable, "-m", "backend.app.bluescrub.isolation.analyzer_main",
         "__dirty_word__", str(source_root), "dirty_word"],
        cwd=Path.cwd(),
        limits=limits or ResourceLimits(),
        require_privilege_drop=os.getenv(
            "AIPAM_BLUESCRUB_REQUIRE_UID_DROP", "true"
        ).lower() not in ("0", "false", "no"),
        # By path, never by value: the terms are the secrets.
        env_extra={"PYTHONPATH": os.getcwd(), WORDLIST_ENV: wordlist_path},
    )

    if not result.ok:
        return ScannerOutcome(sensor=SENSOR, status=result.status.value,
                              duration_ms=result.duration_ms, reason=result.reason)

    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError as exc:
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.unparseable.value,
                              duration_ms=result.duration_ms, reason=str(exc))
    if not payload.get("ok"):
        return ScannerOutcome(sensor=SENSOR, status=AnalyzerStatus.crashed.value,
                              duration_ms=result.duration_ms,
                              reason=str(payload.get("error"))[:256])

    findings = parse_hits(payload.get("findings") or {}, terms, source_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "sensor.results.jsonl").write_text(
        "\n".join(json.dumps(f.to_dict()) for f in findings)
    )
    return ScannerOutcome(
        sensor=SENSOR, status=AnalyzerStatus.completed.value, findings=findings,
        version="vendored", ruleset_version=f"{len(terms)} terms",
        duration_ms=result.duration_ms,
    )
