"""Orchestration for one code-artifact job.

Mirrors ``binalysis/service.py``: the orchestrator owns job status and events,
this module owns the analysis and its persistence.

Reference: docs/BLUESCRUB_DACV_IMPLEMENTATION_PLAN.md §5.3
"""

from __future__ import annotations

import hashlib
import json
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.bluescrub import SCORING_MODEL
from backend.app.bluescrub import binstrings, fpfilter, redaction, wordlists
from backend.app.bluescrub.scanners import dirty_word as dirty_word_scanner
from backend.app.bluescrub.canonicalize import canonicalize
from backend.app.bluescrub.persistence import persist_groups
from backend.app.bluescrub.registry import (
    optional_sensors,
    pillars_in_scope,
    required_for,
    scanners_for,
)
from backend.app.bluescrub.scoring import ScannerRun, compatibility_signature, score_job
from backend.app.bluescrub.severity_table import build_impact_modifiers, build_rule_mapping
from backend.app.models.bluescrub import BlueScrubJobLineage, BlueScrubScoreHistory

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str, str, str | None], None]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _count_files(root: Path) -> int:
    return sum(1 for p in root.rglob("*") if p.is_file()) if root.exists() else 0


def _config_hash(profile: str) -> str:
    """Digest of the settings that change results, not the operational ones."""
    from backend.app.bluescrub.pillars import (
        FAMILY_CAP_FRACTION,
        INFO_CAP_FRACTION,
        K_P,
        RULE_CAP_FULL_WEIGHT,
    )

    payload = {
        "profile": profile,
        "k_p": {p.value: v for p, v in sorted(K_P.items(), key=lambda kv: kv[0].value)},
        "rule_cap": RULE_CAP_FULL_WEIGHT,
        "family_cap": FAMILY_CAP_FRACTION,
        "info_cap": INFO_CAP_FRACTION,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def analyze_and_persist(
    db: Session,
    job_id: str,
    job_dir: Path,
    *,
    profile: str = "standard",
    project_id: str | None = None,
    analysis_kind: str = "source_audit",
    progress: ProgressFn | None = None,
) -> dict[str, Any]:
    """Run the enabled scanners, score, and persist findings for one job.

    Returns the ``dacv`` metrics object. Never raises on scanner failure: a
    failed scanner degrades its pillar and is reported. Only ingest and
    persistence failures are job-level failures.
    """
    source_root = job_dir / "input" / "source"
    specs = scanners_for(profile)
    scope = pillars_in_scope(profile)

    raw: list = []
    runs: list[ScannerRun] = []

    # The dirty-word list holds the very codenames and markings being hunted,
    # so it is handed to the sandbox by path at mode 0600 — never as argv,
    # where `ps` would publish it — and removed once the scan finishes.
    wordlist_path = _stage_wordlist(db, job_dir)
    # The recovery tier is profile-gated: FLOSS emulates the sample, and the
    # isolation contract confines emulation to `deep`.
    os.environ[binstrings.PROFILE_ENV] = profile

    for step, spec in enumerate(specs, start=1):
        if progress:
            progress(spec.name, "running", f"{step}/{len(specs)}")

        pillars = tuple(p for p in spec.pillars if p in scope)
        if not pillars:
            runs.append(ScannerRun(
                sensor=spec.name, status="skipped", required_for=(),
                optional=spec.optional, reason="profile_excludes",
            ))
            continue

        try:
            outcome = spec.run(source_root, job_dir / "sensors" / spec.name)
        except Exception as exc:  # a scanner must never fail the job
            logger.warning("BlueScrub scanner %s raised: %s", spec.name, exc, exc_info=True)
            runs.append(ScannerRun(
                sensor=spec.name, status="crashed", required_for=pillars,
                optional=spec.optional, reason=str(exc)[:256],
            ))
            if progress:
                progress(spec.name, "failed", str(exc)[:120])
            continue

        raw.extend(outcome.findings)
        runs.append(ScannerRun(
            sensor=spec.name, status=outcome.status, required_for=pillars,
            optional=spec.optional, version=outcome.version,
            ruleset_version=outcome.ruleset_version,
            ruleset_state=outcome.ruleset_state,
            duration_ms=outcome.duration_ms, reason=outcome.reason,
        ))
        if progress:
            progress(spec.name, "completed",
                     f"{len(outcome.findings)} findings ({outcome.status})")

    # Suppression runs before canonicalization so a suppressed finding cannot
    # become the primary detector of a group it should not be in. The count is
    # reported, never silent.
    filtered = fpfilter.apply(raw)

    # Redaction runs after suppression, which needs the plaintext to tell a real
    # credential from `password = "changeme"`, and before canonicalization, so
    # nothing downstream — fingerprints, evidence, exports — ever sees the
    # original value.
    redacted = redaction.redact(filtered.kept)
    raw = redacted.findings

    # Tier 1 and 2 of the severity chain. Without these every finding falls
    # through to the scanner's own severity string, which is calibrated for
    # services rather than offensive tooling — it rates a hardcoded C2 address
    # "low".
    _discard_wordlist(wordlist_path)

    result = canonicalize(
        raw,
        project_id=project_id or job_id,
        optional_sensors=optional_sensors(),
        rule_mapping=build_rule_mapping(raw),
        impact_modifiers=build_impact_modifiers(raw, analysis_kind=analysis_kind),
    )

    signature = compatibility_signature(
        profile=profile,
        scanner_manifest_digest=_manifest_digest(runs),
        ruleset_versions_digest=_ruleset_digest(runs),
        required_scanners=sorted(
            {name for p in scope for name in required_for(p, profile)}
        ),
        pillar_scope=list(scope),
        config_hash=_config_hash(profile),
    )

    metrics = score_job(
        result.groups, runs,
        profile=profile,
        analysis_kind=analysis_kind,
        project_id=project_id,
        re_signals=[],
        files_scanned=_count_files(source_root),
        unmapped=result.unmapped,
        collisions=result.collisions,
        compat_signature=signature,
    )
    metrics["dacv"].update(filtered.as_metrics())
    metrics["dacv"].update(redacted.as_metrics())

    created, updated = persist_groups(
        db, job_id, result.groups, project_id=project_id
    )
    logger.info(
        "BlueScrub job %s: %d raw -> %d canonical (%d created, %d updated)",
        job_id, len(raw), len(result.groups), created, updated,
    )

    _record_lineage(db, job_id, project_id, analysis_kind, signature)
    if project_id:
        _record_history(db, job_id, project_id, profile, signature, metrics["dacv"])

    metrics["dacv"]["findings_created"] = created
    metrics["dacv"]["findings_updated"] = updated
    return metrics


def _stage_wordlist(db: Session, job_dir: Path) -> Path | None:
    """Seed the shipped packs, then write every active term for the sandbox."""
    try:
        wordlists.seed_builtins(db)
        terms = wordlists.active_terms(db)
    except Exception as exc:  # a wordlist problem must not fail the job
        logger.warning("could not assemble dirty-word terms: %s", exc)
        return None

    path = dirty_word_scanner.write_wordlist(job_dir, terms)
    if path:
        os.environ[dirty_word_scanner.WORDLIST_ENV] = str(path)
    return path


def _discard_wordlist(path: Path | None) -> None:
    os.environ.pop(dirty_word_scanner.WORDLIST_ENV, None)
    os.environ.pop(binstrings.PROFILE_ENV, None)
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:  # pragma: no cover - runtime dir is writable
        logger.warning("could not remove staged wordlist %s: %s", path, exc)


def _manifest_digest(runs: list[ScannerRun]) -> str:
    payload = sorted(
        f"{r.sensor}@{r.version or 'unknown'}" for r in runs if not r.optional
    )
    return "sha256:" + hashlib.sha256("|".join(payload).encode()).hexdigest()


def _ruleset_digest(runs: list[ScannerRun]) -> str:
    payload = sorted(
        f"{r.sensor}:{r.ruleset_version or 'none'}" for r in runs if not r.optional
    )
    return "sha256:" + hashlib.sha256("|".join(payload).encode()).hexdigest()


def _record_lineage(
    db: Session, job_id: str, project_id: str | None,
    analysis_kind: str, signature: str,
) -> None:
    row = db.scalar(
        select(BlueScrubJobLineage).where(BlueScrubJobLineage.job_id == job_id)
    )
    if row is None:
        db.add(BlueScrubJobLineage(
            job_id=job_id, project_id=project_id,
            analysis_kind=analysis_kind, compatibility_signature=signature,
        ))
    else:
        row.compatibility_signature = signature
        row.analysis_kind = analysis_kind
    db.commit()


def _record_history(
    db: Session, job_id: str, project_id: str, profile: str,
    signature: str, dacv: dict[str, Any],
) -> None:
    existing = db.scalar(
        select(BlueScrubScoreHistory).where(BlueScrubScoreHistory.job_id == job_id)
    )
    if existing is not None:
        return  # append-only

    severity_counts: dict[str, int] = {}
    for pillar in dacv["pillars"].values():
        severity_counts[pillar["status"]] = severity_counts.get(pillar["status"], 0) + 1

    db.add(BlueScrubScoreHistory(
        project_id=project_id,
        job_id=job_id,
        scanned_at=_now(),
        profile=profile,
        scoring_model=SCORING_MODEL,
        compatibility_signature=signature,
        coverage_json=json.dumps(
            {k: v.get("coverage") for k, v in dacv["pillars"].items()}
        ),
        pillars_json=json.dumps(dacv["pillars"]),
        overall_score=dacv["overall"]["score"],
        grade=dacv["overall"]["grade"],
        scoped_score=dacv["scoped"]["score"],
        severity_counts_json=json.dumps(severity_counts),
    ))
    db.commit()
