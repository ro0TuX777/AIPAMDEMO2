"""Runtime contract validation.

The JSON Schemas in ``contracts/`` are the gate's deliverable and the reason
several defects were caught during review. But until now they were enforced
only where a test happened to call them, and a test validates whatever object
it was handed — which is not always the object that ships.

Three violations were live at once when this module was written, and the shape
of each is the argument for it:

- A binary dirty-word finding wrote its byte offset into a ``source`` location,
  which the raw-finding contract rejects because a source location must carry a
  line number. No test exercised the binary path, so it reached the database
  with the offset discarded.
- ``dacv`` is ``additionalProperties: false``, and the service adds
  ``findings_created`` and ``findings_updated`` *after* scoring. The scoring
  test validated ``score_job``'s return value, so the object actually served by
  ``/report/{job_id}`` was never checked.
- ``strings_static_only`` was added as a ``ruleset_state`` in Sprint 5 without
  extending the enum, so every deep scan without FLOSS produced metrics that
  failed their own schema.

None of the three was found by 1500 unit tests. All three are found instantly
by validating the real object at the point it is produced.

**Off by default, on in tests.** Validating thousands of findings per job costs
real time on a large corpus, and a contract violation must never fail a
production job — the finding is still a finding. Enabled, violations are logged
at error level and counted; the job continues.
"""

from __future__ import annotations

from backend.app.pipeline.outcomes import PROPAGATE_ERRORS, public_failure

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ENV = "AIPAM_BLUESCRUB_VALIDATE_CONTRACTS"
CONTRACTS = Path(__file__).resolve().parent / "contracts"

#: How many violations to describe before summarising. One malformed adapter
#: produces thousands of identical messages, which buries everything else.
MAX_REPORTED = 5


def enabled() -> bool:
    return os.getenv(ENV, "").strip().lower() in ("1", "true", "yes", "on")


@lru_cache(maxsize=None)
def _validator(name: str):
    """Build a validator, or None when validation cannot run.

    The schemas cross-reference each other by filename, which needs a resolver
    registry; without one the refs silently fail to resolve and everything
    "validates" against nothing.
    """
    try:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource
    except ImportError:  # pragma: no cover - jsonschema is a test dependency
        logger.warning("%s is set but jsonschema is not installed", ENV)
        return None

    registry = Registry()
    for path in CONTRACTS.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(path.name, resource)
        if "$id" in schema:
            registry = registry.with_resource(schema["$id"], resource)

    return Draft202012Validator(
        json.loads((CONTRACTS / name).read_text()), registry=registry
    )


def _describe(instance: Any, schema: str) -> str | None:
    validator = _validator(schema)
    if validator is None:
        return None
    error = next(iter(validator.iter_errors(instance)), None)
    if error is None:
        return None
    where = "/".join(str(p) for p in error.absolute_path) or "(root)"
    return f"{where}: {error.message}"[:300]


def check_raw_findings(findings: list) -> list[str]:
    """Validate raw findings against ``raw-finding.schema.json``.

    Returns a description per violating finding. Never raises: a contract
    violation is a defect to fix, not a reason to lose the scan.
    """
    if not enabled():
        return []

    violations: list[str] = []
    for finding in findings:
        try:
            problem = _describe(finding.to_dict(), "raw-finding.schema.json")
        except PROPAGATE_ERRORS:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            problem = public_failure(exc)
        if problem:
            # The rule id, never the evidence — a violating finding may hold a
            # plaintext credential, and this goes to the log.
            violations.append(f"{finding.sensor}/{finding.rule_id} {problem}")

    _report("raw finding", violations)
    return violations


def check_metrics(metrics: dict) -> list[str]:
    """Validate the object that reaches ``Job.metrics_json`` and the API."""
    if not enabled():
        return []
    problem = _describe(metrics, "dacv-metrics.schema.json")
    violations = [problem] if problem else []
    _report("dacv metrics", violations)
    return violations


def _report(subject: str, violations: list[str]) -> None:
    if not violations:
        return
    logger.error(
        "%d %s contract violation(s); the contract is the specification, so "
        "this is a defect in whatever produced them: %s%s",
        len(violations), subject, "; ".join(violations[:MAX_REPORTED]),
        f" (and {len(violations) - MAX_REPORTED} more)"
        if len(violations) > MAX_REPORTED else "",
    )
