"""One terminal policy for every analysis branch; no lifecycle writes."""
from dataclasses import dataclass
from typing import Any, Literal, Sequence

from sqlalchemy.exc import SQLAlchemyError


class PipelineCanceled(Exception):
    """Cooperative cancellation must escape every enrichment catch."""


class OwnershipLost(Exception):
    """The current execution no longer owns the durable job."""


# Only catalogue values cross public/log boundaries. Never infer a message from
# exception text: SQL parameters, provider payloads and broker URLs may be secret.
PUBLIC_FAILURES = {
    "analysis_failed": "Analysis stage failed.",
    "database_failed": "Analysis database operation failed.",
    "input_invalid": "Required analysis input is missing or invalid.",
    "insufficient_disk": "Insufficient disk space for analysis.",
    "canceled": "Analysis was canceled.",
    "ownership_lost": "Analysis execution was superseded.",
    "quota_exceeded": "Job exceeded disk quota.",
    "timed_out": "Timeout while running analysis stage.",
    "telemetry_partial": "Telemetry processing was incomplete.",
    "binary_missing": "No binary artifact found for job",
    "source_missing": "No staged source found for job",
}

PROPAGATE_ERRORS = (PipelineCanceled, OwnershipLost, SQLAlchemyError)


def public_failure(error: BaseException | str | None = None) -> str:
    """Return a bounded category message without formatting untrusted payloads."""
    if isinstance(error, SQLAlchemyError):
        return PUBLIC_FAILURES["database_failed"]
    if isinstance(error, PipelineCanceled):
        return PUBLIC_FAILURES["canceled"]
    if isinstance(error, OwnershipLost):
        return PUBLIC_FAILURES["ownership_lost"]
    if isinstance(error, str):
        if error in PUBLIC_FAILURES.values():
            return error
        return PUBLIC_FAILURES.get(error, PUBLIC_FAILURES["analysis_failed"])
    return PUBLIC_FAILURES["analysis_failed"]


def public_failure_summary(failures) -> str | None:
    # Stage names may originate in provider reports; publish catalogue values only.
    messages = sorted({public_failure(f.error) for f in failures})
    return "; ".join(messages)[:512] or None


@dataclass(frozen=True)
class StageFailure:
    stage: str
    error: str

    def __post_init__(self):
        object.__setattr__(self, "error", public_failure(self.error))


@dataclass(frozen=True)
class PipelineOutcome:
    status: Literal['completed', 'completed_with_errors', 'failed']
    metrics: dict[str, Any]
    required_failures: Sequence[StageFailure]
    optional_failures: Sequence[StageFailure]
    accepted_manifest_json: str


def stage_failure(stage: str, error: Exception | str) -> StageFailure:
    # Database errors may poison the transaction: the worker must recover using
    # a fresh session, never keep processing with this session.
    if isinstance(error, PROPAGATE_ERRORS):
        raise error
    return StageFailure(stage, public_failure(error))


def derive_outcome(*, required=(), optional=(), metrics=None,
                   accepted_manifest_json: str = '[]') -> PipelineOutcome:
    status = 'failed' if required else 'completed_with_errors' if optional else 'completed'
    return PipelineOutcome(status, dict(metrics or {}), tuple(required), tuple(optional), accepted_manifest_json)
