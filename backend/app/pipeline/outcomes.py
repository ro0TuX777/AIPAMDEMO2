"""One terminal policy for every analysis branch; no lifecycle writes."""
from dataclasses import dataclass
from typing import Any, Literal, Sequence

from sqlalchemy.exc import SQLAlchemyError


class PipelineCanceled(Exception):
    """Cooperative cancellation must escape every enrichment catch."""


class OwnershipLost(Exception):
    """The current execution no longer owns the durable job."""


@dataclass(frozen=True)
class StageFailure:
    stage: str
    error: str


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
    if isinstance(error, (PipelineCanceled, OwnershipLost, SQLAlchemyError)):
        raise error
    return StageFailure(stage, str(error))


def derive_outcome(*, required=(), optional=(), metrics=None,
                   accepted_manifest_json: str = '[]') -> PipelineOutcome:
    status = 'failed' if required else 'completed_with_errors' if optional else 'completed'
    return PipelineOutcome(status, dict(metrics or {}), tuple(required), tuple(optional), accepted_manifest_json)
