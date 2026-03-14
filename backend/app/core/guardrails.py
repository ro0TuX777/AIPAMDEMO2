"""Anti-hallucination guardrails for forensic analysis.

These ``ValidationStep`` implementations run after an analyzer produces
``Finding`` objects but *before* the findings are committed to the
Evidence Store.  They catch common LLM hallucinations and flag them
for analyst review.

Usage::

    engine = ForensicEngine(
        analyzers=[cot_analyzer],
        guardrails=[FlowExistenceGuardrail()],
    )
"""

from __future__ import annotations

import logging
from typing import Optional, Set

from sqlmodel import Session, select

from ..db_models import FlowDB
from ..core.interfaces import Finding
from .engine import ValidationStep

logger = logging.getLogger(__name__)


class FlowExistenceGuardrail(ValidationStep):
    """Verify that cited flow IDs exist in FlowDB.

    When an LLM cites a flow ID in its evidence, this guardrail checks
    the database to confirm the flow actually exists.  If any cited ID
    is missing, the finding is flagged ``requires_review = True`` so
    an analyst can manually verify the claim.

    This avoids silently committing findings that reference hallucinated
    network flows — a common failure mode for LLMs performing
    forensic analysis.
    """

    def validate(
        self,
        finding: Finding,
        session: Optional[Session] = None,
    ) -> Finding:
        """Check all cited_flow_ids against FlowDB.

        Args:
            finding: The Finding to validate.
            session: Active DB session for FlowDB queries.
                If None, the guardrail is **skipped** (fail-open).

        Returns:
            The (possibly modified) Finding with ``requires_review``
            set if any flow IDs are hallucinated.
        """
        if not finding.cited_flow_ids:
            return finding

        if session is None:
            logger.debug(
                "FlowExistenceGuardrail skipped — no session provided"
            )
            return finding

        # Query DB for existing IDs
        existing_ids: Set[str] = set()
        for flow_id in finding.cited_flow_ids:
            row = session.exec(
                select(FlowDB).where(FlowDB.id == flow_id)
            ).first()
            if row:
                existing_ids.add(flow_id)

        hallucinated = set(finding.cited_flow_ids) - existing_ids

        if hallucinated:
            logger.warning(
                "FlowExistenceGuardrail: %d/%d cited flow IDs do not exist "
                "in FlowDB: %s — flagging for review",
                len(hallucinated),
                len(finding.cited_flow_ids),
                hallucinated,
            )
            finding = finding.model_copy(
                update={
                    "requires_review": True,
                    "review_reason": (
                        f"Hallucinated flow IDs: {sorted(hallucinated)}"
                    ),
                }
            )
        else:
            logger.debug(
                "FlowExistenceGuardrail: all %d cited flow IDs verified ✓",
                len(finding.cited_flow_ids),
            )

        return finding
