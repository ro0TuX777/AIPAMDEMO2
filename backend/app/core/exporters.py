"""Advanced rule exporters — generate Suricata and Sigma rules from findings.

Uses ``OllamaProvider`` to produce context-aware detection rules
tailored to the specific evidence in a Finding.

Usage::

    exporter = SuricataExporter(provider=ollama)
    rule = await exporter.generate(finding_row, evidence_rows)
    print(rule.rule_text)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..llm.providers.ollama import OllamaProvider
from ..llm.prompt_renderer import render_prompt
from ..llm.parsers import parse_llm_response

logger = logging.getLogger(__name__)


class ExportedRule(BaseModel):
    """A generated detection rule with metadata.

    Attributes:
        rule_type: ``"suricata"`` or ``"sigma"``.
        rule_text: The raw rule content (SID rule or YAML).
        finding_id: The Finding this rule was generated from.
        description: Human-readable summary of what the rule detects.
        metadata: Additional info (model used, template version, etc.).
    """

    rule_type: str  # "suricata" | "sigma"
    rule_text: str
    finding_id: str
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SuricataExporter:
    """Generate Suricata IDS rules from confirmed findings."""

    def __init__(self, provider: OllamaProvider) -> None:
        self.provider = provider

    async def generate(
        self,
        finding: Any,
        evidence_snippets: Optional[List[str]] = None,
    ) -> ExportedRule:
        """Generate a Suricata rule for the given finding.

        Args:
            finding: A ``FindingDB`` row (or dict-like).
            evidence_snippets: Raw evidence text from ``EvidenceDB.snippet``.

        Returns:
            An ``ExportedRule`` with the generated Suricata signature.
        """
        prompt = render_prompt(
            "suricata_export.j2",
            finding=finding,
            evidence_snippets=evidence_snippets or [],
        )

        raw_response = await self.provider.send(
            messages=[
                {"role": "system", "content": "You are an expert Suricata rule writer."},
                {"role": "user", "content": prompt},
            ]
        )

        # Try to parse structured output; fall back to raw text
        parsed = parse_llm_response(raw_response)
        if parsed and isinstance(parsed, dict):
            rule_text = parsed.get("rule", raw_response)
            description = parsed.get("description", "")
        else:
            rule_text = raw_response.strip()
            description = ""

        return ExportedRule(
            rule_type="suricata",
            rule_text=rule_text,
            finding_id=getattr(finding, "id", str(finding)),
            description=description,
            metadata={"model": self.provider.model},
        )


class SigmaExporter:
    """Generate Sigma detection rules from confirmed findings."""

    def __init__(self, provider: OllamaProvider) -> None:
        self.provider = provider

    async def generate(
        self,
        finding: Any,
        evidence_snippets: Optional[List[str]] = None,
    ) -> ExportedRule:
        """Generate a Sigma YAML rule for the given finding.

        Args:
            finding: A ``FindingDB`` row (or dict-like).
            evidence_snippets: Raw evidence text from ``EvidenceDB.snippet``.

        Returns:
            An ``ExportedRule`` with the generated Sigma YAML.
        """
        prompt = render_prompt(
            "sigma_export.j2",
            finding=finding,
            evidence_snippets=evidence_snippets or [],
        )

        raw_response = await self.provider.send(
            messages=[
                {"role": "system", "content": "You are an expert Sigma rule writer."},
                {"role": "user", "content": prompt},
            ]
        )

        # Try to parse structured output; fall back to raw text
        parsed = parse_llm_response(raw_response)
        if parsed and isinstance(parsed, dict):
            rule_text = parsed.get("rule", raw_response)
            description = parsed.get("description", "")
        else:
            rule_text = raw_response.strip()
            description = ""

        return ExportedRule(
            rule_type="sigma",
            rule_text=rule_text,
            finding_id=getattr(finding, "id", str(finding)),
            description=description,
            metadata={"model": self.provider.model},
        )
