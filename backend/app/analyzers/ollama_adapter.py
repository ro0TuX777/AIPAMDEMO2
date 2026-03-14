"""OllamaAnalyzer — Adapter wrapping the existing LLMClient behind BaseAnalyzer.

This is the bridge between the old monolithic LLMClient and the new
pluggable analyzer interface.  It delegates to the existing 1,766-line
llm_client.py but presents the clean BaseAnalyzer contract.

In Phase 2, the LLMClient internals will be refactored, but this
adapter ensures consumers only depend on the stable interface.
"""

from __future__ import annotations

import logging
from typing import List

import httpx

from ..domain.finding import Finding
from ..domain.forensic_data import ForensicData
from ..domain.finding_adapter import llm_output_to_findings
from ..llm_client import LLMClient, LLMConfig
from ..llm_chunking import aggregate_llm_results, build_llm_chunks

logger = logging.getLogger(__name__)


class OllamaAnalyzer:
    """Adapter wrapping the existing LLMClient behind BaseAnalyzer.

    Converts ForensicData into the legacy LLMInputBundle format, runs
    analysis via the existing LLMClient, then converts the results into
    a list of Finding objects.

    Args:
        config: LLMConfig for the Ollama backend.
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client = LLMClient(config=config)

    async def analyze(self, data: ForensicData) -> List[Finding]:
        """Perform forensic analysis via the existing LLM pipeline.

        1. Convert ForensicData → LLMInputBundle chunks
        2. Run each chunk through LLMClient.analyze_chunk()
        3. Aggregate results via existing aggregate_llm_results()
        4. Convert aggregated LLMOutput → List[Finding]

        Args:
            data: Unified forensic data IR.

        Returns:
            List of discrete Finding objects.
        """
        # Step 1: Build LLM chunks from ForensicData
        bundles = build_llm_chunks(
            exercise_id=data.exercise_id,
            mode=data.mode,
            time_ranges=data.time_ranges,
            host_summaries_baseline=data.host_summaries_baseline,
            host_summaries_exploit=data.host_summaries_exploit,
            hostpair_summaries_baseline=data.hostpair_summaries_baseline,
            hostpair_summaries_exploit=data.hostpair_summaries_exploit,
            change_summaries=data.change_summaries,
            alerts=data.alerts,
            trafficllm_results=data.trafficllm_results,
            raw_packet_samples=data.raw_packet_samples,
            anomaly_report=data.anomaly_report,
        )

        # Step 2: Analyze each chunk
        from ..llm_chunking import analyze_chunks

        llm_results = await analyze_chunks(
            [b.model_dump() for b in bundles], client=self._client
        )

        # Step 3: Aggregate multi-chunk results
        summary, host_findings = aggregate_llm_results(
            llm_results,
            trafficllm_results=data.trafficllm_results,
            alerts=data.alerts,
            exercise_id=data.exercise_id,
        )

        # Step 4: Convert to Finding objects
        all_findings: List[Finding] = []
        for llm_output in llm_results:
            findings = llm_output_to_findings(
                job_id=data.job_id,
                llm_output=llm_output,
                analyzer_source=self.name,
            )
            all_findings.extend(findings)

        return all_findings

    async def health_check(self) -> bool:
        """Check whether the Ollama endpoint is reachable.

        Returns:
            True if the Ollama API responds successfully.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._config.endpoint}")
                return resp.status_code == 200
        except Exception:
            return False

    @property
    def name(self) -> str:
        """Human-readable name for this analyzer."""
        return f"Ollama ({self._config.model})"
