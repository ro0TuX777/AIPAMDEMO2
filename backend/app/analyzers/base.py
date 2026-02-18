"""BaseAnalyzer — Contract for forensic analysis backends.

Any AI model (TrafficLLM, Ollama/Llama, vLLM, TGI, or future
providers) must implement this interface to be pluggable into the
AIPAM analysis pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from ..domain.finding import Finding
from ..domain.forensic_data import ForensicData


class BaseAnalyzer(ABC):
    """Abstract base class for forensic analysis backends.

    Implementations wrap a specific LLM provider or heuristic engine
    and expose a uniform ``analyze()`` method that accepts structured
    ForensicData and returns a list of discrete Finding objects.

    Example usage::

        analyzer = OllamaAnalyzer(config)
        if await analyzer.health_check():
            findings = await analyzer.analyze(forensic_data)

    Subclasses **must** implement:
    - ``analyze`` — perform forensic analysis
    - ``health_check`` — verify backend connectivity
    - ``name`` property — human-readable identifier
    """

    @abstractmethod
    async def analyze(self, data: ForensicData) -> List[Finding]:
        """Perform forensic analysis on the given data.

        Args:
            data: Unified ForensicData IR containing flows, alerts,
                  host summaries, and supplementary context.

        Returns:
            A list of discrete Finding objects, each representing one
            identified technique, anomaly, or classification.
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check whether the analyzer backend is reachable and ready.

        Returns:
            True if the backend can accept analysis requests.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this analyzer.

        Examples: ``"Ollama Llama 3.1 8B"``, ``"TrafficLLM v4"``.
        """
        ...
