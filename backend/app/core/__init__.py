"""Core module for AIPAM forensic analysis contracts.

Re-exports the interface contracts for clean imports::

    from app.core import AnalysisContext, Finding, ForensicAnalyzer
    from app.core import ForensicEngine, ChainOfThoughtAnalyzer
    from app.core import CampaignCorrelator, SuricataExporter, SigmaExporter
"""

from .interfaces import AnalysisContext, Finding, ForensicAnalyzer
from .engine import ForensicEngine, ChainOfThoughtAnalyzer, ValidationStep
from .guardrails import FlowExistenceGuardrail
from .correlation import CampaignCorrelator, CorrelationGroup
from .exporters import SuricataExporter, SigmaExporter, ExportedRule

__all__ = [
    "AnalysisContext",
    "Finding",
    "ForensicAnalyzer",
    "ForensicEngine",
    "ChainOfThoughtAnalyzer",
    "ValidationStep",
    "FlowExistenceGuardrail",
    "CampaignCorrelator",
    "CorrelationGroup",
    "SuricataExporter",
    "SigmaExporter",
    "ExportedRule",
]
