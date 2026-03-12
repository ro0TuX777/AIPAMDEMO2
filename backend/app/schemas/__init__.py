"""AIPAM V2 Pydantic request/response schemas.

All schemas match the openapi.yaml component definitions.
"""

from backend.app.schemas.common import (
    SCHEMA_VERSION,
    ErrorResponse,
    ExecutionProfile,
    IocType,
    JobStatus,
    PageInfo,
    Priority,
    SensorStatus,
    Severity,
)

# Re-export V1 legacy schemas so `from .schemas import X` keeps working
from backend.app.schemas_legacy import *  # noqa: F401,F403
from backend.app.schemas_legacy import (  # explicit re-exports
    AvailableModelsResponse,
    ChatCitation,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ConversationHistory,
    ConversationSummary,
    CorrelationGroupResponse,
    CreateJobResponse,
    ExportRuleResponse,
    FindingResponse,
    FindingVerifyRequest,
    JobResultResponse,
    JobStatusResponse,
    JobStepStatusSchema,
    MitreStatusItem,
    MitreStatusResponse,
    MitreTechniqueResponse,
    OllamaModelInfo,
    SecurityOnionJobRequest,
    Settings,
    SetupStatusResponse,
    TrafficLLMBatchClassifyRequest,
    TrafficLLMBatchClassifyResponse,
    TrafficLLMClassifyRequest,
    TrafficLLMClassifyResponse,
    TrafficLLMStatusResponse,
)

__all__ = [
    # V2
    "SCHEMA_VERSION",
    "ErrorResponse",
    "ExecutionProfile",
    "IocType",
    "JobStatus",
    "PageInfo",
    "Priority",
    "SensorStatus",
    "Severity",
    # V1 legacy
    "ArkimeJobRequest",
    "AvailableModelsResponse",
    "ChatCitation",
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "ConversationHistory",
    "ConversationSummary",
    "CorrelationGroupResponse",
    "CreateJobResponse",
    "ExportRuleResponse",
    "FindingResponse",
    "FindingVerifyRequest",
    "JobResultResponse",
    "JobStatusResponse",
    "JobStepStatusSchema",
    "MitreStatusItem",
    "MitreStatusResponse",
    "MitreTechniqueResponse",
    "OllamaModelInfo",
    "SecurityOnionJobRequest",
    "Settings",
    "SetupStatusResponse",
    "TrafficLLMBatchClassifyRequest",
    "TrafficLLMBatchClassifyResponse",
    "TrafficLLMClassifyRequest",
    "TrafficLLMClassifyResponse",
    "TrafficLLMStatusResponse",
]

