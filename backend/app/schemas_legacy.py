from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from .models import (
    JobResult,
    JobStatus,
    JobStepStatus,
)


class JobStepStatusSchema(BaseModel):
    name: str
    status: JobStepStatus
    message: Optional[str] = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    steps: List[JobStepStatusSchema]
    error_message: Optional[str] = None


class CreateJobResponse(BaseModel):
    job_id: str
    status: JobStatus


class JobResultResponse(JobResult):
    pass


class SecurityOnionJobRequest(BaseModel):
    source: str
    time_range: Dict[str, str]
    sensors: List[str]
    mode: str
    metadata: Dict[str, object] = Field(default_factory=dict)


class ArkimeJobRequest(BaseModel):
    source: str
    filter: str
    time_range: Dict[str, str]
    mode: str
    metadata: Dict[str, object] = Field(default_factory=dict)


class Settings(BaseModel):
    llm_endpoint: Optional[str] = None
    llm_model_name: Optional[str] = None
    llm_max_tokens: Optional[int] = None
    llm_temperature: Optional[float] = None
    # Dual-model selection (Forensic + General)
    forensic_model_name: Optional[str] = None
    general_model_name: Optional[str] = None
    security_onion_mode: Optional[str] = None
    security_onion_base_pcap_path: Optional[str] = None
    security_onion_zeek_log_path: Optional[str] = None
    security_onion_suricata_log_path: Optional[str] = None
    security_onion_api_url: Optional[str] = None
    security_onion_api_token: Optional[str] = None
    arkime_api_url: Optional[str] = None
    arkime_api_username: Optional[str] = None
    arkime_api_password: Optional[str] = None
    file_storage_path: Optional[str] = None
    # TrafficLLM settings
    trafficllm_endpoint: Optional[str] = None
    trafficllm_enabled: Optional[bool] = None
    # Fine-tuning configuration
    finetune_base_model: Optional[str] = None        # HuggingFace model ID
    finetune_dataset_url: Optional[str] = None       # HuggingFace dataset URL or repo ID
    finetune_lora_rank: Optional[int] = None         # LoRA rank (default: 16)
    finetune_learning_rate: Optional[float] = None   # Learning rate (default: 2e-4)
    finetune_max_seq_length: Optional[int] = None    # Context window (default: 32768)
    dataset_storage_path: Optional[str] = None       # Custom path for large datasets
    finetuning_backend: Optional[str] = "mlx"        # mlx, cuda, unsloth
    # Model setup tracking – set to True after initial model selection
    model_configured: Optional[bool] = None


class SetupStatusResponse(BaseModel):
    """Lightweight response for first-boot model setup check."""
    model_configured: bool = False
    llm_model_name: Optional[str] = None


class OllamaModelInfo(BaseModel):
    """Information about a model available in Ollama."""
    name: str
    size: int = 0
    family: str = "Unknown"
    parameter_size: str = "N/A"
    quantization: str = "Unknown"


class AvailableModelsResponse(BaseModel):
    """Response listing models available from Ollama."""
    models: List[OllamaModelInfo] = Field(default_factory=list)


# TrafficLLM API Schemas
class TrafficLLMClassifyRequest(BaseModel):
    """Request to classify traffic using TrafficLLM."""
    packet_hex: str = Field(..., description="Hex-encoded packet data (e.g., '45 00 00 3c 1c 46...')")
    task: str = Field(
        default="MTD",
        description="Detection task: MTD (Malware), EVD (VPN), TBD (Tor), BND (Botnet), WAD (Web Attack), AAD (APT)"
    )


class TrafficLLMClassifyResponse(BaseModel):
    """Response from TrafficLLM classification."""
    task: str = Field(..., description="Detection task that was performed")
    classification: str = Field(..., description="Classification result (e.g., 'Zeus', 'normal', 'skype')")
    success: bool = Field(..., description="Whether the classification was successful")
    error: Optional[str] = Field(None, description="Error message if classification failed")


class TrafficLLMBatchClassifyRequest(BaseModel):
    """Request to classify multiple packets."""
    packets: List[TrafficLLMClassifyRequest] = Field(..., description="List of packets to classify")


class TrafficLLMBatchClassifyResponse(BaseModel):
    """Response from batch TrafficLLM classification."""
    results: List[TrafficLLMClassifyResponse] = Field(..., description="Classification results")
    total: int = Field(..., description="Total number of packets processed")
    successful: int = Field(..., description="Number of successful classifications")


class TrafficLLMStatusResponse(BaseModel):
    """TrafficLLM service status."""
    available: bool = Field(..., description="Whether TrafficLLM is available")
    endpoint: Optional[str] = Field(None, description="TrafficLLM endpoint URL")
    supported_tasks: List[str] = Field(
        default=["MTD", "EVD", "TBD", "BND", "WAD", "AAD"],
        description="Supported detection tasks"
    )


# ============================================================================
# Chat API Schemas (Phase 1: Interactive PCAP Chat)
# ============================================================================

class ChatCitation(BaseModel):
    """A citation referencing evidence from the analysis."""
    type: str = Field(..., description="Type of citation: 'alert', 'host_summary', 'finding', 'flow'")
    id: Optional[str] = Field(None, description="ID of the referenced item")
    snippet: str = Field(..., description="Relevant excerpt from the evidence")


class ChatMessage(BaseModel):
    """A single message in a chat conversation."""
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content")
    citations: List[ChatCitation] = Field(default_factory=list, description="Evidence citations")
    timestamp: Optional[datetime] = None


class ChatRequest(BaseModel):
    """Request to send a chat message about a job's findings."""
    message: str = Field(..., description="User's question about the analysis")
    conversation_id: Optional[str] = Field(None, description="Optional conversation ID for context")
    context_hint: Optional[str] = Field(
        None,
        description="Optional hint about what the question relates to (e.g., host IP, finding text)"
    )


class ChatResponse(BaseModel):
    """Response from the chat endpoint."""
    response: str = Field(..., description="AI-generated response to the question")
    citations: List[ChatCitation] = Field(default_factory=list, description="Evidence citations")
    conversation_id: str = Field(..., description="Conversation ID for follow-up questions")
    confidence: Optional[float] = Field(None, description="Confidence score 0.0-1.0")


class ConversationSummary(BaseModel):
    """Summary of a conversation."""
    id: str = Field(..., description="Conversation ID")
    job_id: str = Field(..., description="Associated job ID")
    created_at: datetime = Field(..., description="When conversation started")
    updated_at: datetime = Field(..., description="Last message timestamp")
    title: Optional[str] = Field(None, description="Conversation title")
    message_count: int = Field(..., description="Number of messages")


class ConversationHistory(BaseModel):
    """Full conversation history with messages."""
    id: str = Field(..., description="Conversation ID")
    job_id: str = Field(..., description="Associated job ID")
    messages: List[ChatMessage] = Field(default_factory=list, description="Messages in order")
    created_at: datetime = Field(..., description="When conversation started")
    updated_at: datetime = Field(..., description="Last message timestamp")


# ============================================================================
# Phase 3: Findings, Correlation & Export Schemas
# ============================================================================

VALID_ANALYST_STATUSES = {"unverified", "confirmed", "false_positive"}


class FindingVerifyRequest(BaseModel):
    """Request to update an analyst's verdict on a finding."""
    status: str = Field(
        ...,
        description="Analyst verdict: 'confirmed' or 'false_positive'"
    )
    notes: Optional[str] = Field(
        None,
        description="Optional analyst notes explaining the verdict"
    )


class FindingResponse(BaseModel):
    """API response for a single finding."""
    id: str
    job_id: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_description: Optional[str] = None
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_version: Optional[str] = None
    mitre_domain: Optional[str] = None
    mitre_deprecated: Optional[bool] = None
    mitre_revoked: Optional[bool] = None
    mitre_is_subtechnique: Optional[bool] = None
    bzar_techniques: List[str] = Field(default_factory=list)
    bzar_match: Optional[bool] = None
    classification: Optional[str] = None
    severity: str
    title: str
    description: str
    evidence: Dict[str, object] = Field(default_factory=dict)
    affected_hosts: Dict[str, object] = Field(default_factory=dict)
    confidence: float = 0.0
    analyzer_source: str
    attack_chain_stage: Optional[str] = None
    analyst_status: str = "unverified"
    analyst_notes: Optional[str] = None
    created_at: datetime


class CorrelationGroupResponse(BaseModel):
    """API response for a correlation group."""
    group_id: str
    mitre_technique_id: str
    common_indicators: List[str] = Field(default_factory=list)
    job_ids: List[str] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)
    confidence: float = 0.0


class ExportRuleResponse(BaseModel):
    """API response for an exported detection rule."""
    rule_type: str
    rule_text: str
    finding_id: str
    description: str = ""


# ============================================================================
# MITRE CTI Schemas
# ============================================================================


class MitreStatusItem(BaseModel):
    domain: str
    bundle_version: Optional[str] = None
    bundle_sha256: Optional[str] = None
    bundle_modified: Optional[datetime] = None
    ingested_at: Optional[datetime] = None
    source_url: Optional[str] = None


class MitreStatusResponse(BaseModel):
    items: List[MitreStatusItem] = Field(default_factory=list)


class MitreTechniqueResponse(BaseModel):
    domain: str
    technique_id: str
    name: str
    description: Optional[str] = None
    tactics: List[str] = Field(default_factory=list)
    revoked: bool = False
    deprecated: bool = False
    is_subtechnique: bool = False
    version: Optional[str] = None
    created_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    source_url: Optional[str] = None
    bundle_sha256: Optional[str] = None
    ingested_at: Optional[datetime] = None
