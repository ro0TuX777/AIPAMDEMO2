"""
Distillation v1 — Output schemas, task registry, and prompt templates.

Defines the structured output schemas the teacher must produce, the
global system prompt, and per-task user prompt templates.  Each task
maps to exactly one output schema.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════════════════
# Output Schemas — strict JSON contracts the teacher must satisfy
# ═══════════════════════════════════════════════════════════════════════════


class EvidenceRef(BaseModel):
    """A reference to an entity inside the evidence bundle."""
    type: Literal[
        "finding", "alert", "ioc", "host", "file",
        "timeline", "slice", "theory", "dns", "tls", "connection",
    ]
    id: str


class GroundedExplanationV1(BaseModel):
    """Output schema for explain_finding and optionally slice_summary."""
    assessment: str
    confidence: Literal["low", "medium", "high"]
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    possible_benign_explanations: List[str] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)


class HostSummaryV1(BaseModel):
    """Output schema for host_summary."""
    host_assessment: Literal["suspicious", "likely_benign", "inconclusive"]
    summary: str
    confidence: Literal["low", "medium", "high"]
    key_behaviors: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    possible_benign_explanations: List[str] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)


class TopHostEntry(BaseModel):
    host_ip: str
    reason: str


class TopFindingEntry(BaseModel):
    finding_id: str
    reason: str


class LikelyTheoryEntry(BaseModel):
    theory_id: str
    label: str


class JobSummaryV1(BaseModel):
    """Output schema for job_summary."""
    overall_assessment: str
    confidence: Literal["low", "medium", "high"]
    top_hosts: List[TopHostEntry] = Field(default_factory=list)
    top_findings: List[TopFindingEntry] = Field(default_factory=list)
    likely_theories: List[LikelyTheoryEntry] = Field(default_factory=list)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)


class AnalystReportV1(BaseModel):
    """Output schema for analyst_report."""
    report_title: str
    executive_summary: str
    technical_summary: str
    top_hosts: List[str] = Field(default_factory=list)
    top_findings: List[str] = Field(default_factory=list)
    likely_theories: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)


class ExecutiveReportV1(BaseModel):
    """Output schema for executive_report."""
    summary: str
    business_impact: str
    top_concerns: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"]
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Global System Prompt
# ═══════════════════════════════════════════════════════════════════════════

TEACHER_SYSTEM_PROMPT = """\
You are AIPAM's frontier teacher model for cybersecurity investigation distillation.

RULES:
- Use ONLY the evidence provided in the input bundle. Do not invent entities.
- Cite evidence references whenever making a meaningful conclusion.
- If evidence is weak or inconclusive, say so explicitly.
- Do not claim malware family attribution unless strongly supported.
- Treat MITRE ATT&CK as candidate mapping only, not authoritative truth.
- Return ONLY a JSON object matching the exact schema specified in the task.
- Do NOT add extra fields like "schema_version" or "version".
- Do NOT wrap values in objects when the schema says string.
- "evidence_refs" must be an array of objects: [{"type": "<type>", "id": "<id>"}]
  where type is one of: finding, alert, ioc, host, file, timeline, slice, theory, dns, tls, connection.
- "possible_benign_explanations" must be an array of plain strings, NOT objects.
- Do NOT include markdown, prose outside JSON, or commentary outside the schema."""


# ═══════════════════════════════════════════════════════════════════════════
# Task-specific user prompt templates
# ═══════════════════════════════════════════════════════════════════════════

TASK_PROMPTS: Dict[str, str] = {
    "explain_finding": """\
Task: explain_finding

Required JSON schema (return EXACTLY these fields, no extras):
{{
  "assessment": "<string: explain the finding to a security analyst>",
  "confidence": "<'low' | 'medium' | 'high'>",
  "evidence_refs": [{{"type": "<finding|alert|ioc|host|timeline|...>", "id": "<entity_id>"}}],
  "possible_benign_explanations": ["<plain string>", ...],
  "next_steps": ["<plain string>", ...]
}}

Instructions:
- Describe what the finding likely means and its severity.
- Cite evidence_refs with type+id objects from the bundle.
- possible_benign_explanations must be plain strings, NOT objects.
- Use only the supplied evidence.

Evidence Bundle:
{bundle_json}""",

    "host_summary": """\
Task: host_summary

Required JSON schema (return EXACTLY these fields, no extras):
{{
  "host_assessment": "<'suspicious' | 'likely_benign' | 'inconclusive'>",
  "summary": "<string: narrative summary of host behavior>",
  "confidence": "<'low' | 'medium' | 'high'>",
  "key_behaviors": ["<plain string>", ...],
  "evidence_refs": [{{"type": "<finding|alert|ioc|host|timeline|...>", "id": "<entity_id>"}}],
  "possible_benign_explanations": ["<plain string>", ...],
  "next_steps": ["<plain string>", ...]
}}

Instructions:
- Summarize whether the host appears suspicious, benign, or inconclusive.
- evidence_refs must be objects with "type" and "id" fields, not plain strings.
- possible_benign_explanations must be plain strings, NOT objects.
- Use only the supplied evidence.

Evidence Bundle:
{bundle_json}""",

    "job_summary": """\
Task: job_summary

Required JSON schema (return EXACTLY these fields, no extras):
{{
  "overall_assessment": "<string: overall investigation summary>",
  "confidence": "<'low' | 'medium' | 'high'>",
  "top_hosts": [{{"host_ip": "<ip>", "reason": "<string>"}}],
  "top_findings": [{{"finding_id": "<id>", "reason": "<string>"}}],
  "likely_theories": [{{"theory_id": "<id>", "label": "<string>"}}],
  "evidence_refs": [{{"type": "<finding|alert|ioc|host|timeline|...>", "id": "<entity_id>"}}],
  "next_steps": ["<plain string>", ...]
}}

Instructions:
- Summarize the overall investigation for an analyst.
- Identify top suspicious hosts and top findings.
- Use only the supplied evidence.

Evidence Bundle:
{bundle_json}""",

    "slice_summary": """\
Task: slice_summary

Required JSON schema (return EXACTLY these fields, no extras):
{{
  "assessment": "<string: describe what occurred in this time window>",
  "confidence": "<'low' | 'medium' | 'high'>",
  "evidence_refs": [{{"type": "<finding|alert|ioc|host|timeline|...>", "id": "<entity_id>"}}],
  "possible_benign_explanations": ["<plain string>", ...],
  "next_steps": ["<plain string>", ...]
}}

Instructions:
- Summarize what activity occurred during this suspicious time window.
- Identify key entities involved.
- possible_benign_explanations must be plain strings, NOT objects.
- Use only the supplied evidence.

Evidence Bundle:
{bundle_json}""",

    "analyst_report": """\
Task: analyst_report

Required JSON schema (return EXACTLY these fields, no extras):
{{
  "report_title": "<string>",
  "executive_summary": "<string>",
  "technical_summary": "<string>",
  "top_hosts": ["<plain string>", ...],
  "top_findings": ["<plain string>", ...],
  "likely_theories": ["<plain string>", ...],
  "recommended_actions": ["<plain string>", ...],
  "evidence_refs": [{{"type": "<finding|alert|ioc|host|timeline|...>", "id": "<entity_id>"}}]
}}

Instructions:
- Draft a technical evidence-backed investigation report.
- All list fields must contain plain strings, not objects.
- Use only the supplied evidence.

Evidence Bundle:
{bundle_json}""",

    "executive_report": """\
Task: executive_report

Required JSON schema (return EXACTLY these fields, no extras):
{{
  "summary": "<string: concise impact-focused summary>",
  "business_impact": "<string>",
  "top_concerns": ["<plain string>", ...],
  "recommended_actions": ["<plain string>", ...],
  "confidence": "<'low' | 'medium' | 'high'>",
  "evidence_refs": [{{"type": "<finding|alert|ioc|host|timeline|...>", "id": "<entity_id>"}}]
}}

Instructions:
- Draft a concise impact-focused summary for leadership.
- Focus on business impact and top concerns.
- Use only the supplied evidence.

Evidence Bundle:
{bundle_json}""",
}


# ═══════════════════════════════════════════════════════════════════════════
# Task Registry — maps task_type to output schema and bundle scope
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TaskSpec:
    """Specification for a single distillation task type."""
    task_type: str
    output_schema: type  # Pydantic model class
    output_schema_name: str
    bundle_scope: str  # "finding", "host", "job", "slice"
    prompt_template: str


TASK_REGISTRY: Dict[str, TaskSpec] = {
    "explain_finding": TaskSpec(
        task_type="explain_finding",
        output_schema=GroundedExplanationV1,
        output_schema_name="GroundedExplanationV1",
        bundle_scope="finding",
        prompt_template=TASK_PROMPTS["explain_finding"],
    ),
    "host_summary": TaskSpec(
        task_type="host_summary",
        output_schema=HostSummaryV1,
        output_schema_name="HostSummaryV1",
        bundle_scope="host",
        prompt_template=TASK_PROMPTS["host_summary"],
    ),
    "job_summary": TaskSpec(
        task_type="job_summary",
        output_schema=JobSummaryV1,
        output_schema_name="JobSummaryV1",
        bundle_scope="job",
        prompt_template=TASK_PROMPTS["job_summary"],
    ),
    "slice_summary": TaskSpec(
        task_type="slice_summary",
        output_schema=GroundedExplanationV1,
        output_schema_name="GroundedExplanationV1",
        bundle_scope="slice",
        prompt_template=TASK_PROMPTS["slice_summary"],
    ),
    "analyst_report": TaskSpec(
        task_type="analyst_report",
        output_schema=AnalystReportV1,
        output_schema_name="AnalystReportV1",
        bundle_scope="job",
        prompt_template=TASK_PROMPTS["analyst_report"],
    ),
    "executive_report": TaskSpec(
        task_type="executive_report",
        output_schema=ExecutiveReportV1,
        output_schema_name="ExecutiveReportV1",
        bundle_scope="job",
        prompt_template=TASK_PROMPTS["executive_report"],
    ),
}

# Convenience list of all v1 task types
V1_TASK_TYPES = list(TASK_REGISTRY.keys())

