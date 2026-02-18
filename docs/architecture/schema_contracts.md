# AIPAM — Input/Output Schema Contracts

> Complete reference for all API request/response schemas, internal data contracts, and inter-component interfaces.

---

## API Schema Overview

All API schemas are Pydantic `BaseModel` subclasses defined in [schemas.py](file:///Users/vinsoncornejo/AIPAM/backend/app/schemas.py).

---

## Job Management Schemas

### `CreateJobResponse`
**Endpoint**: `POST /jobs/upload`, `POST /jobs/security-onion`, `POST /jobs/arkime`
```json
{
  "job_id": "string (UUID)",
  "status": "queued"
}
```

### `SecurityOnionJobRequest`
**Endpoint**: `POST /jobs/security-onion`
```json
{
  "source": "security_onion",
  "time_range": { "start": "ISO8601", "end": "ISO8601" },
  "sensors": ["sensor1", "sensor2"],
  "mode": "baseline_vs_exploit | single_window",
  "metadata": {}
}
```

### `ArkimeJobRequest`
**Endpoint**: `POST /jobs/arkime`
```json
{
  "source": "arkime",
  "filter": "ip.src == 10.0.0.1",
  "time_range": { "start": "ISO8601", "end": "ISO8601" },
  "mode": "baseline_vs_exploit | single_window",
  "metadata": {}
}
```

### `JobStatusResponse`
**Endpoint**: `GET /jobs/{job_id}/status`
```json
{
  "job_id": "string",
  "status": "queued | running | completed | failed",
  "created_at": "ISO8601",
  "updated_at": "ISO8601",
  "steps": [
    {
      "name": "ingest | extract | analyze | report",
      "status": "pending | running | completed | failed",
      "message": "string?"
    }
  ],
  "error_message": "string?"
}
```

### `JobResultResponse`
**Endpoint**: `GET /jobs/{job_id}/result`

Wraps the `JobResult` domain model:
```json
{
  "job_id": "string",
  "status": "completed",
  "summary": {
    "classification": "string?",
    "severity": "critical | high | medium | low | info",
    "key_findings": ["string", "..."],
    "mitre_techniques": [{ "id": "T1071", "name": "..." }]
  },
  "hosts": [
    { "ip": "10.0.0.1", "role": "victim", "findings": ["..."] }
  ],
  "raw": {
    "alerts": ["..."],
    "llm_analysis_raw": {}
  },
  "report_urls": {
    "html": "/reports/{job_id}.html",
    "markdown": "/reports/{job_id}.md"
  }
}
```

---

## Settings Schema

### `Settings`
**Endpoints**: `GET /settings`, `PUT /settings`
```json
{
  "llm_endpoint": "string?",
  "llm_model_name": "string?",
  "llm_max_tokens": "int?",
  "llm_temperature": "float?",
  "security_onion_mode": "string?",
  "security_onion_base_pcap_path": "string?",
  "security_onion_zeek_log_path": "string?",
  "security_onion_suricata_log_path": "string?",
  "security_onion_api_url": "string?",
  "security_onion_api_token": "string?",
  "arkime_api_url": "string?",
  "arkime_api_username": "string?",
  "arkime_api_password": "string?",
  "file_storage_path": "string?",
  "trafficllm_endpoint": "string?",
  "trafficllm_enabled": "bool?"
}
```

---

## Chat Schemas

### `ChatRequest`
**Endpoint**: `POST /jobs/{job_id}/chat`
```json
{
  "message": "What malware was detected?",
  "conversation_id": "string? (optional, for follow-ups)",
  "context_hint": "string? (e.g., host IP or finding text)"
}
```

### `ChatResponse`
```json
{
  "response": "Based on the analysis, IcedID was detected...",
  "citations": [
    {
      "type": "alert | host_summary | finding | flow",
      "id": "string?",
      "snippet": "relevant excerpt"
    }
  ],
  "conversation_id": "string",
  "confidence": 0.85
}
```

### `ConversationSummary`
**Endpoint**: `GET /jobs/{job_id}/conversations`
```json
{
  "id": "string",
  "job_id": "string",
  "created_at": "ISO8601",
  "updated_at": "ISO8601",
  "title": "string?",
  "message_count": 5
}
```

### `ConversationHistory`
**Endpoint**: `GET /jobs/{job_id}/conversations/{conversation_id}`
```json
{
  "id": "string",
  "job_id": "string",
  "messages": [
    {
      "role": "user | assistant",
      "content": "string",
      "citations": [],
      "timestamp": "ISO8601?"
    }
  ],
  "created_at": "ISO8601",
  "updated_at": "ISO8601"
}
```

---

## TrafficLLM Schemas

### `TrafficLLMClassifyRequest`
**Endpoint**: `POST /trafficllm/classify`
```json
{
  "packet_hex": "45 00 00 3c 1c 46...",
  "task": "MTD | EVD | TBD | BND | WAD | AAD"
}
```

### `TrafficLLMClassifyResponse`
```json
{
  "task": "MTD",
  "classification": "Zeus",
  "success": true,
  "error": null
}
```

### `TrafficLLMBatchClassifyRequest` / `TrafficLLMBatchClassifyResponse`
```json
// Request
{ "packets": [TrafficLLMClassifyRequest, ...] }

// Response
{
  "results": [TrafficLLMClassifyResponse, ...],
  "total": 50,
  "successful": 48
}
```

### `TrafficLLMStatusResponse`
**Endpoint**: `GET /trafficllm/status`
```json
{
  "available": true,
  "endpoint": "http://host.docker.internal:8001/v1/chat/completions",
  "supported_tasks": ["MTD", "EVD", "TBD", "BND", "WAD", "AAD"]
}
```

---

## Findings & Correlation Schemas (Phase 3)

### `FindingResponse`
**Endpoint**: `GET /jobs/{job_id}/findings`
```json
{
  "id": "string",
  "job_id": "string",
  "mitre_technique_id": "T1071.001",
  "mitre_technique_name": "Application Layer Protocol: Web Protocols",
  "classification": "IcedID",
  "severity": "critical",
  "title": "C2 Communication via HTTPS",
  "description": "Detected periodic beacon...",
  "evidence": {},
  "affected_hosts": { "10.0.0.5": "victim" },
  "confidence": 0.92,
  "analyzer_source": "ollama",
  "attack_chain_stage": "command_and_control",
  "analyst_status": "unverified",
  "analyst_notes": null,
  "created_at": "ISO8601"
}
```

### `FindingVerifyRequest`
**Endpoint**: `PATCH /jobs/{job_id}/findings/{finding_id}/verify`
```json
{
  "status": "confirmed | false_positive",
  "notes": "Verified against PCAP headers"
}
```

### `CorrelationGroupResponse`
**Endpoint**: `GET /correlations`
```json
{
  "group_id": "a1b2c3d4e5f6",
  "mitre_technique_id": "T1071.001",
  "common_indicators": ["10.0.0.5", "192.168.1.100"],
  "job_ids": ["job-1", "job-2"],
  "finding_ids": ["finding-a", "finding-b"],
  "confidence": 0.7
}
```

### `ExportRuleResponse`
**Endpoint**: `POST /jobs/{job_id}/findings/{finding_id}/export/{rule_type}`
```json
{
  "rule_type": "suricata | sigma",
  "rule_text": "alert tcp $HOME_NET any -> $EXTERNAL_NET 443 ...",
  "finding_id": "string",
  "description": "Detects IcedID C2 beacon pattern"
}
```

---

## Internal Contracts

### `AnalysisContext` (Input to Analyzers)
Defined in [interfaces.py](file:///Users/vinsoncornejo/AIPAM/backend/app/core/interfaces.py):

| Field | Type | Description |
|-------|------|-------------|
| `job_id` | `str` | Job identifier |
| `exercise_id` | `str` | Exercise/scenario ID |
| `mode` | `str` | `"baseline_vs_exploit"` or `"single_window"` |
| `zeek_log_path` | `Path?` | Path to Zeek conn.log |
| `suricata_log_path` | `Path?` | Path to Suricata eve.json |
| `high_priority_flow_ids` | `List[str]` | Pre-scored suspicious flows |
| `alert_ids` | `List[str]` | Alert IDs to include |
| `metadata` | `Dict` | Extensible metadata |

### `Finding` (Output from Analyzers)
Defined in [interfaces.py](file:///Users/vinsoncornejo/AIPAM/backend/app/core/interfaces.py):

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mitre_technique_id` | `str` | ✓ | e.g. `"T1071.001"` |
| `confidence_score` | `float` | ✓ | 0.0–1.0 |
| `raw_evidence_snippet` | `str` | ✓ | Actual network data excerpt |
| `rationale` | `str` | ✓ | LLM reasoning explanation |
| `severity` | `str` | ✓ | `critical/high/medium/low/info` |
| `affected_hosts` | `List[str]` | — | IPs involved |
| `classification` | `str?` | — | Malware family |
| `attack_chain_stage` | `str?` | — | Kill-chain phase |
| `cited_flow_ids` | `List[str]` | — | FlowDB IDs (validated by guardrails) |
| `requires_review` | `bool` | — | Set by guardrails |
| `review_reason` | `str?` | — | Why review is needed |

### `LLMInputBundle` (LLM Payload)
Defined in [models.py](file:///Users/vinsoncornejo/AIPAM/backend/app/models.py):

| Field | Type | Description |
|-------|------|-------------|
| `exercise_id` | `str` | Exercise identifier |
| `mode` | `str` | Analysis mode |
| `time_ranges` | `Dict[str, TimeWindow]` | `"baseline"` / `"exploit"` / `"window"` |
| `host_summaries_baseline` | `List[HostSummary]` | Baseline host stats |
| `host_summaries_exploit` | `List[HostSummary]` | Exploit host stats |
| `hostpair_summaries_baseline` | `List[HostPairSummary]` | Baseline pair stats |
| `hostpair_summaries_exploit` | `List[HostPairSummary]` | Exploit pair stats |
| `change_summaries` | `List[ChangeSummary]` | Baseline→exploit diffs |
| `alerts` | `List[AlertRecord]` | All alerts for the job |
| `trafficllm_results` | `TrafficLLMResult?` | Classification results |
| `raw_packet_samples` | `List[str]` | Scapy-extracted packet data |
| `anomaly_report` | `AnomalyReportModel?` | Heuristic anomaly findings |

### `LLMOutput` (LLM Response)
```json
{
  "classification": "IcedID",
  "overall_severity": "critical",
  "attack_chain": [
    {
      "stage": "initial_access",
      "description": "...",
      "evidence": ["..."],
      "mitre_techniques": [{ "id": "T1190", "name": "Exploit Public-Facing Application" }]
    }
  ],
  "host_findings": [
    { "ip": "10.0.0.5", "role_in_attack": "victim", "summary": "...", "suspicious_behaviors": ["..."] }
  ],
  "anomalies": [
    { "description": "...", "related_hosts": ["..."], "confidence": 0.8, "reason": "..." }
  ],
  "mitre_techniques_overall": [{ "id": "T1071", "name": "..." }]
}
```
