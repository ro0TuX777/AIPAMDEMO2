# AIPAM Implementation Plan: Phase 1 & 2

## Overview

This document outlines the implementation plan for the next two phases of AIPAM development:
- **Phase 1**: Interactive PCAP Chat (4 weeks)
- **Phase 2**: Enhanced Analysis Pipeline (6 weeks)

---

## Phase 1: Interactive PCAP Chat

### Goal
Enable analysts to ask natural-language questions about analyzed PCAPs and receive contextual, evidence-backed answers.

### Week 1-2: Foundation

#### 1.1 Data Indexing Layer
- **Index normalized summaries only** (NOT raw Zeek logs or packets):
  - `HostSummary` - per-host traffic profiles
  - `HostPairSummary` - communication patterns between hosts
  - `AlertRecord` - Suricata/TrafficLLM alerts
  - `FlowRecord` (aggregated) - connection metadata
- **Storage**: Use LanceDB for vector embeddings (embedded, serverless)
- **Embedding model**: `sentence-transformers/all-MiniLM-L6-v2` (local, air-gap compatible)

#### 1.2 Chunking & Ranking Strategy
- **Chunk by host**: Each host's complete profile as one chunk
- **Chunk by time window**: 10-minute buckets for temporal queries
- **Anomaly ranking**: Use the same anomaly-focused bundle ranking from auto-analysis
  - High-severity alerts → top priority
  - Unusual traffic patterns → medium priority
  - Baseline traffic → lowest priority

### Week 3: RAG Implementation

#### 2.1 RAG Pipeline
```
User Query → Embed → Vector Search → Retrieve Top-K Chunks → LLM Context → Response
```

- **RAG over normalized network summaries** (hosts, host-pairs, alerts) for semantic Q&A
- **Context window management**:
  - Max 8 chunks per query
  - Prioritize anomaly-ranked content
  - Include relevant alerts with each host chunk

#### 2.2 Query Types Supported
| Query Type | Example | Retrieval Strategy |
|------------|---------|-------------------|
| Host investigation | "What did 10.6.13.133 do?" | Host summary + all alerts |
| Lateral movement | "Show connections between compromised hosts" | Host-pair summaries |
| Timeline | "What happened between 14:00-15:00?" | Time-windowed chunks |
| Malware focus | "Which hosts had Zeus activity?" | Alert-based retrieval |

### Week 4: Chat UI & Integration

#### 3.1 Frontend Components
- Chat panel (collapsible sidebar or dedicated view)
- Message history with citations
- "Ask about this host" quick actions from report view
- Export conversation to markdown

#### 3.2 Backend API
```python
POST /api/v1/jobs/{job_id}/chat
{
  "message": "What malware was detected on 10.6.13.133?",
  "conversation_id": "uuid",  # optional, for context
  "include_evidence": true
}

Response:
{
  "response": "Host 10.6.13.133 was detected with 5 malware types...",
  "citations": [
    {"type": "alert", "id": "...", "snippet": "..."},
    {"type": "host_summary", "id": "...", "snippet": "..."}
  ],
  "confidence": 0.92
}
```

### Deliverables
- [x] Vector database integration (LanceDB)
- [x] Embedding pipeline for normalized summaries
- [x] RAG retrieval with anomaly-ranked chunking
- [x] Chat API endpoint
- [x] Chat UI component
- [x] Conversation persistence

---

## Phase 2: Enhanced Analysis Pipeline

### Goal
Deeper TrafficLLM integration, confidence-aware analysis, and real-time progress streaming.

### Week 1-2: Deep TrafficLLM Integration

#### 1.1 Decision Matrix: Rule-based vs LLM Reasoning

| Signal | Source | Processing |
|--------|--------|------------|
| Malware classification | TrafficLLM MTD | **Rule-based**: Direct mapping to MITRE ATT&CK |
| Botnet detection | TrafficLLM BND | **Rule-based**: Auto-tag hosts as C2/bot |
| Attack chain reasoning | LLM | **LLM reasoning**: Connect signals into narrative |
| Severity assessment | LLM | **LLM reasoning**: Weigh multiple factors |
| Lateral movement inference | Both | **Hybrid**: TrafficLLM detects, LLM explains |

#### 1.2 Parallel Model Execution
```python
# Run TrafficLLM tasks in parallel
async def analyze_with_trafficllm(flows: List[FlowRecord]):
    tasks = [
        classify_malware(flows),      # MTD
        detect_botnets(flows),        # BND
        detect_web_attacks(flows),    # WAD
        detect_apt(flows),            # AAD
    ]
    results = await asyncio.gather(*tasks)
    return merge_trafficllm_results(results)
```

### Week 3-4: Confidence Scoring System

#### 2.1 Confidence Score Model
```python
class FindingConfidence(BaseModel):
    score: float           # 0.0 - 1.0
    level: str             # "high", "medium", "low"
    factors: List[str]     # What contributed to this score

class Finding(BaseModel):
    description: str
    evidence: List[str]
    confidence: FindingConfidence
    mitre_techniques: List[str]
```

#### 2.2 Confidence Usage

**In UI** (so analysts see risk level):
- Color-coded badges: 🟢 High | 🟡 Medium | 🔴 Low confidence
- Expandable "Why this confidence?" section
- Sort/filter findings by confidence

**In LLM Prompts** (so model can reason over high/low confidence signals):
```
The following findings have varying confidence levels.
Weight HIGH confidence findings more heavily in your analysis:

HIGH CONFIDENCE:
- TrafficLLM detected Zeus malware (F1=0.98)
- 47 C2 beacon connections to known bad IP

MEDIUM CONFIDENCE:
- Unusual data transfer volume (3x baseline)

LOW CONFIDENCE:
- Possible lateral movement (only 2 connections)
```

### Week 5-6: Real-time WebSocket Streaming

#### 3.1 State Transition Events
Stream pipeline state transitions to connected clients:

```python
# WebSocket message types
class PipelineEvent(BaseModel):
    job_id: str
    event_type: Literal[
        "state_change",      # Pipeline stage transitions
        "high_severity_alert", # Early alert notification
        "progress_update",   # Percentage complete
        "partial_finding"    # High-confidence early finding
    ]
    timestamp: datetime
    payload: dict

# Example events
{"event_type": "state_change", "payload": {"from": "ingest", "to": "parse"}}
{"event_type": "state_change", "payload": {"from": "parse", "to": "aggregate"}}
{"event_type": "high_severity_alert", "payload": {"host": "10.6.13.133", "alert": "Zeus C2 beacon"}}
{"event_type": "state_change", "payload": {"from": "aggregate", "to": "llm_analysis"}}
{"event_type": "partial_finding", "payload": {"finding": "5 malware types detected", "confidence": "high"}}
{"event_type": "state_change", "payload": {"from": "llm_analysis", "to": "report"}}
```

#### 3.2 What We Stream (and Don't)

**DO stream:**
- State transitions: `ingest → parse → aggregate → llm_analysis → report`
- High-severity alerts as soon as detected
- Partial findings with high confidence
- Overall progress percentage

**DON'T stream:**
- Every debug log message
- Individual flow parsing events
- Low-confidence preliminary results
- Raw TrafficLLM classification outputs

#### 3.3 WebSocket API
```python
# Backend: WebSocket endpoint
@app.websocket("/ws/jobs/{job_id}")
async def job_progress_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    async for event in job_event_stream(job_id):
        await websocket.send_json(event.dict())

# Frontend: Connection
const ws = new WebSocket(`ws://localhost:8000/ws/jobs/${jobId}`);
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.event_type === 'high_severity_alert') {
        showAlertNotification(data.payload);
    }
    updateProgressUI(data);
};
```

#### 3.4 Frontend Integration
- Real-time progress bar with stage labels
- Toast notifications for high-severity alerts during analysis
- Live-updating findings panel (partial results)
- "Analysis in progress" indicator with ETA

### Deliverables
- [x] TrafficLLM parallel execution pipeline
- [x] Rule-based vs LLM decision matrix implementation
- [x] Confidence scoring model and calculation
- [x] Confidence display in UI (badges, filters)
- [x] Confidence injection into LLM prompts
- [x] WebSocket endpoint for job progress (implemented as SSE)
- [x] Real-time progress UI components
- [x] High-severity alert notifications

---

## Technical Architecture

### Data Flow (Updated)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AIPAM Pipeline                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PCAP Upload                                                                │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────┐    ┌─────────┐    ┌───────────┐    ┌─────────────┐            │
│  │ Ingest  │───▶│  Parse  │───▶│ Aggregate │───▶│ TrafficLLM  │            │
│  └─────────┘    └─────────┘    └───────────┘    │  (parallel) │            │
│       │              │              │           └──────┬──────┘            │
│       │              │              │                  │                   │
│       │              │              ▼                  ▼                   │
│       │              │         ┌─────────┐      ┌───────────┐              │
│       │              │         │ Vector  │      │ Confidence│              │
│       │              │         │ Index   │      │  Scoring  │              │
│       │              │         └────┬────┘      └─────┬─────┘              │
│       │              │              │                 │                    │
│  [WebSocket: state_change]         │                 ▼                    │
│                                    │          ┌───────────┐               │
│                                    │          │    LLM    │               │
│                                    │          │ Analysis  │               │
│                                    │          └─────┬─────┘               │
│                                    │                │                     │
│                                    ▼                ▼                     │
│                              ┌──────────┐    ┌───────────┐                │
│                              │   RAG    │    │  Report   │                │
│                              │   Chat   │    │ Generator │                │
│                              └──────────┘    └───────────┘                │
│                                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### New Dependencies

| Component | Library | Purpose |
|-----------|---------|---------|
| Vector DB | `lancedb` + `pyarrow` | RAG embeddings storage |
| Embeddings | `sentence-transformers` | Local text embeddings |
| WebSockets | `fastapi[websockets]` | Real-time streaming |
| Async | `asyncio`, `aioredis` | Parallel TrafficLLM calls |

---

## Timeline Summary

| Phase | Duration | Priority | Effort |
|-------|----------|----------|--------|
| Phase 1: Interactive PCAP Chat | 4 weeks | High | Medium |
| Phase 2: Enhanced Analysis Pipeline | 6 weeks | High | High |

### Milestones

- **Week 2**: RAG foundation complete, basic chat working
- **Week 4**: Phase 1 complete, chat UI integrated
- **Week 6**: TrafficLLM deep integration + confidence scoring
- **Week 10**: Phase 2 complete, WebSocket streaming live

---

## Success Criteria

### Phase 1
- [x] Analyst can ask "What malware was on host X?" and get accurate, cited answer
- [x] Chat uses same anomaly-ranked data as auto-analysis
- [x] Response time < 5 seconds for typical queries
- [x] Citations link back to source evidence

### Phase 2
- [x] TrafficLLM results directly influence LLM reasoning
- [x] Confidence scores visible in UI for all findings
- [x] Real-time progress updates via WebSocket (implemented as SSE)
- [x] High-severity alerts shown within 30s of detection
