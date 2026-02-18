# AIPAM — Data Models & Database Structure

> Complete reference for all database tables, domain models, and their relationships.

---

## Database Engine

| Aspect | Detail |
|--------|--------|
| Engine | SQLite |
| ORM | SQLModel (SQLAlchemy + Pydantic) |
| File | `/data/aipam.db` (Docker) or `backend/aipam.db` (local) |
| Schema Init | Auto-created via `SQLModel.metadata.create_all()` on startup |

---

## Entity-Relationship Diagram

```mermaid
erDiagram
    JobDB ||--o{ JobStepDB : "has steps"
    JobDB ||--o| JobResultDB : "has result"
    JobDB ||--o{ ConversationDB : "has conversations"
    JobDB ||--o{ FindingDB : "has findings"
    JobDB ||--o{ FlowDB : "has flows"
    JobDB ||--o{ AlertDB : "has alerts"
    JobDB ||--o{ PipelineCheckpointDB : "has checkpoints"
    ConversationDB ||--o{ ChatMessageDB : "has messages"
    FindingDB ||--o{ EvidenceDB : "linked evidence"
    FlowDB ||--o{ EvidenceDB : "supports findings"
    AlertDB }o--o| FlowDB : "correlates to"

    JobDB {
        string id PK
        string source
        string mode
        string exercise_id
        datetime created_at
        datetime updated_at
        enum status
        json job_metadata
        string error_message
    }

    JobStepDB {
        string id PK
        string job_id FK
        string name
        enum status
        string message
        datetime started_at
        datetime finished_at
    }

    JobResultDB {
        string job_id PK_FK
        json result
    }

    FindingDB {
        string id PK
        string job_id FK
        string mitre_technique_id
        string mitre_technique_name
        string classification
        string severity
        string title
        string description
        json evidence
        json affected_hosts
        float confidence
        string analyzer_source
        string attack_chain_stage
        string analyst_status
        string analyst_notes
        datetime created_at
    }

    FlowDB {
        string id PK
        string job_id FK
        string src_ip
        int src_port
        string dst_ip
        int dst_port
        string transport_proto
        string app_proto
        datetime start_time
        datetime end_time
        float duration_sec
        int bytes_from_src
        int bytes_from_dst
        json extra
    }

    AlertDB {
        string id PK
        string job_id FK
        datetime timestamp
        string alert_source
        string signature_id
        string signature_name
        string severity
        string flow_id
        json extra
    }

    EvidenceDB {
        string id PK
        string finding_id FK
        string flow_id FK
        string relationship
        string snippet
    }

    ConversationDB {
        string id PK
        string job_id FK
        datetime created_at
        datetime updated_at
        string title
    }

    ChatMessageDB {
        string id PK
        string conversation_id FK
        string role
        string content
        json citations
        datetime created_at
    }

    PipelineCheckpointDB {
        string id PK
        string job_id FK
        string step_name
        json state_data
        datetime completed_at
    }

    SettingsDB {
        int id PK
        json values
    }
```

---

## Table Reference

### `JobDB` — Analysis Jobs
The root entity for every analysis. Each PCAP upload or connector query creates one job.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `str` PK | UUID, generated at creation |
| `source` | `str` | `"upload"`, `"security_onion"`, or `"arkime"` |
| `mode` | `str` | `"baseline_vs_exploit"` or `"single_window"` |
| `exercise_id` | `str?` | Exercise/scenario identifier |
| `status` | `JobStatus` | `queued` → `running` → `completed` / `failed` |
| `job_metadata` | `JSON` | Arbitrary metadata (connector params, file names) |
| `error_message` | `str?` | Error detail when `status = failed` |
| `created_at` / `updated_at` | `datetime` | Timestamps |

---

### `JobStepDB` — Pipeline Step Tracking
One row per pipeline step per job. Enables fine-grained progress tracking.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `str` PK | UUID |
| `job_id` | `str` FK | Parent job |
| `name` | `str` | `"ingest"`, `"extract"`, `"analyze"`, `"report"` |
| `status` | `JobStepStatus` | `pending` → `running` → `completed` / `failed` |
| `message` | `str?` | Status message or error detail |
| `started_at` / `finished_at` | `datetime?` | Timing |

---

### `JobResultDB` — Final Analysis Results
One row per completed job. Stores the entire `JobResult` as a JSON blob.

| Column | Type | Description |
|--------|------|-------------|
| `job_id` | `str` PK/FK | Parent job |
| `result` | `JSON` | Serialized `JobResult` (summary, hosts, raw data, report URLs) |

---

### `FindingDB` — Forensic Findings
One row per discrete forensic observation. Enables cross-job analytics.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `str` PK | UUID |
| `job_id` | `str` FK | Parent job |
| `mitre_technique_id` | `str?` | ATT&CK technique (e.g. `"T1071.001"`) |
| `mitre_technique_name` | `str?` | Human-readable technique name |
| `classification` | `str?` | Malware family (e.g. `"IcedID"`) |
| `severity` | `str` | `critical` / `high` / `medium` / `low` / `info` |
| `title` | `str` | Short finding title |
| `description` | `str` | Detailed description |
| `evidence` | `JSON` | Supporting evidence strings |
| `affected_hosts` | `JSON` | IP addresses involved |
| `confidence` | `float` | Score 0.0–1.0 |
| `analyzer_source` | `str` | `"ollama"`, `"trafficllm"`, `"heuristic"` |
| `attack_chain_stage` | `str?` | Kill-chain phase |
| `analyst_status` | `str` | `"unverified"` / `"confirmed"` / `"false_positive"` |
| `analyst_notes` | `str?` | Analyst notes |

---

### `FlowDB` — Network Flows
One row per normalized network flow from Zeek `conn.log`.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `str` PK | `{job_id}:{zeek_uid}` composite key |
| `job_id` | `str` FK | Parent job |
| `src_ip` / `dst_ip` | `str` | Source/destination IP (indexed) |
| `src_port` / `dst_port` | `int` | Ports |
| `transport_proto` | `str` | `TCP` / `UDP` / `ICMP` |
| `app_proto` | `str` | `HTTP` / `TLS` / `DNS` / `SSH` / `SMB` / `UNKNOWN` |
| `start_time` / `end_time` | `datetime` | Flow timing |
| `duration_sec` | `float` | Duration in seconds |
| `bytes_from_src` / `bytes_from_dst` | `int` | Byte counts |
| `packets_from_src` / `packets_from_dst` | `int` | Packet counts |
| `tcp_flags_summary` | `str?` | TCP flags (e.g. `"SYN,ACK"`) |
| `state` | `str?` | Zeek conn_state (`SF`, `S0`, `REJ`, etc.) |
| `extra` | `JSON` | Extensible metadata |

---

### `AlertDB` — IDS/IPS Alerts
One row per alert from Suricata EVE or TrafficLLM.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `str` PK | `{job_id}:{alert_id}` |
| `job_id` | `str` FK | Parent job |
| `timestamp` | `datetime` | Alert timestamp |
| `src_ip` / `dst_ip` | `str?` | Source/destination (indexed) |
| `alert_source` | `str` | `"SURICATA"` / `"TRAFFICLLM"` |
| `signature_id` | `str?` | Signature/rule ID (indexed) |
| `signature_name` | `str` | Human-readable rule name |
| `severity` | `str` | Severity level (indexed) |
| `category` | `str?` | Alert category |
| `flow_id` | `str?` | Correlating FlowDB ID |
| `extra` | `JSON` | Additional alert data |

---

### `EvidenceDB` — Finding↔Flow Links
Many-to-many mapping between findings and the flows that prove them.

| Column | Type | Description |
|--------|------|-------------|
| `id` | `str` PK | UUID |
| `finding_id` | `str` FK | `FindingDB.id` |
| `flow_id` | `str` FK | `FlowDB.id` |
| `relationship` | `str` | `"supports"` / `"contradicts"` / `"context"` |
| `snippet` | `str?` | Raw evidence excerpt for analyst review |

---

### `ConversationDB` / `ChatMessageDB` — Interactive Chat
Conversations and messages for the RAG-powered chat feature.

### `PipelineCheckpointDB` — Retry State
Checkpoint ID format: `{job_id}:{step_name}`. State stored as JSON blob.

### `SettingsDB` — Application Settings
Singleton table (1 row, `id = 1`). All settings stored in a single JSON `values` column.

---

## Domain Models (`models.py`)

### Network Data Models

| Model | Purpose |
|-------|---------|
| `FlowRecord` | Parsed network flow (Pydantic, in-memory) |
| `EventRecord` | Generic network event |
| `AlertRecord` | Parsed IDS alert |
| `HostSummary` | Per-host aggregated metrics |
| `HostPairSummary` | Communication pattern between two IPs |
| `ChangeSummary` | Baseline vs exploit diff per entity |

### LLM Output Models

| Model | Purpose |
|-------|---------|
| `LLMOutput` | Complete LLM analysis response (attack chain, findings, anomalies) |
| `AttackChainItem` | One stage in the kill chain |
| `HostFindingLLM` | Per-host finding from LLM |
| `Anomaly` | LLM-detected anomaly |
| `MitreTechnique` | ATT&CK technique reference |
| `LLMInputBundle` | Full input payload sent to the LLM |

### Job Models

| Model | Purpose |
|-------|---------|
| `JobResult` | Final analysis result (summary + hosts + raw + report URLs) |
| `AnalysisSummary` | High-level summary (classification, severity, key findings) |
| `HostFinding` | Per-host finding summary |
| `TrafficLLMResult` | TrafficLLM classification aggregation |
| `AnomalyReportModel` | Heuristic anomaly detector output |

---

## Core Domain Models (`domain/`)

| Model | File | Purpose |
|-------|------|---------|
| `Finding` | `domain/finding.py` | Atomic forensic observation with MITRE mapping |
| `FindingSeverity` | `domain/finding.py` | Enum: critical/high/medium/low/info |
| `AnalysisContext` | `core/interfaces.py` | Input contract for analyzers |
| `ExportedRule` | `core/exporters.py` | Generated Suricata/Sigma rule |
| `CorrelationGroup` | `core/correlation.py` | Cross-job correlation cluster |
