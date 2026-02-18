export interface JobStep {
    name: string;
    status: "pending" | "running" | "completed" | "failed";
    message?: string;
}

export interface JobStatusResponse {
    job_id: string;
    status: "queued" | "running" | "failed" | "completed";
    created_at: string;
    updated_at: string;
    steps: JobStep[];
    error_message?: string;
}

export interface CreateJobResponse {
    job_id: string;
    status: string;
}

export interface AnomalyFinding {
    category: string;
    severity: string;
    description: string;
    evidence: string[];
    affected_hosts: string[];
    confidence: number;
    chain_of_thought: string;
}

export interface AnomalyReport {
    findings: AnomalyFinding[];
    overall_anomaly_score: number;
    zero_day_likelihood: string;
    summary: string;
}

export interface JobResultRaw {
    alerts?: any[];
    llm_analysis_raw?: {
        chunks?: any[];
        summary?: any;
    };
    anomaly_detection?: AnomalyReport | null;
}

export interface JobResultResponse {
    job_id: string;
    status: string;
    summary: {
        classification?: string;
        severity: string;
        key_findings: any[];
        mitre_techniques: any[];
    };
    hosts: any[];
    raw: JobResultRaw;
    report_urls: Record<string, string>;
}

export interface SettingsPayload {
    llm_endpoint?: string | null;
    llm_model_name?: string | null;
    llm_max_tokens?: number | null;
    llm_temperature?: number | null;
    forensic_model_name?: string | null;
    general_model_name?: string | null;
    security_onion_mode?: string | null;
    security_onion_base_pcap_path?: string | null;
    security_onion_zeek_log_path?: string | null;
    security_onion_suricata_log_path?: string | null;
    security_onion_api_url?: string | null;
    security_onion_api_token?: string | null;
    arkime_api_url?: string | null;
    arkime_api_username?: string | null;
    arkime_api_password?: string | null;
    file_storage_path?: string | null;
    // Fine-tuning configuration
    finetune_base_model?: string | null;
    finetune_dataset_url?: string | null;
    finetune_lora_rank?: number | null;
    finetune_learning_rate?: number | null;
    finetune_max_seq_length?: number | null;
    dataset_storage_path?: string | null;
    finetuning_backend?: string | null;
    model_configured?: boolean | null;
}

export interface SetupStatusResponse {
    model_configured: boolean;
    llm_model_name: string | null;
}

export interface OllamaModelInfo {
    name: string;
    size: number;
    family: string;
    parameter_size: string;
    quantization: string;
}

export interface EffectiveSettingsResponse {
    llm_endpoint: string;
    llm_model_name: string;
    llm_max_tokens: number;
    llm_temperature: number;
    forensic_model_name?: string | null;
    general_model_name?: string | null;

    file_storage_path: string;
    reports_path: string;

    security_onion_mode: string;
    security_onion_base_pcap_path: string;
    security_onion_zeek_log_path: string;
    security_onion_suricata_log_path: string;
    security_onion_api_url?: string | null;
    security_onion_api_token?: string | null;

    arkime_api_url?: string | null;
    arkime_api_username?: string | null;
    arkime_api_password?: string | null;
}

// Chat API types
export interface ChatCitation {
    type: string;
    id?: string;
    snippet: string;
}

export interface ChatRequest {
    message: string;
    conversation_id?: string;
    context_hint?: string;
}

export interface ChatResponse {
    response: string;
    citations: ChatCitation[];
    conversation_id: string;
    confidence?: number;
}

export interface ChatMessage {
    role: string;
    content: string;
    citations: ChatCitation[];
    timestamp?: string;
}

export interface ConversationSummary {
    id: string;
    job_id: string;
    created_at: string;
    updated_at: string;
    title?: string;
    message_count: number;
}

export interface ConversationHistory {
    id: string;
    job_id: string;
    messages: ChatMessage[];
    created_at: string;
    updated_at: string;
}

export interface PartialResultResponse {
    flow_count: number;
    alert_count: number;
    top_alerts: any[];
    host_summaries: any[];
    anomaly_detection: AnomalyReport | null;
    trafficllm: any | null;
}


const API_BASE = (import.meta as any).env.VITE_API_BASE_URL?.replace(/\/$/, "") || "http://localhost:8000/api/v1";

export const api = {
    async getJobs(): Promise<JobStatusResponse[]> {
        const res = await fetch(`${API_BASE}/jobs`);
        if (!res.ok) throw new Error("Failed to fetch jobs");
        return res.json();
    },

    async getJob(jobId: string): Promise<JobStatusResponse> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}`);
        if (!res.ok) throw new Error("Failed to fetch job");
        return res.json();
    },

    async createJobUpload(
        files: FileList,
        mode: string,
        metadata: any
    ): Promise<CreateJobResponse> {
        const formData = new FormData();
        formData.append("mode", mode);
        formData.append("metadata", JSON.stringify(metadata));
        for (let i = 0; i < files.length; i++) {
            formData.append("pcap_files", files[i]);
        }

        const res = await fetch(`${API_BASE}/jobs`, {
            method: "POST",
            body: formData,
        });
        if (!res.ok) throw new Error("Failed to create job");
        return res.json();
    },

    async createJobFromSecurityOnion(payload: {
        source: string;
        time_range: { start: string; end: string };
        sensors: string[];
        mode: string;
        metadata: Record<string, any>;
    }): Promise<CreateJobResponse> {
        const res = await fetch(`${API_BASE}/jobs/from_security_onion`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error("Failed to create Security Onion job");
        return res.json();
    },

    async createJobFromArkime(payload: {
        source: string;
        filter: string;
        time_range: { start: string; end: string };
        mode: string;
        metadata: Record<string, any>;
    }): Promise<CreateJobResponse> {
        const res = await fetch(`${API_BASE}/jobs/from_arkime`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error("Failed to create Arkime job");
        return res.json();
    },


    async getJobResult(jobId: string): Promise<JobResultResponse> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/result`);
        if (!res.ok) throw new Error("Failed to fetch job result");
        return res.json();
    },

    async getPartialResult(jobId: string): Promise<PartialResultResponse | null> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/partial_result`);
        if (res.status === 404) return null;
        if (!res.ok) throw new Error("Failed to fetch partial result");
        return res.json();
    },

    async getSettings(): Promise<SettingsPayload> {
        const res = await fetch(`${API_BASE}/settings`);
        if (!res.ok) throw new Error("Failed to fetch settings");
        return res.json();
    },

    async getAvailableModels(): Promise<OllamaModelInfo[]> {
        const res = await fetch(`${API_BASE}/models/available`);
        if (!res.ok) return [];
        const data = await res.json();
        return data.models ?? [];
    },

    async getSetupStatus(): Promise<SetupStatusResponse> {
        const res = await fetch(`${API_BASE}/settings/setup_status`);
        if (!res.ok) return { model_configured: false, llm_model_name: null };
        return res.json();
    },

    async updateSettings(payload: SettingsPayload): Promise<SettingsPayload> {
        const res = await fetch(`${API_BASE}/settings`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error("Failed to update settings");
        return res.json();
    },

    async testLlmConnection(payload: SettingsPayload): Promise<{ ok: boolean; error?: string }> {
        const res = await fetch(`${API_BASE}/settings/test_llm`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error("Failed to test LLM connection");
        return res.json();
    },

    async getEffectiveSettings(): Promise<EffectiveSettingsResponse> {
        const res = await fetch(`${API_BASE}/admin/effective_settings`);
        if (!res.ok) throw new Error("Failed to fetch effective settings");
        return res.json();
    },

    async chatWithJob(jobId: string, request: ChatRequest): Promise<ChatResponse> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request),
        });
        if (!res.ok) throw new Error("Failed to send chat message");
        return res.json();
    },

    async getJobConversations(jobId: string): Promise<ConversationSummary[]> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/conversations`);
        if (!res.ok) throw new Error("Failed to fetch conversations");
        return res.json();
    },

    async getConversationHistory(jobId: string, conversationId: string): Promise<ConversationHistory> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/conversations/${conversationId}`);
        if (!res.ok) throw new Error("Failed to fetch conversation history");
        return res.json();
    },

    async deleteJob(jobId: string): Promise<void> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}`, {
            method: "DELETE",
        });
        if (!res.ok) {
            const error = await res.json().catch(() => ({ detail: "Failed to delete job" }));
            throw new Error(error.detail || "Failed to delete job");
        }
    },

    async generateSimulation(jobId: string): Promise<{ status: string; script: string; filename: string; simulations: number }> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/simulation`, {
            method: "POST",
        });
        if (!res.ok) {
            const error = await res.json().catch(() => ({ detail: "Failed to generate simulation" }));
            throw new Error(error.detail || "Failed to generate simulation");
        }
        return res.json();
    },

    // -- Training Intelligence (Phase 6 Dashboard) --

    async getTrainingLedger(): Promise<TrainingLedgerResponse> {
        const res = await fetch(`${API_BASE}/training/ledger`);
        if (!res.ok) throw new Error("Failed to fetch training ledger");
        return res.json();
    },

    async getTrainingSummary(): Promise<TrainingSummary> {
        const res = await fetch(`${API_BASE}/training/summary`);
        if (!res.ok) throw new Error("Failed to fetch training summary");
        return res.json();
    },

    async getTrainingConfig(): Promise<TrainingConfig> {
        const res = await fetch(`${API_BASE}/training/config`);
        if (!res.ok) throw new Error("Failed to fetch training config");
        return res.json();
    },

    async getTrainingStatus(): Promise<TrainingStatus> {
        const res = await fetch(`${API_BASE}/training/status`);
        if (!res.ok) throw new Error("Failed to fetch training status");
        return res.json();
    },

    async startTrainingJob(): Promise<{ status: string; task_id: string; message: string }> {
        const res = await fetch(`${API_BASE}/training/jobs`, {
            method: "POST",
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            throw new Error(body.message || `Failed to start training job (${res.status})`);
        }
        return res.json();
    },

    async validateStoragePath(path: string): Promise<{ valid: boolean; message: string; exists?: boolean; writable?: boolean }> {
        const res = await fetch(`${API_BASE}/training/validate_path`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ path }),
        });
        if (!res.ok) throw new Error("Failed to validate path");
        return res.json();
    },

    async stopTraining(): Promise<{ status: string; job_id?: string; error?: string }> {
        const res = await fetch(`${API_BASE}/training/stop`, { method: "POST" });
        return res.json();
    },

    async pauseTraining(): Promise<{ status: string; job_id?: string; error?: string }> {
        const res = await fetch(`${API_BASE}/training/pause`, { method: "POST" });
        return res.json();
    },
};

export interface TrainingConfig {
    base_model: string | null;
    dataset_url: string | null;
    lora_rank: number | null;
    learning_rate: number | null;
    max_seq_length: number | null;
    configured: boolean;
}

export interface TrainingStatus {
    trainer_online: boolean;
    job_id: string | null;
    status: string;
    current_iter: number;
    total_iters: number;
    percent: number;
    last_loss: number;
    it_per_sec: number;
    elapsed_seconds: number | null;
    eta_seconds: number | null;
}

// -- Training Intelligence Types --

export interface TrainingLedgerEntry {
    timestamp: string;
    event_type: string;
    phase_label: string;
    status: string;
    config_hash?: string;
    random_seed?: number;
    base_model?: string;
    dataset_path?: string;
    dataset_samples?: number;
    lora_r?: number;
    lora_alpha?: number;
    epochs?: number;
    learning_rate?: number;
    batch_size?: number;
    max_seq_length?: number;
    trainer_type?: string;
    beta?: number;
    metrics?: Record<string, any>;
}

export interface TrainingLedgerResponse {
    entries: TrainingLedgerEntry[];
    total: number;
    ledger_path: string;
    ledger_exists: boolean;
}

export interface PhaseStats {
    total_events: number;
    completed: number;
    failed: number;
    latest_timestamp: string | null;
    latest_loss: number | null;
}

export interface ActiveModel {
    name: string;
    phase: string;
    config_hash?: string;
    context_window?: number;
    lora_r?: number;
    lora_alpha?: number;
    trained_at?: string;
    loss?: number;
    dawn_seed?: number;
}

export interface SelfHealingStats {
    runs: number;
    total_synthetic_pcaps: number;
    families_augmented: string[];
    latest_timestamp: string | null;
}

export interface TrainingSummary {
    has_data: boolean;
    latest_run: TrainingLedgerEntry | null;
    active_model: ActiveModel | null;
    phase_counts: Record<string, PhaseStats>;
    models: string[];
    peak_vram_gb: number | null;
    self_healing: SelfHealingStats | null;
    total_events: number;
}
