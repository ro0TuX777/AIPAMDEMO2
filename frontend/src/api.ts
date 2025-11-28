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

export interface JobResultResponse {
    job_id: string;
    status: string;
    summary: {
        severity: string;
        key_findings: any[];
        mitre_techniques: any[];
    };
    hosts: any[];
    raw: any;
    report_urls: Record<string, string>;
}

export interface SettingsPayload {
    llm_endpoint?: string | null;
    llm_model_name?: string | null;
    llm_max_tokens?: number | null;
    llm_temperature?: number | null;
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
}

export interface EffectiveSettingsResponse {
    llm_endpoint: string;
    llm_model_name: string;
    llm_max_tokens: number;
    llm_temperature: number;

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

    async getSettings(): Promise<SettingsPayload> {
        const res = await fetch(`${API_BASE}/settings`);
        if (!res.ok) throw new Error("Failed to fetch settings");
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
};
