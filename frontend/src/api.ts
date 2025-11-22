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

const API_BASE = "http://localhost:8000/api/v1";

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

    async getJobResult(jobId: string): Promise<JobResultResponse> {
        const res = await fetch(`${API_BASE}/jobs/${jobId}/result`);
        if (!res.ok) throw new Error("Failed to fetch job result");
        return res.json();
    },
};
