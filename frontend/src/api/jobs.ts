import type {
  ExecutionProfile,
  Priority,
  JobCreateRequest,
  JobCreateResponse,
  JobGetResponse,
  JobListResponse,
  JobSummaryResponse,
  SensorListResponse,
  BatchJobsRequest,
  BatchJobsResponse,
  PartialResultsResponse,
  JobListParams,
} from "./types";
import {
  API_BASE,
  DEMO_MODE,
  qs,
  get,
  post,
  del,
  getApiToken,
} from "./transport";

export const jobsApi = {
  getExportUrl(jobId: string): string {
    const _token = getApiToken();
    if (DEMO_MODE) return "#";
    const tokenQs = _token ? `?token=${encodeURIComponent(_token)}` : "";
    return `${API_BASE}/jobs/${jobId}/export${tokenQs}`;
  },

  listJobs(p: JobListParams = {}): Promise<JobListResponse> {
    return get<JobListResponse>(`/jobs${qs(p)}`);
  },

  createJob(body: JobCreateRequest): Promise<JobCreateResponse> {
    return post<JobCreateResponse>("/jobs", body);
  },

  getJobDetail(jobId: string): Promise<JobGetResponse> {
    return get<JobGetResponse>(`/jobs/${jobId}`);
  },

  deleteJob(jobId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}`);
  },

  cancelJob(jobId: string): Promise<void> {
    return post<void>(`/jobs/${jobId}/cancel`);
  },

  rerunJob(jobId: string, body: { execution_profile: ExecutionProfile; priority?: Priority }): Promise<JobCreateResponse> {
    return post<JobCreateResponse>(`/jobs/${jobId}/rerun`, body);
  },

  batchJobs(body: BatchJobsRequest): Promise<BatchJobsResponse> {
    return post<BatchJobsResponse>("/jobs/batch", body);
  },

  getJobSummary(jobId: string): Promise<JobSummaryResponse> {
    return get<JobSummaryResponse>(`/jobs/${jobId}/summary`);
  },

  getJobSensors(jobId: string): Promise<SensorListResponse> {
    return get<SensorListResponse>(`/jobs/${jobId}/sensors`);
  },

  getPartialResults(jobId: string): Promise<PartialResultsResponse> {
    return get<PartialResultsResponse>(`/jobs/${jobId}/partial-results`);
  },

  /** Create an EventSource for job progress. Caller is responsible for closing it. */
  createJobEventSource(jobId: string, lastEventId?: string): EventSource {
    const _token = getApiToken();
    // EventSource does not support custom headers, so pass the token as a
    // query parameter. The backend's verify_token_or_query accepts both.
    const tokenQs = _token ? `?token=${encodeURIComponent(_token)}` : "";
    const url = `${API_BASE}/jobs/${jobId}/events${tokenQs}`;
    const es = new EventSource(url);
    return es;
  },

  addJobPcap(jobId: string, body: { upload_id: string; label: string }): Promise<void> {
    return post<void>(`/jobs/${jobId}/pcaps`, body);
  },

  reanalyzeJob(jobId: string, pcapLabel: string): Promise<{ job_id: string; pcap_label: string; status: string }> {
    return post<{ job_id: string; pcap_label: string; status: string }>(`/jobs/${jobId}/reanalyze`, { pcap_label: pcapLabel });
  },
};
