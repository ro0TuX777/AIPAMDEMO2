import type {
  TemporalCorrelationsResponse,
  TemporalDeltaResponse,
  TemporalFlowsResponse,
  TemporalNarrativeResponse,
  CorrelationResponse,
  RelatedJobsResponse,
} from "./types";
import {
  API_BASE,
  DEMO_MODE,
  qs,
  get,
  post,
  getApiToken,
} from "./transport";

export const temporalApi = {
  getTemporalDelta(jobId: string): Promise<TemporalDeltaResponse> {
    return get<TemporalDeltaResponse>(`/jobs/${jobId}/temporal-delta`);
  },

  getTemporalFlows(jobId: string): Promise<TemporalFlowsResponse> {
    return get<TemporalFlowsResponse>(`/jobs/${jobId}/temporal-flows`);
  },

  generateTemporalNarrative(jobId: string): Promise<TemporalNarrativeResponse> {
    return post<TemporalNarrativeResponse>(`/jobs/${jobId}/temporal-narrative`);
  },

  getTemporalExportUrl(jobId: string, format: "markdown" | "html" = "markdown"): string {
    const _token = getApiToken();
    if (DEMO_MODE) return "#";
    const tokenQs = _token ? `?token=${encodeURIComponent(_token)}&format=${format}` : `?format=${format}`;
    return `${API_BASE}/jobs/${jobId}/temporal-export${tokenQs}`;
  },

  getTemporalCorrelations(
    jobId: string,
    opts: { offset?: number; limit?: number; minScore?: number } = {},
  ): Promise<TemporalCorrelationsResponse> {
    const qs = new URLSearchParams();
    if (opts.offset != null) qs.set("offset", String(opts.offset));
    if (opts.limit != null) qs.set("limit", String(opts.limit));
    if (opts.minScore != null) qs.set("min_score", String(opts.minScore));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return get<TemporalCorrelationsResponse>(`/jobs/${jobId}/temporal-correlations${suffix}`);
  },

  getCorrelations(
    jobId: string,
    params?: { item_id?: string; host?: string; ioc?: string; limit?: number },
  ): Promise<CorrelationResponse> {
    const qs = new URLSearchParams();
    if (params?.item_id) qs.set("item_id", params.item_id);
    if (params?.host) qs.set("host", params.host);
    if (params?.ioc) qs.set("ioc", params.ioc);
    if (params?.limit != null) qs.set("limit", String(params.limit));
    const q = qs.toString();
    return get<CorrelationResponse>(`/jobs/${jobId}/correlations${q ? `?${q}` : ""}`);
  },

  getRelatedJobs(jobId: string): Promise<RelatedJobsResponse> {
    return get<RelatedJobsResponse>(`/jobs/${jobId}/related-jobs`);
  },
};
