import type {
  AlertListResponse,
  AlertDetailResponse,
  FindingItem,
  FindingExplainFeedback,
  FindingDetailResponse,
  FindingListResponse,
  FindingExplainRequest,
  FindingExplainResponse,
  FindingExplainFeedbackResponse,
  IocListResponse,
  TheoryListResponse,
  TheoryExplainResponse,
  SliceListResponse,
  SliceDetailResponse,
  ContextAnnotationListResponse,
  TimelineListResponse,
  AlertListParams,
  FindingListParams,
  TimelineListParams,
  IocListParams,
  AnalystStatus,
  QueueItemSource,
  EvidenceBundleResponse,
  InvestigationQueueResponse,
  StatusUpdateRequest,
  StatusUpdateResponse,
  BulkStatusUpdateRequest,
  BulkStatusUpdateResponse,
  ReviewQueueResponse,
} from "./types";
import {
  qs,
  get,
  post,
  patch,
} from "./transport";

export const investigationApi = {
  updateFindingFeedback(jobId: string, finding_id: string, feedback: string | null) {
    return patch<FindingItem>(`/jobs/${jobId}/findings/${finding_id}/feedback`, { feedback });
  },

  updateFindingExplainFeedback(jobId: string, finding_id: string, explanation_feedback: FindingExplainFeedback | null) {
    return patch<FindingExplainFeedbackResponse>(
      `/jobs/${jobId}/findings/${finding_id}/explain/feedback`,
      { explanation_feedback },
    );
  },

  listAlerts(jobId: string, p: AlertListParams = {}): Promise<AlertListResponse> {
    return get<AlertListResponse>(`/jobs/${jobId}/alerts${qs(p)}`);
  },

  getAlert(jobId: string, alertId: string): Promise<AlertDetailResponse> {
    return get<AlertDetailResponse>(`/jobs/${jobId}/alerts/${alertId}`);
  },

  listFindings(jobId: string, p: FindingListParams = {}): Promise<FindingListResponse> {
    return get<FindingListResponse>(`/jobs/${jobId}/findings${qs(p)}`);
  },

  getFinding(jobId: string, findingId: string): Promise<FindingDetailResponse> {
    return get<FindingDetailResponse>(`/jobs/${jobId}/findings/${findingId}`);
  },

  explainFinding(jobId: string, findingId: string, body: FindingExplainRequest): Promise<FindingExplainResponse> {
    return post<FindingExplainResponse>(`/jobs/${jobId}/findings/${findingId}/explain`, body);
  },

  listJobTheories(jobId: string, p: { pcap_label?: string } = {}): Promise<TheoryListResponse> {
    return get<TheoryListResponse>(`/jobs/${jobId}/theories${qs(p)}`);
  },

  listHostTheories(jobId: string, ip: string): Promise<TheoryListResponse> {
    return get<TheoryListResponse>(`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}/theories`);
  },

  generateTheories(jobId: string): Promise<TheoryListResponse> {
    return post<TheoryListResponse>(`/jobs/${jobId}/theories/generate`);
  },

  explainTheory(jobId: string, theoryId: string): Promise<TheoryExplainResponse> {
    return post<TheoryExplainResponse>(`/jobs/${jobId}/theories/${encodeURIComponent(theoryId)}/explain`, { format: "markdown" });
  },

  listSlices(jobId: string, p: { pcap_label?: string } = {}): Promise<SliceListResponse> {
    return get<SliceListResponse>(`/jobs/${jobId}/slices${qs(p)}`);
  },

  getSlice(jobId: string, sliceId: string): Promise<SliceDetailResponse> {
    return get<SliceDetailResponse>(`/jobs/${jobId}/slices/${encodeURIComponent(sliceId)}`);
  },

  generateSlices(jobId: string): Promise<SliceListResponse> {
    return post<SliceListResponse>(`/jobs/${jobId}/slices/generate`);
  },

  listAnnotations(jobId: string, hostIp?: string, pcapLabel?: string): Promise<ContextAnnotationListResponse> {
    const p: Record<string, string> = {};
    if (hostIp) p.host_ip = hostIp;
    if (pcapLabel) p.pcap_label = pcapLabel;
    return get<ContextAnnotationListResponse>(`/jobs/${jobId}/annotations${qs(p)}`);
  },

  generateAnnotations(jobId: string): Promise<ContextAnnotationListResponse> {
    return post<ContextAnnotationListResponse>(`/jobs/${jobId}/annotations/generate`);
  },

  listTimeline(jobId: string, p: TimelineListParams = {}): Promise<TimelineListResponse> {
    return get<TimelineListResponse>(`/jobs/${jobId}/timeline${qs(p)}`);
  },

  listIocs(jobId: string, p: IocListParams = {}): Promise<IocListResponse> {
    return get<IocListResponse>(`/jobs/${jobId}/iocs${qs(p)}`);
  },

  getInvestigationQueue(jobId: string, params?: {
    status?: AnalystStatus; source?: QueueItemSource; severity?: string;
    q?: string; offset?: number; limit?: number;
    host?: string; mitre_id?: string; has_corroboration?: boolean; reviewed?: boolean;
  }): Promise<InvestigationQueueResponse> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.source) qs.set("source", params.source);
    if (params?.severity) qs.set("severity", params.severity);
    if (params?.q) qs.set("q", params.q);
    if (params?.offset != null) qs.set("offset", String(params.offset));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    if (params?.host) qs.set("host", params.host);
    if (params?.mitre_id) qs.set("mitre_id", params.mitre_id);
    if (params?.has_corroboration != null) qs.set("has_corroboration", String(params.has_corroboration));
    if (params?.reviewed != null) qs.set("reviewed", String(params.reviewed));
    const q = qs.toString();
    return get<InvestigationQueueResponse>(`/jobs/${jobId}/investigation-queue${q ? `?${q}` : ""}`);
  },

  getEvidenceBundle(jobId: string, itemId: string): Promise<EvidenceBundleResponse> {
    return get<EvidenceBundleResponse>(`/jobs/${jobId}/investigation-queue/${encodeURIComponent(itemId)}/evidence-bundle`);
  },

  updateQueueItemStatus(jobId: string, itemId: string, body: StatusUpdateRequest): Promise<StatusUpdateResponse> {
    return patch<StatusUpdateResponse>(`/jobs/${jobId}/investigation-queue/${encodeURIComponent(itemId)}/status`, body);
  },

  bulkUpdateQueueStatus(jobId: string, body: BulkStatusUpdateRequest): Promise<BulkStatusUpdateResponse> {
    return post<BulkStatusUpdateResponse>(`/jobs/${jobId}/investigation-queue/bulk-status`, body);
  },

  getReviewQueue(jobId: string, params?: {
    status?: AnalystStatus; reviewer?: string; since?: string;
    offset?: number; limit?: number;
  }): Promise<ReviewQueueResponse> {
    const qs = new URLSearchParams();
    if (params?.status) qs.set("status", params.status);
    if (params?.reviewer) qs.set("reviewer", params.reviewer);
    if (params?.since) qs.set("since", params.since);
    if (params?.offset != null) qs.set("offset", String(params.offset));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    const q = qs.toString();
    return get<ReviewQueueResponse>(`/jobs/${jobId}/review-queue${q ? `?${q}` : ""}`);
  },
};
