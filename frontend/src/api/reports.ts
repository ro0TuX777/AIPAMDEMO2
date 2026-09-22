import type {
  JobGraphResponse,
  EvidenceGraphResponse,
  StorylineResponse,
  FileListResponse,
  ReportListResponse,
  ReportDetailResponse,
  ProofMode,
  ProofListResponse,
  ProofDetailResponse,
  ProofItemListResponse,
  ProofItemDetailResponse,
  ProofNarrativeResponse,
  ProofExportResponse,
  ArtifactListResponse,
  EvidencePackageCreateResponse,
} from "./types";
import {
  API_BASE,
  DEMO_MODE,
  qs,
  authHeaders,
  get,
  post,
  del,
  patch,
} from "./transport";

export const reportsApi = {
  listReports(jobId: string): Promise<ReportListResponse> {
    return get<ReportListResponse>(`/jobs/${jobId}/reports`);
  },

  getReport(jobId: string, reportId: string): Promise<ReportDetailResponse> {
    return get<ReportDetailResponse>(`/jobs/${jobId}/reports/${reportId}`);
  },

  generateReport(jobId: string, mode: "executive" | "analyst" = "analyst", pcapLabel?: string): Promise<ReportDetailResponse> {
    const body: Record<string, string> = { mode };
    if (pcapLabel) body.pcap_label = pcapLabel;
    return post<ReportDetailResponse>(`/jobs/${jobId}/reports/generate`, body);
  },

  listProofs(jobId: string): Promise<ProofListResponse> {
    return get<ProofListResponse>(`/jobs/${jobId}/proofs`);
  },

  getProof(jobId: string, proofId: string): Promise<ProofDetailResponse> {
    return get<ProofDetailResponse>(`/jobs/${jobId}/proofs/${proofId}`);
  },

  createProof(jobId: string, body: { title: string; conclusion?: string; severity?: string; confidence?: number; mode?: ProofMode }): Promise<ProofDetailResponse> {
    return post<ProofDetailResponse>(`/jobs/${jobId}/proofs`, body);
  },

  updateProof(jobId: string, proofId: string, body: Record<string, unknown>): Promise<ProofDetailResponse> {
    return patch<ProofDetailResponse>(`/jobs/${jobId}/proofs/${proofId}`, body);
  },

  deleteProof(jobId: string, proofId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/proofs/${proofId}`);
  },

  listProofItems(jobId: string, proofId: string): Promise<ProofItemListResponse> {
    return get<ProofItemListResponse>(`/jobs/${jobId}/proofs/${proofId}/items`);
  },

  addProofItem(jobId: string, proofId: string, body: { entity_type: string; entity_id: string; role?: string; analyst_note?: string }): Promise<ProofItemDetailResponse> {
    return post<ProofItemDetailResponse>(`/jobs/${jobId}/proofs/${proofId}/items`, body);
  },

  removeProofItem(jobId: string, proofId: string, itemId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/proofs/${proofId}/items/${itemId}`);
  },

  renderProofNarrative(jobId: string, proofId: string): Promise<ProofNarrativeResponse> {
    return post<ProofNarrativeResponse>(`/jobs/${jobId}/proofs/${proofId}/narrative`, {});
  },

  exportProof(jobId: string, proofId: string, fmt: "markdown" | "html" = "markdown"): Promise<ProofExportResponse> {
    return get<ProofExportResponse>(`/jobs/${jobId}/proofs/${proofId}/export?fmt=${fmt}`);
  },

  listArtifacts(jobId: string): Promise<ArtifactListResponse> {
    return get<ArtifactListResponse>(`/jobs/${jobId}/artifacts`);
  },

  listFiles(jobId: string, params: { cursor?: string; limit?: number }): Promise<FileListResponse> {
    return get<FileListResponse>(`/jobs/${jobId}/files${qs(params)}`);
  },

  getJobGraph(jobId: string): Promise<JobGraphResponse> {
    return get<JobGraphResponse>(`/jobs/${jobId}/graph`);
  },

  getEvidenceGraph(jobId: string, include?: string[]): Promise<EvidenceGraphResponse> {
    const params = include?.length ? `?include=${include.join(",")}` : "";
    return get<EvidenceGraphResponse>(`/jobs/${jobId}/evidence-graph${params}`);
  },

  getStoryline(jobId: string): Promise<StorylineResponse> {
    return get<StorylineResponse>(`/jobs/${jobId}/storyline`);
  },

  generateEvidencePackage(jobId: string): Promise<EvidencePackageCreateResponse> {
    return post<EvidencePackageCreateResponse>(`/jobs/${jobId}/artifacts/evidence-package`);
  },

  getArtifactDownloadUrl(artifactId: string): string {
    if (DEMO_MODE) return "#";
    return `${API_BASE}/artifacts/${artifactId}/download`;
  },

  async downloadArtifact(artifactId: string, filename?: string): Promise<void> {
    if (DEMO_MODE) return;
    const res = await fetch(`${API_BASE}/artifacts/${artifactId}/download`, {
      headers: authHeaders(),
    });
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || `artifact-${artifactId}.zip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  async downloadExtractedFile(jobId: string, fileId: string, filename?: string): Promise<void> {
    if (DEMO_MODE) return;
    const res = await fetch(`${API_BASE}/jobs/${jobId}/files/${encodeURIComponent(fileId)}/download`, {
      headers: authHeaders(),
    });
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || fileId;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
