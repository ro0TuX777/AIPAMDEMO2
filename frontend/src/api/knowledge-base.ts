import type {
  KBDocumentCreate,
  KBDocumentOut,
  KBDocumentDetail,
  KBDocumentListOut,
  KBSearchResponse,
} from "./types";
import {
  API_BASE,
  qs,
  request,
  get,
  post,
  del,
} from "./transport";

export const knowledgeBaseApi = {
  listKBDocuments(jobId: string, docType?: string): Promise<KBDocumentListOut> {
    const qs = docType ? `?doc_type=${encodeURIComponent(docType)}` : "";
    return get<KBDocumentListOut>(`/jobs/${jobId}/kb/documents${qs}`);
  },

  uploadKBDocument(jobId: string, body: KBDocumentCreate): Promise<KBDocumentOut> { return post<KBDocumentOut>(`/jobs/${jobId}/kb/documents`, body); },

  uploadKBBinaryFile(jobId: string, file: File, name: string, docType: string, description?: string): Promise<KBDocumentOut> {
    const form = new FormData();
    form.append("file", file);
    form.append("name", name);
    form.append("doc_type", docType);
    if (description) form.append("description", description);
    return request<KBDocumentOut>(`${API_BASE}/jobs/${jobId}/kb/upload-binary`, { method: "POST", body: form });
  },

  getKBDocument(jobId: string, docId: string): Promise<KBDocumentDetail> { return get<KBDocumentDetail>(`/jobs/${jobId}/kb/documents/${docId}`); },

  deleteKBDocument(jobId: string, docId: string): Promise<void> { return del<void>(`/jobs/${jobId}/kb/documents/${docId}`); },

  reindexKBDocument(jobId: string, docId: string): Promise<KBDocumentOut> { return post<KBDocumentOut>(`/jobs/${jobId}/kb/documents/${docId}/reindex`, {}); },

  searchKB(jobId: string, query: string, nResults?: number, docType?: string): Promise<KBSearchResponse> {
    return post<KBSearchResponse>(`/jobs/${jobId}/kb/search`, { query, n_results: nResults ?? 5, doc_type: docType });
  },

  getLibraryConfig(): Promise<{ admin_required: boolean }> { return get(`/kb/library/config`); },

  listLibraryDocuments(docType?: string): Promise<KBDocumentListOut> {
    const qs = docType ? `?doc_type=${encodeURIComponent(docType)}` : "";
    return get<KBDocumentListOut>(`/kb/library/documents${qs}`);
  },

  uploadLibraryDocument(body: KBDocumentCreate, adminToken?: string): Promise<KBDocumentOut> {
    return request<KBDocumentOut>(`${API_BASE}/kb/library/documents`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(adminToken ? { "X-KB-Admin-Token": adminToken } : {}) },
      body: JSON.stringify(body),
    });
  },

  uploadLibraryBinaryFile(file: File, name: string, docType: string, description?: string, adminToken?: string): Promise<KBDocumentOut> {
    const form = new FormData();
    form.append("file", file);
    form.append("name", name);
    form.append("doc_type", docType);
    if (description) form.append("description", description);
    return request<KBDocumentOut>(`${API_BASE}/kb/library/upload-binary`, {
      method: "POST",
      headers: adminToken ? { "X-KB-Admin-Token": adminToken } : {},
      body: form,
    });
  },

  deleteLibraryDocument(docId: string, adminToken?: string): Promise<void> {
    return request<void>(`${API_BASE}/kb/library/documents/${docId}`, {
      method: "DELETE",
      headers: adminToken ? { "X-KB-Admin-Token": adminToken } : {},
    });
  },

  reindexLibraryDocument(docId: string, adminToken?: string): Promise<KBDocumentOut> {
    return request<KBDocumentOut>(`${API_BASE}/kb/library/documents/${docId}/reindex`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(adminToken ? { "X-KB-Admin-Token": adminToken } : {}) },
      body: JSON.stringify({}),
    });
  },
};
