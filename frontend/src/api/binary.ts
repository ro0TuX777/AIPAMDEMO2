import type {
  BinaryAnalysisListResponse,
  BinaryAnalysisResponse,
} from "./types";
import {
  API_BASE,
  authHeaders,
  request,
  get,
} from "./transport";

export const binaryApi = {
  listBinaryAnalyses(jobId: string): Promise<BinaryAnalysisListResponse> {
    return get<BinaryAnalysisListResponse>(`/jobs/${jobId}/binary`);
  },

  /**
   * Both binary endpoints take the file as a raw request body with the name in
   * a query param, not multipart — see _filename_from_request in binary.py.
   * `persist: false` routes to the stateless inspector.
   */
  analyzeBinary(
    file: File,
    opts: { jobId?: string; onProgress?: (pct: number) => void } = {},
  ): Promise<BinaryAnalysisResponse> {
    const path = opts.jobId
      ? `/jobs/${opts.jobId}/binary?filename=${encodeURIComponent(file.name)}`
      : `/binary/inspect?filename=${encodeURIComponent(file.name)}`;
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${API_BASE}${path}`);
      const headers = authHeaders();
      Object.keys(headers).forEach((k) => xhr.setRequestHeader(k, headers[k]));
      if (opts.onProgress) {
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) opts.onProgress!(Math.round((e.loaded / e.total) * 100));
        };
      }
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch {
            reject(new Error("Invalid JSON response from server"));
          }
        } else {
          let detail = `Analysis failed with status ${xhr.status}`;
          try {
            const body = JSON.parse(xhr.responseText);
            if (body?.detail) detail = body.detail;
          } catch { /* non-JSON error body */ }
          reject(new Error(detail));
        }
      };
      xhr.onerror = () => reject(new Error("Network error during upload"));
      xhr.send(file);
    });
  },
};
