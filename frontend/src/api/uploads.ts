import type { UploadCreateResponse, UploadValidateResponse } from "./types";
import { API_BASE, DEMO_MODE, authHeaders, post } from "./transport";

interface UploadOptions {
  path: string;
  demoPrefix: string;
  useServerDetail?: boolean;
  onProgress?: (pct: number) => void;
}

function uploadFile(file: File, options: UploadOptions): Promise<UploadCreateResponse> {
  const { path, demoPrefix, useServerDetail, onProgress } = options;
  if (DEMO_MODE) {
    if (onProgress) onProgress(100);
    return Promise.resolve({
      schema_version: "1.0",
      upload_id: `${demoPrefix}-${Date.now()}`,
      filename: file.name,
      size_bytes: file.size,
      sha256: `demo-${Date.now()}`,
    });
  }

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}${path}`);

    const headers = authHeaders();
    Object.keys(headers).forEach(k => xhr.setRequestHeader(k, headers[k]));
    xhr.setRequestHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(file.name)}"`);

    if (onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
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
        let msg = `Upload failed with status ${xhr.status}`;
        // PCAP uploads retain their generic message; bundles and artifacts
        // expose the server's validation detail when one is available.
        if (useServerDetail) {
          try { msg = JSON.parse(xhr.responseText).detail || msg; } catch {}
        }
        reject(new Error(msg));
      }
    };

    xhr.onerror = () => reject(new Error("Network error during upload"));
    xhr.send(file);
  });
}

export const uploadsApi = {
  uploadPcap(file: File, onProgress?: (pct: number) => void): Promise<UploadCreateResponse> {
    return uploadFile(file, { path: "/uploads", demoPrefix: "up", onProgress });
  },

  uploadBundle(file: File, onProgress?: (pct: number) => void): Promise<UploadCreateResponse> {
    return uploadFile(file, {
      path: "/uploads/bundle", demoPrefix: "bundle", useServerDetail: true, onProgress,
    });
  },

  /** Upload a code artifact (source archive or standalone binary).
   *  Uses the existing artifact endpoint — artifact_classifier already
   *  recognises zip/gzip/bzip2/tar, so no new upload path was needed. */
  uploadArtifact(file: File, onProgress?: (pct: number) => void): Promise<UploadCreateResponse> {
    return uploadFile(file, {
      path: "/uploads/artifact", demoPrefix: "artifact", useServerDetail: true, onProgress,
    });
  },

  validateUpload(uploadId: string): Promise<UploadValidateResponse> {
    return post<UploadValidateResponse>(`/uploads/${uploadId}/validate`);
  },
};
