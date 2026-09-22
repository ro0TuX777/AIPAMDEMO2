import type {
  SecurityOnionImportResponse,
  ArkimeImportResponse,
  ArkimeStatusResponse,
  ArkimePivotResponse,
  IntegrationSettingsPayload,
  IntegrationTestRequest,
  IntegrationTestResponse,
} from "./types";
import {
  API_BASE,
  request,
  get,
  post,
} from "./transport";

export const integrationsApi = {
  /** @deprecated V1 */
  createJobFromSecurityOnion(payload: any): Promise<{ job_id: string }> { return post<{ job_id: string }>("/jobs/from_security_onion", payload); },

  /** @deprecated V1 */
  createJobFromArkime(payload: any): Promise<{ job_id: string }> { return post<{ job_id: string }>("/jobs/from_arkime", payload); },

  triggerArkimeImport(jobId: string): Promise<ArkimeImportResponse> {
    return post<ArkimeImportResponse>(`/jobs/${jobId}/arkime/import`);
  },

  getArkimeStatus(jobId: string): Promise<ArkimeStatusResponse> {
    return get<ArkimeStatusResponse>(`/jobs/${jobId}/arkime/status`);
  },

  getAlertArkimeLink(jobId: string, alertId: string): Promise<ArkimePivotResponse> {
    return get<ArkimePivotResponse>(`/jobs/${jobId}/alerts/${alertId}/arkime-link`);
  },

  getFindingArkimeLink(jobId: string, findingId: string): Promise<ArkimePivotResponse> {
    return get<ArkimePivotResponse>(`/jobs/${jobId}/findings/${findingId}/arkime-link`);
  },

  triggerSecurityOnionImport(jobId: string): Promise<SecurityOnionImportResponse> {
    return post<SecurityOnionImportResponse>(`/jobs/${jobId}/security_onion/import`);
  },

  getIntegrationSettings(): Promise<IntegrationSettingsPayload> {
    return get<IntegrationSettingsPayload>("/integrations/settings");
  },

  saveIntegrationSettings(values: IntegrationSettingsPayload): Promise<IntegrationSettingsPayload> {
    return request<IntegrationSettingsPayload>(`${API_BASE}/integrations/settings`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(values),
    });
  },

  testIntegrationConnection(body: IntegrationTestRequest): Promise<IntegrationTestResponse> {
    return post<IntegrationTestResponse>("/integrations/test", body);
  },
};
