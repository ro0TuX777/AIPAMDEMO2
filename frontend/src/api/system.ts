import type {
  SystemConfigResponse,
  HealthResponse,
  ExplainTelemetryResponse,
  SettingsPayload,
  EffectiveSettingsResponse,
  OllamaModelInfo,
  SetupStatusResponse,
  OllamaGpuStatusResponse,
  FeedbackMetricsResponse,
} from "./types";
import {
  API_BASE,
  request,
  get,
  post,
} from "./transport";

export const systemApi = {
  getHealth(): Promise<HealthResponse> { return get<HealthResponse>("/health"); },

  getSystemConfig(): Promise<SystemConfigResponse> { return get<SystemConfigResponse>("/system/config"); },

  getExplainTelemetry(): Promise<ExplainTelemetryResponse> {
    return get<ExplainTelemetryResponse>("/system/explain-telemetry");
  },

  resetExplainTelemetry(): Promise<ExplainTelemetryResponse> {
    return post<ExplainTelemetryResponse>("/system/explain-telemetry/reset");
  },

  getOllamaStatus(): Promise<OllamaGpuStatusResponse> {
    return get<OllamaGpuStatusResponse>("/system/ollama-status");
  },

  /** @deprecated V1 */
  getSettings(): Promise<SettingsPayload> { return get<SettingsPayload>("/settings"); },

  /** @deprecated V1 */
  updateSettings(values: Record<string, any>): Promise<SettingsPayload> {
    return request<SettingsPayload>(`${API_BASE}/settings`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(values) });
  },

  /** @deprecated V1 */
  testLlmConnection(body: Record<string, any>): Promise<any> { return post<any>("/settings/test_llm", body); },

  /** @deprecated V1 */
  getEffectiveSettings(): Promise<EffectiveSettingsResponse> { return get<EffectiveSettingsResponse>("/admin/effective_settings"); },

  /** @deprecated V1 */
  getAvailableModels(): Promise<OllamaModelInfo[]> { return get<any>("/models/available").then((r: any) => r.models ?? r); },

  /** @deprecated V1 */
  getSetupStatus(): Promise<SetupStatusResponse> { return get<SetupStatusResponse>("/settings/setup_status"); },

  /** @deprecated V1 */
  validateStoragePath(path: string): Promise<any> { return post<any>("/settings/validate_storage_path", { path }); },

  getFeedbackMetrics(): Promise<FeedbackMetricsResponse> {
    return get<FeedbackMetricsResponse>("/admin/feedback-metrics");
  },
};
