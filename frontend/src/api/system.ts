import type {
  SystemConfigResponse,
  HealthResponse,
  ExplainTelemetryResponse,
  SettingsPayload,
  EffectiveSettingsResponse,
  OllamaModelInfo,
  EmbeddingModelsResponse,
  EmbeddingModelConfig,
  EmbeddingModelPullStatus,
  OllamaRuntimeConfig,
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
  getEmbeddingModel(): Promise<EmbeddingModelConfig> { return get<EmbeddingModelConfig>("/embedding-model"); },
  getEmbeddingRuntime(): Promise<OllamaRuntimeConfig> { return get<OllamaRuntimeConfig>("/embedding-model/runtime"); },
  saveEmbeddingRuntime(ollamaUrl: string): Promise<OllamaRuntimeConfig> {
    return request<OllamaRuntimeConfig>(`${API_BASE}/embedding-model/runtime`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ollama_url: ollamaUrl }),
    });
  },
  getEmbeddingModels(): Promise<OllamaModelInfo[]> { return get<EmbeddingModelsResponse>("/embedding-models").then((r) => r.models); },
  selectEmbeddingModel(model: string): Promise<EmbeddingModelConfig> { return post<EmbeddingModelConfig>("/embedding-model", { model }); },
  pullEmbeddingModel(model: string): Promise<EmbeddingModelPullStatus> { return post<EmbeddingModelPullStatus>("/embedding-models/pull", { model }); },
  getEmbeddingModelPull(model: string): Promise<EmbeddingModelPullStatus> { return get<EmbeddingModelPullStatus>(`/embedding-models/pull/${encodeURIComponent(model)}`); },
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
