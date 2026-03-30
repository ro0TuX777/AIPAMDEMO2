import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  api,
  SettingsPayload,
  EffectiveSettingsResponse,
  OllamaModelInfo,
  OllamaGpuStatusResponse,
  ExplainTelemetryResponse,
  SystemConfigResponse,
} from "../api";
import { HelpGuidePanel } from "../components/HelpGuidePanel";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDurationMs(durationMs: number): string {
  return `${durationMs.toLocaleString()} ms`;
}

/** Small helper — returns class names for a clickable label */
function labelHint(field: string, activeField: string | null): string {
  const base = "help-label-hint";
  return activeField === field ? `${base} help-label-hint--active` : base;
}

export const SettingsPage: React.FC = () => {
  const [values, setValues] = useState<SettingsPayload>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [llmTestResult, setLlmTestResult] = useState<string | null>(null);
  const [showDebug, setShowDebug] = useState(false);
  const [effectiveSettings, setEffectiveSettings] = useState<EffectiveSettingsResponse | null>(null);
  const [effectiveLoading, setEffectiveLoading] = useState(false);
  const [effectiveError, setEffectiveError] = useState<string | null>(null);
  const [systemConfig, setSystemConfig] = useState<SystemConfigResponse | null>(null);
  const [systemConfigLoading, setSystemConfigLoading] = useState(false);
  const [systemConfigError, setSystemConfigError] = useState<string | null>(null);
  const [explainTelemetry, setExplainTelemetry] = useState<ExplainTelemetryResponse | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState(false);
  const [telemetryResetting, setTelemetryResetting] = useState(false);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);
  // Ollama models
  const [availableModels, setAvailableModels] = useState<OllamaModelInfo[]>([]);
  const [modelsLoading, setModelsLoading] = useState(false);
  // Ollama GPU status
  const [gpuStatus, setGpuStatus] = useState<OllamaGpuStatusResponse | null>(null);
  const [gpuStatusLoading, setGpuStatusLoading] = useState(false);
  // Help guide
  const [activeHelpField, setActiveHelpField] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const toggleHelp = (field: string) => {
    setActiveHelpField((prev) => (prev === field ? null : field));
  };

  const fetchModels = useCallback(async () => {
    setModelsLoading(true);
    try {
      const models = await api.getAvailableModels();
      setAvailableModels(models);
    } catch (err) {
      console.error("Failed to fetch models:", err);
    } finally {
      setModelsLoading(false);
    }
  }, []);

  const fetchGpuStatus = useCallback(async () => {
    setGpuStatusLoading(true);
    try {
      const status = await api.getOllamaStatus();
      setGpuStatus(status);
    } catch (err) {
      console.error("Failed to fetch GPU status:", err);
    } finally {
      setGpuStatusLoading(false);
    }
  }, []);

  const loadExplainTelemetry = useCallback(async () => {
    setTelemetryLoading(true);
    setTelemetryError(null);
    try {
      const telemetry = await api.getExplainTelemetry();
      setExplainTelemetry(telemetry);
    } catch (err) {
      console.error("Failed to fetch explain telemetry:", err);
      setTelemetryError("Failed to load explain telemetry");
    } finally {
      setTelemetryLoading(false);
    }
  }, []);

  const loadSystemConfig = useCallback(async () => {
    setSystemConfigLoading(true);
    setSystemConfigError(null);
    try {
      const config = await api.getSystemConfig();
      setSystemConfig(config);
    } catch (err) {
      console.error("Failed to fetch system config:", err);
      setSystemConfigError("Failed to load explain configuration");
    } finally {
      setSystemConfigLoading(false);
    }
  }, []);

  const handleResetExplainTelemetry = useCallback(async () => {
    setTelemetryResetting(true);
    setTelemetryError(null);
    try {
      const telemetry = await api.resetExplainTelemetry();
      setExplainTelemetry(telemetry);
    } catch (err) {
      console.error("Failed to reset explain telemetry:", err);
      setTelemetryError("Failed to reset explain telemetry");
    } finally {
      setTelemetryResetting(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [data, models] = await Promise.all([
          api.getSettings(),
          api.getAvailableModels(),
        ]);
        if (!cancelled) {
          setValues(data || {});
          setAvailableModels(models);
        }
      } catch (err) {
        console.error(err);
        if (!cancelled) {
          setError("Failed to load settings");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    void loadExplainTelemetry();
  }, [loadExplainTelemetry]);

  useEffect(() => {
    void loadSystemConfig();
  }, [loadSystemConfig]);

  useEffect(() => {
    void fetchGpuStatus();
  }, [fetchGpuStatus]);

  const explainMode = systemConfig?.explain_configuration.mode ?? "deterministic";
  const explainModeLabel = explainMode === "llm" ? "LLM-enabled" : "Deterministic only";
  const explainModeDescription = explainMode === "llm"
    ? "Finding explanations will try the configured LLM first and fall back to deterministic grounded output on invalid or unavailable responses."
    : "Finding explanations are currently generated using deterministic grounded output only.";
  const explainModelName = systemConfig?.explain_configuration.llm_model_name ?? "Not configured";
  const explainEndpoint = systemConfig?.explain_configuration.llm_endpoint ?? "Not configured";

  const handleChange = (key: keyof SettingsPayload, value: string) => {
    setValues((prev) => ({ ...prev, [key]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      const updated = await api.updateSettings(values);
      setValues(updated || {});
      setSuccess("Settings saved");
    } catch (err) {
      console.error(err);
      setError("Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const handleTestLlm = async () => {
    setTesting(true);
    setLlmTestResult(null);
    try {
      const res = await api.testLlmConnection({
        llm_endpoint: values.llm_endpoint,
        llm_model_name: values.llm_model_name,
        llm_max_tokens: values.llm_max_tokens,
        llm_temperature: values.llm_temperature,
      });
      if (res.ok) {
        setLlmTestResult("LLM connection OK");
      } else {
        setLlmTestResult(`LLM test failed: ${res.error ?? "unknown error"}`);
      }
    } catch (err) {
      console.error(err);
      setLlmTestResult("LLM test failed: request error");
    } finally {
      setTesting(false);
    }
  };

  const explainResponseCounts = explainTelemetry?.explain_response_counts ?? {};
  const totalExplainResponses = Object.values(explainResponseCounts).reduce((sum, count) => sum + count, 0);
  const deterministicExplainResponses = explainResponseCounts.deterministic ?? 0;
  const llmExplainResponses = explainResponseCounts.llm ?? 0;
  const fallbackExplainResponses = explainResponseCounts.fallback ?? 0;
  const explainLatency = explainTelemetry?.explain_latency_ms;
  const averageExplainLatencyMs = explainLatency?.average_ms ?? 0;
  const minExplainLatencyMs = explainLatency?.min_ms ?? 0;
  const maxExplainLatencyMs = explainLatency?.max_ms ?? 0;
  const lastExplainLatencyMs = explainLatency?.last_ms ?? 0;

  if (loading) {
    return (
      <div className="space-y-4 max-w-xl">
        <h1 className="text-xl font-semibold">Settings</h1>
        <div className="border border-slate-800 rounded-lg p-4 text-sm text-slate-200">Loading...</div>
      </div>
    );
  }

  return (
    <div className="flex gap-6 items-start" data-testid="page-settings">
      {/* ── Main Settings Form ──────────────────────────── */}
      <div className="space-y-4 flex-1 min-w-0 max-w-2xl">
        <h1 className="text-xl font-semibold">Settings</h1>
        <form
          className="border border-slate-800 rounded-lg p-4 text-sm text-slate-200 space-y-6"
          onSubmit={handleSubmit}
        >
          {/* Ollama Hardware Status (read-only) */}
          <section className="space-y-2" data-testid="section-gpu-status">
            <div className="flex items-center justify-between">
              <h2
                className={`font-semibold text-slate-100 cursor-pointer ${labelHint("hardware_acceleration", activeHelpField)}`}
                onClick={() => toggleHelp("hardware_acceleration")}
              >
                Hardware Acceleration
                <span className="ml-1.5 text-[10px] text-slate-500 font-normal align-middle">ⓘ</span>
              </h2>
              <button
                type="button"
                onClick={fetchGpuStatus}
                disabled={gpuStatusLoading}
                className="rounded bg-slate-700 px-2 py-0.5 text-[10px] font-medium hover:bg-slate-600 disabled:opacity-50"
              >
                {gpuStatusLoading ? "Checking…" : "↻ Refresh"}
              </button>
            </div>
            {gpuStatusLoading && !gpuStatus ? (
              <div className="text-xs text-slate-400">Checking hardware…</div>
            ) : gpuStatus ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <div className="rounded border border-slate-800 bg-slate-950/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">Device</div>
                  <div className="mt-0.5 text-sm font-semibold" data-testid="gpu-device">
                    {gpuStatus.gpu_detected ? (
                      <span className="text-emerald-400">{gpuStatus.compute_device}</span>
                    ) : (
                      <span className="text-amber-400">CPU</span>
                    )}
                  </div>
                </div>
                <div className="rounded border border-slate-800 bg-slate-950/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">GPU</div>
                  <div className="mt-0.5 text-sm font-medium text-slate-200" data-testid="gpu-name">
                    {gpuStatus.gpu_name ?? "Not detected"}
                  </div>
                </div>
                <div className="rounded border border-slate-800 bg-slate-950/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">VRAM Used</div>
                  <div className="mt-0.5 text-sm font-medium text-slate-200" data-testid="gpu-vram-used">
                    {gpuStatus.vram_used_bytes > 0 ? formatBytes(gpuStatus.vram_used_bytes) : "—"}
                    {gpuStatus.vram_total_bytes > 0 && (
                      <span className="text-slate-500 text-xs"> / {formatBytes(gpuStatus.vram_total_bytes)}</span>
                    )}
                  </div>
                </div>
                <div className="rounded border border-slate-800 bg-slate-950/60 p-2">
                  <div className="text-[10px] uppercase tracking-wide text-slate-500">Ollama</div>
                  <div className="mt-0.5 text-sm font-medium text-slate-200" data-testid="ollama-version">
                    v{gpuStatus.ollama_version}
                  </div>
                </div>
                {gpuStatus.loaded_models.length > 0 && (
                  <div className="col-span-2 md:col-span-4 rounded border border-slate-800 bg-slate-950/60 p-2">
                    <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">Loaded Models</div>
                    {gpuStatus.loaded_models.map((m) => (
                      <div key={m.name} className="flex items-center gap-2 text-xs text-slate-300">
                        <span className="font-medium">{m.name}</span>
                        <span className="text-slate-500">|</span>
                        <span>{m.parameter_size}</span>
                        <span className="text-slate-500">|</span>
                        <span className={m.gpu_offload_pct === 100 ? "text-emerald-400" : m.gpu_offload_pct > 0 ? "text-amber-400" : "text-slate-400"}>
                          {m.gpu_offload_pct}% GPU
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="text-xs text-slate-500">Unable to determine hardware status</div>
            )}
            {gpuStatus && !gpuStatus.gpu_detected && (
              <div className="text-[10px] text-amber-400/70 bg-amber-900/10 border border-amber-800/20 rounded px-2 py-1">
                No GPU detected. Inference runs on CPU, which is slower. To enable GPU, configure <code>deploy.resources.reservations.devices</code> in docker-compose.yml and restart the Ollama container.
              </div>
            )}
          </section>

          {/* LLM Settings */}
          <section className="space-y-3">
            <h2 className="font-semibold text-slate-100">LLM Settings</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  className={`block mb-1 ${labelHint("llm_endpoint", activeHelpField)}`}
                  onClick={() => toggleHelp("llm_endpoint")}
                >
                  Endpoint URL
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.llm_endpoint ?? ""}
                  onChange={(e) => handleChange("llm_endpoint", e.target.value)}
                  data-testid="input-llm-endpoint"
                />
              </div>
              <div>
                <label
                  className={`block mb-1 ${labelHint("llm_model_name", activeHelpField)}`}
                  onClick={() => toggleHelp("llm_model_name")}
                >
                  Default Model Name
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.llm_model_name ?? ""}
                  onChange={(e) => handleChange("llm_model_name", e.target.value)}
                  data-testid="input-llm-model-name"
                />
                <span className="text-[10px] text-slate-500 mt-0.5 block">Fallback if role models are not set</span>
              </div>
            </div>

            {/* Dual Model Selection */}
            <div className="border border-slate-700/50 rounded-lg p-3 space-y-3 bg-slate-900/40">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">Model Role Assignment</span>
                <button
                  type="button"
                  onClick={fetchModels}
                  disabled={modelsLoading}
                  className="rounded bg-slate-700 px-2 py-0.5 text-[10px] font-medium hover:bg-slate-600 disabled:opacity-50 flex items-center gap-1"
                  data-testid="btn-refresh-models"
                >
                  {modelsLoading ? (
                    <span className="animate-spin inline-block w-3 h-3 border border-slate-400 border-t-transparent rounded-full" />
                  ) : (
                    <span>↻</span>
                  )}
                  {modelsLoading ? "Scanning…" : "Refresh Models"}
                </button>
              </div>

              {availableModels.length === 0 && !modelsLoading && (
                <div className="text-xs text-amber-400/80 bg-amber-900/20 border border-amber-700/30 rounded px-2 py-1.5">
                  No models found. Ensure Ollama is running on the configured endpoint.
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("forensic_model_name", activeHelpField)}`}
                    onClick={() => toggleHelp("forensic_model_name")}
                  >
                    Forensic Model
                    <span className="text-[10px] text-slate-500 ml-1">(deep analysis, MITRE mapping)</span>
                  </label>
                  <select
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.forensic_model_name ?? ""}
                    onChange={(e) => handleChange("forensic_model_name", e.target.value)}
                    data-testid="select-forensic-model"
                  >
                    <option value="">— Select Forensic Model —</option>
                    {availableModels.map((m) => (
                      <option key={`forensic-${m.name}`} value={m.name}>
                        {m.name} ({m.parameter_size}, {formatBytes(m.size)})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("general_model_name", activeHelpField)}`}
                    onClick={() => toggleHelp("general_model_name")}
                  >
                    General Model
                    <span className="text-[10px] text-slate-500 ml-1">(reasoning, out-of-distribution)</span>
                  </label>
                  <select
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.general_model_name ?? ""}
                    onChange={(e) => handleChange("general_model_name", e.target.value)}
                    data-testid="select-general-model"
                  >
                    <option value="">— Select General Model —</option>
                    {availableModels.map((m) => (
                      <option key={`general-${m.name}`} value={m.name}>
                        {m.name} ({m.parameter_size}, {formatBytes(m.size)})
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  className={`block mb-1 ${labelHint("llm_max_tokens", activeHelpField)}`}
                  onClick={() => toggleHelp("llm_max_tokens")}
                >
                  Max Tokens
                </label>
                <input
                  type="number"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.llm_max_tokens ?? ""}
                  onChange={(e) => handleChange("llm_max_tokens", e.target.value)}
                  data-testid="input-llm-max-tokens"
                />
              </div>
              <div>
                <label
                  className={`block mb-1 ${labelHint("llm_temperature", activeHelpField)}`}
                  onClick={() => toggleHelp("llm_temperature")}
                >
                  Temperature
                </label>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="1"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.llm_temperature ?? ""}
                  onChange={(e) => handleChange("llm_temperature", e.target.value)}
                  data-testid="input-llm-temperature"
                />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handleTestLlm}
                disabled={testing}
                data-testid="btn-test-llm"
                className="rounded bg-slate-700 px-3 py-1 text-xs font-medium hover:bg-slate-600 disabled:opacity-50"
              >
                {testing ? "Testing..." : "Test Connection"}
              </button>
              {llmTestResult && <span className="text-xs text-slate-300">{llmTestResult}</span>}
            </div>
          </section>

          {/* Security Onion Settings */}
          <section className="space-y-3">
            <h2 className="font-semibold text-slate-100">Security Onion</h2>
            <p className="text-xs text-slate-400">
              Connect to a Security Onion 2.4+ instance via the SOC API for PCAP pull/push and alert enrichment.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="md:col-span-2">
                <label
                  className={`block mb-1 ${labelHint("security_onion_api_url", activeHelpField)}`}
                  onClick={() => toggleHelp("security_onion_api_url")}
                >
                  API URL
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_api_url ?? ""}
                  onChange={(e) => handleChange("security_onion_api_url", e.target.value)}
                  placeholder="https://172.16.0.15"
                  data-testid="input-so-api-url"
                />
              </div>
              <div>
                <label className="block mb-1 text-slate-300">Username</label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_username ?? ""}
                  onChange={(e) => handleChange("security_onion_username", e.target.value)}
                  placeholder="analyst@example.com"
                  data-testid="input-so-username"
                />
              </div>
              <div>
                <label className="block mb-1 text-slate-300">Password</label>
                <input
                  type="password"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_password ?? ""}
                  onChange={(e) => handleChange("security_onion_password", e.target.value)}
                  data-testid="input-so-password"
                />
              </div>
            </div>
          </section>

          {/* Arkime Settings */}
          <section className="space-y-3">
            <h2 className="font-semibold text-slate-100">Arkime</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  className={`block mb-1 ${labelHint("arkime_api_url", activeHelpField)}`}
                  onClick={() => toggleHelp("arkime_api_url")}
                >
                  API URL
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.arkime_api_url ?? ""}
                  onChange={(e) => handleChange("arkime_api_url", e.target.value)}
                  data-testid="input-arkime-api-url"
                />
              </div>
              <div>
                <label
                  className={`block mb-1 ${labelHint("arkime_api_username", activeHelpField)}`}
                  onClick={() => toggleHelp("arkime_api_username")}
                >
                  Username
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.arkime_api_username ?? ""}
                  onChange={(e) => handleChange("arkime_api_username", e.target.value)}
                  data-testid="input-arkime-username"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  className={`block mb-1 ${labelHint("arkime_api_password", activeHelpField)}`}
                  onClick={() => toggleHelp("arkime_api_password")}
                >
                  Password / Token
                </label>
                <input
                  type="password"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.arkime_api_password ?? ""}
                  onChange={(e) => handleChange("arkime_api_password", e.target.value)}
                  data-testid="input-arkime-password"
                />
              </div>
            </div>
          </section>

          {/* Storage Settings */}
          <section className="space-y-3">
            <h2 className="font-semibold text-slate-100">Storage</h2>
            <div>
              <label
                className={`block mb-1 ${labelHint("file_storage_path", activeHelpField)}`}
                onClick={() => toggleHelp("file_storage_path")}
              >
                File Storage Path
              </label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.file_storage_path ?? ""}
                onChange={(e) => handleChange("file_storage_path", e.target.value)}
                data-testid="input-file-storage-path"
              />
            </div>
          </section>

          {/* Advanced (Debug / Telemetry) — collapsible */}
          <section className="space-y-3">
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-2 text-sm font-semibold text-slate-400 hover:text-slate-200 transition-colors"
            >
              <span className={`transform transition-transform ${showAdvanced ? "rotate-90" : ""}`}>▶</span>
              Advanced
            </button>

            {showAdvanced && (
              <div className="space-y-4 border border-slate-800 rounded-lg p-4 bg-slate-900/30">

                {/* Debug: Effective Runtime Settings */}
                <div className="space-y-2" data-testid="section-effective-settings-debug">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-300">Effective Runtime Settings</span>
                    <button
                      type="button"
                      onClick={async () => {
                        setEffectiveLoading(true);
                        setEffectiveError(null);
                        try {
                          const data = await api.getEffectiveSettings();
                          setEffectiveSettings(data);
                        } catch (err) {
                          console.error(err);
                          setEffectiveError("Failed to load effective settings");
                        } finally {
                          setEffectiveLoading(false);
                        }
                      }}
                      className="rounded bg-slate-700 px-2 py-1 text-[11px] font-medium hover:bg-slate-600 disabled:opacity-50"
                      disabled={effectiveLoading}
                      data-testid="btn-load-effective-settings"
                    >
                      {effectiveLoading ? "Loading..." : "Load"}
                    </button>
                  </div>
                  {effectiveError && (
                    <div className="text-red-400 text-xs" data-testid="text-effective-settings-error">{effectiveError}</div>
                  )}
                  {effectiveSettings && (
                    <pre className="bg-slate-950 border border-slate-800 rounded p-2 overflow-auto max-h-48 text-xs" data-testid="pre-effective-settings-json">
                      {JSON.stringify(effectiveSettings, null, 2)}
                    </pre>
                  )}
                </div>

                {/* Explain Configuration */}
                <div className="space-y-2" data-testid="section-explain-config">
                  <span className="text-xs font-semibold text-slate-300">Explain Configuration</span>
                  {systemConfigError && (
                    <div className="text-red-400 text-xs" data-testid="text-explain-config-error">{systemConfigError}</div>
                  )}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                    <div className="rounded border border-slate-800 bg-slate-950/60 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-400">Mode</div>
                      <div className="mt-1 text-lg font-semibold text-slate-100" data-testid="text-explain-config-mode">
                        {systemConfigLoading ? "Loading..." : explainModeLabel}
                      </div>
                      <div className="mt-1 text-xs text-slate-400" data-testid="text-explain-config-mode-description">
                        {systemConfigLoading ? "..." : explainModeDescription}
                      </div>
                    </div>
                    <div className="rounded border border-slate-800 bg-slate-950/60 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-400">LLM model</div>
                      <div className="mt-1 text-sm font-medium text-slate-100 break-all" data-testid="text-explain-config-model">
                        {systemConfigLoading ? "Loading..." : explainModelName}
                      </div>
                    </div>
                    <div className="rounded border border-slate-800 bg-slate-950/60 p-3">
                      <div className="text-xs uppercase tracking-wide text-slate-400">LLM endpoint</div>
                      <div className="mt-1 text-sm font-medium text-slate-100 break-all" data-testid="text-explain-config-endpoint">
                        {systemConfigLoading ? "Loading..." : explainEndpoint}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Explain Telemetry */}
                <div className="space-y-2" data-testid="section-explain-telemetry">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-300">Explain Telemetry</span>
                    <div className="flex items-center gap-2">
                      <button type="button" onClick={loadExplainTelemetry} disabled={telemetryLoading || telemetryResetting}
                        className="rounded bg-slate-700 px-2 py-1 text-[11px] font-medium hover:bg-slate-600 disabled:opacity-50"
                        data-testid="btn-refresh-explain-telemetry">
                        {telemetryLoading ? "..." : "Refresh"}
                      </button>
                      <button type="button" onClick={handleResetExplainTelemetry} disabled={telemetryLoading || telemetryResetting}
                        className="rounded border border-amber-700 bg-amber-950/40 px-2 py-1 text-[11px] font-medium text-amber-200 hover:bg-amber-900/40 disabled:opacity-50"
                        data-testid="btn-reset-explain-telemetry">
                        {telemetryResetting ? "..." : "Reset"}
                      </button>
                    </div>
                  </div>
                  {telemetryError && (
                    <div className="text-red-400 text-xs" data-testid="text-explain-telemetry-error">{telemetryError}</div>
                  )}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                    {[
                      ["Total", totalExplainResponses, "text-explain-telemetry-total"],
                      ["Deterministic", deterministicExplainResponses, "text-explain-telemetry-deterministic"],
                      ["LLM", llmExplainResponses, "text-explain-telemetry-llm"],
                      ["Fallback", fallbackExplainResponses, "text-explain-telemetry-fallback"],
                      ["Avg latency", formatDurationMs(averageExplainLatencyMs), "text-explain-telemetry-average-ms"],
                      ["Last", formatDurationMs(lastExplainLatencyMs), "text-explain-telemetry-last-ms"],
                      ["Fastest", formatDurationMs(minExplainLatencyMs), "text-explain-telemetry-min-ms"],
                      ["Slowest", formatDurationMs(maxExplainLatencyMs), "text-explain-telemetry-max-ms"],
                    ].map(([label, value, testId]) => (
                      <div key={testId as string} className="rounded border border-slate-800 bg-slate-950/60 p-2">
                        <div className="text-[10px] uppercase tracking-wide text-slate-400">{label}</div>
                        <div className="mt-1 text-lg font-semibold text-slate-100" data-testid={testId}>{value}</div>
                      </div>
                    ))}
                  </div>
                </div>

              </div>
            )}
          </section>

          {error && <div className="text-red-400 text-sm">{error}</div>}
          {success && <div className="text-emerald-400 text-sm">{success}</div>}

          <button
            type="submit"
            data-testid="btn-save-settings"
            disabled={saving}
            className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>
        </form>
      </div>

      {/* ── Help Guide Panel ────────────────────────────── */}
      <HelpGuidePanel
        activeField={activeHelpField}
        onClose={() => setActiveHelpField(null)}
        onNavigate={(field) => setActiveHelpField(field)}
      />
    </div>
  );
};
