import React, { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { api, SettingsPayload, EffectiveSettingsResponse, OllamaModelInfo } from "../api";
import { HelpGuidePanel } from "../components/HelpGuidePanel";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
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
  // Ollama models
  const [availableModels, setAvailableModels] = useState<OllamaModelInfo[]>([]);
  const [modelsLoading, setModelsLoading] = useState(false);
  // Help guide
  const [activeHelpField, setActiveHelpField] = useState<string | null>(null);
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

          {/* Fine-Tuning Configuration */}
          <section className="space-y-3">
            <h2 className="font-semibold text-slate-100">Fine-Tuning</h2>
            <div className="border border-emerald-500/20 rounded-lg p-3 space-y-3 bg-slate-900/40">
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">
                Training Pipeline Configuration
              </span>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("finetune_base_model", activeHelpField)}`}
                    onClick={() => toggleHelp("finetune_base_model")}
                  >
                    Base Model
                    <span className="text-[10px] text-slate-500 ml-1">(select local model)</span>
                  </label>
                  <select
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.finetune_base_model ?? ""}
                    onChange={(e) => handleChange("finetune_base_model", e.target.value)}
                    data-testid="input-finetune-base-model"
                  >
                    <option value="">— Select Base Model —</option>
                    {availableModels.map((m) => (
                      <option key={`finetune-${m.name}`} value={m.name}>
                        {m.name} ({m.parameter_size}, {formatBytes(m.size)})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("finetuning_backend", activeHelpField)}`}
                    onClick={() => toggleHelp("finetuning_backend")}
                  >
                    Training Backend
                    <span className="text-[10px] text-slate-500 ml-1">(hardware acceleration)</span>
                  </label>
                  <select
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.finetuning_backend ?? "mlx"}
                    onChange={(e) => handleChange("finetuning_backend", e.target.value)}
                    data-testid="select-finetuning-backend"
                  >
                    <option value="mlx">Apple Silicon (MLX)</option>
                    <option value="cuda">NVIDIA GPU (CUDA/Unsloth)</option>
                  </select>
                </div>
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("finetune_dataset_url", activeHelpField)}`}
                    onClick={() => toggleHelp("finetune_dataset_url")}
                  >
                    Dataset Source
                    <span className="text-[10px] text-slate-500 ml-1">(HuggingFace URL or repo ID)</span>
                  </label>
                  <input
                    type="text"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.finetune_dataset_url ?? ""}
                    onChange={(e) => handleChange("finetune_dataset_url", e.target.value)}
                    placeholder="https://huggingface.co/datasets/your-org/dataset"
                    data-testid="input-finetune-dataset-url"
                  />
                </div>
                <div className="md:col-span-2">
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("dataset_storage_path", activeHelpField)}`}
                    onClick={() => toggleHelp("dataset_storage_path")}
                  >
                    Dataset Storage Path
                    <span className="text-[10px] text-slate-500 ml-1">(filesystem path for large downloads)</span>
                  </label>
                  <input
                    type="text"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.dataset_storage_path ?? ""}
                    onChange={(e) => handleChange("dataset_storage_path", e.target.value)}
                    placeholder="/data/finetune_datasets"
                    data-testid="input-dataset-storage-path"
                  />
                  <div className="flex items-center gap-2 mt-1">
                    <button
                      type="button"
                      onClick={async () => {
                        if (!values.dataset_storage_path) return;
                        try {
                          const res = await api.validateStoragePath(values.dataset_storage_path);
                          if (res.valid) {
                            alert("✅ Path is valid and writable!");
                          } else {
                            alert(`❌ Invalid Path: ${res.message}`);
                          }
                        } catch (err: any) {
                          alert(`❌ Error validating path: ${err.message}`);
                        }
                      }}
                      className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded border border-slate-600"
                    >
                      Validate Path
                    </button>
                    <span className="text-[10px] text-slate-500">
                      (e.g., /Volumes/MyExternalDrive/data)
                    </span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("finetune_lora_rank", activeHelpField)}`}
                    onClick={() => toggleHelp("finetune_lora_rank")}
                  >
                    LoRA Rank
                    <span className="text-[10px] text-slate-500 ml-1">(adapter rank)</span>
                  </label>
                  <input
                    type="number"
                    min="4"
                    max="256"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.finetune_lora_rank ?? ""}
                    onChange={(e) => handleChange("finetune_lora_rank", e.target.value)}
                    placeholder="16"
                    data-testid="input-finetune-lora-rank"
                  />
                </div>
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("finetune_learning_rate", activeHelpField)}`}
                    onClick={() => toggleHelp("finetune_learning_rate")}
                  >
                    Learning Rate
                  </label>
                  <input
                    type="number"
                    step="0.00001"
                    min="0"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.finetune_learning_rate ?? ""}
                    onChange={(e) => handleChange("finetune_learning_rate", e.target.value)}
                    placeholder="0.0002"
                    data-testid="input-finetune-learning-rate"
                  />
                </div>
                <div>
                  <label
                    className={`block mb-1 text-slate-300 ${labelHint("finetune_max_seq_length", activeHelpField)}`}
                    onClick={() => toggleHelp("finetune_max_seq_length")}
                  >
                    Context Window
                    <span className="text-[10px] text-slate-500 ml-1">(tokens)</span>
                  </label>
                  <input
                    type="number"
                    step="1024"
                    min="1024"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={values.finetune_max_seq_length ?? ""}
                    onChange={(e) => handleChange("finetune_max_seq_length", e.target.value)}
                    placeholder="32768"
                    data-testid="input-finetune-max-seq-length"
                  />
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={async () => {
                    if (!window.confirm("Start fine-tuning job with current settings?")) return;
                    try {
                      const res = await api.startTrainingJob();
                      setSuccess(`Job started: ${res.task_id}`);
                      // Navigate to Training page to see live progress
                      window.location.href = '/training';
                    } catch (err: any) {
                      const msg = err.message || "Failed to start job";
                      setError(msg);
                    }
                  }}
                  className="rounded bg-emerald-600 px-3 py-1.5 text-xs font-medium hover:bg-emerald-500 flex items-center gap-2"
                  data-testid="btn-start-finetuning"
                >
                  Start Fine-Tuning Job
                </button>
              </div>
            </div>
          </section>

          {/* Debug: Effective Runtime Settings */}
          <section className="space-y-2 border border-slate-800 rounded-lg p-3" data-testid="section-effective-settings-debug">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-slate-300">Debug: Effective Runtime Settings</span>
              <label className="inline-flex items-center gap-1 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={showDebug}
                  onChange={(e) => setShowDebug(e.target.checked)}
                  data-testid="toggle-effective-settings-debug"
                />
                <span>Show</span>
              </label>
            </div>
            {showDebug && (
              <div className="mt-2 text-xs">
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
                  className="mb-2 rounded bg-slate-700 px-2 py-1 text-[11px] font-medium hover:bg-slate-600 disabled:opacity-50"
                  disabled={effectiveLoading}
                  data-testid="btn-load-effective-settings"
                >
                  {effectiveLoading ? "Loading..." : "Load Effective Settings"}
                </button>

                {effectiveError && (
                  <div className="text-red-400 mb-1" data-testid="text-effective-settings-error">
                    {effectiveError}
                  </div>
                )}

                {effectiveSettings && (
                  <pre
                    className="bg-slate-950 border border-slate-800 rounded p-2 overflow-auto max-h-48"
                    data-testid="pre-effective-settings-json"
                  >
                    {JSON.stringify(effectiveSettings, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </section>

          {/* Security Onion Settings */}
          <section className="space-y-3">
            <h2 className="font-semibold text-slate-100">Security Onion</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  className={`block mb-1 ${labelHint("security_onion_mode", activeHelpField)}`}
                  onClick={() => toggleHelp("security_onion_mode")}
                >
                  Mode
                </label>
                <select
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_mode ?? "filesystem"}
                  onChange={(e) => handleChange("security_onion_mode", e.target.value)}
                  data-testid="select-so-mode-settings"
                >
                  <option value="filesystem">Filesystem</option>
                  <option value="api">API</option>
                </select>
              </div>
              <div>
                <label
                  className={`block mb-1 ${labelHint("security_onion_base_pcap_path", activeHelpField)}`}
                  onClick={() => toggleHelp("security_onion_base_pcap_path")}
                >
                  Base PCAP Path (filesystem)
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_base_pcap_path ?? ""}
                  onChange={(e) => handleChange("security_onion_base_pcap_path", e.target.value)}
                  placeholder="/srv/aipam/so-pcaps"
                  data-testid="input-so-base-pcap-path"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  className={`block mb-1 ${labelHint("security_onion_zeek_log_path", activeHelpField)}`}
                  onClick={() => toggleHelp("security_onion_zeek_log_path")}
                >
                  Zeek Log Path
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_zeek_log_path ?? ""}
                  onChange={(e) => handleChange("security_onion_zeek_log_path", e.target.value)}
                  data-testid="input-so-zeek-log-path"
                />
              </div>
              <div>
                <label
                  className={`block mb-1 ${labelHint("security_onion_suricata_log_path", activeHelpField)}`}
                  onClick={() => toggleHelp("security_onion_suricata_log_path")}
                >
                  Suricata Log Path
                </label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_suricata_log_path ?? ""}
                  onChange={(e) => handleChange("security_onion_suricata_log_path", e.target.value)}
                  data-testid="input-so-suricata-log-path"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
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
                  data-testid="input-so-api-url"
                />
              </div>
              <div>
                <label
                  className={`block mb-1 ${labelHint("security_onion_api_token", activeHelpField)}`}
                  onClick={() => toggleHelp("security_onion_api_token")}
                >
                  API Token
                </label>
                <input
                  type="password"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={values.security_onion_api_token ?? ""}
                  onChange={(e) => handleChange("security_onion_api_token", e.target.value)}
                  data-testid="input-so-api-token"
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
