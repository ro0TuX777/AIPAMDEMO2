import React, { useEffect, useState } from "react";
import { api, SettingsPayload, EffectiveSettingsResponse } from "../api";

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

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.getSettings();
        if (!cancelled) {
          setValues(data || {});
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
    <div className="space-y-4 max-w-2xl" data-testid="page-settings">
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
              <label className="block mb-1">Endpoint URL</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.llm_endpoint ?? ""}
                onChange={(e) => handleChange("llm_endpoint", e.target.value)}
                data-testid="input-llm-endpoint"
              />
            </div>
            <div>
              <label className="block mb-1">Model Name</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.llm_model_name ?? ""}
                onChange={(e) => handleChange("llm_model_name", e.target.value)}
                data-testid="input-llm-model-name"
              />
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block mb-1">Max Tokens</label>
              <input
                type="number"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.llm_max_tokens ?? ""}
                onChange={(e) => handleChange("llm_max_tokens", e.target.value)}
                data-testid="input-llm-max-tokens"
              />
            </div>
            <div>
              <label className="block mb-1">Temperature</label>
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
              <label className="block mb-1">Mode</label>
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
              <label className="block mb-1">Base PCAP Path (filesystem)</label>
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
              <label className="block mb-1">Zeek Log Path</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.security_onion_zeek_log_path ?? ""}
                onChange={(e) => handleChange("security_onion_zeek_log_path", e.target.value)}
                data-testid="input-so-zeek-log-path"
              />
            </div>
            <div>
              <label className="block mb-1">Suricata Log Path</label>
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
              <label className="block mb-1">API URL</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.security_onion_api_url ?? ""}
                onChange={(e) => handleChange("security_onion_api_url", e.target.value)}
                data-testid="input-so-api-url"
              />
            </div>
            <div>
              <label className="block mb-1">API Token</label>
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
              <label className="block mb-1">API URL</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                value={values.arkime_api_url ?? ""}
                onChange={(e) => handleChange("arkime_api_url", e.target.value)}
                data-testid="input-arkime-api-url"
              />
            </div>
            <div>
              <label className="block mb-1">Username</label>
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
              <label className="block mb-1">Password / Token</label>
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
            <label className="block mb-1">File Storage Path</label>
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
  );
};

