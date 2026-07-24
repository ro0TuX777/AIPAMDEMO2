import React, { useEffect, useState, useCallback } from "react";
import { api, OllamaModelInfo } from "../api";
import { useFocusTrap } from "../hooks/useFocusTrap";

function formatBytes(bytes: number): string {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

interface ModelSetupModalProps {
    onComplete: () => void;
}

export const ModelSetupModal: React.FC<ModelSetupModalProps> = ({ onComplete }) => {
    const [models, setModels] = useState<OllamaModelInfo[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedModel, setSelectedModel] = useState<string>("");
    const [remember, setRemember] = useState(true);
    // Always mounted-open (it only renders when shown), so the trap is active.
    const dialogRef = useFocusTrap<HTMLDivElement>(true);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const fetchModels = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const fetched = await api.getAvailableModels();
            setModels(fetched);
            if (fetched.length === 1) {
                setSelectedModel(fetched[0].name);
            }
        } catch {
            setError("Could not reach Ollama. Make sure it is running.");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchModels();
    }, [fetchModels]);

    const selectedInfo = models.find((m) => m.name === selectedModel);

    const handleContinue = async () => {
        if (!selectedModel) return;
        setSaving(true);
        setError(null);
        try {
            await api.updateSettings({
                llm_model_name: selectedModel,
                forensic_model_name: selectedModel,
                model_configured: remember,
            });
            onComplete();
        } catch {
            setError("Failed to save model selection.");
        } finally {
            setSaving(false);
        }
    };

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center"
            data-testid="model-setup-modal"
        >
            {/* Backdrop */}
            <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm" />

            {/* Modal card */}
            <div
                ref={dialogRef}
                role="dialog"
                aria-modal="true"
                aria-label="First-time model setup"
                className="relative w-full max-w-lg mx-4 rounded-2xl border border-slate-700/60 bg-gradient-to-b from-slate-900 to-slate-950 shadow-2xl shadow-blue-900/20 overflow-hidden"
            >
                {/* Glow accent */}
                <div className="absolute -top-24 left-1/2 -translate-x-1/2 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

                <div className="relative p-8 space-y-6">
                    {/* Header */}
                    <div className="text-center space-y-2">
                        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium tracking-wide uppercase">
                            <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                            First-Time Setup
                        </div>
                        <h2 className="text-2xl font-bold text-white tracking-tight">
                            Welcome to AIPAM
                        </h2>
                        <p className="text-sm text-slate-400 max-w-sm mx-auto">
                            Select a base LLM model from your local Ollama instance to power
                            threat analysis and classification.
                        </p>
                    </div>

                    {/* Model selector */}
                    <div className="space-y-3">
                        <label className="block text-sm font-medium text-slate-300">
                            Available Models
                        </label>

                        {loading ? (
                            <div className="flex items-center justify-center py-8 text-slate-500 text-sm gap-2">
                                <span className="animate-spin inline-block w-4 h-4 border-2 border-slate-500 border-t-transparent rounded-full" />
                                Scanning Ollama…
                            </div>
                        ) : models.length === 0 ? (
                            <div className="rounded-lg border border-amber-700/40 bg-amber-900/20 px-4 py-3 text-sm text-amber-300 space-y-2">
                                <p>No models found. Make sure Ollama is running.</p>
                                <button
                                    type="button"
                                    onClick={fetchModels}
                                    className="rounded bg-amber-700/40 px-3 py-1 text-xs font-medium text-amber-200 hover:bg-amber-700/60 transition-colors"
                                >
                                    ↻ Retry
                                </button>
                            </div>
                        ) : (
                            <>
                                <select
                                    className="w-full rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-colors"
                                    value={selectedModel}
                                    onChange={(e) => setSelectedModel(e.target.value)}
                                    data-testid="select-setup-model"
                                >
                                    <option value="">— Select a model —</option>
                                    {models.map((m) => (
                                        <option key={m.name} value={m.name}>
                                            {m.name} ({m.parameter_size}, {formatBytes(m.size)})
                                        </option>
                                    ))}
                                </select>

                                {/* Model details card */}
                                {selectedInfo && (
                                    <div
                                        className="rounded-lg border border-slate-700/50 bg-slate-800/40 p-3 text-xs text-slate-400 grid grid-cols-2 gap-x-4 gap-y-1 animate-in fade-in"
                                        data-testid="model-details"
                                    >
                                        <span className="text-slate-500">Family</span>
                                        <span className="text-slate-200">{selectedInfo.family}</span>
                                        <span className="text-slate-500">Parameters</span>
                                        <span className="text-slate-200">{selectedInfo.parameter_size}</span>
                                        <span className="text-slate-500">Size</span>
                                        <span className="text-slate-200">{formatBytes(selectedInfo.size)}</span>
                                        <span className="text-slate-500">Quantization</span>
                                        <span className="text-slate-200">{selectedInfo.quantization}</span>
                                    </div>
                                )}
                            </>
                        )}
                    </div>

                    {/* Remember checkbox */}
                    <label
                        className="flex items-center gap-3 cursor-pointer group"
                        data-testid="label-remember"
                    >
                        <input
                            type="checkbox"
                            checked={remember}
                            onChange={(e) => setRemember(e.target.checked)}
                            className="w-4 h-4 rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500/40 focus:ring-offset-0 cursor-pointer"
                            data-testid="checkbox-remember"
                        />
                        <div>
                            <span className="text-sm text-slate-300 group-hover:text-slate-200 transition-colors">
                                Remember this selection
                            </span>
                            <span className="block text-xs text-slate-500 mt-0.5">
                                Uncheck to be prompted again on next launch
                            </span>
                        </div>
                    </label>

                    {/* Error */}
                    {error && (
                        <div className="rounded-lg border border-red-700/40 bg-red-900/20 px-3 py-2 text-sm text-red-400" data-testid="setup-error">
                            {error}
                        </div>
                    )}

                    {/* Actions */}
                    <div className="flex items-center justify-between pt-1">
                        <button
                            type="button"
                            onClick={onComplete}
                            className="text-xs text-slate-500 hover:text-slate-300 transition-colors underline underline-offset-2"
                            data-testid="btn-skip-setup"
                        >
                            Skip for now
                        </button>
                        <button
                            type="button"
                            onClick={handleContinue}
                            disabled={!selectedModel || saving}
                            className="rounded-lg bg-blue-600 px-6 py-2.5 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-lg shadow-blue-900/30 hover:shadow-blue-800/40"
                            data-testid="btn-continue-setup"
                        >
                            {saving ? (
                                <span className="flex items-center gap-2">
                                    <span className="animate-spin inline-block w-3.5 h-3.5 border-2 border-white/40 border-t-white rounded-full" />
                                    Saving…
                                </span>
                            ) : (
                                "Continue →"
                            )}
                        </button>
                    </div>

                    {/* Footer hint */}
                    <p className="text-center text-[11px] text-slate-600">
                        You can change the model anytime from Settings → LLM Settings
                    </p>
                </div>
            </div>
        </div>
    );
};
