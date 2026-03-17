import React, { useEffect, useState } from "react";
import {
    api,
    TrainingLedgerEntry,
    TrainingLedgerResponse,
    TrainingSummary,
    TrainingConfig,
    TrainingStatus,
    PhaseStats,
    DistillConfig,
    DistillStats,
    ExportStatus,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { CardGridSkeleton } from "../components/SkeletonLoader";

// Phase icon mapping
const PHASE_ICONS: Record<string, string> = {
    "6.1": "🛡️",
    "6.2": "🔍",
    "6.3": "⚡",
    "6.4": "🔄",
    "6.0": "📦",
};

const STATUS_COLORS: Record<string, string> = {
    completed: "text-emerald-400 bg-emerald-400/10 border-emerald-500/20",
    running: "text-blue-400 bg-blue-400/10 border-blue-500/20",
    failed: "text-red-400 bg-red-400/10 border-red-500/20",
    info: "text-slate-400 bg-slate-400/10 border-slate-500/20",
};

function timeAgo(ts: string | null | undefined): string {
    if (!ts) return "—";
    const d = new Date(ts);
    const now = new Date();
    const diff = now.getTime() - d.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
}

function formatDate(ts: string | null | undefined): string {
    if (!ts) return "—";
    return new Date(ts).toLocaleString();
}

function formatDuration(seconds: number | null | undefined): string {
    if (seconds == null || seconds < 0) return "—";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

function getPhaseIcon(label: string): string {
    for (const [key, icon] of Object.entries(PHASE_ICONS)) {
        if (label.includes(key)) return icon;
    }
    return "📋";
}

export const TrainingPage: React.FC = () => {
    const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
    const [summary, setSummary] = useState<TrainingSummary | null>(null);
    const [ledger, setLedger] = useState<TrainingLedgerResponse | null>(null);
    const [config, setConfig] = useState<TrainingConfig | null>(null);
    const [trainerStatus, setTrainerStatus] = useState<TrainingStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [showAll, setShowAll] = useState(false);
    const [jobStatus, setJobStatus] = useState<{ type: 'idle' | 'loading' | 'success' | 'error'; message: string }>({ type: 'idle', message: '' });

    // ── Frontier distillation state ──
    const [distillConfig, setDistillConfig] = useState<DistillConfig | null>(null);
    const [distillStats, setDistillStats] = useState<DistillStats | null>(null);
    const [distillOpen, setDistillOpen] = useState(false);
    const [distillForm, setDistillForm] = useState({ endpoint: '', api_key: '', model: '', enabled: false });
    const [distillTestStatus, setDistillTestStatus] = useState<{ type: 'idle' | 'loading' | 'success' | 'error'; message: string }>({ type: 'idle', message: '' });

    // ── Merge & Deploy state ──
    const [exportStatus, setExportStatus] = useState<ExportStatus | null>(null);
    const [exportTriggering, setExportTriggering] = useState(false);

    // Auto-dismiss job status banner
    useEffect(() => {
        if (jobStatus.type === 'success' || jobStatus.type === 'error') {
            const t = setTimeout(() => setJobStatus({ type: 'idle', message: '' }), 8000);
            return () => clearTimeout(t);
        }
    }, [jobStatus]);

    const handleStartTraining = async () => {
        setJobStatus({ type: 'loading', message: 'Starting fine-tuning job…' });
        try {
            const res = await api.startTrainingJob();
            setJobStatus({ type: 'success', message: `Job started — ${res.task_id}` });
        } catch (err: any) {
            setJobStatus({ type: 'error', message: err.message || 'Failed to start job' });
        }
    };

    const handleExport = async () => {
        if (!confirm('Merge LoRA adapters and deploy as a new Ollama model? This may take 5-15 minutes.')) return;
        setExportTriggering(true);
        try {
            await api.exportModel();
            // Start polling export status
        } catch (err: any) {
            alert(`Export failed: ${err.message || 'Unknown error'}`);
        } finally {
            setExportTriggering(false);
        }
    };

    // Poll export status when export is running
    useEffect(() => {
        const poll = async () => {
            try {
                const s = await api.getExportStatus();
                setExportStatus(s);
            } catch { /* ignore */ }
        };
        poll(); // initial fetch
        const interval = setInterval(poll, 3000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        const fetchData = () => {
            Promise.all([
                api.getTrainingSummary(),
                api.getTrainingLedger(),
                api.getTrainingConfig(),
                api.getTrainingStatus().catch(() => null),
                api.getDistillConfig().catch(() => null),
                api.getDistillStats().catch(() => null),
            ])
                .then(([s, l, c, ts, dc, ds]) => {
                    setSummary(s);
                    setLedger(l);
                    setConfig(c);
                    if (ts) setTrainerStatus(ts);
                    if (dc) {
                        setDistillConfig(dc);
                        if (!distillForm.endpoint && !distillForm.model) {
                            setDistillForm({ endpoint: dc.endpoint, api_key: '', model: dc.model, enabled: dc.enabled });
                        }
                    }
                    if (ds) setDistillStats(ds);
                })
                .catch((err) => {
                    console.error(err);
                    if (loading) setError("Failed to load training data. Is the backend running?");
                })
                .finally(() => setLoading(false));
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    if (loading) {
        return (
            <div className="p-6">
                <CardGridSkeleton count={6} />
            </div>
        );
    }

    if (error) {
        return (
            <div className="border border-red-500/30 bg-red-500/5 rounded-xl p-6 text-center">
                <p className="text-red-400">{error}</p>
            </div>
        );
    }

    if (!summary?.has_data) {
        return (
            <div className="flex gap-6 items-start">
            <div className="space-y-6 flex-1 min-w-0">
                <h1 className={`text-2xl font-semibold text-slate-100 ${labelHint("training", activeHelpField)}`} onClick={() => toggleHelp("training")}>
                    Training Intelligence
                </h1>
                <div className="border border-slate-800 rounded-xl p-12 text-center">
                    <div className="text-4xl mb-4">🧠</div>
                    <p className="text-slate-400 text-lg">
                        No training data yet.
                    </p>
                    <p className="text-slate-500 text-sm mt-2 mb-6">
                        Run a training pipeline to see results here.
                    </p>
                    <button
                        onClick={handleStartTraining}
                        disabled={jobStatus.type === 'loading'}
                        className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 inline-flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {jobStatus.type === 'loading' ? 'Starting…' : 'Start New Training'}
                    </button>
                    {jobStatus.type !== 'idle' && (
                        <div className={`mt-3 px-4 py-2.5 rounded-lg text-sm flex items-center justify-between ${jobStatus.type === 'loading' ? 'bg-blue-500/10 border border-blue-500/20 text-blue-300' :
                            jobStatus.type === 'success' ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300' :
                                'bg-red-500/10 border border-red-500/20 text-red-300'
                            }`}>
                            <span>{jobStatus.type === 'loading' ? '⏳' : jobStatus.type === 'success' ? '✓' : '✗'} {jobStatus.message}</span>
                            {jobStatus.type !== 'loading' && (
                                <button onClick={() => setJobStatus({ type: 'idle', message: '' })} className="text-slate-500 hover:text-slate-300 ml-3">✕</button>
                            )}
                        </div>
                    )}
                </div>
            </div>
            <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
            </div>
        );
    }

    const entries = ledger?.entries ?? [];
    const visibleEntries = showAll ? entries : entries.slice(-15).reverse();

    return (
        <div className="flex gap-6 items-start">
        <div className="space-y-6 flex-1 min-w-0">
            <div className="flex items-center justify-between">
                <h1 className={`text-2xl font-semibold text-slate-100 ${labelHint("training", activeHelpField)}`} onClick={() => toggleHelp("training")}>
                    Training Intelligence
                </h1>
                <div className="flex items-center gap-3">
                    {/* Live trainer status badge */}
                    {trainerStatus && (
                        <span className={`px-3 py-1 rounded-full text-xs font-medium border flex items-center gap-1.5 ${trainerStatus.status === 'running'
                            ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                            : trainerStatus.status === 'paused'
                                ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                : trainerStatus.status === 'offline'
                                    ? 'bg-slate-500/10 text-slate-500 border-slate-600/20'
                                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            }`}>
                            <span className={`inline-block w-1.5 h-1.5 rounded-full ${trainerStatus.status === 'running' ? 'bg-blue-400 animate-pulse' :
                                    trainerStatus.status === 'paused' ? 'bg-amber-400' :
                                        trainerStatus.status === 'offline' ? 'bg-slate-500' : 'bg-emerald-400'
                                }`} />
                            {trainerStatus.status === 'running' ? 'Training…' :
                                trainerStatus.status === 'paused' ? 'Paused' :
                                    trainerStatus.status === 'offline' ? 'Trainer Offline' : 'Trainer Idle'}
                        </span>
                    )}
                    <span className="px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-xs font-medium border border-emerald-500/20">
                        {summary.total_events} events logged
                    </span>
                    <button
                        onClick={handleStartTraining}
                        disabled={jobStatus.type === 'loading' || trainerStatus?.status === 'running' || trainerStatus?.status === 'paused'}
                        className="rounded bg-emerald-600 px-3 py-1.5 text-xs font-medium hover:bg-emerald-500 flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {jobStatus.type === 'loading' ? 'Starting…' :
                            trainerStatus?.status === 'running' ? 'Training in Progress' : 'Start Training'}
                    </button>
                </div>
            </div>

            {/* ── Job Status Banner ── */}
            {jobStatus.type !== 'idle' && (
                <div className={`px-4 py-2.5 rounded-lg text-sm flex items-center justify-between transition-all ${jobStatus.type === 'loading' ? 'bg-blue-500/10 border border-blue-500/20 text-blue-300' :
                    jobStatus.type === 'success' ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300' :
                        'bg-red-500/10 border border-red-500/20 text-red-300'
                    }`}>
                    <span>{jobStatus.type === 'loading' ? '⏳' : jobStatus.type === 'success' ? '✓' : '✗'} {jobStatus.message}</span>
                    {jobStatus.type !== 'loading' && (
                        <button onClick={() => setJobStatus({ type: 'idle', message: '' })} className="text-slate-500 hover:text-slate-300 ml-3">✕</button>
                    )}
                </div>
            )}

            {/* ── Training Progress Bar ── */}
            {(trainerStatus?.status === 'running' || trainerStatus?.status === 'paused') && trainerStatus.total_iters > 0 && (() => {
                const isPaused = trainerStatus.status === 'paused';
                const borderColor = isPaused ? 'border-amber-500/20' : 'border-blue-500/20';
                const bgGrad = isPaused
                    ? 'from-amber-500/5 to-orange-500/5'
                    : 'from-blue-500/5 to-indigo-500/5';
                const barGrad = isPaused
                    ? 'from-amber-500 to-orange-500'
                    : 'from-blue-500 to-indigo-500';
                const accentColor = isPaused ? 'text-amber-300' : 'text-blue-300';
                const dotColor = isPaused ? 'bg-amber-400' : 'bg-blue-400';
                return (
                    <div className={`border ${borderColor} bg-gradient-to-r ${bgGrad} rounded-xl p-4 space-y-3`}>
                        <div className="flex items-center justify-between text-sm">
                            <div className="flex items-center gap-2">
                                <span className={`inline-block w-2 h-2 rounded-full ${dotColor} ${isPaused ? '' : 'animate-pulse'}`} />
                                <span className={`${accentColor} font-medium`}>{isPaused ? 'Training Paused' : 'Training in Progress'}</span>
                                <span className="text-slate-500">·</span>
                                <span className="text-slate-400 font-mono text-xs">{trainerStatus.job_id?.slice(0, 8)}</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <span className={`${accentColor} font-semibold`}>{trainerStatus.percent.toFixed(1)}%</span>
                                {/* Pause / Resume button */}
                                <button
                                    onClick={async () => {
                                        try { await api.pauseTraining(); } catch { }
                                    }}
                                    className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${isPaused
                                        ? 'bg-emerald-600/80 hover:bg-emerald-500 text-white'
                                        : 'bg-amber-600/80 hover:bg-amber-500 text-white'
                                        }`}
                                    title={isPaused ? 'Resume training' : 'Pause training'}
                                >
                                    {isPaused ? '▶ Resume' : '⏸ Pause'}
                                </button>
                                {/* Stop button */}
                                <button
                                    onClick={async () => {
                                        if (!confirm('Stop training? This will terminate the current job.')) return;
                                        try {
                                            await api.stopTraining();
                                            setJobStatus({ type: 'error', message: 'Training stopped by user' });
                                        } catch { }
                                    }}
                                    className="px-2.5 py-1 rounded bg-red-600/80 hover:bg-red-500 text-white text-xs font-medium transition-colors"
                                    title="Stop training"
                                >
                                    ⏹ Stop
                                </button>
                            </div>
                        </div>
                        {/* Progress bar */}
                        <div className="relative w-full h-2.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                                className={`absolute inset-y-0 left-0 rounded-full bg-gradient-to-r ${barGrad} transition-all duration-500 ease-out`}
                                style={{ width: `${Math.min(trainerStatus.percent, 100)}%` }}
                            />
                            {!isPaused && (
                                <div
                                    className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-blue-400/30 to-indigo-400/30 animate-pulse"
                                    style={{ width: `${Math.min(trainerStatus.percent, 100)}%` }}
                                />
                            )}
                        </div>
                        {/* Stats row */}
                        <div className="flex items-center justify-between text-xs text-slate-400">
                            <div className="flex items-center gap-4">
                                <span>Iter <span className="text-slate-200 font-mono">{trainerStatus.current_iter}</span>/<span className="font-mono">{trainerStatus.total_iters}</span></span>
                                {trainerStatus.last_loss > 0 && (
                                    <span>Loss <span className="text-amber-400 font-mono">{trainerStatus.last_loss.toFixed(4)}</span></span>
                                )}
                                {trainerStatus.it_per_sec > 0 && (
                                    <span>Speed <span className="text-slate-200 font-mono">{trainerStatus.it_per_sec.toFixed(2)}</span> it/s</span>
                                )}
                            </div>
                            <div className="flex items-center gap-4">
                                <span>Elapsed <span className="text-slate-200 font-mono">{formatDuration(trainerStatus.elapsed_seconds)}</span></span>
                                {trainerStatus.eta_seconds != null && !isPaused && (
                                    <span>ETA <span className="text-blue-300 font-mono">{formatDuration(trainerStatus.eta_seconds)}</span></span>
                                )}
                            </div>
                        </div>
                    </div>
                );
            })()}

            {/* ── Merge & Deploy Panel ── */}
            {(() => {
                const trainingActive = trainerStatus?.status === 'running' || trainerStatus?.status === 'paused';
                const exportRunning = exportStatus?.status === 'running';
                const exportDone = exportStatus?.status === 'completed';
                const exportFailed = exportStatus?.status === 'failed';
                const showPanel = !trainingActive || exportRunning || exportDone || exportFailed;
                if (!showPanel) return null;
                return (
                    <div className={`px-4 py-3 rounded-lg border ${exportDone ? 'border-emerald-500/30 bg-emerald-500/5' : exportFailed ? 'border-red-500/30 bg-red-500/5' : exportRunning ? 'border-purple-500/30 bg-purple-500/5' : 'border-slate-700/50 bg-slate-900/40'}`}>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <span className="text-lg">{exportDone ? '✅' : exportRunning ? '⏳' : exportFailed ? '❌' : '🚀'}</span>
                                <div>
                                    <h4 className="text-sm font-medium text-slate-200">
                                        {exportDone ? `Deployed: ${exportStatus?.model_name}` :
                                         exportRunning ? 'Merging & Deploying…' :
                                         exportFailed ? 'Export Failed' :
                                         'Merge & Deploy to Ollama'}
                                    </h4>
                                    <p className="text-xs text-slate-400 mt-0.5">
                                        {exportDone ? `GGUF model registered with Ollama as ${exportStatus?.model_name}` :
                                         exportRunning ? (exportStatus?.message || 'Processing…') :
                                         exportFailed ? (exportStatus?.message || 'Unknown error') :
                                         'Merge LoRA adapters into base model, quantize to GGUF, and register with Ollama'}
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                {exportRunning && exportStatus?.elapsed_seconds != null && (
                                    <span className="text-xs text-purple-300 font-mono">{formatDuration(exportStatus.elapsed_seconds)}</span>
                                )}
                                {!exportRunning && !exportDone && (
                                    <button
                                        onClick={handleExport}
                                        disabled={exportTriggering || trainerStatus?.status === 'running'}
                                        className="rounded bg-purple-600 px-4 py-1.5 text-xs font-medium hover:bg-purple-500 flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        {exportTriggering ? '⏳ Starting…' : '🚀 Merge & Deploy'}
                                    </button>
                                )}
                                {exportRunning && (
                                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-purple-500/10 text-purple-400 text-xs font-medium border border-purple-500/20">
                                        <span className="inline-block w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
                                        Exporting…
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                );
            })()}

            {/* ── Training Config Bar ── */}
            {config?.configured && (
                <div className="flex flex-wrap items-center gap-x-6 gap-y-1 px-4 py-2.5 rounded-lg border border-slate-700/50 bg-slate-900/40 text-xs">
                    <div className="flex items-center gap-1.5">
                        <span className="text-slate-500">Base Model:</span>
                        <span className="text-slate-200 font-medium">{config.base_model}</span>
                    </div>
                    {config.dataset_url && (
                        <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">Dataset:</span>
                            <a
                                href={config.dataset_url.startsWith("http") ? config.dataset_url : `https://huggingface.co/datasets/${config.dataset_url}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:text-blue-300 underline truncate max-w-[280px]"
                            >
                                {config.dataset_url.split("/").slice(-2).join("/")}
                            </a>
                        </div>
                    )}
                    {config.lora_rank && (
                        <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">LoRA r=</span>
                            <span className="text-slate-300">{config.lora_rank}</span>
                        </div>
                    )}
                    {config.learning_rate && (
                        <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">LR:</span>
                            <span className="text-slate-300">{config.learning_rate}</span>
                        </div>
                    )}
                    {config.max_seq_length && (
                        <div className="flex items-center gap-1.5">
                            <span className="text-slate-500">Context:</span>
                            <span className="text-slate-300">{(config.max_seq_length / 1024).toFixed(0)}k</span>
                        </div>
                    )}
                </div>
            )}

            {/* ── Frontier Knowledge Distillation Card ── */}
            <div className="border border-indigo-500/20 rounded-xl bg-gradient-to-r from-indigo-500/5 to-violet-500/5">
                <button
                    className="w-full px-5 py-4 flex items-center justify-between text-left"
                    onClick={() => setDistillOpen(!distillOpen)}
                >
                    <div className="flex items-center gap-3">
                        <span className="text-xl">🧠</span>
                        <div>
                            <h2 className="text-sm font-semibold text-slate-100">Frontier Knowledge Distillation</h2>
                            <p className="text-xs text-slate-400 mt-0.5">
                                {distillConfig?.enabled && distillConfig?.configured
                                    ? `Active — teaching via ${distillConfig.model}`
                                    : 'Train your model using a smarter frontier model'}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-3">
                        {distillStats && distillStats.total_samples > 0 && (
                            <span className="px-2.5 py-1 rounded-full bg-violet-500/10 text-violet-400 text-xs font-medium border border-violet-500/20">
                                {distillStats.total_samples} distilled samples
                            </span>
                        )}
                        <span className={`text-slate-400 transition-transform ${distillOpen ? 'rotate-180' : ''}`}>▾</span>
                    </div>
                </button>

                {distillOpen && (
                    <div className="px-5 pb-5 space-y-4 border-t border-indigo-500/10 pt-4">
                        <p className="text-xs text-slate-400">
                            Configure a frontier model (GPT-4o, Claude, etc.) as a "teacher." When enabled, every PCAP analysis
                            will also be sent to the teacher — its superior responses become gold-standard training data for your
                            local model.
                        </p>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            <div>
                                <label className="block text-xs text-slate-500 mb-1">API Endpoint</label>
                                <input
                                    type="text"
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
                                    placeholder="https://api.openai.com/v1/chat/completions"
                                    value={distillForm.endpoint}
                                    onChange={e => setDistillForm(f => ({ ...f, endpoint: e.target.value }))}
                                />
                            </div>
                            <div>
                                <label className="block text-xs text-slate-500 mb-1">Model Name</label>
                                <input
                                    type="text"
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
                                    placeholder="gpt-4o"
                                    value={distillForm.model}
                                    onChange={e => setDistillForm(f => ({ ...f, model: e.target.value }))}
                                />
                            </div>
                            <div>
                                <label className="block text-xs text-slate-500 mb-1">
                                    API Key {distillConfig?.api_key_set && <span className="text-emerald-400 ml-1">✓ set ({distillConfig.api_key_preview})</span>}
                                </label>
                                <input
                                    type="password"
                                    className="w-full bg-slate-800/50 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
                                    placeholder="sk-..."
                                    value={distillForm.api_key}
                                    onChange={e => setDistillForm(f => ({ ...f, api_key: e.target.value }))}
                                />
                            </div>
                            <div className="flex items-end gap-3">
                                <label className="flex items-center gap-2 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={distillForm.enabled}
                                        onChange={e => setDistillForm(f => ({ ...f, enabled: e.target.checked }))}
                                        className="rounded bg-slate-800 border-slate-600 text-indigo-500 focus:ring-indigo-500/30"
                                    />
                                    <span className="text-sm text-slate-300">Enable auto-distillation</span>
                                </label>
                            </div>
                        </div>

                        <div className="flex items-center gap-3">
                            <button
                                onClick={async () => {
                                    const payload: Record<string, any> = {};
                                    if (distillForm.endpoint) payload.endpoint = distillForm.endpoint;
                                    if (distillForm.api_key) payload.api_key = distillForm.api_key;
                                    if (distillForm.model) payload.model = distillForm.model;
                                    payload.enabled = distillForm.enabled;
                                    try {
                                        await api.updateDistillConfig(payload);
                                        setDistillTestStatus({ type: 'success', message: 'Configuration saved' });
                                        // Refresh config
                                        const dc = await api.getDistillConfig();
                                        setDistillConfig(dc);
                                    } catch (err: any) {
                                        setDistillTestStatus({ type: 'error', message: err.message || 'Save failed' });
                                    }
                                }}
                                className="px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-500 text-sm font-medium text-white transition-colors"
                            >
                                Save Configuration
                            </button>
                            <button
                                onClick={async () => {
                                    setDistillTestStatus({ type: 'loading', message: 'Testing connection…' });
                                    try {
                                        const res = await api.testTeacher();
                                        setDistillTestStatus({ type: 'success', message: `Connected to ${res.model}` });
                                    } catch (err: any) {
                                        setDistillTestStatus({ type: 'error', message: err.message || 'Connection failed' });
                                    }
                                }}
                                disabled={distillTestStatus.type === 'loading'}
                                className="px-4 py-2 rounded border border-slate-600 hover:border-slate-500 text-sm text-slate-300 transition-colors disabled:opacity-50"
                            >
                                {distillTestStatus.type === 'loading' ? 'Testing…' : '🔗 Test Connection'}
                            </button>
                            {distillTestStatus.type !== 'idle' && distillTestStatus.type !== 'loading' && (
                                <span className={`text-xs ${distillTestStatus.type === 'success' ? 'text-emerald-400' : 'text-red-400'}`}>
                                    {distillTestStatus.type === 'success' ? '✓' : '✗'} {distillTestStatus.message}
                                </span>
                            )}
                        </div>

                        {distillStats && distillStats.total_samples > 0 && (
                            <div className="space-y-3 mt-2">
                                <div className="grid grid-cols-4 gap-3">
                                    <div className="bg-slate-900/50 rounded-lg px-3 py-2">
                                        <div className="text-lg font-bold text-violet-400">{distillStats.total_samples}</div>
                                        <div className="text-xs text-slate-500">Validated Samples</div>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg px-3 py-2">
                                        <div className="text-lg font-bold text-red-400">{distillStats.rejected_count || 0}</div>
                                        <div className="text-xs text-slate-500">Rejected</div>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg px-3 py-2">
                                        <div className="text-lg font-bold text-slate-200">{distillStats.file_size_mb} MB</div>
                                        <div className="text-xs text-slate-500">Data Size</div>
                                    </div>
                                    <div className="bg-slate-900/50 rounded-lg px-3 py-2">
                                        <div className="text-lg font-bold text-slate-200 text-sm truncate">{distillStats.teacher_models.join(', ') || '—'}</div>
                                        <div className="text-xs text-slate-500">Teacher Model</div>
                                    </div>
                                </div>
                                {distillStats.per_task && Object.keys(distillStats.per_task).length > 0 && (
                                    <div>
                                        <div className="text-xs text-slate-500 mb-1.5">Per-Task Breakdown</div>
                                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
                                            {Object.entries(distillStats.per_task).sort(([,a],[,b]) => b - a).map(([task, count]) => (
                                                <div key={task} className="bg-slate-800/50 rounded px-2.5 py-1.5 flex items-center justify-between">
                                                    <span className="text-xs text-slate-400 truncate">{task.replace(/_/g, ' ')}</span>
                                                    <span className="text-xs font-medium text-violet-300 ml-2">{count}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* ── Section 1: Active Model Card ── */}
            {summary.active_model && (
                <div
                    className="relative overflow-hidden rounded-xl border border-slate-700/50"
                    style={{
                        background:
                            "linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(59,130,246,0.06) 100%)",
                    }}
                >
                    <div className="px-6 py-5">
                        <div className="flex items-start justify-between">
                            <div>
                                <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">
                                    Active Model
                                </div>
                                <h2 className="text-lg font-semibold text-slate-100">
                                    {summary.active_model.name}
                                </h2>
                                <p className="text-sm text-slate-400 mt-0.5">
                                    {summary.active_model.phase}
                                </p>
                            </div>
                            <div className="flex items-center gap-2">
                                {summary.active_model.dawn_seed && (
                                    <span className="px-2 py-0.5 rounded bg-violet-500/10 text-violet-400 text-xs border border-violet-500/20">
                                        DAWN {summary.active_model.dawn_seed}
                                    </span>
                                )}
                            </div>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5">
                            {summary.active_model.context_window && (
                                <div className="bg-slate-900/40 rounded-lg px-3 py-2">
                                    <div className="text-xs text-slate-500">Context</div>
                                    <div className="text-sm font-medium text-slate-200">
                                        {(summary.active_model.context_window / 1024).toFixed(0)}k
                                        tokens
                                    </div>
                                </div>
                            )}
                            {summary.active_model.lora_r && (
                                <div className="bg-slate-900/40 rounded-lg px-3 py-2">
                                    <div className="text-xs text-slate-500">LoRA Rank</div>
                                    <div className="text-sm font-medium text-slate-200">
                                        r={summary.active_model.lora_r} α=
                                        {summary.active_model.lora_alpha}
                                    </div>
                                </div>
                            )}
                            {summary.active_model.loss != null && (
                                <div className="bg-slate-900/40 rounded-lg px-3 py-2">
                                    <div className="text-xs text-slate-500">Final Loss</div>
                                    <div className="text-sm font-medium text-emerald-400">
                                        {summary.active_model.loss.toFixed(4)}
                                    </div>
                                </div>
                            )}
                            {summary.active_model.config_hash && (
                                <div className="bg-slate-900/40 rounded-lg px-3 py-2">
                                    <div className="text-xs text-slate-500">Config Hash</div>
                                    <div
                                        className="text-sm font-mono text-slate-300 truncate"
                                        title={summary.active_model.config_hash}
                                    >
                                        {summary.active_model.config_hash.slice(0, 20)}…
                                    </div>
                                </div>
                            )}
                        </div>

                        {summary.active_model.trained_at && (
                            <div className="mt-3 text-xs text-slate-500">
                                Trained {timeAgo(summary.active_model.trained_at)} —{" "}
                                {formatDate(summary.active_model.trained_at)}
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* ── Section 2: Phase Statistics ── */}
            <div>
                <h2 className="text-lg font-semibold text-slate-200 mb-3">
                    Phase Statistics
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {Object.entries(summary.phase_counts)
                        .sort(([a], [b]) => a.localeCompare(b))
                        .map(([phase, stats]) => (
                            <PhaseCard key={phase} phase={phase} stats={stats} />
                        ))}
                </div>
            </div>

            {/* ── Section 3: Self-Healing Status ── */}
            {summary.self_healing && (
                <div className="border border-amber-500/20 bg-amber-500/5 rounded-xl px-6 py-4">
                    <div className="flex items-center gap-2 mb-3">
                        <span className="text-lg">🔄</span>
                        <h2 className="text-lg font-semibold text-slate-200">
                            Self-Healing Loop
                        </h2>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        <div>
                            <div className="text-xs text-slate-500">Runs</div>
                            <div className="text-xl font-semibold text-amber-400">
                                {summary.self_healing.runs}
                            </div>
                        </div>
                        <div>
                            <div className="text-xs text-slate-500">Synthetic PCAPs</div>
                            <div className="text-xl font-semibold text-amber-400">
                                {summary.self_healing.total_synthetic_pcaps.toLocaleString()}
                            </div>
                        </div>
                        <div className="col-span-2">
                            <div className="text-xs text-slate-500">Families Augmented</div>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                                {summary.self_healing.families_augmented.map((f) => (
                                    <span
                                        key={f}
                                        className="px-2 py-0.5 rounded bg-amber-400/10 text-amber-300 text-xs border border-amber-500/20"
                                    >
                                        {f}
                                    </span>
                                ))}
                            </div>
                        </div>
                    </div>
                    {summary.self_healing.latest_timestamp && (
                        <div className="mt-3 text-xs text-slate-500">
                            Last run: {formatDate(summary.self_healing.latest_timestamp)}
                        </div>
                    )}
                </div>
            )}

            {/* ── Section 4: Training Timeline ── */}
            <div>
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-lg font-semibold text-slate-200">
                        Training Timeline
                    </h2>
                    {entries.length > 15 && (
                        <button
                            onClick={() => setShowAll(!showAll)}
                            className="text-xs text-emerald-400 hover:text-emerald-300 font-medium transition-colors"
                        >
                            {showAll
                                ? `Show Latest 15`
                                : `Show All ${entries.length}`}
                        </button>
                    )}
                </div>

                <div className="border border-slate-800 rounded-xl overflow-hidden">
                    <table className="w-full text-left text-sm">
                        <thead className="bg-slate-900/50 text-slate-400 border-b border-slate-800">
                            <tr>
                                <th className="px-4 py-3 font-medium">Time</th>
                                <th className="px-4 py-3 font-medium">Event</th>
                                <th className="px-4 py-3 font-medium">Phase</th>
                                <th className="px-4 py-3 font-medium hidden md:table-cell">
                                    Model
                                </th>
                                <th className="px-4 py-3 font-medium hidden lg:table-cell">
                                    Config Hash
                                </th>
                                <th className="px-4 py-3 font-medium">Metrics</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                            {visibleEntries.length === 0 ? (
                                <tr>
                                    <td
                                        colSpan={6}
                                        className="px-4 py-8 text-center text-slate-500"
                                    >
                                        No events recorded yet
                                    </td>
                                </tr>
                            ) : (
                                visibleEntries.map((entry, i) => (
                                    <TimelineRow key={i} entry={entry} />
                                ))
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* ── Meta Info ── */}
            {summary.models.length > 0 && (
                <div className="text-xs text-slate-600 flex items-center gap-4">
                    <span>
                        Models:{" "}
                        {summary.models.map((m) => m.split("/").pop()).join(", ")}
                    </span>
                    {summary.peak_vram_gb && (
                        <span>Peak VRAM: {summary.peak_vram_gb.toFixed(1)} GB</span>
                    )}
                </div>
            )}
        </div>
        <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
        </div>
    );
};

/* ── Sub-components ── */

const PhaseCard: React.FC<{ phase: string; stats: PhaseStats }> = ({
    phase,
    stats,
}) => {
    const icon = getPhaseIcon(phase);
    const hasFailures = stats.failed > 0;

    return (
        <div className="border border-slate-800 rounded-xl px-4 py-3 bg-slate-900/30 hover:bg-slate-900/50 transition-colors">
            <div className="flex items-center gap-2 mb-2">
                <span className="text-base">{icon}</span>
                <span className="text-sm font-medium text-slate-200 truncate">
                    {phase}
                </span>
            </div>
            <div className="flex items-baseline gap-3">
                <div>
                    <span className="text-2xl font-bold text-slate-100">
                        {stats.completed}
                    </span>
                    <span className="text-xs text-slate-500 ml-1">completed</span>
                </div>
                {hasFailures && (
                    <div>
                        <span className="text-sm font-medium text-red-400">
                            {stats.failed}
                        </span>
                        <span className="text-xs text-slate-500 ml-0.5">failed</span>
                    </div>
                )}
            </div>
            {stats.latest_loss != null && (
                <div className="mt-2 text-xs text-slate-500">
                    Loss: <span className="text-emerald-400">{stats.latest_loss.toFixed(4)}</span>
                </div>
            )}
            {stats.latest_timestamp && (
                <div className="mt-1 text-xs text-slate-600">
                    {timeAgo(stats.latest_timestamp)}
                </div>
            )}
        </div>
    );
};

const TimelineRow: React.FC<{ entry: TrainingLedgerEntry }> = ({ entry }) => {
    const statusClass = STATUS_COLORS[entry.status] ?? STATUS_COLORS.info;
    const metrics = entry.metrics ?? {};
    const metricsStr = Object.entries(metrics)
        .filter(([k]) => ["train_loss", "eval_loss", "peak_vram_gb", "total_pcaps", "simulations"].includes(k))
        .map(([k, v]) => {
            const label = k.replace(/_/g, " ").replace("train ", "").replace("eval ", "eval ");
            return `${label}: ${typeof v === "number" ? v.toFixed(4) : v}`;
        })
        .join(" · ");

    return (
        <tr className="hover:bg-slate-800/30 transition-colors">
            <td className="px-4 py-2.5 text-slate-400 text-xs whitespace-nowrap">
                {formatDate(entry.timestamp)}
            </td>
            <td className="px-4 py-2.5">
                <span
                    className={`px-2 py-0.5 rounded-full text-xs font-medium border ${statusClass}`}
                >
                    {entry.event_type}
                </span>
            </td>
            <td className="px-4 py-2.5 text-slate-300 text-xs">
                {entry.phase_label}
            </td>
            <td className="px-4 py-2.5 text-slate-400 text-xs hidden md:table-cell truncate max-w-[200px]">
                {entry.base_model?.split("/").pop() ?? "—"}
            </td>
            <td className="px-4 py-2.5 font-mono text-slate-600 text-xs hidden lg:table-cell truncate max-w-[140px]">
                {entry.config_hash ? entry.config_hash.slice(7, 19) + "…" : "—"}
            </td>
            <td className="px-4 py-2.5 text-slate-400 text-xs truncate max-w-[180px]">
                {metricsStr || "—"}
            </td>
        </tr>
    );
};
