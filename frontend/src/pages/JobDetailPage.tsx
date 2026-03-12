import React, { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type JobDetail,
  type JobSummaryResponse,
  type SensorItem,
  type SensorStatus,
  type JobStatus,
} from "../api";
import { useJobEvents } from "../hooks/useJobEvents";

// ─── Constants ──────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  completed: "text-emerald-400 bg-emerald-400/10",
  completed_with_errors: "text-amber-400 bg-amber-400/10",
  running: "text-blue-400 bg-blue-400/10",
  queued: "text-slate-300 bg-slate-400/10",
  failed: "text-red-400 bg-red-400/10",
  canceled: "text-slate-500 bg-slate-500/10",
};

const SENSOR_STATUS_COLORS: Record<SensorStatus, string> = {
  pending: "bg-slate-600",
  running: "bg-blue-500 animate-pulse",
  completed: "bg-emerald-500",
  failed: "bg-red-500",
  skipped: "bg-slate-700",
  timeout: "bg-amber-500",
  canceled: "bg-slate-500",
};

const TERMINAL_STATUSES = new Set<string>([
  "completed", "completed_with_errors", "failed", "canceled", "deleted",
]);

const SUB_TABS = [
  { label: "Hosts", path: "hosts" },
  { label: "Alerts", path: "alerts" },
  { label: "Findings", path: "findings" },
  { label: "Files", path: "files" },
  { label: "Timeline", path: "timeline" },
  { label: "IOCs", path: "iocs" },
  { label: "Graph", path: "graph" },
  { label: "Artifacts", path: "artifacts" },
  { label: "AI Chat", path: "chat" },
  { label: "Report", path: "report" },
] as const;

export const JobDetailPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showRerun, setShowRerun] = useState(false);

  // ── Data fetching ──
  const isTerminal = (s?: string) => TERMINAL_STATUSES.has(s ?? "");

  const jobQ = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) => {
      const status = query.state.data?.job?.status;
      return isTerminal(status) ? false : 5000;
    },
  });

  const job: JobDetail | undefined = jobQ.data?.job;

  const summaryQ = useQuery({
    queryKey: ["job", jobId, "summary"],
    queryFn: () => api.getJobSummary(jobId!),
    enabled: !!jobId && isTerminal(job?.status),
  });

  const sensorsQ = useQuery({
    queryKey: ["job", jobId, "sensors"],
    queryFn: () => api.getJobSensors(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) => isTerminal(job?.status) ? false : 3000,
  });

  // ── SSE for live updates ──
  useJobEvents(jobId, {
    enabled: !!jobId && !isTerminal(job?.status),
  });

  // ── Mutations ──
  const cancelMut = useMutation({
    mutationFn: () => api.cancelJob(jobId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["job", jobId] }),
  });
  const deleteMut = useMutation({
    mutationFn: () => api.deleteJob(jobId!),
    onSuccess: () => navigate("/jobs"),
  });
  const rerunMut = useMutation({
    mutationFn: (profile: string) =>
      api.rerunJob(jobId!, { execution_profile: profile as any }),
    onSuccess: (data) => navigate(`/jobs/${data.job_id}`),
  });

  // ── Loading / Error states ──
  if (jobQ.isLoading) {
    return <div className="text-slate-400 animate-pulse">Loading job details…</div>;
  }
  if (jobQ.error || !job) {
    return (
      <div className="p-4 text-red-400 border border-red-900/50 rounded bg-red-900/10">
        Failed to load job.
        <div className="mt-2">
          <Link to="/jobs" className="text-sm text-slate-400 hover:text-white underline">Back to Jobs</Link>
        </div>
      </div>
    );
  }

  const summary: JobSummaryResponse | undefined = summaryQ.data;
  const sensors: SensorItem[] = sensorsQ.data?.items ?? job.sensors ?? [];

  return (
    <div className="space-y-6">
      {/* Breadcrumbs */}
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">{job.job_id.slice(0, 8)}</span>
      </nav>

      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-semibold text-slate-100">Job Detail</h1>
            <span className={`px-2 py-0.5 rounded-full text-xs font-medium uppercase tracking-wide ${STATUS_COLORS[job.status] ?? "text-slate-400 bg-slate-400/10"}`}>
              {job.status.replace(/_/g, " ")}
            </span>
            {job.execution_profile && (
              <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-300 capitalize">{job.execution_profile}</span>
            )}
          </div>
          <div className="text-sm text-slate-500 font-mono">ID: {job.job_id}</div>
          {job.pcaps && job.pcaps.length > 1 ? (
            <div className="mt-1">
              <div className="text-xs text-slate-500">{job.pcaps.length} PCAPs (Temporal Comparative Analysis)</div>
              <div className="flex flex-wrap gap-2 mt-1">
                {job.pcaps.map((p, i) => (
                  <span key={p.id ?? i} className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-xs">
                    <span className="text-blue-400 font-medium">{p.label || p.filename}</span>
                    <span className="text-slate-500 font-mono">{p.filename}</span>
                    {p.size_bytes ? <span className="text-slate-600">({(p.size_bytes / 1048576).toFixed(1)} MB)</span> : null}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            job.pcap_filename && <div className="text-xs text-slate-500 mt-0.5">PCAP: {job.pcap_filename}</div>
          )}
        </div>
        <div className="flex items-center gap-2">
          {job.status === "running" && (
            <button onClick={() => cancelMut.mutate()} disabled={cancelMut.isPending}
              className="px-3 py-1.5 text-sm rounded border border-amber-500/40 text-amber-400 hover:bg-amber-500/10 disabled:opacity-50">
              {cancelMut.isPending ? "Canceling…" : "Cancel"}
            </button>
          )}
          {isTerminal(job.status) && job.status !== "deleted" && (
            <>
              <a href={api.getExportUrl(job.job_id)} download
                className="px-3 py-1.5 text-sm rounded border border-slate-700 text-slate-300 hover:bg-slate-800 flex items-center gap-1.5">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Export Package
              </a>
              <button onClick={() => setShowRerun(!showRerun)}
                className="px-3 py-1.5 text-sm rounded border border-blue-500/40 text-blue-400 hover:bg-blue-500/10">
                Rerun
              </button>
              <button onClick={() => { if (confirm("Delete this job? This cannot be undone.")) deleteMut.mutate(); }}
                disabled={deleteMut.isPending}
                className="px-3 py-1.5 text-sm rounded border border-red-500/40 text-red-400 hover:bg-red-500/10 disabled:opacity-50">
                {deleteMut.isPending ? "Deleting…" : "Delete"}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Rerun dropdown */}
      {showRerun && (
        <div className="flex items-center gap-2 bg-slate-800/60 rounded px-4 py-2 text-sm">
          <span className="text-slate-300">Rerun with profile:</span>
          {(["triage", "standard", "deep"] as const).map(p => (
            <button key={p} onClick={() => rerunMut.mutate(p)} disabled={rerunMut.isPending}
              className="px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 capitalize disabled:opacity-50">
              {p}
            </button>
          ))}
          {rerunMut.isPending && <span className="text-slate-400 animate-pulse">Creating…</span>}
        </div>
      )}

      {/* Sensor Progress Panel */}
      {sensors.length > 0 && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Sensors</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
            {sensors.map((s) => (
              <div key={s.sensor} className="flex items-center gap-2 p-2 bg-slate-950/50 rounded border border-slate-800/50 group relative cursor-default hover:bg-slate-900/80 transition-colors">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${SENSOR_STATUS_COLORS[s.status] ?? "bg-slate-600"}`} />
                <span className="text-xs text-slate-300 truncate" title={s.sensor}>{s.sensor}</span>
                <span className="text-[10px] text-slate-500 ml-auto capitalize flex items-center gap-1">
                  {s.status}
                  {s.error && <span className="text-red-400 font-bold" title="Hover for details">⚠</span>}
                </span>
                {s.error && (
                  <div className="absolute left-0 top-full mt-2 z-50 hidden group-hover:block w-72 p-3 bg-slate-950/95 border border-red-900/80 rounded shadow-2xl backdrop-blur-md">
                    <div className="flex items-center justify-between mb-1 border-b border-red-900/50 pb-1">
                      <div className="text-xs font-semibold text-red-400">Sensor Error</div>
                      {s.error_code && <div className="text-[9px] font-mono text-slate-500 uppercase">{s.error_code}</div>}
                    </div>
                    <div className="text-[10px] text-red-300/90 whitespace-pre-wrap font-mono break-words max-h-48 overflow-y-auto">
                      {s.error}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
          {/* Progress bar */}
          {(() => {
            const done = sensors.filter(s => ["completed", "failed", "skipped", "timeout", "canceled"].includes(s.status)).length;
            const pct = sensors.length ? Math.round((done / sensors.length) * 100) : 0;
            return (
              <div className="mt-3">
                <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
                  <span>{done}/{sensors.length} sensors complete</span>
                  <span>{pct}%</span>
                </div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* Metrics row */}
      {job.metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {job.metrics.pcap_stats?.packet_count != null && (
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
              <div className="text-xs text-slate-500 uppercase tracking-wider">Packets</div>
              <div className="text-2xl font-bold text-slate-100 mt-1">{job.metrics.pcap_stats.packet_count.toLocaleString()}</div>
            </div>
          )}
          {job.metrics.pcap_stats?.capture_duration_seconds != null && (
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
              <div className="text-xs text-slate-500 uppercase tracking-wider">Capture Duration</div>
              <div className="text-2xl font-bold text-slate-100 mt-1">{job.metrics.pcap_stats.capture_duration_seconds.toFixed(1)}s</div>
            </div>
          )}
          {Object.entries(job.metrics.durations).slice(0, 2).map(([k, v]) => (
            <div key={k} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
              <div className="text-xs text-slate-500 uppercase tracking-wider">{k}</div>
              <div className="text-2xl font-bold text-slate-100 mt-1">{v.toFixed(1)}s</div>
            </div>
          ))}
        </div>
      )}

      {/* Summary Card (only when job is terminal) */}
      {summary && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-slate-100 mb-3">Summary</h2>
          <p className="text-slate-300 mb-4">{summary.headline}</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            {summary.alert_count != null && (
              <div><div className="text-xs text-slate-500 uppercase">Alerts</div><div className="text-xl font-bold text-red-400">{summary.alert_count}</div></div>
            )}
            {summary.finding_count != null && (
              <div><div className="text-xs text-slate-500 uppercase">Findings</div><div className="text-xl font-bold text-amber-400">{summary.finding_count}</div></div>
            )}
            {summary.ioc_count != null && (
              <div><div className="text-xs text-slate-500 uppercase">IOCs</div><div className="text-xl font-bold text-orange-400">{summary.ioc_count}</div></div>
            )}
            {summary.host_count != null && (
              <div><div className="text-xs text-slate-500 uppercase">Hosts</div><div className="text-xl font-bold text-blue-400">{summary.host_count}</div></div>
            )}
          </div>
          {summary.top_signals && summary.top_signals.length > 0 && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 uppercase mb-2">Top Signals</div>
              <ul className="text-sm text-slate-300 space-y-1">
                {summary.top_signals.map((s, i) => <li key={i} className="flex items-start gap-2"><span className="text-slate-500">•</span>{s}</li>)}
              </ul>
            </div>
          )}
          {summary.recommendations && summary.recommendations.length > 0 && (
            <div>
              <div className="text-xs text-slate-500 uppercase mb-2">Recommendations</div>
              <ul className="text-sm text-slate-300 space-y-1">
                {summary.recommendations.map((r, i) => <li key={i} className="flex items-start gap-2"><span className="text-emerald-500">→</span>{r}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Tab Navigation — links to sub-resource pages */}
      <div className="border-b border-slate-800">
        <nav className="flex gap-1 -mb-px" data-testid="jobdetail-tabs">
          {SUB_TABS.map(({ label, path }) => (
            <Link
              key={path}
              to={`/jobs/${jobId}/${path}`}
              className="px-4 py-2 text-sm border-b-2 border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600 transition-colors"
            >
              {label}
            </Link>
          ))}
        </nav>
      </div>

      {/* Stage progress (if available) */}
      {job.stages && job.stages.length > 0 && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Pipeline Stages</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {job.stages.map((stage) => (
              <div key={stage.stage} className="flex items-center gap-2 group relative cursor-default hover:bg-slate-900/80 p-1.5 -m-1.5 rounded transition-colors">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${stage.status === "completed" ? "bg-emerald-500" :
                  stage.status === "running" ? "bg-blue-500 animate-pulse" :
                    stage.status === "failed" ? "bg-red-500" : "bg-slate-700"
                  }`} />
                <span className="text-xs text-slate-300 capitalize flex items-center gap-1">
                  {stage.stage.replace(/_/g, " ")}
                  {stage.error && <span className="text-red-400 font-bold ml-1" title="Hover for details">⚠</span>}
                </span>
                {stage.error && (
                  <div className="absolute right-0 top-full mt-2 z-50 hidden group-hover:block w-72 p-3 bg-slate-950/95 border border-red-900/80 rounded shadow-2xl backdrop-blur-md">
                    <div className="text-xs font-semibold text-red-400 mb-1 border-b border-red-900/50 pb-1">Stage Error</div>
                    <div className="text-[10px] text-red-300/90 whitespace-pre-wrap font-mono break-words max-h-48 overflow-y-auto">
                      {stage.error}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
};
