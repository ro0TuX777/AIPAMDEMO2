import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type ContextAnnotationItem, type ContextAnnotationListResponse } from "../api";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-700",
  high: "bg-orange-900/40 text-orange-300 border-orange-700",
  medium: "bg-amber-900/40 text-amber-300 border-amber-700",
  low: "bg-slate-800 text-slate-400 border-slate-600",
  info: "bg-slate-800 text-slate-500 border-slate-700",
};

const CATEGORY_ICONS: Record<string, string> = {
  traffic: "📊",
  behavioral: "🧠",
  protocol: "🔌",
  alert: "🚨",
  dns: "🌐",
};

function DeviationBadge({ factor }: { factor: number | null }) {
  if (factor == null) return null;
  const color = factor >= 5 ? "text-red-400" : factor >= 3 ? "text-orange-400" : "text-amber-400";
  return <span className={`text-xs font-mono font-bold ${color}`}>{factor.toFixed(1)}σ</span>;
}

function AnnotationCard({ ann, jobId }: { ann: ContextAnnotationItem; jobId: string }) {
  const icon = CATEGORY_ICONS[ann.metric_category] || "📊";
  const sevClass = SEVERITY_COLORS[ann.severity] || SEVERITY_COLORS.info;

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 hover:border-slate-500 transition-colors">
      <div className="flex items-start gap-3">
        <span className="text-2xl">{icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <h3 className="text-sm font-semibold text-slate-100">{ann.title}</h3>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass}`}>
              {ann.severity.toUpperCase()}
            </span>
            <DeviationBadge factor={ann.deviation_factor} />
          </div>

          <Link
            to={`/jobs/${jobId}/hosts/${encodeURIComponent(ann.host_ip)}`}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"
          >
            {ann.host_ip}
          </Link>

          <p className="text-xs text-slate-300 mt-2">{ann.description}</p>
          <p className="text-xs text-slate-500 mt-1 italic">{ann.why_unusual}</p>

          <div className="flex gap-4 mt-2 text-[10px] text-slate-500">
            <span>Observed: <strong className="text-slate-300">{ann.observed_value}</strong></span>
            <span>Baseline: <strong className="text-slate-400">{ann.baseline_value}</strong></span>
            <span>Pop: {ann.population_size} hosts</span>
            <span>Confidence: {Math.round((ann.confidence ?? 0) * 100)}%</span>
          </div>

          {(ann.related_alert_ids.length > 0 || ann.related_finding_ids.length > 0) && (
            <div className="flex gap-3 mt-1 text-[10px] text-slate-500">
              {ann.related_alert_ids.length > 0 && <span>🚨 {ann.related_alert_ids.length} alert(s)</span>}
              {ann.related_finding_ids.length > 0 && <span>🔎 {ann.related_finding_ids.length} finding(s)</span>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function AnnotationsPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery<ContextAnnotationListResponse>({
    queryKey: ["annotations", jobId],
    queryFn: () => api.listAnnotations(jobId!),
    enabled: !!jobId,
  });

  const regenerate = useMutation({
    mutationFn: () => api.generateAnnotations(jobId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["annotations", jobId] }),
  });

  if (isLoading) return <div className="p-6 text-slate-400">Loading annotations…</div>;
  if (error) return <div className="p-6 text-red-400">Error loading annotations</div>;

  const annotations = data?.items ?? [];

  return (
    <div className="p-6 max-w-4xl">
      <nav className="text-sm text-slate-400 mb-4">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Why Unusual?</span>
      </nav>

      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold text-slate-100">
          Why Unusual? <span className="text-slate-500 text-sm font-normal ml-2">({annotations.length})</span>
        </h2>
        <button
          onClick={() => regenerate.mutate()}
          disabled={regenerate.isPending}
          className="text-xs px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 disabled:opacity-50"
        >
          {regenerate.isPending ? "Generating…" : "↻ Regenerate"}
        </button>
      </div>

      {annotations.length === 0 ? (
        <p className="text-slate-500 text-sm">
          No statistical outliers detected. This usually means no host deviates significantly
          from the job-wide baseline, or there are too few hosts for meaningful comparison.
        </p>
      ) : (
        <div className="space-y-3">
          {annotations.map((a) => (
            <AnnotationCard key={a.annotation_id} ann={a} jobId={jobId!} />
          ))}
        </div>
      )}
    </div>
  );
}

