import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type SliceItem, type SliceListResponse } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-700",
  high: "bg-orange-900/40 text-orange-300 border-orange-700",
  medium: "bg-amber-900/40 text-amber-300 border-amber-700",
  low: "bg-slate-800 text-slate-400 border-slate-600",
  info: "bg-slate-800 text-slate-500 border-slate-700",
};

const TYPE_ICONS: Record<string, string> = {
  attack_thread: "🧵",
  c2_session: "📡",
  recon_phase: "🔍",
  lateral: "↔️",
  exfil: "📤",
  misc: "📎",
};

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const color = confidence >= 0.7 ? "bg-green-500" : confidence >= 0.4 ? "bg-amber-500" : "bg-slate-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-500">{pct}%</span>
    </div>
  );
}

function SliceCard({ slice, jobId }: { slice: SliceItem; jobId: string }) {
  const icon = TYPE_ICONS[slice.slice_type] || "🧵";
  const sevClass = SEVERITY_COLORS[slice.severity] || SEVERITY_COLORS.info;
  const totalEvidence = slice.alert_ids.length + slice.finding_ids.length + slice.ioc_ids.length;

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 hover:border-slate-500 transition-colors">
      <div className="flex items-start gap-3">
        <span className="text-2xl">{icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="text-xs text-slate-500 font-mono">#{slice.rank}</span>
            <h3 className="text-sm font-semibold text-slate-100 truncate">{slice.label}</h3>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass}`}>
              {slice.severity.toUpperCase()}
            </span>
          </div>

          {slice.summary && (
            <p className="text-xs text-slate-400 mb-2 line-clamp-2">{slice.summary}</p>
          )}

          <div className="flex items-center gap-3 mb-2">
            <span className="text-[10px] text-slate-500">Confidence:</span>
            <ConfidenceBar confidence={slice.confidence} />
          </div>

          {/* Host IPs */}
          {slice.host_ips.length > 0 && (
            <div className="flex flex-wrap gap-1 mb-2">
              {slice.host_ips.map((ip) => (
                <Link
                  key={ip}
                  to={`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}`}
                  className="text-[10px] px-1.5 py-0.5 bg-cyan-900/30 text-cyan-300 rounded hover:bg-cyan-900/50"
                >
                  {ip}
                </Link>
              ))}
            </div>
          )}

          {/* Evidence counts */}
          <div className="flex gap-3 text-[10px] text-slate-500">
            {slice.alert_ids.length > 0 && (
              <span>🚨 {slice.alert_ids.length} alert(s)</span>
            )}
            {slice.finding_ids.length > 0 && (
              <span>🔎 {slice.finding_ids.length} finding(s)</span>
            )}
            {slice.ioc_ids.length > 0 && (
              <span>⚠️ {slice.ioc_ids.length} IOC(s)</span>
            )}
            {slice.connection_ids.length > 0 && (
              <span>🔗 {slice.connection_ids.length} conn(s)</span>
            )}
          </div>

          {/* Time range */}
          {(slice.time_start || slice.time_end) && (
            <div className="text-[10px] text-slate-600 mt-1">
              {slice.time_start || "?"} → {slice.time_end || "?"}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function SlicesPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const { data, isLoading, error } = useQuery<SliceListResponse>({
    queryKey: ["slices", jobId],
    queryFn: () => api.listSlices(jobId!),
    enabled: !!jobId,
  });

  const regenerate = useMutation({
    mutationFn: () => api.generateSlices(jobId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["slices", jobId] }),
  });

  if (isLoading) return <div className="p-6 text-slate-400">Loading slices…</div>;
  if (error) return <div className="p-6 text-red-400">Error loading slices</div>;

  const slices = data?.items ?? [];

  return (
    <div className="flex gap-6 items-start p-6">
    <div className="max-w-4xl flex-1 min-w-0">
      <nav className="text-sm text-slate-400 mb-4">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Slices</span>
      </nav>

      <div className="flex items-center justify-between mb-4">
        <h2 className={`text-lg font-bold text-slate-100 ${labelHint("slices", activeHelpField)}`} onClick={() => toggleHelp("slices")}>
          Incident Slices <span className="text-slate-500 text-sm font-normal ml-2">({slices.length})</span>
        </h2>
        <button
          onClick={() => regenerate.mutate()}
          disabled={regenerate.isPending}
          className="text-xs px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 disabled:opacity-50"
        >
          {regenerate.isPending ? "Generating…" : "↻ Regenerate"}
        </button>
      </div>

      {slices.length === 0 ? (
        <p className="text-slate-500 text-sm">No slices generated yet. Click Regenerate or run a job analysis.</p>
      ) : (
        <div className="space-y-3">
          {slices.map((s) => (
            <SliceCard key={s.slice_id} slice={s} jobId={jobId!} />
          ))}
        </div>
      )}
    </div>
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
}

