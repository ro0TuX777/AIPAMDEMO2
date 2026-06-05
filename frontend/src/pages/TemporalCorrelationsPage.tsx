import React, { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type TemporalCorrelationItem } from "../api";
import { JobSubPageNav } from "../components/JobSubPageNav";

const PAGE_SIZE = 200;

/** Link destination for the PCAP side of a correlation row. */
function pcapLinkFor(jobId: string, tc: TemporalCorrelationItem): string {
  if (tc.pcap_entity_type === "alert") {
    return `/jobs/${jobId}/alerts/${encodeURIComponent(tc.pcap_entity_id)}`;
  }
  // Connections don't have a dedicated detail page — jump to the host's
  // Connections tab filtered by the shared IP.
  return `/jobs/${jobId}/hosts/${encodeURIComponent(tc.shared_ip)}/connections`;
}

function fmtTimestamp(ts: string): string {
  return ts.replace("T", " ").replace(/\.\d+Z?$/, "");
}

export const TemporalCorrelationsPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [offset, setOffset] = useState(0);
  const [minScore, setMinScore] = useState(0);

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "temporal-correlations", offset, minScore],
    queryFn: () => api.getTemporalCorrelations(jobId!, { offset, limit: PAGE_SIZE, minScore }),
    enabled: !!jobId,
    placeholderData: (prev) => prev,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-4 sm:p-6 space-y-4 max-w-7xl mx-auto">
      <JobSubPageNav jobId={jobId!} currentPath="correlations" />

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Temporal Correlations
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            What the logs captured vs what the PCAP captured at the same time — linked by shared IP + time window.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <label className="text-slate-400 flex items-center gap-1.5">
            Min match %
            <select
              value={minScore}
              onChange={(e) => { setOffset(0); setMinScore(Number(e.target.value)); }}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
            >
              <option value={0}>Any</option>
              <option value={0.5}>50%</option>
              <option value={0.7}>70%</option>
              <option value={0.9}>90%</option>
            </select>
          </label>
          <span className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
            {total} match{total !== 1 ? "es" : ""}
          </span>
        </div>
      </div>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading correlations…</p>}
      {error && <p className="text-red-400">Failed to load correlations.</p>}
      {!isLoading && items.length === 0 && (
        <div className="rounded border border-slate-800 bg-slate-900/50 p-6 text-center text-slate-400 text-sm">
          No temporal correlations found. This happens when logs and PCAP events share no community_id, 5-tuple, or IP
          within the matching window, or when the job only has one source of telemetry.
        </div>
      )}

      {items.length > 0 && (
        <div className="space-y-2">
          {items.map((tc) => (
            <CorrelationRow key={tc.id} jobId={jobId!} tc={tc} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between pt-2 text-xs">
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            className="px-3 py-1.5 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent"
          >
            ← Previous
          </button>
          <span className="text-slate-500">
            Showing {offset + 1}–{Math.min(offset + items.length, total)} of {total}
          </span>
          <button
            disabled={!data?.page.has_more}
            onClick={() => setOffset(offset + PAGE_SIZE)}
            className="px-3 py-1.5 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-40 disabled:hover:bg-transparent"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
};

// ── Row component ─────────────────────────────────────────────────────────

interface RowProps { jobId: string; tc: TemporalCorrelationItem; }

const CorrelationRow: React.FC<RowProps> = ({ jobId, tc }) => {
  const deltaCls =
    tc.time_delta_seconds < 5 ? "bg-emerald-900/30 text-emerald-400" :
    tc.time_delta_seconds < 15 ? "bg-amber-900/30 text-amber-400" :
    "bg-slate-700 text-slate-400";
  const scoreCls =
    tc.match_score >= 0.8 ? "bg-emerald-900/30 text-emerald-400" :
    tc.match_score >= 0.5 ? "bg-amber-900/30 text-amber-400" :
    "bg-slate-700 text-slate-400";
  const pcapLabel = tc.pcap_entity_type === "alert" ? "ALERT" : "CONNECTION";
  const pcapCls = tc.pcap_entity_type === "alert"
    ? "bg-red-500/20 text-red-400 border-red-500/40"
    : "bg-blue-500/20 text-blue-400 border-blue-500/40";
  const logLink = `/jobs/${jobId}/telemetry/${encodeURIComponent(tc.log_event_id)}`;
  const pcapLink = pcapLinkFor(jobId, tc);

  // Match-type badge: stronger keys are weighted higher and styled distinctly.
  const matchTypeMeta: Record<string, { label: string; cls: string }> = {
    community_id: { label: "community_id", cls: "bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/40" },
    five_tuple: { label: "5-tuple", cls: "bg-sky-500/20 text-sky-300 border-sky-500/40" },
    ip_temporal: { label: "IP + time", cls: "bg-slate-600/40 text-slate-300 border-slate-500/40" },
  };
  const mt = matchTypeMeta[tc.match_type] ?? matchTypeMeta.ip_temporal;
  // Phase labels disagree → highlight as a weaker correlation.
  const labelMismatch = !!tc.log_label && !!tc.pcap_label && tc.log_label !== tc.pcap_label;
  const offset = tc.clock_offset_seconds ?? 0;
  const adjDelta = tc.adjusted_time_delta_seconds;
  const deltaTitle =
    `raw Δ ${tc.time_delta_seconds.toFixed(3)}s` +
    (offset ? ` · clock offset ${offset.toFixed(1)}s · aligned Δ ${(adjDelta ?? tc.time_delta_seconds).toFixed(3)}s` : "");

  return (
    <div className="rounded bg-slate-800/60 border border-slate-700/40 overflow-hidden">
      {/* Header: match type, shared IP, delta, score, labels */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-1.5 bg-slate-800/80 border-b border-slate-700/40 text-[11px]">
        <span className={`px-1.5 py-0.5 rounded border font-mono ${mt.cls}`}
              title={tc.match_keys?.length ? `Matched on: ${tc.match_keys.join(", ")}` : "Match key"}>
          {mt.label}
        </span>
        <span className="px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 font-mono">
          {tc.match_type === "community_id" && tc.community_id ? "cid " : "IP "}
          {tc.match_type === "community_id" && tc.community_id ? tc.community_id : tc.shared_ip}
        </span>
        <span className={`px-1.5 py-0.5 rounded font-mono ${deltaCls}`} title={deltaTitle}>
          Δ {tc.time_delta_seconds < 1 ? "<1" : tc.time_delta_seconds.toFixed(1)}s
          {offset ? "*" : ""}
        </span>
        <span className={`px-1.5 py-0.5 rounded font-mono ${scoreCls}`}
              title={`Composite match score${tc.confidence_band ? ` · ${tc.confidence_band} confidence` : ""}`}>
          {Math.round(tc.match_score * 100)}% match
        </span>
        {(tc.log_label || tc.pcap_label) && (
          <span className={`px-1.5 py-0.5 rounded font-mono ${labelMismatch ? "bg-amber-900/30 text-amber-400" : "bg-slate-700 text-slate-300"}`}
                title={labelMismatch ? "Phase labels disagree" : "Phase labels"}>
            {tc.log_label ?? "—"} {labelMismatch ? "≠" : "="} {tc.pcap_label ?? "—"}
          </span>
        )}
        <span className="text-slate-500 ml-auto font-mono truncate" title={tc.log_event_id}>
          {tc.log_event_id}
        </span>
      </div>
      {/* Side-by-side clickable cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-700/40">
        <Link to={logLink}
              className="p-3 space-y-1 hover:bg-emerald-500/5 transition-colors group"
              title="View full log event">
          <div className="flex items-center gap-2 text-[10px]">
            <span className="px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 font-semibold uppercase tracking-wider group-hover:bg-emerald-500/20">
              LOG says
            </span>
            {tc.log_event_type && (
              <span className="px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-300 uppercase">
                {tc.log_event_type}
              </span>
            )}
            <span className="text-slate-500 font-mono ml-auto" title={tc.log_timestamp}>
              {fmtTimestamp(tc.log_timestamp)}
            </span>
          </div>
          <div className="text-xs text-slate-200 font-mono break-words whitespace-pre-wrap leading-snug"
               title={tc.log_summary ?? undefined}>
            {tc.log_summary || <span className="text-slate-500 italic">(no message captured)</span>}
          </div>
          {(tc.log_source || tc.log_source_filename) && (
            <div className="text-[10px] text-slate-500 font-mono truncate">
              {tc.log_source_filename || tc.log_source}
              {tc.log_source && tc.log_source_filename ? ` · ${tc.log_source}` : ""}
            </div>
          )}
        </Link>
        <Link to={pcapLink}
              className={`p-3 space-y-1 transition-colors group ${
                tc.pcap_entity_type === "alert" ? "hover:bg-red-500/5" : "hover:bg-blue-500/5"
              }`}
              title={tc.pcap_entity_type === "alert" ? "View alert detail" : "View host connections"}>
          <div className="flex items-center gap-2 text-[10px]">
            <span className={`px-1.5 py-0.5 rounded border font-semibold uppercase tracking-wider ${pcapCls}`}>
              PCAP — {pcapLabel}
            </span>
            <span className="text-slate-500 font-mono ml-auto" title={tc.pcap_timestamp}>
              {fmtTimestamp(tc.pcap_timestamp)}
            </span>
          </div>
          <div className="text-xs text-slate-200 font-mono break-words whitespace-pre-wrap leading-snug"
               title={tc.pcap_summary ?? tc.pcap_entity_id}>
            {tc.pcap_summary || tc.pcap_entity_id}
          </div>
          <div className="text-[10px] text-slate-500 font-mono truncate">
            {tc.pcap_entity_id}
          </div>
        </Link>
      </div>
    </div>
  );
};
