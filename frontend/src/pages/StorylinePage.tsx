import React, { useState } from "react";
import { useParams } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery } from "@tanstack/react-query";
import { api, type StorylineStage } from "../api";

// ── Stage colour config ──────────────────────────────────────────────────────

const STAGE_COLORS: Record<string, { bg: string; border: string; text: string; dot: string }> = {
  recon:            { bg: "bg-blue-900/30",   border: "border-blue-700",   text: "text-blue-300",   dot: "bg-blue-500" },
  initial_access:   { bg: "bg-orange-900/30", border: "border-orange-700", text: "text-orange-300", dot: "bg-orange-500" },
  execution:        { bg: "bg-yellow-900/30", border: "border-yellow-700", text: "text-yellow-300", dot: "bg-yellow-500" },
  persistence:      { bg: "bg-pink-900/30",   border: "border-pink-700",   text: "text-pink-300",   dot: "bg-pink-500" },
  c2:               { bg: "bg-red-900/30",    border: "border-red-700",    text: "text-red-300",    dot: "bg-red-500" },
  lateral_movement: { bg: "bg-purple-900/30", border: "border-purple-700", text: "text-purple-300", dot: "bg-purple-500" },
  credential_access:{ bg: "bg-amber-900/30",  border: "border-amber-700",  text: "text-amber-300",  dot: "bg-amber-500" },
  exfiltration:     { bg: "bg-emerald-900/30",border: "border-emerald-700",text: "text-emerald-300",dot: "bg-emerald-500" },
  impact:           { bg: "bg-rose-900/30",   border: "border-rose-700",   text: "text-rose-300",   dot: "bg-rose-500" },
};

const FALLBACK_COLOR = { bg: "bg-slate-800", border: "border-slate-600", text: "text-slate-300", dot: "bg-slate-500" };

function stageColor(name: string) {
  return STAGE_COLORS[name] ?? FALLBACK_COLOR;
}

// ── Confidence bar ───────────────────────────────────────────────────────────

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = value >= 0.7 ? "bg-red-500" : value >= 0.4 ? "bg-amber-500" : "bg-slate-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-slate-400 font-mono">{pct}%</span>
    </div>
  );
}

// ── Stage card ───────────────────────────────────────────────────────────────

function StageCard({ stage, index }: { stage: StorylineStage; index: number }) {
  const c = stageColor(stage.name);
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="flex items-start gap-3">
      {/* Timeline connector */}
      <div className="flex flex-col items-center pt-1">
        <div className={`w-3 h-3 rounded-full ${c.dot} ring-2 ring-slate-900`} />
        {index < 8 && <div className="w-0.5 flex-1 bg-slate-700 mt-1" />}
      </div>

      {/* Card */}
      <div
        className={`flex-1 ${c.bg} border ${c.border} rounded-lg p-4 mb-3 cursor-pointer hover:brightness-110 transition`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center justify-between mb-2">
          <h3 className={`text-sm font-semibold ${c.text}`}>{stage.display_name}</h3>
          <ConfidenceBar value={stage.confidence} />
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">{stage.summary || "No evidence for this stage."}</p>

        <div className="flex items-center gap-3 mt-2 text-[10px] text-slate-500">
          <span>{stage.node_count} nodes</span>
          <span>{stage.edge_count} edges</span>
          {stage.host_ips.length > 0 && <span>{stage.host_ips.length} hosts</span>}
          {stage.time_start && <span>From {stage.time_start.slice(0, 19)}</span>}
        </div>

        {expanded && stage.host_ips.length > 0 && (
          <div className="mt-3 pt-3 border-t border-slate-700/50">
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Involved Hosts</p>
            <div className="flex flex-wrap gap-1">
              {stage.host_ips.map(ip => (
                <span key={ip} className="px-1.5 py-0.5 text-[10px] font-mono bg-slate-800 text-slate-300 rounded">
                  {ip}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export const StorylinePage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();

  const { data, isLoading, error } = useQuery({
    queryKey: ["storyline", jobId],
    queryFn: () => api.getStoryline(jobId!),
    enabled: !!jobId,
    staleTime: 120_000,
  });

  const activeStages = data?.stages.filter(s => s.node_count > 0) ?? [];

  return (
    <div className="space-y-6">
      <JobSubPageNav jobId={jobId!} currentPath="storyline" />

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold text-white">Attack Storyline</h2>
        {data && (
          <span className="text-xs text-slate-500">
            {data.total_nodes} nodes · {data.total_edges} edges · {data.unclassified_count} unclassified
          </span>
        )}
      </div>

      {isLoading && (
        <div className="space-y-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-24 bg-slate-800 rounded-lg animate-pulse" />
          ))}
        </div>
      )}

      {error && (
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-4 text-sm text-red-300">
          Failed to load storyline: {(error as Error).message}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Kill-chain timeline — left 2/3 */}
          <div className="lg:col-span-2 space-y-0">
            {data.stages.map((stage, i) => (
              <StageCard key={stage.name} stage={stage} index={i} />
            ))}
          </div>

          {/* Right sidebar */}
          <div className="space-y-4">
            {/* Narrative */}
            <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Narrative</h3>
              <p className="text-xs text-slate-400 leading-relaxed whitespace-pre-line">
                {data.narrative || "No narrative generated."}
              </p>
            </div>

            {/* Host timelines */}
            {Object.keys(data.host_timelines).length > 0 && (
              <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Host Timelines</h3>
                <div className="space-y-2">
                  {Object.entries(data.host_timelines).map(([host, stages]) => (
                    <div key={host}>
                      <p className="text-xs font-mono text-slate-300">{host}</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {stages.map(s => {
                          const c = stageColor(s);
                          return (
                            <span key={s} className={`px-1.5 py-0.5 text-[10px] ${c.bg} ${c.text} ${c.border} border rounded`}>
                              {s.replace("_", " ")}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Active stages summary */}
            {activeStages.length > 0 && (
              <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  Active Stages ({activeStages.length})
                </h3>
                <div className="space-y-1">
                  {activeStages.map(s => {
                    const c = stageColor(s.name);
                    return (
                      <div key={s.name} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${c.dot}`} />
                          <span className={`text-xs ${c.text}`}>{s.display_name}</span>
                        </div>
                        <span className="text-[10px] text-slate-500 font-mono">{Math.round(s.confidence * 100)}%</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

