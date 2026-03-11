import React, { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type FindingItem, type Severity } from "../api";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-amber-400 bg-amber-400/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-slate-400 bg-slate-400/10",
};

export const FindingsListPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [sevFilter, setSevFilter] = useState<Severity | "">("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "findings", sevFilter, categoryFilter],
    queryFn: () => api.listFindings(jobId!, {
      severity: sevFilter || undefined,
      category: categoryFilter || undefined,
      limit: 200,
    }),
    enabled: !!jobId,
  });

  const queryClient = useQueryClient();
  const feedbackMut = useMutation({
    mutationFn: ({ id, val }: { id: string; val: string | null }) =>
      api.updateFindingFeedback(jobId!, id, val),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] }),
  });

  const findings = data?.items ?? [];
  const categories = Array.from(
    new Set(findings.map((f) => f.category).filter((value): value is string => Boolean(value))),
  ).sort();

  return (
    <div className="space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Findings</span>
      </nav>

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">Findings ({findings.length})</h1>
        <div className="flex items-center gap-2 flex-wrap">
          <select value={sevFilter} onChange={e => setSevFilter(e.target.value as Severity | "")}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
            <option value="">All categories</option>
            {categories.map((category) => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading findings…</p>}
      {error && <p className="text-red-400">Failed to load findings.</p>}
      {!isLoading && findings.length === 0 && (
        <p className="text-slate-500">No findings found for this job.</p>
      )}

      {findings.length > 0 && (
        <div className="space-y-3">
          {findings.map((f: FindingItem) => (
            <div key={f.finding_id} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLORS[f.severity] ?? SEV_COLORS.info}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    {f.category && (
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                        {f.category}
                      </span>
                    )}
                    <h3 className="text-sm font-semibold text-slate-200">{f.title}</h3>
                  </div>
                  {(f.sensor || f.pcap_label) && (
                    <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] text-slate-500">
                      {f.sensor && <span>sensor: <span className="text-slate-300">{f.sensor}</span></span>}
                      {f.pcap_label && <span>pcap: <span className="text-slate-300">{f.pcap_label}</span></span>}
                    </div>
                  )}
                  {f.summary && <p className="text-xs text-slate-400 mt-1 line-clamp-2">{f.summary}</p>}
                </div>

                <div className="flex flex-col items-end gap-2 shrink-0">
                  <span className="text-xs text-slate-600 font-mono">{f.finding_id.slice(0, 8)}</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <button
                      onClick={() => feedbackMut.mutate({ id: f.finding_id, val: "confirmed" })}
                      disabled={feedbackMut.isPending}
                      title="Mark as Confirmed"
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${f.feedback === "confirmed"
                        ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
                        : "bg-slate-800 border-slate-700 text-slate-500 hover:text-emerald-400 hover:border-emerald-500/30"
                      }`}
                    >
                      {f.feedback === "confirmed" ? "✓ Confirmed" : "Confirm"}
                    </button>
                    <button
                      onClick={() => feedbackMut.mutate({ id: f.finding_id, val: "false_positive" })}
                      disabled={feedbackMut.isPending}
                      title="Mark as False Positive"
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${f.feedback === "false_positive"
                        ? "bg-red-500/20 border-red-500/50 text-red-400"
                        : "bg-slate-800 border-slate-700 text-slate-500 hover:text-red-400 hover:border-red-500/30"
                      }`}
                    >
                      {f.feedback === "false_positive" ? "✗ FP" : "FP"}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
