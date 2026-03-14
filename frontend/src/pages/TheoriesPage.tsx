import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type EvidenceRef, type TheoryItem, type TheoryListResponse } from "../api";

const CONFIDENCE_COLORS: Record<string, string> = {
  high: "bg-red-900/40 text-red-300 border-red-700",
  medium: "bg-amber-900/40 text-amber-300 border-amber-700",
  low: "bg-slate-800 text-slate-400 border-slate-600",
};

const HYPOTHESIS_ICONS: Record<string, string> = {
  c2: "📡",
  malware_delivery: "🦠",
  recon: "🔍",
  lateral_movement: "↔️",
  exfiltration: "📤",
  admin_tools: "🔧",
  benign: "✅",
  inconclusive: "❓",
};

function ScoreBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.6 ? "bg-red-500" : score >= 0.3 ? "bg-amber-500" : "bg-slate-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{pct}%</span>
    </div>
  );
}

const EVIDENCE_TYPE_ICONS: Record<string, string> = {
  alert: "🚨",
  finding: "🔎",
  ioc: "💀",
  unknown: "❔",
};

function EvidenceChip({ ref_, jobId, variant }: { ref_: EvidenceRef; jobId: string; variant: "supporting" | "contradicting" }) {
  const icon = EVIDENCE_TYPE_ICONS[ref_.type] || "❔";
  const linkMap: Record<string, string> = {
    alert: `/jobs/${jobId}/alerts`,
    finding: `/jobs/${jobId}/findings`,
    ioc: `/jobs/${jobId}/iocs`,
  };
  const href = linkMap[ref_.type] || `/jobs/${jobId}/findings`;
  const baseClass = variant === "supporting"
    ? "bg-green-900/30 text-green-400 hover:bg-green-900/50"
    : "bg-red-900/30 text-red-400 hover:bg-red-900/50";

  return (
    <Link
      to={href}
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${baseClass}`}
      title={`${ref_.type}: ${ref_.id}`}
    >
      <span>{icon}</span>
      <span className="truncate max-w-[200px]">{ref_.label}</span>
    </Link>
  );
}

function TheoryCard({ theory, jobId }: { theory: TheoryItem; jobId: string }) {
  const icon = HYPOTHESIS_ICONS[theory.hypothesis_type] || "🔬";
  const confClass = CONFIDENCE_COLORS[theory.confidence] || CONFIDENCE_COLORS.low;

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 hover:border-slate-500 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 flex-1">
          <span className="text-2xl">{icon}</span>
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs text-slate-500 font-mono">#{theory.rank}</span>
              <h3 className="text-sm font-semibold text-slate-100">{theory.label}</h3>
            </div>
            <ScoreBar score={theory.score} />
          </div>
        </div>
        <span className={`px-2 py-0.5 text-xs rounded border ${confClass}`}>
          {theory.confidence}
        </span>
      </div>

      {theory.explanation && (
        <p className="mt-3 text-sm text-slate-300 leading-relaxed">{theory.explanation}</p>
      )}

      {theory.supporting_evidence.length > 0 && (
        <div className="mt-3">
          <span className="text-xs text-slate-500 uppercase">Supporting Evidence</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {theory.supporting_evidence.map((ref) => (
              <EvidenceChip key={ref.id} ref_={ref} jobId={jobId} variant="supporting" />
            ))}
          </div>
        </div>
      )}

      {theory.contradicting_evidence.length > 0 && (
        <div className="mt-2">
          <span className="text-xs text-slate-500 uppercase">Contradicting</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {theory.contradicting_evidence.map((ref) => (
              <EvidenceChip key={ref.id} ref_={ref} jobId={jobId} variant="contradicting" />
            ))}
          </div>
        </div>
      )}

      {theory.next_steps.length > 0 && (
        <div className="mt-3">
          <span className="text-xs text-slate-500 uppercase">Recommended Next Steps</span>
          <ul className="mt-1 space-y-1">
            {theory.next_steps.map((step, i) => (
              <li key={i} className="text-xs text-slate-400 flex gap-1.5">
                <span className="text-slate-600">→</span> {step}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export const TheoriesPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ["theories", jobId],
    queryFn: () => api.listJobTheories(jobId!),
    enabled: !!jobId,
  });

  const generateMut = useMutation({
    mutationFn: () => api.generateTheories(jobId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["theories", jobId] }),
  });

  if (isLoading) return <div className="p-6 text-slate-400">Loading theories…</div>;
  if (error) return <div className="p-6 text-red-400">Failed to load theories.</div>;

  const theories = data?.items ?? [];

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Theories</span>
      </nav>

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold text-slate-100">Theory of the Case</h2>
        <button
          onClick={() => generateMut.mutate()}
          disabled={generateMut.isPending}
          className="px-3 py-1.5 text-xs bg-indigo-600 hover:bg-indigo-500 text-white rounded disabled:opacity-50"
        >
          {generateMut.isPending ? "Generating…" : "Re-generate"}
        </button>
      </div>

      <p className="text-sm text-slate-400">
        Ranked hypotheses based on alerts, findings, and IOCs. Scores are deterministic — no AI hallucination.
      </p>

      {theories.length === 0 ? (
        <div className="text-center py-12 text-slate-500">
          No theories generated yet. Click "Re-generate" to analyze evidence.
        </div>
      ) : (
        <div className="space-y-3">
          {theories.map((t) => (
            <TheoryCard key={t.theory_id} theory={t} jobId={jobId!} />
          ))}
        </div>
      )}
    </div>
  );
};

