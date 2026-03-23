import React, { useState, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type EvidenceRef,
  type TheoryItem,
  type ScoreBreakdown,
  type SliceItem,
  type HostListItem,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";
import { CardGridSkeleton } from "../components/SkeletonLoader";

// ── Constants ────────────────────────────────────────────────────────────────

const CONFIDENCE_COLORS: Record<string, string> = {
  high: "bg-red-900/40 text-red-300 border-red-700",
  medium: "bg-amber-900/40 text-amber-300 border-amber-700",
  low: "bg-slate-800 text-slate-400 border-slate-600",
};

const HYPOTHESIS_SHORT: Record<string, string> = {
  c2: "C2",
  malware_delivery: "MAL",
  recon: "RCN",
  lateral_movement: "LAT",
  exfiltration: "EXF",
  admin_tools: "ADM",
  benign: "OK",
  inconclusive: "?",
};

// 1️⃣ MITRE ATT&CK mapping
const MITRE_MAP: Record<string, { tactic: string; id: string }> = {
  c2: { tactic: "Command and Control", id: "TA0011" },
  malware_delivery: { tactic: "Initial Access", id: "TA0001" },
  recon: { tactic: "Reconnaissance", id: "TA0043" },
  lateral_movement: { tactic: "Lateral Movement", id: "TA0008" },
  exfiltration: { tactic: "Exfiltration", id: "TA0010" },
  admin_tools: { tactic: "Execution", id: "TA0002" },
};

const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  alert: "ALR", finding: "FND", ioc: "IOC", unknown: "—",
};

const HYP_COLORS: Record<string, string> = {
  c2: "bg-red-500", malware_delivery: "bg-orange-500", recon: "bg-blue-500",
  lateral_movement: "bg-purple-500", exfiltration: "bg-yellow-500",
  admin_tools: "bg-teal-500", benign: "bg-green-500", inconclusive: "bg-slate-500",
};

// ── Small components ─────────────────────────────────────────────────────────

function MitreBadge({ hypothesisType }: { hypothesisType: string }) {
  const m = MITRE_MAP[hypothesisType];
  if (!m) return null;
  return (
    <a
      href={`https://attack.mitre.org/tactics/${m.id}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono bg-indigo-900/40 text-indigo-300 border border-indigo-700 rounded hover:bg-indigo-900/60"
      title={m.tactic}
    >
      {m.id}
    </a>
  );
}

// 9️⃣ Score breakdown tooltip
function ScoreBar({ score, breakdown }: { score: number; breakdown?: ScoreBreakdown | null }) {
  const pct = Math.round(score * 100);
  const color = score >= 0.6 ? "bg-red-500" : score >= 0.3 ? "bg-amber-500" : "bg-slate-500";
  const [showTip, setShowTip] = useState(false);

  const tipText = useMemo(() => {
    if (!breakdown) return `Score: ${pct}%`;
    const parts: string[] = [];
    if (breakdown.finding_count) parts.push(`${breakdown.finding_count} finding(s) → ${Math.round(breakdown.findings * 100)}%`);
    if (breakdown.alert_count) parts.push(`${breakdown.alert_count} alert(s) → ${Math.round(breakdown.alerts * 100)}%`);
    if (breakdown.ioc_count) parts.push(`${breakdown.ioc_count} IOC(s) → ${Math.round(breakdown.iocs * 100)}%`);
    if (breakdown.reason) parts.push(breakdown.reason);
    return parts.length ? parts.join("\n") : `Score: ${pct}%`;
  }, [breakdown, pct]);

  return (
    <div className="relative flex items-center gap-2"
      onMouseEnter={() => setShowTip(true)} onMouseLeave={() => setShowTip(false)}>
      <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400">{pct}%</span>
      {showTip && (
        <div className="absolute left-0 top-full mt-1 z-20 bg-slate-800 border border-slate-600 rounded px-3 py-2 text-xs text-slate-300 whitespace-pre-wrap shadow-lg min-w-[200px]">
          {tipText}
        </div>
      )}
    </div>
  );
}

function EvidenceChip({ ref_, jobId, variant }: { ref_: EvidenceRef; jobId: string; variant: "supporting" | "contradicting" }) {
  const label = EVIDENCE_TYPE_LABELS[ref_.type] || "—";
  // Deep-link to the specific evidence item (findings and alerts have detail pages; IOCs go to list)
  const hrefMap: Record<string, string> = {
    alert: `/jobs/${jobId}/alerts/${encodeURIComponent(ref_.id)}`,
    finding: `/jobs/${jobId}/findings/${encodeURIComponent(ref_.id)}`,
    ioc: `/jobs/${jobId}/iocs`,
  };
  const href = hrefMap[ref_.type] || `/jobs/${jobId}/findings`;
  const baseClass = variant === "supporting"
    ? "bg-green-900/30 text-green-400 hover:bg-green-900/50"
    : "bg-red-900/30 text-red-400 hover:bg-red-900/50";
  return (
    <Link to={href} className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${baseClass}`}
      title={`${ref_.type}: ${ref_.id}`}>
      <span className="font-mono text-[10px] opacity-70">{label}</span>
      <span className="truncate max-w-[200px]">{ref_.label}</span>
    </Link>
  );
}

// 2️⃣ Evidence summary bar
function EvidenceSummaryBar({ theories }: { theories: TheoryItem[] }) {
  const { supporting, contradicting, theoryCount } = useMemo(() => {
    let sup = 0, con = 0;
    for (const t of theories) { sup += t.supporting_evidence.length; con += t.contradicting_evidence.length; }
    return { supporting: sup, contradicting: con, theoryCount: theories.length };
  }, [theories]);
  if (!theories.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-4 px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-lg text-xs">
      <span className="text-slate-400">{theoryCount} hypothes{theoryCount === 1 ? "is" : "es"}</span>
      <span className="text-green-400">{supporting} supporting</span>
      <span className="text-red-400">{contradicting} contradicting</span>
    </div>
  );
}

// 7️⃣ Distribution chart — horizontal bars
function DistributionChart({ theories }: { theories: TheoryItem[] }) {
  if (!theories.length) return null;
  const maxScore = Math.max(...theories.map(t => t.score), 0.01);
  return (
    <div className="bg-slate-800/40 border border-slate-700 rounded-lg p-4">
      <h3 className="text-xs text-slate-500 uppercase mb-3">Hypothesis Distribution</h3>
      <div className="space-y-2">
        {theories.map(t => {
          const tag = HYPOTHESIS_SHORT[t.hypothesis_type] || "?";
          const barColor = HYP_COLORS[t.hypothesis_type] || "bg-slate-500";
          const widthPct = Math.max((t.score / maxScore) * 100, 2);
          return (
            <div key={t.theory_id} className="flex items-center gap-2">
              <span className="w-8 text-right text-[10px] font-mono text-slate-500">{tag}</span>
              <div className="flex-1 h-3 bg-slate-700/60 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${barColor} opacity-80`} style={{ width: `${widthPct}%` }} />
              </div>
              <span className="w-10 text-right text-[10px] text-slate-400">{Math.round(t.score * 100)}%</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// 8️⃣ Related slices helper
function RelatedSliceLinks({ theory, slices, jobId }: { theory: TheoryItem; slices: SliceItem[]; jobId: string }) {
  const related = useMemo(() => {
    const supIds = new Set(theory.supporting_evidence.map(e => e.id));
    return slices.filter(s =>
      s.host_ips?.some(ip => theory.scope_id === ip) ||
      s.community_ids?.some(c => supIds.has(c))
    );
  }, [theory, slices]);
  if (!related.length) return null;
  return (
    <div className="mt-2">
      <span className="text-xs text-slate-500 uppercase">Related Slices</span>
      <div className="flex flex-wrap gap-1 mt-1">
        {related.map(s => (
          <Link key={s.slice_id} to={`/jobs/${jobId}/slices`}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-xs bg-cyan-900/30 text-cyan-400 hover:bg-cyan-900/50 rounded">
            {s.label}
          </Link>
        ))}
      </div>
    </div>
  );
}

// 3️⃣ + 5️⃣ Collapsible theory card with LLM explain
function TheoryCard({ theory, jobId, slices, defaultExpanded }: {
  theory: TheoryItem; jobId: string; slices: SliceItem[]; defaultExpanded: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const { addToast } = useToast();
  const queryClient = useQueryClient();

  const explainMut = useMutation({
    mutationFn: () => api.explainTheory(jobId, theory.theory_id),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["theories", jobId] });
      addToast({ severity: "info", title: "Explanation generated", body: res.source === "llm" ? "LLM explanation" : "Deterministic explanation" });
    },
    onError: () => addToast({ severity: "high", title: "Explain failed", body: "Could not generate explanation." }),
  });

  const tag = HYPOTHESIS_SHORT[theory.hypothesis_type] || "UNK";
  const confClass = CONFIDENCE_COLORS[theory.confidence] || CONFIDENCE_COLORS.low;
  const mitre = MITRE_MAP[theory.hypothesis_type];

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg hover:border-slate-500 transition-colors">
      {/* Compact header — always visible */}
      <button className="w-full text-left p-4 flex items-start justify-between gap-3"
        onClick={() => setExpanded(e => !e)}>
        <div className="flex items-start gap-3 flex-1">
          <span className="text-xs font-mono font-bold text-slate-400 bg-slate-800 rounded px-1.5 py-0.5">{tag}</span>
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="text-xs text-slate-500 font-mono">#{theory.rank}</span>
              <h3 className="text-sm font-semibold text-slate-100">{theory.label}</h3>
              {/* 1️⃣ MITRE badge */}
              {mitre && <MitreBadge hypothesisType={theory.hypothesis_type} />}
            </div>
            <ScoreBar score={theory.score} breakdown={theory.score_breakdown} />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 text-xs rounded border ${confClass}`}>{theory.confidence}</span>
          <span className="text-slate-500 text-xs">{expanded ? "▲" : "▼"}</span>
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-800 pt-3">
          {/* 5️⃣ Explanation + explain button */}
          {theory.explanation ? (
            <p className="text-sm text-slate-300 leading-relaxed">{theory.explanation}</p>
          ) : (
            <button onClick={() => explainMut.mutate()} disabled={explainMut.isPending}
              className="px-2.5 py-1 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded disabled:opacity-50">
              {explainMut.isPending ? "Generating…" : "🔍 Generate Explanation"}
            </button>
          )}

          {theory.supporting_evidence.length > 0 && (
            <div>
              <span className="text-xs text-slate-500 uppercase">Supporting Evidence</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {theory.supporting_evidence.map(ref => (
                  <EvidenceChip key={ref.id} ref_={ref} jobId={jobId} variant="supporting" />
                ))}
              </div>
            </div>
          )}

          {theory.contradicting_evidence.length > 0 && (
            <div>
              <span className="text-xs text-slate-500 uppercase">Contradicting</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {theory.contradicting_evidence.map(ref => (
                  <EvidenceChip key={ref.id} ref_={ref} jobId={jobId} variant="contradicting" />
                ))}
              </div>
            </div>
          )}

          {theory.next_steps.length > 0 && (
            <div>
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

          {/* 8️⃣ Related slices */}
          <RelatedSliceLinks theory={theory} slices={slices} jobId={jobId} />
        </div>
      )}
    </div>
  );
}


// ── Main page ──────────────────────────────────────────────────────────────

export const TheoriesPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const { addToast } = useToast();

  // 4️⃣ Scope toggle: job vs host
  const [scopeType, setScopeType] = useState<"job" | "host">("job");
  const [selectedHost, setSelectedHost] = useState<string | null>(null);

  // 6️⃣ Temporal tabs
  const [activeLabel, setActiveLabel] = useState<string | null>(null);

  // Fetch job detail for pcap labels
  const { data: jobData } = useQuery({
    queryKey: ["job-detail", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId,
  });

  const pcapLabels = useMemo(() => {
    const labels = (jobData?.job?.pcaps ?? []).map(p => p.label).filter(Boolean) as string[];
    return [...new Set(labels)];
  }, [jobData]);

  // Fetch hosts for the host-scope dropdown
  const { data: hostsData } = useQuery({
    queryKey: ["hosts", jobId],
    queryFn: () => api.listHosts(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });

  const hosts: HostListItem[] = hostsData?.items ?? [];

  // Fetch theories based on scope
  const theoryQueryKey = scopeType === "host" && selectedHost
    ? ["theories", jobId, "host", selectedHost]
    : ["theories", jobId, "job", activeLabel];

  const { data: theoryData, isLoading, error } = useQuery({
    queryKey: theoryQueryKey,
    queryFn: () => {
      if (scopeType === "host" && selectedHost) {
        return api.listHostTheories(jobId!, selectedHost);
      }
      return api.listJobTheories(jobId!, activeLabel ? { pcap_label: activeLabel } : {});
    },
    enabled: !!jobId,
  });

  // Fetch slices for cross-linking (8️⃣)
  const { data: sliceData } = useQuery({
    queryKey: ["slices", jobId],
    queryFn: () => api.listSlices(jobId!),
    enabled: !!jobId,
  });

  const slices: SliceItem[] = sliceData?.items ?? [];
  const theories: TheoryItem[] = theoryData?.items ?? [];

  const generateMut = useMutation({
    mutationFn: () => api.generateTheories(jobId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["theories", jobId] });
      addToast({ severity: "info", title: "Theories regenerated", body: "Hypotheses have been recalculated." });
    },
    onError: () => addToast({ severity: "high", title: "Failed to generate theories", body: "Check backend connectivity." }),
  });

  if (isLoading) return <div className="p-6"><CardGridSkeleton count={3} /></div>;
  if (error) return <div className="p-6 text-red-400">Failed to load theories.</div>;

  return (
    <div className="flex gap-6 items-start p-6">
      <div className="max-w-4xl mx-auto space-y-4 flex-1 min-w-0">
        {/* Breadcrumb */}
        <nav className="text-sm text-slate-400">
          <Link to="/jobs" className="hover:text-white">Jobs</Link>
          <span className="mx-1">/</span>
          <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
          <span className="mx-1">/</span>
          <span className="text-slate-200">Theories</span>
        </nav>

        {/* Title row */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className={`text-lg font-bold text-slate-100 ${labelHint("theories", activeHelpField)}`}
            onClick={() => toggleHelp("theories")}>Theory of the Case</h2>
          <button onClick={() => generateMut.mutate()} disabled={generateMut.isPending}
            className="px-3 py-1.5 text-xs bg-indigo-600 hover:bg-indigo-500 text-white rounded disabled:opacity-50">
            {generateMut.isPending ? "Generating…" : "Re-generate"}
          </button>
        </div>

        <p className="text-sm text-slate-400">
          Ranked hypotheses based on alerts, findings, and IOCs. Scores are deterministic — no AI hallucination.
        </p>

        {/* 4️⃣ Scope toggle + 6️⃣ Temporal tabs */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Scope buttons */}
          <div className="flex bg-slate-800 rounded overflow-hidden border border-slate-700">
            <button onClick={() => { setScopeType("job"); setSelectedHost(null); }}
              className={`px-3 py-1.5 text-xs ${scopeType === "job" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-white"}`}>
              Job
            </button>
            <button onClick={() => setScopeType("host")}
              className={`px-3 py-1.5 text-xs ${scopeType === "host" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-white"}`}>
              Host
            </button>
          </div>

          {/* Host selector */}
          {scopeType === "host" && (
            <select value={selectedHost ?? ""} onChange={e => setSelectedHost(e.target.value || null)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-300">
              <option value="">Select host…</option>
              {hosts.map(h => <option key={h.ip} value={h.ip}>{h.ip} ({h.role})</option>)}
            </select>
          )}

          {/* Temporal label tabs */}
          {scopeType === "job" && pcapLabels.length > 1 && (
            <div className="flex bg-slate-800 rounded overflow-hidden border border-slate-700 ml-auto">
              <button onClick={() => setActiveLabel(null)}
                className={`px-3 py-1.5 text-xs ${activeLabel === null ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-white"}`}>
                All
              </button>
              {pcapLabels.map(lbl => (
                <button key={lbl} onClick={() => setActiveLabel(lbl)}
                  className={`px-3 py-1.5 text-xs ${activeLabel === lbl ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-white"}`}>
                  {lbl}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 2️⃣ Evidence summary bar */}
        <EvidenceSummaryBar theories={theories} />

        {theories.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            {scopeType === "host" && !selectedHost
              ? "Select a host to view host-level theories."
              : "No theories generated yet. Click \"Re-generate\" to analyze evidence."}
          </div>
        ) : (
          <>
            {/* 7️⃣ Distribution chart */}
            <DistributionChart theories={theories} />

            {/* 3️⃣ Collapsible cards */}
            <div className="space-y-3">
              {theories.map((t, i) => (
                <TheoryCard key={t.theory_id} theory={t} jobId={jobId!} slices={slices}
                  defaultExpanded={i < 2} />
              ))}
            </div>
          </>
        )}
      </div>
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};

