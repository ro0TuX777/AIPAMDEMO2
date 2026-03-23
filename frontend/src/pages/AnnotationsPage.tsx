import React, { useState, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type ContextAnnotationItem,
  type ContextAnnotationListResponse,
  type TheoryItem,
  type SliceItem,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";
import { CardGridSkeleton } from "../components/SkeletonLoader";

// ── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-700",
  high: "bg-orange-900/40 text-orange-300 border-orange-700",
  medium: "bg-amber-900/40 text-amber-300 border-amber-700",
  low: "bg-slate-800 text-slate-400 border-slate-600",
  info: "bg-slate-800 text-slate-500 border-slate-700",
};

const SEV_BAR_COLORS: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-amber-500",
  low: "bg-blue-500", info: "bg-slate-500",
};

const CATEGORY_LABELS: Record<string, string> = {
  traffic: "TRF", behavioral: "BHV", protocol: "PRT", alert: "ALR", dns: "DNS",
};

const CATEGORY_FULL: Record<string, string> = {
  traffic: "Traffic", behavioral: "Behavioral", protocol: "Protocol", alert: "Alert", dns: "DNS",
};

type SortField = "deviation" | "severity" | "host" | "category";
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtValue(metric: string, value: number | null): string {
  if (value == null) return "—";
  if (metric.includes("bytes")) {
    if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB`;
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB`;
    return `${Math.round(value)} B`;
  }
  return String(Math.round(value));
}

// ── 2️⃣ Deep-linked evidence chips ──────────────────────────────────────────

function EvidenceChips({ ids, type, jobId }: { ids: string[]; type: "alert" | "finding"; jobId: string }) {
  if (!ids.length) return null;
  const label = type === "alert" ? "ALR" : "FND";
  const maxShow = 4;
  const shown = ids.slice(0, maxShow);
  const extra = ids.length - maxShow;
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map(id => {
        const href = type === "alert"
          ? `/jobs/${jobId}/alerts/${encodeURIComponent(id)}`
          : `/jobs/${jobId}/findings/${encodeURIComponent(id)}`;
        return (
          <Link key={id} to={href}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700"
            title={`${type}: ${id}`}>
            <span className="font-mono opacity-60">{label}</span>
            <span className="truncate max-w-[120px]">{id}</span>
          </Link>
        );
      })}
      {extra > 0 && (
        <Link to={type === "alert" ? `/jobs/${jobId}/alerts` : `/jobs/${jobId}/findings`}
          className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700">
          +{extra} more
        </Link>
      )}
    </div>
  );
}

// ── 5️⃣ Visual deviation gauge ──────────────────────────────────────────────

function DeviationGauge({ observed, baseline, deviation }: {
  observed: number | null; baseline: number | null; deviation: number | null;
}) {
  if (observed == null || baseline == null || baseline === 0) return null;
  const ratio = Math.min(observed / Math.max(baseline, 1), 20);
  const baselinePct = Math.min((1 / ratio) * 100, 100);
  const color = (deviation ?? 0) >= 5 ? "bg-red-500" : (deviation ?? 0) >= 3 ? "bg-orange-500" : "bg-amber-500";
  return (
    <div className="flex items-center gap-2 mt-1">
      <span className="text-[10px] text-slate-500 w-14 text-right">Baseline</span>
      <div className="flex-1 h-3 bg-slate-800 rounded-full overflow-hidden relative">
        <div className="absolute inset-y-0 left-0 bg-slate-600 rounded-full" style={{ width: `${baselinePct}%` }} />
        <div className={`absolute inset-y-0 left-0 ${color} rounded-full opacity-70`} style={{ width: "100%" }} />
      </div>
      <span className="text-[10px] text-slate-400 font-mono w-12">{ratio.toFixed(1)}×</span>
    </div>
  );
}

// ── 9️⃣ Baseline comparison mini-chart ──────────────────────────────────────

function BaselineComparisonBar({ metric, observed, baseline }: {
  metric: string; observed: number | null; baseline: number | null;
}) {
  if (observed == null || baseline == null) return null;
  const maxVal = Math.max(observed, baseline, 1);
  const obsPct = (observed / maxVal) * 100;
  const basePct = (baseline / maxVal) * 100;
  return (
    <div className="space-y-1 mt-2">
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-slate-500 w-16">Observed</span>
        <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${obsPct}%` }} />
        </div>
        <span className="text-[10px] text-cyan-300 font-mono w-20 text-right">{fmtValue(metric, observed)}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[10px] text-slate-500 w-16">Baseline</span>
        <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
          <div className="h-full bg-slate-600 rounded-full" style={{ width: `${basePct}%` }} />
        </div>
        <span className="text-[10px] text-slate-400 font-mono w-20 text-right">{fmtValue(metric, baseline)}</span>
      </div>
    </div>
  );
}

// ── 6️⃣ Summary statistics bar ──────────────────────────────────────────────

function SummaryBar({ annotations }: { annotations: ContextAnnotationItem[] }) {
  const hostCount = new Set(annotations.map(a => a.host_ip)).size;
  const sevCounts: Record<string, number> = {};
  annotations.forEach(a => { sevCounts[a.severity] = (sevCounts[a.severity] || 0) + 1; });
  const topHost = annotations.length > 0
    ? Object.entries(annotations.reduce<Record<string, number>>((acc, a) => {
        acc[a.host_ip] = (acc[a.host_ip] || 0) + 1; return acc;
      }, {})).sort((a, b) => b[1] - a[1])[0]
    : null;

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400">
      <span>Total: <strong className="text-slate-200">{annotations.length}</strong> anomalies</span>
      <span>Hosts affected: <strong className="text-slate-200">{hostCount}</strong></span>
      {["critical", "high", "medium", "low"].map(s => sevCounts[s] ? (
        <span key={s}>{s.charAt(0).toUpperCase() + s.slice(1)}: <strong className="text-slate-200">{sevCounts[s]}</strong></span>
      ) : null)}
      {topHost && (
        <span className="ml-auto">Most anomalous: <strong className="text-cyan-300 font-mono">{topHost[0]}</strong> ({topHost[1]})</span>
      )}
    </div>
  );
}

// ── Severity distribution chart ─────────────────────────────────────────────

function SeverityChart({ annotations }: { annotations: ContextAnnotationItem[] }) {
  const counts: Record<string, number> = {};
  annotations.forEach(a => { counts[a.severity] = (counts[a.severity] || 0) + 1; });
  const total = annotations.length || 1;
  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-3">
      <h3 className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Severity Distribution</h3>
      <div className="h-3 flex rounded-full overflow-hidden">
        {["critical", "high", "medium", "low", "info"].map(s => {
          const pct = ((counts[s] || 0) / total) * 100;
          if (!pct) return null;
          return <div key={s} className={`${SEV_BAR_COLORS[s] || "bg-slate-600"}`} style={{ width: `${pct}%` }}
            title={`${s}: ${counts[s]}`} />;
        })}
      </div>
      <div className="flex gap-3 mt-1 text-[10px] text-slate-500 flex-wrap">
        {["critical", "high", "medium", "low", "info"].filter(s => counts[s]).map(s => (
          <span key={s} className="flex items-center gap-1">
            <span className={`w-2 h-2 rounded-full ${SEV_BAR_COLORS[s]}`} />
            {s}: {counts[s]}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── 10️⃣ Cross-link to related theories/slices ─────────────────────────────

function RelatedLinks({ hostIp, theories, slices, jobId }: {
  hostIp: string; theories: TheoryItem[]; slices: SliceItem[]; jobId: string;
}) {
  const relTheories = theories.filter(t =>
    t.supporting_evidence.some(e => e.id.includes(hostIp)) ||
    t.contradicting_evidence.some(e => e.id.includes(hostIp)) ||
    t.label.includes(hostIp)
  );
  const relSlices = slices.filter(s => s.host_ips.includes(hostIp));

  if (relTheories.length === 0 && relSlices.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2 mt-2">
      {relTheories.slice(0, 3).map(t => (
        <Link key={t.theory_id} to={`/jobs/${jobId}/theories`}
          className="text-[10px] px-2 py-0.5 bg-purple-900/30 text-purple-300 border border-purple-800 rounded hover:bg-purple-900/50">
          Theory: {t.label}
        </Link>
      ))}
      {relSlices.slice(0, 3).map(s => (
        <Link key={s.slice_id} to={`/jobs/${jobId}/slices`}
          className="text-[10px] px-2 py-0.5 bg-emerald-900/30 text-emerald-300 border border-emerald-800 rounded hover:bg-emerald-900/50">
          Slice: {s.label}
        </Link>
      ))}
    </div>
  );
}


// ── 1️⃣ Collapsible annotation card ─────────────────────────────────────────

function AnnotationCard({ ann, jobId, theories, slices, defaultExpanded = false }: {
  ann: ContextAnnotationItem; jobId: string;
  theories: TheoryItem[]; slices: SliceItem[];
  defaultExpanded?: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const tag = CATEGORY_LABELS[ann.metric_category] || "TRF";
  const sevClass = SEVERITY_COLORS[ann.severity] || SEVERITY_COLORS.info;
  const deviationColor = (ann.deviation_factor ?? 0) >= 5
    ? "text-red-400" : (ann.deviation_factor ?? 0) >= 3
    ? "text-orange-400" : "text-amber-400";

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg hover:border-slate-500 transition-colors">
      {/* Compact header — always visible */}
      <button onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left">
        <span className="text-[10px] text-slate-500">{expanded ? "▼" : "▶"}</span>
        <span className="text-xs font-mono font-bold text-slate-400 bg-slate-800 rounded px-1.5 py-0.5">{tag}</span>
        <h3 className="text-sm font-semibold text-slate-100 flex-1 min-w-0 truncate">{ann.title}</h3>
        <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(ann.host_ip)}`}
          className="text-xs text-cyan-400 hover:text-cyan-300 font-mono"
          onClick={e => e.stopPropagation()}>
          {ann.host_ip}
        </Link>
        <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass}`}>
          {ann.severity.toUpperCase()}
        </span>
        {ann.deviation_factor != null && (
          <span className={`text-xs font-mono font-bold ${deviationColor}`}>
            {ann.deviation_factor.toFixed(1)}σ
          </span>
        )}
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-800 pt-3 space-y-2">
          <p className="text-xs text-slate-300">{ann.description}</p>
          <p className="text-xs text-slate-500 italic">{ann.why_unusual}</p>

          {/* 5️⃣ Deviation gauge */}
          <DeviationGauge observed={ann.observed_value} baseline={ann.baseline_value} deviation={ann.deviation_factor} />

          {/* 9️⃣ Baseline comparison chart */}
          <BaselineComparisonBar metric={ann.metric_name} observed={ann.observed_value} baseline={ann.baseline_value} />

          {/* Stats row */}
          <div className="flex gap-4 text-[10px] text-slate-500 flex-wrap">
            <span>Observed: <strong className="text-slate-300">{fmtValue(ann.metric_name, ann.observed_value)}</strong></span>
            <span>Baseline: <strong className="text-slate-400">{fmtValue(ann.metric_name, ann.baseline_value)}</strong></span>
            <span>Pop: {ann.population_size} hosts</span>
            <span>Confidence: {Math.round((ann.confidence ?? 0) * 100)}%</span>
          </div>

          {/* 2️⃣ Deep-linked evidence */}
          {ann.related_alert_ids.length > 0 && (
            <div>
              <span className="text-[10px] text-slate-500 block mb-0.5">Related Alerts</span>
              <EvidenceChips ids={ann.related_alert_ids} type="alert" jobId={jobId} />
            </div>
          )}
          {ann.related_finding_ids.length > 0 && (
            <div>
              <span className="text-[10px] text-slate-500 block mb-0.5">Related Findings</span>
              <EvidenceChips ids={ann.related_finding_ids} type="finding" jobId={jobId} />
            </div>
          )}

          {/* 10️⃣ Cross-links */}
          <RelatedLinks hostIp={ann.host_ip} theories={theories} slices={slices} jobId={jobId} />
        </div>
      )}
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export function AnnotationsPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const { addToast } = useToast();

  // 3️⃣ Category filter
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  // 3️⃣ Severity filter
  const [severityFilter, setSeverityFilter] = useState<string>("");
  // 7️⃣ Temporal tabs
  const [activeLabel, setActiveLabel] = useState<string | null>(null);
  // 8️⃣ Sort
  const [sortBy, setSortBy] = useState<SortField>("deviation");
  // 4️⃣ Host grouping toggle
  const [groupByHost, setGroupByHost] = useState(false);

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

  // Fetch annotations
  const { data, isLoading, error } = useQuery<ContextAnnotationListResponse>({
    queryKey: ["annotations", jobId, activeLabel],
    queryFn: () => api.listAnnotations(jobId!, undefined, activeLabel ?? undefined),
    enabled: !!jobId,
  });

  // 10️⃣ Fetch theories + slices for cross-linking
  const { data: theoryData } = useQuery({
    queryKey: ["theories", jobId, "job"],
    queryFn: () => api.listJobTheories(jobId!),
    enabled: !!jobId,
  });
  const { data: sliceData } = useQuery({
    queryKey: ["slices", jobId],
    queryFn: () => api.listSlices(jobId!),
    enabled: !!jobId,
  });

  const theories: TheoryItem[] = theoryData?.items ?? [];
  const allSlices: SliceItem[] = sliceData?.items ?? [];
  const allAnnotations = data?.items ?? [];

  // 3️⃣ + 8️⃣ Filter + sort
  const annotations = useMemo(() => {
    let result = allAnnotations;
    if (categoryFilter) result = result.filter(a => a.metric_category === categoryFilter);
    if (severityFilter) result = result.filter(a => a.severity === severityFilter);

    result = [...result].sort((a, b) => {
      switch (sortBy) {
        case "deviation": return (b.deviation_factor ?? 0) - (a.deviation_factor ?? 0);
        case "severity": return (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0);
        case "host": return a.host_ip.localeCompare(b.host_ip);
        case "category": return a.metric_category.localeCompare(b.metric_category);
        default: return 0;
      }
    });
    return result;
  }, [allAnnotations, categoryFilter, severityFilter, sortBy]);

  // Distinct categories + severities for filters
  const categories = useMemo(() => [...new Set(allAnnotations.map(a => a.metric_category))].sort(), [allAnnotations]);
  const severities = useMemo(() => [...new Set(allAnnotations.map(a => a.severity))].sort((a, b) => (SEV_RANK[b] ?? 0) - (SEV_RANK[a] ?? 0)), [allAnnotations]);

  // 4️⃣ Host grouping
  const hostGroups = useMemo(() => {
    if (!groupByHost) return null;
    const groups: Record<string, ContextAnnotationItem[]> = {};
    annotations.forEach(a => {
      (groups[a.host_ip] ??= []).push(a);
    });
    return Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  }, [annotations, groupByHost]);

  const regenerate = useMutation({
    mutationFn: () => api.generateAnnotations(jobId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["annotations", jobId] });
      addToast({ severity: "info", title: "Annotations regenerated", body: "Context annotations have been recalculated." });
    },
    onError: () => addToast({ severity: "high", title: "Failed to generate annotations", body: "Check backend connectivity." }),
  });

  if (isLoading) return <div className="p-6"><CardGridSkeleton count={4} /></div>;
  if (error) return <div className="p-6 text-red-400">Error loading annotations</div>;

  const renderCards = (items: ContextAnnotationItem[], startExpanded = 0) => (
    <div className="space-y-3">
      {items.map((a, i) => (
        <AnnotationCard key={a.annotation_id} ann={a} jobId={jobId!}
          theories={theories} slices={allSlices} defaultExpanded={i < startExpanded} />
      ))}
    </div>
  );

  return (
    <div className="flex gap-6 items-start p-6">
      <div className="max-w-4xl mx-auto flex-1 min-w-0 space-y-4">
        {/* Breadcrumb */}
        <nav className="text-sm text-slate-400">
          <Link to="/jobs" className="hover:text-white">Jobs</Link>
          <span className="mx-1">/</span>
          <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
          <span className="mx-1">/</span>
          <span className="text-slate-200">Why Unusual?</span>
        </nav>

        {/* Title row */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className={`text-lg font-bold text-slate-100 ${labelHint("annotations", activeHelpField)}`}
            onClick={() => toggleHelp("annotations")}>
            Why Unusual? <span className="text-slate-500 text-sm font-normal ml-2">({annotations.length})</span>
          </h2>
          <button onClick={() => regenerate.mutate()} disabled={regenerate.isPending}
            className="text-xs px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 disabled:opacity-50">
            {regenerate.isPending ? "Generating…" : "↻ Regenerate"}
          </button>
        </div>

        <p className="text-sm text-slate-400">
          Statistical outliers and anomalies — hosts that deviate significantly from the job-wide baseline.
        </p>

        {/* Filters row */}
        <div className="flex flex-wrap items-center gap-3">
          {/* 3️⃣ Category filter */}
          {categories.length > 1 && (
            <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-300">
              <option value="">All categories</option>
              {categories.map(c => <option key={c} value={c}>{CATEGORY_FULL[c] || c}</option>)}
            </select>
          )}

          {/* 3️⃣ Severity filter */}
          {severities.length > 1 && (
            <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-300">
              <option value="">All severities</option>
              {severities.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
            </select>
          )}

          {/* 8️⃣ Sort */}
          <select value={sortBy} onChange={e => setSortBy(e.target.value as SortField)}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-300">
            <option value="deviation">Sort: Deviation ↓</option>
            <option value="severity">Sort: Severity ↓</option>
            <option value="host">Sort: Host IP</option>
            <option value="category">Sort: Category</option>
          </select>

          {/* 4️⃣ Host grouping toggle */}
          <button onClick={() => setGroupByHost(!groupByHost)}
            className={`px-2 py-1.5 text-xs rounded border ${groupByHost
              ? "bg-cyan-900/40 text-cyan-300 border-cyan-700"
              : "bg-slate-800 text-slate-400 border-slate-700 hover:text-white"}`}>
            {groupByHost ? "⊟ Ungroup" : "⊞ Group by Host"}
          </button>

          {/* 7️⃣ Temporal label tabs */}
          {pcapLabels.length > 1 && (
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

        {/* 6️⃣ Summary bar */}
        <SummaryBar annotations={annotations} />

        {annotations.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            No statistical outliers detected. Click "Regenerate" or run a job analysis.
          </div>
        ) : (
          <>
            {/* Severity distribution chart */}
            <SeverityChart annotations={annotations} />

            {/* 4️⃣ Host-grouped or flat list */}
            {groupByHost && hostGroups ? (
              <div className="space-y-6">
                {hostGroups.map(([ip, items]) => (
                  <div key={ip}>
                    <div className="flex items-center gap-2 mb-2">
                      <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}`}
                        className="text-sm font-mono text-cyan-400 hover:text-cyan-300">{ip}</Link>
                      <span className="text-[10px] text-slate-500">({items.length} anomalies)</span>
                    </div>
                    {renderCards(items)}
                  </div>
                ))}
              </div>
            ) : (
              renderCards(annotations, 2)
            )}
          </>
        )}
      </div>
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
}
