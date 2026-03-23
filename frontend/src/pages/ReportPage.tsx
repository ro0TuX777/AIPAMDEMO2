import React, { useRef, useCallback, useState, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  api,
  type JobSummaryResponse,
  type JobDetail,
  type HostListItem,
  type IocItem,
  type AlertItem,
  type FindingItem,
  type TheoryItem,
  type TheoryListResponse,
  type SliceItem,
  type SliceListResponse,
  type ContextAnnotationItem,
  type ContextAnnotationListResponse,
  type Severity,
  type ReportItem,
  type ReportListResponse,
  type TemporalDeltaResponse,
  type TemporalFlowsResponse,
  type TemporalNarrativeResponse,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { DetailSkeleton } from "../components/SkeletonLoader";

/* ────────────────────────────────────────────────────────────────────────── */
/*  Helpers                                                                  */
/* ────────────────────────────────────────────────────────────────────────── */

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_COLOR: Record<string, string> = {
  critical: "text-red-500", high: "text-red-400", medium: "text-amber-400",
  low: "text-blue-400", info: "text-slate-400",
};
const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/20 border-red-500/40", high: "bg-red-400/15 border-red-400/30",
  medium: "bg-amber-400/15 border-amber-400/30", low: "bg-blue-400/15 border-blue-400/30",
  info: "bg-slate-400/10 border-slate-500/30",
};
const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500/30 text-red-300", high: "bg-red-400/20 text-red-300",
  medium: "bg-amber-400/20 text-amber-300", low: "bg-blue-400/20 text-blue-300",
  info: "bg-slate-600/40 text-slate-300",
};

function fmtBytes(b: number | null | undefined): string {
  if (!b) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(2)} GB`;
}

function fmtDate(d: string | null | undefined): string {
  if (!d) return "—";
  try { return new Date(d).toLocaleString(); } catch { return d; }
}

function fmtDuration(sec: number | null | undefined): string {
  if (!sec) return "—";
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = (sec % 60).toFixed(0);
  return `${m}m ${s}s`;
}

/** Group alerts by signature and count them. */
function groupAlertsBySignature(alerts: AlertItem[]): { sig: string; count: number; severity: string }[] {
  const map = new Map<string, { count: number; severity: string }>();
  for (const a of alerts) {
    const existing = map.get(a.signature);
    if (existing) {
      existing.count++;
      if (SEV_ORDER[a.severity] < SEV_ORDER[existing.severity]) existing.severity = a.severity;
    } else {
      map.set(a.signature, { count: 1, severity: a.severity });
    }
  }
  return Array.from(map.entries())
    .map(([sig, v]) => ({ sig, ...v }))
    .sort((a, b) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || (b.count - a.count));
}

/** Count alerts by severity. */
function countBySeverity(alerts: AlertItem[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const a of alerts) counts[a.severity] = (counts[a.severity] || 0) + 1;
  return counts;
}

/** Unique src_ip → dest_ip pairs from alerts. */
function getAlertFlows(alerts: AlertItem[]): { src: string; dest: string; count: number; sigs: string[] }[] {
  const map = new Map<string, { count: number; sigs: Set<string> }>();
  for (const a of alerts) {
    if (!a.src_ip || !a.dest_ip) continue;
    const key = `${a.src_ip} → ${a.dest_ip}`;
    const existing = map.get(key);
    if (existing) { existing.count++; existing.sigs.add(a.signature); }
    else map.set(key, { count: 1, sigs: new Set([a.signature]) });
  }
  return Array.from(map.entries())
    .map(([, v], i, arr) => {
      const key = Array.from(map.keys())[arr.indexOf(arr[i])];
      const [src, dest] = key ? key.split(" → ") : ["", ""];
      return { src, dest, count: v.count, sigs: Array.from(v.sigs) };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
}

/* ────────────────────────────────────────────────────────────────────────── */
/*  Section Components                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

const Section: React.FC<{ title: string; icon?: string; children: React.ReactNode }> = ({ title, icon, children }) => (
  <section className="report-section bg-slate-900/50 border border-slate-800 rounded-lg p-6 print:border-gray-300 print:bg-white print:shadow-none">
    <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2 print:text-gray-900">
      {icon && <span>{icon}</span>}
      {title}
    </h2>
    {children}
  </section>
);

const Table: React.FC<{
  headers: string[];
  rows: React.ReactNode[][];
  colClasses?: string[];
}> = ({ headers, rows, colClasses }) => (
  <div className="overflow-x-auto">
    <table className="w-full text-sm">
      <thead>
        <tr className="border-b border-slate-700 print:border-gray-300">
          {headers.map((h, i) => (
            <th key={i} className={`text-left py-2 px-3 text-xs font-semibold text-slate-400 uppercase tracking-wider print:text-gray-600 ${colClasses?.[i] || ""}`}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, ri) => (
          <tr key={ri} className="border-b border-slate-800/50 print:border-gray-200">
            {row.map((cell, ci) => (
              <td key={ci} className={`py-2 px-3 text-slate-300 print:text-gray-800 ${colClasses?.[ci] || ""}`}>
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => (
  <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium uppercase ${SEV_BADGE[severity] || SEV_BADGE.info}`}>
    {severity}
  </span>
);

/* ────────────────────────────────────────────────────────────────────────── */
/*  Main Report Page                                                         */
/* ────────────────────────────────────────────────────────────────────────── */

/* ────────────────────────────────────────────────────────────────────────── */
/*  Markdown renderer components for styled prose                           */
/* ────────────────────────────────────────────────────────────────────────── */

const MarkdownReport: React.FC<{ content: string }> = ({ content }) => (
  <div className="prose prose-invert prose-sm max-w-none
    prose-headings:text-slate-200 prose-h1:text-xl prose-h2:text-lg prose-h3:text-base
    prose-p:text-slate-300 prose-strong:text-slate-100
    prose-table:text-sm prose-th:text-slate-400 prose-th:font-semibold prose-th:uppercase prose-th:text-xs
    prose-td:text-slate-300 prose-td:py-1.5 prose-td:px-3
    prose-tr:border-slate-700/50 prose-thead:border-slate-700
    prose-li:text-slate-300 prose-a:text-blue-400 prose-code:text-emerald-400
    print:prose-headings:text-gray-900 print:prose-p:text-gray-700 print:prose-td:text-gray-700 print:prose-th:text-gray-600
    print:prose-strong:text-gray-900 print:prose-li:text-gray-700">
    <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
  </div>
);

/* ────────────────────────────────────────────────────────────────────────── */
/*  Severity Stacked Bar                                                     */
/* ────────────────────────────────────────────────────────────────────────── */

const SEV_BAR_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f87171", medium: "#fbbf24", low: "#60a5fa", info: "#94a3b8",
};

const SeverityStackedBar: React.FC<{ counts: Record<string, number> }> = ({ counts }) => {
  const total = Object.values(counts).reduce((s, c) => s + c, 0);
  if (total === 0) return null;
  return (
    <div className="space-y-1.5">
      <div className="flex h-4 rounded-full overflow-hidden bg-slate-800 print:bg-gray-200">
        {(["critical", "high", "medium", "low", "info"] as const).map(sev => {
          const c = counts[sev] || 0;
          if (c === 0) return null;
          const pct = (c / total) * 100;
          return (
            <div key={sev} style={{ width: `${pct}%`, backgroundColor: SEV_BAR_COLORS[sev] }}
              className="relative group cursor-default transition-all hover:brightness-110"
              title={`${sev}: ${c} (${pct.toFixed(1)}%)`} />
          );
        })}
      </div>
      <div className="flex gap-3 text-[10px] text-slate-400">
        {(["critical", "high", "medium", "low", "info"] as const).map(sev => {
          const c = counts[sev] || 0;
          if (c === 0) return null;
          return (
            <span key={sev} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: SEV_BAR_COLORS[sev] }} />
              {sev} ({c})
            </span>
          );
        })}
      </div>
    </div>
  );
};

/* ────────────────────────────────────────────────────────────────────────── */
/*  Threat Level Gauge                                                       */
/* ────────────────────────────────────────────────────────────────────────── */

const GAUGE_LEVELS = ["Informational", "Low", "Medium", "High", "Critical"] as const;
const GAUGE_COLORS = ["#22c55e", "#60a5fa", "#fbbf24", "#f87171", "#ef4444"];

const ThreatGauge: React.FC<{ level: string }> = ({ level }) => {
  const idx = GAUGE_LEVELS.indexOf(level as any);
  const activeIdx = idx >= 0 ? idx : 0;
  return (
    <div className="flex items-center gap-1.5">
      {GAUGE_LEVELS.map((l, i) => (
        <div key={l} className="flex flex-col items-center gap-0.5">
          <div className={`h-6 rounded transition-all ${i <= activeIdx ? "w-5" : "w-3 opacity-30"}`}
            style={{ backgroundColor: GAUGE_COLORS[i] }} />
          <span className={`text-[8px] uppercase tracking-wider ${i === activeIdx ? "text-slate-200 font-bold" : "text-slate-600"}`}>
            {l.slice(0, 4)}
          </span>
        </div>
      ))}
    </div>
  );
};

/* ────────────────────────────────────────────────────────────────────────── */
/*  Table of Contents                                                        */
/* ────────────────────────────────────────────────────────────────────────── */

interface TocEntry { id: string; label: string; icon: string }

const TableOfContents: React.FC<{ entries: TocEntry[] }> = ({ entries }) => (
  <nav className="no-print sticky top-4 space-y-0.5">
    <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-2">Contents</p>
    {entries.map(e => (
      <a key={e.id} href={`#${e.id}`}
        className="flex items-center gap-1.5 px-2 py-1 text-xs text-slate-400 hover:text-white hover:bg-slate-800/60 rounded transition-colors">
        <span>{e.icon}</span>
        <span>{e.label}</span>
      </a>
    ))}
  </nav>
);

export const ReportPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const reportRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const [genMode, setGenMode] = useState<"executive" | "analyst">("analyst");
  const [viewMode, setViewMode] = useState<"live" | "generated" | "compare" | "temporal">("live");
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [compareLeftId, setCompareLeftId] = useState<string | null>(null);
  const [compareRightId, setCompareRightId] = useState<string | null>(null);
  const [activePhase, setActivePhase] = useState<string>("all"); // "all", "before", "after", custom
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  // ── Generated reports ──
  const reportsQ = useQuery<ReportListResponse>({
    queryKey: ["job", jobId, "reports"],
    queryFn: () => api.listReports(jobId!),
    enabled: !!jobId,
  });

  const generateMut = useMutation({
    mutationFn: (mode: "executive" | "analyst") =>
      api.generateReport(jobId!, mode, activePhase !== "all" ? activePhase : undefined),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "reports"] });
      setSelectedReportId(data.item.report_id);
      setViewMode("generated");
    },
  });

  const generatedReports: ReportItem[] = reportsQ.data?.items ?? [];
  const activeReport = selectedReportId
    ? generatedReports.find(r => r.report_id === selectedReportId)
    : generatedReports[0] ?? null;

  // ── Data fetching (parallel) — filtered by activePhase ──
  const phaseFilter = activePhase !== "all" ? activePhase : undefined;

  const summaryQ = useQuery<JobSummaryResponse>({
    queryKey: ["job", jobId, "summary"],
    queryFn: () => api.getJobSummary(jobId!),
    enabled: !!jobId,
  });

  const jobQ = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId,
  });

  const alertsQ = useQuery({
    queryKey: ["job", jobId, "alerts", "report", activePhase],
    queryFn: () => api.listAlerts(jobId!, { limit: 200, pcap_label: phaseFilter }),
    enabled: !!jobId,
  });

  const findingsQ = useQuery({
    queryKey: ["job", jobId, "findings", "report", activePhase],
    queryFn: () => api.listFindings(jobId!, { limit: 50, pcap_label: phaseFilter }),
    enabled: !!jobId,
  });

  const iocsQ = useQuery({
    queryKey: ["job", jobId, "iocs", "report", activePhase],
    queryFn: () => api.listIocs(jobId!, { limit: 50, pcap_label: phaseFilter }),
    enabled: !!jobId,
  });

  const hostsQ = useQuery({
    queryKey: ["job", jobId, "hosts", "report", activePhase],
    queryFn: () => api.listHosts(jobId!, { limit: 50, pcap_label: phaseFilter }),
    enabled: !!jobId,
  });

  const theoriesQ = useQuery<TheoryListResponse>({
    queryKey: ["job", jobId, "theories", "report", activePhase],
    queryFn: () => api.listJobTheories(jobId!, { pcap_label: phaseFilter }),
    enabled: !!jobId,
  });

  const slicesQ = useQuery<SliceListResponse>({
    queryKey: ["job", jobId, "slices", "report", activePhase],
    queryFn: () => api.listSlices(jobId!, { pcap_label: phaseFilter }),
    enabled: !!jobId,
  });

  const annotationsQ = useQuery<ContextAnnotationListResponse>({
    queryKey: ["job", jobId, "annotations", "report", activePhase],
    queryFn: () => api.listAnnotations(jobId!, undefined, phaseFilter),
    enabled: !!jobId,
  });

  const summary = summaryQ.data;
  const job: JobDetail | undefined = jobQ.data?.job;
  const alerts: AlertItem[] = alertsQ.data?.items ?? [];
  const findings: FindingItem[] = findingsQ.data?.items ?? [];
  const iocs: IocItem[] = iocsQ.data?.items ?? [];
  const hosts: HostListItem[] = hostsQ.data?.items ?? [];
  const theories: TheoryItem[] = theoriesQ.data?.items ?? [];
  const slices: SliceItem[] = slicesQ.data?.items ?? [];
  const annotations: ContextAnnotationItem[] = annotationsQ.data?.items ?? [];

  const isLoading = summaryQ.isLoading || jobQ.isLoading;
  const error = summaryQ.error || jobQ.error;

  // ── Available phases from job PCAPs ──
  const availablePhases = useMemo<string[]>(() => {
    const pcaps = job?.pcaps ?? [];
    const labels = new Set<string>();
    let hasUnlabeled = false;
    for (const p of pcaps) {
      if (p.label) labels.add(p.label);
      else hasUnlabeled = true;
    }
    // Treat unlabeled PCAPs as "before" when other labeled PCAPs exist
    if (hasUnlabeled && labels.size > 0) labels.add("before");
    return Array.from(labels).sort();
  }, [job?.pcaps]);

  const hasTemporalPhases = availablePhases.length > 1;

  // ── Temporal delta (fetched when user activates temporal view) ──
  const temporalQ = useQuery<TemporalDeltaResponse>({
    queryKey: ["job", jobId, "temporal-delta"],
    queryFn: () => api.getTemporalDelta(jobId!),
    enabled: !!jobId && hasTemporalPhases && viewMode === "temporal",
    staleTime: 30_000,
  });
  const delta = temporalQ.data;

  const flowsQ = useQuery<TemporalFlowsResponse>({
    queryKey: ["job", jobId, "temporal-flows"],
    queryFn: () => api.getTemporalFlows(jobId!),
    enabled: !!jobId && hasTemporalPhases && viewMode === "temporal",
    staleTime: 30_000,
  });

  const narrativeM = useMutation<TemporalNarrativeResponse>({
    mutationFn: () => api.generateTemporalNarrative(jobId!),
  });

  // ── Derived data ──
  const sevCounts = countBySeverity(alerts);
  const sigGroups = groupAlertsBySignature(alerts);
  const alertFlows = getAlertFlows(alerts);

  const internalHosts = hosts.filter(h => h.role === "internal");
  const externalHosts = hosts.filter(h => h.role === "external" || h.role === "unknown");

  // ── Comparison reports ──
  const compareLeft = compareLeftId ? generatedReports.find(r => r.report_id === compareLeftId) : null;
  const compareRight = compareRightId ? generatedReports.find(r => r.report_id === compareRightId) : null;

  // ── Threat level ──
  const threatLevel: string = (() => {
    if (sevCounts.critical > 0) return "Critical";
    if (sevCounts.high > 0) return "High";
    if (sevCounts.medium > 0) return "Medium";
    if (sevCounts.low > 0) return "Low";
    return "Informational";
  })();

  const threatColor: string = (() => {
    if (threatLevel === "Critical") return "text-red-500";
    if (threatLevel === "High") return "text-red-400";
    if (threatLevel === "Medium") return "text-amber-400";
    if (threatLevel === "Low") return "text-blue-400";
    return "text-green-400";
  })();

  // ── Table of Contents entries ──
  const tocEntries = useMemo<TocEntry[]>(() => {
    const entries: TocEntry[] = [
      { id: "sec-executive", label: "Executive Summary", icon: "📋" },
      { id: "sec-metrics", label: "Key Metrics", icon: "📊" },
    ];
    if (alerts.length > 0) entries.push({ id: "sec-alerts", label: "Alert Analysis", icon: "🚨" });
    if (theories.length > 0) entries.push({ id: "sec-theories", label: "Theories", icon: "🧠" });
    if (slices.length > 0) entries.push({ id: "sec-slices", label: "Incident Threads", icon: "🧩" });
    if (findings.length > 0) entries.push({ id: "sec-findings", label: "Detailed Findings", icon: "🔍" });
    if (iocs.length > 0) entries.push({ id: "sec-iocs", label: "IOCs", icon: "🎯" });
    if (annotations.length > 0) entries.push({ id: "sec-annotations", label: "Anomalies", icon: "⚡" });
    if (hosts.length > 0) entries.push({ id: "sec-hosts", label: "Host Analysis", icon: "🖥️" });
    if (summary?.top_signals && summary.top_signals.length > 0) entries.push({ id: "sec-signals", label: "Top Signals", icon: "📡" });
    if (summary?.recommendations && summary.recommendations.length > 0) entries.push({ id: "sec-recommendations", label: "Recommendations", icon: "✅" });
    return entries;
  }, [alerts.length, theories.length, slices.length, findings.length, iocs.length, annotations.length, hosts.length, summary]);

  // ── PDF Export ──
  const handleExportPdf = useCallback(() => {
    window.print();
  }, []);

  return (
    <>
      {/* Print-specific styles */}
      <style>{`
        @media print {
          body { background: white !important; color: #111 !important; font-size: 11px !important; }
          nav, .no-print, header, [class*="navbar"], [class*="sidebar"] { display: none !important; }
          .report-container { max-width: 100% !important; padding: 0 !important; }
          .report-section { break-inside: avoid; page-break-inside: avoid; margin-bottom: 12px; border: 1px solid #ddd !important; }
          .report-section h2 { color: #111 !important; }
          table { font-size: 10px; }
          .stat-card-print { border: 1px solid #ccc !important; background: #f9f9f9 !important; }
          a { color: #111 !important; text-decoration: none !important; }
          .print-header { display: flex !important; }
          .report-toc { display: none !important; }
          @page { margin: 0.75in; size: A4; }
        }
        @media screen { .print-header { display: none !important; } }
      `}</style>

      <div ref={reportRef} className="report-container space-y-6 max-w-5xl mx-auto pb-12">
        {/* Screen nav bar */}
        <div className="flex items-center justify-between no-print">
          <nav className="text-sm text-slate-400">
            <Link to="/jobs" className="hover:text-white">Jobs</Link>
            <span className="mx-1">/</span>
            <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
            <span className="mx-1">/</span>
            <span className="text-slate-200">Report</span>
          </nav>
          <button
            onClick={handleExportPdf}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
          >
            Export PDF
          </button>
        </div>

        {/* ── Report Generator Panel ── */}
        <div className="no-print bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">Report Composer</h3>
            <div className="flex items-center gap-2">
              {/* View mode toggle */}
              <button
                onClick={() => setViewMode("live")}
                className={`px-3 py-1 text-xs rounded ${viewMode === "live" ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}
              >
                Live View
              </button>
              <button
                onClick={() => setViewMode("generated")}
                className={`px-3 py-1 text-xs rounded ${viewMode === "generated" ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}
                disabled={generatedReports.length === 0}
              >
                Generated ({generatedReports.length})
              </button>
              <button
                onClick={() => { setViewMode("compare"); if (!compareLeftId && generatedReports[0]) setCompareLeftId(generatedReports[0].report_id); if (!compareRightId && generatedReports[1]) setCompareRightId(generatedReports[1].report_id); }}
                className={`px-3 py-1 text-xs rounded ${viewMode === "compare" ? "bg-purple-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}
                disabled={generatedReports.length < 2}
                title={generatedReports.length < 2 ? "Generate at least 2 reports to compare" : "Compare reports side by side"}
              >
                ⚖️ Compare
              </button>
              {hasTemporalPhases && (
                <button
                  onClick={() => setViewMode("temporal")}
                  className={`px-3 py-1 text-xs rounded ${viewMode === "temporal" ? "bg-emerald-600 text-white" : "bg-slate-800 text-slate-400 hover:text-white"}`}
                  title="Compare Before vs After phases"
                >
                  🔬 Temporal
                </button>
              )}
            </div>
          </div>
          {/* ── Phase selector (temporal analysis) ── */}
          {hasTemporalPhases && (
            <div className="flex items-center gap-2 bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2">
              <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold mr-1">Phase:</span>
              <button
                onClick={() => setActivePhase("all")}
                className={`px-2.5 py-1 text-xs rounded ${activePhase === "all" ? "bg-blue-600 text-white" : "bg-slate-700 text-slate-400 hover:text-white"}`}
              >
                All
              </button>
              {availablePhases.map(ph => (
                <button
                  key={ph}
                  onClick={() => setActivePhase(ph)}
                  className={`px-2.5 py-1 text-xs rounded capitalize ${activePhase === ph
                    ? (ph === "before" ? "bg-cyan-600 text-white" : ph === "after" ? "bg-orange-600 text-white" : "bg-indigo-600 text-white")
                    : "bg-slate-700 text-slate-400 hover:text-white"}`}
                >
                  {ph === "before" ? "🕐 Before" : ph === "after" ? "🕓 After" : ph}
                </button>
              ))}
            </div>
          )}
          <div className="flex items-center gap-3">
            <select
              value={genMode}
              onChange={(e) => setGenMode(e.target.value as "executive" | "analyst")}
              className="bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded px-3 py-1.5"
            >
              <option value="analyst">Analyst Report</option>
              <option value="executive">Executive Summary</option>
            </select>
            {hasTemporalPhases && activePhase !== "all" && (
              <span className={`text-xs px-2 py-1 rounded capitalize ${activePhase === "before" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30" : "bg-orange-500/20 text-orange-300 border border-orange-500/30"}`}>
                Phase: {activePhase}
              </span>
            )}
            <button
              onClick={() => generateMut.mutate(genMode)}
              disabled={generateMut.isPending}
              className="px-4 py-1.5 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-medium rounded transition-colors"
            >
              {generateMut.isPending ? "Generating…" : `Generate ${activePhase !== "all" ? `"${activePhase}" ` : ""}Report`}
            </button>
            {generateMut.isError && (
              <span className="text-red-400 text-xs">Generation failed</span>
            )}
          </div>
          {/* Generated report selector */}
          {viewMode === "generated" && generatedReports.length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {generatedReports.map(r => (
                <button
                  key={r.report_id}
                  onClick={() => setSelectedReportId(r.report_id)}
                  className={`px-3 py-1 text-xs rounded border ${
                    activeReport?.report_id === r.report_id
                      ? "border-blue-500 bg-blue-500/20 text-blue-300"
                      : "border-slate-700 bg-slate-800 text-slate-400 hover:text-white"
                  }`}
                >
                  {r.pcap_label ? `[${r.pcap_label}] ` : ""}{r.mode} — {r.threat_level.toUpperCase()} ({new Date(r.created_at).toLocaleString()})
                </button>
              ))}
            </div>
          )}
          {/* Compare selectors */}
          {viewMode === "compare" && generatedReports.length >= 2 && (
            <div className="flex items-center gap-3">
              <div className="flex-1 space-y-1">
                <label className="text-[10px] text-slate-500 uppercase tracking-wider">Left Report {hasTemporalPhases && "(Before)"}</label>
                <select value={compareLeftId || ""} onChange={e => setCompareLeftId(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1.5">
                  {generatedReports.map(r => (
                    <option key={r.report_id} value={r.report_id}>{r.pcap_label ? `[${r.pcap_label}] ` : ""}{r.mode} — {r.threat_level.toUpperCase()} ({new Date(r.created_at).toLocaleString()})</option>
                  ))}
                </select>
              </div>
              <span className="text-slate-600 mt-4 text-lg">⚖️</span>
              <div className="flex-1 space-y-1">
                <label className="text-[10px] text-slate-500 uppercase tracking-wider">Right Report {hasTemporalPhases && "(After)"}</label>
                <select value={compareRightId || ""} onChange={e => setCompareRightId(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1.5">
                  {generatedReports.map(r => (
                    <option key={r.report_id} value={r.report_id}>{r.pcap_label ? `[${r.pcap_label}] ` : ""}{r.mode} — {r.threat_level.toUpperCase()} ({new Date(r.created_at).toLocaleString()})</option>
                  ))}
                </select>
              </div>
            </div>
          )}
        </div>

        {/* ── Generated Report View (rendered markdown) ── */}
        {viewMode === "generated" && activeReport && (
          <Section title={activeReport.title}>
            <div className="space-y-3">
              <div className="flex gap-3 text-xs text-slate-400 flex-wrap">
                {activeReport.pcap_label && (
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${activeReport.pcap_label === "before" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30" : "bg-orange-500/20 text-orange-300 border border-orange-500/30"}`}>
                    {activeReport.pcap_label}
                  </span>
                )}
                <span>Threat: <span className={`font-bold ${
                  activeReport.threat_level === "critical" ? "text-red-500" :
                  activeReport.threat_level === "high" ? "text-red-400" :
                  activeReport.threat_level === "medium" ? "text-amber-400" :
                  activeReport.threat_level === "low" ? "text-blue-400" : "text-green-400"
                }`}>{activeReport.threat_level.toUpperCase()}</span></span>
                <span>Confidence: {(activeReport.confidence * 100).toFixed(0)}%</span>
                <span>Theories: {activeReport.theory_count}</span>
                <span>Slices: {activeReport.slice_count}</span>
                <span>Findings: {activeReport.finding_count}</span>
                <span>Alerts: {activeReport.alert_count}</span>
              </div>
              <MarkdownReport content={activeReport.content_markdown} />
            </div>
          </Section>
        )}

        {/* ── Compare View (side-by-side) ── */}
        {viewMode === "compare" && compareLeft && compareRight && (
          <div className="grid grid-cols-2 gap-4">
            {[compareLeft, compareRight].map((rpt, idx) => (
              <div key={rpt.report_id} className={`bg-slate-900/40 border rounded-lg p-4 space-y-3 ${idx === 0 ? "border-cyan-500/30" : "border-orange-500/30"}`}>
                <div className="flex items-center gap-2">
                  {rpt.pcap_label && (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${rpt.pcap_label === "before" ? "bg-cyan-500/20 text-cyan-300" : "bg-orange-500/20 text-orange-300"}`}>
                      {rpt.pcap_label}
                    </span>
                  )}
                  <h3 className="text-sm font-bold text-slate-200">{rpt.title}</h3>
                </div>
                <div className="flex gap-2 text-[10px] text-slate-400 flex-wrap">
                  <span className="font-bold uppercase">{rpt.mode}</span>
                  <span>Threat: {rpt.threat_level.toUpperCase()}</span>
                  <span>Confidence: {(rpt.confidence * 100).toFixed(0)}%</span>
                  <span>A:{rpt.alert_count} F:{rpt.finding_count} T:{rpt.theory_count}</span>
                  <span>{new Date(rpt.created_at).toLocaleString()}</span>
                </div>
                <div className="max-h-[70vh] overflow-y-auto">
                  <MarkdownReport content={rpt.content_markdown} />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Temporal Comparison View ── */}
        {viewMode === "temporal" && (
          <div className="space-y-6">
            {temporalQ.isLoading && (
              <div className="text-center py-12 text-slate-400">
                <div className="animate-spin inline-block w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full mb-3" />
                <p>Computing temporal delta…</p>
              </div>
            )}
            {temporalQ.isError && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-300">
                Failed to load temporal delta: {(temporalQ.error as Error).message}
              </div>
            )}
            {delta && (
              <>
                {/* ── Delta Summary Cards ── */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: "Hosts", before: delta.summary.hosts.before, after: delta.summary.hosts.after, added: delta.summary.hosts.new, removed: delta.summary.hosts.removed, icon: "🖥️" },
                    { label: "Alerts", before: delta.summary.alerts.before, after: delta.summary.alerts.after, added: delta.summary.alerts.new_signatures, removed: delta.summary.alerts.removed_signatures, icon: "🚨" },
                    { label: "Findings", before: delta.summary.findings.before, after: delta.summary.findings.after, added: delta.summary.findings.new, removed: delta.summary.findings.removed, icon: "🔍" },
                    { label: "IOCs", before: delta.summary.iocs.before, after: delta.summary.iocs.after, added: delta.summary.iocs.new, removed: delta.summary.iocs.removed, icon: "☣️" },
                    { label: "DNS Domains", before: delta.summary.dns_domains.before, after: delta.summary.dns_domains.after, added: delta.summary.dns_domains.new, removed: delta.summary.dns_domains.removed, icon: "🌐" },
                    { label: "Connections", before: delta.summary.traffic.before.connections, after: delta.summary.traffic.after.connections, added: 0, removed: 0, icon: "🔗" },
                    { label: "Theories", before: delta.summary.theories.before, after: delta.summary.theories.after, added: 0, removed: 0, icon: "🧠" },
                    { label: "TLS Sessions", before: delta.summary.tls_sessions.before, after: delta.summary.tls_sessions.after, added: 0, removed: 0, icon: "🔒" },
                  ].map(c => {
                    const pctChange = c.before > 0 ? ((c.after - c.before) / c.before * 100) : (c.after > 0 ? 100 : 0);
                    return (
                      <div key={c.label} className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-3 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs text-slate-400">{c.icon} {c.label}</span>
                          {pctChange !== 0 && (
                            <span className={`text-[10px] font-bold ${pctChange > 0 ? "text-orange-400" : "text-green-400"}`}>
                              {pctChange > 0 ? "↑" : "↓"}{Math.abs(pctChange).toFixed(0)}%
                            </span>
                          )}
                        </div>
                        <div className="flex items-baseline gap-2">
                          <span className="text-lg font-bold text-cyan-300">{c.before}</span>
                          <span className="text-slate-500">→</span>
                          <span className="text-lg font-bold text-orange-300">{c.after}</span>
                        </div>
                        {(c.added > 0 || c.removed > 0) && (
                          <div className="flex gap-2 text-[10px]">
                            {c.added > 0 && <span className="text-red-400">+{c.added} new</span>}
                            {c.removed > 0 && <span className="text-green-400">-{c.removed} removed</span>}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* ── Traffic Volume Delta ── */}
                <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                  <h3 className="text-sm font-bold text-slate-200 mb-3">📊 Traffic Volume</h3>
                  <div className="grid grid-cols-3 gap-4 text-center">
                    {[
                      { label: "Bytes Sent", before: delta.summary.traffic.before.bytes_sent, after: delta.summary.traffic.after.bytes_sent },
                      { label: "Bytes Received", before: delta.summary.traffic.before.bytes_recv, after: delta.summary.traffic.after.bytes_recv },
                      { label: "Total Bytes", before: delta.summary.traffic.before.bytes_sent + delta.summary.traffic.before.bytes_recv, after: delta.summary.traffic.after.bytes_sent + delta.summary.traffic.after.bytes_recv },
                    ].map(t => {
                      const pct = t.before > 0 ? ((t.after - t.before) / t.before * 100) : 0;
                      const fmt = (n: number) => n >= 1e9 ? (n/1e9).toFixed(1) + "GB" : n >= 1e6 ? (n/1e6).toFixed(1) + "MB" : n >= 1e3 ? (n/1e3).toFixed(1) + "KB" : n + "B";
                      return (
                        <div key={t.label}>
                          <div className="text-xs text-slate-400 mb-1">{t.label}</div>
                          <div className="text-cyan-300 text-sm">{fmt(t.before)}</div>
                          <div className="text-slate-500 text-xs">→</div>
                          <div className="text-orange-300 text-sm">{fmt(t.after)}</div>
                          {pct !== 0 && <div className={`text-[10px] font-bold ${pct > 0 ? "text-orange-400" : "text-green-400"}`}>{pct > 0 ? "↑" : "↓"}{Math.abs(pct).toFixed(1)}%</div>}
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* ── Severity Distribution Comparison ── */}
                <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                  <h3 className="text-sm font-bold text-slate-200 mb-3">⚡ Alert Severity Distribution</h3>
                  <div className="grid grid-cols-5 gap-2">
                    {(["critical", "high", "medium", "low", "info"] as const).map(sev => {
                      const b = delta.summary.severity_before[sev];
                      const a = delta.summary.severity_after[sev];
                      const colors: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400", info: "text-slate-400" };
                      return (
                        <div key={sev} className="text-center">
                          <div className={`text-xs font-bold uppercase ${colors[sev]}`}>{sev}</div>
                          <div className="text-cyan-300">{b}</div>
                          <div className="text-slate-500 text-xs">→</div>
                          <div className="text-orange-300">{a}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Temporal Diff Tables ── */}
        {viewMode === "temporal" && delta && (
          <div className="space-y-6 mt-4">
            {/* New / Removed Hosts */}
            {(delta.hosts.added.length > 0 || delta.hosts.removed.length > 0 || delta.hosts.changed.length > 0) && (
              <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-200 mb-3">🖥️ Host Changes</h3>
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-400 border-b border-slate-700">
                    <th className="py-1 px-2">Status</th><th className="py-1 px-2">IP</th><th className="py-1 px-2">Role</th>
                    <th className="py-1 px-2">Conns</th><th className="py-1 px-2">Alerts</th>
                  </tr></thead>
                  <tbody>
                    {delta.hosts.added.map(h => (
                      <tr key={h.ip} className="border-b border-slate-800/50 bg-red-500/5">
                        <td className="py-1 px-2"><span className="text-red-400 font-bold">🆕 NEW</span></td>
                        <td className="py-1 px-2 text-slate-200 font-mono">{h.ip}</td>
                        <td className="py-1 px-2 text-slate-400">{h.role}</td>
                        <td className="py-1 px-2 text-slate-300">{h.conn_count}</td>
                        <td className="py-1 px-2 text-slate-300">{h.alert_count}</td>
                      </tr>
                    ))}
                    {delta.hosts.removed.map(h => (
                      <tr key={h.ip} className="border-b border-slate-800/50 bg-green-500/5">
                        <td className="py-1 px-2"><span className="text-green-400 font-bold">🗑️ GONE</span></td>
                        <td className="py-1 px-2 text-slate-200 font-mono">{h.ip}</td>
                        <td className="py-1 px-2 text-slate-400">{h.role}</td>
                        <td className="py-1 px-2 text-slate-300">{h.conn_count}</td>
                        <td className="py-1 px-2 text-slate-300">{h.alert_count}</td>
                      </tr>
                    ))}
                    {delta.hosts.changed.map(h => (
                      <tr key={h.ip} className="border-b border-slate-800/50 bg-yellow-500/5">
                        <td className="py-1 px-2"><span className="text-yellow-400 font-bold">📈 CHG</span></td>
                        <td className="py-1 px-2 text-slate-200 font-mono">{h.ip}</td>
                        <td className="py-1 px-2 text-slate-400">{h.role}</td>
                        <td className="py-1 px-2 text-slate-300">{h.conn_before} → {h.conn_after}</td>
                        <td className="py-1 px-2 text-slate-300">{h.alert_before} → {h.alert_after}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Alert Signature Changes */}
            {delta.alerts.length > 0 && (
              <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-200 mb-3">🚨 Alert Signature Changes</h3>
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-400 border-b border-slate-700">
                    <th className="py-1 px-2">Status</th><th className="py-1 px-2">Signature</th>
                    <th className="py-1 px-2">Severity</th><th className="py-1 px-2">Before</th><th className="py-1 px-2">After</th>
                  </tr></thead>
                  <tbody>
                    {delta.alerts.map(a => (
                      <tr key={a.signature} className={`border-b border-slate-800/50 ${a.status === "new" ? "bg-red-500/5" : a.status === "removed" ? "bg-green-500/5" : "bg-yellow-500/5"}`}>
                        <td className="py-1 px-2"><span className={`font-bold ${a.status === "new" ? "text-red-400" : a.status === "removed" ? "text-green-400" : "text-yellow-400"}`}>{a.status === "new" ? "🆕 NEW" : a.status === "removed" ? "✅ RESOLVED" : "📈 CHANGED"}</span></td>
                        <td className="py-1 px-2 text-slate-200 max-w-xs truncate">{a.signature}</td>
                        <td className="py-1 px-2"><span className={`uppercase text-[10px] font-bold ${a.severity === "critical" ? "text-red-400" : a.severity === "high" ? "text-orange-400" : a.severity === "medium" ? "text-yellow-400" : "text-slate-400"}`}>{a.severity}</span></td>
                        <td className="py-1 px-2 text-cyan-300">{a.before_count}</td>
                        <td className="py-1 px-2 text-orange-300">{a.after_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ── Temporal Diff Tables continued (Findings, IOCs, DNS) ── */}
        {viewMode === "temporal" && delta && (
          <div className="space-y-6 mt-4">
            {/* Finding Changes */}
            {delta.findings.length > 0 && (
              <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-200 mb-3">🔍 Finding Changes</h3>
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-slate-400 border-b border-slate-700">
                    <th className="py-1 px-2">Status</th><th className="py-1 px-2">Title</th>
                    <th className="py-1 px-2">Severity</th><th className="py-1 px-2">Sensor</th>
                  </tr></thead>
                  <tbody>
                    {delta.findings.map(f => (
                      <tr key={f.title} className={`border-b border-slate-800/50 ${f.status === "new" ? "bg-red-500/5" : "bg-green-500/5"}`}>
                        <td className="py-1 px-2"><span className={`font-bold ${f.status === "new" ? "text-red-400" : "text-green-400"}`}>{f.status === "new" ? "🆕 NEW" : "✅ RESOLVED"}</span></td>
                        <td className="py-1 px-2 text-slate-200">{f.title}</td>
                        <td className="py-1 px-2"><span className={`uppercase text-[10px] font-bold ${f.severity === "critical" ? "text-red-400" : f.severity === "high" ? "text-orange-400" : "text-yellow-400"}`}>{f.severity}</span></td>
                        <td className="py-1 px-2 text-slate-400">{f.sensor}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* IOC Changes */}
            {(delta.iocs.added.length > 0 || delta.iocs.removed.length > 0) && (
              <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-200 mb-3">☣️ IOC Changes</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-xs font-bold text-red-400 mb-2">🆕 New IOCs ({delta.iocs.added.length})</h4>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {delta.iocs.added.map(v => <div key={v} className="text-xs text-slate-300 font-mono bg-red-500/5 px-2 py-0.5 rounded">{v}</div>)}
                      {delta.iocs.added.length === 0 && <div className="text-xs text-slate-500">None</div>}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-green-400 mb-2">✅ Removed IOCs ({delta.iocs.removed.length})</h4>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {delta.iocs.removed.map(v => <div key={v} className="text-xs text-slate-300 font-mono bg-green-500/5 px-2 py-0.5 rounded">{v}</div>)}
                      {delta.iocs.removed.length === 0 && <div className="text-xs text-slate-500">None</div>}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* DNS Domain Changes */}
            {(delta.dns.added.length > 0 || delta.dns.removed.length > 0) && (
              <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-200 mb-3">🌐 DNS Domain Changes</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-xs font-bold text-red-400 mb-2">🆕 New Domains ({delta.dns.added.length})</h4>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {delta.dns.added.map(d => <div key={d} className="text-xs text-slate-300 font-mono bg-red-500/5 px-2 py-0.5 rounded">{d}</div>)}
                      {delta.dns.added.length === 0 && <div className="text-xs text-slate-500">None</div>}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-xs font-bold text-green-400 mb-2">✅ Removed Domains ({delta.dns.removed.length})</h4>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {delta.dns.removed.map(d => <div key={d} className="text-xs text-slate-300 font-mono bg-green-500/5 px-2 py-0.5 rounded">{d}</div>)}
                      {delta.dns.removed.length === 0 && <div className="text-xs text-slate-500">None</div>}
                    </div>
                  </div>
                </div>
              </div>
            )}
            {/* New Connection Flows */}
            {flowsQ.isLoading && (
              <div className="text-center py-6 text-slate-400">
                <div className="animate-spin inline-block w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full mb-2" />
                <p className="text-xs">Loading new connection flows…</p>
              </div>
            )}
            {flowsQ.data && flowsQ.data.flows.length > 0 && (
              <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-200 mb-3">🔀 New Connection Flows <span className="text-xs font-normal text-slate-400">({flowsQ.data.total_new_flows} total, showing top {flowsQ.data.flows.length})</span></h3>
                <div className="overflow-x-auto max-h-64 overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="text-left text-slate-400 border-b border-slate-700 sticky top-0 bg-slate-900">
                      <th className="py-1 px-2">Source IP</th><th className="py-1 px-2">Dest IP</th>
                      <th className="py-1 px-2">Port</th><th className="py-1 px-2">Proto</th>
                      <th className="py-1 px-2">Service</th><th className="py-1 px-2">Sessions</th>
                      <th className="py-1 px-2">Bytes ↑</th><th className="py-1 px-2">Bytes ↓</th>
                    </tr></thead>
                    <tbody>
                      {flowsQ.data.flows.map((f, i) => {
                        const fmt = (n: number) => n >= 1e6 ? (n/1e6).toFixed(1) + "M" : n >= 1e3 ? (n/1e3).toFixed(1) + "K" : String(n);
                        return (
                          <tr key={i} className="border-b border-slate-800/50 bg-red-500/5">
                            <td className="py-1 px-2 font-mono text-slate-200">{f.src_ip}</td>
                            <td className="py-1 px-2 font-mono text-slate-200">{f.dest_ip}</td>
                            <td className="py-1 px-2 text-orange-300">{f.dest_port ?? "—"}</td>
                            <td className="py-1 px-2 text-slate-400">{f.proto}</td>
                            <td className="py-1 px-2 text-slate-400">{f.service || "—"}</td>
                            <td className="py-1 px-2 text-slate-300">{f.count}</td>
                            <td className="py-1 px-2 text-cyan-300">{fmt(f.total_bytes_sent)}</td>
                            <td className="py-1 px-2 text-orange-300">{fmt(f.total_bytes_recv)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* LLM Change Narrative */}
            <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-bold text-slate-200">🤖 AI Security Assessment</h3>
                {!narrativeM.data && !narrativeM.isPending && (
                  <button
                    onClick={() => narrativeM.mutate()}
                    className="px-3 py-1 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors"
                  >
                    Generate Narrative
                  </button>
                )}
              </div>
              {narrativeM.isPending && (
                <div className="text-center py-8 text-slate-400">
                  <div className="animate-spin inline-block w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full mb-3" />
                  <p className="text-sm">Generating security assessment… This may take 30-60 seconds.</p>
                </div>
              )}
              {narrativeM.isError && (
                <div className="bg-red-500/10 border border-red-500/30 rounded p-3 text-red-300 text-sm">
                  Failed to generate narrative: {(narrativeM.error as Error).message}
                  <button onClick={() => narrativeM.mutate()} className="ml-3 text-xs underline hover:text-red-200">Retry</button>
                </div>
              )}
              {narrativeM.data && (
                <div className="prose prose-invert prose-sm max-w-none text-slate-300">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{narrativeM.data.narrative_markdown}</ReactMarkdown>
                </div>
              )}
              {!narrativeM.data && !narrativeM.isPending && !narrativeM.isError && (
                <p className="text-xs text-slate-500 italic">Click "Generate Narrative" to have the LLM analyze the temporal changes and produce a security assessment.</p>
              )}
            </div>
          </div>
        )}

        {/* ── Live Report View (original client-side rendering) ── */}
        {viewMode === "live" && (<>
        {/* Print header (only shows in print) */}
        <div className="print-header items-center justify-between border-b-2 border-gray-900 pb-4 mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">AIPAM — Network Analysis Report</h1>
            <p className="text-sm text-gray-600 mt-1">Job ID: {jobId}</p>
            {job?.pcaps && job.pcaps.length > 1 ? (
              <div className="text-sm text-gray-600">
                <span>{job.pcaps.length} Capture Phases:</span>
                {job.pcaps.map((p, i) => (
                  <span key={p.id ?? i} className="ml-2">{p.label || p.filename}{i < job.pcaps!.length - 1 ? "," : ""}</span>
                ))}
              </div>
            ) : (
              job?.pcap_filename && <p className="text-sm text-gray-600">PCAP: {job.pcap_filename}</p>
            )}
            <p className="text-sm text-gray-600">Generated: {new Date().toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-gray-400">AI-Powered Advanced Packet Analysis Machine</p>
          </div>
        </div>

        {/* Screen title */}
        <div className="no-print">
          <h1 className={`text-2xl font-bold ${labelHint("report", activeHelpField)}`} onClick={() => toggleHelp("report")}>
            Network Analysis Report
            {activePhase !== "all" && (
              <span className={`ml-3 text-sm px-2.5 py-1 rounded capitalize ${activePhase === "before" ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30" : "bg-orange-500/20 text-orange-300 border border-orange-500/30"}`}>
                Showing: {activePhase} phase
              </span>
            )}
          </h1>
          {job?.pcaps && job.pcaps.length > 1 ? (
            <div className="mt-1">
              <p className="text-slate-400 text-sm">{job.pcaps.length} Capture Phases (Temporal Comparative Analysis)</p>
              <div className="flex flex-wrap gap-2 mt-1.5">
                {job.pcaps.map((p, i) => (
                  <span key={p.id ?? i} className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-xs">
                    <span className="text-blue-400 font-medium">{p.label || p.filename}</span>
                    <span className="text-slate-500 font-mono">{p.filename}</span>
                    {p.size_bytes ? <span className="text-slate-600">({fmtBytes(p.size_bytes)})</span> : null}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            job?.pcap_filename && (
              <p className="text-slate-400 text-sm mt-1">
                PCAP: <span className="text-slate-300 font-mono">{job.pcap_filename}</span>
                {job.pcap_size_bytes ? ` (${fmtBytes(job.pcap_size_bytes)})` : ""}
              </p>
            )
          )}
        </div>

        {isLoading && <DetailSkeleton />}
        {error && <p className="text-red-400">Failed to load report data.</p>}

        {summary && (
          <div className="flex gap-6">
            {/* ── Sticky TOC sidebar ── */}
            <aside className="report-toc hidden lg:block w-44 flex-shrink-0">
              <TableOfContents entries={tocEntries} />
            </aside>

            <div className="flex-1 min-w-0 space-y-6">
            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  1. EXECUTIVE SUMMARY                                         */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            <div id="sec-executive">
            <Section title="Executive Summary">
              <div className="space-y-4">
                {/* Threat level banner + gauge */}
                <div className={`flex items-center gap-4 p-3 rounded-lg border ${
                  threatLevel === "Critical" ? "bg-red-500/10 border-red-500/30" :
                  threatLevel === "High" ? "bg-red-400/10 border-red-400/30" :
                  threatLevel === "Medium" ? "bg-amber-400/10 border-amber-400/30" :
                  threatLevel === "Low" ? "bg-blue-400/10 border-blue-400/30" :
                  "bg-green-400/10 border-green-400/30"
                }`}>
                  <div className="flex-1">
                    <p className="text-xs text-slate-400 uppercase tracking-wider print:text-gray-500">Overall Threat Level</p>
                    <p className={`text-xl font-bold ${threatColor} print:text-gray-900`}>{threatLevel}</p>
                  </div>
                  <ThreatGauge level={threatLevel} />
                </div>

                <p className="text-slate-300 print:text-gray-700">{summary.headline}</p>

                {/* Job metadata */}
                {job && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    <div className="text-slate-400 print:text-gray-500">
                      <span className="block text-slate-500 print:text-gray-400">Submitted</span>
                      {fmtDate(job.created_at)}
                    </div>
                    <div className="text-slate-400 print:text-gray-500">
                      <span className="block text-slate-500 print:text-gray-400">Completed</span>
                      {fmtDate(job.completed_at)}
                    </div>
                    <div className="text-slate-400 print:text-gray-500">
                      <span className="block text-slate-500 print:text-gray-400">Profile</span>
                      <span className="uppercase">{job.execution_profile}</span>
                    </div>
                    <div className="text-slate-400 print:text-gray-500">
                      <span className="block text-slate-500 print:text-gray-400">Duration</span>
                      {job.metrics?.pcap_stats?.capture_duration_seconds
                        ? fmtDuration(job.metrics.pcap_stats.capture_duration_seconds)
                        : "—"}
                    </div>
                  </div>
                )}
              </div>
            </Section>
            </div>

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  2. KEY METRICS                                               */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            <div id="sec-metrics" className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: "Alerts", value: summary.alert_count ?? 0, color: "text-red-400" },
                  { label: "Findings", value: summary.finding_count ?? 0, color: "text-amber-400" },
                  { label: "IOCs", value: summary.ioc_count ?? 0, color: "text-orange-400" },
                  { label: "Hosts", value: summary.host_count ?? 0, color: "text-blue-400" },
                ].map(({ label, value, color }) => (
                  <div key={label} className="stat-card-print bg-slate-900/60 border border-slate-800 rounded-lg p-4 text-center print:bg-gray-50 print:border-gray-300">
                    <p className={`text-3xl font-bold ${color} print:text-gray-900`}>{value.toLocaleString()}</p>
                    <p className="text-xs text-slate-500 mt-1 uppercase tracking-wider print:text-gray-500">{label}</p>
                  </div>
                ))}
              </div>
              {/* Severity stacked bar */}
              <SeverityStackedBar counts={sevCounts} />
            </div>

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  3. ALERT ANALYSIS                                            */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {alerts.length > 0 && (
              <div id="sec-alerts">
              <Section title="Alert Analysis">
                <div className="space-y-5">
                  {/* Severity breakdown */}
                  <div>
                    <h3 className="text-sm font-semibold text-slate-300 mb-3 print:text-gray-700">Severity Distribution</h3>
                    <div className="flex gap-3 flex-wrap">
                      {(["critical", "high", "medium", "low", "info"] as const).map(sev => {
                        const count = sevCounts[sev] || 0;
                        if (count === 0) return null;
                        return (
                          <div key={sev} className={`px-4 py-2 rounded-lg border ${SEV_BG[sev]} print:bg-gray-100 print:border-gray-300`}>
                            <p className={`text-xl font-bold ${SEV_COLOR[sev]} print:text-gray-900`}>{count}</p>
                            <p className="text-xs text-slate-400 uppercase print:text-gray-500">{sev}</p>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Top alert signatures */}
                  <div>
                    <h3 className="text-sm font-semibold text-slate-300 mb-3 print:text-gray-700">
                      Top Alert Signatures ({sigGroups.length} unique)
                    </h3>
                    <Table
                      headers={["Severity", "Signature", "Count"]}
                      colClasses={["w-24", "", "w-20 text-right"]}
                      rows={sigGroups.slice(0, 15).map(g => [
                        <SeverityBadge severity={g.severity} />,
                        <span className="font-mono text-xs">{g.sig}</span>,
                        <span className="font-mono text-right block">{g.count}</span>,
                      ])}
                    />
                  </div>

                  {/* Alert flow pairs */}
                  {alertFlows.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-slate-300 mb-3 print:text-gray-700">
                        Top Alert Traffic Flows
                      </h3>
                      <Table
                        headers={["Source", "Destination", "Alerts", "Signatures"]}
                        colClasses={["w-36", "w-36", "w-20 text-right", ""]}
                        rows={alertFlows.slice(0, 10).map(f => [
                          <span className="font-mono text-xs">{f.src}</span>,
                          <span className="font-mono text-xs">{f.dest}</span>,
                          <span className="font-mono text-right block">{f.count}</span>,
                          <span className="text-xs text-slate-400 print:text-gray-500">{f.sigs.slice(0, 2).join("; ")}{f.sigs.length > 2 ? ` +${f.sigs.length - 2} more` : ""}</span>,
                        ])}
                      />
                    </div>
                  )}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  3b. THEORIES                                                  */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {theories.length > 0 && (
              <div id="sec-theories">
              <Section title={`Theories (${theories.length})`}>
                <div className="space-y-3">
                  {theories
                    .sort((a, b) => a.rank - b.rank)
                    .map((t, i) => (
                    <div key={t.theory_id} className="p-4 rounded-lg border border-slate-800 bg-slate-900/40 print:bg-gray-50 print:border-gray-300">
                      <div className="flex items-start justify-between gap-3 mb-1.5">
                        <h4 className="text-sm font-semibold text-slate-200 print:text-gray-900">
                          #{i + 1} {t.label}
                        </h4>
                        <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                          t.confidence === "high" ? "bg-green-500/20 text-green-400" :
                          t.confidence === "medium" ? "bg-amber-500/20 text-amber-400" :
                          "bg-slate-700 text-slate-400"
                        }`}>{t.confidence} confidence</span>
                      </div>
                      <span className="inline-block text-[10px] uppercase tracking-wider text-slate-500 mb-2">
                        {t.hypothesis_type.replace(/_/g, " ")} • Score {t.score.toFixed(2)}
                      </span>
                      {t.explanation && <p className="text-sm text-slate-300 print:text-gray-700">{t.explanation}</p>}
                      {t.next_steps.length > 0 && (
                        <details className="mt-2">
                          <summary className="text-xs text-blue-400 cursor-pointer hover:text-blue-300">Next Steps ({t.next_steps.length})</summary>
                          <ul className="mt-1 space-y-1 ml-4 list-disc text-xs text-slate-400">
                            {t.next_steps.map((s, si) => <li key={si}>{s}</li>)}
                          </ul>
                        </details>
                      )}
                      {(t.supporting_evidence.length > 0 || t.contradicting_evidence.length > 0) && (
                        <div className="mt-2 flex gap-4 text-[10px] text-slate-500">
                          {t.supporting_evidence.length > 0 && <span className="text-green-500">✓ {t.supporting_evidence.length} supporting</span>}
                          {t.contradicting_evidence.length > 0 && <span className="text-red-400">✗ {t.contradicting_evidence.length} contradicting</span>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  3c. INCIDENT THREADS (SLICES)                                 */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {slices.length > 0 && (
              <div id="sec-slices">
              <Section title={`Incident Threads (${slices.length})`}>
                <div className="space-y-3">
                  {slices
                    .sort((a, b) => a.rank - b.rank)
                    .map((sl, i) => (
                    <div key={sl.slice_id} className={`p-4 rounded-lg border ${SEV_BG[sl.severity] || SEV_BG.info} print:bg-gray-50 print:border-gray-300`}>
                      <div className="flex items-start justify-between gap-3 mb-1.5">
                        <h4 className="text-sm font-semibold text-slate-200 print:text-gray-900">
                          #{i + 1} {sl.label}
                        </h4>
                        <SeverityBadge severity={sl.severity} />
                      </div>
                      <div className="flex gap-3 text-[10px] text-slate-500 mb-2 flex-wrap">
                        <span className="uppercase">{sl.slice_type.replace(/_/g, " ")}</span>
                        <span>Confidence: {(sl.confidence * 100).toFixed(0)}%</span>
                        {sl.host_ips.length > 0 && <span>Hosts: {sl.host_ips.slice(0, 3).join(", ")}{sl.host_ips.length > 3 ? ` +${sl.host_ips.length - 3}` : ""}</span>}
                        {sl.alert_ids.length > 0 && <span>{sl.alert_ids.length} alerts</span>}
                        {sl.finding_ids.length > 0 && <span>{sl.finding_ids.length} findings</span>}
                      </div>
                      {sl.summary && <p className="text-sm text-slate-300 print:text-gray-700">{sl.summary}</p>}
                      {sl.time_start && sl.time_end && (
                        <p className="mt-1 text-[10px] text-slate-500">Timespan: {new Date(sl.time_start).toLocaleString()} → {new Date(sl.time_end).toLocaleString()}</p>
                      )}
                    </div>
                  ))}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  4. DETAILED FINDINGS                                         */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {findings.length > 0 && (
              <div id="sec-findings">
              <Section title="Detailed Findings">
                <div className="space-y-4">
                  {findings
                    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
                    .map((f, i) => (
                    <div key={f.finding_id} className={`p-4 rounded-lg border ${SEV_BG[f.severity] || SEV_BG.info} print:bg-gray-50 print:border-gray-300`}>
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <h4 className="text-sm font-semibold text-slate-200 print:text-gray-900">
                          {i + 1}. {f.title}
                        </h4>
                        <SeverityBadge severity={f.severity} />
                      </div>
                      {f.summary && (
                        <p className="text-sm text-slate-300 mb-2 print:text-gray-700">{f.summary}</p>
                      )}
                      {/* Evidence cross-links */}
                      {f.evidence && (f.evidence as any).source_ips && (
                        <div className="flex gap-2 flex-wrap mb-2">
                          {((f.evidence as any).source_ips as string[] || []).slice(0, 4).map((ip: string) => (
                            <Link key={ip} to={`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}`}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-blue-400 border border-slate-700 hover:border-blue-500">
                              🖥️ <span className="font-mono">{ip}</span>
                            </Link>
                          ))}
                        </div>
                      )}
                      {f.evidence && Object.keys(f.evidence).length > 0 && (
                        <details className="mt-2">
                          <summary className="text-xs text-slate-400 cursor-pointer hover:text-slate-300 print:text-gray-500">
                            View Evidence
                          </summary>
                          <pre className="mt-2 text-xs bg-slate-950/50 rounded p-3 overflow-x-auto text-slate-400 print:bg-gray-100 print:text-gray-600">
                            {JSON.stringify(f.evidence, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  5. INDICATORS OF COMPROMISE                                  */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {iocs.length > 0 && (
              <div id="sec-iocs">
              <Section title="Indicators of Compromise (IOCs)">
                <Table
                  headers={["Type", "Value", "Severity", "Confidence", "Sources"]}
                  colClasses={["w-20", "", "w-20", "w-24 text-right", ""]}
                  rows={iocs.map(ioc => [
                    <span className="text-xs font-medium uppercase text-slate-400 print:text-gray-500">{ioc.type}</span>,
                    <span className="font-mono text-xs break-all">{ioc.value}</span>,
                    ioc.severity ? <SeverityBadge severity={ioc.severity} /> : <span className="text-slate-500">—</span>,
                    ioc.confidence != null
                      ? <span className="font-mono text-right block">{(ioc.confidence * 100).toFixed(0)}%</span>
                      : <span className="text-slate-500 text-right block">—</span>,
                    <span className="text-xs text-slate-400 print:text-gray-500">{ioc.sources?.join(", ") || "—"}</span>,
                  ])}
                />
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  5b. ANOMALIES / ANNOTATIONS                                   */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {annotations.length > 0 && (
              <div id="sec-annotations">
              <Section title={`Anomalies & Context (${annotations.length})`}>
                <div className="space-y-3">
                  {annotations
                    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
                    .map(ann => (
                    <div key={ann.annotation_id} className={`p-4 rounded-lg border ${SEV_BG[ann.severity] || SEV_BG.info} print:bg-gray-50 print:border-gray-300`}>
                      <div className="flex items-start justify-between gap-3 mb-1.5">
                        <h4 className="text-sm font-semibold text-slate-200 print:text-gray-900">{ann.title}</h4>
                        <SeverityBadge severity={ann.severity} />
                      </div>
                      <div className="flex gap-3 text-[10px] text-slate-500 mb-2">
                        <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(ann.host_ip)}`} className="text-blue-400 hover:underline font-mono">{ann.host_ip}</Link>
                        <span>{ann.metric_category} / {ann.metric_name}</span>
                        {ann.deviation_factor != null && <span className="text-amber-400">{ann.deviation_factor.toFixed(1)}× deviation</span>}
                      </div>
                      <p className="text-sm text-slate-300 print:text-gray-700">{ann.why_unusual}</p>
                      {ann.description && ann.description !== ann.why_unusual && (
                        <p className="text-xs text-slate-400 mt-1 print:text-gray-500">{ann.description}</p>
                      )}
                      {(ann.baseline_value != null || ann.observed_value != null) && (
                        <div className="mt-2 flex gap-4 text-[10px] text-slate-500">
                          {ann.baseline_value != null && <span>Baseline: {ann.baseline_value.toFixed(2)}</span>}
                          {ann.observed_value != null && <span>Observed: <span className="text-amber-400">{ann.observed_value.toFixed(2)}</span></span>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  6. HOST ANALYSIS                                             */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {hosts.length > 0 && (
              <div id="sec-hosts">
              <Section title="Host Analysis">
                <div className="space-y-5">
                  {/* Internal hosts */}
                  {internalHosts.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-slate-300 mb-3 print:text-gray-700">
                        Internal Hosts ({internalHosts.length})
                      </h3>
                      <Table
                        headers={["IP Address", "Connections", "Alerts", "Sent", "Received"]}
                        colClasses={["", "w-28 text-right", "w-20 text-right", "w-24 text-right", "w-24 text-right"]}
                        rows={internalHosts
                          .sort((a, b) => (b.alert_count || 0) - (a.alert_count || 0))
                          .map(h => [
                            <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(h.ip)}`}
                              className="font-mono text-xs text-blue-400 hover:underline print:text-gray-900 print:no-underline">{h.ip}</Link>,
                            <span className="font-mono text-right block">{h.conn_count.toLocaleString()}</span>,
                            h.alert_count > 0
                              ? <span className="font-mono text-right block text-red-400 print:text-gray-900">{h.alert_count}</span>
                              : <span className="font-mono text-right block text-slate-500">0</span>,
                            <span className="font-mono text-right block text-xs">{fmtBytes(h.bytes_sent)}</span>,
                            <span className="font-mono text-right block text-xs">{fmtBytes(h.bytes_recv)}</span>,
                          ])}
                      />
                    </div>
                  )}

                  {/* External hosts */}
                  {externalHosts.length > 0 && (
                    <div>
                      <h3 className="text-sm font-semibold text-slate-300 mb-3 print:text-gray-700">
                        External Hosts ({externalHosts.length})
                      </h3>
                      <Table
                        headers={["IP Address", "Connections", "Alerts", "Sent", "Received", "Top Domains"]}
                        colClasses={["", "w-28 text-right", "w-20 text-right", "w-24 text-right", "w-24 text-right", ""]}
                        rows={externalHosts
                          .sort((a, b) => (b.alert_count || 0) - (a.alert_count || 0))
                          .slice(0, 20)
                          .map(h => [
                            <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(h.ip)}`}
                              className="font-mono text-xs text-blue-400 hover:underline print:text-gray-900">{h.ip}</Link>,
                            <span className="font-mono text-right block">{h.conn_count.toLocaleString()}</span>,
                            h.alert_count > 0
                              ? <span className="font-mono text-right block text-red-400 print:text-gray-900">{h.alert_count}</span>
                              : <span className="font-mono text-right block text-slate-500">0</span>,
                            <span className="font-mono text-right block text-xs">{fmtBytes(h.bytes_sent)}</span>,
                            <span className="font-mono text-right block text-xs">{fmtBytes(h.bytes_recv)}</span>,
                            <span className="text-xs text-slate-400 print:text-gray-500 truncate max-w-[200px] block">
                              {h.top_domains?.slice(0, 2).join(", ") || "—"}
                            </span>,
                          ])}
                      />
                    </div>
                  )}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  7. TOP SIGNALS                                               */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {summary.top_signals && summary.top_signals.length > 0 && (
              <div id="sec-signals">
              <Section title="Top Threat Signals">
                <div className="space-y-2">
                  {summary.top_signals.map((sig, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 bg-amber-400/5 border border-amber-400/20 rounded-lg print:bg-yellow-50 print:border-yellow-200">
                      <span className="text-amber-400 font-bold text-sm mt-0.5">{i + 1}</span>
                      <span className="text-sm text-slate-300 print:text-gray-700 font-mono">{sig}</span>
                    </div>
                  ))}
                </div>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  8. RECOMMENDATIONS                                           */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {summary.recommendations && summary.recommendations.length > 0 && (
              <div id="sec-recommendations">
              <Section title="Recommendations">
                <ol className="space-y-3">
                  {summary.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-3">
                      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-blue-500/20 text-blue-400 text-xs font-bold flex items-center justify-center print:bg-blue-100 print:text-blue-800">
                        {i + 1}
                      </span>
                      <span className="text-sm text-slate-300 print:text-gray-700">{rec}</span>
                    </li>
                  ))}
                </ol>
              </Section>
              </div>
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  FOOTER                                                        */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            <div className="text-center text-xs text-slate-600 pt-4 border-t border-slate-800 print:border-gray-300 print:text-gray-400">
              <p>Report generated by AIPAM — AI-Powered Advanced Packet Analysis Machine</p>
              <p className="mt-1">Job: {jobId} • {new Date().toLocaleString()}</p>
            </div>
            </div>
          </div>
        )}
        </>)}
      </div>
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </>
  );
};

