import React, { useRef, useCallback, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type JobSummaryResponse,
  type JobDetail,
  type HostListItem,
  type IocItem,
  type AlertItem,
  type FindingItem,
  type Severity,
  type ReportItem,
  type ReportListResponse,
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

export const ReportPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const reportRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();
  const [genMode, setGenMode] = useState<"executive" | "analyst">("analyst");
  const [viewMode, setViewMode] = useState<"live" | "generated">("live");
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  // ── Generated reports ──
  const reportsQ = useQuery<ReportListResponse>({
    queryKey: ["job", jobId, "reports"],
    queryFn: () => api.listReports(jobId!),
    enabled: !!jobId,
  });

  const generateMut = useMutation({
    mutationFn: (mode: "executive" | "analyst") => api.generateReport(jobId!, mode),
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

  // ── Data fetching (parallel) ──
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
    queryKey: ["job", jobId, "alerts", "report"],
    queryFn: () => api.listAlerts(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });

  const findingsQ = useQuery({
    queryKey: ["job", jobId, "findings", "report"],
    queryFn: () => api.listFindings(jobId!, { limit: 50 }),
    enabled: !!jobId,
  });

  const iocsQ = useQuery({
    queryKey: ["job", jobId, "iocs", "report"],
    queryFn: () => api.listIocs(jobId!, { limit: 50 }),
    enabled: !!jobId,
  });

  const hostsQ = useQuery({
    queryKey: ["job", jobId, "hosts", "report"],
    queryFn: () => api.listHosts(jobId!, { limit: 50 }),
    enabled: !!jobId,
  });

  const summary = summaryQ.data;
  const job: JobDetail | undefined = jobQ.data?.job;
  const alerts: AlertItem[] = alertsQ.data?.items ?? [];
  const findings: FindingItem[] = findingsQ.data?.items ?? [];
  const iocs: IocItem[] = iocsQ.data?.items ?? [];
  const hosts: HostListItem[] = hostsQ.data?.items ?? [];

  const isLoading = summaryQ.isLoading || jobQ.isLoading;
  const error = summaryQ.error || jobQ.error;

  // ── Derived data ──
  const sevCounts = countBySeverity(alerts);
  const sigGroups = groupAlertsBySignature(alerts);
  const alertFlows = getAlertFlows(alerts);

  const internalHosts = hosts.filter(h => h.role === "internal");
  const externalHosts = hosts.filter(h => h.role === "external" || h.role === "unknown");

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
            </div>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={genMode}
              onChange={(e) => setGenMode(e.target.value as "executive" | "analyst")}
              className="bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded px-3 py-1.5"
            >
              <option value="analyst">Analyst Report</option>
              <option value="executive">Executive Summary</option>
            </select>
            <button
              onClick={() => generateMut.mutate(genMode)}
              disabled={generateMut.isPending}
              className="px-4 py-1.5 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm font-medium rounded transition-colors"
            >
              {generateMut.isPending ? "Generating…" : "Generate Report"}
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
                  {r.mode} — {r.threat_level.toUpperCase()} ({new Date(r.created_at).toLocaleString()})
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Generated Report View ── */}
        {viewMode === "generated" && activeReport && (
          <Section title={activeReport.title}>
            <div className="space-y-3">
              <div className="flex gap-3 text-xs text-slate-400">
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
              <div className="prose prose-invert prose-sm max-w-none">
                <pre className="whitespace-pre-wrap text-sm text-slate-300 font-sans leading-relaxed bg-slate-950/30 rounded-lg p-4 border border-slate-800">
                  {activeReport.content_markdown}
                </pre>
              </div>
            </div>
          </Section>
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
          <h1 className={`text-2xl font-bold ${labelHint("report", activeHelpField)}`} onClick={() => toggleHelp("report")}>Network Analysis Report</h1>
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
          <>
            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  1. EXECUTIVE SUMMARY                                         */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            <Section title="Executive Summary">
              <div className="space-y-4">
                {/* Threat level banner */}
                <div className={`flex items-center gap-3 p-3 rounded-lg border ${
                  threatLevel === "Critical" ? "bg-red-500/10 border-red-500/30" :
                  threatLevel === "High" ? "bg-red-400/10 border-red-400/30" :
                  threatLevel === "Medium" ? "bg-amber-400/10 border-amber-400/30" :
                  threatLevel === "Low" ? "bg-blue-400/10 border-blue-400/30" :
                  "bg-green-400/10 border-green-400/30"
                }`}>
                  <span className={`inline-block w-3 h-3 rounded-full ${
                    threatLevel === "Critical" || threatLevel === "High" ? "bg-red-500" :
                    threatLevel === "Medium" ? "bg-amber-500" : threatLevel === "Low" ? "bg-blue-500" : "bg-green-500"
                  }`} />
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wider print:text-gray-500">Overall Threat Level</p>
                    <p className={`text-xl font-bold ${threatColor} print:text-gray-900`}>{threatLevel}</p>
                  </div>
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

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  2. KEY METRICS                                               */}
            {/* ═══════════════════════════════════════════════════════════════ */}
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

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  3. ALERT ANALYSIS                                            */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {alerts.length > 0 && (
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
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  4. DETAILED FINDINGS                                         */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {findings.length > 0 && (
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
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  5. INDICATORS OF COMPROMISE                                  */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {iocs.length > 0 && (
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
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  6. HOST ANALYSIS                                             */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {hosts.length > 0 && (
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
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  7. TOP SIGNALS                                               */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {summary.top_signals && summary.top_signals.length > 0 && (
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
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  8. RECOMMENDATIONS                                           */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            {summary.recommendations && summary.recommendations.length > 0 && (
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
            )}

            {/* ═══════════════════════════════════════════════════════════════ */}
            {/*  FOOTER                                                        */}
            {/* ═══════════════════════════════════════════════════════════════ */}
            <div className="text-center text-xs text-slate-600 pt-4 border-t border-slate-800 print:border-gray-300 print:text-gray-400">
              <p>Report generated by AIPAM — AI-Powered Advanced Packet Analysis Machine</p>
              <p className="mt-1">Job: {jobId} • {new Date().toLocaleString()}</p>
            </div>
          </>
        )}
        </>)}
      </div>
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </>
  );
};

