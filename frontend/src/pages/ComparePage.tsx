import React from "react";
import { useParams, Link } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery, useMutation } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  api,
  type TemporalDeltaResponse,
  type TemporalFlowsResponse,
  type TemporalNarrativeResponse,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

const fmt = (n: number) => n >= 1e9 ? (n/1e9).toFixed(1) + "GB" : n >= 1e6 ? (n/1e6).toFixed(1) + "MB" : n >= 1e3 ? (n/1e3).toFixed(1) + "KB" : n + "B";
const fmtShort = (n: number) => n >= 1e6 ? (n/1e6).toFixed(1) + "M" : n >= 1e3 ? (n/1e3).toFixed(1) + "K" : String(n);

export const ComparePage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const temporalQ = useQuery<TemporalDeltaResponse>({
    queryKey: ["job", jobId, "temporal-delta"],
    queryFn: () => api.getTemporalDelta(jobId!),
    enabled: !!jobId,
    staleTime: 30_000,
  });
  const delta = temporalQ.data;

  const flowsQ = useQuery<TemporalFlowsResponse>({
    queryKey: ["job", jobId, "temporal-flows"],
    queryFn: () => api.getTemporalFlows(jobId!),
    enabled: !!jobId,
    staleTime: 30_000,
  });

  const narrativeM = useMutation<TemporalNarrativeResponse>({
    mutationFn: () => api.generateTemporalNarrative(jobId!),
  });

  if (!jobId) return null;

  return (
    <>
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId.slice(0, 8)}…</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Compare</span>
      </nav>

      <div className="flex items-center justify-between">
        <h1 className={`text-xl font-semibold text-slate-100 ${labelHint("compare", activeHelpField)}`} onClick={() => toggleHelp("compare")}>
          🔬 {delta ? `${delta.phase_labels[0].charAt(0).toUpperCase() + delta.phase_labels[0].slice(1)} / ${delta.phase_labels[1].charAt(0).toUpperCase() + delta.phase_labels[1].slice(1)}` : "Phase"} Comparison
        </h1>
        <a
          href={api.getTemporalExportUrl(jobId)}
          className="px-3 py-1.5 text-xs rounded border border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 transition-colors"
          download
        >
          ⬇ Export Report
        </a>
      </div>

      {/* Loading */}
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
        <div className="space-y-6">
          {/* Phase Summary */}
          <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
            <h3 className="text-sm font-bold text-slate-200 mb-3">📋 Phase Summary</h3>
            <div className="grid grid-cols-2 gap-6">
              {(["before", "after"] as const).map((phase, idx) => {
                const ps = delta.phase_summary[phase];
                const label = delta.phase_labels[idx];
                const color = idx === 0 ? "text-cyan-300" : "text-orange-300";
                return (
                  <div key={phase}>
                    <div className={`text-xs font-bold uppercase mb-2 ${color}`}>{label}</div>
                    <div className="grid grid-cols-5 gap-2 text-center text-xs">
                      {[
                        { label: "Hosts", val: ps.host_count },
                        { label: "Alerts", val: ps.alert_count },
                        { label: "Findings", val: ps.finding_count },
                        { label: "Conns", val: ps.connection_count },
                        { label: "IOCs", val: ps.ioc_count },
                      ].map(m => (
                        <div key={m.label}>
                          <div className="text-slate-500">{m.label}</div>
                          <div className={`text-lg font-bold ${color}`}>{m.val}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Containment Indicators */}
          {(delta.containment_indicators.removed_c2_connections > 0 ||
            delta.containment_indicators.reduced_alert_categories.length > 0 ||
            delta.containment_indicators.new_defensive_activity.length > 0) && (
            <div className="bg-emerald-900/20 border border-emerald-500/30 rounded-lg p-4">
              <h3 className="text-sm font-bold text-emerald-300 mb-3">🛡️ Containment Indicators</h3>
              <div className="grid grid-cols-3 gap-4 text-xs">
                <div>
                  <div className="text-slate-400 mb-1">Removed C2 Connections</div>
                  <div className="text-2xl font-bold text-emerald-400">{delta.containment_indicators.removed_c2_connections}</div>
                </div>
                <div>
                  <div className="text-slate-400 mb-1">Reduced Alert Categories</div>
                  <div className="space-y-0.5">
                    {delta.containment_indicators.reduced_alert_categories.length > 0
                      ? delta.containment_indicators.reduced_alert_categories.map(c => <div key={c} className="text-emerald-300">{c}</div>)
                      : <div className="text-slate-500">None</div>}
                  </div>
                </div>
                <div>
                  <div className="text-slate-400 mb-1">New Defensive Activity</div>
                  <div className="space-y-0.5">
                    {delta.containment_indicators.new_defensive_activity.length > 0
                      ? delta.containment_indicators.new_defensive_activity.map(a => <div key={a} className="text-blue-300">{a}</div>)
                      : <div className="text-slate-500">None</div>}
                  </div>
                </div>
              </div>
            </div>
          )}
          {/* Severity Shift */}
          <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
            <h3 className="text-sm font-bold text-slate-200 mb-3">⚡ Severity Shift</h3>
            <div className="grid grid-cols-4 gap-3">
              {(["critical", "high", "medium", "low"] as const).map(sev => {
                const s = delta.severity_shift[sev];
                const colors: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-blue-400" };
                return (
                  <div key={sev} className="text-center">
                    <div className={`text-xs font-bold uppercase ${colors[sev]}`}>{sev}</div>
                    <div className="text-cyan-300">{s.before}</div>
                    <div className="text-slate-500 text-xs">→</div>
                    <div className="text-orange-300">{s.after}</div>
                    {s.delta !== 0 && (
                      <div className={`text-[10px] font-bold ${s.delta > 0 ? "text-red-400" : "text-green-400"}`}>
                        {s.delta > 0 ? "+" : ""}{s.delta}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Delta Summary Cards */}
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

          {/* Traffic Volume */}
          <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
            <h3 className="text-sm font-bold text-slate-200 mb-3">📊 Traffic Volume</h3>
            <div className="grid grid-cols-3 gap-4 text-center">
              {[
                { label: "Bytes Sent", before: delta.summary.traffic.before.bytes_sent, after: delta.summary.traffic.after.bytes_sent },
                { label: "Bytes Received", before: delta.summary.traffic.before.bytes_recv, after: delta.summary.traffic.after.bytes_recv },
                { label: "Total Bytes", before: delta.summary.traffic.before.bytes_sent + delta.summary.traffic.before.bytes_recv, after: delta.summary.traffic.after.bytes_sent + delta.summary.traffic.after.bytes_recv },
              ].map(t => {
                const pct = t.before > 0 ? ((t.after - t.before) / t.before * 100) : 0;
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

          {/* Deep-link shortcuts */}
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="text-slate-500">Jump to phase data:</span>
            {["hosts", "alerts", "findings"].map(section => (
              <React.Fragment key={section}>
                <Link to={`/jobs/${jobId}/${section}?pcap_label=${delta.phase_labels[0]}`} className="text-cyan-400 hover:underline">{section.charAt(0).toUpperCase() + section.slice(1)} ({delta.phase_labels[0]})</Link>
                <Link to={`/jobs/${jobId}/${section}?pcap_label=${delta.phase_labels[1]}`} className="text-orange-400 hover:underline">{section.charAt(0).toUpperCase() + section.slice(1)} ({delta.phase_labels[1]})</Link>
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* Diff tables and flows/narrative - rendered below the summary section */}
      {delta && <DiffTables delta={delta} flowsQ={flowsQ} narrativeM={narrativeM} jobId={jobId} />}

    </div>
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
    <JobSubPageNav jobId={jobId} currentPath="compare" showTemporal />
    </>
  );
};

/* ── Diff Tables sub-component (keeps main component readable) ── */
interface DiffTablesProps {
  delta: TemporalDeltaResponse;
  flowsQ: ReturnType<typeof useQuery<TemporalFlowsResponse>>;
  narrativeM: ReturnType<typeof useMutation<TemporalNarrativeResponse>>;
  jobId: string;
}
const DiffTables: React.FC<DiffTablesProps> = ({ delta, flowsQ, narrativeM, jobId }) => (
  <div className="space-y-6 mt-4">
    {/* Host Changes */}
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
                <td className="py-1 px-2 text-slate-200 font-mono"><Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(h.ip)}`} className="hover:underline">{h.ip}</Link></td>
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
                <td className="py-1 px-2 text-slate-200 font-mono"><Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(h.ip)}`} className="hover:underline">{h.ip}</Link></td>
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
              {flowsQ.data.flows.map((f, i) => (
                <tr key={i} className="border-b border-slate-800/50 bg-red-500/5">
                  <td className="py-1 px-2 font-mono text-slate-200">{f.src_ip}</td>
                  <td className="py-1 px-2 font-mono text-slate-200">{f.dest_ip}</td>
                  <td className="py-1 px-2 text-orange-300">{f.dest_port ?? "—"}</td>
                  <td className="py-1 px-2 text-slate-400">{f.proto}</td>
                  <td className="py-1 px-2 text-slate-400">{f.service || "—"}</td>
                  <td className="py-1 px-2 text-slate-300">{f.count}</td>
                  <td className="py-1 px-2 text-cyan-300">{fmtShort(f.total_bytes_sent)}</td>
                  <td className="py-1 px-2 text-orange-300">{fmtShort(f.total_bytes_recv)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )}

    {/* AI Security Assessment */}
    <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-slate-200">🤖 AI Security Assessment</h3>
        {!narrativeM.data && !narrativeM.isPending && (
          <button onClick={() => narrativeM.mutate()} className="px-3 py-1 text-xs bg-emerald-600 hover:bg-emerald-500 text-white rounded-md transition-colors">
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
);

