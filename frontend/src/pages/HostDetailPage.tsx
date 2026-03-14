import React from "react";
import { useParams, Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  api,
  type ConnectionItem,
  type DnsQueryItem,
  type TlsSessionItem,
  type AlertItem,
  type FileItem,
} from "../api";

const TABS = [
  { label: "Connections", path: "connections" },
  { label: "DNS", path: "dns" },
  { label: "TLS", path: "tls" },
  { label: "Alerts", path: "alerts" },
  { label: "Files", path: "files" },
] as const;

export const HostDetailPage: React.FC = () => {
  const { jobId, ip } = useParams<{ jobId: string; ip: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const base = `/jobs/${jobId}/hosts/${ip}`;

  const { data: hostData, isLoading } = useQuery({
    queryKey: ["host", jobId, ip],
    queryFn: () => api.getHost(jobId!, ip!),
    enabled: !!jobId && !!ip,
  });

  const h = hostData?.host;

  return (
    <div className="space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}/hosts`} className="hover:text-white">Hosts</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">{ip}</span>
      </nav>

      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">{ip}</h1>
            <p className="text-xs text-slate-500 font-mono mt-1">Host Identity / Analysis</p>
          </div>
          <button
            onClick={() => navigate(`/jobs/${jobId}/chat?ask=${encodeURIComponent(`Analyze host ${ip}. What is its role, what suspicious activity is associated with it, and what are the key alerts and findings?`)}&hint=${encodeURIComponent(`host:${ip}`)}`)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-400 hover:text-emerald-300 text-sm rounded-lg transition-colors"
            title="Ask AI about this host"
          >
            🤖 Ask AI
          </button>
        </div>

        {h?.global_stats && h.global_stats.job_count > 1 && (
          <div className="flex items-center gap-4 bg-slate-900/80 border border-blue-500/20 rounded-lg px-4 py-2">
            <div className="flex flex-col">
              <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider text-blue-400/80">Cross-Job History</span>
              <div className="flex items-center gap-3 mt-1">
                <div className="flex flex-col">
                  <span className="text-xs text-slate-400">Jobs</span>
                  <span className="text-sm font-bold text-white leading-none">{h.global_stats.job_count}</span>
                </div>
                <div className="h-6 w-px bg-slate-800" />
                <div className="flex flex-col">
                  <span className="text-xs text-slate-400">Total Alerts</span>
                  <span className={`text-sm font-bold leading-none ${h.global_stats.total_alerts > 0 ? "text-red-400" : "text-white"}`}>
                    {h.global_stats.total_alerts}
                  </span>
                </div>
              </div>
            </div>
            {h.global_history && h.global_history.length > 1 && (
              <div className="hidden lg:flex flex-col ml-2 border-l border-slate-800 pl-4 max-w-[200px]">
                <span className="text-[10px] text-slate-500 uppercase font-bold mb-1">Recent Jobs</span>
                <div className="flex flex-wrap gap-1">
                  {h.global_history.slice(0, 3).map((hist, i) => (
                    <Link key={i} to={`/jobs/${hist.job_id}/hosts/${ip}`}
                      className="text-[10px] bg-slate-800 hover:bg-slate-700 px-1.5 py-0.5 rounded text-slate-400 hover:text-white transition-colors border border-slate-700">
                      {hist.job_id.slice(0, 8)}
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex gap-2 border-b border-slate-700 pb-1">
        {TABS.map(t => {
          const active = location.pathname.endsWith(t.path);
          return (
            <Link key={t.path} to={`${base}/${t.path}`}
              className={`px-3 py-1 text-sm rounded-t ${active ? "bg-slate-800 text-white" : "text-slate-400 hover:text-white"}`}>
              {t.label}
            </Link>
          );
        })}
      </div>
      <Outlet />
    </div>
  );
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500", high: "text-orange-400", medium: "text-amber-400",
  low: "text-blue-400", info: "text-slate-400",
};

/** Data-fetching sub-tab component — dispatches based on label prop. */
export const HostSubTab: React.FC<{ label: string }> = ({ label }) => {
  const { jobId, ip } = useParams<{ jobId: string; ip: string }>();

  if (label === "Connections") return <ConnectionsTab jobId={jobId!} ip={ip!} />;
  if (label === "DNS Queries") return <DnsTab jobId={jobId!} ip={ip!} />;
  if (label === "TLS Sessions") return <TlsTab jobId={jobId!} ip={ip!} />;
  if (label === "Alerts") return <AlertsTab jobId={jobId!} ip={ip!} />;
  if (label === "Files") return <FilesTab jobId={jobId!} ip={ip!} />;
  return <p className="text-slate-400">{label} — no data available.</p>;
};

const ConnectionsTab: React.FC<{ jobId: string; ip: string }> = ({ jobId, ip }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["host", jobId, ip, "connections"],
    queryFn: () => api.listConnections(jobId, ip, { limit: 100 }),
  });
  if (isLoading) return <p className="text-slate-400 animate-pulse">Loading…</p>;
  const items = data?.items ?? [];
  if (!items.length) return <p className="text-slate-500">No connections.</p>;
  return (
    <table className="w-full text-sm text-left">
      <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
        <tr><th className="px-2 py-1">Time</th><th className="px-2 py-1">Dest IP</th><th className="px-2 py-1">Port</th>
          <th className="px-2 py-1">Proto</th><th className="px-2 py-1">Service</th><th className="px-2 py-1 text-right">Duration</th>
          <th className="px-2 py-1 text-right">Sent</th><th className="px-2 py-1 text-right">Recv</th></tr>
      </thead>
      <tbody>
        {items.map((c: ConnectionItem) => (
          <tr key={c.connection_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
            <td className="px-2 py-1 text-xs font-mono text-slate-500">{new Date(c.ts).toLocaleString()}</td>
            <td className="px-2 py-1 font-mono">{c.dest_ip}</td>
            <td className="px-2 py-1 font-mono text-slate-400">{c.dest_port ?? "—"}</td>
            <td className="px-2 py-1 text-xs">{c.proto}</td>
            <td className="px-2 py-1 text-xs text-slate-400">{c.service ?? "—"}</td>
            <td className="px-2 py-1 text-right text-xs">{c.duration_seconds != null ? `${c.duration_seconds.toFixed(1)}s` : "—"}</td>
            <td className="px-2 py-1 text-right text-xs font-mono">{c.bytes_sent?.toLocaleString() ?? "—"}</td>
            <td className="px-2 py-1 text-right text-xs font-mono">{c.bytes_recv?.toLocaleString() ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const DnsTab: React.FC<{ jobId: string; ip: string }> = ({ jobId, ip }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["host", jobId, ip, "dns"],
    queryFn: () => api.listDns(jobId, ip, { limit: 100 }),
  });
  if (isLoading) return <p className="text-slate-400 animate-pulse">Loading…</p>;
  const items = data?.items ?? [];
  if (!items.length) return <p className="text-slate-500">No DNS queries.</p>;
  return (
    <table className="w-full text-sm text-left">
      <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
        <tr><th className="px-2 py-1">Time</th><th className="px-2 py-1">Query</th><th className="px-2 py-1">Type</th>
          <th className="px-2 py-1">Answers</th><th className="px-2 py-1">Rcode</th></tr>
      </thead>
      <tbody>
        {items.map((d: DnsQueryItem) => (
          <tr key={d.dns_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
            <td className="px-2 py-1 text-xs font-mono text-slate-500">{new Date(d.ts).toLocaleString()}</td>
            <td className="px-2 py-1 font-mono text-slate-300">{d.query}</td>
            <td className="px-2 py-1 text-xs">{d.qtype ?? "—"}</td>
            <td className="px-2 py-1 text-xs text-slate-400 max-w-[200px] truncate">{d.answers?.join(", ") || "—"}</td>
            <td className="px-2 py-1 text-xs">{d.rcode ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const TlsTab: React.FC<{ jobId: string; ip: string }> = ({ jobId, ip }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["host", jobId, ip, "tls"],
    queryFn: () => api.listTls(jobId, ip, { limit: 100 }),
  });
  if (isLoading) return <p className="text-slate-400 animate-pulse">Loading…</p>;
  const items = data?.items ?? [];
  if (!items.length) return <p className="text-slate-500">No TLS sessions.</p>;
  return (
    <table className="w-full text-sm text-left">
      <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
        <tr><th className="px-2 py-1">Time</th><th className="px-2 py-1">Dest</th><th className="px-2 py-1">SNI</th>
          <th className="px-2 py-1">Version</th><th className="px-2 py-1">JA3</th></tr>
      </thead>
      <tbody>
        {items.map((t: TlsSessionItem) => (
          <tr key={t.tls_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
            <td className="px-2 py-1 text-xs font-mono text-slate-500">{new Date(t.ts).toLocaleString()}</td>
            <td className="px-2 py-1 font-mono">{t.dest_ip}:{t.dest_port ?? "—"}</td>
            <td className="px-2 py-1 text-slate-300">{t.sni ?? "—"}</td>
            <td className="px-2 py-1 text-xs">{t.version ?? "—"}</td>
            <td className="px-2 py-1 text-xs font-mono text-slate-500 max-w-[120px] truncate">{t.ja3 ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const AlertsTab: React.FC<{ jobId: string; ip: string }> = ({ jobId, ip }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["host", jobId, ip, "alerts"],
    queryFn: () => api.listHostAlerts(jobId, ip, { limit: 100 }),
  });
  if (isLoading) return <p className="text-slate-400 animate-pulse">Loading…</p>;
  const items = data?.items ?? [];
  if (!items.length) return <p className="text-slate-500">No alerts.</p>;
  return (
    <table className="w-full text-sm text-left">
      <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
        <tr><th className="px-2 py-1">Time</th><th className="px-2 py-1">Severity</th><th className="px-2 py-1">Signature</th>
          <th className="px-2 py-1">Category</th></tr>
      </thead>
      <tbody>
        {items.map((a: AlertItem) => (
          <tr key={a.alert_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
            <td className="px-2 py-1 text-xs font-mono text-slate-500">{new Date(a.ts).toLocaleString()}</td>
            <td className={`px-2 py-1 text-xs font-medium ${SEV_COLORS[a.severity] ?? "text-slate-400"}`}>{a.severity.toUpperCase()}</td>
            <td className="px-2 py-1 text-slate-300">{a.signature}</td>
            <td className="px-2 py-1 text-xs text-slate-400">{a.category ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const FilesTab: React.FC<{ jobId: string; ip: string }> = ({ jobId, ip }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["host", jobId, ip, "files"],
    queryFn: () => api.listHostFiles(jobId, ip, { limit: 100 }),
  });
  if (isLoading) return <p className="text-slate-400 animate-pulse">Loading…</p>;
  const items = data?.items ?? [];
  if (!items.length) return <p className="text-slate-500">No files.</p>;
  return (
    <table className="w-full text-sm text-left">
      <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
        <tr><th className="px-2 py-1">SHA256</th><th className="px-2 py-1">MIME</th>
          <th className="px-2 py-1 text-right">Size</th><th className="px-2 py-1">Source</th></tr>
      </thead>
      <tbody>
        {items.map((f: FileItem) => (
          <tr key={f.file_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
            <td className="px-2 py-1 font-mono text-xs text-slate-400 max-w-[200px] truncate">{f.sha256}</td>
            <td className="px-2 py-1 text-xs">{f.mime ?? "—"}</td>
            <td className="px-2 py-1 text-right text-xs">{f.size_bytes.toLocaleString()} B</td>
            <td className="px-2 py-1 text-xs text-slate-400">{f.source ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};
