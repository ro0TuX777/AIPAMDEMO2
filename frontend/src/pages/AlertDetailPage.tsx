import React from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type AlertRelatedHost, type AlertRelatedConnection } from "../api";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500", high: "text-orange-400", medium: "text-amber-400",
  low: "text-blue-400", info: "text-slate-400",
};

export const AlertDetailPage: React.FC = () => {
  const { jobId, alertId } = useParams<{ jobId: string; alertId: string }>();
  const navigate = useNavigate();

  const { data: alert, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "alert", alertId],
    queryFn: () => api.getAlert(jobId!, alertId!),
    enabled: !!jobId && !!alertId,
  });

  if (isLoading) return <p className="text-slate-400 animate-pulse">Loading alert…</p>;
  if (error || !alert) return <p className="text-red-400">Failed to load alert.</p>;

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}/alerts`} className="hover:text-white">Alerts</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">{alert.signature.slice(0, 50)}</span>
      </nav>

      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-semibold">{alert.signature}</h1>
          <button
            onClick={() => navigate(`/jobs/${jobId}/chat?ask=${encodeURIComponent(`Analyze alert "${alert.signature}" (severity: ${alert.severity}, SID: ${alert.sid ?? "unknown"}). Source: ${alert.src_ip ?? "unknown"}${alert.src_port ? ":" + alert.src_port : ""} → Destination: ${alert.dest_ip ?? "unknown"}${alert.dest_port ? ":" + alert.dest_port : ""}. Category: ${alert.category ?? "unknown"}. What does this alert mean, is it a true positive, and what should an analyst do next?`)}&hint=${encodeURIComponent(`alert:${alertId}`)}`)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-400 hover:text-emerald-300 text-sm rounded-lg transition-colors"
            title="Ask AI about this alert"
          >
            🤖 Ask AI
          </button>
        </div>
        <div className="flex gap-4 mt-2 text-sm">
          <span className={`font-medium ${SEV_COLORS[alert.severity] ?? "text-slate-400"}`}>
            {alert.severity.toUpperCase()}
          </span>
          {alert.category && <span className="text-slate-400">Category: {alert.category}</span>}
          {alert.engine && <span className="text-slate-500">Engine: {alert.engine}</span>}
          {alert.sid && <span className="text-slate-500">SID: {alert.sid}</span>}
        </div>
      </div>

      {/* Details card */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-800/40 rounded-lg p-4">
        <div><div className="text-xs text-slate-500 uppercase">Time</div>
          <div className="font-mono text-sm">{new Date(alert.ts).toLocaleString()}</div></div>
        <div><div className="text-xs text-slate-500 uppercase">Source</div>
          <div className="font-mono text-sm">
            {alert.src_ip ? <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(alert.src_ip)}`}
              className="text-blue-400 hover:underline">{alert.src_ip}</Link> : "—"}
            {alert.src_port ? `:${alert.src_port}` : ""}
          </div></div>
        <div><div className="text-xs text-slate-500 uppercase">Destination</div>
          <div className="font-mono text-sm">
            {alert.dest_ip ? <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(alert.dest_ip)}`}
              className="text-blue-400 hover:underline">{alert.dest_ip}</Link> : "—"}
            {alert.dest_port ? `:${alert.dest_port}` : ""}
          </div></div>
        <div><div className="text-xs text-slate-500 uppercase">Protocol</div>
          <div className="text-sm">{alert.proto ?? "—"}</div></div>
      </div>

      {alert.community_id && (
        <div className="text-xs text-slate-500">Community ID: <span className="font-mono">{alert.community_id}</span></div>
      )}

      {/* References & Tags */}
      {alert.refs && alert.refs.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-1">References</h2>
          <ul className="list-disc list-inside text-sm text-blue-400">
            {alert.refs.map((r, i) => <li key={i}><a href={r} target="_blank" rel="noreferrer" className="hover:underline">{r}</a></li>)}
          </ul>
        </div>
      )}
      {alert.tags && alert.tags.length > 0 && (
        <div className="flex gap-2 flex-wrap">
          {alert.tags.map((t, i) => <span key={i} className="bg-slate-700 text-slate-300 px-2 py-0.5 rounded text-xs">{t}</span>)}
        </div>
      )}

      {/* Related Hosts */}
      {alert.related_hosts.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Related Hosts</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {alert.related_hosts.map((h: AlertRelatedHost) => (
              <Link key={h.ip} to={`/jobs/${jobId}/hosts/${encodeURIComponent(h.ip)}`}
                className="bg-slate-800/50 rounded-lg p-3 hover:bg-slate-800 transition-colors">
                <div className="font-mono text-blue-400">{h.ip}</div>
                <div className="text-xs text-slate-500 mt-1">
                  {h.role} · {h.conn_count ?? 0} conns · {h.alert_count ?? 0} alerts
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Related Connections */}
      {alert.related_connections.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Related Connections</h2>
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
              <tr>
                <th className="px-2 py-1">Time</th><th className="px-2 py-1">Src</th>
                <th className="px-2 py-1">Dest</th><th className="px-2 py-1">Proto</th>
                <th className="px-2 py-1">Service</th>
              </tr>
            </thead>
            <tbody>
              {alert.related_connections.map((c: AlertRelatedConnection) => (
                <tr key={c.connection_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-2 py-1 text-xs font-mono text-slate-500">{c.ts ? new Date(c.ts).toLocaleString() : "—"}</td>
                  <td className="px-2 py-1 font-mono text-xs">{c.src_ip}{c.src_port ? `:${c.src_port}` : ""}</td>
                  <td className="px-2 py-1 font-mono text-xs">{c.dest_ip}{c.dest_port ? `:${c.dest_port}` : ""}</td>
                  <td className="px-2 py-1 text-xs">{c.proto ?? "—"}</td>
                  <td className="px-2 py-1 text-xs text-slate-400">{c.service ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

