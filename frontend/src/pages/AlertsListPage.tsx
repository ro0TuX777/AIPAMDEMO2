import React, { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type AlertItem, type Severity } from "../api";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-amber-400 bg-amber-400/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-slate-400 bg-slate-400/10",
};

export const AlertsListPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [sevFilter, setSevFilter] = useState<Severity | "">("");

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "alerts", sevFilter],
    queryFn: () => api.listAlerts(jobId!, { severity: sevFilter || undefined, limit: 200 }),
    enabled: !!jobId,
  });

  const alerts = data?.items ?? [];

  return (
    <div className="space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Alerts</span>
      </nav>

      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Alerts ({alerts.length})</h1>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value as Severity | "")}
          className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading alerts…</p>}
      {error && <p className="text-red-400">Failed to load alerts.</p>}

      {!isLoading && alerts.length === 0 && (
        <p className="text-slate-500">No alerts found for this job.</p>
      )}

      {alerts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
              <tr>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Signature</th>
                <th className="px-3 py-2">Category</th>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Destination</th>
                <th className="px-3 py-2">Proto</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a: AlertItem) => (
                <tr key={a.alert_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-3 py-2 text-xs font-mono text-slate-500">
                    {new Date(a.ts).toLocaleString()}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLORS[a.severity] ?? SEV_COLORS.info}`}>
                      {a.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <Link to={`/jobs/${jobId}/alerts/${a.alert_id}`}
                      className="text-blue-400 hover:underline">{a.signature}</Link>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400">{a.category ?? "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {a.src_ip ? (
                      <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(a.src_ip)}`}
                        className="text-blue-400 hover:underline">{a.src_ip}</Link>
                    ) : "—"}
                    {a.src_port ? `:${a.src_port}` : ""}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {a.dest_ip ? (
                      <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(a.dest_ip)}`}
                        className="text-blue-400 hover:underline">{a.dest_ip}</Link>
                    ) : "—"}
                    {a.dest_port ? `:${a.dest_port}` : ""}
                  </td>
                  <td className="px-3 py-2 text-xs">{a.proto ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

