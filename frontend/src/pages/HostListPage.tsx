import React, { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type HostListItem, type HostRole } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

const ROLE_COLORS: Record<string, string> = {
  internal: "text-blue-400 bg-blue-400/10",
  external: "text-amber-400 bg-amber-400/10",
  unknown: "text-slate-400 bg-slate-400/10",
};

export const HostListPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [roleFilter, setRoleFilter] = useState<HostRole | "">("");
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "hosts", roleFilter],
    queryFn: () => api.listHosts(jobId!, { role: roleFilter || undefined, limit: 200 }),
    enabled: !!jobId,
  });

  const hosts = data?.items ?? [];

  return (
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Hosts</span>
      </nav>

      <div className="flex items-center justify-between">
        <h1 className={`text-xl font-semibold ${labelHint("hosts", activeHelpField)}`} onClick={() => toggleHelp("hosts")}>Hosts ({hosts.length})</h1>
        <select value={roleFilter} onChange={e => setRoleFilter(e.target.value as HostRole | "")}
          className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
          <option value="">All roles</option>
          <option value="internal">Internal</option>
          <option value="external">External</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading hosts…</p>}
      {error && <p className="text-red-400">Failed to load hosts.</p>}

      {!isLoading && hosts.length === 0 && (
        <p className="text-slate-500">No hosts found for this job.</p>
      )}

      {hosts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
              <tr>
                <th className="px-3 py-2">IP Address</th>
                <th className="px-3 py-2">Role</th>
                <th className="px-3 py-2 text-right">Connections</th>
                <th className="px-3 py-2 text-right">Bytes Sent</th>
                <th className="px-3 py-2 text-right">Bytes Recv</th>
                <th className="px-3 py-2 text-right">Alerts</th>
                <th className="px-3 py-2">Top Domains</th>
                <th className="px-3 py-2 text-center">AI</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h: HostListItem) => (
                <tr key={h.ip} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-3 py-2">
                    <Link to={`/jobs/${jobId}/hosts/${encodeURIComponent(h.ip)}`}
                      className="text-blue-400 hover:underline font-mono">{h.ip}</Link>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${ROLE_COLORS[h.role] ?? ROLE_COLORS.unknown}`}>
                      {h.role}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right font-mono">{h.conn_count}</td>
                  <td className="px-3 py-2 text-right font-mono text-slate-400">
                    {h.bytes_sent != null ? h.bytes_sent.toLocaleString() : "—"}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-slate-400">
                    {h.bytes_recv != null ? h.bytes_recv.toLocaleString() : "—"}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {h.alert_count > 0
                      ? <span className="text-red-400 font-bold">{h.alert_count}</span>
                      : <span className="text-slate-600">0</span>}
                  </td>
                  <td className="px-3 py-2 text-slate-400 text-xs max-w-[200px] truncate">
                    {h.top_domains?.slice(0, 3).join(", ") || "—"}
                  </td>
                  <td className="px-3 py-2 text-center">
                    <button
                      onClick={() => navigate(`/jobs/${jobId}/chat?ask=${encodeURIComponent(`Analyze host ${h.ip}. What is its role, what suspicious activity is associated with it, and what are the key alerts and findings?`)}&hint=${encodeURIComponent(`host:${h.ip}`)}`)}
                      className="text-emerald-400/60 hover:text-emerald-400 transition-colors text-sm"
                      title={`Ask AI about ${h.ip}`}
                    >
                      🤖
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};

