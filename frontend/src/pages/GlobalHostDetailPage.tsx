import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

const ROLE_COLORS: Record<string, string> = {
  internal: "text-blue-400 bg-blue-400/10",
  external: "text-amber-400 bg-amber-400/10",
  unknown: "text-slate-400 bg-slate-400/10",
};

export const GlobalHostDetailPage: React.FC = () => {
  const { ip } = useParams<{ ip: string }>();
  const decodedIp = decodeURIComponent(ip || "");
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const { data, isLoading, error } = useQuery({
    queryKey: ["global-host", decodedIp],
    queryFn: () => api.getGlobalHost(decodedIp),
    enabled: !!decodedIp,
  });

  const host = data?.host;

  return (
    <div className="flex gap-6 items-start">
    <div className="space-y-6 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to="/hosts" className="hover:text-white">Global Hosts</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200 font-mono">{decodedIp}</span>
      </nav>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading host…</p>}
      {error && <p className="text-red-400">Failed to load host details.</p>}

      {host && (
        <>
          {/* Header */}
          <div className="flex items-center gap-4">
            <h1 className={`text-2xl font-semibold font-mono ${labelHint("global_host_detail", activeHelpField)}`} onClick={() => toggleHelp("global_host_detail")}>{host.ip}</h1>
            {host.hostname && (
              <span className="text-slate-400">({host.hostname})</span>
            )}
            {host.seen_as_internal && (
              <span className="px-2 py-0.5 rounded text-xs text-blue-300 bg-blue-400/10">
                Internal
              </span>
            )}
          </div>

          {/* Stats grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <p className="text-xs text-slate-500 uppercase">Jobs Seen In</p>
              <p className="text-2xl font-bold">{host.job_count}</p>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <p className="text-xs text-slate-500 uppercase">Total Alerts</p>
              <p className="text-2xl font-bold text-red-400">{host.total_alerts}</p>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <p className="text-xs text-slate-500 uppercase">Total Findings</p>
              <p className="text-2xl font-bold text-amber-400">{host.total_findings}</p>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <p className="text-xs text-slate-500 uppercase">Roles</p>
              <div className="flex flex-wrap gap-1 mt-1">
                {host.roles.length > 0
                  ? host.roles.map((r) => (
                      <span key={r} className={`px-2 py-0.5 rounded text-xs ${ROLE_COLORS[r] ?? ROLE_COLORS.unknown}`}>
                        {r}
                      </span>
                    ))
                  : <span className="text-slate-600">—</span>}
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div className="text-xs text-slate-500">
            First seen: <span className="text-slate-300">{host.first_seen || "—"}</span>
            <span className="mx-3">|</span>
            Last seen: <span className="text-slate-300">{host.last_seen || "—"}</span>
          </div>

          {/* Cross-Job History */}
          <div>
            <h2 className={`text-lg font-semibold mb-3 ${labelHint("global_host_history", activeHelpField)}`} onClick={() => toggleHelp("global_host_history")}>Cross-Job History</h2>
            {host.history.length === 0 ? (
              <p className="text-slate-500">No history entries.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
                    <tr>
                      <th className="px-3 py-2">Job</th>
                      <th className="px-3 py-2">Timestamp</th>
                      <th className="px-3 py-2">Role</th>
                      <th className="px-3 py-2 text-right">Alerts</th>
                      <th className="px-3 py-2 text-right">Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {host.history.map((h, i) => (
                      <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                        <td className="px-3 py-2">
                          <Link
                            to={`/jobs/${h.job_id}`}
                            className="text-blue-400 hover:underline font-mono text-xs"
                          >
                            {h.job_id.slice(0, 8)}…
                          </Link>
                        </td>
                        <td className="px-3 py-2 text-slate-400 text-xs">{h.ts || "—"}</td>
                        <td className="px-3 py-2">
                          <span className={`px-2 py-0.5 rounded text-xs ${ROLE_COLORS[h.role ?? "unknown"] ?? ROLE_COLORS.unknown}`}>
                            {h.role || "unknown"}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-right">
                          {h.alert_count > 0
                            ? <span className="text-red-400">{h.alert_count}</span>
                            : <span className="text-slate-600">0</span>}
                        </td>
                        <td className="px-3 py-2 text-right">
                          {h.finding_count > 0
                            ? <span className="text-amber-400">{h.finding_count}</span>
                            : <span className="text-slate-600">0</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};

