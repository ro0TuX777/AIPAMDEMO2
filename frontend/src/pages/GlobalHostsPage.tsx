import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type GlobalHostListItem } from "../api";

const ROLE_COLORS: Record<string, string> = {
  internal: "text-blue-400 bg-blue-400/10",
  external: "text-amber-400 bg-amber-400/10",
  unknown: "text-slate-400 bg-slate-400/10",
};

export const GlobalHostsPage: React.FC = () => {
  const [filter, setFilter] = useState<"" | "true" | "false">("");

  const { data, isLoading, error } = useQuery({
    queryKey: ["global-hosts", filter],
    queryFn: () =>
      api.listGlobalHosts({
        limit: 200,
        internal_only: filter === "" ? undefined : filter === "true",
      }),
  });

  const hosts = data?.items ?? [];

  return (
    <div className="space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Global Hosts</span>
      </nav>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Global Hosts ({hosts.length})</h1>
          <p className="text-sm text-slate-400 mt-1">
            Host identities tracked across all analysis jobs
          </p>
        </div>
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value as "" | "true" | "false")}
          className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300"
        >
          <option value="">All hosts</option>
          <option value="true">Internal only</option>
          <option value="false">External only</option>
        </select>
      </div>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading hosts…</p>}
      {error && <p className="text-red-400">Failed to load global hosts.</p>}

      {!isLoading && hosts.length === 0 && (
        <p className="text-slate-500">
          No global hosts yet. Hosts are registered when analysis jobs complete.
        </p>
      )}

      {hosts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
              <tr>
                <th className="px-3 py-2">IP Address</th>
                <th className="px-3 py-2">Hostname</th>
                <th className="px-3 py-2">Roles</th>
                <th className="px-3 py-2 text-right">Jobs</th>
                <th className="px-3 py-2 text-right">Alerts</th>
                <th className="px-3 py-2 text-right">Findings</th>
                <th className="px-3 py-2">First Seen</th>
                <th className="px-3 py-2">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h: GlobalHostListItem) => (
                <tr key={h.ip} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-3 py-2">
                    <Link
                      to={`/hosts/${encodeURIComponent(h.ip)}`}
                      className="text-blue-400 hover:underline font-mono"
                    >
                      {h.ip}
                    </Link>
                    {h.seen_as_internal && (
                      <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] text-blue-300 bg-blue-400/10">
                        INT
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-400">{h.hostname || "—"}</td>
                  <td className="px-3 py-2">
                    {h.roles.length > 0
                      ? h.roles.map((r) => (
                          <span
                            key={r}
                            className={`px-2 py-0.5 rounded text-xs mr-1 ${ROLE_COLORS[r] ?? ROLE_COLORS.unknown}`}
                          >
                            {r}
                          </span>
                        ))
                      : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="px-3 py-2 text-right font-mono">{h.job_count}</td>
                  <td className="px-3 py-2 text-right">
                    {h.total_alerts > 0 ? (
                      <span className="text-red-400 font-bold">{h.total_alerts}</span>
                    ) : (
                      <span className="text-slate-600">0</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {h.total_findings > 0 ? (
                      <span className="text-amber-400 font-bold">{h.total_findings}</span>
                    ) : (
                      <span className="text-slate-600">0</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-slate-400 text-xs">
                    {h.first_seen?.slice(0, 10) || "—"}
                  </td>
                  <td className="px-3 py-2 text-slate-400 text-xs">
                    {h.last_seen?.slice(0, 10) || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

