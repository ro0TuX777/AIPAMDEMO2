import React, { useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery } from "@tanstack/react-query";
import { api, type IocItem, type IocType } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

const TYPE_LABELS: Record<string, string> = {
  ip: "IP", domain: "DOM", url: "URL", hash: "HSH",
  ja3: "JA3", ja3s: "J3S", sni: "SNI", email: "EML",
  mutex: "MTX", registry: "REG",
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400",
  medium: "text-yellow-400", low: "text-blue-400", info: "text-slate-400",
};

export const IocsListPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [typeFilter, setTypeFilter] = useState<IocType | "">("");
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "iocs", typeFilter],
    queryFn: () => api.listIocs(jobId!, { type: typeFilter || undefined, limit: 200 }),
    enabled: !!jobId,
  });

  const iocs = data?.items ?? [];

  return (
    <>
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">IOCs</span>
      </nav>

      <div className="flex items-center justify-between">
        <h1 className={`text-xl font-semibold ${labelHint("iocs", activeHelpField)}`} onClick={() => toggleHelp("iocs")}>Indicators of Compromise ({iocs.length})</h1>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value as IocType | "")}
          className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
          <option value="">All types</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash">Hash</option>
          <option value="ja3">JA3</option>
          <option value="ja3s">JA3S</option>
          <option value="sni">SNI</option>
          <option value="email">Email</option>
          <option value="mutex">Mutex</option>
          <option value="registry">Registry</option>
        </select>
      </div>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading IOCs…</p>}
      {error && <p className="text-red-400">Failed to load IOCs.</p>}

      {!isLoading && iocs.length === 0 && (
        <p className="text-slate-500">No IOCs found for this job.</p>
      )}

      {iocs.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
              <tr>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Value</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2 text-right">Confidence</th>
                <th className="px-3 py-2">Reason</th>
                <th className="px-3 py-2">Sources</th>
                <th className="px-3 py-2 text-center">AI</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc: IocItem) => (
                <tr key={ioc.ioc_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-3 py-2">
                    <span className="text-xs">{TYPE_LABELS[ioc.type] ?? "•"} {ioc.type.toUpperCase()}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-slate-300">{ioc.value}</td>
                  <td className="px-3 py-2">
                    <span className={`text-xs font-medium ${SEV_COLORS[ioc.severity ?? ""] ?? "text-slate-400"}`}>
                      {ioc.severity?.toUpperCase() ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right text-slate-400">
                    {ioc.confidence != null ? `${(ioc.confidence * 100).toFixed(0)}%` : "—"}
                  </td>
                  <td className="px-3 py-2 text-sm text-slate-300">
                    {ioc.context || "—"}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">
                    {ioc.sources?.join(", ") || "—"}
                  </td>
                  <td className="px-3 py-2 text-center">
                    <button
                      onClick={() => navigate(`/jobs/${jobId}/chat?ask=${encodeURIComponent(`Analyze IOC "${ioc.value}" (type: ${ioc.type}, severity: ${ioc.severity ?? "unknown"}). ${ioc.context ? ioc.context + ' ' : ''}What is this indicator, where was it seen, and what threat does it represent?`)}&hint=${encodeURIComponent(`ioc:${ioc.value}`)}`)}
                      className="text-emerald-400/60 hover:text-emerald-400 transition-colors text-sm"
                      title={`Ask AI about ${ioc.value}`}
                    >
                      Ask AI
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
    <JobSubPageNav jobId={jobId!} currentPath="iocs" />
    </>
  );
};

