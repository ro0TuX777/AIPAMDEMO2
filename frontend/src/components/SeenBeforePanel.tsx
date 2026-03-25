import React from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type CorrelationMatch, type CampaignCandidate } from "../api";

/** Per-match-type display config. */
const MATCH_TYPE_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
  same_host:       { label: "Host",    color: "text-blue-400 bg-blue-400/10",   icon: "🖥" },
  same_ioc:        { label: "IOC",     color: "text-red-400 bg-red-400/10",     icon: "🔴" },
  same_mitre:      { label: "MITRE",   color: "text-amber-400 bg-amber-400/10", icon: "⚔" },
  similar_pattern: { label: "Pattern", color: "text-purple-400 bg-purple-400/10", icon: "🔗" },
};

const FALLBACK_MATCH = MATCH_TYPE_CONFIG.similar_pattern;

interface SeenBeforePanelProps {
  jobId: string;
  itemId?: string;
  host?: string;
  ioc?: string;
}

export const SeenBeforePanel: React.FC<SeenBeforePanelProps> = ({ jobId, itemId, host, ioc }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["correlations", jobId, itemId, host, ioc],
    queryFn: () => api.getCorrelations(jobId, { item_id: itemId, host, ioc, limit: 10 }),
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Seen Before?</h3>
        <div className="animate-pulse space-y-2">
          {[1, 2, 3].map(i => <div key={i} className="h-8 bg-slate-800 rounded" />)}
        </div>
      </div>
    );
  }

  if (!data || (data.matches.length === 0 && data.campaigns.length === 0)) {
    return (
      <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Seen Before?</h3>
        <p className="text-xs text-slate-500">No prior occurrences found across other jobs.</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Seen Before?</h3>
        <span className="text-xs text-slate-500">{data.total_matches} match{data.total_matches !== 1 ? "es" : ""}</span>
      </div>

      {/* Matches */}
      <div className="space-y-1.5">
        {data.matches.map((m: CorrelationMatch, i: number) => {
          const info = MATCH_TYPE_CONFIG[m.match_type] ?? FALLBACK_MATCH;
          return (
            <Link
              key={`${m.job_id}-${m.matched_entity}-${i}`}
              to={`/jobs/${m.job_id}`}
              className="flex items-start gap-2 p-2 rounded hover:bg-slate-800/60 transition-colors group"
            >
              <span className="text-sm mt-0.5">{info.icon}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${info.color}`}>{info.label}</span>
                  <span className="text-xs text-slate-300 truncate">{m.matched_entity}</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 truncate">{m.context}</p>
                <p className="text-[10px] text-slate-600 mt-0.5">
                  {m.job_name} {m.job_created_at ? `· ${m.job_created_at.slice(0, 10)}` : ""}
                </p>
              </div>
              <div className="flex-shrink-0">
                <div className="w-8 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full"
                    style={{ width: `${Math.round(m.similarity_score * 100)}%` }}
                  />
                </div>
              </div>
            </Link>
          );
        })}
      </div>

      {/* Campaign candidates */}
      {data.campaigns.length > 0 && (
        <div className="border-t border-slate-800 pt-2 mt-2">
          <h4 className="text-[10px] font-semibold text-amber-400 uppercase tracking-wider mb-1.5">
            ⚡ Possible Campaign
          </h4>
          {data.campaigns.map((c: CampaignCandidate) => (
            <div key={c.campaign_id} className="bg-amber-900/10 border border-amber-900/30 rounded p-2">
              <p className="text-xs text-amber-300">{c.label}</p>
              <div className="flex gap-3 mt-1 text-[10px] text-slate-400">
                <span>{c.job_ids.length} jobs</span>
                {c.shared_iocs.length > 0 && <span>{c.shared_iocs.length} IOCs</span>}
                {c.shared_hosts.length > 0 && <span>{c.shared_hosts.length} hosts</span>}
                <span>confidence: {Math.round(c.confidence * 100)}%</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

