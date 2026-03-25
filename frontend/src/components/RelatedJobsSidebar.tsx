import React from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type RelatedJob } from "../api";

/** Overlap-type display config: label + Tailwind colour classes. */
const OVERLAP_CONFIG: Record<string, { label: string; color: string }> = {
  shared_iocs:  { label: "IOCs",  color: "text-red-400 bg-red-400/10" },
  shared_hosts: { label: "Hosts", color: "text-blue-400 bg-blue-400/10" },
  shared_mitre: { label: "MITRE", color: "text-amber-400 bg-amber-400/10" },
};

const FALLBACK_OVERLAP = { label: "Other", color: "text-slate-400 bg-slate-700" };

interface RelatedJobsSidebarProps {
  jobId: string;
}

export const RelatedJobsSidebar: React.FC<RelatedJobsSidebarProps> = ({ jobId }) => {
  const { data, isLoading } = useQuery({
    queryKey: ["related-jobs", jobId],
    queryFn: () => api.getRelatedJobs(jobId),
    staleTime: 120_000,
  });

  if (isLoading) {
    return (
      <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Related Jobs</h3>
        <div className="animate-pulse space-y-2">
          {[1, 2, 3].map(i => <div key={i} className="h-10 bg-slate-800 rounded" />)}
        </div>
      </div>
    );
  }

  if (!data || data.related_jobs.length === 0) {
    return (
      <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Related Jobs</h3>
        <p className="text-xs text-slate-500">No related jobs found.</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4 space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Related Jobs</h3>
        <span className="text-xs text-slate-500">{data.related_jobs.length}</span>
      </div>

      <div className="space-y-1">
        {data.related_jobs.map((rj: RelatedJob) => (
          <Link
            key={rj.job_id}
            to={`/jobs/${rj.job_id}`}
            className="block p-2 rounded hover:bg-slate-800/60 transition-colors group"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-200 truncate max-w-[70%] group-hover:text-white">
                {rj.job_name || rj.job_id.slice(0, 8)}
              </span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${(OVERLAP_CONFIG[rj.overlap_type] ?? FALLBACK_OVERLAP).color}`}>
                {(OVERLAP_CONFIG[rj.overlap_type] ?? FALLBACK_OVERLAP).label}
              </span>
            </div>
            <div className="flex items-center justify-between mt-1">
              <span className="text-[10px] text-slate-500 truncate max-w-[60%]">
                {rj.shared_entities.slice(0, 3).join(", ")}
                {rj.shared_entities.length > 3 ? ` +${rj.shared_entities.length - 3}` : ""}
              </span>
              <div className="flex items-center gap-1">
                <div className="w-10 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-500 rounded-full"
                    style={{ width: `${Math.round(rj.relevance_score * 100)}%` }}
                  />
                </div>
                <span className="text-[9px] text-slate-600">{Math.round(rj.relevance_score * 100)}%</span>
              </div>
            </div>
            {rj.job_created_at && (
              <p className="text-[10px] text-slate-600 mt-0.5">{rj.job_created_at.slice(0, 10)}</p>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
};

