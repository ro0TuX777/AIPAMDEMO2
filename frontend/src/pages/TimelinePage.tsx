import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type TimelineItem } from "../api";

const TYPE_ICONS: Record<string, string> = {
  connection: "🔗", alert: "🚨", dns: "🌐", tls: "🔒",
  finding: "🔍", ioc: "⚠️", file: "📄", unknown: "•",
};

const SEV_COLORS: Record<string, string> = {
  critical: "border-red-500", high: "border-orange-400",
  medium: "border-amber-400", low: "border-blue-400", info: "border-slate-600",
};

export const TimelinePage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "timeline"],
    queryFn: () => api.listTimeline(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });

  const events = data?.items ?? [];

  return (
    <div className="space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Timeline</span>
      </nav>

      <h1 className="text-xl font-semibold">Timeline ({events.length} events)</h1>

      {isLoading && <p className="text-slate-400 animate-pulse">Loading timeline…</p>}
      {error && <p className="text-red-400">Failed to load timeline.</p>}

      {!isLoading && events.length === 0 && (
        <p className="text-slate-500">No timeline events found for this job.</p>
      )}

      {events.length > 0 && (
        <div className="space-y-1">
          {events.map((evt: TimelineItem, idx: number) => (
            <div key={idx}
              className={`flex items-start gap-3 px-3 py-2 border-l-2 ${SEV_COLORS[evt.severity ?? "info"] ?? SEV_COLORS.info} hover:bg-slate-800/30`}>
              <span className="text-sm shrink-0">{TYPE_ICONS[evt.type] ?? TYPE_ICONS.unknown}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className="text-xs text-slate-500 font-mono shrink-0">
                    {new Date(evt.ts).toLocaleString()}
                  </span>
                  <span className="text-xs text-slate-600 uppercase">{evt.type}</span>
                </div>
                <p className="text-sm text-slate-300 truncate">{evt.title}</p>
                {evt.description && <p className="text-xs text-slate-500 truncate mt-0.5">{evt.description}</p>}
                {evt.entities && (evt.entities.src_ip || evt.entities.dest_ip) && (
                  <p className="text-xs text-slate-600 font-mono mt-0.5">
                    {evt.entities.src_ip}{evt.entities.src_port ? `:${evt.entities.src_port}` : ""}
                    {evt.entities.dest_ip ? ` → ${evt.entities.dest_ip}` : ""}
                    {evt.entities.dest_port ? `:${evt.entities.dest_port}` : ""}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

