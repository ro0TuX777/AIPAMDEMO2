import React from "react";
import { useParams, Link } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery } from "@tanstack/react-query";
import { api, type TimelineItem } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

const TYPE_LABELS: Record<string, string> = {
  connection: "CONN", alert: "ALR", dns: "DNS", tls: "TLS",
  finding: "FND", ioc: "IOC", file: "FILE",
  c2_callback: "C2", c2_task: "C2T", process: "PROC", unknown: "•",
};

const SEV_COLORS: Record<string, string> = {
  critical: "border-red-500", high: "border-orange-400",
  medium: "border-amber-400", low: "border-blue-400", info: "border-slate-600",
};

const STATUS_BADGES: Record<string, { label: string; cls: string }> = {
  confirmed:     { label: "CONFIRMED",     cls: "text-green-300 bg-green-900/40 border-green-700" },
  corroborated:  { label: "CORROBORATED",  cls: "text-emerald-300 bg-emerald-900/40 border-emerald-700" },
  observed:      { label: "OBSERVED",      cls: "text-slate-400 bg-slate-800 border-slate-600" },
};

export const TimelinePage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "timeline"],
    queryFn: () => api.listTimeline(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });

  const events = data?.items ?? [];

  return (
    <>
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Timeline</span>
      </nav>

      <h1 className={`text-xl font-semibold ${labelHint("timeline", activeHelpField)}`} onClick={() => toggleHelp("timeline")}>Timeline ({events.length} events)</h1>

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
              <span className="text-[10px] font-mono font-bold text-slate-500 shrink-0">{TYPE_LABELS[evt.type] ?? TYPE_LABELS.unknown}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className="text-xs text-slate-500 font-mono shrink-0">
                    {new Date(evt.ts).toLocaleString()}
                  </span>
                  <span className="text-xs text-slate-600 uppercase">{evt.type}</span>
                </div>
                <div className="flex items-center gap-2">
                  <p className="text-sm text-slate-300 truncate">{evt.title}</p>
                  {evt.evidence_status && evt.evidence_status !== "observed" && (() => {
                    const badge = STATUS_BADGES[evt.evidence_status] ?? STATUS_BADGES.observed;
                    return (
                      <span className={`inline-flex px-1.5 py-0.5 text-[9px] font-semibold border rounded ${badge.cls}`}>
                        {badge.label}
                      </span>
                    );
                  })()}
                  {evt.sensor && (
                    <span className="px-1 py-0.5 text-[9px] font-mono text-slate-500 bg-slate-800/60 rounded">
                      {evt.sensor}
                    </span>
                  )}
                </div>
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
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
    <JobSubPageNav jobId={jobId!} currentPath="timeline" />
    </>
  );
};

