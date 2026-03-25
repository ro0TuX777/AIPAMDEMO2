import React from "react";
import { Link } from "react-router-dom";

/**
 * Canonical tab order for job sub-pages.
 * Shared between JobDetailPage tab bar and bottom navigation.
 */
export const JOB_SUB_TABS = [
  { label: "🔎 Investigate", path: "investigation" },
  { label: "Theories", path: "theories" },
  { label: "Slices", path: "slices" },
  { label: "Why Unusual?", path: "annotations" },
  { label: "Hosts", path: "hosts" },
  { label: "Alerts", path: "alerts" },
  { label: "Findings", path: "findings" },
  { label: "Files", path: "files" },
  { label: "Timeline", path: "timeline" },
  { label: "IOCs", path: "iocs" },
  { label: "Graph", path: "graph" },
  { label: "Artifacts", path: "artifacts" },
  { label: "AI Chat", path: "chat" },
  { label: "Report", path: "report" },
  { label: "📋 Build Case", path: "proof" },
] as const;

/** Tabs that only appear conditionally (e.g. Compare requires multiple PCAP labels). */
export const CONDITIONAL_TABS: { label: string; path: string; condition: "temporal" }[] = [
  { label: "🔬 Compare", path: "compare", condition: "temporal" },
];

interface JobSubPageNavProps {
  jobId: string;
  /** The current page's path segment, e.g. "theories", "alerts" */
  currentPath: string;
  /** When true, temporal-only tabs (Compare) are included. */
  showTemporal?: boolean;
}

/**
 * Bottom navigation tab bar for job sub-pages.
 * Mirrors the tab bar on the Job Detail page — shows all available pages
 * with the current page highlighted, so analysts can jump to any view.
 */
export const JobSubPageNav: React.FC<JobSubPageNavProps> = ({ jobId, currentPath, showTemporal }) => {
  const allTabs = [
    ...JOB_SUB_TABS,
    ...(showTemporal ? CONDITIONAL_TABS : []),
  ];
  return (
    <div className="mt-8 border-t border-slate-800 w-full">
      <nav className="flex gap-1 flex-wrap" data-testid="job-subpage-nav">
        {allTabs.map(({ label, path }) => (
          <Link
            key={path}
            to={`/jobs/${jobId}/${path}`}
            className={`px-4 py-2 text-sm border-b-2 transition-colors ${
              path === currentPath
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-600"
            }`}
          >
            {label}
          </Link>
        ))}
      </nav>
    </div>
  );
};

