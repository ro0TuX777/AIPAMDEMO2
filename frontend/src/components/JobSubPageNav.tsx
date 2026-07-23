import React from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";

/**
 * Job sub-page navigation.
 *
 * Previously this was a flat row of 17 peer tabs, which gave an analyst no
 * sense of where to start and overflowed its container on the job detail page.
 * The tabs are now grouped by what they are *for*: triage the queue, look at
 * raw evidence, read derived analysis, produce output. Routes are unchanged —
 * every existing deep link still resolves.
 */

export interface JobTab {
  label: string;
  path: string;
  /** Only shown for multi-PCAP (temporal) jobs. */
  temporalOnly?: boolean;
}

export interface JobTabGroup {
  /** Stable key used to track which group is open. */
  id: string;
  label: string;
  tabs: JobTab[];
}

export const JOB_TAB_GROUPS: JobTabGroup[] = [
  {
    id: "triage",
    label: "Triage",
    tabs: [{ label: "🔎 Investigate", path: "investigation" }],
  },
  {
    id: "evidence",
    label: "Evidence",
    tabs: [
      { label: "Hosts", path: "hosts" },
      { label: "Alerts", path: "alerts" },
      { label: "Findings", path: "findings" },
      { label: "Extracted Files", path: "files" },
      { label: "Streams", path: "streams" },
      { label: "Raw Events", path: "raw-events" },
      { label: "Binary", path: "binary" },
      { label: "IOCs", path: "iocs" },
      { label: "Timeline", path: "timeline" },
    ],
  },
  {
    id: "analysis",
    label: "Analysis",
    tabs: [
      { label: "Sigma", path: "sigma" },
      { label: "Theories", path: "theories" },
      { label: "Slices", path: "slices" },
      { label: "Why Unusual?", path: "annotations" },
      { label: "🕒 Correlations", path: "correlations" },
      { label: "Storyline", path: "storyline" },
      { label: "Graph", path: "graph" },
      { label: "🔬 Compare", path: "compare", temporalOnly: true },
    ],
  },
  {
    id: "output",
    label: "Output",
    tabs: [
      { label: "📋 Build Case", path: "proof" },
      { label: "Report", path: "report" },
      { label: "Exports", path: "artifacts" },
      { label: "AI Chat", path: "chat" },
    ],
  },
];

/** Flat list of every tab, in group order. */
export const JOB_SUB_TABS: JobTab[] = JOB_TAB_GROUPS.flatMap((g) => g.tabs);

/** Which group contains a given path segment. Defaults to the first group. */
export function groupForPath(path: string): JobTabGroup {
  return JOB_TAB_GROUPS.find((g) => g.tabs.some((t) => t.path === path)) ?? JOB_TAB_GROUPS[0];
}

/**
 * True when the job has more than one PCAP, which is what makes the phase
 * comparison view meaningful.
 *
 * Reads through the shared react-query cache, so it's free on any page that
 * already loaded the job. `enabled` gates the fetch to the only case that needs
 * the answer — a group with a temporal-only tab is open — so the ~18 sub-pages
 * whose open group has no such tab never issue this request at all.
 */
function useIsTemporalJob(jobId: string | undefined, enabled: boolean): boolean {
  const { data } = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId && enabled,
    staleTime: 60_000,
  });
  return (data?.job?.pcaps?.length ?? 0) > 1;
}

interface JobSubPageNavProps {
  jobId: string;
  /** Current page's path segment, e.g. "findings". */
  currentPath: string;
  /**
   * Render without the top border/margin — used where the nav sits directly
   * under a page header rather than at the foot of the content.
   */
  flush?: boolean;
  /**
   * Group to open when `currentPath` matches no tab (i.e. on the job detail
   * page, which is the parent of all of them).
   */
  defaultGroupId?: string;
}

export const JobSubPageNav: React.FC<JobSubPageNavProps> = ({
  jobId,
  currentPath,
  flush,
  defaultGroupId,
}) => {
  const matchedGroup = JOB_TAB_GROUPS.find((g) => g.tabs.some((t) => t.path === currentPath));
  const activeGroup =
    matchedGroup ??
    JOB_TAB_GROUPS.find((g) => g.id === defaultGroupId) ??
    JOB_TAB_GROUPS[0];
  const [openGroupId, setOpenGroupId] = React.useState(activeGroup.id);

  // Follow the route when the user navigates via a link outside this nav.
  React.useEffect(() => {
    setOpenGroupId(activeGroup.id);
  }, [activeGroup.id]);

  const openGroup = JOB_TAB_GROUPS.find((g) => g.id === openGroupId) ?? activeGroup;

  // Only the temporal-only tabs care whether the job is temporal, and they all
  // live in one group — so the job-detail fetch is only worth making when that
  // group is the one on screen.
  const openGroupHasTemporalTab = openGroup.tabs.some((t) => t.temporalOnly);
  const isTemporal = useIsTemporalJob(jobId, openGroupHasTemporalTab);
  const visibleTabs = openGroup.tabs.filter((t) => !t.temporalOnly || isTemporal);

  return (
    <div className={flush ? "w-full" : "mt-8 border-t border-slate-800 pt-2 w-full"}>
      {/* Group row */}
      <nav className="flex flex-wrap gap-1" data-testid="job-nav-groups" aria-label="Section">
        {JOB_TAB_GROUPS.map((group) => {
          // "Active" means the current page lives in this group — on the job
          // detail page nothing is active, so no group gets the marker.
          const isActive = group.id === matchedGroup?.id;
          const isOpen = group.id === openGroup.id;
          return (
            <button
              key={group.id}
              onClick={() => setOpenGroupId(group.id)}
              data-testid={`job-nav-group-${group.id}`}
              aria-current={isActive ? "page" : undefined}
              className={`px-3 py-1.5 text-sm rounded-t transition-colors ${
                isOpen
                  ? "bg-slate-800/70 text-slate-100 font-medium"
                  : "text-slate-500 hover:text-slate-300"
              } ${isActive ? "border-b-2 border-blue-500" : "border-b-2 border-transparent"}`}
            >
              {group.label}
            </button>
          );
        })}
      </nav>

      {/* Tabs of the open group */}
      <nav
        className="flex flex-wrap gap-1 bg-slate-800/70 rounded-b px-1 py-1"
        data-testid="job-subpage-nav"
        aria-label={`${openGroup.label} pages`}
      >
        {visibleTabs.map(({ label, path }) => (
          <Link
            key={path}
            to={`/jobs/${jobId}/${path}`}
            className={`px-3 py-1.5 text-sm rounded transition-colors ${
              path === currentPath
                ? "bg-blue-500/15 text-blue-300 font-medium"
                : "text-slate-400 hover:text-slate-100 hover:bg-slate-700/60"
            }`}
          >
            {label}
          </Link>
        ))}
      </nav>
    </div>
  );
};
