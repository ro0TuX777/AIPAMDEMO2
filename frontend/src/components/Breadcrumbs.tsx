import React from "react";
import { Link } from "react-router-dom";

/**
 * One breadcrumb segment. Omit `to` for the final (current) crumb — it renders
 * as static emphasised text rather than a link.
 */
export interface Crumb {
  label: string;
  to?: string;
  /** Render in a monospace face (IPs, hashes, IDs). */
  mono?: boolean;
}

interface BreadcrumbsProps {
  items: Crumb[];
  className?: string;
}

/**
 * Shared breadcrumb trail.
 *
 * This markup was hand-written in 19 pages, and four more pages used an
 * entirely different back-link pattern instead ("← Job Detail", "← Back to
 * Job", or nothing), so the same navigation read differently depending on
 * where you landed.
 */
export const Breadcrumbs: React.FC<BreadcrumbsProps> = ({ items, className }) => (
  <nav
    className={`text-sm text-slate-400 ${className ?? ""}`}
    aria-label="Breadcrumb"
    data-testid="breadcrumbs"
  >
    {items.map((item, i) => (
      <React.Fragment key={`${item.label}-${i}`}>
        {i > 0 && <span className="mx-1">/</span>}
        {item.to ? (
          <Link to={item.to} className="hover:text-slate-50">
            {item.label}
          </Link>
        ) : (
          <span className={`text-slate-200 ${item.mono ? "font-mono" : ""}`}>{item.label}</span>
        )}
      </React.Fragment>
    ))}
  </nav>
);

/** Short display form for a job id — the full UUID is too wide for a crumb. */
export function jobCrumbLabel(jobId: string | undefined): string {
  return (jobId ?? "").slice(0, 8);
}

interface JobBreadcrumbsProps {
  jobId: string | undefined;
  /** Crumbs appended after the `Jobs / {id}` prefix. */
  trail?: Crumb[];
  className?: string;
}

/**
 * Breadcrumbs rooted at a job: `Jobs / {shortId} / …trail`.
 * The job id links back to the job detail page unless it is the last crumb.
 */
export const JobBreadcrumbs: React.FC<JobBreadcrumbsProps> = ({ jobId, trail = [], className }) => {
  const items: Crumb[] = [
    { label: "Jobs", to: "/jobs" },
    trail.length === 0
      ? { label: jobCrumbLabel(jobId), mono: true }
      : { label: jobCrumbLabel(jobId), to: `/jobs/${jobId}` },
    ...trail,
  ];
  return <Breadcrumbs items={items} className={className} />;
};
