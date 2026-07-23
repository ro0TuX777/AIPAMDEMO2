import React, { useState, useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import {
  api,
  type JobListItem,
  type JobListParams,
  type JobStatus,
  type ExecutionProfile,
  type BatchAction,
} from "../api";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { useToast } from "../components/ToastProvider";
import { jobStatusClass } from "../theme/colors";

// ─── Constants ──────────────────────────────────────────────────────────────

const ALL_STATUSES: JobStatus[] = [
  "queued", "running", "completed", "completed_with_errors",
  "failed", "canceled",
];
const ALL_PROFILES: ExecutionProfile[] = ["triage", "standard", "deep"];
const PAGE_SIZE = 25;

// ─── Helpers ────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString();
}

// ─── JobListPage ────────────────────────────────────────────────────────────

export const JobListPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  // Read filters from URL
  const statusFilter = (params.get("status") as JobStatus) || undefined;
  const profileFilter = (params.get("profile") as ExecutionProfile) || undefined;
  const searchQuery = params.get("q") || "";
  const sortField = params.get("sort") || "created_at";
  const sortOrder = (params.get("order") || "desc") as "asc" | "desc";

  const queryParams: JobListParams = {
    status: statusFilter,
    profile: profileFilter,
    q: searchQuery || undefined,
    sort: sortField,
    order: sortOrder,
    limit: PAGE_SIZE,
  };

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["jobs", queryParams],
    queryFn: () => api.listJobs(queryParams),
  });

  const jobs = data?.items ?? [];
  const hasMore = data?.page?.has_more ?? false;

  // ── Filter setters ──
  const setFilter = useCallback((key: string, value: string | undefined) => {
    setParams(prev => {
      const next = new URLSearchParams(prev);
      if (value) next.set(key, value); else next.delete(key);
      next.delete("cursor"); // reset pagination on filter change
      return next;
    });
    setSelected(new Set());
  }, [setParams]);

  const toggleSort = useCallback((field: string) => {
    setParams(prev => {
      const next = new URLSearchParams(prev);
      if (prev.get("sort") === field && prev.get("order") !== "asc") {
        next.set("order", "asc");
      } else {
        next.set("sort", field);
        next.set("order", "desc");
      }
      next.delete("cursor");
      return next;
    });
  }, [setParams]);

  // ── Selection ──
  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const toggleSelectAll = () => {
    if (selected.size === jobs.length) setSelected(new Set());
    else setSelected(new Set(jobs.map(j => j.job_id)));
  };

  const { addToast } = useToast();

  // ── Batch mutations ──
  const batchMut = useMutation({
    mutationFn: (action: BatchAction) =>
      api.batchJobs({ action, job_ids: Array.from(selected) }),
    onSuccess: (_data, action) => {
      const count = selected.size;
      setSelected(new Set());
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
      addToast({ severity: "info", title: `Batch ${action} complete`, body: `${count} job(s) affected.` });
    },
    onError: (_err, action) => addToast({ severity: "high", title: `Batch ${action} failed` }),
  });

  // ── Single delete mutation ──
  const deleteMut = useMutation({
    mutationFn: (jobId: string) => api.deleteJob(jobId),
    onSuccess: (_data, jobId) => {
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
      addToast({ severity: "info", title: "Job deleted", body: `Job ${jobId.slice(0, 8)} removed.` });
    },
    onError: () => addToast({ severity: "high", title: "Failed to delete job" }),
  });

  // ── Render ──
  return (
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className={`text-2xl font-semibold ${labelHint("jobs_list", activeHelpField)}`} onClick={() => toggleHelp("jobs_list")}>Jobs</h1>
        <Link to="/new"
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-md text-sm font-medium transition-colors">
          New Analysis
        </Link>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <select value={statusFilter ?? ""}
          onChange={e => setFilter("status", e.target.value || undefined)}
          className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200">
          <option value="">All Statuses</option>
          {ALL_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={profileFilter ?? ""}
          onChange={e => setFilter("profile", e.target.value || undefined)}
          className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200">
          <option value="">All Profiles</option>
          {ALL_PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <input type="text" placeholder="Search jobs…" value={searchQuery}
          onChange={e => setFilter("q", e.target.value || undefined)}
          className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 w-56" />
      </div>

      {/* Batch actions */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 bg-slate-800/60 rounded px-4 py-2 text-sm">
          <span className="text-slate-300">{selected.size} selected</span>
          <button onClick={() => batchMut.mutate("cancel")}
            className="text-amber-400 hover:text-amber-300 font-medium" disabled={batchMut.isPending}>
            Cancel
          </button>
          <button onClick={() => { if (confirm("Delete selected jobs? This cannot be undone.")) batchMut.mutate("delete"); }}
            className="text-red-400 hover:text-red-300 font-medium" disabled={batchMut.isPending}>
            Delete
          </button>
          <button onClick={() => batchMut.mutate("export_iocs")}
            className="text-blue-400 hover:text-blue-300 font-medium" disabled={batchMut.isPending}>
            Export IOCs
          </button>
          {batchMut.isPending && <span className="text-slate-400 animate-pulse">Processing…</span>}
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="text-slate-400 animate-pulse">Loading jobs…</div>
      ) : error ? (
        <div className="text-red-400">
          Failed to load jobs.{" "}
          <button onClick={() => refetch()} className="underline">Retry</button>
        </div>
      ) : jobs.length === 0 ? (
        <div className="text-slate-400 border border-slate-800 rounded-lg p-8 text-center">
          No jobs found.{" "}
          <Link to="/new" className="text-emerald-400 underline">
            Start a new analysis
          </Link>
        </div>
      ) : (
        <div className="border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/50 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-3 py-3 w-8">
                  <input type="checkbox" checked={selected.size === jobs.length && jobs.length > 0}
                    onChange={toggleSelectAll} className="accent-emerald-500" />
                </th>
                <SortHeader label="Job" field="job_id" current={sortField} order={sortOrder} onToggle={toggleSort} />
                <SortHeader label="Status" field="status" current={sortField} order={sortOrder} onToggle={toggleSort} />
                <SortHeader label="Profile" field="execution_profile" current={sortField} order={sortOrder} onToggle={toggleSort} />
                <th className="px-4 py-3 font-medium">PCAP</th>
                <SortHeader label="Created" field="created_at" current={sortField} order={sortOrder} onToggle={toggleSort} />
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {jobs.map((job) => (
                <tr key={job.job_id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-3 py-3">
                    <input type="checkbox" checked={selected.has(job.job_id)}
                      onChange={() => toggleSelect(job.job_id)} className="accent-emerald-500" />
                  </td>
                  <td className="px-4 py-3 text-slate-300">
                    <Link to={`/jobs/${job.job_id}`} className="hover:text-emerald-400">
                      <span className="font-medium">{job.job_name || job.pcap_filename || job.job_id.slice(0, 8) + "…"}</span>
                      <span className="block text-[11px] font-mono text-slate-500">{job.job_id.slice(0, 8)}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${jobStatusClass(job.status)}`}>
                      {job.status.replace(/_/g, " ").toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-300 capitalize">{job.execution_profile}</td>
                  <td className="px-4 py-3 text-slate-400 truncate max-w-[160px]" title={job.pcap_filename}>
                    {job.pcap_filename ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{fmtDate(job.created_at)}</td>
                  <td className="px-4 py-3 flex items-center gap-3">
                    <Link to={`/jobs/${job.job_id}`}
                      className="text-emerald-400 hover:text-emerald-300 font-medium text-xs">
                      View
                    </Link>
                    {(job.status === "completed" || job.status === "completed_with_errors" || job.status === "failed" || job.status === "canceled") && (
                      <button
                        onClick={() => { if (window.confirm("Delete this job?")) deleteMut.mutate(job.job_id); }}
                        className="text-red-400 hover:text-red-300 font-medium text-xs"
                        disabled={deleteMut.isPending}
                      >
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {hasMore && data?.page?.next_cursor && (
        <div className="flex justify-center pt-2">
          <Link
            to={`?${new URLSearchParams({ ...Object.fromEntries(params), cursor: data.page.next_cursor }).toString()}`}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 rounded text-sm text-slate-300 transition-colors"
          >
            Load More
          </Link>
        </div>
      )}
    </div>
    <HelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};

// ─── Sort Header Helper ─────────────────────────────────────────────────────

const SortHeader: React.FC<{
  label: string; field: string; current: string; order: string;
  onToggle: (field: string) => void;
}> = ({ label, field, current, order, onToggle }) => {
  const active = current === field;
  const arrow = active ? (order === "asc" ? " ↑" : " ↓") : "";
  return (
    <th className="px-4 py-3 font-medium cursor-pointer select-none hover:text-slate-200"
      onClick={() => onToggle(field)}>
      {label}{arrow}
    </th>
  );
};
