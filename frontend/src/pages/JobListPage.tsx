import React, { useState, useCallback, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import {
  api,
  type JobListItem,
  type JobListParams,
  type JobStatus,
  type ExecutionProfile,
  type BatchAction,
  type PcapUploadItem,
} from "../api";

// ─── Constants ──────────────────────────────────────────────────────────────

const ALL_STATUSES: JobStatus[] = [
  "queued", "running", "completed", "completed_with_errors",
  "failed", "canceled",
];
const ALL_PROFILES: ExecutionProfile[] = ["triage", "standard", "deep"];
const PAGE_SIZE = 25;

const STATUS_COLORS: Record<string, string> = {
  completed: "text-emerald-400 bg-emerald-400/10",
  completed_with_errors: "text-amber-400 bg-amber-400/10",
  running: "text-blue-400 bg-blue-400/10",
  queued: "text-slate-300 bg-slate-400/10",
  failed: "text-red-400 bg-red-400/10",
  canceled: "text-slate-500 bg-slate-500/10",
  deleting: "text-slate-500 bg-slate-500/10",
  deleted: "text-slate-600 bg-slate-600/10",
};

// ─── Helpers ────────────────────────────────────────────────────────────────

function statusColor(s: string) {
  return STATUS_COLORS[s] ?? "text-slate-400 bg-slate-400/10";
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString();
}

// ─── Upload Dialog (Multi-PCAP) ─────────────────────────────────────────────

interface PcapEntry {
  file: File;
  label: string;
}

interface UploadDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: (jobId: string) => void;
}

const LABEL_PRESETS = ["", "before", "during", "after", "baseline", "exploit"];
const MAX_PCAPS = 10;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 2 GB

const UploadDialog: React.FC<UploadDialogProps> = ({ open, onClose, onCreated }) => {
  const [entries, setEntries] = useState<PcapEntry[]>([]);
  const [profile, setProfile] = useState<ExecutionProfile>("standard");
  const [step, setStep] = useState<"pick" | "uploading" | "creating" | "error">("pick");
  const [progress, setProgress] = useState("");
  const [currentFilePct, setCurrentFilePct] = useState(0);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const reset = () => { setEntries([]); setStep("pick"); setError(""); setProgress(""); setCurrentFilePct(0); };

  const addFiles = (files: FileList | File[]) => {
    const arr = Array.from(files).filter(f =>
      /\.(pcap|pcapng|cap)$/i.test(f.name)
    );
    setEntries(prev => {
      const next = [...prev];
      for (const f of arr) {
        if (next.length >= MAX_PCAPS) break;
        if (f.size > MAX_FILE_SIZE) continue;
        if (!next.some(e => e.file.name === f.name && e.file.size === f.size)) {
          next.push({ file: f, label: "" });
        }
      }
      return next;
    });
  };

  const removeEntry = (idx: number) => setEntries(prev => prev.filter((_, i) => i !== idx));

  const setLabel = (idx: number, label: string) => setEntries(prev =>
    prev.map((e, i) => i === idx ? { ...e, label } : e)
  );

  const moveEntry = (idx: number, dir: -1 | 1) => setEntries(prev => {
    const next = [...prev];
    const target = idx + dir;
    if (target < 0 || target >= next.length) return prev;
    [next[idx], next[target]] = [next[target], next[idx]];
    return next;
  });

  const totalSize = entries.reduce((s, e) => s + e.file.size, 0);

  const handleSubmit = async () => {
    if (entries.length === 0) return;
    try {
      setStep("uploading");
      const uploads: PcapUploadItem[] = [];

      for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        setProgress(`Uploading ${i + 1}/${entries.length}: ${e.file.name}…`);
        setCurrentFilePct(0);
        const upload = await api.uploadPcap(e.file, (pct) => setCurrentFilePct(pct));
        const validation = await api.validateUpload(upload.upload_id);
        if (!validation.is_valid) {
          setError(`${e.file.name}: ${validation.warnings?.join(", ") ?? "Validation failed"}`);
          setStep("error");
          return;
        }
        uploads.push({ upload_id: upload.upload_id, label: e.label || undefined });
      }

      setStep("creating");
      setProgress("Creating job…");
      const job = await api.createJob({ uploads, execution_profile: profile });
      reset();
      onCreated(job.job_id);
    } catch (err: any) {
      setError(err.message ?? "Upload failed");
      setStep("error");
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-lg p-6 w-full max-w-lg space-y-4"
        onClick={e => e.stopPropagation()}>
        <h2 className="text-lg font-semibold">New Analysis</h2>
        <p className="text-xs text-slate-500">Upload one or more PCAP files. Optional labels help compare snapshots (e.g. before/during/after).</p>

        {step === "error" && (
          <div className="text-red-400 text-sm bg-red-400/10 rounded p-2">{error}
            <button className="ml-2 underline" onClick={reset}>Retry</button>
          </div>
        )}

        {(step === "pick" || step === "error") && (
          <>
            {/* Drop zone */}
            <div className="border-2 border-dashed border-slate-600 rounded-lg p-4 text-center cursor-pointer hover:border-slate-400 transition-colors"
              onClick={() => inputRef.current?.click()}
              onDragOver={e => { e.preventDefault(); e.stopPropagation(); }}
              onDrop={e => { e.preventDefault(); addFiles(e.dataTransfer.files); }}>
              <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" multiple className="hidden"
                onChange={e => { if (e.target.files) { addFiles(e.target.files); e.target.value = ""; } }} />
              <span className="text-slate-400 text-sm">
                {entries.length === 0 ? "Drop PCAP file(s) here or click to browse" : `+ Add more PCAPs (${entries.length}/${MAX_PCAPS})`}
              </span>
            </div>

            {/* File list */}
            {entries.length > 0 && (
              <div className="max-h-48 overflow-y-auto space-y-1">
                {entries.map((e, i) => (
                  <div key={i} className="flex items-center gap-2 bg-slate-800/60 rounded px-2 py-1.5 text-sm">
                    <span className="text-slate-500 w-5 text-center text-xs">{i + 1}</span>
                    <div className="flex gap-0.5">
                      <button onClick={() => moveEntry(i, -1)} disabled={i === 0}
                        className="text-slate-500 hover:text-slate-300 disabled:opacity-20 text-xs px-0.5">▲</button>
                      <button onClick={() => moveEntry(i, 1)} disabled={i === entries.length - 1}
                        className="text-slate-500 hover:text-slate-300 disabled:opacity-20 text-xs px-0.5">▼</button>
                    </div>
                    <span className="flex-1 truncate text-slate-200" title={e.file.name}>
                      {e.file.name} <span className="text-slate-500">({(e.file.size / 1e6).toFixed(1)} MB)</span>
                    </span>
                    <select value={e.label} onChange={ev => setLabel(i, ev.target.value)}
                      className="bg-slate-700 border border-slate-600 rounded px-1.5 py-0.5 text-xs text-slate-300 w-24">
                      <option value="">No label</option>
                      {LABEL_PRESETS.filter(l => l).map(l => <option key={l} value={l}>{l}</option>)}
                    </select>
                    <input
                      type="text"
                      value={!LABEL_PRESETS.includes(e.label) ? e.label : ""}
                      onChange={ev => setLabel(i, ev.target.value)}
                      placeholder="Custom…"
                      className="bg-slate-700 border border-slate-600 rounded px-1.5 py-0.5 text-xs text-slate-300 w-20"
                    />
                    <button onClick={() => removeEntry(i)} className="text-red-400 hover:text-red-300 text-xs">✕</button>
                  </div>
                ))}
                <div className="text-xs text-slate-500 text-right">
                  Total: {(totalSize / 1e6).toFixed(1)} MB across {entries.length} file{entries.length !== 1 ? "s" : ""}
                </div>
              </div>
            )}

            {/* Profile selector */}
            <div>
              <label className="text-sm text-slate-400">Execution Profile</label>
              <select value={profile} onChange={e => setProfile(e.target.value as ExecutionProfile)}
                className="mt-1 w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200">
                {ALL_PROFILES.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-2">
              <button onClick={() => { reset(); onClose(); }}
                className="px-4 py-2 text-sm text-slate-400 hover:text-white">Cancel</button>
              <button onClick={handleSubmit} disabled={entries.length === 0}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-sm font-medium disabled:opacity-40">
                Upload & Analyze{entries.length > 1 ? ` (${entries.length} files)` : ""}
              </button>
            </div>
          </>
        )}

        {(step === "uploading" || step === "creating") && (
          <div className="py-6 space-y-4">
            <div className="text-slate-300 text-center text-sm font-medium">
              {progress}
            </div>
            {step === "uploading" && (
              <div className="space-y-1.5">
                <div className="flex justify-between text-[10px] uppercase tracking-wider text-slate-500 font-bold">
                  <span>Transfer Progress</span>
                  <span>{currentFilePct}%</span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                  <div
                    className="h-full bg-emerald-500 transition-all duration-300 ease-out shadow-[0_0_10px_rgba(16,185,129,0.4)]"
                    style={{ width: `${currentFilePct}%` }}
                  />
                </div>
              </div>
            )}
            {step === "creating" && (
              <div className="flex justify-center">
                <div className="w-8 h-8 border-2 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin" />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

// ─── JobListPage ────────────────────────────────────────────────────────────

export const JobListPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [uploadOpen, setUploadOpen] = useState(false);

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

  // ── Batch mutations ──
  const batchMut = useMutation({
    mutationFn: (action: BatchAction) =>
      api.batchJobs({ action, job_ids: Array.from(selected) }),
    onSuccess: () => {
      setSelected(new Set());
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });

  // ── Single delete mutation ──
  const deleteMut = useMutation({
    mutationFn: (jobId: string) => api.deleteJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
  });

  // ── Upload complete handler ──
  const handleUploadCreated = useCallback((_jobId: string) => {
    setUploadOpen(false);
    queryClient.invalidateQueries({ queryKey: ["jobs"] });
  }, [queryClient]);

  // ── Render ──
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Jobs</h1>
        <button onClick={() => setUploadOpen(true)}
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-md text-sm font-medium transition-colors">
          New Analysis
        </button>
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
          <button onClick={() => setUploadOpen(true)} className="text-emerald-400 underline">
            Start a new analysis
          </button>
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
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${statusColor(job.status)}`}>
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

      {/* Upload dialog */}
      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} onCreated={handleUploadCreated} />
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
