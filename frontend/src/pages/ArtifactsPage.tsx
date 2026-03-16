import React, { useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type ArtifactItem } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";
import { CardSkeleton } from "../components/SkeletonLoader";

const STATUS_COLORS: Record<string, string> = {
  available: "text-emerald-400", generating: "text-blue-400 animate-pulse",
  failed: "text-red-400", purged: "text-slate-500",
};

export const ArtifactsPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const { addToast } = useToast();

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "artifacts"],
    queryFn: () => api.listArtifacts(jobId!),
    enabled: !!jobId,
  });

  const genMut = useMutation({
    mutationFn: () => api.generateEvidencePackage(jobId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "artifacts"] });
      addToast({ severity: "info", title: "Evidence package generated", body: "Artifacts are now available for download." });
    },
    onError: () => addToast({ severity: "high", title: "Failed to generate evidence package" }),
  });

  const handleDownload = useCallback((artifactId: string, filename?: string | null) => {
    api.downloadArtifact(artifactId, filename || undefined).catch(err => {
      console.error("Download failed:", err);
      alert("Download failed. Please try again.");
    });
  }, []);

  const artifacts = data?.items ?? [];

  return (
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Artifacts</span>
      </nav>

      <div className="flex items-center justify-between">
        <h1 className={`text-xl font-semibold ${labelHint("artifacts", activeHelpField)}`} onClick={() => toggleHelp("artifacts")}>Artifacts</h1>
        <button onClick={() => genMut.mutate()} disabled={genMut.isPending}
          className="px-3 py-1.5 text-sm rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white">
          {genMut.isPending ? "Generating…" : "Generate Evidence Package"}
        </button>
      </div>

      {isLoading && <div className="space-y-2"><CardSkeleton lines={2} /><CardSkeleton lines={2} /></div>}
      {error && <p className="text-red-400">Failed to load artifacts.</p>}

      {!isLoading && artifacts.length === 0 && (
        <p className="text-slate-500">No artifacts yet. Generate an evidence package to get started.</p>
      )}

      {artifacts.length > 0 && (
        <div className="space-y-2">
          {artifacts.map((a: ArtifactItem) => (
            <div key={a.artifact_id} className="flex items-center justify-between bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-200">{a.filename || a.type}</span>
                  <span className={`text-xs ${STATUS_COLORS[a.status] ?? "text-slate-400"}`}>{a.status}</span>
                </div>
                <div className="text-xs text-slate-500 mt-0.5">
                  {a.size_bytes != null && <span>{(a.size_bytes / 1024).toFixed(1)} KB • </span>}
                  {new Date(a.created_at).toLocaleString()}
                </div>
              </div>
              {a.status === "available" && (
                <button onClick={() => handleDownload(a.artifact_id, a.filename)}
                  className="px-3 py-1 text-sm rounded border border-slate-700 text-slate-300 hover:bg-slate-800">
                  Download
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};

