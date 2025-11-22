import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";

export const NewAnalysisPage: React.FC = () => {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"upload" | "security_onion" | "arkime">("upload");
  const [files, setFiles] = useState<FileList | null>(null);
  const [analysisMode, setAnalysisMode] = useState("single_window");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!files || files.length === 0) return;

    setIsSubmitting(true);
    setError(null);

    try {
      const res = await api.createJobUpload(files, analysisMode, {
        exercise_id: "manual-upload",
        notes: "Created via web UI",
      });
      navigate(`/jobs/${res.job_id}`);
    } catch (err) {
      setError("Failed to create job. Please try again.");
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4 max-w-2xl">
      <h1 className="text-xl font-semibold">New Analysis</h1>
      <div className="border border-slate-800 rounded-lg p-4 space-y-4 text-sm">
        <div className="flex gap-4">
          <button
            className={mode === "upload" ? "font-semibold text-emerald-400" : "text-slate-400"}
            onClick={() => setMode("upload")}
          >
            Upload PCAP
          </button>
          <button
            className={mode === "security_onion" ? "font-semibold text-emerald-400" : "text-slate-400"}
            onClick={() => setMode("security_onion")}
          >
            Security Onion
          </button>
          <button
            className={mode === "arkime" ? "font-semibold text-emerald-400" : "text-slate-400"}
            onClick={() => setMode("arkime")}
          >
            Arkime
          </button>
        </div>

        {mode === "upload" && (
          <form className="space-y-4" onSubmit={handleSubmit}>
            <div>
              <label className="block mb-1 text-slate-300">PCAP Files</label>
              <input
                type="file"
                multiple
                className="text-sm text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-slate-700 file:text-slate-200 hover:file:bg-slate-600"
                onChange={(e) => setFiles(e.target.files)}
                required
              />
            </div>
            <div>
              <label className="block mb-1 text-slate-300">Mode</label>
              <select
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200"
                value={analysisMode}
                onChange={(e) => setAnalysisMode(e.target.value)}
              >
                <option value="single_window">Single Window</option>
                <option value="baseline_vs_exploit">Baseline vs Exploit</option>
              </select>
            </div>

            {error && <div className="text-red-400 text-sm">{error}</div>}

            <button
              type="submit"
              disabled={isSubmitting || !files}
              className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? "Submitting..." : "Start Analysis"}
            </button>
          </form>
        )}

        {mode === "security_onion" && (
          <div className="text-slate-300">
            Security Onion job creation UI stub (to call /api/v1/jobs/from_security_onion).
          </div>
        )}

        {mode === "arkime" && (
          <div className="text-slate-300">
            Arkime job creation UI stub (to call /api/v1/jobs/from_arkime).
          </div>
        )}
      </div>
    </div>
  );
};

