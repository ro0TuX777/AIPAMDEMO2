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

  // Security Onion form state
  const [soStartTime, setSoStartTime] = useState("");
  const [soEndTime, setSoEndTime] = useState("");
  const [soSensors, setSoSensors] = useState("");
  const [soExerciseId, setSoExerciseId] = useState("");
  const [soNotes, setSoNotes] = useState("");

  // Arkime form state
  const [arkimeStartTime, setArkimeStartTime] = useState("");
  const [arkimeEndTime, setArkimeEndTime] = useState("");
  const [arkimeFilter, setArkimeFilter] = useState("");
  const [arkimeExerciseId, setArkimeExerciseId] = useState("");
  const [arkimeNotes, setArkimeNotes] = useState("");


  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    setIsSubmitting(true);
    setError(null);

    try {
      if (mode === "upload") {
        if (!files || files.length === 0) {
          setError("Please select at least one PCAP file.");
          return;
        }
        const res = await api.createJobUpload(files, analysisMode, {
          exercise_id: "manual-upload",
          notes: "Created via web UI",
        });
        navigate(`/jobs/${res.job_id}`);
      } else if (mode === "security_onion") {
        if (!soStartTime || !soEndTime) {
          setError("Please provide a start and end time.");
          return;
        }
        const sensors = soSensors
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);

        const payload = {
          source: "security_onion",
          time_range: {
            start: new Date(soStartTime).toISOString(),
            end: new Date(soEndTime).toISOString(),
          },
          sensors,
          mode: analysisMode,
          metadata: {
            exercise_id: soExerciseId || "so-ui",
            notes: soNotes || "Created via Security Onion UI tab",
          },
        };

        const res = await api.createJobFromSecurityOnion(payload);
        navigate(`/jobs/${res.job_id}`);
      } else if (mode === "arkime") {
        if (!arkimeStartTime || !arkimeEndTime || !arkimeFilter) {
          setError("Please provide start/end time and a filter.");
          return;
        }

        const payload = {
          source: "arkime",
          filter: arkimeFilter,
          time_range: {
            start: new Date(arkimeStartTime).toISOString(),
            end: new Date(arkimeEndTime).toISOString(),
          },
          mode: analysisMode,
          metadata: {
            exercise_id: arkimeExerciseId || "arkime-ui",
            notes: arkimeNotes || "Created via Arkime UI tab",
          },
        };

        const res = await api.createJobFromArkime(payload);
        navigate(`/jobs/${res.job_id}`);
      }
    } catch (err) {
      setError("Failed to create job. Please try again.");
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4 max-w-2xl" data-testid="page-new-analysis">
      <h1 className="text-xl font-semibold">New Analysis</h1>
      <div className="border border-slate-800 rounded-lg p-4 space-y-4 text-sm">
        <div className="flex gap-4">
          <button
            data-testid="tab-upload"
            className={mode === "upload" ? "font-semibold text-emerald-400" : "text-slate-400"}
            onClick={() => setMode("upload")}
          >
            Upload PCAP
          </button>
          <button
            data-testid="tab-security-onion"
            className={mode === "security_onion" ? "font-semibold text-emerald-400" : "text-slate-400"}
            onClick={() => setMode("security_onion")}
          >
            Security Onion
          </button>
          <button
            data-testid="tab-arkime"
            className={mode === "arkime" ? "font-semibold text-emerald-400" : "text-slate-400"}
            onClick={() => setMode("arkime")}
          >
            Arkime
          </button>
        </div>

        {mode === "upload" && (
          <form className="space-y-4" onSubmit={handleSubmit} data-testid="form-upload">
            <div>
              <label className="block mb-1 text-slate-300">PCAP Files</label>
              <input
                type="file"
                multiple
                data-testid="input-pcap-files"
                className="text-sm text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-slate-700 file:text-slate-200 hover:file:bg-slate-600"
                onChange={(e) => setFiles(e.target.files)}
                required
              />
            </div>
            <div>
              <label className="block mb-1 text-slate-300">Mode</label>
              <select
                data-testid="select-analysis-mode"
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
              data-testid="btn-start-analysis"
              disabled={isSubmitting || !files}
              className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? "Submitting..." : "Start Analysis"}
            </button>
          </form>
        )}

        {mode === "security_onion" && (
          <form className="space-y-4" onSubmit={handleSubmit} data-testid="form-security-onion">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block mb-1 text-slate-300">Start Time (local)</label>
                <input
                  type="datetime-local"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={soStartTime}
                  onChange={(e) => setSoStartTime(e.target.value)}
                  data-testid="input-so-start"
                  required
                />
              </div>
              <div>
                <label className="block mb-1 text-slate-300">End Time (local)</label>
                <input
                  type="datetime-local"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={soEndTime}
                  onChange={(e) => setSoEndTime(e.target.value)}
                  data-testid="input-so-end"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block mb-1 text-slate-300">Sensors (comma-separated)</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                placeholder="sensor1,sensor2"
                value={soSensors}
                onChange={(e) => setSoSensors(e.target.value)}
                data-testid="input-so-sensors"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block mb-1 text-slate-300">Mode</label>
                <select
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={analysisMode}
                  onChange={(e) => setAnalysisMode(e.target.value)}
                  data-testid="select-so-mode"
                >
                  <option value="single_window">Single Window</option>
                  <option value="baseline_vs_exploit">Baseline vs Exploit</option>
                </select>
              </div>
              <div>
                <label className="block mb-1 text-slate-300">Exercise ID (optional)</label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={soExerciseId}
                  onChange={(e) => setSoExerciseId(e.target.value)}
                  data-testid="input-so-exercise-id"
                  placeholder="ex-001"
                />
              </div>
            </div>

            <div>
              <label className="block mb-1 text-slate-300">Notes (optional)</label>
              <textarea
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm min-h-[60px]"
                value={soNotes}
                onChange={(e) => setSoNotes(e.target.value)}
                data-testid="input-so-notes"
              />
            </div>

            {error && <div className="text-red-400 text-sm">{error}</div>}

            <button
              type="submit"
              data-testid="btn-start-so-analysis"
              disabled={isSubmitting}
              className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? "Submitting..." : "Start Security Onion Analysis"}
            </button>
          </form>
        )}

        {mode === "arkime" && (
          <form className="space-y-4" onSubmit={handleSubmit} data-testid="form-arkime">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block mb-1 text-slate-300">Start Time (local)</label>
                <input
                  type="datetime-local"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={arkimeStartTime}
                  onChange={(e) => setArkimeStartTime(e.target.value)}
                  data-testid="input-arkime-start"
                  required
                />
              </div>
              <div>
                <label className="block mb-1 text-slate-300">End Time (local)</label>
                <input
                  type="datetime-local"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={arkimeEndTime}
                  onChange={(e) => setArkimeEndTime(e.target.value)}
                  data-testid="input-arkime-end"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block mb-1 text-slate-300">Arkime Filter</label>
              <input
                type="text"
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                placeholder="expression: ip.src == 10.0.0.1"
                value={arkimeFilter}
                onChange={(e) => setArkimeFilter(e.target.value)}
                data-testid="input-arkime-filter"
                required
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block mb-1 text-slate-300">Mode</label>
                <select
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={analysisMode}
                  onChange={(e) => setAnalysisMode(e.target.value)}
                  data-testid="select-arkime-mode"
                >
                  <option value="single_window">Single Window</option>
                  <option value="baseline_vs_exploit">Baseline vs Exploit</option>
                </select>
              </div>
              <div>
                <label className="block mb-1 text-slate-300">Exercise ID (optional)</label>
                <input
                  type="text"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                  value={arkimeExerciseId}
                  onChange={(e) => setArkimeExerciseId(e.target.value)}
                  data-testid="input-arkime-exercise-id"
                  placeholder="ex-arkime-001"
                />
              </div>
            </div>

            <div>
              <label className="block mb-1 text-slate-300">Notes (optional)</label>
              <textarea
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm min-h-[60px]"
                value={arkimeNotes}
                onChange={(e) => setArkimeNotes(e.target.value)}
                data-testid="input-arkime-notes"
              />
            </div>

            {error && <div className="text-red-400 text-sm">{error}</div>}

            <button
              type="submit"
              data-testid="btn-start-arkime-analysis"
              disabled={isSubmitting}
              className="rounded bg-emerald-600 px-4 py-2 text-sm font-medium hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? "Submitting..." : "Start Arkime Analysis"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};

