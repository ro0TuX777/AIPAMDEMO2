import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api, type ExecutionProfile, type PcapUploadItem } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

type Step = "select" | "uploading" | "creating" | "error";

const LABEL_PRESETS = ["", "before", "during", "after", "baseline", "exploit"];
const MAX_PCAPS = 10;
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 2 GB

const fmtSize = (bytes: number) => bytes >= 1e9 ? `${(bytes / 1e9).toFixed(1)} GB` : `${(bytes / 1e6).toFixed(1)} MB`;

interface PcapEntry {
  file: File;
  label: string;
}

interface RejectedFile {
  name: string;
  size: number;
  reason: string;
}

export const NewAnalysisPage: React.FC = () => {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  // Upload tab state (multi-file)
  const [entries, setEntries] = useState<PcapEntry[]>([]);
  const [profile, setProfile] = useState<ExecutionProfile>("standard");
  const [jobName, setJobName] = useState("");
  const [notes, setNotes] = useState("");

  // Flow state
  const [step, setStep] = useState<Step>("select");
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState("");
  const [currentFilePct, setCurrentFilePct] = useState(0);

  // Source tab
  const [mode, setMode] = useState<"upload" | "security_onion" | "arkime">("upload");

  // Security Onion form state
  const [soStartTime, setSoStartTime] = useState("");
  const [soEndTime, setSoEndTime] = useState("");
  const [soSensors, setSoSensors] = useState("");
  const [soProtocol, setSoProtocol] = useState("");
  const [soSrcIp, setSoSrcIp] = useState("");
  const [soDstIp, setSoDstIp] = useState("");
  const [soSrcPort, setSoSrcPort] = useState("");
  const [soDstPort, setSoDstPort] = useState("");
  const [soExerciseId, setSoExerciseId] = useState("");
  const [soNotes, setSoNotes] = useState("");
  const [analysisMode, setAnalysisMode] = useState("single_window");

  // Arkime form state
  const [arkimeStartTime, setArkimeStartTime] = useState("");
  const [arkimeEndTime, setArkimeEndTime] = useState("");
  const [arkimeFilter, setArkimeFilter] = useState("");
  const [arkimeExerciseId, setArkimeExerciseId] = useState("");
  const [arkimeNotes, setArkimeNotes] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [rejectedFiles, setRejectedFiles] = useState<RejectedFile[]>([]);

  // ── Multi-file helpers ──────────────────────────────────────────────────
  const addFiles = (files: FileList | File[]) => {
    const arr = Array.from(files).filter(f => /\.(pcap|pcapng|cap)$/i.test(f.name));
    const newRejected: RejectedFile[] = [];
    setEntries(prev => {
      const next = [...prev];
      for (const f of arr) {
        if (next.length >= MAX_PCAPS) {
          newRejected.push({ name: f.name, size: f.size, reason: `Exceeds max file count (${MAX_PCAPS})` });
          continue;
        }
        if (f.size > MAX_FILE_SIZE) {
          newRejected.push({ name: f.name, size: f.size, reason: `File too large (${fmtSize(f.size)} — max ${fmtSize(MAX_FILE_SIZE)})` });
          continue;
        }
        if (!next.some(e => e.file.name === f.name && e.file.size === f.size)) {
          next.push({ file: f, label: "" });
        }
      }
      return next;
    });
    if (newRejected.length > 0) {
      setRejectedFiles(prev => [...prev, ...newRejected]);
    }
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

  const reset = () => { setEntries([]); setStep("select"); setError(null); setProgress(""); setCurrentFilePct(0); };

  // ── V2 Upload Flow (multi-PCAP) ──────────────────────────────────────────
  const handleSubmit = async () => {
    if (entries.length === 0) return;
    setError(null);
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
      const job = await api.createJob({
        uploads,
        execution_profile: profile,
        ...(jobName ? { job_name: jobName } : {}),
        ...(notes ? { notes } : {}),
      });
      reset();
      navigate(`/jobs/${job.job_id}`);
    } catch (err: any) {
      setError(err.message ?? "Upload failed");
      setStep("error");
    }
  };

  // ── Legacy source handlers ──────────────────────────────────────────────
  const handleLegacySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);
    try {
      if (mode === "security_onion") {
        if (!soStartTime || !soEndTime) { setError("Please provide a start and end time."); return; }
        const sensors = soSensors.split(",").map((s) => s.trim()).filter(Boolean);
        const filter_fields: Record<string, any> = {};
        if (soProtocol) filter_fields.protocol = soProtocol;
        if (soSrcIp) filter_fields.srcIp = soSrcIp;
        if (soDstIp) filter_fields.dstIp = soDstIp;
        if (soSrcPort) filter_fields.srcPort = parseInt(soSrcPort, 10);
        if (soDstPort) filter_fields.dstPort = parseInt(soDstPort, 10);
        const res = await api.createJobFromSecurityOnion({
          source: "security_onion",
          time_range: { start: new Date(soStartTime).toISOString(), end: new Date(soEndTime).toISOString() },
          sensors, mode: analysisMode, filter_fields,
          metadata: { exercise_id: soExerciseId || "so-ui", notes: soNotes || "Created via Security Onion UI tab" },
        });
        navigate(`/jobs/${res.job_id}`);
      } else if (mode === "arkime") {
        if (!arkimeStartTime || !arkimeEndTime || !arkimeFilter) { setError("Please provide start/end time and a filter."); return; }
        const res = await api.createJobFromArkime({
          source: "arkime", filter: arkimeFilter,
          time_range: { start: new Date(arkimeStartTime).toISOString(), end: new Date(arkimeEndTime).toISOString() },
          mode: analysisMode,
          metadata: { exercise_id: arkimeExerciseId || "arkime-ui", notes: arkimeNotes || "Created via Arkime UI tab" },
        });
        navigate(`/jobs/${res.job_id}`);
      }
    } catch (err: any) {
      const msg = err?.serverMessage || err?.message || "Unknown error";
      setError(`Failed to create job: ${msg}`);
      console.error(err);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex gap-6 items-start">
    <div className="space-y-4 max-w-2xl flex-1 min-w-0" data-testid="page-new-analysis">
      <h1 className={`text-xl font-semibold ${labelHint("new_analysis", activeHelpField)}`} onClick={() => toggleHelp("new_analysis")}>New Analysis</h1>
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
          <div className="space-y-4" data-testid="form-upload">
            <p className="text-xs text-slate-500">Upload one or more PCAP files. Optional labels help compare snapshots (e.g. before/during/after).</p>
            <p className="text-xs text-slate-500">
              Max <strong>{fmtSize(MAX_FILE_SIZE)}</strong> per file &middot; up to <strong>{MAX_PCAPS}</strong> files per job
            </p>

            {rejectedFiles.length > 0 && (
              <div className="text-amber-400 text-sm bg-amber-400/10 border border-amber-400/30 rounded p-3 space-y-1">
                <div className="font-medium flex items-center justify-between">
                  <span>⚠ {rejectedFiles.length} file{rejectedFiles.length !== 1 ? "s" : ""} rejected</span>
                  <button className="text-xs text-amber-300 hover:text-amber-100 underline" onClick={() => setRejectedFiles([])}>Dismiss</button>
                </div>
                {rejectedFiles.map((r, i) => (
                  <div key={i} className="text-xs text-amber-300">
                    <span className="font-mono">{r.name}</span> ({fmtSize(r.size)}) — {r.reason}
                  </div>
                ))}
              </div>
            )}

            {step === "error" && (
              <div className="text-red-400 text-sm bg-red-400/10 rounded p-2">{error}
                <button className="ml-2 underline" onClick={reset}>Retry</button>
              </div>
            )}

            {(step === "select" || step === "error") && (
              <>
                {/* Drop zone */}
                <div className="border-2 border-dashed border-slate-600 rounded-lg p-6 text-center cursor-pointer hover:border-slate-400 transition-colors"
                  onClick={() => inputRef.current?.click()}
                  onDragOver={e => { e.preventDefault(); e.stopPropagation(); }}
                  onDrop={e => { e.preventDefault(); addFiles(e.dataTransfer.files); }}>
                  <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap" multiple className="hidden"
                    data-testid="input-pcap-files"
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

                {/* Profile + Job Name + Notes */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block mb-1 text-slate-300">Execution Profile</label>
                    <select
                      data-testid="select-profile"
                      className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200"
                      value={profile}
                      onChange={(e) => setProfile(e.target.value as ExecutionProfile)}
                    >
                      <option value="triage">Triage (fast)</option>
                      <option value="standard">Standard</option>
                      <option value="deep">Deep (thorough)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block mb-1 text-slate-300">Job Name (optional)</label>
                    <input
                      type="text"
                      className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                      placeholder="My analysis"
                      value={jobName}
                      onChange={(e) => setJobName(e.target.value)}
                      data-testid="input-job-name"
                    />
                  </div>
                </div>
                <div>
                  <label className="block mb-1 text-slate-300">Notes (optional)</label>
                  <textarea
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm min-h-[60px]"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    data-testid="input-notes"
                  />
                </div>

                {/* Actions */}
                <div className="flex justify-end gap-2">
                  <button onClick={handleSubmit} disabled={entries.length === 0}
                    data-testid="btn-start-analysis"
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-sm font-medium disabled:opacity-40">
                    Upload &amp; Analyze{entries.length > 1 ? ` (${entries.length} files)` : ""}
                  </button>
                </div>
              </>
            )}

            {(step === "uploading" || step === "creating") && (
              <div className="py-6 space-y-4">
                <div className="text-slate-300 text-center text-sm font-medium">{progress}</div>
                {step === "uploading" && (
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-[10px] uppercase tracking-wider text-slate-500 font-bold">
                      <span>Transfer Progress</span>
                      <span>{currentFilePct}%</span>
                    </div>
                    <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                      <div className="h-full bg-emerald-500 transition-all duration-300 ease-out"
                        style={{ width: `${currentFilePct}%` }} />
                    </div>
                  </div>
                )}
                {step === "creating" && (
                  <div className="flex justify-center">
                    <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {mode === "security_onion" && (
          <form className="space-y-4" onSubmit={handleLegacySubmit} data-testid="form-security-onion">
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

            <div className="border border-slate-700/50 rounded p-3 space-y-3">
              <p className="text-xs text-slate-400">
                <span className="text-amber-400">⚡ Packet Filters</span> — Use these to narrow the export.
                Tip: set <strong>Protocol = tcp</strong> if you get serialization errors (e.g. OSPF).
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="block mb-1 text-slate-400 text-xs">Protocol</label>
                  <select
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    value={soProtocol}
                    onChange={(e) => setSoProtocol(e.target.value)}
                    data-testid="input-so-protocol"
                  >
                    <option value="">Any</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                  </select>
                </div>
                <div>
                  <label className="block mb-1 text-slate-400 text-xs">Source IP</label>
                  <input
                    type="text"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    placeholder="e.g. 192.168.1.10"
                    value={soSrcIp}
                    onChange={(e) => setSoSrcIp(e.target.value)}
                    data-testid="input-so-src-ip"
                  />
                </div>
                <div>
                  <label className="block mb-1 text-slate-400 text-xs">Destination IP</label>
                  <input
                    type="text"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    placeholder="e.g. 10.0.0.1"
                    value={soDstIp}
                    onChange={(e) => setSoDstIp(e.target.value)}
                    data-testid="input-so-dst-ip"
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="block mb-1 text-slate-400 text-xs">Source Port</label>
                  <input
                    type="number"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    placeholder="e.g. 443"
                    value={soSrcPort}
                    onChange={(e) => setSoSrcPort(e.target.value)}
                    data-testid="input-so-src-port"
                  />
                </div>
                <div>
                  <label className="block mb-1 text-slate-400 text-xs">Destination Port</label>
                  <input
                    type="number"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-sm"
                    placeholder="e.g. 445"
                    value={soDstPort}
                    onChange={(e) => setSoDstPort(e.target.value)}
                    data-testid="input-so-dst-port"
                  />
                </div>
              </div>
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
          <form className="space-y-4" onSubmit={handleLegacySubmit} data-testid="form-arkime">
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
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};

