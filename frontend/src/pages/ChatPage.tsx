import React, { useState, useCallback, useEffect, useMemo } from "react";
import { useParams, Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChatPanel } from "../components/ChatPanel";
import {
  api,
  type JobDetail,
  type KBDocumentOut,
  type KBDocType,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";

// ─── Constants ───────────────────────────────────────────────────────────────

const DOC_LABELS: Record<string, string> = {
  asset_inventory: "INV",
  network_map: "MAP",
  baseline_profile: "BAS",
  threat_intel: "TI",
  soc_playbook: "SOC",
  other: "DOC",
};

// ─── Component ───────────────────────────────────────────────────────────────

export const ChatPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [searchParams] = useSearchParams();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const initialAsk = useMemo(() => searchParams.get("ask") || undefined, [searchParams]);
  const contextHint = useMemo(() => searchParams.get("hint") || undefined, [searchParams]);
  const [kbOpen, setKbOpen] = useState(false);

  // ── KB state ──
  const [kbDocs, setKbDocs] = useState<KBDocumentOut[]>([]);
  const [kbLoading, setKbLoading] = useState(false);
  const [kbUploading, setKbUploading] = useState(false);
  const [kbError, setKbError] = useState<string | null>(null);
  const [kbSuccess, setKbSuccess] = useState<string | null>(null);
  const [kbName, setKbName] = useState("");
  const [kbDocType, setKbDocType] = useState<KBDocType>("asset_inventory");
  const [kbDescription, setKbDescription] = useState("");
  const [kbContent, setKbContent] = useState("");
  const [kbShowUpload, setKbShowUpload] = useState(false);

  const jobQ = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId,
  });
  const job: JobDetail | undefined = jobQ.data?.job;
  const isTerminal = job?.status === "completed" || job?.status === "completed_with_errors";

  // ── KB helpers ──
  const fetchKBDocs = useCallback(async () => {
    if (!jobId) return;
    setKbLoading(true);
    setKbError(null);
    try {
      const res = await api.listKBDocuments(jobId);
      setKbDocs(res.items);
    } catch {
      setKbError("Failed to load knowledge base documents");
    } finally {
      setKbLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    fetchKBDocs();
  }, [fetchKBDocs]);

  const handleKBUpload = async () => {
    if (!jobId || !kbName.trim() || !kbContent.trim()) {
      setKbError("Name and content are required");
      return;
    }
    setKbUploading(true);
    setKbError(null);
    setKbSuccess(null);
    try {
      await api.uploadKBDocument(jobId, {
        name: kbName.trim(),
        doc_type: kbDocType,
        description: kbDescription.trim() || undefined,
        content: kbContent,
      });
      setKbSuccess(`"${kbName}" uploaded and indexed`);
      setKbName("");
      setKbDescription("");
      setKbContent("");
      setKbShowUpload(false);
      fetchKBDocs();
    } catch (err: any) {
      setKbError(err.message || "Failed to upload document");
    } finally {
      setKbUploading(false);
    }
  };

  const handleKBDelete = async (docId: string, docName: string) => {
    if (!jobId || !window.confirm(`Delete "${docName}" from the knowledge base?`)) return;
    try {
      await api.deleteKBDocument(jobId, docId);
      setKbDocs((prev) => prev.filter((d) => d.id !== docId));
      setKbSuccess(`"${docName}" deleted`);
    } catch (err: any) {
      setKbError(err.message || "Failed to delete document");
    }
  };

  const handleKBFileRead = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 500_000) {
      setKbError("File too large (max 500KB)");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setKbContent(reader.result as string);
      if (!kbName) setKbName(file.name.replace(/\.[^.]+$/, ""));
    };
    reader.readAsText(file);
  };

  if (!jobId) return null;

  // ── Render ──
  return (
    <div className="space-y-4">
      {/* Breadcrumb + heading */}
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Link to={`/jobs/${jobId}`} className="hover:text-slate-200 transition-colors">
          ← Back to Job
        </Link>
        {job?.job_name && (
          <>
            <span className="text-slate-600">·</span>
            <span className="text-slate-500 truncate max-w-xs">{job.job_name}</span>
          </>
        )}
      </div>

      <h1 className={`text-xl font-semibold ${labelHint("chat", activeHelpField)}`} onClick={() => toggleHelp("chat")}>AI Chat</h1>
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />

      {/* Not ready state */}
      {!isTerminal && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-8 text-center">
          <p className="text-slate-400 text-lg mb-2">AI Chat is available after analysis completes</p>
          <p className="text-slate-500 text-sm">
            Job status: <span className="capitalize font-medium text-slate-300">{job?.status ?? "loading…"}</span>
          </p>
        </div>
      )}

      {/* Main layout: Chat + KB sidebar */}
      {isTerminal && (
        <div className="flex gap-4 items-start" style={{ height: "calc(100vh - 140px)" }}>
          {/* ── Chat (main area) ── */}
          <div className={`flex-1 min-w-0 h-full transition-all ${kbOpen ? "" : ""}`}>
            <ChatPanel jobId={jobId} initialMessage={initialAsk} contextHint={contextHint} />
          </div>

          {/* ── KB Sidebar ── */}
          <div className={`flex-shrink-0 transition-all duration-300 h-full ${kbOpen ? "w-96" : "w-10"}`}>
            {/* Toggle button (always visible) */}
            {!kbOpen ? (
              <button
                onClick={() => setKbOpen(true)}
                className="w-10 h-full bg-slate-900/80 border border-slate-800 rounded-lg flex flex-col items-center justify-center gap-2 hover:bg-slate-800/80 transition-colors group"
                title="Open Knowledge Base"
              >
                <span className="text-xs font-bold text-slate-400">KB</span>
                <span className="text-[10px] text-slate-500 group-hover:text-slate-300 writing-vertical" style={{ writingMode: "vertical-rl" }}>
                  Knowledge Base{kbDocs.length > 0 ? ` (${kbDocs.length})` : ""}
                </span>
              </button>
            ) : (
              <KBSidebar />
            )}
          </div>
        </div>
      )}
    </div>
  );

  // ── KB Sidebar (extracted for readability) ──
  function KBSidebar() {
    return (
      <div className="w-96 h-full bg-slate-900/80 border border-slate-800 rounded-lg flex flex-col overflow-hidden">
        {/* Sidebar header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 flex-shrink-0">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-slate-400">KB</span>
            <span className="text-sm font-semibold text-slate-300">Knowledge Base</span>
            {kbDocs.length > 0 && (
              <span className="text-[10px] bg-emerald-900/40 text-emerald-400 px-1.5 py-0.5 rounded">
                {kbDocs.length}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1">
            <button onClick={fetchKBDocs} disabled={kbLoading}
              className="text-slate-500 hover:text-slate-300 text-xs px-1.5 py-0.5 rounded hover:bg-slate-700 disabled:opacity-50"
              title="Refresh">↻</button>
            <button onClick={() => setKbShowUpload(!kbShowUpload)}
              className="text-emerald-400 hover:text-emerald-300 text-xs px-1.5 py-0.5 rounded hover:bg-emerald-900/30"
              title="Add document">{kbShowUpload ? "Cancel" : "+ Add"}</button>
            <button onClick={() => setKbOpen(false)}
              className="text-slate-500 hover:text-slate-300 text-xs px-1.5 py-0.5 rounded hover:bg-slate-700 ml-1"
              title="Close sidebar">✕</button>
          </div>
        </div>

        {/* Sidebar body (scrollable) */}
        <div className="flex-1 overflow-y-auto p-3 space-y-3">
          {kbError && (
            <div className="text-red-400 text-xs bg-red-900/20 border border-red-700/30 rounded px-2 py-1.5">{kbError}</div>
          )}
          {kbSuccess && (
            <div className="text-emerald-400 text-xs bg-emerald-900/20 border border-emerald-700/30 rounded px-2 py-1.5">{kbSuccess}</div>
          )}

          {/* Upload form */}
          {kbShowUpload && (
            <div className="border border-slate-700/50 rounded-lg p-3 space-y-2 bg-slate-950/40">
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wide">New Document</span>
              <div>
                <label className="block mb-0.5 text-slate-400 text-[10px]">Name</label>
                <input type="text" className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-xs"
                  value={kbName} onChange={(e) => setKbName(e.target.value)} placeholder="e.g. Corporate Asset Inventory" />
              </div>
              <div>
                <label className="block mb-0.5 text-slate-400 text-[10px]">Type</label>
                <select className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-xs"
                  value={kbDocType} onChange={(e) => setKbDocType(e.target.value as KBDocType)}>
                  <option value="asset_inventory">Asset Inventory</option>
                  <option value="network_map">Network Map</option>
                  <option value="baseline_profile">Baseline Profile</option>
                  <option value="threat_intel">Threat Intelligence</option>
                  <option value="soc_playbook">SOC Playbook</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label className="block mb-0.5 text-slate-400 text-[10px]">Description (optional)</label>
                <input type="text" className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-xs"
                  value={kbDescription} onChange={(e) => setKbDescription(e.target.value)} placeholder="Brief description" />
              </div>
              <div>
                <label className="block mb-0.5 text-slate-400 text-[10px]">Content</label>
                <div className="flex items-center gap-2 mb-1">
                  <label className="text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-0.5 rounded border border-slate-600 cursor-pointer">
                    Load file
                    <input type="file" accept=".csv,.txt,.json,.md,.log" className="hidden" onChange={handleKBFileRead} />
                  </label>
                  <span className="text-[10px] text-slate-500">Max 500KB</span>
                </div>
                <textarea className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-[10px] font-mono h-24 resize-y"
                  value={kbContent} onChange={(e) => setKbContent(e.target.value)}
                  placeholder={"IP,Hostname,OS,Department\n10.10.10.113,HR-WS-042,Windows 11,Finance"} />
                {kbContent && <span className="text-[10px] text-slate-500">{kbContent.length.toLocaleString()} chars</span>}
              </div>
              <button onClick={handleKBUpload} disabled={kbUploading || !kbName.trim() || !kbContent.trim()}
                className="w-full rounded bg-emerald-600 px-3 py-1.5 text-xs font-medium hover:bg-emerald-500 disabled:opacity-50">
                {kbUploading ? "Uploading…" : "Upload & Index"}
              </button>
            </div>
          )}

          {/* Document list */}
          {kbDocs.length === 0 && !kbLoading && !kbShowUpload ? (
            <div className="text-xs text-slate-500 text-center py-8 border border-dashed border-slate-700 rounded-lg">
              <p>No documents yet.</p>
              <p className="mt-1">Add asset inventories, network maps, or threat intel to enrich AI analysis.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {kbDocs.map((doc) => (
                <div key={doc.id} className="flex items-start justify-between bg-slate-950/50 border border-slate-700/50 rounded-lg px-3 py-2 group">
                  <div className="flex items-start gap-2 min-w-0">
                    <span className="text-[10px] font-mono font-bold text-slate-500 mt-0.5">{DOC_LABELS[doc.doc_type] ?? "DOC"}</span>
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-slate-200 truncate">{doc.name}</div>
                      <div className="text-[10px] text-slate-500 flex items-center gap-1.5 mt-0.5">
                        <span className="bg-slate-800 px-1 py-0.5 rounded">{doc.doc_type.replace("_", " ")}</span>
                        <span>{doc.chunk_count} chunks</span>
                        <span className={doc.status === "indexed" ? "text-emerald-400" : doc.status === "error" ? "text-red-400" : "text-amber-400"}>
                          {doc.status}
                        </span>
                      </div>
                      {doc.description && (
                        <div className="text-[10px] text-slate-500 mt-0.5 truncate" title={doc.description}>{doc.description}</div>
                      )}
                    </div>
                  </div>
                  <button onClick={() => handleKBDelete(doc.id, doc.name)}
                    className="text-red-400/50 hover:text-red-400 text-xs px-1 py-0.5 rounded hover:bg-red-900/20 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
                    title="Delete">Del</button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Sidebar footer hint */}
        <div className="px-3 py-2 border-t border-slate-800 flex-shrink-0">
          <p className="text-[10px] text-slate-600 text-center">
            Documents here are used as context by the AI when answering questions.
          </p>
        </div>
      </div>
    );
  }
};

