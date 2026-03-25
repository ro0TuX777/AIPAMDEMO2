import React, { useState, useMemo } from "react";
import { useParams, Link, useSearchParams } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type ProofItem,
  type ProofMode,
  type ProofItemEntry,
  type InvestigationQueueItem,
} from "../api";
import { useToast } from "../components/ToastProvider";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { InfoTooltip } from "../components/InfoTooltip";

// ─── Constants ────────────────────────────────────────────────────────────────

const MODE_OPTIONS: { value: ProofMode; label: string; desc: string }[] = [
  { value: "soc_handoff", label: "SOC Handoff", desc: "Key findings, affected systems, recommended actions" },
  { value: "ir_technical", label: "IR Technical", desc: "Attack path, MITRE mapping, timeline, containment" },
  { value: "executive_summary", label: "Executive Summary", desc: "Business impact, risk, remediation status" },
];

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "info"];

const ROLE_COLORS: Record<string, string> = {
  supports: "text-emerald-400",
  contradicts: "text-red-400",
  context: "text-sky-400",
};
const ROLE_EMOJI: Record<string, string> = { supports: "✅", contradicts: "❌", context: "ℹ️" };

// ─── Component ────────────────────────────────────────────────────────────────

export const ProofBuilderPage: React.FC = () => {
  const { jobId, proofId: urlProofId } = useParams<{ jobId: string; proofId?: string }>();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const [searchParams] = useSearchParams();

  // State
  const [activeProofId, setActiveProofId] = useState<string | null>(urlProofId ?? null);
  const [newTitle, setNewTitle] = useState("");
  const [newMode, setNewMode] = useState<ProofMode>("soc_handoff");
  const [editingConclusion, setEditingConclusion] = useState(false);
  const [conclusionDraft, setConclusionDraft] = useState("");
  const [addEntityType, setAddEntityType] = useState("finding");
  const [addEntityId, setAddEntityId] = useState("");
  const [addRole, setAddRole] = useState("supports");
  const [addNote, setAddNote] = useState("");
  const [showNarrativePanel, setShowNarrativePanel] = useState(true);
  const [generating, setGenerating] = useState(false);

  // ─── Queries ──────────────────────────────────────────────────────────────
  const proofsQ = useQuery({
    queryKey: ["proofs", jobId],
    queryFn: () => api.listProofs(jobId!),
    enabled: !!jobId,
  });

  const proofDetailQ = useQuery({
    queryKey: ["proof-detail", jobId, activeProofId],
    queryFn: () => api.getProof(jobId!, activeProofId!),
    enabled: !!jobId && !!activeProofId,
  });

  const proofItemsQ = useQuery({
    queryKey: ["proof-items", jobId, activeProofId],
    queryFn: () => api.listProofItems(jobId!, activeProofId!),
    enabled: !!jobId && !!activeProofId,
  });

  // Investigation queue for quick-add
  const queueQ = useQuery({
    queryKey: ["investigation-queue", jobId, "for-proof"],
    queryFn: () => api.getInvestigationQueue(jobId!, { status: "confirmed", limit: 200 }),
    enabled: !!jobId && !!activeProofId,
  });

  const proof = proofDetailQ.data?.item;
  const proofItems = proofItemsQ.data?.items ?? [];
  const proofs = proofsQ.data?.items ?? [];
  const confirmedItems = queueQ.data?.items ?? [];

  // Filter out already-pinned items
  const availableItems = useMemo(() => {
    const pinnedKeys = new Set(proofItems.map((i) => `${i.entity_type}:${i.entity_id}`));
    return confirmedItems.filter((i) => !pinnedKeys.has(`${i.source_type}:${i.source_id}`));
  }, [confirmedItems, proofItems]);

  // ─── Mutations ────────────────────────────────────────────────────────────
  const createMut = useMutation({
    mutationFn: () => api.createProof(jobId!, { title: newTitle, mode: newMode }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ["proofs", jobId] });
      setActiveProofId(res.item.proof_id);
      setNewTitle("");
      addToast({ severity: "info", title: "Proof created", duration: 2000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to create proof" }),
  });

  const updateMut = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.updateProof(jobId!, activeProofId!, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proof-detail", jobId, activeProofId] });
      queryClient.invalidateQueries({ queryKey: ["proofs", jobId] });
      addToast({ severity: "info", title: "Proof updated", duration: 2000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to update" }),
  });

  const deleteMut = useMutation({
    mutationFn: () => api.deleteProof(jobId!, activeProofId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proofs", jobId] });
      setActiveProofId(null);
      addToast({ severity: "info", title: "Proof deleted", duration: 2000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to delete" }),
  });

  const addItemMut = useMutation({
    mutationFn: (body: { entity_type: string; entity_id: string; role?: string; analyst_note?: string }) =>
      api.addProofItem(jobId!, activeProofId!, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proof-items", jobId, activeProofId] });
      queryClient.invalidateQueries({ queryKey: ["proof-detail", jobId, activeProofId] });
      setAddEntityId("");
      setAddNote("");
      addToast({ severity: "info", title: "Item added", duration: 2000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to add item" }),
  });

  const removeItemMut = useMutation({
    mutationFn: (itemId: string) => api.removeProofItem(jobId!, activeProofId!, itemId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["proof-items", jobId, activeProofId] });
      queryClient.invalidateQueries({ queryKey: ["proof-detail", jobId, activeProofId] });
      addToast({ severity: "info", title: "Item removed", duration: 2000 });
    },
  });

  // Narrative + Export
  const [narrative, setNarrative] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);

  const handleGenerate = async () => {
    if (!activeProofId) return;
    setGenerating(true);
    try {
      const res = await api.renderProofNarrative(jobId!, activeProofId);
      setNarrative(res.narrative_markdown);
      setWarnings(res.warnings);
      queryClient.invalidateQueries({ queryKey: ["proof-detail", jobId, activeProofId] });
      addToast({ severity: "info", title: "Narrative generated", duration: 3000 });
    } catch {
      addToast({ severity: "high", title: "Failed to generate narrative" });
    } finally {
      setGenerating(false);
    }
  };

  const handleExport = async (fmt: "markdown" | "html") => {
    if (!activeProofId) return;
    try {
      const res = await api.exportProof(jobId!, activeProofId, fmt);
      const blob = new Blob([res.content], { type: fmt === "html" ? "text/html" : "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = res.filename;
      a.click();
      URL.revokeObjectURL(url);
      addToast({ severity: "info", title: `Exported as ${fmt.toUpperCase()}`, duration: 2000 });
    } catch {
      addToast({ severity: "high", title: "Export failed" });
    }
  };

  const handleSaveNarrative = () => {
    if (!narrative) return;
    updateMut.mutate({ narrative_markdown: narrative });
  };

  const handleQuickAdd = (item: InvestigationQueueItem) => {
    addItemMut.mutate({
      entity_type: item.source_type,
      entity_id: item.source_id,
      role: "supports",
      analyst_note: item.title,
    });
  };

  // Load existing narrative when proof changes
  React.useEffect(() => {
    if (proof?.narrative_markdown) {
      setNarrative(proof.narrative_markdown);
    } else {
      setNarrative("");
    }
    setWarnings([]);
  }, [proof?.proof_id, proof?.narrative_markdown]);

  if (!jobId) return <p className="text-red-400">Missing job ID</p>;

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link to={`/jobs/${jobId}`} className="text-xs text-slate-500 hover:text-slate-300">← Job Detail</Link>
          <h1 className={`text-xl font-semibold text-slate-100 ${labelHint("proof_builder", activeHelpField)}`}
            onClick={() => toggleHelp("proof_builder")}>
            📋 Build Case
          </h1>
        </div>
        <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
      </div>

      {/* Proof selector / creator */}
      <div className="bg-slate-900/60 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <label className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Active Proof</label>
          <select
            className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200"
            value={activeProofId ?? ""}
            onChange={(e) => setActiveProofId(e.target.value || null)}
          >
            <option value="">— Select or create —</option>
            {proofs.map((p) => (
              <option key={p.proof_id} value={p.proof_id}>
                {p.title} ({p.status}, {p.item_count} items)
              </option>
            ))}
          </select>
          {activeProofId && (
            <button onClick={() => { if (confirm("Delete this proof?")) deleteMut.mutate(); }}
              className="px-2 py-1 text-xs text-red-400 hover:text-red-300 border border-red-800 rounded">
              🗑 Delete
            </button>
          )}
        </div>

        {/* Create new proof */}
        {!activeProofId && (
          <div className="flex items-end gap-3 flex-wrap">
            <div>
              <label className="block text-xs text-slate-500 mb-1">Title</label>
              <input type="text" value={newTitle} onChange={(e) => setNewTitle(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 w-64"
                placeholder="e.g. C2 Activity on 10.0.0.5" />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">Mode</label>
              <select value={newMode} onChange={(e) => setNewMode(e.target.value as ProofMode)}
                className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200">
                {MODE_OPTIONS.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
            <button onClick={() => newTitle.trim() && createMut.mutate()}
              disabled={!newTitle.trim() || createMut.isPending}
              className="px-4 py-1.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 rounded text-sm text-white font-medium">
              + Create Proof
            </button>
          </div>
        )}
      </div>

      {/* ─── Active Proof workspace ─── */}
      {activeProofId && proof && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* LEFT: Evidence panel */}
          <div className="space-y-4">
            {/* Proof metadata */}
            <div className="bg-slate-900/60 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-slate-200">{proof.title}</h2>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  proof.status === "final" ? "bg-emerald-900 text-emerald-300" :
                  proof.status === "archived" ? "bg-slate-800 text-slate-400" :
                  "bg-amber-900 text-amber-300"
                }`}>{proof.status}</span>
              </div>

              <div className="flex items-center gap-3 flex-wrap text-xs text-slate-400">
                <span>Mode: <strong className="text-slate-200">{MODE_OPTIONS.find(m => m.value === proof.mode)?.label ?? proof.mode}</strong></span>
                <span>Severity: <strong className="text-slate-200">{proof.severity}</strong></span>
                <span>Confidence: <strong className="text-slate-200">{Math.round(proof.confidence * 100)}%</strong></span>
                <span>{proof.item_count} item(s)</span>
              </div>

              {/* Mode + Severity + Status quick-edit */}
              <div className="flex items-center gap-2 flex-wrap">
                <select value={proof.mode} onChange={(e) => updateMut.mutate({ mode: e.target.value })}
                  className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200">
                  {MODE_OPTIONS.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
                </select>
                <select value={proof.severity} onChange={(e) => updateMut.mutate({ severity: e.target.value })}
                  className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200">
                  {SEVERITY_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <select value={proof.status} onChange={(e) => updateMut.mutate({ status: e.target.value })}
                  className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200">
                  <option value="draft">Draft</option>
                  <option value="final">Final</option>
                  <option value="archived">Archived</option>
                </select>
              </div>

              {/* Conclusion */}
              <div>
                <label className="text-xs text-slate-500 mb-1 block">Conclusion</label>
                {editingConclusion ? (
                  <div className="space-y-1">
                    <textarea rows={3} value={conclusionDraft} onChange={(e) => setConclusionDraft(e.target.value)}
                      className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200" />
                    <div className="flex gap-2">
                      <button onClick={() => { updateMut.mutate({ conclusion: conclusionDraft }); setEditingConclusion(false); }}
                        className="px-3 py-1 bg-cyan-700 hover:bg-cyan-600 rounded text-xs text-white">Save</button>
                      <button onClick={() => setEditingConclusion(false)}
                        className="px-3 py-1 text-slate-400 hover:text-slate-200 text-xs">Cancel</button>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-slate-300 cursor-pointer hover:bg-slate-800/50 rounded px-2 py-1"
                    onClick={() => { setConclusionDraft(proof.conclusion ?? ""); setEditingConclusion(true); }}>
                    {proof.conclusion || <span className="text-slate-500 italic">Click to add conclusion…</span>}
                  </p>
                )}
              </div>
            </div>

            {/* Pinned evidence items */}
            <div className="bg-slate-900/60 rounded-lg p-4">
              <h3 className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">
                Pinned Evidence ({proofItems.length})
              </h3>
              {proofItems.length === 0 && (
                <p className="text-sm text-slate-500 italic">No evidence pinned yet. Add items below.</p>
              )}
              <div className="space-y-2">
                {proofItems.map((item) => (
                  <div key={item.item_id} className="flex items-center justify-between bg-slate-800/60 rounded px-3 py-2 text-sm">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-base">{ROLE_EMOJI[item.role] ?? "•"}</span>
                      <span className={`text-xs font-mono ${ROLE_COLORS[item.role] ?? "text-slate-400"}`}>{item.role}</span>
                      <span className="text-xs text-slate-500 font-mono">{item.entity_type.toUpperCase()}</span>
                      <span className="text-slate-300 truncate">{item.label ?? item.entity_id}</span>
                    </div>
                    <button onClick={() => removeItemMut.mutate(item.item_id)}
                      className="text-red-500 hover:text-red-400 text-xs ml-2 shrink-0">✕</button>
                  </div>
                ))}
              </div>

              {/* Manual add */}
              <div className="mt-3 pt-3 border-t border-slate-800">
                <p className="text-xs text-slate-500 mb-2">Manual Add</p>
                <div className="flex items-end gap-2 flex-wrap">
                  <select value={addEntityType} onChange={(e) => setAddEntityType(e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200">
                    {["finding", "alert", "theory", "host", "ioc", "slice"].map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                  <input type="text" value={addEntityId} onChange={(e) => setAddEntityId(e.target.value)}
                    placeholder="Entity ID" className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 w-32" />
                  <select value={addRole} onChange={(e) => setAddRole(e.target.value)}
                    className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200">
                    <option value="supports">Supports</option>
                    <option value="contradicts">Contradicts</option>
                    <option value="context">Context</option>
                  </select>
                  <input type="text" value={addNote} onChange={(e) => setAddNote(e.target.value)}
                    placeholder="Note (optional)" className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 w-40" />
                  <button onClick={() => addEntityId.trim() && addItemMut.mutate({
                    entity_type: addEntityType, entity_id: addEntityId, role: addRole, analyst_note: addNote || undefined,
                  })} disabled={!addEntityId.trim() || addItemMut.isPending}
                    className="px-3 py-1 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 rounded text-xs text-white">+ Add</button>
                </div>
              </div>
            </div>


            {/* Quick-add from confirmed queue items */}
            {availableItems.length > 0 && (
              <div className="bg-slate-900/60 rounded-lg p-4">
                <h3 className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">
                  Quick Add — Confirmed Items ({availableItems.length})
                  <InfoTooltip text="Items from the Investigation Queue with 'confirmed' status that haven't been added to this proof yet." />
                </h3>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {availableItems.map((item) => (
                    <div key={item.item_id} className="flex items-center justify-between bg-slate-800/40 rounded px-3 py-1.5 text-xs hover:bg-slate-800/70">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-slate-500 font-mono">{item.source_type.toUpperCase()}</span>
                        <span className="text-slate-300 truncate">{item.title}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                          item.severity === "critical" ? "bg-red-900 text-red-300" :
                          item.severity === "high" ? "bg-orange-900 text-orange-300" :
                          "bg-slate-800 text-slate-400"
                        }`}>{item.severity}</span>
                      </div>
                      <button onClick={() => handleQuickAdd(item)}
                        className="text-cyan-400 hover:text-cyan-300 shrink-0 ml-2">+ Pin</button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* RIGHT: Narrative panel */}
          <div className="space-y-4">
            <div className="bg-slate-900/60 rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs text-slate-500 uppercase tracking-wider font-semibold">
                  Draft Narrative
                </h3>
                <div className="flex items-center gap-2">
                  <button onClick={handleGenerate} disabled={generating || proofItems.length === 0}
                    className="px-3 py-1.5 bg-purple-700 hover:bg-purple-600 disabled:opacity-50 rounded text-xs text-white font-medium">
                    {generating ? "⏳ Generating…" : "🤖 Generate"}
                  </button>
                  <button onClick={handleSaveNarrative} disabled={!narrative}
                    className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 rounded text-xs text-white">
                    💾 Save
                  </button>
                </div>
              </div>

              {/* Warnings */}
              {warnings.length > 0 && (
                <div className="mb-3 space-y-1">
                  {warnings.map((w, i) => (
                    <div key={i} className="flex items-center gap-2 bg-amber-950/40 border border-amber-800/50 rounded px-3 py-1.5 text-xs text-amber-300">
                      ⚠️ {w}
                    </div>
                  ))}
                </div>
              )}

              {/* Narrative content */}
              {narrative ? (
                <div className="prose prose-invert prose-sm max-w-none">
                  <pre className="whitespace-pre-wrap text-sm text-slate-300 bg-slate-950/50 rounded p-4 max-h-[60vh] overflow-y-auto font-mono leading-relaxed">
                    {narrative}
                  </pre>
                </div>
              ) : (
                <p className="text-sm text-slate-500 italic py-8 text-center">
                  {proofItems.length === 0
                    ? "Pin evidence items, then click Generate to create a narrative."
                    : "Click Generate to create a narrative from pinned evidence."}
                </p>
              )}

              {/* Export buttons */}
              {narrative && (
                <div className="mt-3 pt-3 border-t border-slate-800 flex items-center gap-2">
                  <span className="text-xs text-slate-500">Export:</span>
                  <button onClick={() => handleExport("markdown")}
                    className="px-3 py-1 border border-slate-700 rounded text-xs text-slate-300 hover:bg-slate-800">
                    📄 Markdown
                  </button>
                  <button onClick={() => handleExport("html")}
                    className="px-3 py-1 border border-slate-700 rounded text-xs text-slate-300 hover:bg-slate-800">
                    🌐 HTML
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Loading / Empty states */}
      {proofsQ.isLoading && <p className="text-slate-400 animate-pulse">Loading proofs…</p>}
      {!activeProofId && proofs.length === 0 && !proofsQ.isLoading && (
        <p className="text-center text-slate-500 py-12">No proofs yet. Create one above to start building your case.</p>
      )}

      <JobSubPageNav jobId={jobId} currentPath="proof" />
    </div>
  );
};