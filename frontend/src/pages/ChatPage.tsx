import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery } from "@tanstack/react-query";
import { ChatPanel } from "../components/ChatPanel";
import type { ChatSendTarget } from "../components/ChatPanel";
import { MnemosChatDrawer } from "../components/MnemosChatDrawer";
import type { ChatComparisonBranch, ChatComparisonGroup, ChatConversation } from "../components/chatTypes";
import {
  api,
  type JobDetail,
  type KBDocumentOut,
  type KBDocType,
} from "../api";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { JobBreadcrumbs } from "../components/Breadcrumbs";

// ─── Constants ───────────────────────────────────────────────────────────────

const DOC_LABELS: Record<string, string> = {
  asset_inventory: "INV",
  network_map: "MAP",
  baseline_profile: "BAS",
  threat_intel: "TI",
  soc_playbook: "SOC",
  policy: "POL",
  reference: "REF",
  user_guide: "GDE",
  exploit_capability: "EXP",
  other: "DOC",
};

// ─── Component ───────────────────────────────────────────────────────────────

export const ChatPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  // Capture ?ask= and ?hint= ONCE on first mount, then strip them from the URL.
  // Without this, navigating away and back would re-submit the same question
  // because ChatPanel re-reads initialMessage on every mount.
  const [initialAsk] = useState<string | undefined>(() => searchParams.get("ask") || undefined);
  const [contextHint] = useState<string | undefined>(() => searchParams.get("hint") || undefined);
  useEffect(() => {
    if (searchParams.has("ask") || searchParams.has("hint")) {
      const next = new URLSearchParams(searchParams);
      next.delete("ask");
      next.delete("hint");
      setSearchParams(next, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [kbOpen, setKbOpen] = useState(false);
  const mnemosToggleRef = useRef<HTMLButtonElement>(null);
  const draftSequenceRef = useRef(0);
  const hydratedJobRef = useRef<string | null>(null);
  const [baselineConversation, setBaselineConversation] = useState<ChatConversation>({ job_id: jobId ?? "", messages: [] });
  const [baselineToken, setBaselineToken] = useState("baseline-draft-0");
  const [conversationSummaries, setConversationSummaries] = useState<Array<{ id: string; title?: string }>>([]);
  const [mnemosOpen, setMnemosOpen] = useState(false);
  const [comparisonGroup, setComparisonGroup] = useState<ChatComparisonGroup | null>(null);
  const [mnemosDraft, setMnemosDraft] = useState("");
  const [copiedPrompt, setCopiedPrompt] = useState<{ messageId: string; content: string } | null>(null);

  const refreshConversations = useCallback(async () => {
    if (!jobId) return;
    try {
      const conversations = await api.listConversations(jobId);
      setConversationSummaries(conversations);
    } catch {
      // The user can still start a draft if conversation history is temporarily unavailable.
    }
  }, [jobId]);

  useEffect(() => { void refreshConversations(); }, [refreshConversations]);

  useEffect(() => {
    if (!jobId || hydratedJobRef.current === jobId) return;
    hydratedJobRef.current = jobId;
    void (async () => {
      try {
        const conversations = await api.listConversations(jobId);
        setConversationSummaries(conversations);
        if (conversations[0]) {
          const history = await api.getConversation(jobId, conversations[0].id);
          setBaselineConversation(history);
          setBaselineToken(`baseline-${history.id}`);
        }
      } catch { /* Initial drafts remain usable while history is unavailable. */ }
    })();
  }, [jobId]);

  const selectBaselineConversation = useCallback(async (conversationId: string) => {
    if (!jobId || conversationId === baselineConversation.id) return;
    const history = await api.getConversation(jobId, conversationId);
    setBaselineConversation(history);
    setBaselineToken(`baseline-${history.id}`);
    setComparisonGroup(null);
    setCopiedPrompt(null);
    setMnemosDraft("");
  }, [baselineConversation.id, jobId]);

  const activeBranch = useMemo<ChatComparisonBranch | null>(() => {
    if (!comparisonGroup) return null;
    return comparisonGroup.branches.find(branch => branch.id === comparisonGroup.active_branch_id)
      ?? comparisonGroup.branches.find(branch => branch.id === comparisonGroup.snapshot_branch_id)
      ?? null;
  }, [comparisonGroup]);

  const ensureComparison = useCallback(async () => {
    if (!jobId || !baselineConversation.id) return null;
    if (comparisonGroup?.root_conversation_id === baselineConversation.id) return comparisonGroup;
    const group = await api.openComparison(jobId, baselineConversation.id);
    setComparisonGroup(group);
    return group;
  }, [baselineConversation.id, comparisonGroup, jobId]);

  const openMnemos = useCallback(async () => {
    const group = await ensureComparison();
    if (group) setMnemosOpen(true);
  }, [ensureComparison]);

  const copyToMnemos = useCallback(async (messageId: string, content: string) => {
    const group = await ensureComparison();
    if (!group) return;
    if (mnemosDraft.trim() && mnemosDraft !== content && !window.confirm("Replace the unfinished MNEMOS message with the copied question?")) return;
    setCopiedPrompt({ messageId, content });
    setMnemosDraft(content);
    setMnemosOpen(true);
  }, [ensureComparison, mnemosDraft]);

  const onBaselineChanged = useCallback((next: ChatConversation) => {
    // A persisted conversation becoming saved is the same selection; only the
    // explicit transition from a persisted conversation to a new draft gets a
    // fresh controlled-selection identity.
    if (!next.id && baselineConversation.id) {
      draftSequenceRef.current += 1;
      setBaselineToken(`baseline-draft-${draftSequenceRef.current}`);
    }
    setBaselineConversation(next);
    if (next.id) void refreshConversations();
  }, [baselineConversation.id, refreshConversations]);

  const onMnemosChanged = useCallback((next: ChatConversation) => {
    setComparisonGroup(current => {
      if (!current || !next.id) return current;
      const branchIndex = current.branches.findIndex(branch => branch.conversation_id === next.id);
      if (branchIndex < 0) return current;
      const branches = [...current.branches];
      branches[branchIndex] = { ...branches[branchIndex], messages: next.messages, updated_at: next.updated_at ?? branches[branchIndex].updated_at };
      return { ...current, branches, updated_at: next.updated_at ?? current.updated_at };
    });
  }, []);

  const prepareMnemosSend = useCallback(async (_message: string, requestId: string): Promise<ChatSendTarget | undefined> => {
    if (!jobId || !comparisonGroup || !activeBranch) return undefined;
    if (!copiedPrompt) return { conversation: { id: activeBranch.conversation_id, job_id: jobId, messages: activeBranch.messages }, branchId: activeBranch.id, selectionToken: activeBranch.id };
    try {
      const branch = await api.createComparisonBranch(jobId, comparisonGroup.group_id, copiedPrompt.messageId, requestId);
      const selected = await api.selectComparisonBranch(jobId, comparisonGroup.group_id, branch.id);
      setComparisonGroup(selected);
      setCopiedPrompt(null);
      return { conversation: { id: branch.conversation_id, job_id: jobId, messages: branch.messages }, branchId: branch.id, selectionToken: branch.id };
    } catch {
      return undefined;
    }
  }, [activeBranch, comparisonGroup, copiedPrompt, jobId]);

  const completeMnemosTurn = useCallback((conversationId: string) => {
    setComparisonGroup(current => {
      const branch = current?.branches.find(item => item.conversation_id === conversationId);
      if (!current || !branch) return current;
      return { ...current, active_branch_id: branch.id };
    });
  }, []);

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
  const [kbBinaryFile, setKbBinaryFile] = useState<File | null>(null);
  const [kbGlobal, setKbGlobal] = useState(false);
  const [kbAdminRequired, setKbAdminRequired] = useState(false);
  const [kbAdminToken, setKbAdminToken] = useState("");

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
      // This job's own documents plus the shared global library — both are used
      // to ground the AI's answers, so both are shown here.
      const [jobRes, libRes] = await Promise.all([
        api.listKBDocuments(jobId),
        api.listLibraryDocuments(),
      ]);
      const lib = libRes.items.map((d) => ({ ...d, is_global: true }));
      setKbDocs([...jobRes.items, ...lib]);
    } catch {
      setKbError("Failed to load knowledge base documents");
    } finally {
      setKbLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    fetchKBDocs();
  }, [fetchKBDocs]);

  // Does curating the shared library require an admin token on this server?
  useEffect(() => {
    api.getLibraryConfig()
      .then((c) => setKbAdminRequired(!!c.admin_required))
      .catch(() => setKbAdminRequired(false));
  }, []);

  // While any document is still indexing (background task), poll until it
  // settles — capped so a stuck doc doesn't poll forever.
  const kbHasPending = kbDocs.some((d) => d.status === "pending");
  useEffect(() => {
    if (!kbHasPending) return;
    let attempts = 0;
    const timer = setInterval(() => {
      attempts += 1;
      if (attempts > 20) {
        clearInterval(timer);
        return;
      }
      fetchKBDocs();
    }, 2500);
    return () => clearInterval(timer);
  }, [kbHasPending, fetchKBDocs]);

  const handleKBReindex = async (docId: string, isGlobal: boolean) => {
    if (!jobId) return;
    setKbError(null);
    try {
      if (isGlobal) await api.reindexLibraryDocument(docId, kbAdminRequired ? kbAdminToken.trim() || undefined : undefined);
      else await api.reindexKBDocument(jobId, docId);
      setKbSuccess("Re-indexing started…");
      fetchKBDocs();
    } catch (err: any) {
      setKbError(err.message || "Failed to re-index document");
    }
  };

  const handleKBUpload = async () => {
    if (!jobId || !kbName.trim()) {
      setKbError("Name is required");
      return;
    }
    // Require either text content or a binary file
    if (!kbBinaryFile && !kbContent.trim()) {
      setKbError("Content or a file is required");
      return;
    }
    setKbUploading(true);
    setKbError(null);
    setKbSuccess(null);
    try {
      const adminTok = kbAdminRequired ? kbAdminToken.trim() || undefined : undefined;
      if (kbBinaryFile) {
        // Binary upload (PDF, DOCX, XLSX, PPTX)
        if (kbGlobal) {
          await api.uploadLibraryBinaryFile(kbBinaryFile, kbName.trim(), kbDocType, kbDescription.trim() || undefined, adminTok);
        } else {
          await api.uploadKBBinaryFile(jobId, kbBinaryFile, kbName.trim(), kbDocType, kbDescription.trim() || undefined);
        }
      } else {
        // Text upload
        const body = {
          name: kbName.trim(),
          doc_type: kbDocType,
          description: kbDescription.trim() || undefined,
          content: kbContent,
        };
        if (kbGlobal) {
          await api.uploadLibraryDocument(body, adminTok);
        } else {
          await api.uploadKBDocument(jobId, body);
        }
      }
      setKbSuccess(`"${kbName}" uploaded${kbGlobal ? " to the library" : ""} — indexing…`);
      setKbName("");
      setKbDescription("");
      setKbContent("");
      setKbBinaryFile(null);
      setKbShowUpload(false);
      fetchKBDocs();
    } catch (err: any) {
      setKbError(err.message || "Failed to upload document");
    } finally {
      setKbUploading(false);
    }
  };

  const handleKBDelete = async (docId: string, docName: string, isGlobal: boolean) => {
    if (!jobId) return;
    const scopeMsg = isGlobal ? " from the shared library (affects all analyses)" : "";
    if (!window.confirm(`Delete "${docName}"${scopeMsg}?`)) return;
    try {
      if (isGlobal) {
        await api.deleteLibraryDocument(docId, kbAdminRequired ? kbAdminToken.trim() || undefined : undefined);
      } else {
        await api.deleteKBDocument(jobId, docId);
      }
      setKbDocs((prev) => prev.filter((d) => d.id !== docId));
      setKbSuccess(`"${docName}" deleted`);
    } catch (err: any) {
      setKbError(err.message || "Failed to delete document");
    }
  };

  const BINARY_EXTENSIONS = [".pdf", ".docx", ".xlsx", ".xls", ".pptx"];

  const handleKBFileRead = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const ext = file.name.includes(".") ? "." + file.name.split(".").pop()!.toLowerCase() : "";
    const isBinary = BINARY_EXTENSIONS.includes(ext);

    if (isBinary && file.size > 10_000_000) {
      setKbError("File too large (max 10MB for binary files)");
      return;
    }
    if (!isBinary && file.size > 5_000_000) {
      setKbError("File too large (max 5MB)");
      return;
    }

    if (!kbName) setKbName(file.name.replace(/\.[^.]+$/, ""));

    if (isBinary) {
      // Store reference for binary upload — don't read as text
      setKbBinaryFile(file);
      setKbContent(""); // clear any previous text content
    } else {
      // Read as text for plain-text files
      setKbBinaryFile(null);
      const reader = new FileReader();
      reader.onload = () => setKbContent(reader.result as string);
      reader.readAsText(file);
    }
  };

  if (!jobId) return null;

  // ── Render ──
  return (
    <div className="space-y-4">
      {/* Breadcrumb + heading */}
      <JobBreadcrumbs jobId={jobId} trail={[{ label: "AI Chat" }]} />

      <h1 className={`text-xl font-semibold ${labelHint("chat", activeHelpField)}`} onClick={() => toggleHelp("chat")}>AI Chat</h1>
      <HelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />

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
          <div className={`flex-1 min-w-0 h-full transition-all ${kbOpen ? "" : ""} flex flex-col gap-2`}>
            <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
              <div className="min-w-0">
                {conversationSummaries.length > 1 && <select aria-label="Baseline conversation" value={baselineConversation.id ?? ""} onChange={event => void selectBaselineConversation(event.target.value)} className="max-w-xs rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200">
                  {conversationSummaries.map(conversation => <option key={conversation.id} value={conversation.id}>{conversation.title || conversation.id}</option>)}
                </select>}
              </div>
              <button ref={mnemosToggleRef} type="button" onClick={() => void (mnemosOpen ? Promise.resolve(setMnemosOpen(false)) : openMnemos())} disabled={!baselineConversation.id} className="rounded bg-cyan-700 px-3 py-1.5 text-sm text-white hover:bg-cyan-600 disabled:cursor-not-allowed disabled:opacity-50">MNEMOS comparison</button>
            </div>
            <div className="min-h-0 flex-1">
              <ChatPanel
                jobId={jobId}
                conversation={baselineConversation}
                selectionToken={baselineToken}
                mode="baseline"
                initialMessage={initialAsk}
                contextHint={contextHint}
                onConversationChanged={onBaselineChanged}
                onCopyToMnemos={copyToMnemos}
                onRetry={() => {}}
              />
            </div>
          </div>

          {mnemosOpen && comparisonGroup && activeBranch && (
            <MnemosChatDrawer
              jobId={jobId}
              group={comparisonGroup}
              activeBranch={activeBranch}
              conversation={{ id: activeBranch.conversation_id, job_id: jobId, messages: activeBranch.messages }}
              draft={mnemosDraft}
              onDraftChange={setMnemosDraft}
              onClose={() => setMnemosOpen(false)}
              onBranchChange={branchId => { if (comparisonGroup) void api.selectComparisonBranch(jobId, comparisonGroup.group_id, branchId).then(setComparisonGroup); }}
              onBeforeSend={prepareMnemosSend}
              onConversationChanged={onMnemosChanged}
              onTurnComplete={completeMnemosTurn}
              onRetry={() => {}}
              returnFocusRef={mnemosToggleRef}
            />
          )}

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
              /* ── KB Sidebar (inlined to preserve input focus) ── */
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
                          <option value="policy">Policy / Procedure</option>
                          <option value="reference">Reference / Manual</option>
                          <option value="user_guide">User Guide</option>
                          <option value="exploit_capability">Exploit / Capability</option>
                          <option value="other">Other</option>
                        </select>
                      </div>
                      <label className="flex items-start gap-2 bg-slate-950/40 border border-slate-700/50 rounded px-2 py-1.5 cursor-pointer">
                        <input type="checkbox" className="mt-0.5 accent-emerald-500"
                          checked={kbGlobal} onChange={(e) => setKbGlobal(e.target.checked)} />
                        <span className="text-[10px] text-slate-300 leading-tight">
                          Add to <span className="font-semibold text-emerald-400">shared library</span>
                          <span className="block text-slate-500">Available to every analysis — ideal for exploit user guides, capability manuals, and playbooks (not just this capture).</span>
                        </span>
                      </label>
                      {kbGlobal && kbAdminRequired && (
                        <div>
                          <label className="block mb-0.5 text-slate-400 text-[10px]">
                            Library admin token <span className="text-slate-600">(required to curate the shared library)</span>
                          </label>
                          <input type="password" autoComplete="off"
                            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-xs"
                            value={kbAdminToken} onChange={(e) => setKbAdminToken(e.target.value)}
                            placeholder="X-KB-Admin-Token" />
                        </div>
                      )}
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
                            <input type="file" accept=".csv,.txt,.json,.md,.log,.xml,.yaml,.yml,.html,.tsv,.conf,.ini,.rules,.ioc,.stix,.yar,.pdf,.docx,.xlsx,.xls,.pptx" className="hidden" onChange={handleKBFileRead} />
                          </label>
                          <span className="text-[10px] text-slate-500">PDF, Word, PowerPoint, Excel, Markdown, CSV, TXT, and more (max 10MB)</span>
                        </div>
                        {kbBinaryFile ? (
                          <div className="bg-slate-900 border border-slate-700 rounded px-2 py-2 text-xs text-slate-300 flex items-center justify-between">
                            <span>
                              <span className="text-emerald-400 font-medium">{kbBinaryFile.name}</span>
                              <span className="text-slate-500 ml-2">({(kbBinaryFile.size / 1024).toFixed(0)} KB)</span>
                            </span>
                            <button onClick={() => setKbBinaryFile(null)} className="text-red-400/60 hover:text-red-400 text-[10px] px-1">Remove</button>
                          </div>
                        ) : (
                          <>
                            <textarea className="bg-slate-900 border border-slate-700 rounded px-2 py-1 w-full text-slate-200 text-[10px] font-mono h-24 resize-y"
                              value={kbContent} onChange={(e) => setKbContent(e.target.value)}
                              placeholder={"IP,Hostname,OS,Department\n10.10.10.113,HR-WS-042,Windows 11,Finance"} />
                            {kbContent && <span className="text-[10px] text-slate-500">{kbContent.length.toLocaleString()} chars</span>}
                          </>
                        )}
                      </div>
                      <button onClick={handleKBUpload} disabled={kbUploading || !kbName.trim() || (!kbContent.trim() && !kbBinaryFile)}
                        className="w-full rounded bg-emerald-600 px-3 py-1.5 text-xs font-medium hover:bg-emerald-500 disabled:opacity-50">
                        {kbUploading ? "Uploading…" : "Upload & Index"}
                      </button>
                    </div>
                  )}

                  {/* Document list */}
                  {kbDocs.length === 0 && !kbLoading && !kbShowUpload ? (
                    <div className="text-xs text-slate-500 text-center py-8 border border-dashed border-slate-700 rounded-lg">
                      <p>No documents yet.</p>
                      <p className="mt-1">Add exploit user guides, capability manuals, playbooks, asset inventories, or threat intel to ground the AI's analysis.</p>
                      <p className="mt-1 text-slate-600">Tip: tick <span className="text-emerald-500/80">shared library</span> when adding so a manual is available to every analysis, not just this capture.</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {kbDocs.map((doc) => (
                        <div key={doc.id} className="flex items-start justify-between bg-slate-950/50 border border-slate-700/50 rounded-lg px-3 py-2 group">
                          <div className="flex items-start gap-2 min-w-0">
                            <span className="text-[10px] font-mono font-bold text-slate-500 mt-0.5">{DOC_LABELS[doc.doc_type] ?? "DOC"}</span>
                            <div className="min-w-0">
                              <div className="text-xs font-medium text-slate-200 truncate flex items-center gap-1.5">
                                {doc.name}
                                {doc.is_global && (
                                  <span className="text-[9px] font-semibold bg-emerald-900/40 text-emerald-400 px-1 py-0.5 rounded flex-shrink-0" title="Shared library — available to every analysis">LIBRARY</span>
                                )}
                              </div>
                              <div className="text-[10px] text-slate-500 flex items-center gap-1.5 mt-0.5">
                                <span className="bg-slate-800 px-1 py-0.5 rounded">{doc.doc_type.replace("_", " ")}</span>
                                <span>{doc.chunk_count} chunks</span>
                                <span
                                  title={doc.error_message || undefined}
                                  className={
                                    doc.status === "indexed" ? "text-emerald-400"
                                    : doc.status === "error" ? "text-red-400"
                                    : doc.status === "degraded" ? "text-orange-400"
                                    : "text-amber-400 animate-pulse"
                                  }
                                >
                                  {doc.status === "pending" ? "indexing…" : doc.status}
                                </span>
                              </div>
                              {doc.description && (
                                <div className="text-[10px] text-slate-500 mt-0.5 truncate" title={doc.description}>{doc.description}</div>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-0.5 flex-shrink-0">
                            <button onClick={() => handleKBReindex(doc.id, !!doc.is_global)}
                              className={`text-xs px-1 py-0.5 rounded hover:bg-slate-700 transition-opacity ${
                                doc.status === "degraded" || doc.status === "error"
                                  ? "text-orange-400 hover:text-orange-300"
                                  : "text-slate-500 hover:text-slate-300 opacity-0 group-hover:opacity-100"
                              }`}
                              title={doc.status === "degraded" ? "Embeddings degraded — re-index to fix" : "Re-index"}>↻</button>
                            <button onClick={() => handleKBDelete(doc.id, doc.name, !!doc.is_global)}
                              className="text-red-400/50 hover:text-red-400 text-xs px-1 py-0.5 rounded hover:bg-red-900/20 opacity-0 group-hover:opacity-100 transition-opacity"
                              title="Delete">Del</button>
                          </div>
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
            )}
          </div>
        </div>
      )}
      <JobSubPageNav jobId={jobId!} currentPath="chat" />
    </div>
  );
};
