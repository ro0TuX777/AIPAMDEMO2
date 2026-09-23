import React, { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery } from "@tanstack/react-query";
import { ChatPanel } from "../components/ChatPanel";
import type { ChatSendTarget } from "../components/ChatPanel";
import type { ChatAttempt } from "../components/ChatPanel";
import { MnemosChatDrawer } from "../components/MnemosChatDrawer";
import type { ChatConversation } from "../components/chatTypes";
import {
  api,
  type ChatComparisonBranch,
  type ChatComparisonGroup,
  type JobDetail,
  type KBDocumentOut,
  type KBDocType,
} from "../api";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { JobBreadcrumbs } from "../components/Breadcrumbs";
import { isActiveJobStatus, isChatReadyJobStatus } from "../api/jobStatus";

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
  const [conversationActionError, setConversationActionError] = useState("");
  const mnemosToggleRef = useRef<HTMLButtonElement>(null);
  const draftSequenceRef = useRef(0);
  const hydratedJobRef = useRef<string | null>(null);
  const pageGenerationRef = useRef(0);
  const navigationIntentRef = useRef(0);
  const [baselineConversation, setBaselineConversation] = useState<ChatConversation>({ job_id: jobId ?? "", messages: [] });
  const [baselineToken, setBaselineToken] = useState("baseline-draft-0");
  const [conversationSummaries, setConversationSummaries] = useState<Array<{ id: string; title?: string }>>([]);
  const [mnemosOpen, setMnemosOpen] = useState(false);
  const [comparisonGroup, setComparisonGroup] = useState<ChatComparisonGroup | null>(null);
  const [mnemosDraft, setMnemosDraft] = useState("");
  const [copiedPrompt, setCopiedPrompt] = useState<{ messageId: string; content: string } | null>(null);
  const [activeAttempt, setActiveAttempt] = useState<ChatAttempt | null>(null);
  const activeAttemptRef = useRef<ChatAttempt | null>(null);
  const branchSelectionRef = useRef(0);
  const branchWritesRef = useRef(new Map<string, Promise<void>>());
  const pageOwnerRef = useRef({ jobId, rootId: baselineConversation.id, group: comparisonGroup });
  pageOwnerRef.current = { jobId, rootId: baselineConversation.id, group: comparisonGroup };

  const jobQ = useQuery({
    queryKey: ["job", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId,
    retry: false,
    refetchInterval: query => isActiveJobStatus(query.state.data?.job.status) ? 2_000 : false,
    refetchIntervalInBackground: true,
  });
  const job: JobDetail | undefined = jobQ.data?.job;
  const chatReady = !jobQ.isError && isChatReadyJobStatus(job?.status);

  const storeAttempt = useCallback((next: ChatAttempt | null) => {
    activeAttemptRef.current = next;
    setActiveAttempt(next);
  }, []);

  const isCurrentAttempt = useCallback((owner: ChatAttempt) => {
    const live = pageOwnerRef.current;
    const current = activeAttemptRef.current;
    return Boolean(current && owner.jobId === live.jobId && owner.rootConversationId === live.rootId
      && owner.groupId === live.group?.group_id && owner.generation === pageGenerationRef.current
      && owner.requestId === current.requestId && owner.selectionToken === current.selectionToken
      && owner.branchId === current.branchId && owner.conversationId === current.conversationId);
  }, []);

  const changeAttempt = useCallback((next: ChatAttempt | null, owner: ChatAttempt) => {
    if (isCurrentAttempt(owner)) storeAttempt(next);
  }, [isCurrentAttempt, storeAttempt]);

  const selectBaselineToken = useCallback((conversationId?: string) => {
    if (conversationId) setBaselineToken(`baseline-${conversationId}`);
    else {
      draftSequenceRef.current += 1;
      setBaselineToken(`baseline-draft-${draftSequenceRef.current}`);
    }
  }, []);

  const refreshConversations = useCallback(async () => {
    if (!jobId || !chatReady) return;
    try {
      const conversations = await api.listConversations(jobId);
      setConversationSummaries(conversations);
    } catch {
      // The user can still start a draft if conversation history is temporarily unavailable.
    }
  }, [jobId, chatReady]);

  useEffect(() => { void refreshConversations(); }, [refreshConversations]);

  useEffect(() => {
    if (!jobId || !chatReady || hydratedJobRef.current === jobId) return;
    hydratedJobRef.current = jobId;
    const generation = pageGenerationRef.current;
    const navigationIntent = navigationIntentRef.current;
    void (async () => {
      try {
        const conversations = await api.listConversations(jobId);
        setConversationSummaries(conversations);
        const requestedId = searchParams.get("conversation");
        const selected = conversations.find(item => item.id === requestedId) ?? conversations[0];
        if (selected) {
          const history = await api.getConversation(jobId, selected.id);
          if (generation !== pageGenerationRef.current || navigationIntent !== navigationIntentRef.current) return;
          setBaselineConversation(history);
          selectBaselineToken(history.id);
          if (requestedId !== history.id) {
            const next = new URLSearchParams(searchParams);
            next.set("conversation", history.id);
            setSearchParams(next, { replace: true });
          }
        }
      } catch { /* Initial drafts remain usable while history is unavailable. */ }
    })();
  }, [jobId, chatReady, searchParams, selectBaselineToken, setSearchParams]);

  const selectBaselineConversation = useCallback(async (conversationId: string) => {
    if (!jobId) return;
    const navigationIntent = ++navigationIntentRef.current;
    if (conversationId === baselineConversation.id) return;
    let history: Awaited<ReturnType<typeof api.getConversation>>;
    try {
      history = await api.getConversation(jobId, conversationId);
    } catch {
      // A failed navigation keeps the committed selection and its live attempt.
      return;
    }
    if (navigationIntent !== navigationIntentRef.current || jobId !== pageOwnerRef.current.jobId) return;
    pageGenerationRef.current += 1;
    setBaselineConversation(history);
    selectBaselineToken(history.id);
    const next = new URLSearchParams(searchParams);
    next.set("conversation", history.id);
    setSearchParams(next, { replace: true });
    setComparisonGroup(null);
    setCopiedPrompt(null);
    setMnemosDraft("");
    setMnemosOpen(false);
    storeAttempt(null);
  }, [baselineConversation.id, jobId, searchParams, selectBaselineToken, setSearchParams, storeAttempt]);

  const activeBranch = useMemo<ChatComparisonBranch | null>(() => {
    if (!comparisonGroup) return null;
    return comparisonGroup.branches.find(branch => branch.id === comparisonGroup.active_branch_id)
      ?? comparisonGroup.branches.find(branch => branch.id === comparisonGroup.snapshot_branch_id)
      ?? null;
  }, [comparisonGroup]);

  const ensureComparison = useCallback(async () => {
    if (!jobId || !chatReady || !baselineConversation.id) return null;
    if (comparisonGroup?.root_conversation_id === baselineConversation.id) return comparisonGroup;
    const generation = pageGenerationRef.current;
    const rootId = baselineConversation.id;
    const group = await api.openComparison(jobId, baselineConversation.id);
    if (generation !== pageGenerationRef.current || rootId !== baselineConversation.id) return null;
    setComparisonGroup(group);
    return group;
  }, [baselineConversation.id, chatReady, comparisonGroup, jobId]);

  const openMnemos = useCallback(async () => {
    const group = await ensureComparison();
    if (group) setMnemosOpen(true);
  }, [ensureComparison]);

  const copyToMnemos = useCallback(async (messageId: string, content: string) => {
    if (activeAttemptRef.current && activeAttemptRef.current.status !== "error") return;
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
      selectBaselineToken();
    }
    setBaselineConversation(next);
    if (next.id) {
      void refreshConversations();
      if (!baselineConversation.id) {
        const params = new URLSearchParams(searchParams);
        params.set("conversation", next.id);
        setSearchParams(params, { replace: true });
      }
    }
  }, [baselineConversation.id, refreshConversations, searchParams, selectBaselineToken, setSearchParams]);

  const startNewBaseline = useCallback(() => {
    navigationIntentRef.current += 1;
    pageGenerationRef.current += 1;
    selectBaselineToken();
    setBaselineConversation({ job_id: jobId ?? "", messages: [] });
    setComparisonGroup(null);
    setCopiedPrompt(null);
    setMnemosDraft("");
    setMnemosOpen(false);
    storeAttempt(null);
    const next = new URLSearchParams(searchParams);
    next.delete("conversation");
    setSearchParams(next, { replace: true });
  }, [jobId, searchParams, selectBaselineToken, setSearchParams, storeAttempt]);

  const renameBaseline = async () => {
    if (!jobId || !baselineConversation.id) return;
    const rootId = baselineConversation.id;
    const title = window.prompt("Rename conversation", conversationSummaries.find(item => item.id === rootId)?.title ?? "");
    if (!title?.trim()) return;
    setConversationActionError("");
    try {
      await api.renameConversation(jobId, rootId, title.trim());
      if (pageOwnerRef.current.rootId !== rootId || pageOwnerRef.current.jobId !== jobId) return;
      setComparisonGroup(current => current?.root_conversation_id === rootId ? { ...current, title: title.trim() } : current);
      await refreshConversations();
    } catch { setConversationActionError("Could not rename the conversation. Try again."); }
  };

  const deleteBaseline = async () => {
    if (!jobId || !baselineConversation.id) return;
    const rootId = baselineConversation.id;
    if (!window.confirm("Delete this original conversation and all saved MNEMOS comparisons? This cannot be undone.")) return;
    setConversationActionError("");
    try {
      await api.deleteConversation(jobId, rootId);
      if (pageOwnerRef.current.rootId !== rootId || pageOwnerRef.current.jobId !== jobId) return;
      const remaining = conversationSummaries.filter(item => item.id !== rootId);
      setConversationSummaries(remaining);
      startNewBaseline();
      if (remaining[0]) await selectBaselineConversation(remaining[0].id);
      await refreshConversations();
    } catch { setConversationActionError("Could not delete the conversation. Try again."); }
  };

  const onMnemosChanged = useCallback((next: ChatConversation, owner?: ChatAttempt) => {
    if (!owner || !isCurrentAttempt(owner)) return;
    setComparisonGroup(current => {
      if (!current || !next.id) return current;
      const branchIndex = current.branches.findIndex(branch => branch.conversation_id === next.id);
      if (branchIndex < 0) return current;
      const branches = [...current.branches];
      branches[branchIndex] = { ...branches[branchIndex], messages: next.messages, updated_at: next.updated_at ?? branches[branchIndex].updated_at };
      return { ...current, branches, updated_at: next.updated_at ?? current.updated_at };
    });
  }, [isCurrentAttempt]);

  const persistBranchSelection = useCallback((jobId: string, groupId: string, branchId: string) => {
    const key = JSON.stringify([jobId, groupId]);
    const previous = branchWritesRef.current.get(key) ?? Promise.resolve();
    // Order mutations themselves, including copy preparation, so an older
    // request cannot reach persistence after a newer choice for this group.
    const response = previous.then(() => api.selectComparisonBranch(jobId, groupId, branchId));
    const settled = response.then(() => {}, () => {});
    branchWritesRef.current.set(key, settled);
    void settled.then(() => {
      if (branchWritesRef.current.get(key) === settled) branchWritesRef.current.delete(key);
    });
    return response;
  }, []);

  const prepareMnemosSend = useCallback(async (message: string, requestId: string): Promise<ChatSendTarget | undefined> => {
    if (!jobId || !comparisonGroup || !activeBranch) return undefined;
    const live = pageOwnerRef.current;
    if (live.jobId !== jobId || live.rootId !== baselineConversation.id || live.group?.group_id !== comparisonGroup.group_id) return undefined;
    const previous = activeAttemptRef.current;
    if (previous && previous.status !== "error") return undefined;
    const retry = previous?.requestId === requestId ? previous : null;
    if (retry && !isCurrentAttempt(retry)) return undefined;
    let owner: ChatAttempt = retry ? { ...retry, status: "preparing" } : {
      jobId, rootConversationId: baselineConversation.id, groupId: comparisonGroup.group_id,
      branchId: copiedPrompt ? undefined : activeBranch.id,
      conversationId: copiedPrompt ? undefined : activeBranch.conversation_id,
      sourceMessageId: copiedPrompt?.messageId, prompt: message, requestId,
      selectionToken: activeBranch.id, generation: pageGenerationRef.current, status: "preparing",
    };
    // Admit before the first request so remounts and lost POST responses retain
    // both the busy state and the idempotency key.
    branchSelectionRef.current += 1;
    storeAttempt(owner);
    try {
      let branch = live.group.branches.find(item => item.id === owner.branchId);
      if (owner.sourceMessageId && !owner.branchId) {
        const createdBranch = await api.createComparisonBranch(jobId, comparisonGroup.group_id, owner.sourceMessageId, requestId);
        if (!isCurrentAttempt(owner)) return undefined;
        branch = createdBranch;
        owner = { ...owner, branchId: branch.id, conversationId: branch.conversation_id, selectionToken: branch.id };
        storeAttempt(owner);
        setComparisonGroup(current => current ? { ...current, active_branch_id: createdBranch.id, branches: [...current.branches.filter(item => item.id !== createdBranch.id), createdBranch] } : current);
        setCopiedPrompt(null);
        try {
          const selected = await persistBranchSelection(jobId, comparisonGroup.group_id, branch.id);
          if (!isCurrentAttempt(owner)) return undefined;
          setComparisonGroup(selected);
        } catch {
          // The POST is authoritative. Retain its owner if selection persistence
          // fails; subsequent retries must not create another branch.
        }
      }
      if (!branch || !isCurrentAttempt(owner)) return undefined;
      return { conversation: { id: branch.conversation_id, job_id: jobId, messages: branch.messages }, branchId: branch.id, selectionToken: branch.id, attempt: owner };
    } catch {
      changeAttempt({ ...owner, status: "error" }, owner);
      return undefined;
    }
  }, [activeBranch, baselineConversation.id, changeAttempt, comparisonGroup, copiedPrompt, isCurrentAttempt, jobId, persistBranchSelection, storeAttempt]);

  const selectMnemosBranch = useCallback(async (branchId: string) => {
    if (!jobId || !comparisonGroup || (activeAttemptRef.current && activeAttemptRef.current.status !== "error")) return;
    const generation = pageGenerationRef.current;
    const selection = ++branchSelectionRef.current;
    const rootId = baselineConversation.id;
    const groupId = comparisonGroup.group_id;
    storeAttempt(null);
    // Keep the controlled selector responsive while persistence is pending.
    setComparisonGroup(current => current ? { ...current, active_branch_id: branchId } : current);
    try {
      const selected = await persistBranchSelection(jobId, groupId, branchId);
      const live = pageOwnerRef.current;
      if (generation !== pageGenerationRef.current || selection !== branchSelectionRef.current
        || jobId !== live.jobId || rootId !== live.rootId || groupId !== live.group?.group_id) return;
      setComparisonGroup(selected);
    } catch { /* Keep the user's local selection when persistence is unavailable. */ }
  }, [baselineConversation.id, comparisonGroup, jobId, persistBranchSelection, storeAttempt]);

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

  // ── KB helpers ──
  const fetchKBDocs = useCallback(async () => {
    if (!jobId || !chatReady) return;
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
  }, [jobId, chatReady]);

  useEffect(() => {
    fetchKBDocs();
  }, [fetchKBDocs]);

  // Does curating the shared library require an admin token on this server?
  useEffect(() => {
    if (!chatReady) return;
    api.getLibraryConfig()
      .then((c) => setKbAdminRequired(!!c.admin_required))
      .catch(() => setKbAdminRequired(false));
  }, [chatReady]);

  // While any document is still indexing (background task), poll until it
  // settles — capped so a stuck doc doesn't poll forever.
  const kbHasPending = kbDocs.some((d) => d.status === "pending");
  useEffect(() => {
    if (!chatReady || !kbHasPending) return;
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
  }, [chatReady, kbHasPending, fetchKBDocs]);

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

      {!chatReady && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-8 text-center" role="status">
          {jobQ.isError ? <>
            <p className="text-slate-200 text-lg mb-2">Could not load job status</p>
            <button type="button" onClick={() => void jobQ.refetch()} className="text-blue-300 underline">Retry</button>
          </> : !job ? <p className="text-slate-400">Loading job status…</p> : <>
            <p className="text-slate-200 text-lg mb-2">{{
              queued: "Analysis queued", running: "Analysis in progress", canceling: "Cancellation requested",
              deleting: "Job deletion in progress", failed: "Analysis failed", canceled: "Analysis canceled",
              deleted: "Job deleted", completed: "AI Chat ready", completed_with_errors: "AI Chat ready",
            }[job.status]}</p>
            {job.status === "failed" && job.error_summary && <p className="text-amber-300 text-sm">{job.error_summary.slice(0, 240)}</p>}
            {job.status === "canceled" && <Link to={`/jobs/${jobId}`} className="text-blue-300 underline">Rerun analysis from job details</Link>}
            {isActiveJobStatus(job.status) && <p className="text-slate-400 text-sm">AI Chat will open when analysis completes.</p>}
          </>}
        </div>
      )}

      {chatReady && job?.status === "completed_with_errors" && <div role="alert" className="rounded-lg border border-amber-700/50 bg-amber-900/20 px-4 py-3 text-sm text-amber-200">Partial analysis: some stages did not complete. Chat is available using the results that were saved.</div>}

      {/* Main layout: Chat + KB sidebar */}
      {chatReady && (
        <div className="flex gap-4 items-start" style={{ height: "calc(100vh - 140px)" }}>
          {/* ── Chat (main area) ── */}
          <div className={`flex-1 min-w-0 h-full transition-all ${kbOpen ? "" : ""} flex flex-col gap-2`}>
            <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
              <div className="min-w-0">
                {conversationSummaries.length > 0 && <select aria-label="Baseline conversation" value={baselineConversation.id ?? ""} onChange={event => void selectBaselineConversation(event.target.value)} className="max-w-xs rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs text-slate-200">
                  {!baselineConversation.id && <option value="" disabled>New conversation</option>}
                  {conversationSummaries.map(conversation => <option key={conversation.id} value={conversation.id}>{conversation.title || conversation.id}</option>)}
                </select>}
                {baselineConversation.id && <span className="ml-2 inline-flex gap-2 text-xs text-slate-300">
                  <button type="button" onClick={() => void renameBaseline()}>Rename conversation</button>
                  <button type="button" onClick={() => void deleteBaseline()}>Delete conversation</button>
                </span>}
                {conversationActionError && <p role="alert" className="text-xs text-amber-300">{conversationActionError}</p>}
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
                onNewConversation={startNewBaseline}
              />
            </div>
          </div>

          {mnemosOpen && comparisonGroup && activeBranch && (
            <MnemosChatDrawer
              jobId={jobId}
              group={comparisonGroup}
              activeBranch={activeBranch}
              baselineConversation={baselineConversation}
              conversation={{ id: activeBranch.conversation_id, job_id: jobId, messages: activeBranch.messages }}
              draft={mnemosDraft}
              onDraftChange={setMnemosDraft}
              onClose={() => setMnemosOpen(false)}
              onBranchChange={branchId => void selectMnemosBranch(branchId)}
              onBeforeSend={prepareMnemosSend}
              onConversationChanged={onMnemosChanged}
              onRetry={() => {}}
              returnFocusRef={mnemosToggleRef}
              pendingCopiedSource={copiedPrompt?.messageId}
              attempt={activeAttempt}
              onAttemptChange={changeAttempt}
              isCurrentAttempt={isCurrentAttempt}
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
