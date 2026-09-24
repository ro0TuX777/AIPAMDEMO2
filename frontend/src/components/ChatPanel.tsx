import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, isDemoMode } from "../api";
import { ChatStreamError, normalizeChatMessages } from "../api/chat";
import type { ChatStreamTerminalMetadata } from "../api/chat";
import type { ChatConversation, ChatMessage, ChatMode } from "./chatTypes";

export interface ChatPanelProps {
  jobId: string;
  conversation: ChatConversation;
  /** Parent-owned identity that changes for every controlled selection, including drafts. */
  selectionToken: string | number;
  mode: ChatMode;
  onCopyToMnemos: (messageId: string, content: string) => void;
  onRetry: (requestId: string) => void;
  onConversationChanged: (conversation: ChatConversation, owner?: ChatAttempt) => void;
  initialMessage?: string;
  contextHint?: string;
  onClose?: () => void;
  inputValue?: string;
  onInputChange?: (value: string) => void;
  inputLabel?: string;
  sendLabel?: string;
  /** Admits a page-owned attempt and prepares copied branches before a request. */
  onBeforeSend?: (message: string, requestId: string) => Promise<ChatSendTarget | undefined>;
  onTurnComplete?: (conversationId: string) => void;
  onNewConversation?: () => void;
  attempt?: ChatAttempt | null;
  onAttemptChange?: (attempt: ChatAttempt | null, owner: ChatAttempt) => void;
  isCurrentAttempt?: (owner: ChatAttempt) => boolean;
}

export interface ChatSendTarget {
  conversation: ChatConversation;
  branchId?: string;
  selectionToken?: string | number;
  attempt?: ChatAttempt;
}

export interface ChatAttempt {
  jobId: string;
  rootConversationId?: string;
  groupId?: string;
  branchId?: string;
  conversationId?: string;
  sourceMessageId?: string;
  prompt: string;
  requestId: string;
  selectionToken: string | number;
  generation: number;
  userMessageId?: string;
  assistantMessageId?: string;
  /** A terminal error is immutable; sending this request again only replays it. */
  terminalError?: boolean;
  status: "preparing" | "streaming" | "error";
}

interface LegacyChatPanelProps {
  jobId: string;
  initialMessage?: string;
  contextHint?: string;
  onClose?: () => void;
}

type ChatPanelInputProps = ChatPanelProps | LegacyChatPanelProps;

const newId = () => globalThis.crypto?.randomUUID?.() ?? "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, token => {
  const value = Math.floor(Math.random() * 16);
  return (token === "x" ? value : (value & 0x3) | 0x8).toString(16);
});
const emptyConversation = (jobId: string): ChatConversation => ({ job_id: jobId, messages: [] });
const errorMessage = (error: unknown) => error instanceof Error ? error.message : "Failed to get response";
const messageRequestId = (message: ChatMessage) => message.role === "assistant" && typeof message.metadata?.request_id === "string"
  ? message.metadata.request_id : message.request_id;
interface RequestOwner {
  conversationId?: string;
  branchId?: string;
  prompt: string;
  requestId: string;
  selectionToken: string | number | undefined;
  attempt: ChatAttempt;
}

export function ChatPanel(props: ChatPanelInputProps) {
  const { jobId, initialMessage, contextHint, onClose } = props;
  const controlled = "conversation" in props;
  const sourceConversation = controlled ? props.conversation : undefined;
  const conversation = useMemo(() => sourceConversation
    ? { ...sourceConversation, messages: normalizeChatMessages(sourceConversation.messages, sourceConversation.id) }
    : emptyConversation(jobId), [sourceConversation, jobId]);
  const selectionToken = controlled ? props.selectionToken : undefined;
  const mode: ChatMode = controlled ? props.mode : "baseline";
  const onConversationChanged = controlled ? props.onConversationChanged : () => {};
  const onCopyToMnemos = controlled ? props.onCopyToMnemos : () => {};
  const onRetry = controlled ? props.onRetry : () => {};
  const controlledInput = controlled && props.inputValue !== undefined;
  const inputValue = controlled ? props.inputValue : undefined;
  const onInputChange = controlled ? props.onInputChange : undefined;
  const onBeforeSend = controlled ? props.onBeforeSend : undefined;
  const onTurnComplete = controlled ? props.onTurnComplete : undefined;
  const attempt = controlled ? props.attempt : undefined;
  const onAttemptChange = controlled ? props.onAttemptChange : undefined;
  const isCurrentAttempt = controlled ? props.isCurrentAttempt : undefined;
  const [input, setInput] = useState("");
  const [loadingGeneration, setLoadingGeneration] = useState<number | null>(null);
  const [failure, setFailure] = useState<{ requestId: string; generation: number } | null>(null);
  const preparingRef = useRef(false);
  const requestOwnersRef = useRef(new Map<string, RequestOwner>());
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesRef = useRef(conversation.messages);
  const selectedConversationRef = useRef(conversation);
  selectedConversationRef.current = conversation;
  const selectionTokenRef = useRef(selectionToken);
  const selectionGenerationRef = useRef(0);
  if (controlled && selectionTokenRef.current !== selectionToken) {
    selectionTokenRef.current = selectionToken;
    selectionGenerationRef.current += 1;
    messagesRef.current = conversation.messages;
  }
  const selectionGeneration = selectionGenerationRef.current;
  const isLoading = onAttemptChange
    ? Boolean(attempt && attempt.status !== "error")
    : loadingGeneration === selectionGeneration;
  const activeFailure = attempt?.status === "error" && attempt.selectionToken === selectionToken
    ? { requestId: attempt.requestId, generation: selectionGeneration }
    : !onAttemptChange && failure?.generation === selectionGeneration ? failure : null;
  const terminalFailure = activeFailure && (attempt?.requestId === activeFailure.requestId
    ? attempt.terminalError : requestOwnersRef.current.get(activeFailure.requestId)?.attempt.terminalError);
  const initialContextHandled = useRef(false);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [conversation.messages]);

  useEffect(() => {
    messagesRef.current = conversation.messages;
  }, [conversation.messages]);

  useEffect(() => {
    setLoadingGeneration(null);
    setFailure(null);
  }, [selectionGeneration]);

  const isCurrentSelection = useCallback((originGeneration: number, requestId?: string) => {
    if (controlled && selectionGenerationRef.current !== originGeneration) return false;
    const owner = requestId ? requestOwnersRef.current.get(requestId)?.attempt : undefined;
    return !isCurrentAttempt || Boolean(owner && isCurrentAttempt(owner));
  }, [controlled, isCurrentAttempt]);

  const emit = useCallback((originGeneration: number, messages: ChatMessage[], id = selectedConversationRef.current.id, requestId?: string) => {
    const selected = selectedConversationRef.current;
    if (!isCurrentSelection(originGeneration, requestId)) return false;
    messagesRef.current = messages;
    onConversationChanged({ ...selected, ...(id ? { id } : {}), updated_at: new Date().toISOString(), messages }, requestId ? requestOwnersRef.current.get(requestId)?.attempt : undefined);
    return true;
  }, [isCurrentSelection, onConversationChanged]);

  const updateAssistant = useCallback((originGeneration: number, requestId: string, update: (message: ChatMessage) => ChatMessage) => {
    emit(originGeneration, messagesRef.current.map(message => messageRequestId(message) === requestId && message.role === "assistant" ? update(message) : message), undefined, requestId);
  }, [emit]);

  const complete = useCallback(async (originGeneration: number, requestId: string, terminal: ChatStreamTerminalMetadata, content: string) => {
    const owner = requestOwnersRef.current.get(requestId);
    if (!owner || !isCurrentSelection(originGeneration, requestId)) return;
    if (owner.conversationId && owner.conversationId !== terminal.conversation_id) return;
    if (terminal.request_id && terminal.request_id !== requestId) return;
    if (owner.branchId && terminal.branch_id && owner.branchId !== terminal.branch_id) return;
    // An id-less draft acquires its server identity only while its original
    // controlled selection still owns this response.
    owner.conversationId = terminal.conversation_id;
    const metadata: Record<string, unknown> = {
      request_id: requestId,
      status: terminal.status, retrieval_status: terminal.retrieval_status ?? null,
      model_id: terminal.model_id ?? null, generation: terminal.generation ?? null,
      confidence: terminal.confidence ?? null, evidence_refs: terminal.evidence_refs ?? [],
      suggested_followups: terminal.suggested_followups ?? [],
      receipt_id: terminal.receipt_id ?? null,
    };
    let finishedAttempt = { ...owner.attempt, conversationId: terminal.conversation_id };
    try {
      const history = await api.getConversation(jobId, terminal.conversation_id);
      if (!emit(originGeneration, history.messages.map(message => ({ ...message, saved: message.saved !== false })), terminal.conversation_id, requestId)) return;
      finishedAttempt = {
        ...finishedAttempt,
        userMessageId: history.messages.find(message => messageRequestId(message) === requestId && message.role === "user")?.id ?? finishedAttempt.userMessageId,
        assistantMessageId: history.messages.find(message => messageRequestId(message) === requestId && message.role === "assistant")?.id ?? finishedAttempt.assistantMessageId,
      };
    } catch {
      emit(originGeneration, messagesRef.current.map(message => messageRequestId(message) === requestId && message.role === "assistant"
        ? { ...message, content, citations: terminal.citations, metadata } : message), terminal.conversation_id, requestId);
    }
    if (!isCurrentSelection(originGeneration, requestId)) return;
    if (terminal.status === "error") {
      const failedAttempt: ChatAttempt = { ...finishedAttempt, status: "error", terminalError: true };
      onAttemptChange?.(failedAttempt, owner.attempt);
      owner.attempt = failedAttempt;
      setFailure({ requestId, generation: originGeneration });
    } else onAttemptChange?.(null, owner.attempt);
    onTurnComplete?.(terminal.conversation_id);
  }, [emit, isCurrentSelection, jobId, onAttemptChange, onTurnComplete]);

  const handleSend = useCallback(async (messageText?: string, retryRequestId?: string) => {
    const text = messageText || (controlledInput ? inputValue ?? "" : input).trim();
    if (!text || isLoading || preparingRef.current) return;
    const requestId = retryRequestId ?? newId();
    let originGeneration = selectionGeneration;
    let targetConversation = conversation;
    let targetBranchId: string | undefined;
    let admittedAttempt = retryRequestId
      ? attempt?.requestId === retryRequestId ? attempt : requestOwnersRef.current.get(retryRequestId)?.attempt
      : undefined;
    if (onBeforeSend) {
      preparingRef.current = true;
      try {
        const prepared = await onBeforeSend(text, requestId);
        if (!prepared) return;
        targetConversation = prepared.conversation;
        targetBranchId = prepared.branchId;
        admittedAttempt = prepared.attempt;
        messagesRef.current = targetConversation.messages;
        selectedConversationRef.current = targetConversation;
        if (prepared.selectionToken !== undefined && selectionTokenRef.current !== prepared.selectionToken) {
          selectionTokenRef.current = prepared.selectionToken;
          selectionGenerationRef.current += 1;
        }
        // Branch creation deliberately selects the returned owner before streaming.
        originGeneration = selectionGenerationRef.current;
      } finally {
        preparingRef.current = false;
      }
    }
    const timestamp = new Date().toISOString();
    const existingAttempt = retryRequestId && admittedAttempt?.userMessageId && admittedAttempt.assistantMessageId ? admittedAttempt : null;
    const nextSequence = targetConversation.messages.reduce((highest, message) => Math.max(highest, message.sequence), 0) + 1;
    const userMessage: ChatMessage = { id: existingAttempt?.userMessageId ?? newId(), sequence: nextSequence, role: "user", content: text, citations: [], metadata: null, request_id: requestId, timestamp, saved: false };
    const assistantMessage: ChatMessage = { id: existingAttempt?.assistantMessageId ?? newId(), sequence: nextSequence + 1, role: "assistant", content: "", citations: [], metadata: { status: "pending" }, request_id: requestId, timestamp, saved: false };
    const currentAttempt: ChatAttempt = {
      ...(admittedAttempt ?? { jobId, prompt: text, requestId, selectionToken: selectionToken ?? "legacy", generation: originGeneration, status: "preparing" }),
      conversationId: targetConversation.id, branchId: targetBranchId ?? admittedAttempt?.branchId, prompt: text, requestId,
      selectionToken: selectionTokenRef.current ?? "legacy",
      userMessageId: userMessage.id, assistantMessageId: assistantMessage.id, status: "streaming",
    };
    requestOwnersRef.current.set(requestId, {
      conversationId: targetConversation.id, branchId: currentAttempt.branchId, prompt: text,
      requestId, selectionToken: selectionTokenRef.current, attempt: currentAttempt,
    });
    if (!isCurrentSelection(originGeneration, requestId)) return;
    onAttemptChange?.(currentAttempt, admittedAttempt ?? currentAttempt);
    if (!existingAttempt) emit(originGeneration, [...targetConversation.messages, userMessage, assistantMessage], targetConversation.id, requestId);
    if (controlledInput) onInputChange?.(""); else setInput("");
    setFailure(null);
    setLoadingGeneration(originGeneration);
    const body = { message: text, conversation_id: targetConversation.id, context_hint: contextHint, mode, request_id: requestId };
    const applyJsonResponse = async (response: Awaited<ReturnType<typeof api.chatWithJob>>) => {
      while (response.status === "pending" && isCurrentSelection(originGeneration, requestId)) {
        body.conversation_id = response.conversation_id;
        emit(originGeneration, messagesRef.current, response.conversation_id, requestId);
        await new Promise(resolve => setTimeout(resolve, (response.retry_after_seconds ?? 2) * 1000));
        if (!isCurrentSelection(originGeneration, requestId)) return;
        response = await api.chatWithJob(jobId, body);
      }
      if (!isCurrentSelection(originGeneration, requestId)) return;
      await complete(originGeneration, requestId, {
      type: "meta", conversation_id: response.conversation_id, branch_id: response.branch_id,
      request_id: response.request_id, status: response.status ?? "completed", retrieval_status: response.retrieval_status,
      citations: response.citations, model_id: response.model_id, generation: response.generation,
      confidence: response.confidence, evidence_refs: response.evidence_refs, suggested_followups: response.suggested_followups,
      }, response.response);
    };
    try {
      if (isDemoMode()) {
        await applyJsonResponse(await api.chatWithJob(jobId, body));
        return;
      }
      let content = "";
      const terminal = await api.streamWithJob(jobId, body, event => {
        if (event.type === "token") content += event.content;
        if (event.type === "replace") content = event.content;
        if (event.type === "error") {
          content = `Error: ${event.content || event.error || "Failed to get response"}`;
          if (isCurrentSelection(originGeneration, requestId)) {
            setFailure({ requestId, generation: originGeneration });
          }
        }
        updateAssistant(originGeneration, requestId, message => ({ ...message, content }));
      }, metadata => {
        const owner = requestOwnersRef.current.get(requestId);
        if (!owner || !isCurrentSelection(originGeneration, requestId)) return;
        if (metadata.request_id && metadata.request_id !== requestId) return;
        if (owner.conversationId && owner.conversationId !== metadata.conversation_id) return;
        body.conversation_id = metadata.conversation_id;
        owner.conversationId = metadata.conversation_id;
        emit(originGeneration, messagesRef.current, metadata.conversation_id, requestId);
      });
      await complete(originGeneration, requestId, terminal, content);
    } catch (error) {
      if (error instanceof ChatStreamError && (error.code === "TURN_PENDING" || (mode === "baseline" && !error.responseReceived))) {
        try {
          await applyJsonResponse(await api.chatWithJob(jobId, body));
        } catch (fallbackError) {
          const message = `Error: ${errorMessage(fallbackError)}`;
          updateAssistant(originGeneration, requestId, assistant => ({ ...assistant, content: message, metadata: { status: "error" } }));
          if (isCurrentSelection(originGeneration, requestId)) {
            setFailure({ requestId, generation: originGeneration });
            onAttemptChange?.({ ...currentAttempt, status: "error" }, currentAttempt);
          }
        }
      } else {
        const message = `Error: ${errorMessage(error)}`;
        const unavailable = mode === "mnemos" && error instanceof ChatStreamError && error.code === "MNEMOS_UNAVAILABLE";
        updateAssistant(originGeneration, requestId, assistant => ({ ...assistant, content: message, metadata: { ...assistant.metadata, status: "error", ...(unavailable ? { retrieval_status: "unavailable" } : {}) } }));
        if (isCurrentSelection(originGeneration, requestId)) {
          setFailure({ requestId, generation: originGeneration });
          onAttemptChange?.({ ...currentAttempt, status: "error" }, currentAttempt);
        }
      }
    } finally {
      if (!controlled || selectionGenerationRef.current === originGeneration) setLoadingGeneration(null);
    }
  }, [attempt, complete, contextHint, controlledInput, conversation, emit, input, isCurrentSelection, isLoading, jobId, mode, onAttemptChange, onBeforeSend, inputValue, onInputChange, selectionGeneration, updateAssistant]);

  useEffect(() => {
    if (initialMessage && controlled && !initialContextHandled.current) {
      initialContextHandled.current = true;
      void handleSend(initialMessage);
    }
  }, [controlled, handleSend, initialMessage]);

  const exportToMarkdown = () => {
    if (!conversation.messages.length) return;
    const lines = [`# Chat Export - Job ${jobId}`, "", `**Exported:** ${new Date().toISOString()}`, ""];
    for (const message of conversation.messages) lines.push(`## ${message.role === "user" ? "User" : "Assistant"} (${new Date(message.timestamp).toLocaleString()})`, "", message.content, "", "---", "");
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/markdown" }));
    const link = document.createElement("a");
    link.href = url; link.download = `chat-export-${jobId}-${Date.now()}.md`;
    document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
  };

  const startNewConversation = () => { initialContextHandled.current = false; if (controlled && props.onNewConversation) props.onNewConversation(); else onConversationChanged(emptyConversation(jobId)); };

  return <div className="flex min-h-0 flex-col h-full overflow-hidden bg-slate-900 rounded-lg border border-slate-700">
    <div className="flex shrink-0 items-center justify-between px-4 py-3 border-b border-slate-700">
      <span className="text-slate-100 font-semibold">{mode === "mnemos" ? "MNEMOS comparison" : "AI Chat"}</span>
      <div className="flex items-center gap-2">
        {conversation.messages.length > 0 && <>{mode === "baseline" && <button onClick={startNewConversation} className="text-slate-400 hover:text-slate-50 transition-colors text-sm px-2 py-1 rounded hover:bg-slate-700">+ New</button>}<button onClick={exportToMarkdown} className="text-slate-400 hover:text-slate-50 transition-colors text-sm px-2 py-1 rounded hover:bg-slate-700">Export</button></>}
        {onClose && <button onClick={onClose} className="text-slate-400 hover:text-slate-50 transition-colors">×</button>}
      </div>
    </div>
    <div className="min-h-0 flex-1 overflow-y-auto p-4 space-y-4">
      {conversation.messages.length === 0 && <div className="text-slate-500 text-center py-8"><p className="text-base mb-4">Ask questions about this PCAP analysis</p><div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-xl mx-auto text-left">{["Summarize the key findings and their severity", "What are the highest-severity alerts and which hosts triggered them?", "Check for signs of lateral movement between internal hosts", "Identify any command-and-control (C2) communication patterns", "Is there evidence of data exfiltration?", "Which hosts have the most suspicious activity?"].map(question => <button key={question} onClick={() => void handleSend(question)} disabled={isLoading} className="px-3 py-2 rounded-lg border border-slate-700 bg-slate-800/50 hover:bg-slate-700/60 text-slate-300 text-xs text-left disabled:opacity-50">{question}</button>)}</div></div>}
      {conversation.messages.map(message => <div key={message.id} className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}><div className={`max-w-[80%] rounded-lg px-4 py-2 ${message.role === "user" ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-100"}`}>
        <p className="whitespace-pre-wrap">{message.content}</p>
        {message.role === "user" && mode === "baseline" && controlled && message.saved !== false && <button type="button" onClick={() => onCopyToMnemos(message.id, message.content)} className="mt-2 text-xs underline underline-offset-2 hover:text-slate-200">Copy to MNEMOS</button>}
        {message.role === "assistant" && mode === "mnemos" && message.metadata?.status === "completed" && typeof message.metadata.receipt_id === "string" && message.metadata.receipt_id.length > 0 && <Link className="mt-2 inline-block text-xs text-cyan-300 underline" to={`/mnemos/receipts/${encodeURIComponent(message.metadata.receipt_id)}`}>View evidence receipt</Link>}
        {message.citations.length > 0 && <div className="mt-3 pt-2 border-t border-slate-600"><details className="group"><summary className="flex cursor-pointer list-none items-center gap-2 text-xs text-slate-300 hover:text-slate-50"><span className="font-medium">Sources</span><span className="text-slate-500">({message.citations.length})</span></summary><div className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1">{message.citations.map((citation, index) => <div key={`${citation.type}-${citation.id ?? index}-${index}`} className="rounded-md border border-slate-700 bg-slate-900/60 px-2 py-2"><p className="text-[11px] uppercase tracking-wide text-slate-500">{citation.type.replace(/_/g, " ")}</p><p className="mt-1 whitespace-pre-wrap break-words text-xs text-slate-300">{citation.snippet}</p></div>)}</div></details></div>}
        {message.role === "assistant" && message.metadata?.suggested_followups instanceof Array && !isLoading && <div className="mt-3 pt-2 border-t border-slate-700"><p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Follow-up questions</p><div className="flex flex-wrap gap-1.5">{message.metadata.suggested_followups.filter((item): item is string => typeof item === "string").map(question => <button key={question} onClick={() => void handleSend(question)} className="text-left text-xs px-2 py-1 rounded border border-slate-700 bg-slate-900/60 text-emerald-400/80">{question}</button>)}</div></div>}
      </div></div>)}
      {isLoading && <div className="flex justify-start"><div className="bg-slate-800 rounded-lg px-4 py-2 text-slate-400"><span className="animate-pulse">Thinking...</span></div></div>}
      {mode === "mnemos" && activeFailure && <div>
        {terminalFailure && <p className="mb-1 text-xs text-slate-400">This request has finished. Replay returns its saved error.</p>}
        <button type="button" onClick={() => { const owner = requestOwnersRef.current.get(activeFailure.requestId); setFailure(null); onRetry(activeFailure.requestId); void handleSend(owner?.prompt ?? attempt?.prompt, activeFailure.requestId); }} className="text-sm text-amber-300 underline underline-offset-2">{terminalFailure ? "Replay MNEMOS" : "Retry MNEMOS"}</button>
      </div>}
      <div ref={messagesEndRef} />
    </div>
    <div className="shrink-0 p-4 border-t border-slate-700"><div className="flex gap-2"><input type="text" aria-label={controlled ? props.inputLabel : undefined} value={controlledInput ? props.inputValue : input} onChange={event => controlledInput ? props.onInputChange?.(event.target.value) : setInput(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void handleSend(); } }} placeholder="Ask about the findings..." className="min-w-0 flex-1 bg-slate-800 text-slate-100 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" disabled={isLoading} /><button onClick={() => void handleSend()} disabled={isLoading || !(controlledInput ? props.inputValue : input)?.trim()} className="shrink-0 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50">{controlled ? props.sendLabel ?? "Send" : "Send"}</button></div></div>
  </div>;
}
