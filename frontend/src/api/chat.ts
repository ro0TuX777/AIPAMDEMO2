import type {
  ChatComparisonBranch,
  ChatComparisonGroup,
  ChatCitation,
  ChatEvidenceRef,
  ChatGenerationMetadata,
  ChatRequest,
  ChatMessage,
  ChatResponse,
  ConversationSummary,
  ConversationHistoryOut,
  MnemosRetrievalStatus,
} from "./types";
import {
  get,
  post,
  del,
  patch,
} from "./transport";
import { API_BASE, getApiToken } from "./transport";

export type ChatStreamEvent =
  | { type: "token"; content: string }
  | { type: "replace"; content: string }
  | { type: "error"; content?: string; error?: string; code?: string; retryable?: boolean };

export interface ChatStreamTerminalMetadata {
  type: "meta";
  conversation_id: string;
  branch_id?: string | null;
  request_id?: string | null;
  status: "pending" | "completed" | "error";
  retrieval_status?: MnemosRetrievalStatus | null;
  citations: ChatCitation[];
  model_id?: string | null;
  generation?: ChatGenerationMetadata | null;
  confidence?: number | null;
  evidence_refs?: ChatEvidenceRef[];
  suggested_followups?: string[];
}

export class ChatStreamError extends Error {
  constructor(message: string, public readonly responseReceived: boolean, public readonly code?: string) {
    super(message);
    this.name = "ChatStreamError";
  }
}

async function streamWithJob(
  jobId: string,
  body: ChatRequest,
  onEvent: (event: ChatStreamEvent) => void,
  onMetadata?: (event: ChatStreamTerminalMetadata) => void,
): Promise<ChatStreamTerminalMetadata> {
  const token = getApiToken();
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/jobs/${jobId}/chat/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
  } catch (error) {
    throw new ChatStreamError(error instanceof Error ? error.message : "Stream transport failed", false);
  }
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    let code: string | undefined;
    try {
      const payload = await response.json();
      const detail = payload?.detail ?? payload;
      if (detail && typeof detail === "object") {
        if (typeof detail.error === "string") message = detail.error;
        if (typeof detail.code === "string") code = detail.code;
      }
    } catch { /* Preserve the status fallback for non-JSON errors. */ }
    throw new ChatStreamError(message, true, code);
  }
  const reader = response.body?.getReader();
  if (!reader) throw new ChatStreamError("No readable stream", true);

  const decoder = new TextDecoder();
  let buffer = "";
  let terminal: ChatStreamTerminalMetadata | undefined;
  const consume = (chunk: string) => {
    for (const line of chunk.split("\n")) {
      if (!line.startsWith("data: ")) continue;
      const raw = line.slice(6).trim();
      if (!raw || raw === "[DONE]") continue;
      const event = JSON.parse(raw) as ChatStreamEvent | ChatStreamTerminalMetadata;
      if (event.type === "meta") { terminal = event; onMetadata?.(event); }
      else onEvent(event);
    }
  };
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split("\n\n");
    buffer = events.pop() || "";
    events.forEach(consume);
  }
  if (buffer) consume(buffer);
  if (!terminal || terminal.status === "pending") {
    throw new ChatStreamError(`Stream ended with ${terminal?.status ?? "no"} terminal metadata`, true, terminal?.status === "pending" ? "TURN_PENDING" : undefined);
  }
  return terminal;
}

export function normalizeChatMessages(messages: ChatMessage[], conversationId?: string): ChatMessage[] {
  return messages.map((message, index) => ({
    ...message, id: message.id || `legacy:${conversationId ?? "draft"}:${index + 1}`,
    sequence: Number.isFinite(message.sequence) ? message.sequence : index + 1,
    citations: Array.isArray(message.citations) ? message.citations : [],
    ...(!message.id ? { saved: false } : {}),
  }));
}

export const chatApi = {
  chatWithJob(jobId: string, body: ChatRequest): Promise<ChatResponse> { return post<ChatResponse>(`/jobs/${jobId}/chat`, body); },

  streamWithJob,

  openComparison(jobId: string, rootConversationId: string): Promise<ChatComparisonGroup> {
    return post<ChatComparisonGroup>(`/jobs/${jobId}/chat/comparisons`, { root_conversation_id: rootConversationId });
  },

  getComparison(jobId: string, groupId: string): Promise<ChatComparisonGroup> {
    return get<ChatComparisonGroup>(`/jobs/${jobId}/chat/comparisons/${groupId}`);
  },

  selectComparisonBranch(jobId: string, groupId: string, branchId: string): Promise<ChatComparisonGroup> {
    return patch<ChatComparisonGroup>(`/jobs/${jobId}/chat/comparisons/${groupId}`, { active_branch_id: branchId });
  },

  createComparisonBranch(
    jobId: string,
    groupId: string,
    sourceMessageId: string,
    requestId: string,
  ): Promise<ChatComparisonBranch> {
    return post<ChatComparisonBranch>(`/jobs/${jobId}/chat/comparisons/${groupId}/branches`, {
      source_message_id: sourceMessageId,
      request_id: requestId,
    });
  },

  listConversations(jobId: string): Promise<ConversationSummary[]> {
    return get<ConversationSummary[]>(`/jobs/${jobId}/conversations`);
  },

  getConversation(jobId: string, convId: string): Promise<ConversationHistoryOut> {
    return get<ConversationHistoryOut>(`/jobs/${jobId}/conversations/${convId}`).then(history => ({ ...history, messages: normalizeChatMessages(history.messages, history.id) }));
  },

  renameConversation(jobId: string, convId: string, title: string): Promise<ConversationSummary> {
    return patch<ConversationSummary>(`/jobs/${jobId}/conversations/${convId}`, { title });
  },

  deleteConversation(jobId: string, convId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/conversations/${convId}`);
  },
};
