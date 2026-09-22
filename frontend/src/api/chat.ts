import type {
  ChatRequest,
  ChatResponse,
  ConversationSummary,
  ConversationHistoryOut,
} from "./types";
import {
  get,
  post,
  del,
  patch,
} from "./transport";

export const chatApi = {
  chatWithJob(jobId: string, body: ChatRequest): Promise<ChatResponse> { return post<ChatResponse>(`/jobs/${jobId}/chat`, body); },

  listConversations(jobId: string): Promise<ConversationSummary[]> {
    return get<ConversationSummary[]>(`/jobs/${jobId}/conversations`);
  },

  getConversation(jobId: string, convId: string): Promise<ConversationHistoryOut> {
    return get<ConversationHistoryOut>(`/jobs/${jobId}/conversations/${convId}`);
  },

  renameConversation(jobId: string, convId: string, title: string): Promise<ConversationSummary> {
    return patch<ConversationSummary>(`/jobs/${jobId}/conversations/${convId}`, { title });
  },

  deleteConversation(jobId: string, convId: string): Promise<void> {
    return del<void>(`/jobs/${jobId}/conversations/${convId}`);
  },
};
