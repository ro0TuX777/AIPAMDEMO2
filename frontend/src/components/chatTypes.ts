import type {
  ChatCitation,
  ChatEvidenceRef,
  ChatMessage,
  ChatMode,
  HistoricalFindingCitation,
  MnemosRetrievalStatus,
} from "../api";

export type { ChatCitation, ChatEvidenceRef, ChatMessage, ChatMode, HistoricalFindingCitation, MnemosRetrievalStatus };

export interface ChatConversation {
  id?: string;
  job_id: string;
  created_at?: string;
  updated_at?: string;
  messages: ChatMessage[];
}
