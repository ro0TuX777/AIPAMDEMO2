import { useState, useRef, useEffect, useCallback } from "react";
import { api, ChatResponse, ChatCitation, ConversationSummary } from "../api";

interface ChatMessage {
    role: "user" | "assistant";
    content: string;
    citations?: ChatCitation[];
    timestamp: Date;
}

interface ChatPanelProps {
    jobId: string;
    initialContext?: string;
    onClose?: () => void;
}

export function ChatPanel({ jobId, initialContext, onClose }: ChatPanelProps) {
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [input, setInput] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [isLoadingHistory, setIsLoadingHistory] = useState(true);
    const [conversationId, setConversationId] = useState<string | undefined>();
    const [conversations, setConversations] = useState<ConversationSummary[]>([]);
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const initialContextHandled = useRef(false);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

    // Load existing conversations on mount
    useEffect(() => {
        const loadConversations = async () => {
            try {
                const convs = await api.getJobConversations(jobId);
                setConversations(convs);

                // If there's a recent conversation, load it
                if (convs.length > 0) {
                    const mostRecent = convs[0]; // Already sorted by updated_at desc
                    await loadConversation(mostRecent.id);
                }
            } catch (error) {
                console.error("Failed to load conversations:", error);
            } finally {
                setIsLoadingHistory(false);
            }
        };
        loadConversations();
    }, [jobId]);

    const loadConversation = async (convId: string) => {
        try {
            const history = await api.getConversationHistory(jobId, convId);
            setConversationId(history.id);
            setMessages(
                history.messages.map((m) => ({
                    role: m.role as "user" | "assistant",
                    content: m.content,
                    citations: m.citations,
                    timestamp: m.timestamp ? new Date(m.timestamp) : new Date(),
                }))
            );
        } catch (error) {
            console.error("Failed to load conversation:", error);
        }
    };

    // If initialContext is provided, send it as a message (only once per mount)
    useEffect(() => {
        if (initialContext && !isLoadingHistory && !initialContextHandled.current) {
            initialContextHandled.current = true;
            handleSend(initialContext);
        }
    }, [initialContext, isLoadingHistory]);

    const handleSend = async (messageText?: string) => {
        const text = messageText || input.trim();
        if (!text || isLoading) return;

        const userMessage: ChatMessage = {
            role: "user",
            content: text,
            timestamp: new Date(),
        };
        setMessages((prev) => [...prev, userMessage]);
        setInput("");
        setIsLoading(true);

        try {
            const response: ChatResponse = await api.chatWithJob(jobId, {
                message: text,
                conversation_id: conversationId,
                context_hint: initialContext,
            });

            setConversationId(response.conversation_id);

            const assistantMessage: ChatMessage = {
                role: "assistant",
                content: response.response,
                citations: response.citations,
                timestamp: new Date(),
            };
            setMessages((prev) => [...prev, assistantMessage]);
        } catch (error) {
            const errorMessage: ChatMessage = {
                role: "assistant",
                content: `Error: ${error instanceof Error ? error.message : "Failed to get response"}`,
                timestamp: new Date(),
            };
            setMessages((prev) => [...prev, errorMessage]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    const exportToMarkdown = () => {
        if (messages.length === 0) return;

        const lines: string[] = [
            `# Chat Export - Job ${jobId}`,
            ``,
            `**Exported:** ${new Date().toISOString()}`,
            `**Conversation ID:** ${conversationId || "N/A"}`,
            ``,
            `---`,
            ``,
        ];

        for (const msg of messages) {
            const timestamp = msg.timestamp.toLocaleString();
            if (msg.role === "user") {
                lines.push(`## 🧑 User (${timestamp})`);
                lines.push(``);
                lines.push(msg.content);
            } else {
                lines.push(`## 🤖 Assistant (${timestamp})`);
                lines.push(``);
                lines.push(msg.content);
                if (msg.citations && msg.citations.length > 0) {
                    lines.push(``);
                    lines.push(`**Sources:**`);
                    for (const c of msg.citations) {
                        lines.push(`- [${c.type}] ${c.snippet}`);
                    }
                }
            }
            lines.push(``);
            lines.push(`---`);
            lines.push(``);
        }

        const markdown = lines.join("\n");
        const blob = new Blob([markdown], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `chat-export-${jobId}-${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    const startNewConversation = () => {
        setMessages([]);
        setConversationId(undefined);
        initialContextHandled.current = false;
    };

    return (
        <div className="flex flex-col h-full bg-gray-900 rounded-lg border border-gray-700">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
                <h3 className="text-lg font-semibold text-white">Ask about findings</h3>
                <div className="flex items-center gap-2">
                    {messages.length > 0 && (
                        <>
                            <button
                                onClick={startNewConversation}
                                className="text-gray-400 hover:text-white transition-colors text-sm px-2 py-1 rounded hover:bg-gray-700"
                                title="Start new conversation"
                            >
                                ➕ New
                            </button>
                            <button
                                onClick={exportToMarkdown}
                                className="text-gray-400 hover:text-white transition-colors text-sm px-2 py-1 rounded hover:bg-gray-700"
                                title="Export chat to Markdown"
                            >
                                📥 Export
                            </button>
                        </>
                    )}
                    {onClose && (
                        <button
                            onClick={onClose}
                            className="text-gray-400 hover:text-white transition-colors"
                        >
                            ✕
                        </button>
                    )}
                </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {isLoadingHistory ? (
                    <div className="text-gray-500 text-center py-8">
                        <span className="animate-pulse">Loading conversation history...</span>
                    </div>
                ) : messages.length === 0 ? (
                    <div className="text-gray-500 text-center py-8">
                        <p>Ask questions about the analysis findings.</p>
                        <p className="text-sm mt-2">
                            Examples: "What malware was detected?" or "Explain the lateral movement"
                        </p>
                    </div>
                ) : null}
                {messages.map((msg, idx) => (
                    <div
                        key={idx}
                        className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                    >
                        <div
                            className={`max-w-[80%] rounded-lg px-4 py-2 ${
                                msg.role === "user"
                                    ? "bg-blue-600 text-white"
                                    : "bg-gray-800 text-gray-100"
                            }`}
                        >
                            <p className="whitespace-pre-wrap">{msg.content}</p>
                            {msg.citations && msg.citations.length > 0 && (
                                <div className="mt-2 pt-2 border-t border-gray-600">
                                    <p className="text-xs text-gray-400 mb-1">Sources:</p>
                                    {msg.citations.slice(0, 3).map((c, i) => (
                                        <p key={i} className="text-xs text-gray-400">
                                            • [{c.type}] {c.snippet.slice(0, 60)}...
                                        </p>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                ))}
                {isLoading && (
                    <div className="flex justify-start">
                        <div className="bg-gray-800 rounded-lg px-4 py-2 text-gray-400">
                            <span className="animate-pulse">Thinking...</span>
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-4 border-t border-gray-700">
                <div className="flex gap-2">
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Ask about the findings..."
                        className="flex-1 bg-gray-800 text-white rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        disabled={isLoading}
                    />
                    <button
                        onClick={() => handleSend()}
                        disabled={isLoading || !input.trim()}
                        className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                        Send
                    </button>
                </div>
            </div>
        </div>
    );
}

