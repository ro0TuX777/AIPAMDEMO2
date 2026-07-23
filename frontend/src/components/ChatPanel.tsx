import { useState, useRef, useEffect, useCallback } from "react";
import { api, ChatResponse, ChatCitation, ChatEvidenceRef, ConversationSummary, setApiToken } from "../api";

interface ChatMessage {
    role: "user" | "assistant";
    content: string;
    citations?: ChatCitation[];
    evidence_refs?: ChatEvidenceRef[];
    suggested_followups?: string[];
    timestamp: Date;
}

interface ChatPanelProps {
    jobId: string;
    /** Auto-sent as the first message on mount (e.g. the ?ask= value). */
    initialMessage?: string;
    /** Scope hint passed as context_hint on every request (e.g. "finding:F-101"). */
    contextHint?: string;
    onClose?: () => void;
}

export function ChatPanel({ jobId, initialMessage, contextHint, onClose }: ChatPanelProps) {
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [input, setInput] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [isLoadingHistory, setIsLoadingHistory] = useState(true);
    const [conversationId, setConversationId] = useState<string | undefined>();
    const [conversations, setConversations] = useState<ConversationSummary[]>([]);
    const [isEditingTitle, setIsEditingTitle] = useState(false);
    const [newTitle, setNewTitle] = useState("");
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const initialContextHandled = useRef(false);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

    // Load existing conversations on mount
    useEffect(() => {
        const loadConversations = async () => {
            try {
                const convs = await api.listConversations(jobId);
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
            const history = await api.getConversation(jobId, convId);
            setConversationId(history.id);
            setMessages(
                history.messages.map((m: any) => ({
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

    const refreshConversations = async () => {
        try {
            const convs = await api.listConversations(jobId);
            setConversations(convs);
        } catch (error) {
            console.error("Failed to refresh conversations:", error);
        }
    };

    const handleRenameConv = async () => {
        if (!conversationId || !newTitle.trim()) return;
        try {
            await api.renameConversation(jobId, conversationId, newTitle.trim());
            setIsEditingTitle(false);
            await refreshConversations();
        } catch (error) {
            console.error("Failed to rename conversation:", error);
        }
    };

    const handleDeleteConv = async () => {
        if (!conversationId) return;
        if (!confirm("Are you sure you want to delete this conversation?")) return;
        try {
            await api.deleteConversation(jobId, conversationId);
            startNewConversation();
            await refreshConversations();
        } catch (error) {
            console.error("Failed to delete conversation:", error);
        }
    };

    // If initialMessage is provided, send it as a message (only once per mount)
    useEffect(() => {
        if (initialMessage && !isLoadingHistory && !initialContextHandled.current) {
            initialContextHandled.current = true;
            handleSend(initialMessage);
        }
    }, [initialMessage, isLoadingHistory]);

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

        // Add a placeholder assistant message that we'll update with streamed tokens
        const placeholderMsg: ChatMessage = {
            role: "assistant",
            content: "",
            timestamp: new Date(),
        };
        setMessages((prev) => [...prev, placeholderMsg]);

        try {
            const API_BASE =
                (import.meta as any).env?.VITE_API_BASE_URL?.replace(/\/$/, "") ||
                "http://localhost:8000/api/v1";
            const token = localStorage.getItem("aipam_token") || "";

            const resp = await fetch(`${API_BASE}/jobs/${jobId}/chat/stream`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                },
                body: JSON.stringify({
                    message: text,
                    conversation_id: conversationId,
                    context_hint: contextHint,
                }),
            });

            if (!resp.ok) {
                throw new Error(`HTTP ${resp.status}`);
            }

            const reader = resp.body?.getReader();
            if (!reader) throw new Error("No readable stream");

            const decoder = new TextDecoder();
            let accumulated = "";
            let buffer = "";

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });
                const parts = buffer.split("\n\n");
                buffer = parts.pop() || "";

                for (const eventStr of parts) {
                    const lines = eventStr.split("\n");
                    for (const line of lines) {
                        if (!line.startsWith("data: ")) continue;
                        const payload = line.slice(6).trim();
                        if (payload === "[DONE]") continue;

                        try {
                            const evt = JSON.parse(payload);
                            if (evt.type === "meta" || evt.conversation_id) {
                                setConversationId(evt.conversation_id);
                                if (evt.citations || evt.evidence_refs || evt.suggested_followups) {
                                    setMessages((prev) => {
                                        const updated = [...prev];
                                        const last = updated[updated.length - 1];
                                        if (last && last.role === "assistant") {
                                            updated[updated.length - 1] = {
                                                ...last,
                                                ...(evt.citations ? { citations: evt.citations } : {}),
                                                ...(evt.evidence_refs ? { evidence_refs: evt.evidence_refs } : {}),
                                                ...(evt.suggested_followups ? { suggested_followups: evt.suggested_followups } : {}),
                                            };
                                        }
                                        return updated;
                                    });
                                }
                            } else if (evt.type === "token") {
                                accumulated += evt.content || "";
                                const current = accumulated;
                                setMessages((prev) => {
                                    const updated = [...prev];
                                    const last = updated[updated.length - 1];
                                    if (last && last.role === "assistant") {
                                        updated[updated.length - 1] = { ...last, content: current };
                                    }
                                    return updated;
                                });
                            } else if (evt.type === "replace") {
                                // Backend rewrote the response during finalize; swap content.
                                accumulated = evt.content || "";
                                const current = accumulated;
                                setMessages((prev) => {
                                    const updated = [...prev];
                                    const last = updated[updated.length - 1];
                                    if (last && last.role === "assistant") {
                                        updated[updated.length - 1] = { ...last, content: current };
                                    }
                                    return updated;
                                });
                            } else if (evt.type === "error") {
                                accumulated += "\n\nError: " + (evt.content || evt.error || "Unknown error");
                                const current = accumulated;
                                setMessages((prev) => {
                                    const updated = [...prev];
                                    const last = updated[updated.length - 1];
                                    if (last && last.role === "assistant") {
                                        updated[updated.length - 1] = { ...last, content: current };
                                    }
                                    return updated;
                                });
                            }
                        } catch (e) {
                            // skip unparseable lines
                            console.warn("Failed to parse SSE payload", payload, e);
                        }
                    }
                }
            }
        } catch (error) {
            // If streaming fails entirely, fall back to non-streaming
            try {
                const response: ChatResponse = await api.chatWithJob(jobId, {
                    message: text,
                    conversation_id: conversationId,
                    context_hint: contextHint,
                });
                setConversationId(response.conversation_id);
                setMessages((prev) => {
                    const updated = [...prev];
                    const last = updated[updated.length - 1];
                    if (last && last.role === "assistant") {
                        updated[updated.length - 1] = {
                            ...last,
                            content: response.response,
                            citations: response.citations,
                            evidence_refs: response.evidence_refs,
                            suggested_followups: response.suggested_followups,
                        };
                    }
                    return updated;
                });
            } catch (fallbackError) {
                setMessages((prev) => {
                    const updated = [...prev];
                    const last = updated[updated.length - 1];
                    if (last && last.role === "assistant") {
                        updated[updated.length - 1] = {
                            ...last,
                            content: `Error: ${fallbackError instanceof Error ? fallbackError.message : "Failed to get response"}`,
                        };
                    }
                    return updated;
                });
            }
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
                lines.push(`## User (${timestamp})`);
                lines.push(``);
                lines.push(msg.content);
            } else {
                lines.push(`## Assistant (${timestamp})`);
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
        <div className="flex flex-col h-full bg-slate-900 rounded-lg border border-slate-700">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                <div className="flex-1 flex items-center gap-2">
                    {isEditingTitle ? (
                        <div className="flex items-center gap-2 flex-1">
                            <input
                                type="text"
                                value={newTitle}
                                onChange={(e) => setNewTitle(e.target.value)}
                                className="bg-slate-800 text-slate-100 text-sm rounded px-2 py-1 outline-none ring-1 ring-blue-500 flex-1"
                                autoFocus
                                onKeyDown={(e) => {
                                    if (e.key === "Enter") handleRenameConv();
                                    if (e.key === "Escape") setIsEditingTitle(false);
                                }}
                            />
                            <button onClick={handleRenameConv} className="text-emerald-400 hover:text-emerald-300">✓</button>
                            <button onClick={() => setIsEditingTitle(false)} className="text-red-400 hover:text-red-300">✕</button>
                        </div>
                    ) : (
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                            <select
                                value={conversationId || ""}
                                onChange={(e) => e.target.value ? loadConversation(e.target.value) : startNewConversation()}
                                className="bg-transparent text-slate-100 font-semibold focus:outline-none cursor-pointer max-w-full truncate"
                            >
                                <option value="" className="bg-slate-900 text-slate-400">New Conversation</option>
                                {conversations.map(c => (
                                    <option key={c.id} value={c.id} className="bg-slate-900">
                                        {c.title || `Chat ${c.id.slice(0, 4)}...`}
                                    </option>
                                ))}
                            </select>
                            {conversationId && (
                                <>
                                    <button
                                        onClick={() => {
                                            const current = conversations.find(c => c.id === conversationId);
                                            setNewTitle(current?.title || "");
                                            setIsEditingTitle(true);
                                        }}
                                        className="text-slate-500 hover:text-slate-300 transition-colors"
                                        title="Rename conversation"
                                    >
                                        ✎
                                    </button>
                                    <button
                                        onClick={handleDeleteConv}
                                        className="text-slate-500 hover:text-red-400 transition-colors"
                                        title="Delete conversation"
                                    >
                                        Del
                                    </button>
                                </>
                            )}
                        </div>
                    )}
                </div>
                <div className="flex items-center gap-2">
                    {messages.length > 0 && (
                        <>
                            <button
                                onClick={startNewConversation}
                                className="text-slate-400 hover:text-slate-50 transition-colors text-sm px-2 py-1 rounded hover:bg-slate-700"
                                title="Start new conversation"
                            >
                                + New
                            </button>
                            <button
                                onClick={exportToMarkdown}
                                className="text-slate-400 hover:text-slate-50 transition-colors text-sm px-2 py-1 rounded hover:bg-slate-700"
                                title="Export chat to Markdown"
                            >
                                Export
                            </button>
                        </>
                    )}
                    {onClose && (
                        <button
                            onClick={onClose}
                            className="text-slate-400 hover:text-slate-50 transition-colors"
                        >
                            ✕
                        </button>
                    )}
                </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {isLoadingHistory ? (
                    <div className="text-slate-500 text-center py-8">
                        <span className="animate-pulse">Loading conversation history...</span>
                    </div>
                ) : messages.length === 0 ? (
                    <div className="text-slate-500 text-center py-8">
                        <p className="text-base mb-4">Ask questions about this PCAP analysis</p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-xl mx-auto text-left">
                            {[
                                { icon: "•", text: "Summarize the key findings and their severity" },
                                { icon: "•", text: "What are the highest-severity alerts and which hosts triggered them?" },
                                { icon: "•", text: "Check for signs of lateral movement between internal hosts" },
                                { icon: "•", text: "Identify any command-and-control (C2) communication patterns" },
                                { icon: "•", text: "Is there evidence of data exfiltration?" },
                                { icon: "•", text: "Which hosts have the most suspicious activity?" },
                            ].map((q) => (
                                <button
                                    key={q.text}
                                    onClick={() => handleSend(q.text)}
                                    disabled={isLoading}
                                    className="flex items-start gap-2 px-3 py-2 rounded-lg border border-slate-700 bg-slate-800/50 hover:bg-slate-700/60 hover:border-slate-600 text-slate-300 hover:text-slate-50 text-xs transition-colors text-left disabled:opacity-50"
                                >
                                    <span className="shrink-0 mt-0.5">{q.icon}</span>
                                    <span>{q.text}</span>
                                </button>
                            ))}
                        </div>
                    </div>
                ) : null}
                {messages.map((msg, idx) => (
                    <div
                        key={idx}
                        className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                    >
                        <div
                            className={`max-w-[80%] rounded-lg px-4 py-2 ${msg.role === "user"
                                ? "bg-blue-600 text-white"
                                : "bg-slate-800 text-slate-100"
                                }`}
                        >
                            <p className="whitespace-pre-wrap">{msg.content}</p>
                            {msg.citations && msg.citations.length > 0 && (
                                <div className="mt-3 pt-2 border-t border-slate-600">
                                    <details className="group">
                                        <summary className="flex cursor-pointer list-none items-center gap-2 text-xs text-slate-300 hover:text-slate-50">
                                            <span className="font-medium">Sources</span>
                                            <span className="text-slate-500">({msg.citations.length})</span>
                                            <span className="text-slate-500 group-open:hidden">Show</span>
                                            <span className="hidden text-slate-500 group-open:inline">Hide</span>
                                        </summary>
                                        <div className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1">
                                            {msg.citations.map((c, i) => (
                                                <div key={`${c.type}-${c.id ?? i}-${i}`} className="rounded-md border border-slate-700 bg-slate-900/60 px-2 py-2">
                                                    <p className="text-[11px] uppercase tracking-wide text-slate-500">
                                                        {c.type.replace(/_/g, " ")}
                                                    </p>
                                                    <p className="mt-1 whitespace-pre-wrap break-words text-xs text-slate-300">
                                                        {c.snippet}
                                                    </p>
                                                </div>
                                            ))}
                                        </div>
                                    </details>
                                </div>
                            )}
                            {/* Follow-up suggestions */}
                            {msg.role === "assistant" && msg.suggested_followups && msg.suggested_followups.length > 0 && !isLoading && (
                                <div className="mt-3 pt-2 border-t border-slate-700">
                                    <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5">Follow-up questions</p>
                                    <div className="flex flex-wrap gap-1.5">
                                        {msg.suggested_followups.map((q, i) => (
                                            <button
                                                key={i}
                                                onClick={() => handleSend(q)}
                                                disabled={isLoading}
                                                className="text-left text-xs px-2 py-1 rounded border border-slate-700 bg-slate-900/60 text-emerald-400/80 hover:text-emerald-300 hover:border-emerald-500/30 hover:bg-slate-800/80 transition-colors disabled:opacity-50"
                                            >
                                                {q}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                ))}
                {isLoading && messages.length > 0 && messages[messages.length - 1].content === "" && (
                    <div className="flex justify-start">
                        <div className="bg-slate-800 rounded-lg px-4 py-2 text-slate-400">
                            <span className="animate-pulse">Thinking...</span>
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-4 border-t border-slate-700">
                <div className="flex gap-2">
                    <input
                        type="text"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Ask about the findings..."
                        className="flex-1 bg-slate-800 text-slate-100 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
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

