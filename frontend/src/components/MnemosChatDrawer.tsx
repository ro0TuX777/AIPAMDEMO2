import { useEffect, useRef, useState } from "react";
import { ChatPanel, type ChatSendTarget } from "./ChatPanel";
import type { ChatComparisonBranch, ChatComparisonGroup, ChatConversation, HistoricalFindingCitation } from "./chatTypes";

interface MnemosChatDrawerProps {
  jobId: string;
  group: ChatComparisonGroup;
  activeBranch: ChatComparisonBranch;
  conversation: ChatConversation;
  draft: string;
  onDraftChange: (value: string) => void;
  onClose: () => void;
  onBranchChange: (branchId: string) => void;
  onBeforeSend: (message: string, requestId: string) => Promise<ChatSendTarget | undefined>;
  onConversationChanged: (conversation: ChatConversation) => void;
  onTurnComplete: (conversationId: string) => void;
  onRetry: (requestId: string) => void;
  returnFocusRef: React.RefObject<HTMLButtonElement>;
}

const retrievalStatus = (conversation: ChatConversation) => {
  const assistant = [...conversation.messages].reverse().find(message => message.role === "assistant");
  const status = assistant?.metadata?.retrieval_status;
  return typeof status === "string" ? status : null;
};

const historicalSources = (conversation: ChatConversation): HistoricalFindingCitation[] => conversation.messages
  .flatMap(message => message.citations)
  .filter((citation): citation is HistoricalFindingCitation => citation.type === "historical_finding");

export function MnemosChatDrawer({
  jobId, group, activeBranch, conversation, draft, onDraftChange, onClose, onBranchChange,
  onBeforeSend, onConversationChanged, onTurnComplete, onRetry, returnFocusRef,
}: MnemosChatDrawerProps) {
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const [mobile, setMobile] = useState(() => window.matchMedia("(max-width: 767px)").matches);
  const status = retrievalStatus(conversation);
  const sources = historicalSources(conversation);

  useEffect(() => {
    closeButtonRef.current?.focus();
    return () => returnFocusRef.current?.focus();
  }, [returnFocusRef]);

  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const update = () => setMobile(media.matches);
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    if (!mobile) return;
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [mobile, onClose]);

  return (
    <aside role={mobile ? "dialog" : "complementary"} aria-modal={mobile || undefined} aria-label="MNEMOS comparison" className="fixed inset-y-0 right-0 z-40 flex w-full max-w-lg flex-col border-l border-slate-700 bg-slate-950 shadow-2xl md:static md:h-full md:w-[28rem] md:rounded-lg md:border">
      <div className="flex items-center justify-between border-b border-slate-700 px-4 py-3">
        <div>
          <h2 className="font-semibold text-slate-100">MNEMOS comparison</h2>
          <p className="text-xs text-slate-400">Historical context is kept separate from the baseline chat.</p>
        </div>
        <button ref={closeButtonRef} type="button" onClick={onClose} aria-label="Close MNEMOS comparison" className="rounded px-2 py-1 text-slate-300 hover:bg-slate-800">×</button>
      </div>

      <div className="border-b border-slate-800 px-4 py-3">
        <label className="block text-xs text-slate-400" htmlFor="mnemos-branch">Comparison branch</label>
        <select id="mnemos-branch" value={activeBranch.id} onChange={event => onBranchChange(event.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100">
          {group.branches.map(branch => <option key={branch.id} value={branch.id}>{branch.label}</option>)}
        </select>
      </div>

      {activeBranch.source_message_id && <p className="mx-4 mt-3 text-xs text-cyan-200">Copied from baseline message {activeBranch.source_message_id}</p>}
      {(activeBranch.inherited_messages?.length ?? 0) > 0 && <section className="mx-4 mt-3 rounded border border-slate-700 bg-slate-900/60 p-3" aria-label="Baseline history">
        <h3 className="text-sm font-medium text-slate-100">Baseline history</h3>
        <div className="mt-2 space-y-2 text-xs text-slate-300">
          {activeBranch.inherited_messages?.map(message => <p key={message.id}><span className="mr-2 uppercase text-slate-500">{message.role}</span>{message.content}</p>)}
        </div>
      </section>}

      {status === "used" && <div className="mx-4 mt-3 rounded border border-emerald-800 bg-emerald-950/40 px-3 py-2 text-sm text-emerald-200">Historical confirmed findings used</div>}
      {status === "no_matches" && <div className="mx-4 mt-3 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300">No relevant historical confirmed findings found</div>}
      {(status === "unavailable" || status === "error") && <div className="mx-4 mt-3 rounded border border-amber-800 bg-amber-950/40 px-3 py-2 text-sm text-amber-200">MNEMOS is unavailable. Try again.</div>}

      {sources.length > 0 && <section className="mx-4 mt-3 rounded border border-slate-700 bg-slate-900/60 p-3" aria-label="Historical confirmed findings">
        <h3 className="text-sm font-medium text-slate-100">Historical confirmed findings</h3>
        <ul className="mt-2 space-y-2">
          {sources.map(source => <li key={`${source.source_job_id}-${source.id}`} className="text-xs text-slate-300"><a className="text-cyan-300 underline" href={source.href}>{source.snippet || source.id}</a><span className="ml-2 text-slate-500">Job {source.source_job_id}{source.source_project_id ? ` · Project ${source.source_project_id}` : ""}</span></li>)}
        </ul>
      </section>}

      <div className="min-h-0 flex-1 p-4">
        <ChatPanel
          jobId={jobId}
          conversation={conversation}
          selectionToken={activeBranch.id}
          mode="mnemos"
          inputValue={draft}
          onInputChange={onDraftChange}
          inputLabel="MNEMOS message"
          sendLabel="Send to MNEMOS"
          onBeforeSend={onBeforeSend}
          onConversationChanged={onConversationChanged}
          onTurnComplete={onTurnComplete}
          onCopyToMnemos={() => {}}
          onRetry={onRetry}
        />
      </div>
    </aside>
  );
}
