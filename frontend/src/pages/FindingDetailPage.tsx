import React, { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { api, ApiError, type FindingExplainFeedback, type FindingExplainSection } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { CardGridSkeleton } from "../components/SkeletonLoader";
import { useToast } from "../components/ToastProvider";
import {
  EXPLAIN_FORMAT_LABELS,
  EXPLAIN_MODE_DESCRIPTIONS,
  EXPLAIN_MODE_LABELS,
  EXPLAIN_SOURCE_DESCRIPTIONS,
  EXPLAIN_SOURCE_LABELS,
  type ExplainFormat,
  type ExplainState,
  buildExplainCitationButtonTestId,
  buildExplainClipboardText,
  buildExplainEvidenceTargetId,
  buildExplainEvidenceTestId,
  buildExplainMarkdownFilename,
  buildExplainMarkdownText,
  formatExplainDuration,
  formatExplainUpdatedAt,
  getCachedFindingExplainState,
  getExplainRetryAfterSeconds,
  getExplainRetryMessage,
  hasExplainContent,
  setCachedFindingExplainState,
} from "../findingsExplain";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-amber-400 bg-amber-400/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-slate-400 bg-slate-400/10",
};

function ConfidenceBadge({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    value >= 0.7
      ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
      : value >= 0.4
        ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
        : "text-red-400 bg-red-500/10 border-red-500/20";

  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${color}`} title={`Confidence: ${pct}%`}>
      {pct}% confidence
    </span>
  );
}

const renderExplainSection = (
  section: FindingExplainSection,
  options: {
    findingId: string;
    actionableCitations: Set<string>;
    onCitationClick: (citation: string) => void;
  },
) => (
  <section key={section.id} className="space-y-2">
    <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">{section.title}</h4>
    {section.body && <p className="text-sm leading-6 text-slate-300">{section.body}</p>}
    {section.bullets.length > 0 && (
      <ul className="space-y-2">
        {section.bullets.map((bullet) => (
          <li key={bullet} className="flex items-start gap-2 text-sm leading-6 text-slate-300">
            <span className="mt-1 text-slate-500">•</span>
            <span>{bullet}</span>
          </li>
        ))}
      </ul>
    )}
    {section.citations.length > 0 && (
      <div className="flex flex-wrap gap-1.5 pt-1">
        {section.citations.map((citation) => {
          const actionable = options.actionableCitations.has(citation);
          if (!actionable) {
            return (
              <span key={`${section.id}:${citation}`} className="rounded border border-slate-800 bg-slate-900/60 px-1.5 py-0.5 text-[10px] font-mono text-slate-500">
                {citation}
              </span>
            );
          }

          return (
            <button
              key={`${section.id}:${citation}`}
              type="button"
              onClick={() => options.onCitationClick(citation)}
              data-testid={buildExplainCitationButtonTestId(options.findingId, citation)}
              className="rounded border border-cyan-500/20 bg-cyan-500/10 px-1.5 py-0.5 text-[10px] font-mono text-cyan-300 transition-colors hover:border-cyan-400/40 hover:bg-cyan-500/15"
            >
              {citation}
            </button>
          );
        })}
      </div>
    )}
  </section>
);

const formatDateTime = (value?: string | null) => {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
};

export const FindingDetailPage: React.FC = () => {
  const { jobId, findingId } = useParams<{ jobId: string; findingId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const [retryClockMs, setRetryClockMs] = useState(() => Date.now());
  const [explainState, setExplainState] = useState<ExplainState | undefined>(() =>
    jobId && findingId ? getCachedFindingExplainState(queryClient, jobId, findingId) : undefined,
  );

  const { data: finding, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "finding", findingId],
    queryFn: () => api.getFinding(jobId!, findingId!),
    enabled: !!jobId && !!findingId,
  });
  const { data: systemConfig } = useQuery({
    queryKey: ["system", "config"],
    queryFn: () => api.getSystemConfig(),
  });

  useEffect(() => {
    if (!jobId || !findingId) {
      setExplainState(undefined);
      return;
    }
    setExplainState(getCachedFindingExplainState(queryClient, jobId, findingId));
  }, [findingId, jobId, queryClient]);

  const updateExplainState = (updater: (prev: ExplainState | undefined) => ExplainState) => {
    setExplainState((prev) => {
      const next = updater(prev);
      if (jobId && findingId) {
        setCachedFindingExplainState(queryClient, jobId, findingId, next);
      }
      return next;
    });
  };

  const feedbackMut = useMutation({
    mutationFn: (val: string | null) => api.updateFindingFeedback(jobId!, findingId!, val),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] });
      queryClient.setQueryData(["job", jobId, "finding", findingId], (prev: any) =>
        prev ? { ...prev, feedback: result.feedback } : prev,
      );
      addToast({ severity: "info", title: "Feedback saved", duration: 3000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to save feedback" }),
  });

  const explainFeedbackMut = useMutation({
    mutationFn: (val: FindingExplainFeedback | null) => api.updateFindingExplainFeedback(jobId!, findingId!, val),
    onSuccess: (result) => {
      updateExplainState((prev) => ({
        ...(prev ?? {}),
        explanation_feedback: result.explanation_feedback,
        feedback_error: undefined,
      }));
      queryClient.setQueryData(["job", jobId, "finding", findingId], (prev: any) =>
        prev ? { ...prev, explanation_feedback: result.explanation_feedback } : prev,
      );
    },
    onError: (err) => {
      updateExplainState((prev) => ({
        ...(prev ?? {}),
        feedback_error: err instanceof Error ? err.message : "Failed to save explanation feedback.",
      }));
    },
  });

  const requestExplain = async (options?: { force?: boolean; format?: ExplainFormat }) => {
    if (!jobId || !findingId) return;

    const existing = explainState;
    const requestedFormat = options?.format ?? existing?.format ?? "markdown";
    if (existing?.loading) return;
    if (!options?.force && existing?.content) return;

    updateExplainState((prev) => ({
      ...(prev ?? {}),
      loading: true,
      error: undefined,
      retry_status: undefined,
      retry_at_ms: undefined,
      copy_status: undefined,
      download_status: undefined,
      highlighted_citation: undefined,
      feedback_error: undefined,
      format: requestedFormat,
    }));

    try {
      const result = await api.explainFinding(jobId, findingId, { format: requestedFormat });
      updateExplainState((prev) => ({
        ...(prev ?? {}),
        loading: false,
        error: undefined,
        retry_status: undefined,
        retry_at_ms: undefined,
        content: result.content,
        format: result.format,
        source: result.source,
        duration_ms: result.duration_ms,
        updated_at: new Date().toISOString(),
        copy_status: undefined,
        download_status: undefined,
        highlighted_citation: undefined,
        warning: result.warning,
        explanation_feedback: result.explanation_feedback,
        feedback_error: undefined,
        sections: result.sections,
        evidence_items: result.evidence_items,
      }));
    } catch (err) {
      updateExplainState((prev) => ({
        ...(prev ?? {}),
        loading: false,
        error:
          err instanceof ApiError && (err.status === 429 || err.status === 503)
            ? undefined
            : err instanceof Error
              ? err.message
              : "Failed to explain finding.",
        retry_status:
          err instanceof ApiError && (err.status === 429 || err.status === 503)
            ? err.status as 429 | 503
            : undefined,
        retry_at_ms:
          err instanceof ApiError && (err.status === 429 || err.status === 503)
            ? Date.now() + getExplainRetryAfterSeconds(err) * 1000
            : undefined,
      }));
    }
  };

  useEffect(() => {
    if (explainState?.loading || typeof explainState?.retry_at_ms !== "number") {
      return undefined;
    }

    const retryDelayMs = Math.max(0, explainState.retry_at_ms - Date.now());
    const timerId = window.setTimeout(() => {
      void requestExplain({ force: true, format: explainState.format ?? "markdown" });
    }, retryDelayMs);

    return () => window.clearTimeout(timerId);
  }, [explainState?.format, explainState?.loading, explainState?.retry_at_ms]);

  useEffect(() => {
    if (explainState?.loading || typeof explainState?.retry_at_ms !== "number") {
      return undefined;
    }
    setRetryClockMs(Date.now());
    const intervalId = window.setInterval(() => setRetryClockMs(Date.now()), 250);
    return () => window.clearInterval(intervalId);
  }, [explainState?.loading, explainState?.retry_at_ms]);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <CardGridSkeleton count={4} />
      </div>
    );
  }

  if (error || !finding) {
    return <p className="text-red-400">Failed to load finding detail.</p>;
  }

  const currentExplainFormat = explainState?.format ?? "markdown";
  const explainMode = systemConfig?.explain_configuration?.mode;
  const explainModeLabel = explainMode ? EXPLAIN_MODE_LABELS[explainMode] : null;
  const explainModeDescription = explainMode ? EXPLAIN_MODE_DESCRIPTIONS[explainMode] : null;
  const explainModelName = systemConfig?.explain_configuration?.llm_model_name ?? null;
  const explainRetryMessage = getExplainRetryMessage(explainState, retryClockMs);
  const explainFeedbackSaving = explainFeedbackMut.isPending;
  const explainEvidenceTargetIndexByCitation = new Map<string, number>();
  for (const [index, item] of (explainState?.evidence_items ?? []).entries()) {
    if (!explainEvidenceTargetIndexByCitation.has(item.citation)) {
      explainEvidenceTargetIndexByCitation.set(item.citation, index);
    }
  }
  const explainEvidenceCitations = new Set(explainEvidenceTargetIndexByCitation.keys());
  const highlightedExplainCitation = explainState?.highlighted_citation;

  const handleExplainCopy = async () => {
    if (!hasExplainContent(explainState)) return;
    try {
      await navigator.clipboard.writeText(buildExplainClipboardText(finding, explainState!));
      updateExplainState((prev) => ({ ...(prev ?? {}), copy_status: "copied" }));
    } catch {
      updateExplainState((prev) => ({ ...(prev ?? {}), copy_status: "error" }));
    }
  };

  const handleExplainDownload = async () => {
    if (!hasExplainContent(explainState)) return;
    try {
      const markdown = buildExplainMarkdownText(finding, explainState!);
      const blob = new Blob([markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = buildExplainMarkdownFilename(finding);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      updateExplainState((prev) => ({ ...(prev ?? {}), download_status: "downloaded" }));
    } catch {
      updateExplainState((prev) => ({ ...(prev ?? {}), download_status: "error" }));
    }
  };

  const handleExplainCitationJump = (citation: string) => {
    const target = document.getElementById(buildExplainEvidenceTargetId(finding.finding_id, citation));
    if (!(target instanceof HTMLElement)) return;

    updateExplainState((prev) => ({ ...(prev ?? {}), highlighted_citation: citation }));
    target.scrollIntoView({ behavior: "smooth", block: "nearest" });
    target.focus({ preventScroll: true });
  };

  return (
    <div className="flex gap-6 items-start">
      <div className="space-y-6 flex-1 min-w-0">
        <nav className="text-sm text-slate-400">
          <Link to="/jobs" className="hover:text-white">Jobs</Link>
          <span className="mx-1">/</span>
          <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
          <span className="mx-1">/</span>
          <Link to={`/jobs/${jobId}/findings`} className="hover:text-white">Findings</Link>
          <span className="mx-1">/</span>
          <span className="text-slate-200">{finding.title.slice(0, 60)}</span>
        </nav>

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLORS[finding.severity] ?? SEV_COLORS.info}`}>
                {finding.severity.toUpperCase()}
              </span>
              {finding.category && (
                <span className="px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                  {finding.category}
                </span>
              )}
              <ConfidenceBadge value={finding.confidence} />
            </div>
            <h1 className={`text-2xl font-semibold ${labelHint("finding_detail", activeHelpField)}`} onClick={() => toggleHelp("finding_detail")}>
              {finding.title}
            </h1>
            {finding.summary && <p className="max-w-3xl text-sm leading-6 text-slate-400">{finding.summary}</p>}
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <Link
              to={`/jobs/${jobId}/findings`}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-300 transition-colors hover:border-slate-600 hover:text-white"
            >
              Back to queue
            </Link>
            <button
              onClick={() => navigate(`/jobs/${jobId}/chat?ask=${encodeURIComponent(`Analyze finding "${finding.title}" (severity: ${finding.severity}). ${finding.summary ? finding.summary + " " : ""}What does this mean, what is the impact, and what should an analyst do next?`)}&hint=${encodeURIComponent(`finding:${finding.finding_id}`)}`)}
              className="rounded-lg border border-emerald-500/30 bg-emerald-600/20 px-3 py-2 text-sm text-emerald-400 transition-colors hover:bg-emerald-600/30 hover:text-emerald-300"
            >
              Ask AI
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3 rounded-lg border border-slate-800 bg-slate-900/40 p-4">
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Finding ID</div>
            <div className="mt-1 font-mono text-sm text-slate-200">{finding.finding_id}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Sensor</div>
            <div className="mt-1 text-sm text-slate-200">{finding.sensor ?? "—"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">PCAP label</div>
            <div className="mt-1 text-sm text-slate-200">{finding.pcap_label ?? "—"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Community ID</div>
            <div className="mt-1 font-mono text-sm text-slate-200">{finding.community_id ?? "—"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Analyst disposition</div>
            <div className="mt-1 text-sm text-slate-200">{finding.feedback ?? "unreviewed"}</div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Related pivots</div>
            <div className="mt-1 text-sm text-slate-200">
              {finding.related_hosts.length} hosts · {finding.related_alerts.length} alerts · {finding.related_connections.length} flows
            </div>
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => feedbackMut.mutate("confirmed")}
            disabled={feedbackMut.isPending}
            className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-colors border ${finding.feedback === "confirmed"
              ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
              : "bg-slate-800 border-slate-700 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/30"
              }`}
          >
            {finding.feedback === "confirmed" ? "✓ Confirmed" : "Confirm"}
          </button>
          <button
            onClick={() => feedbackMut.mutate("false_positive")}
            disabled={feedbackMut.isPending}
            className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-colors border ${finding.feedback === "false_positive"
              ? "bg-red-500/20 border-red-500/50 text-red-400"
              : "bg-slate-800 border-slate-700 text-slate-400 hover:text-red-400 hover:border-red-500/30"
              }`}
          >
            {finding.feedback === "false_positive" ? "✗ False positive" : "Mark FP"}
          </button>
        </div>

        <section className="rounded-lg border border-slate-800 bg-slate-950/70 p-4 space-y-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div>
              <h2 className="text-sm font-semibold text-cyan-300">Grounded explanation</h2>
              <p className="mt-1 text-xs text-slate-500">Use Quick Look in the queue for triage, and this panel for full investigation context.</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <div className="flex items-center gap-1 rounded border border-slate-800 bg-slate-900/60 p-1">
                {(Object.keys(EXPLAIN_FORMAT_LABELS) as ExplainFormat[]).map((format) => (
                  <button
                    key={format}
                    onClick={() => void requestExplain({ force: true, format })}
                    disabled={Boolean(explainState?.loading) || currentExplainFormat === format}
                    className={`rounded px-2 py-1 text-[10px] font-bold uppercase tracking-wider transition-colors ${currentExplainFormat === format
                      ? "bg-cyan-500/20 text-cyan-300"
                      : "text-slate-500 hover:text-cyan-300"
                      } disabled:cursor-default disabled:opacity-100`}
                  >
                    {EXPLAIN_FORMAT_LABELS[format]}
                  </button>
                ))}
              </div>
              {hasExplainContent(explainState) && !explainState?.loading && (
                <button onClick={() => void handleExplainCopy()} className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 hover:border-cyan-500/30 hover:text-cyan-300">
                  Copy
                </button>
              )}
              {hasExplainContent(explainState) && !explainState?.loading && (
                <button onClick={() => void handleExplainDownload()} className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 hover:border-cyan-500/30 hover:text-cyan-300">
                  Download
                </button>
              )}
              <button
                onClick={() => void requestExplain({ force: hasExplainContent(explainState), format: currentExplainFormat })}
                className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 hover:border-cyan-500/30 hover:text-cyan-300"
              >
                {hasExplainContent(explainState) ? "Regenerate" : "Generate"}
              </button>
            </div>
          </div>

          {explainModeLabel && (
            <div className="rounded border border-slate-800 bg-slate-900/40 px-3 py-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Explain runtime</span>
                <span className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${explainMode === "llm"
                  ? "bg-violet-500/15 text-violet-300 border border-violet-500/20"
                  : "bg-slate-800 text-slate-300 border border-slate-700"
                  }`}>
                  {explainModeLabel}
                </span>
                {explainMode === "llm" && explainModelName && (
                  <span className="text-[11px] text-slate-400">Model: <span className="font-mono text-slate-300">{explainModelName}</span></span>
                )}
              </div>
              {explainModeDescription && <p className="mt-2 text-[11px] leading-5 text-slate-400">{explainModeDescription}</p>}
              {explainState?.source && <p className="mt-1 text-[11px] leading-5 text-slate-500">{EXPLAIN_SOURCE_LABELS[explainState.source]} — {EXPLAIN_SOURCE_DESCRIPTIONS[explainState.source]}</p>}
            </div>
          )}

          {(explainState?.updated_at || typeof explainState?.duration_ms === "number") && (
            <p className="text-[11px] leading-5 text-slate-500">
              {explainState?.updated_at && (
                <>
                  Updated: <time className="text-slate-400" dateTime={explainState.updated_at}>{formatExplainUpdatedAt(explainState.updated_at)}</time>
                </>
              )}
              {explainState?.updated_at && typeof explainState?.duration_ms === "number" && <span className="px-1.5">·</span>}
              {typeof explainState?.duration_ms === "number" && <><span>Duration: </span><span className="text-slate-400">{formatExplainDuration(explainState.duration_ms)}</span></>}
            </p>
          )}

          {explainState?.copy_status && <p className={`text-xs ${explainState.copy_status === "copied" ? "text-emerald-400" : "text-red-400"}`}>{explainState.copy_status === "copied" ? "Copied explanation bundle to clipboard." : "Failed to copy explanation bundle."}</p>}
          {explainState?.download_status && <p className={`text-xs ${explainState.download_status === "downloaded" ? "text-emerald-400" : "text-red-400"}`}>{explainState.download_status === "downloaded" ? "Downloaded explanation markdown." : "Failed to download explanation markdown."}</p>}
          {explainState?.loading && <p className="text-sm text-slate-400 animate-pulse">{hasExplainContent(explainState) ? `Regenerating ${EXPLAIN_FORMAT_LABELS[currentExplainFormat].toLowerCase()} grounded explanation…` : `Generating ${EXPLAIN_FORMAT_LABELS[currentExplainFormat].toLowerCase()} grounded explanation…`}</p>}
          {explainState?.warning && <p className="text-sm text-amber-300">{explainState.warning}</p>}
          {explainRetryMessage && <p className="text-sm text-amber-300">{explainRetryMessage}</p>}
          {explainState?.error && <p className="text-sm text-red-400">{explainState.error}</p>}

          {!explainState?.loading && hasExplainContent(explainState) && (
            <section className="space-y-3 rounded border border-slate-800 bg-slate-900/40 p-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Analyst feedback</h3>
                {explainFeedbackSaving && <span className="text-[10px] text-slate-500">Saving…</span>}
              </div>
              <div className="flex flex-wrap gap-1.5">
                <button
                  onClick={() => explainFeedbackMut.mutate(explainState?.explanation_feedback === "useful" ? null : "useful")}
                  disabled={explainFeedbackSaving}
                  className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${explainState?.explanation_feedback === "useful"
                    ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
                    : "bg-slate-800 border-slate-700 text-slate-500 hover:text-emerald-400 hover:border-emerald-500/30"
                    }`}
                >
                  {explainState?.explanation_feedback === "useful" ? "✓ Useful" : "Useful"}
                </button>
                <button
                  onClick={() => explainFeedbackMut.mutate(explainState?.explanation_feedback === "not_useful" ? null : "not_useful")}
                  disabled={explainFeedbackSaving}
                  className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${explainState?.explanation_feedback === "not_useful"
                    ? "bg-red-500/20 border-red-500/50 text-red-400"
                    : "bg-slate-800 border-slate-700 text-slate-500 hover:text-red-400 hover:border-red-500/30"
                    }`}
                >
                  {explainState?.explanation_feedback === "not_useful" ? "✗ Not useful" : "Not useful"}
                </button>
              </div>
              {explainState?.feedback_error && <p className="text-xs text-red-400">{explainState.feedback_error}</p>}
            </section>
          )}

          {((explainState?.sections?.length ?? 0) > 0 || (explainState?.evidence_items?.length ?? 0) > 0) && (
            <div className="space-y-4">
              {explainState?.sections?.map((section) => renderExplainSection(section, {
                findingId: finding.finding_id,
                actionableCitations: explainEvidenceCitations,
                onCitationClick: handleExplainCitationJump,
              }))}

              <section className="space-y-2">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Supporting evidence</h4>
                {(explainState?.evidence_items?.length ?? 0) > 0 ? (
                  <ul className="space-y-2">
                    {explainState?.evidence_items?.map((item, index) => {
                      const isPrimaryEvidenceTarget = explainEvidenceTargetIndexByCitation.get(item.citation) === index;
                      const isHighlighted = highlightedExplainCitation === item.citation;
                      return (
                        <li
                          key={`${item.citation}:${item.label}`}
                          id={isPrimaryEvidenceTarget ? buildExplainEvidenceTargetId(finding.finding_id, item.citation) : undefined}
                          tabIndex={isPrimaryEvidenceTarget ? -1 : undefined}
                          data-testid={isPrimaryEvidenceTarget ? buildExplainEvidenceTestId(finding.finding_id, item.citation) : undefined}
                          className={`rounded border p-3 transition-colors ${isHighlighted ? "border-cyan-500/40 bg-cyan-500/10" : "border-slate-800 bg-slate-900/60"}`}
                        >
                          <p className="text-sm leading-6 text-slate-300"><span className="font-medium text-slate-200">{item.label}:</span> {item.value}</p>
                          <div className="mt-1 font-mono text-[10px] text-slate-500">{item.citation}</div>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  <p className="text-sm text-slate-500">No structured evidence was stored for this finding.</p>
                )}
              </section>
            </div>
          )}

          {!((explainState?.sections?.length ?? 0) > 0 || (explainState?.evidence_items?.length ?? 0) > 0) && explainState?.content && (
            explainState.format === "markdown" ? (
              <div className="prose prose-invert prose-sm max-w-none text-slate-300 prose-headings:text-slate-100 prose-p:text-slate-300 prose-li:text-slate-300 prose-strong:text-slate-100">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{explainState.content}</ReactMarkdown>
              </div>
            ) : (
              <div className="whitespace-pre-wrap text-sm leading-6 text-slate-300">{explainState.content}</div>
            )
          )}

          {!explainState && (
            <div className="rounded border border-dashed border-slate-800 bg-slate-900/30 p-4 text-sm text-slate-500">
              Generate a grounded explanation to summarize impact, evidence, and next investigative steps.
            </div>
          )}
        </section>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <h2 className="text-sm font-semibold text-slate-200">Raw finding evidence</h2>
            {finding.evidence ? (
              <pre className="mt-3 overflow-x-auto rounded border border-slate-800 bg-slate-950/70 p-3 text-xs leading-6 text-slate-300">{JSON.stringify(finding.evidence, null, 2)}</pre>
            ) : (
              <p className="mt-3 text-sm text-slate-500">No structured evidence was stored for this finding.</p>
            )}
          </section>

          <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            <h2 className="text-sm font-semibold text-slate-200">Related hosts</h2>
            {finding.related_hosts.length > 0 ? (
              <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
                {finding.related_hosts.map((host) => (
                  <Link key={host.ip} to={`/jobs/${jobId}/hosts/${encodeURIComponent(host.ip)}`} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 transition-colors hover:border-slate-700 hover:bg-slate-950/80">
                    <div className="font-mono text-blue-400">{host.ip}</div>
                    <div className="mt-1 text-xs text-slate-500">{host.role ?? "unknown role"} · {host.conn_count ?? 0} conns · {host.alert_count ?? 0} alerts · {host.finding_count ?? 0} findings</div>
                  </Link>
                ))}
              </div>
            ) : (
              <p className="mt-3 text-sm text-slate-500">No related hosts were resolved from this finding.</p>
            )}
          </section>
        </div>

        <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
          <h2 className="text-sm font-semibold text-slate-200">Related alerts</h2>
          {finding.related_alerts.length > 0 ? (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
                  <tr>
                    <th className="px-2 py-2">Time</th>
                    <th className="px-2 py-2">Signature</th>
                    <th className="px-2 py-2">Host</th>
                    <th className="px-2 py-2">Flow</th>
                    <th className="px-2 py-2">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {finding.related_alerts.map((alert) => (
                    <tr key={alert.alert_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="px-2 py-2 text-xs font-mono text-slate-500">{formatDateTime(alert.ts)}</td>
                      <td className="px-2 py-2">
                        <Link to={`/jobs/${jobId}/alerts/${alert.alert_id}`} className="text-slate-200 hover:text-blue-400">
                          {alert.signature}
                        </Link>
                        {alert.category && <div className="text-xs text-slate-500">{alert.category}</div>}
                      </td>
                      <td className="px-2 py-2 text-xs font-mono text-slate-300">{alert.host_ip ?? "—"}</td>
                      <td className="px-2 py-2 text-xs font-mono text-slate-300">{alert.src_ip ?? "—"}{alert.src_port ? `:${alert.src_port}` : ""} → {alert.dest_ip ?? "—"}{alert.dest_port ? `:${alert.dest_port}` : ""}</td>
                      <td className="px-2 py-2 text-xs text-slate-300">{alert.severity}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-500">No related alerts were resolved from this finding.</p>
          )}
        </section>

        <section className="rounded-lg border border-slate-800 bg-slate-900/40 p-4">
          <h2 className="text-sm font-semibold text-slate-200">Related connections</h2>
          {finding.related_connections.length > 0 ? (
            <div className="mt-3 overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs uppercase text-slate-500 border-b border-slate-800">
                  <tr>
                    <th className="px-2 py-2">Time</th>
                    <th className="px-2 py-2">Source</th>
                    <th className="px-2 py-2">Destination</th>
                    <th className="px-2 py-2">Proto</th>
                    <th className="px-2 py-2">Service</th>
                    <th className="px-2 py-2">PCAP</th>
                  </tr>
                </thead>
                <tbody>
                  {finding.related_connections.map((connection) => (
                    <tr key={connection.connection_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="px-2 py-2 text-xs font-mono text-slate-500">{formatDateTime(connection.ts)}</td>
                      <td className="px-2 py-2 text-xs font-mono text-slate-300">{connection.src_ip}{connection.src_port ? `:${connection.src_port}` : ""}</td>
                      <td className="px-2 py-2 text-xs font-mono text-slate-300">{connection.dest_ip}{connection.dest_port ? `:${connection.dest_port}` : ""}</td>
                      <td className="px-2 py-2 text-xs text-slate-300">{connection.proto}</td>
                      <td className="px-2 py-2 text-xs text-slate-400">{connection.service ?? "—"}</td>
                      <td className="px-2 py-2 text-xs text-slate-400">{connection.pcap_label ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-500">No related network connections were resolved from this finding.</p>
          )}
        </section>
      </div>

      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
};