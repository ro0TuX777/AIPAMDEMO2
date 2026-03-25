import React, { useEffect, useState } from "react";
import { useParams, Link, useNavigate, useSearchParams } from "react-router-dom";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  EXPLAIN_FORMAT_LABELS,
  EXPLAIN_MODE_DESCRIPTIONS,
  EXPLAIN_MODE_LABELS,
  EXPLAIN_SOURCE_DESCRIPTIONS,
  EXPLAIN_SOURCE_LABELS,
  type ExplainFormat,
  type ExplainState,
  buildExplainErrorState,
  buildExplainEvidenceIndex,
  buildExplainLoadingState,
  buildExplainSuccessState,
  copyExplainToClipboard,
  downloadExplainMarkdownFile,
  formatExplainDuration,
  formatExplainUpdatedAt,
  getCachedFindingExplainState,
  getExplainRetryMessage,
  hasExplainContent,
  setCachedFindingExplainState,
  scrollToExplainEvidenceTarget,
} from "../findingsExplain";
import {
  api,
  type FindingExplainFeedback,
  type FindingItem,
  type Severity,
} from "../api";
import { ConfidenceBadge, ExplainEvidenceList, ExplainSectionBlock } from "../components/findings/ExplainShared";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";
import { CardGridSkeleton } from "../components/SkeletonLoader";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-amber-400 bg-amber-400/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-slate-400 bg-slate-400/10",
};

export const FindingsListPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const pcapLabel = searchParams.get("pcap_label") || "";
  const [sevFilter, setSevFilter] = useState<Severity | "">("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [openExplainId, setOpenExplainId] = useState<string | null>(null);
  const [explanations, setExplanations] = useState<Record<string, ExplainState>>({});
  const [retryClockMs, setRetryClockMs] = useState(() => Date.now());
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "findings", sevFilter, categoryFilter, pcapLabel],
    queryFn: () => api.listFindings(jobId!, {
      severity: sevFilter || undefined,
      category: categoryFilter || undefined,
      pcap_label: pcapLabel || undefined,
      limit: 200,
    }),
    enabled: !!jobId,
  });
  const { data: systemConfig } = useQuery({
    queryKey: ["system", "config"],
    queryFn: () => api.getSystemConfig(),
  });

  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const feedbackMut = useMutation({
    mutationFn: ({ id, val }: { id: string; val: string | null }) =>
      api.updateFindingFeedback(jobId!, id, val),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] });
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "finding"] });
      addToast({ severity: "info", title: "Feedback saved", duration: 3000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to save feedback" }),
  });
  const explainFeedbackMut = useMutation({
    mutationFn: ({ id, val }: { id: string; val: FindingExplainFeedback | null }) =>
      api.updateFindingExplainFeedback(jobId!, id, val),
    onSuccess: (result, variables) => {
      setExplainStateForFinding(variables.id, (prev) => ({
          ...(prev ?? {}),
          explanation_feedback: result.explanation_feedback,
          feedback_error: undefined,
      }));
    },
    onError: (err, variables) => {
      setExplainStateForFinding(variables.id, (prev) => ({
          ...(prev ?? {}),
          feedback_error: err instanceof Error ? err.message : "Failed to save explanation feedback.",
      }));
    },
  });

  const findings = data?.items ?? [];
  const categories = Array.from(
    new Set(findings.map((f) => f.category).filter((value): value is string => Boolean(value))),
  ).sort();
  const explainConfiguration = systemConfig?.explain_configuration;
  const explainModeLabel = explainConfiguration
    ? EXPLAIN_MODE_LABELS[explainConfiguration.mode]
    : null;
  const explainModeDescription = explainConfiguration
    ? EXPLAIN_MODE_DESCRIPTIONS[explainConfiguration.mode]
    : null;
  const explainModelName = explainConfiguration?.llm_model_name ?? null;

  const setExplainStateForFinding = (findingId: string, updater: (prev: ExplainState | undefined) => ExplainState) => {
    setExplanations((prev) => {
      const nextState = updater(prev[findingId]);
      if (jobId) {
        setCachedFindingExplainState(queryClient, jobId, findingId, nextState);
      }
      return {
        ...prev,
        [findingId]: nextState,
      };
    });
  };

  useEffect(() => {
    if (!jobId || findings.length === 0) {
      return;
    }

    setExplanations((prev) => {
      let changed = false;
      const next = { ...prev };

      for (const finding of findings) {
        if (next[finding.finding_id]) {
          continue;
        }

        const cached = getCachedFindingExplainState(queryClient, jobId, finding.finding_id);
        if (cached) {
          next[finding.finding_id] = cached;
          changed = true;
        }
      }

      return changed ? next : prev;
    });
  }, [findings, jobId, queryClient]);

  const requestExplain = async (findingId: string, options?: { force?: boolean; format?: ExplainFormat }) => {
    const existing = explanations[findingId];
    const requestedFormat = options?.format ?? existing?.format ?? "markdown";
    if (existing?.loading) return;
    if (!options?.force && existing?.content) return;

    setExplainStateForFinding(findingId, (prev) => buildExplainLoadingState(prev, requestedFormat));

    try {
      const result = await api.explainFinding(jobId!, findingId, { format: requestedFormat });
      setExplainStateForFinding(findingId, (prev) => buildExplainSuccessState(prev, result));
    } catch (err) {
      setExplainStateForFinding(findingId, (prev) => buildExplainErrorState(prev, err));
    }
  };

  const openExplainState = openExplainId ? explanations[openExplainId] : undefined;

  useEffect(() => {
    if (!openExplainId || openExplainState?.loading || typeof openExplainState?.retry_at_ms !== "number") {
      return undefined;
    }

    const retryDelayMs = Math.max(0, openExplainState.retry_at_ms - Date.now());
    const timerId = window.setTimeout(() => {
      void requestExplain(openExplainId, {
        force: true,
        format: openExplainState.format ?? "markdown",
      });
    }, retryDelayMs);

    return () => window.clearTimeout(timerId);
  }, [openExplainId, openExplainState?.format, openExplainState?.loading, openExplainState?.retry_at_ms]);

  useEffect(() => {
    if (!openExplainId || openExplainState?.loading || typeof openExplainState?.retry_at_ms !== "number") {
      return undefined;
    }

    setRetryClockMs(Date.now());
    const intervalId = window.setInterval(() => setRetryClockMs(Date.now()), 250);
    return () => window.clearInterval(intervalId);
  }, [openExplainId, openExplainState?.loading, openExplainState?.retry_at_ms]);

  const handleExplainFormatChange = async (findingId: string, format: ExplainFormat) => {
    await requestExplain(findingId, { force: true, format });
  };

  const handleExplain = async (findingId: string) => {
    const nextOpen = openExplainId === findingId ? null : findingId;
    setOpenExplainId(nextOpen);
    if (!nextOpen) return;

    await requestExplain(findingId);
  };

  const handleExplainCopy = async (finding: FindingItem) => {
    const explainState = explanations[finding.finding_id];
    if (!explainState) return;

    const copyStatus = await copyExplainToClipboard(finding, explainState);
    setExplainStateForFinding(finding.finding_id, (prev) => ({
        ...(prev ?? {}),
        copy_status: copyStatus,
    }));
  };

  const handleExplainDownload = async (finding: FindingItem) => {
    const explainState = explanations[finding.finding_id];
    if (!explainState) return;

    const downloadStatus = downloadExplainMarkdownFile(finding, explainState);
    setExplainStateForFinding(finding.finding_id, (prev) => ({
        ...(prev ?? {}),
        download_status: downloadStatus,
    }));
  };

  const handleExplainCitationJump = (findingId: string, citation: string) => {
    if (!scrollToExplainEvidenceTarget(findingId, citation)) return;

    setExplainStateForFinding(findingId, (prev) => ({
        ...(prev ?? {}),
        highlighted_citation: citation,
    }));
  };

  return (
    <>
    <div className="flex gap-6 items-start">
    <div className="space-y-4 flex-1 min-w-0">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Findings</span>
      </nav>

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h1 className={`text-xl font-semibold ${labelHint("findings", activeHelpField)}`} onClick={() => toggleHelp("findings")}>Findings ({findings.length})</h1>
        <div className="flex items-center gap-2 flex-wrap">
          {pcapLabel && (
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-xs font-medium">
              Phase: {pcapLabel}
              <button onClick={() => { searchParams.delete("pcap_label"); setSearchParams(searchParams); }} className="ml-1.5 text-emerald-400 hover:text-white">✕</button>
            </span>
          )}
          <select value={sevFilter} onChange={e => setSevFilter(e.target.value as Severity | "")}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
            <option value="">All categories</option>
            {categories.map((category) => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
        </div>
      </div>

      <p className="text-sm text-slate-500">
        Use the queue for rapid triage and Quick Look explanations. Open a finding detail page for deeper forensic pivots and related entity review.
      </p>

      {isLoading && <CardGridSkeleton count={4} />}
      {error && <p className="text-red-400">Failed to load findings.</p>}

      {!isLoading && findings.length === 0 && (
        <p className="text-slate-500">No findings found for this job.</p>
      )}

      {findings.length > 0 && (
        <div className="space-y-3">
          {findings.map((f: FindingItem) => {
            const explainState = explanations[f.finding_id];
            const explainOpen = openExplainId === f.finding_id;
            const currentExplainFormat = explainState?.format ?? "markdown";
            const explainFeedbackSaving = explainFeedbackMut.isPending && explainFeedbackMut.variables?.id === f.finding_id;
            const explainEvidenceTargetIndexByCitation = buildExplainEvidenceIndex(explainState?.evidence_items);
            const explainEvidenceCitations = new Set(explainEvidenceTargetIndexByCitation.keys());
            const highlightedExplainCitation = explainState?.highlighted_citation;
            const alertCount = typeof f.evidence?.["alert_count"] === "number" ? f.evidence["alert_count"] : null;
            const affectedHostCount = Array.isArray(f.evidence?.["affected_hosts"]) ? f.evidence["affected_hosts"].length : null;
            const sampleTs = typeof f.evidence?.["sample_ts"] === "string" ? f.evidence["sample_ts"] : null;
            const hasExplainContentForFinding = hasExplainContent(explainState);
            const hasExplainDuration = typeof explainState?.duration_ms === "number";
            const explainRetryMessage = getExplainRetryMessage(explainState, retryClockMs);

            return (
              <div key={f.finding_id} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${SEV_COLORS[f.severity] ?? SEV_COLORS.info}`}>
                      {f.severity.toUpperCase()}
                    </span>
                    {f.category && (
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                        {f.category}
                      </span>
                    )}
                    <ConfidenceBadge value={f.confidence} density="compact" />
                    <h3 className="text-sm font-semibold text-slate-200">{f.title}</h3>
                  </div>
                  {(f.sensor || f.pcap_label) && (
                    <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] text-slate-500">
                      {f.sensor && <span>sensor: <span className="text-slate-300">{f.sensor}</span></span>}
                      {f.pcap_label && <span>pcap: <span className="text-slate-300">{f.pcap_label}</span></span>}
                    </div>
                  )}
                  {f.summary && <p className="text-xs text-slate-400 mt-1 line-clamp-2">{f.summary}</p>}
                  {(alertCount !== null || affectedHostCount !== null || sampleTs) && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {alertCount !== null && <span className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-400">{alertCount} alerts</span>}
                      {affectedHostCount !== null && <span className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-400">{affectedHostCount} hosts</span>}
                      {sampleTs && <span className="rounded border border-slate-800 bg-slate-950/60 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-400">sample {new Date(sampleTs).toLocaleString()}</span>}
                    </div>
                  )}
                </div>

                <div className="flex flex-col items-end gap-2 shrink-0">
                  <span className="text-xs text-slate-600 font-mono">{f.finding_id.slice(0, 8)}</span>

                  <div className="flex items-center gap-1.5 mt-1">
                    <Link
                      to={`/jobs/${jobId}/findings/${f.finding_id}`}
                      data-testid={`link-finding-detail-${f.finding_id}`}
                      className="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border bg-slate-800 border-slate-700 text-blue-300 hover:text-blue-200 hover:border-blue-500/30"
                    >
                      View detail
                    </Link>
                    <button
                      onClick={() => navigate(`/jobs/${jobId}/chat?ask=${encodeURIComponent(`Analyze finding "${f.title}" (severity: ${f.severity}). ${f.summary ? f.summary + ' ' : ''}What does this mean, what is the impact, and what should an analyst do next?`)}&hint=${encodeURIComponent(`finding:${f.finding_id}`)}`)}
                      className="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border bg-slate-800 border-slate-700 text-emerald-400/60 hover:text-emerald-400 hover:border-emerald-500/30"
                      title="Ask AI about this finding"
                    >
                      Ask AI
                    </button>
                    <button
                      onClick={() => void handleExplain(f.finding_id)}
                      disabled={Boolean(explainState?.loading)}
                      title="Explain this finding"
                      data-testid={`btn-explain-${f.finding_id}`}
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${explainOpen
                        ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-300"
                        : "bg-slate-800 border-slate-700 text-slate-500 hover:text-cyan-300 hover:border-cyan-500/30"
                        }`}
                    >
                      {explainState?.loading ? "Explaining…" : explainOpen ? "Hide" : "Explain"}
                    </button>
                    <button
                      onClick={() => feedbackMut.mutate({ id: f.finding_id, val: "confirmed" })}
                      disabled={feedbackMut.isPending}
                      title="Mark as Confirmed"
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${f.feedback === "confirmed"
                        ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
                        : "bg-slate-800 border-slate-700 text-slate-500 hover:text-emerald-400 hover:border-emerald-500/30"
                        }`}
                    >
                      {f.feedback === "confirmed" ? "✓ Confirmed" : "Confirm"}
                    </button>
                    <button
                      onClick={() => feedbackMut.mutate({ id: f.finding_id, val: "false_positive" })}
                      disabled={feedbackMut.isPending}
                      title="Mark as False Positive"
                      className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${f.feedback === "false_positive"
                        ? "bg-red-500/20 border-red-500/50 text-red-400"
                        : "bg-slate-800 border-slate-700 text-slate-500 hover:text-red-400 hover:border-red-500/30"
                        }`}
                    >
                      {f.feedback === "false_positive" ? "✗ FP" : "FP"}
                    </button>
                  </div>
                </div>
              </div>
              {explainOpen && (
                <div
                  data-testid={`explain-panel-${f.finding_id}`}
                  className="mt-3 rounded-md border border-slate-800 bg-slate-950/70 p-3"
                >
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Quick look explanation</h4>
                    <div className="flex items-center gap-2 flex-wrap justify-end">
                      <div className="flex items-center gap-1 rounded border border-slate-800 bg-slate-900/60 p-1">
                        {(Object.keys(EXPLAIN_FORMAT_LABELS) as ExplainFormat[]).map((format) => (
                          <button
                            key={format}
                            onClick={() => void handleExplainFormatChange(f.finding_id, format)}
                            disabled={Boolean(explainState?.loading) || currentExplainFormat === format}
                            data-testid={`btn-explain-format-${format}-${f.finding_id}`}
                            className={`rounded px-2 py-1 text-[10px] font-bold uppercase tracking-wider transition-colors ${currentExplainFormat === format
                              ? "bg-cyan-500/20 text-cyan-300"
                              : "text-slate-500 hover:text-cyan-300"
                              } disabled:cursor-default disabled:opacity-100`}
                          >
                            {EXPLAIN_FORMAT_LABELS[format]}
                          </button>
                        ))}
                      </div>
                      <span className="text-[11px] text-slate-500">
                        {explainState?.source
                          ? EXPLAIN_SOURCE_LABELS[explainState.source]
                          : `${EXPLAIN_FORMAT_LABELS[currentExplainFormat]} response`}
                      </span>
                      {!explainState?.loading && hasExplainContentForFinding && (
                        <button
                          onClick={() => void handleExplainCopy(f)}
                          data-testid={`btn-explain-copy-${f.finding_id}`}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
                        >
                          Copy
                        </button>
                      )}
                      {!explainState?.loading && hasExplainContentForFinding && (
                        <button
                          onClick={() => void handleExplainDownload(f)}
                          data-testid={`btn-explain-download-${f.finding_id}`}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
                        >
                          Download
                        </button>
                      )}
                      {!explainState?.loading && (hasExplainContentForFinding || explainState?.error || explainState?.retry_at_ms) && (
                        <button
                          onClick={() => void requestExplain(f.finding_id, { force: true, format: currentExplainFormat })}
                          data-testid={`btn-explain-regenerate-${f.finding_id}`}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
                        >
                          Regenerate
                        </button>
                      )}
                    </div>
                  </div>

                  {(explainState?.updated_at || hasExplainDuration) && (
                    <p className="mb-3 text-[11px] leading-5 text-slate-500">
                      {explainState?.updated_at && (
                        <>
                          Updated:{" "}
                          <time
                            className="text-slate-400"
                            dateTime={explainState.updated_at}
                            title={explainState.updated_at}
                            data-testid={`text-explain-updated-at-${f.finding_id}`}
                          >
                            {formatExplainUpdatedAt(explainState.updated_at)}
                          </time>
                        </>
                      )}
                      {explainState?.updated_at && hasExplainDuration && <span className="px-1.5">·</span>}
                      {hasExplainDuration && (
                        <>
                          Duration:{" "}
                          <span className="text-slate-400" data-testid={`text-explain-duration-${f.finding_id}`}>
                            {formatExplainDuration(explainState.duration_ms!)}
                          </span>
                        </>
                      )}
                    </p>
                  )}

                  {explainState?.copy_status && (
                    <p
                      className={`mb-3 text-[11px] leading-5 ${explainState.copy_status === "copied" ? "text-emerald-400" : "text-red-400"}`}
                      data-testid={`text-explain-copy-status-${f.finding_id}`}
                    >
                      {explainState.copy_status === "copied"
                        ? "Copied explanation bundle to clipboard."
                        : "Failed to copy explanation bundle."}
                    </p>
                  )}

                  {explainState?.download_status && (
                    <p
                      className={`mb-3 text-[11px] leading-5 ${explainState.download_status === "downloaded" ? "text-emerald-400" : "text-red-400"}`}
                      data-testid={`text-explain-download-status-${f.finding_id}`}
                    >
                      {explainState.download_status === "downloaded"
                        ? "Downloaded explanation markdown."
                        : "Failed to download explanation markdown."}
                    </p>
                  )}

                  {explainModeLabel && (
                    <div
                      className="mb-3 rounded border border-slate-800 bg-slate-900/40 px-2.5 py-2"
                      data-testid={`explain-runtime-${f.finding_id}`}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                          Explain runtime
                        </span>
                        <span
                          className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${explainConfiguration?.mode === "llm"
                            ? "bg-violet-500/15 text-violet-300 border border-violet-500/20"
                            : "bg-slate-800 text-slate-300 border border-slate-700"
                            }`}
                          data-testid={`text-explain-runtime-mode-${f.finding_id}`}
                        >
                          {explainModeLabel}
                        </span>
                        {explainConfiguration?.mode === "llm" && explainModelName && (
                          <span
                            className="text-[11px] text-slate-400"
                            data-testid={`text-explain-runtime-model-${f.finding_id}`}
                          >
                            Model: <span className="font-mono text-slate-300">{explainModelName}</span>
                          </span>
                        )}
                      </div>
                      {explainModeDescription && (
                        <p
                          className="mt-2 text-[11px] leading-5 text-slate-400"
                          data-testid={`text-explain-runtime-description-${f.finding_id}`}
                        >
                          {explainModeDescription}
                        </p>
                      )}
                      <p
                        className="mt-2 text-[11px] leading-5 text-slate-500"
                        data-testid={`text-explain-runtime-helper-${f.finding_id}`}
                      >
                        Runtime mode shows the configured behavior. Response source shows what actually produced this explanation.
                      </p>
                      {explainState?.source && (
                        <p
                          className="mt-1 text-[11px] leading-5 text-slate-400"
                          data-testid={`text-explain-source-description-${f.finding_id}`}
                        >
                          {EXPLAIN_SOURCE_DESCRIPTIONS[explainState.source]}
                        </p>
                      )}
                    </div>
                  )}

                  {explainState?.loading && (
                    <p className="text-xs text-slate-400 animate-pulse">
                      {hasExplainContentForFinding
                        ? `Regenerating ${EXPLAIN_FORMAT_LABELS[currentExplainFormat].toLowerCase()} grounded explanation…`
                        : `Generating ${EXPLAIN_FORMAT_LABELS[currentExplainFormat].toLowerCase()} grounded explanation…`}
                    </p>
                  )}

                  {explainState?.warning && (
                    <p className="mb-2 text-xs text-amber-300">{explainState.warning}</p>
                  )}

                  {explainRetryMessage && (
                    <p
                      className="mb-2 text-xs text-amber-300"
                      data-testid={`text-explain-retry-status-${f.finding_id}`}
                    >
                      {explainRetryMessage}
                    </p>
                  )}

                  {explainState?.error && (
                    <p className="text-xs text-red-400">{explainState.error}</p>
                  )}

                  {!explainState?.loading && hasExplainContentForFinding && (
                    <section className="mb-3 space-y-2 rounded border border-slate-800 bg-slate-900/40 p-2.5">
                      <div className="flex items-center justify-between gap-2">
                        <h5 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                          Analyst feedback
                        </h5>
                        {explainFeedbackSaving && (
                          <span className="text-[10px] text-slate-500">Saving…</span>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        <button
                          onClick={() => explainFeedbackMut.mutate({
                            id: f.finding_id,
                            val: explainState?.explanation_feedback === "useful" ? null : "useful",
                          })}
                          disabled={explainFeedbackSaving}
                          className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${explainState?.explanation_feedback === "useful"
                            ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
                            : "bg-slate-800 border-slate-700 text-slate-500 hover:text-emerald-400 hover:border-emerald-500/30"
                            }`}
                        >
                          {explainState?.explanation_feedback === "useful" ? "✓ Useful" : "Useful"}
                        </button>
                        <button
                          onClick={() => explainFeedbackMut.mutate({
                            id: f.finding_id,
                            val: explainState?.explanation_feedback === "not_useful" ? null : "not_useful",
                          })}
                          disabled={explainFeedbackSaving}
                          className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-colors border ${explainState?.explanation_feedback === "not_useful"
                            ? "bg-red-500/20 border-red-500/50 text-red-400"
                            : "bg-slate-800 border-slate-700 text-slate-500 hover:text-red-400 hover:border-red-500/30"
                            }`}
                        >
                          {explainState?.explanation_feedback === "not_useful" ? "✗ Not useful" : "Not useful"}
                        </button>
                      </div>
                      {explainState?.feedback_error && (
                        <p className="text-xs text-red-400">{explainState.feedback_error}</p>
                      )}
                    </section>
                  )}

                  {((explainState?.sections?.length ?? 0) > 0 || (explainState?.evidence_items?.length ?? 0) > 0) && (
                    <div className="space-y-4">
                      {explainState?.sections?.map((section) => (
                        <ExplainSectionBlock
                          key={section.id}
                          section={section}
                          findingId={f.finding_id}
                          actionableCitations={explainEvidenceCitations}
                          onCitationClick={(citation) => handleExplainCitationJump(f.finding_id, citation)}
                          density="compact"
                          headingLevel="h5"
                        />
                      ))}

                      <ExplainEvidenceList
                        findingId={f.finding_id}
                        evidenceItems={explainState?.evidence_items}
                        citationIndexByCitation={explainEvidenceTargetIndexByCitation}
                        highlightedCitation={highlightedExplainCitation}
                        density="compact"
                        headingLevel="h5"
                        includeHighlightDataAttribute
                      />

                    </div>
                  )}

                  {!((explainState?.sections?.length ?? 0) > 0 || (explainState?.evidence_items?.length ?? 0) > 0) && explainState?.content && (
                    <div className="whitespace-pre-wrap text-xs leading-6 text-slate-300">
                      {explainState.content}
                    </div>
                  )}
                </div>
              )}
              </div>
            );
          })}
        </div>
      )}
    </div>
    <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
    <JobSubPageNav jobId={jobId!} currentPath="findings" />
    </>
  );
};
