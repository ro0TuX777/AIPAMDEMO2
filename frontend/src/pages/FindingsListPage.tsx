import React, { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type FindingExplainEvidenceItem,
  type FindingExplainFeedback,
  type FindingExplainSection,
  type FindingItem,
  type Severity,
} from "../api";

type ExplainState = {
  loading?: boolean;
  error?: string;
  content?: string;
  format?: "markdown" | "text";
  source?: "deterministic" | "llm" | "fallback";
  duration_ms?: number;
  updated_at?: string;
  copy_status?: "copied" | "error";
  download_status?: "downloaded" | "error";
  highlighted_citation?: string;
  warning?: string | null;
  explanation_feedback?: FindingExplainFeedback | null;
  feedback_error?: string;
  sections?: FindingExplainSection[];
  evidence_items?: FindingExplainEvidenceItem[];
};

type ExplainFormat = "markdown" | "text";

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-amber-400 bg-amber-400/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-slate-400 bg-slate-400/10",
};

const EXPLAIN_SOURCE_LABELS: Record<"deterministic" | "llm" | "fallback", string> = {
  deterministic: "Deterministic grounded response",
  llm: "LLM-grounded response",
  fallback: "Fallback grounded response",
};

const EXPLAIN_SOURCE_DESCRIPTIONS: Record<"deterministic" | "llm" | "fallback", string> = {
  deterministic: "This specific explanation came from the deterministic grounded path.",
  llm: "This specific explanation came from the LLM-grounded path.",
  fallback: "This specific explanation used deterministic fallback after the LLM path returned an invalid or unavailable response.",
};

const EXPLAIN_FORMAT_LABELS: Record<ExplainFormat, string> = {
  markdown: "Markdown",
  text: "Text",
};

const EXPLAIN_MODE_LABELS: Record<"deterministic" | "llm", string> = {
  deterministic: "Deterministic only",
  llm: "LLM-enabled",
};

const EXPLAIN_MODE_DESCRIPTIONS: Record<"deterministic" | "llm", string> = {
  deterministic: "Finding explanations are currently generated using deterministic grounded output only.",
  llm: "Finding explanations will try the configured LLM first and fall back to deterministic grounded output on invalid or unavailable responses.",
};

const EXPLAIN_UPDATED_AT_FORMATTER = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "medium",
});

const formatExplainUpdatedAt = (value: string) => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return EXPLAIN_UPDATED_AT_FORMATTER.format(parsed);
};

const formatExplainDuration = (durationMs: number) => `${durationMs.toLocaleString()} ms`;

const buildExplainClipboardText = (finding: FindingItem, explainState: ExplainState) => {
  const lines: string[] = [
    `Finding: ${finding.title}`,
    `Severity: ${finding.severity}`,
  ];

  if (finding.category) lines.push(`Category: ${finding.category}`);
  if (finding.sensor) lines.push(`Sensor: ${finding.sensor}`);
  if (finding.summary) lines.push(`Summary: ${finding.summary}`);
  if (explainState.source) lines.push(`Response source: ${EXPLAIN_SOURCE_LABELS[explainState.source]}`);
  if (typeof explainState.duration_ms === "number") lines.push(`Duration: ${formatExplainDuration(explainState.duration_ms)}`);
  if (explainState.updated_at) lines.push(`Updated: ${explainState.updated_at}`);
  if (explainState.warning) lines.push(`Warning: ${explainState.warning}`);

  lines.push("");

  if ((explainState.sections?.length ?? 0) > 0) {
    for (const section of explainState.sections ?? []) {
      lines.push(section.title);
      if (section.body) lines.push(section.body);
      for (const bullet of section.bullets) lines.push(`- ${bullet}`);
      if (section.citations.length > 0) lines.push(`Citations: ${section.citations.join(", ")}`);
      lines.push("");
    }
  } else if (explainState.content) {
    lines.push(explainState.content);
    lines.push("");
  }

  lines.push("Supporting evidence");
  if ((explainState.evidence_items?.length ?? 0) > 0) {
    for (const item of explainState.evidence_items ?? []) {
      lines.push(`- ${item.label}: ${item.value} (${item.citation})`);
    }
  } else {
    lines.push("- No structured evidence was stored for this finding.");
  }

  return lines.join("\n").trim();
};

const buildExplainMarkdownText = (finding: FindingItem, explainState: ExplainState) => {
  const lines: string[] = [
    "# Finding explanation",
    "",
    `**Finding:** ${finding.title}`,
    `**Severity:** ${finding.severity}`,
  ];

  if (finding.category) lines.push(`**Category:** ${finding.category}`);
  if (finding.sensor) lines.push(`**Sensor:** ${finding.sensor}`);
  if (finding.summary) lines.push(`**Summary:** ${finding.summary}`);
  if (explainState.source) lines.push(`**Response source:** ${EXPLAIN_SOURCE_LABELS[explainState.source]}`);
  if (typeof explainState.duration_ms === "number") lines.push(`**Duration:** ${formatExplainDuration(explainState.duration_ms)}`);
  if (explainState.updated_at) lines.push(`**Updated:** ${explainState.updated_at}`);
  if (explainState.warning) lines.push(`**Warning:** ${explainState.warning}`);

  lines.push("");

  if ((explainState.sections?.length ?? 0) > 0) {
    for (const section of explainState.sections ?? []) {
      lines.push(`## ${section.title}`);
      lines.push("");
      if (section.body) lines.push(section.body, "");
      for (const bullet of section.bullets) lines.push(`- ${bullet}`);
      if (section.bullets.length > 0) lines.push("");
      if (section.citations.length > 0) lines.push(`Citations: ${section.citations.join(", ")}`, "");
    }
  } else if (explainState.content) {
    lines.push("## Explanation", "", explainState.content, "");
  }

  lines.push("## Supporting evidence", "");
  if ((explainState.evidence_items?.length ?? 0) > 0) {
    for (const item of explainState.evidence_items ?? []) {
      lines.push(`- **${item.label}:** ${item.value} _(${item.citation})_`);
    }
  } else {
    lines.push("- No structured evidence was stored for this finding.");
  }

  return lines.join("\n").trim();
};

const buildExplainMarkdownFilename = (finding: FindingItem) => `finding-explanation-${finding.finding_id}.md`;

const sanitizeExplainCitation = (citation: string) => {
  const sanitized = citation.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return sanitized || "citation";
};

const buildExplainEvidenceTargetId = (findingId: string, citation: string) =>
  `explain-evidence-${findingId}-${sanitizeExplainCitation(citation)}`;

const buildExplainEvidenceTestId = (findingId: string, citation: string) =>
  `evidence-item-${findingId}-${sanitizeExplainCitation(citation)}`;

const buildExplainCitationButtonTestId = (findingId: string, citation: string) =>
  `btn-explain-citation-${findingId}-${sanitizeExplainCitation(citation)}`;

const renderExplainSection = (
  section: FindingExplainSection,
  options: {
    findingId: string;
    actionableCitations: Set<string>;
    onCitationClick: (citation: string) => void;
  },
) => (
  <section key={section.id} className="space-y-2">
    <h5 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{section.title}</h5>
    {section.body && <p className="text-xs leading-6 text-slate-300">{section.body}</p>}
    {section.bullets.length > 0 && (
      <ul className="space-y-1.5">
        {section.bullets.map((bullet) => (
          <li key={bullet} className="flex items-start gap-2 text-xs leading-6 text-slate-300">
            <span className="mt-1 text-slate-500">•</span>
            <span>{bullet}</span>
          </li>
        ))}
      </ul>
    )}
    {section.citations.length > 0 && (
      <div className="flex flex-wrap gap-1 pt-1">
        {section.citations.map((citation) => {
          const actionable = options.actionableCitations.has(citation);

          if (!actionable) {
            return (
              <span
                key={`${section.id}:${citation}`}
                className="rounded border border-slate-800 bg-slate-900/60 px-1.5 py-0.5 text-[10px] font-mono text-slate-500"
              >
                {citation}
              </span>
            );
          }

          return (
            <button
              key={`${section.id}:${citation}`}
              type="button"
              onClick={() => options.onCitationClick(citation)}
              title="Jump to supporting evidence"
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

export const FindingsListPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [sevFilter, setSevFilter] = useState<Severity | "">("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [openExplainId, setOpenExplainId] = useState<string | null>(null);
  const [explanations, setExplanations] = useState<Record<string, ExplainState>>({});

  const { data, isLoading, error } = useQuery({
    queryKey: ["job", jobId, "findings", sevFilter, categoryFilter],
    queryFn: () => api.listFindings(jobId!, {
      severity: sevFilter || undefined,
      category: categoryFilter || undefined,
      limit: 200,
    }),
    enabled: !!jobId,
  });
  const { data: systemConfig } = useQuery({
    queryKey: ["system", "config"],
    queryFn: () => api.getSystemConfig(),
  });

  const queryClient = useQueryClient();
  const feedbackMut = useMutation({
    mutationFn: ({ id, val }: { id: string; val: string | null }) =>
      api.updateFindingFeedback(jobId!, id, val),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] }),
  });
  const explainFeedbackMut = useMutation({
    mutationFn: ({ id, val }: { id: string; val: FindingExplainFeedback | null }) =>
      api.updateFindingExplainFeedback(jobId!, id, val),
    onSuccess: (result, variables) => {
      setExplanations((prev) => ({
        ...prev,
        [variables.id]: {
          ...(prev[variables.id] ?? {}),
          explanation_feedback: result.explanation_feedback,
          feedback_error: undefined,
        },
      }));
    },
    onError: (err, variables) => {
      setExplanations((prev) => ({
        ...prev,
        [variables.id]: {
          ...(prev[variables.id] ?? {}),
          feedback_error: err instanceof Error ? err.message : "Failed to save explanation feedback.",
        },
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

  const requestExplain = async (findingId: string, options?: { force?: boolean; format?: ExplainFormat }) => {
    const existing = explanations[findingId];
    const requestedFormat = options?.format ?? existing?.format ?? "markdown";
    if (existing?.loading) return;
    if (!options?.force && existing?.content) return;

    setExplanations((prev) => ({
      ...prev,
      [findingId]: {
        ...(prev[findingId] ?? {}),
        loading: true,
        error: undefined,
        copy_status: undefined,
        download_status: undefined,
        highlighted_citation: undefined,
        feedback_error: undefined,
        format: requestedFormat,
      },
    }));

    try {
      const result = await api.explainFinding(jobId!, findingId, { format: requestedFormat });
      setExplanations((prev) => ({
        ...prev,
        [findingId]: {
          ...(prev[findingId] ?? {}),
          loading: false,
          error: undefined,
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
        },
      }));
    } catch (err) {
      setExplanations((prev) => ({
        ...prev,
        [findingId]: {
          ...(prev[findingId] ?? {}),
          loading: false,
          error: err instanceof Error ? err.message : "Failed to explain finding.",
        },
      }));
    }
  };

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

    try {
      await navigator.clipboard.writeText(buildExplainClipboardText(finding, explainState));
      setExplanations((prev) => ({
        ...prev,
        [finding.finding_id]: {
          ...(prev[finding.finding_id] ?? {}),
          copy_status: "copied",
        },
      }));
    } catch {
      setExplanations((prev) => ({
        ...prev,
        [finding.finding_id]: {
          ...(prev[finding.finding_id] ?? {}),
          copy_status: "error",
        },
      }));
    }
  };

  const handleExplainDownload = async (finding: FindingItem) => {
    const explainState = explanations[finding.finding_id];
    if (!explainState) return;

    try {
      const markdown = buildExplainMarkdownText(finding, explainState);
      const blob = new Blob([markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = buildExplainMarkdownFilename(finding);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setExplanations((prev) => ({
        ...prev,
        [finding.finding_id]: {
          ...(prev[finding.finding_id] ?? {}),
          download_status: "downloaded",
        },
      }));
    } catch {
      setExplanations((prev) => ({
        ...prev,
        [finding.finding_id]: {
          ...(prev[finding.finding_id] ?? {}),
          download_status: "error",
        },
      }));
    }
  };

  const handleExplainCitationJump = (findingId: string, citation: string) => {
    const target = document.getElementById(buildExplainEvidenceTargetId(findingId, citation));
    if (!(target instanceof HTMLElement)) return;

    setExplanations((prev) => ({
      ...prev,
      [findingId]: {
        ...(prev[findingId] ?? {}),
        highlighted_citation: citation,
      },
    }));

    target.scrollIntoView({ behavior: "smooth", block: "nearest" });
    target.focus({ preventScroll: true });
  };

  return (
    <div className="space-y-4">
      <nav className="text-sm text-slate-400">
        <Link to="/jobs" className="hover:text-white">Jobs</Link>
        <span className="mx-1">/</span>
        <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
        <span className="mx-1">/</span>
        <span className="text-slate-200">Findings</span>
      </nav>

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h1 className="text-xl font-semibold">Findings ({findings.length})</h1>
        <div className="flex items-center gap-2 flex-wrap">
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

      {isLoading && <p className="text-slate-400 animate-pulse">Loading findings…</p>}
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
            const explainEvidenceTargetIndexByCitation = new Map<string, number>();
            for (const [index, item] of (explainState?.evidence_items ?? []).entries()) {
              if (!explainEvidenceTargetIndexByCitation.has(item.citation)) {
                explainEvidenceTargetIndexByCitation.set(item.citation, index);
              }
            }
            const explainEvidenceCitations = new Set(explainEvidenceTargetIndexByCitation.keys());
            const highlightedExplainCitation = explainState?.highlighted_citation;
            const hasExplainContent = Boolean(
              explainState?.content
              || (explainState?.sections?.length ?? 0) > 0
              || (explainState?.evidence_items?.length ?? 0) > 0,
            );
            const hasExplainDuration = typeof explainState?.duration_ms === "number";

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
                    <h3 className="text-sm font-semibold text-slate-200">{f.title}</h3>
                  </div>
                  {(f.sensor || f.pcap_label) && (
                    <div className="flex flex-wrap items-center gap-2 mt-1 text-[11px] text-slate-500">
                      {f.sensor && <span>sensor: <span className="text-slate-300">{f.sensor}</span></span>}
                      {f.pcap_label && <span>pcap: <span className="text-slate-300">{f.pcap_label}</span></span>}
                    </div>
                  )}
                  {f.summary && <p className="text-xs text-slate-400 mt-1 line-clamp-2">{f.summary}</p>}
                </div>

                <div className="flex flex-col items-end gap-2 shrink-0">
                  <span className="text-xs text-slate-600 font-mono">{f.finding_id.slice(0, 8)}</span>

                  <div className="flex items-center gap-1.5 mt-1">
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
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-300">Finding explanation</h4>
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
                      {!explainState?.loading && hasExplainContent && (
                        <button
                          onClick={() => void handleExplainCopy(f)}
                          data-testid={`btn-explain-copy-${f.finding_id}`}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
                        >
                          Copy
                        </button>
                      )}
                      {!explainState?.loading && hasExplainContent && (
                        <button
                          onClick={() => void handleExplainDownload(f)}
                          data-testid={`btn-explain-download-${f.finding_id}`}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-slate-400 transition-colors hover:border-cyan-500/30 hover:text-cyan-300"
                        >
                          Download
                        </button>
                      )}
                      {!explainState?.loading && (hasExplainContent || explainState?.error) && (
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
                      {hasExplainContent
                        ? `Regenerating ${EXPLAIN_FORMAT_LABELS[currentExplainFormat].toLowerCase()} grounded explanation…`
                        : `Generating ${EXPLAIN_FORMAT_LABELS[currentExplainFormat].toLowerCase()} grounded explanation…`}
                    </p>
                  )}

                  {explainState?.warning && (
                    <p className="mb-2 text-xs text-amber-300">{explainState.warning}</p>
                  )}

                  {explainState?.error && (
                    <p className="text-xs text-red-400">{explainState.error}</p>
                  )}

                  {!explainState?.loading && hasExplainContent && (
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
                      {explainState?.sections?.map((section) => renderExplainSection(section, {
                        findingId: f.finding_id,
                        actionableCitations: explainEvidenceCitations,
                        onCitationClick: (citation) => handleExplainCitationJump(f.finding_id, citation),
                      }))}

                      <section className="space-y-2">
                        <h5 className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                          Supporting evidence
                        </h5>
                        {(explainState?.evidence_items?.length ?? 0) > 0 ? (
                          <ul className="space-y-2">
                            {explainState?.evidence_items?.map((item, index) => {
                              const isPrimaryEvidenceTarget = explainEvidenceTargetIndexByCitation.get(item.citation) === index;
                              const isHighlighted = highlightedExplainCitation === item.citation;

                              return (
                              <li
                                key={`${item.citation}:${item.label}`}
                                id={isPrimaryEvidenceTarget ? buildExplainEvidenceTargetId(f.finding_id, item.citation) : undefined}
                                tabIndex={isPrimaryEvidenceTarget ? -1 : undefined}
                                data-testid={isPrimaryEvidenceTarget ? buildExplainEvidenceTestId(f.finding_id, item.citation) : undefined}
                                data-highlighted={isHighlighted ? "true" : "false"}
                                className={`rounded border p-2 transition-colors ${isHighlighted
                                  ? "border-cyan-500/40 bg-cyan-500/10"
                                  : "border-slate-800 bg-slate-900/60"
                                  }`}
                              >
                                <p className="text-xs leading-6 text-slate-300">
                                  <span className="font-medium text-slate-200">{item.label}:</span>{" "}
                                  {item.value}
                                </p>
                                <div className="mt-1 text-[10px] text-slate-500 font-mono">{item.citation}</div>
                              </li>
                              );
                            })}
                          </ul>
                        ) : (
                          <p className="text-xs text-slate-500">No structured evidence was stored for this finding.</p>
                        )}
                      </section>

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
  );
};
