import type { QueryClient } from "@tanstack/react-query";

import { ApiError, type FindingExplainEvidenceItem, type FindingExplainFeedback, type FindingExplainSection, type FindingItem } from "./api";

export type ExplainState = {
  loading?: boolean;
  error?: string;
  retry_status?: 429 | 503;
  retry_at_ms?: number;
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

export type ExplainFormat = "markdown" | "text";

export const EXPLAIN_SOURCE_LABELS: Record<"deterministic" | "llm" | "fallback", string> = {
  deterministic: "Deterministic grounded response",
  llm: "LLM-grounded response",
  fallback: "Fallback grounded response",
};

export const EXPLAIN_SOURCE_DESCRIPTIONS: Record<"deterministic" | "llm" | "fallback", string> = {
  deterministic: "This specific explanation came from the deterministic grounded path.",
  llm: "This specific explanation came from the LLM-grounded path.",
  fallback: "This specific explanation used deterministic fallback after the LLM path returned an invalid or unavailable response.",
};

export const EXPLAIN_FORMAT_LABELS: Record<ExplainFormat, string> = {
  markdown: "Markdown",
  text: "Text",
};

export const EXPLAIN_MODE_LABELS: Record<"deterministic" | "llm", string> = {
  deterministic: "Deterministic only",
  llm: "LLM-enabled",
};

export const EXPLAIN_MODE_DESCRIPTIONS: Record<"deterministic" | "llm", string> = {
  deterministic: "Finding explanations are currently generated using deterministic grounded output only.",
  llm: "Finding explanations will try the configured LLM first and fall back to deterministic grounded output on invalid or unavailable responses.",
};

const EXPLAIN_UPDATED_AT_FORMATTER = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });

export const getFindingExplainStateQueryKey = (jobId: string, findingId: string) => ["job", jobId, "findingExplain", findingId] as const;

export const getCachedFindingExplainState = (queryClient: QueryClient, jobId: string, findingId: string) =>
  queryClient.getQueryData<ExplainState>(getFindingExplainStateQueryKey(jobId, findingId));

export const setCachedFindingExplainState = (queryClient: QueryClient, jobId: string, findingId: string, nextState: ExplainState) => {
  queryClient.setQueryData(getFindingExplainStateQueryKey(jobId, findingId), nextState);
};

export const formatExplainUpdatedAt = (value: string) => {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : EXPLAIN_UPDATED_AT_FORMATTER.format(parsed);
};

export const formatExplainDuration = (durationMs: number) => `${durationMs.toLocaleString()} ms`;

export const getExplainRetryAfterSeconds = (error: ApiError) => {
  if (typeof error.retryAfter === "number" && Number.isFinite(error.retryAfter) && error.retryAfter > 0) {
    return Math.max(1, Math.round(error.retryAfter));
  }
  return error.status === 503 ? 5 : 2;
};

export const getExplainRetrySecondsRemaining = (explainState: ExplainState | undefined, nowMs: number) => {
  if (typeof explainState?.retry_at_ms !== "number") return null;
  return Math.max(1, Math.ceil((explainState.retry_at_ms - nowMs) / 1000));
};

export const getExplainRetryMessage = (explainState: ExplainState | undefined, nowMs: number) => {
  const remainingSeconds = getExplainRetrySecondsRemaining(explainState, nowMs);
  if (!remainingSeconds || !explainState?.retry_status) return null;
  return explainState.retry_status === 503
    ? `Analysis queue full, retrying in ${remainingSeconds}s`
    : `LLM busy, retrying in ${remainingSeconds}s`;
};

export const hasExplainContent = (explainState: ExplainState | undefined) => Boolean(
  explainState?.content
  || (explainState?.sections?.length ?? 0) > 0
  || (explainState?.evidence_items?.length ?? 0) > 0,
);

export const buildExplainClipboardText = (finding: FindingItem, explainState: ExplainState) => {
  const lines: string[] = [`Finding: ${finding.title}`, `Severity: ${finding.severity}`];
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
    lines.push(explainState.content, "");
  }
  lines.push("Supporting evidence");
  if ((explainState.evidence_items?.length ?? 0) > 0) {
    for (const item of explainState.evidence_items ?? []) lines.push(`- ${item.label}: ${item.value} (${item.citation})`);
  } else {
    lines.push("- No structured evidence was stored for this finding.");
  }
  return lines.join("\n").trim();
};

export const buildExplainMarkdownText = (finding: FindingItem, explainState: ExplainState) => {
  const lines: string[] = ["# Finding explanation", "", `**Finding:** ${finding.title}`, `**Severity:** ${finding.severity}`];
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
      lines.push(`## ${section.title}`, "");
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
    for (const item of explainState.evidence_items ?? []) lines.push(`- **${item.label}:** ${item.value} _(${item.citation})_`);
  } else {
    lines.push("- No structured evidence was stored for this finding.");
  }
  return lines.join("\n").trim();
};

export const buildExplainMarkdownFilename = (finding: FindingItem) => `finding-explanation-${finding.finding_id}.md`;

export const sanitizeExplainCitation = (citation: string) => {
  const sanitized = citation.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return sanitized || "citation";
};

export const buildExplainEvidenceTargetId = (findingId: string, citation: string) =>
  `explain-evidence-${findingId}-${sanitizeExplainCitation(citation)}`;

export const buildExplainEvidenceTestId = (findingId: string, citation: string) =>
  `evidence-item-${findingId}-${sanitizeExplainCitation(citation)}`;

export const buildExplainCitationButtonTestId = (findingId: string, citation: string) =>
  `btn-explain-citation-${findingId}-${sanitizeExplainCitation(citation)}`;