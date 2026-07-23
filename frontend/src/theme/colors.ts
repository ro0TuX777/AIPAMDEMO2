/**
 * Shared severity / status colour tokens.
 *
 * These were previously copy-pasted into 11+ files with genuinely different
 * values — "critical" rendered as red-500, red-600, red-900/40, rose-400 and
 * red-400 depending on which page you were looking at, so severity could not be
 * scanned across pages. The variants below preserve the distinct *shapes* each
 * call site needs (badge, solid chip, outlined card, bare text, left border,
 * bar fill) while pinning one hue ramp per severity.
 *
 * Hue ramp: critical=red · high=orange · medium=amber · low=blue · info=slate.
 */

export type SeverityKey = "critical" | "high" | "medium" | "low" | "info";

/** Highest first — useful for sorting and for stacked-bar ordering. */
export const SEVERITY_ORDER: SeverityKey[] = ["critical", "high", "medium", "low", "info"];

/**
 * How the severity colour is applied.
 * - `badge`   tinted text on a faint wash (list chips)
 * - `solid`   high-contrast filled chip (dense tables)
 * - `outline` card/panel treatment with a border
 * - `text`    bare coloured text (table cells)
 * - `border`  left rule only (timeline rows)
 * - `bar`     solid fill for meters and legend dots
 */
export type SeverityVariant = "badge" | "solid" | "outline" | "text" | "border" | "bar";

const SEVERITY_CLASSES: Record<SeverityVariant, Record<SeverityKey, string>> = {
  badge: {
    critical: "text-red-500 bg-red-500/10",
    high: "text-orange-400 bg-orange-400/10",
    medium: "text-amber-400 bg-amber-400/10",
    low: "text-blue-400 bg-blue-400/10",
    info: "text-slate-400 bg-slate-400/10",
  },
  solid: {
    critical: "bg-red-600 text-white",
    high: "bg-orange-600 text-white",
    medium: "bg-amber-600 text-white",
    low: "bg-blue-600 text-white",
    info: "bg-slate-600 text-slate-200",
  },
  outline: {
    critical: "bg-red-900/40 text-red-300 border-red-700",
    high: "bg-orange-900/40 text-orange-300 border-orange-700",
    medium: "bg-amber-900/40 text-amber-300 border-amber-700",
    low: "bg-blue-900/40 text-blue-300 border-blue-700",
    info: "bg-slate-800 text-slate-400 border-slate-600",
  },
  text: {
    critical: "text-red-500",
    high: "text-orange-400",
    medium: "text-amber-400",
    low: "text-blue-400",
    info: "text-slate-400",
  },
  border: {
    critical: "border-red-500",
    high: "border-orange-400",
    medium: "border-amber-400",
    low: "border-blue-400",
    info: "border-slate-600",
  },
  bar: {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-blue-500",
    info: "bg-slate-500",
  },
};

/** Raw hex, for contexts that cannot use utility classes (inline SVG, print). */
export const SEVERITY_HEX: Record<SeverityKey, string> = {
  critical: "#ef4444",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#60a5fa",
  info: "#94a3b8",
};

/** Coerce arbitrary input (null, casing, unknown values) to a known severity. */
export function normalizeSeverity(value: string | null | undefined): SeverityKey {
  const key = (value ?? "").toLowerCase() as SeverityKey;
  return key in SEVERITY_HEX ? key : "info";
}

/** Tailwind classes for a severity in the requested visual variant. */
export function severityClass(
  value: string | null | undefined,
  variant: SeverityVariant = "badge",
): string {
  return SEVERITY_CLASSES[variant][normalizeSeverity(value)];
}

/** Hex for a severity — falls back to the info grey. */
export function severityHex(value: string | null | undefined): string {
  return SEVERITY_HEX[normalizeSeverity(value)];
}

// ── Job status ──────────────────────────────────────────────────────────────

const JOB_STATUS_CLASSES: Record<string, string> = {
  completed: "text-emerald-400 bg-emerald-400/10",
  completed_with_errors: "text-amber-400 bg-amber-400/10",
  running: "text-blue-400 bg-blue-400/10",
  queued: "text-slate-300 bg-slate-400/10",
  failed: "text-red-400 bg-red-400/10",
  canceled: "text-slate-500 bg-slate-500/10",
  deleting: "text-slate-500 bg-slate-500/10",
  deleted: "text-slate-600 bg-slate-600/10",
};

export function jobStatusClass(status: string | null | undefined): string {
  return JOB_STATUS_CLASSES[status ?? ""] ?? "text-slate-400 bg-slate-400/10";
}

// ── Analyst triage status ───────────────────────────────────────────────────

const ANALYST_STATUS_CLASSES: Record<string, string> = {
  unreviewed: "text-slate-400",
  confirmed: "text-emerald-400",
  false_positive: "text-red-400",
  needs_review: "text-purple-400",
  deferred: "text-yellow-400",
};

export function analystStatusClass(status: string | null | undefined): string {
  return ANALYST_STATUS_CLASSES[status ?? ""] ?? "text-slate-400";
}

/** "false_positive" → "false positive" */
export function humanizeStatus(status: string | null | undefined): string {
  return (status ?? "unreviewed").replace(/_/g, " ");
}
