import React from "react";

import type { FindingExplainEvidenceItem, FindingExplainSection } from "../../api";
import {
  buildExplainCitationButtonTestId,
  buildExplainEvidenceTargetId,
  buildExplainEvidenceTestId,
} from "../../findingsExplain";

type ExplainDensity = "compact" | "default";

const SECTION_STYLES: Record<ExplainDensity, {
  heading: string;
  body: string;
  bulletList: string;
  bulletItem: string;
  bulletDot: string;
  citationWrap: string;
}> = {
  compact: {
    heading: "text-[11px] font-semibold uppercase tracking-wider text-slate-400",
    body: "text-xs leading-6 text-slate-300",
    bulletList: "space-y-1.5",
    bulletItem: "flex items-start gap-2 text-xs leading-6 text-slate-300",
    bulletDot: "mt-1 text-slate-500",
    citationWrap: "flex flex-wrap gap-1 pt-1",
  },
  default: {
    heading: "text-xs font-semibold uppercase tracking-wider text-slate-400",
    body: "text-sm leading-6 text-slate-300",
    bulletList: "space-y-2",
    bulletItem: "flex items-start gap-2 text-sm leading-6 text-slate-300",
    bulletDot: "mt-1 text-slate-500",
    citationWrap: "flex flex-wrap gap-1.5 pt-1",
  },
};

const EVIDENCE_STYLES: Record<ExplainDensity, {
  heading: string;
  item: string;
  body: string;
  citation: string;
  empty: string;
}> = {
  compact: {
    heading: "text-[11px] font-semibold uppercase tracking-wider text-slate-400",
    item: "rounded border p-2 transition-colors",
    body: "text-xs leading-6 text-slate-300",
    citation: "mt-1 text-[10px] text-slate-500 font-mono",
    empty: "text-xs text-slate-500",
  },
  default: {
    heading: "text-xs font-semibold uppercase tracking-wider text-slate-400",
    item: "rounded border p-3 transition-colors",
    body: "text-sm leading-6 text-slate-300",
    citation: "mt-1 font-mono text-[10px] text-slate-500",
    empty: "text-sm text-slate-500",
  },
};

export function ConfidenceBadge({
  value,
  density = "default",
  showLabel = false,
}: {
  value: number;
  density?: ExplainDensity;
  showLabel?: boolean;
}) {
  const pct = Math.round(value * 100);
  const color =
    value >= 0.7
      ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
      : value >= 0.4
        ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
        : "text-red-400 bg-red-500/10 border-red-500/20";
  const padding = density === "compact" ? "px-1.5 py-0.5" : "px-2 py-0.5";

  return (
    <span className={`${padding} rounded text-[10px] font-mono font-medium border ${color}`} title={`Confidence: ${pct}%`}>
      {showLabel ? `${pct}% confidence` : `${pct}%`}
    </span>
  );
}

export function ExplainSectionBlock({
  section,
  findingId,
  actionableCitations,
  onCitationClick,
  density = "default",
  headingLevel = "h4",
}: {
  section: FindingExplainSection;
  findingId: string;
  actionableCitations: Set<string>;
  onCitationClick: (citation: string) => void;
  density?: ExplainDensity;
  headingLevel?: "h4" | "h5";
}) {
  const HeadingTag = headingLevel;
  const styles = SECTION_STYLES[density];

  return (
    <section className="space-y-2">
      <HeadingTag className={styles.heading}>{section.title}</HeadingTag>
      {section.body && <p className={styles.body}>{section.body}</p>}
      {section.bullets.length > 0 && (
        <ul className={styles.bulletList}>
          {section.bullets.map((bullet) => (
            <li key={bullet} className={styles.bulletItem}>
              <span className={styles.bulletDot}>•</span>
              <span>{bullet}</span>
            </li>
          ))}
        </ul>
      )}
      {section.citations.length > 0 && (
        <div className={styles.citationWrap}>
          {section.citations.map((citation) => {
            const actionable = actionableCitations.has(citation);
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
                onClick={() => onCitationClick(citation)}
                title="Jump to supporting evidence"
                data-testid={buildExplainCitationButtonTestId(findingId, citation)}
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
}

export function ExplainEvidenceList({
  findingId,
  evidenceItems,
  citationIndexByCitation,
  highlightedCitation,
  density = "default",
  headingLevel = "h4",
  includeHighlightDataAttribute = false,
}: {
  findingId: string;
  evidenceItems?: FindingExplainEvidenceItem[];
  citationIndexByCitation: Map<string, number>;
  highlightedCitation?: string;
  density?: ExplainDensity;
  headingLevel?: "h4" | "h5";
  includeHighlightDataAttribute?: boolean;
}) {
  const HeadingTag = headingLevel;
  const styles = EVIDENCE_STYLES[density];

  return (
    <section className="space-y-2">
      <HeadingTag className={styles.heading}>Supporting evidence</HeadingTag>
      {(evidenceItems?.length ?? 0) > 0 ? (
        <ul className="space-y-2">
          {evidenceItems?.map((item, index) => {
            const isPrimaryEvidenceTarget = citationIndexByCitation.get(item.citation) === index;
            const isHighlighted = highlightedCitation === item.citation;

            return (
              <li
                key={`${item.citation}:${item.label}`}
                id={isPrimaryEvidenceTarget ? buildExplainEvidenceTargetId(findingId, item.citation) : undefined}
                tabIndex={isPrimaryEvidenceTarget ? -1 : undefined}
                data-testid={isPrimaryEvidenceTarget ? buildExplainEvidenceTestId(findingId, item.citation) : undefined}
                data-highlighted={includeHighlightDataAttribute && isHighlighted ? "true" : undefined}
                className={`${styles.item} ${isHighlighted ? "border-cyan-500/40 bg-cyan-500/10" : "border-slate-800 bg-slate-900/60"}`}
              >
                <p className={styles.body}>
                  <span className="font-medium text-slate-200">{item.label}:</span>{" "}
                  {item.value}
                </p>
                <div className={styles.citation}>{item.citation}</div>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className={styles.empty}>No structured evidence was stored for this finding.</p>
      )}
    </section>
  );
}