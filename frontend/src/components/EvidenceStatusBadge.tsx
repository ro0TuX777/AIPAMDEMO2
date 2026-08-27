import React from "react";
import type { FindingItem } from "../api";

/**
 * Shows how strongly a finding is backed by evidence outside the capture.
 *
 * `evidence_status` is written by the temporal correlator when uploaded logs
 * line up with the finding: "confirmed" means a ground-truth source (a C2
 * operator log recording what was actually run) attests to it, "corroborated"
 * means some other uploaded perspective — EVTX, router syslog — lines up.
 *
 * Falls back to the legacy c2_fusion sensor/category signal for findings
 * produced before correlation ran.
 */
export function EvidenceStatusBadge({
  finding,
  compact = false,
}: {
  finding: Pick<FindingItem, "evidence_status" | "corroborating_sources" | "sensor" | "category">;
  compact?: boolean;
}) {
  const size = compact
    ? "px-1.5 py-0.5 text-[9px]"
    : "px-2 py-0.5 text-[10px]";
  const sources = finding.corroborating_sources ?? [];
  const sourceHint = sources.length ? ` — ${sources.join(", ")}` : "";

  if (finding.evidence_status === "confirmed") {
    return (
      <span
        className={`inline-flex ${size} font-semibold border rounded text-green-200 bg-green-900/50 border-green-600`}
        title={`Confirmed against ground-truth logs${sourceHint}`}
      >
        GROUND TRUTH
      </span>
    );
  }

  if (finding.evidence_status === "corroborated") {
    return (
      <span
        className={`inline-flex ${size} font-semibold border rounded text-emerald-300 bg-emerald-900/40 border-emerald-700`}
        title={`Corroborated by uploaded logs${sourceHint}`}
      >
        CORROBORATED
      </span>
    );
  }

  // Legacy signals — findings synthesised by the C2 fusion sensor itself.
  if (finding.sensor === "c2_fusion") {
    return (
      <span
        className={`inline-flex ${size} font-semibold border rounded text-green-300 bg-green-900/40 border-green-700`}
        title="Produced by cross-source C2 fusion"
      >
        C2 CONFIRMED
      </span>
    );
  }
  if (finding.category?.startsWith("c2_confirmed")) {
    return (
      <span
        className={`inline-flex ${size} font-semibold border rounded text-emerald-300 bg-emerald-900/40 border-emerald-700`}
        title="Cross-source corroborated"
      >
        CORROBORATED
      </span>
    );
  }
  return null;
}
