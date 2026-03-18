import React, { useState } from "react";
import { AnomalyFinding, AnomalyReport } from "../api";

interface AnomalyFindingsProps {
  anomalyReport: AnomalyReport | null;
  onAskAbout?: (query: string) => void;
}

const severityColors: Record<string, { bg: string; text: string; border: string; glow: string }> = {
  critical: { bg: "bg-red-900/30", text: "text-red-400", border: "border-red-500/50", glow: "shadow-[0_0_15px_rgba(239,68,68,0.3)]" },
  high: { bg: "bg-orange-900/30", text: "text-orange-400", border: "border-orange-500/50", glow: "shadow-[0_0_15px_rgba(249,115,22,0.3)]" },
  medium: { bg: "bg-yellow-900/30", text: "text-yellow-400", border: "border-yellow-500/50", glow: "" },
  low: { bg: "bg-slate-800/50", text: "text-slate-400", border: "border-slate-600/50", glow: "" },
};

const categoryLabels: Record<string, string> = {
  beacon: "BCN",
  dns_beacon: "DNS",
  volume: "VOL",
  port_scan: "SCN",
  lateral_movement: "LAT",
  tls_anomaly: "TLS",
  dns: "DNS",
  entropy: "ENT",
  temporal: "TMP",
  connection: "CON",
};

const likelihoodColors: Record<string, string> = {
  high: "text-red-400",
  medium: "text-orange-400",
  low: "text-yellow-400",
  none: "text-slate-400",
};

export const AnomalyFindings: React.FC<AnomalyFindingsProps> = ({ anomalyReport, onAskAbout }) => {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  if (!anomalyReport || anomalyReport.findings.length === 0) {
    return (
      <div className="text-slate-500 text-sm italic">
        No heuristic anomalies detected. This could indicate clean traffic or traffic that doesn't match known attack patterns.
      </div>
    );
  }

  const { findings, overall_anomaly_score, zero_day_likelihood, summary } = anomalyReport;

  return (
    <div className="space-y-6">
      {/* Summary Header */}
      <div className="flex items-center justify-between p-4 bg-slate-900/80 rounded-lg border border-slate-700">
        <div className="space-y-1">
          <div className="text-sm text-slate-400">Evasion Likelihood</div>
          <div className={`text-xl font-bold uppercase ${likelihoodColors[zero_day_likelihood] || "text-slate-400"}`}>
            {zero_day_likelihood}
          </div>
          <div className="text-[10px] text-slate-500">May evade signature detection</div>
        </div>
        <div className="text-right space-y-1">
          <div className="text-sm text-slate-400">Behavioral Score</div>
          <div className="text-xl font-bold text-slate-100">
            {(overall_anomaly_score * 100).toFixed(0)}%
          </div>
        </div>
        <div className="flex-1 mx-6">
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                overall_anomaly_score >= 0.7 ? "bg-red-500" :
                overall_anomaly_score >= 0.5 ? "bg-orange-500" :
                overall_anomaly_score >= 0.3 ? "bg-yellow-500" : "bg-green-500"
              }`}
              style={{ width: `${overall_anomaly_score * 100}%` }}
            />
          </div>
        </div>
        <div className="text-sm text-slate-400">
          {findings.length} finding{findings.length !== 1 ? "s" : ""}
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {findings.map((finding, index) => {
          const colors = severityColors[finding.severity] || severityColors.low;
          const tag = categoryLabels[finding.category] || "—";
          const isExpanded = expandedIndex === index;

          return (
            <div
              key={index}
              className={`${colors.bg} ${colors.border} border rounded-lg overflow-hidden transition-all duration-200 ${colors.glow}`}
            >
              {/* Header - always visible */}
              <div
                className="p-4 cursor-pointer hover:bg-white/5 transition-colors"
                onClick={() => setExpandedIndex(isExpanded ? null : index)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono font-bold text-slate-400 bg-slate-800 rounded px-1.5 py-0.5">{tag}</span>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-bold uppercase tracking-wider ${colors.text}`}>
                          {finding.severity}
                        </span>
                        <span className="text-xs text-slate-500">•</span>
                        <span className="text-xs text-slate-400 uppercase tracking-wide">
                          {finding.category.replace("_", " ")}
                        </span>
                      </div>
                      <div className="text-slate-200 font-medium mt-1">{finding.description}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-xs text-slate-400">
                      {(finding.confidence * 100).toFixed(0)}% confidence
                    </div>
                    <svg
                      className={`w-5 h-5 text-slate-400 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </div>
                </div>
              </div>

              {/* Expanded content */}
              {isExpanded && (
                <div className="px-4 pb-4 space-y-4 border-t border-slate-700/50">
                  {/* Evidence */}
                  {finding.evidence.length > 0 && (
                    <div className="pt-4">
                      <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Evidence</div>
                      <ul className="space-y-1">
                        {finding.evidence.map((ev, i) => (
                          <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                            <span className="text-slate-500">•</span>
                            <span className="font-mono text-xs">{ev}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Affected Hosts */}
                  {finding.affected_hosts.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Affected Hosts</div>
                      <div className="flex flex-wrap gap-2">
                        {finding.affected_hosts.map((host, i) => (
                          <span key={i} className="px-2 py-1 bg-slate-800 rounded text-xs font-mono text-emerald-400">
                            {host}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Chain of Thought */}
                  {finding.chain_of_thought && (
                    <div>
                      <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Forensic Analysis</div>
                      <div className="bg-slate-950/50 border border-slate-800/50 rounded p-3 max-h-64 overflow-y-auto">
                        <pre className="text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">
                          {finding.chain_of_thought}
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  {onAskAbout && (
                    <div className="flex justify-end pt-2">
                      <button
                        onClick={() => onAskAbout(
                          `Explain this anomaly in detail and provide remediation steps: ${finding.description}. ` +
                          `Evidence: ${finding.evidence.join(", ")}`
                        )}
                        className="text-xs uppercase tracking-widest text-blue-400 hover:text-blue-300 transition-colors flex items-center gap-1"
                      >
                        Investigate Further <span>→</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

