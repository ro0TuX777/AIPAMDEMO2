/**
 * EvidenceDrawer — expandable panel showing corroborating evidence for an investigation queue item.
 * Fetches the evidence bundle on expand and displays tabbed sections: Findings | Alerts | Connections | Timeline.
 */
import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api, type EvidenceBundleResponse } from "../api";
import { severityClass } from "../theme/colors";

type TabKey = "findings" | "alerts" | "connections" | "timeline";

const TABS: { key: TabKey; label: string; icon: string }[] = [
  { key: "findings", label: "Findings", icon: "🔍" },
  { key: "alerts", label: "Alerts", icon: "⚠️" },
  { key: "connections", label: "Connections", icon: "🔗" },
  { key: "timeline", label: "Timeline", icon: "📅" },
];

interface EvidenceDrawerProps {
  jobId: string;
  itemId: string;
  isOpen: boolean;
  onClose: () => void;
}

export function EvidenceDrawer({ jobId, itemId, isOpen, onClose }: EvidenceDrawerProps) {
  const [bundle, setBundle] = useState<EvidenceBundleResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("findings");

  useEffect(() => {
    if (!isOpen) return;
    setLoading(true);
    setError(null);
    api.getEvidenceBundle(jobId, itemId)
      .then(setBundle)
      .catch(() => setError("Failed to load evidence bundle"))
      .finally(() => setLoading(false));
  }, [isOpen, jobId, itemId]);

  if (!isOpen) return null;

  const counts: Record<TabKey, number> = {
    findings: bundle?.related_findings.length ?? 0,
    alerts: bundle?.related_alerts.length ?? 0,
    connections: bundle?.related_connections.length ?? 0,
    timeline: bundle?.timeline_events.length ?? 0,
  };

  return (
    <div className="mt-2 bg-slate-950 border border-slate-700 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-slate-800/60 border-b border-slate-700">
        <span className="text-xs font-semibold text-slate-300">Corroborating Evidence</span>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-200 text-sm">✕</button>
      </div>

      {loading && (
        <div className="p-6 text-center text-sm text-slate-500 animate-pulse">Loading evidence bundle…</div>
      )}
      {error && (
        <div className="p-4 text-center text-sm text-red-400">{error}</div>
      )}

      {bundle && !loading && (
        <>
          {/* Tabs */}
          <div className="flex border-b border-slate-700">
            {TABS.map(t => (
              <button key={t.key} onClick={() => setActiveTab(t.key)}
                className={`flex-1 px-3 py-2 text-xs font-medium transition-colors ${activeTab === t.key
                  ? "text-cyan-400 border-b-2 border-cyan-400 bg-slate-900"
                  : "text-slate-500 hover:text-slate-300"}`}>
                {t.icon} {t.label} <span className="ml-1 text-[10px] text-slate-600">({counts[t.key]})</span>
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="p-3 max-h-72 overflow-y-auto space-y-2">
            {counts[activeTab] === 0 && (
              <div className="text-center py-4 text-xs text-slate-500">No {activeTab} found for shared hosts.</div>
            )}

            {activeTab === "findings" && bundle.related_findings.map((f, i) => (
              <Link key={i} to={`/jobs/${jobId}/findings/${encodeURIComponent(f.finding_id)}`}
                className="block p-2 rounded bg-slate-900 border border-slate-800 hover:border-slate-600 transition-colors">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass(f.severity)}`}>{f.severity?.toUpperCase()}</span>
                  <span className="text-xs text-slate-200 truncate">{f.title}</span>
                </div>
                {f.category && <span className="text-[10px] text-slate-500 mt-0.5 block">{f.category}</span>}
              </Link>
            ))}

            {activeTab === "alerts" && bundle.related_alerts.map((a, i) => (
              <Link key={i} to={`/jobs/${jobId}/alerts/${encodeURIComponent(a.alert_id)}`}
                className="block p-2 rounded bg-slate-900 border border-slate-800 hover:border-slate-600 transition-colors">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass(a.severity)}`}>{a.severity?.toUpperCase()}</span>
                  <span className="text-xs text-slate-200 truncate">{a.signature}</span>
                </div>
                <span className="text-[10px] text-slate-500 mt-0.5 block">{a.src_ip} → {a.dest_ip} · {a.ts}</span>
              </Link>
            ))}

            {activeTab === "connections" && bundle.related_connections.map((c, i) => (
              <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 text-xs">
                <span className="text-slate-300 font-mono">{c.src_ip} → {c.dest_ip}</span>
                <span className="text-slate-500 ml-2">{c.proto}{c.service ? ` / ${c.service}` : ""}</span>
                <span className="text-slate-600 ml-2">{c.ts}</span>
              </div>
            ))}

            {activeTab === "timeline" && bundle.timeline_events.map((te, i) => (
              <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800 text-xs">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass(te.severity)}`}>{te.type}</span>
                  <span className="text-slate-200">{te.title}</span>
                </div>
                <span className="text-[10px] text-slate-600 block mt-0.5">{te.ts}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function sevClass(s: string | null | undefined): string {
  return severityClass(s, "outline");
}

