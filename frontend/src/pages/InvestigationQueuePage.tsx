import React, { useMemo, useState, useEffect } from "react";
import { useParams, Link, useSearchParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type AnalystStatus,
  type QueueItemSource,
  type InvestigationQueueItem,
  type Severity,
} from "../api";
import { useToast } from "../components/ToastProvider";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { EvidenceDrawer } from "../components/EvidenceDrawer";
import { InfoTooltip } from "../components/InfoTooltip";

// ─── Constants ───────────────────────────────────────────────────────────────

const STATUS_OPTIONS: { value: AnalystStatus | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "unreviewed", label: "Unreviewed" },
  { value: "confirmed", label: "Confirmed" },
  { value: "false_positive", label: "False Positive" },
  { value: "deferred", label: "Deferred" },
];

const SOURCE_OPTIONS: { value: QueueItemSource | ""; label: string }[] = [
  { value: "", label: "All Sources" },
  { value: "finding", label: "Findings" },
  { value: "alert", label: "Alerts" },
  { value: "theory", label: "Theories" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-white",
  low: "bg-blue-600 text-white",
  info: "bg-slate-600 text-slate-200",
};

const STATUS_COLORS: Record<string, string> = {
  unreviewed: "text-slate-400",
  confirmed: "text-emerald-400",
  false_positive: "text-red-400",
  deferred: "text-yellow-400",
};

const SOURCE_ICONS: Record<string, string> = {
  finding: "🔍",
  alert: "🚨",
  theory: "💡",
};

// ─── Badge helpers ────────────────────────────────────────────────────────────

function ItemBadges({ item }: { item: InvestigationQueueItem }) {
  const badges: { label: string; cls: string; tooltip?: string }[] = [];
  if (item.pcap_label === "after") {
    badges.push({ label: "New in After", cls: "bg-purple-700/60 text-purple-200 border-purple-600/40" });
  }
  if (item.corroborating_count > 0) {
    badges.push({
      label: `${item.corroborating_count} corroborating`,
      cls: "bg-cyan-700/60 text-cyan-200 border-cyan-600/40",
      tooltip: "Other findings/alerts sharing evidence with this item. More corroboration = higher confidence it's real.",
    });
  }
  if (item.affected_hosts_count >= 3) {
    badges.push({
      label: `${item.affected_hosts_count} hosts`,
      cls: "bg-amber-700/60 text-amber-200 border-amber-600/40",
      tooltip: "Blast radius — number of distinct hosts affected. High blast radius suggests lateral movement or widespread impact.",
    });
  }
  if (item.mitre_ids.length > 0) {
    badges.push({
      label: item.mitre_ids[0],
      cls: "bg-indigo-700/60 text-indigo-200 border-indigo-600/40",
      tooltip: "MITRE ATT&CK technique ID mapping this behavior to a known adversary tactic.",
    });
  }
  if (badges.length === 0) return null;
  return (
    <span className="inline-flex gap-1 ml-2">
      {badges.map(b => (
        b.tooltip ? (
          <InfoTooltip key={b.label} text={b.tooltip}>
            <span className={`text-[9px] px-1 py-0.5 rounded border ${b.cls}`}>{b.label}</span>
          </InfoTooltip>
        ) : (
          <span key={b.label} className={`text-[9px] px-1 py-0.5 rounded border ${b.cls}`}>{b.label}</span>
        )
      ))}
    </span>
  );
}

// ─── Component ───────────────────────────────────────────────────────────────

export const InvestigationQueuePage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const [searchParams, setSearchParams] = useSearchParams();

  // URL-persisted filters
  const statusFilter = (searchParams.get("status") ?? "") as AnalystStatus | "";
  const sourceFilter = (searchParams.get("source") ?? "") as QueueItemSource | "";
  const searchQuery = searchParams.get("q") ?? "";
  const hostFilter = searchParams.get("host") ?? "";
  const mitreFilter = searchParams.get("mitre") ?? "";
  const corrobOnly = searchParams.get("corroboration") === "true";

  const setFilter = (key: string, val: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (val) next.set(key, val); else next.delete(key);
      return next;
    }, { replace: true });
  };

  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [drawerItemId, setDrawerItemId] = useState<string | null>(null);

  // Fetch queue
  const { data, isLoading, error } = useQuery({
    queryKey: ["investigation-queue", jobId, statusFilter, sourceFilter, searchQuery, hostFilter, mitreFilter, corrobOnly],
    queryFn: () =>
      api.getInvestigationQueue(jobId!, {
        status: statusFilter || undefined,
        source: sourceFilter || undefined,
        q: searchQuery || undefined,
        host: hostFilter || undefined,
        mitre_id: mitreFilter || undefined,
        has_corroboration: corrobOnly || undefined,
        limit: 500,
      }),
    enabled: !!jobId,
  });

  const items = data?.items ?? [];
  const summary = data?.summary;

  // Unique hosts & MITRE IDs for filter dropdowns
  const uniqueHosts = useMemo(() => {
    const s = new Set<string>();
    items.forEach((i) => i.affected_hosts.forEach((h) => s.add(h)));
    return [...s].sort();
  }, [items]);

  const uniqueMitre = useMemo(() => {
    const s = new Set<string>();
    items.forEach((i) => i.mitre_ids.forEach((m) => s.add(m)));
    return [...s].sort();
  }, [items]);

  // Status update mutation
  const statusMut = useMutation({
    mutationFn: ({ itemId, status, notes }: { itemId: string; status: AnalystStatus; notes?: string }) =>
      api.updateQueueItemStatus(jobId!, itemId, { analyst_status: status, analyst_notes: notes }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["investigation-queue", jobId] });
      addToast({ severity: "info", title: "Status updated", duration: 2000 });
    },
    onError: () => addToast({ severity: "high", title: "Failed to update status" }),
  });

  // Bulk update
  const bulkMut = useMutation({
    mutationFn: (status: AnalystStatus) =>
      api.bulkUpdateQueueStatus(jobId!, { item_ids: [...selectedItems], analyst_status: status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["investigation-queue", jobId] });
      setSelectedItems(new Set());
      addToast({ severity: "info", title: "Bulk status updated", duration: 2000 });
    },
    onError: () => addToast({ severity: "high", title: "Bulk update failed" }),
  });

  const toggleSelect = (id: string) => {
    setSelectedItems((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedItems.size === items.length) {
      setSelectedItems(new Set());
    } else {
      setSelectedItems(new Set(items.map((i) => i.item_id)));
    }
  };

  const getSourceLink = (item: InvestigationQueueItem) => {
    if (item.source_type === "finding") return `/jobs/${jobId}/findings/${item.source_id}`;
    if (item.source_type === "alert") return `/jobs/${jobId}/alerts/${item.source_id}`;
    if (item.source_type === "theory") return `/jobs/${jobId}/theories#theory-${item.source_id}`;
    return "#";
  };

  if (!jobId) return <p className="text-red-400">Missing job ID</p>;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link to={`/jobs/${jobId}`} className="text-xs text-slate-500 hover:text-slate-300">← Job Detail</Link>
          <h1 className={`text-xl font-semibold text-slate-100 ${labelHint("investigation_queue", activeHelpField)}`}
            onClick={() => toggleHelp("investigation_queue")}>Investigation Queue</h1>
        </div>
        <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
      </div>

      {/* Summary bar */}
      {summary && (
        <div className="grid grid-cols-5 gap-2 text-center text-sm">
          {[
            { label: "Total", count: summary.total, color: "text-slate-200" },
            { label: "Unreviewed", count: summary.unreviewed, color: "text-slate-400" },
            { label: "Confirmed", count: summary.confirmed, color: "text-emerald-400" },
            { label: "False Positive", count: summary.false_positive, color: "text-red-400" },
            { label: "Deferred", count: summary.deferred, color: "text-yellow-400" },
          ].map((s) => (
            <div key={s.label} className="bg-slate-900/50 border border-slate-800 rounded-lg p-2">
              <div className={`text-lg font-bold ${s.color}`}>{s.count}</div>
              <div className="text-xs text-slate-500">{s.label}</div>
            </div>
          ))}
        </div>
      )}
      {/* Filters — row 1 */}
      <div className="flex flex-wrap gap-3 items-center">
        <select value={statusFilter} onChange={(e) => setFilter("status", e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
          {STATUS_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <select value={sourceFilter} onChange={(e) => setFilter("source", e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
          {SOURCE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <input type="text" placeholder="Search title, description, category…"
          value={searchQuery} onChange={(e) => setFilter("q", e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded px-3 py-1 text-sm text-slate-300 flex-1 min-w-[200px]" />
      </div>
      {/* Filters — row 2 (new Sprint 2 filters) */}
      <div className="flex flex-wrap gap-3 items-center">
        {uniqueHosts.length > 0 && (
          <select value={hostFilter} onChange={(e) => setFilter("host", e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
            <option value="">All Hosts</option>
            {uniqueHosts.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
        )}
        {uniqueMitre.length > 0 && (
          <select value={mitreFilter} onChange={(e) => setFilter("mitre", e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-300">
            <option value="">All MITRE</option>
            {uniqueMitre.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        )}
        <label className="flex items-center gap-1.5 text-xs text-slate-400 cursor-pointer select-none">
          <input type="checkbox" checked={corrobOnly}
            onChange={(e) => setFilter("corroboration", e.target.checked ? "true" : "")}
            className="rounded border-slate-600" />
          Corroborated only
        </label>
      </div>

      {/* Bulk actions */}
      {selectedItems.size > 0 && (
        <div className="flex items-center gap-2 bg-slate-900/80 border border-slate-700 rounded-lg px-3 py-2 text-sm">
          <span className="text-slate-400">{selectedItems.size} selected</span>
          <button onClick={() => bulkMut.mutate("confirmed")} className="px-2 py-1 bg-emerald-700 hover:bg-emerald-600 rounded text-xs text-white">
            ✓ Confirm
          </button>
          <button onClick={() => bulkMut.mutate("false_positive")} className="px-2 py-1 bg-red-700 hover:bg-red-600 rounded text-xs text-white">
            ✗ False Positive
          </button>
          <button onClick={() => bulkMut.mutate("deferred")} className="px-2 py-1 bg-yellow-700 hover:bg-yellow-600 rounded text-xs text-white">
            ⏸ Defer
          </button>
          <button onClick={() => setSelectedItems(new Set())} className="px-2 py-1 text-slate-400 hover:text-slate-200 text-xs">
            Clear
          </button>
        </div>
      )}

      {/* Loading / Error */}
      {isLoading && <p className="text-slate-400 animate-pulse">Loading investigation queue…</p>}
      {error && <p className="text-red-400">Failed to load queue.</p>}

      {/* Queue table */}
      {!isLoading && !error && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left text-xs text-slate-500 uppercase">
                <th className="p-2 w-8">
                  <input type="checkbox" checked={selectedItems.size === items.length && items.length > 0} onChange={toggleSelectAll} />
                </th>
                <th className="p-2 w-10">#</th>
                <th className="p-2 w-16">Score <InfoTooltip text="Composite priority (0–100) from Severity 30%, Confidence 25%, Corroboration 20%, Blast Radius 15%, Recency 10%." /></th>
                <th className="p-2 w-10">Type</th>
                <th className="p-2 w-20">Severity</th>
                <th className="p-2">Title</th>
                <th className="p-2 w-24">Confidence <InfoTooltip text="How certain the engine is this represents a real threat (0–100%). Higher = more reliable detection." /></th>
                <th className="p-2 w-28">Status</th>
                <th className="p-2 w-32">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <React.Fragment key={item.item_id}>
                  <tr
                    className={`border-b border-slate-800/50 hover:bg-slate-900/60 transition-colors cursor-pointer ${
                      item.analyst_status === "false_positive" ? "opacity-50" : ""
                    } ${drawerItemId === item.item_id ? "bg-slate-900/80 border-l-2 border-l-cyan-500" : ""}`}
                    onClick={() => setDrawerItemId(drawerItemId === item.item_id ? null : item.item_id)}
                  >
                    <td className="p-2" onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selectedItems.has(item.item_id)} onChange={() => toggleSelect(item.item_id)} />
                    </td>
                    <td className="p-2 text-slate-500 font-mono text-xs">{item.rank_position}</td>
                    <td className="p-2">
                      <div className="flex items-center gap-1">
                        <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-gradient-to-r from-blue-500 to-red-500 rounded-full"
                            style={{ width: `${Math.round(item.rank_score * 100)}%` }} />
                        </div>
                        <span className="text-xs text-slate-400 font-mono">{(item.rank_score * 100).toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="p-2 text-lg" title={item.source_type}>{SOURCE_ICONS[item.source_type] ?? "?"}</td>
                    <td className="p-2">
                      <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${SEV_COLORS[item.severity] ?? SEV_COLORS.info}`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="p-2">
                      <div className="flex items-center flex-wrap">
                        <Link to={getSourceLink(item)} className="text-slate-200 hover:text-white hover:underline"
                          onClick={(e) => e.stopPropagation()}>
                          {item.title}
                        </Link>
                        {item.category && <span className="ml-2 text-xs text-slate-500">[{item.category}]</span>}
                        {item.sensor && <span className="ml-1 text-xs text-slate-600">({item.sensor})</span>}
                        <ItemBadges item={item} />
                      </div>
                    </td>
                    <td className="p-2 text-xs text-slate-400 font-mono">{(item.confidence * 100).toFixed(0)}%</td>
                    <td className="p-2">
                      <span className={`text-xs font-medium ${STATUS_COLORS[item.analyst_status] ?? "text-slate-400"}`}>
                        {item.analyst_status.replace("_", " ")}
                      </span>
                    </td>
                    <td className="p-2" onClick={(e) => e.stopPropagation()}>
                      <div className="flex gap-1">
                        {item.analyst_status !== "confirmed" && (
                          <button onClick={() => statusMut.mutate({ itemId: item.item_id, status: "confirmed" })}
                            className="px-1.5 py-0.5 bg-emerald-800 hover:bg-emerald-700 rounded text-xs text-emerald-200"
                            title="Confirm">✓</button>
                        )}
                        {item.analyst_status !== "false_positive" && (
                          <button onClick={() => statusMut.mutate({ itemId: item.item_id, status: "false_positive" })}
                            className="px-1.5 py-0.5 bg-red-900 hover:bg-red-800 rounded text-xs text-red-200"
                            title="False Positive">✗</button>
                        )}
                        {item.analyst_status !== "deferred" && (
                          <button onClick={() => statusMut.mutate({ itemId: item.item_id, status: "deferred" })}
                            className="px-1.5 py-0.5 bg-yellow-900 hover:bg-yellow-800 rounded text-xs text-yellow-200"
                            title="Defer">⏸</button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {/* Evidence drawer — inline below the row */}
                  {drawerItemId === item.item_id && (
                    <tr>
                      <td colSpan={9} className="p-0">
                        <EvidenceDrawer jobId={jobId} itemId={item.item_id}
                          isOpen={true} onClose={() => setDrawerItemId(null)} />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
          {items.length === 0 && (
            <p className="text-center text-slate-500 py-8">No items in the investigation queue.</p>
          )}
        </div>
      )}
    </div>
  );
};

