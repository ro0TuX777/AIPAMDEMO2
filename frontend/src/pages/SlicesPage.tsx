import React, { useState, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  api,
  type SliceItem,
  type SliceType,
  type TheoryItem,
  type AlertItem,
  type FindingItem,
  type IocItem,
} from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";
import { CardGridSkeleton } from "../components/SkeletonLoader";

// ── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-900/40 text-red-300 border-red-700",
  high: "bg-orange-900/40 text-orange-300 border-orange-700",
  medium: "bg-amber-900/40 text-amber-300 border-amber-700",
  low: "bg-slate-800 text-slate-400 border-slate-600",
  info: "bg-slate-800 text-slate-500 border-slate-700",
};

const SEV_BAR_COLORS: Record<string, string> = {
  critical: "bg-red-500", high: "bg-orange-500", medium: "bg-amber-500",
  low: "bg-blue-500", info: "bg-slate-500",
};

const TYPE_LABELS: Record<string, string> = {
  attack_thread: "ATK", c2_session: "C2", recon_phase: "RCN",
  lateral: "LAT", exfil: "EXF", misc: "MSC",
};

const TYPE_FULL: Record<string, string> = {
  attack_thread: "Attack Thread", c2_session: "C2 Session", recon_phase: "Reconnaissance",
  lateral: "Lateral Movement", exfil: "Exfiltration", misc: "Miscellaneous",
};

// 3️⃣ MITRE ATT&CK mapping for slice types
const MITRE_MAP: Record<string, { tactic: string; id: string }> = {
  c2_session: { tactic: "Command and Control", id: "TA0011" },
  recon_phase: { tactic: "Reconnaissance", id: "TA0043" },
  lateral: { tactic: "Lateral Movement", id: "TA0008" },
  exfil: { tactic: "Exfiltration", id: "TA0010" },
  attack_thread: { tactic: "Execution", id: "TA0002" },
};

// ── Helpers ──────────────────────────────────────────────────────────────────

// 6️⃣ Format ISO timestamp to readable string
function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "?";
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });
  } catch { return iso.slice(0, 19); }
}

function durationStr(start: string | null | undefined, end: string | null | undefined): string {
  if (!start || !end) return "";
  try {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    if (ms < 0) return "";
    const sec = Math.floor(ms / 1000);
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min} min`;
    const hr = Math.floor(min / 60);
    return `${hr}h ${min % 60}m`;
  } catch { return ""; }
}

// ── Sub-components ───────────────────────────────────────────────────────────

function MitreBadge({ sliceType }: { sliceType: string }) {
  const m = MITRE_MAP[sliceType];
  if (!m) return null;
  return (
    <a href={`https://attack.mitre.org/tactics/${m.id}/`} target="_blank" rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono bg-indigo-900/40 text-indigo-300 border border-indigo-700 rounded hover:bg-indigo-900/60"
      title={m.tactic}>
      {m.id}
    </a>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100);
  const color = confidence >= 0.7 ? "bg-green-500" : confidence >= 0.4 ? "bg-amber-500" : "bg-slate-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-500">{pct}%</span>
    </div>
  );
}

// Lookup maps for friendly names
type NameMap = Record<string, string>;

// 2️⃣ Clickable evidence chips with deep links & friendly names
function EvidenceChips({ ids, type, jobId, nameMap }: {
  ids: string[]; type: "alert" | "finding" | "ioc"; jobId: string; nameMap: NameMap;
}) {
  if (!ids.length) return null;
  const label = type === "alert" ? "ALR" : type === "finding" ? "FND" : "IOC";
  const maxShow = 5;
  const shown = ids.slice(0, maxShow);
  const extra = ids.length - maxShow;
  return (
    <div className="flex flex-wrap gap-1">
      {shown.map(id => {
        const href = type === "alert" ? `/jobs/${jobId}/alerts/${encodeURIComponent(id)}`
          : type === "finding" ? `/jobs/${jobId}/findings/${encodeURIComponent(id)}`
          : `/jobs/${jobId}/iocs`;
        const friendlyName = nameMap[id] || id;
        return (
          <Link key={id} to={href}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700"
            title={friendlyName}>
            <span className="font-mono opacity-60">{label}</span>
            <span className="truncate max-w-[180px]">{friendlyName}</span>
          </Link>
        );
      })}
      {extra > 0 && (
        <Link to={type === "alert" ? `/jobs/${jobId}/alerts` : type === "finding" ? `/jobs/${jobId}/findings` : `/jobs/${jobId}/iocs`}
          className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-400 hover:bg-slate-700 border border-slate-700">
          +{extra} more
        </Link>
      )}
    </div>
  );
}

// 5️⃣ Evidence summary bar
function EvidenceSummaryBar({ slices }: { slices: SliceItem[] }) {
  const stats = useMemo(() => {
    let alerts = 0, findings = 0, iocs = 0, conns = 0;
    const hostSet = new Set<string>();
    for (const s of slices) {
      alerts += s.alert_ids.length;
      findings += s.finding_ids.length;
      iocs += s.ioc_ids.length;
      conns += s.connection_ids.length;
      s.host_ips.forEach(ip => hostSet.add(ip));
    }
    return { alerts, findings, iocs, conns, hosts: hostSet.size, count: slices.length };
  }, [slices]);
  if (!slices.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-4 px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-lg text-xs">
      <span className="text-slate-400">{stats.count} slice{stats.count !== 1 ? "s" : ""}</span>
      <span className="text-orange-400">{stats.alerts} alerts</span>
      <span className="text-amber-400">{stats.findings} findings</span>
      <span className="text-red-400">{stats.iocs} IOCs</span>
      <span className="text-cyan-400">{stats.hosts} hosts</span>
    </div>
  );
}

// 7️⃣ Severity distribution mini-chart
function SeverityChart({ slices }: { slices: SliceItem[] }) {
  const dist = useMemo(() => {
    const m: Record<string, number> = {};
    for (const s of slices) m[s.severity] = (m[s.severity] || 0) + 1;
    return Object.entries(m).sort(([a], [b]) => {
      const order = ["critical", "high", "medium", "low", "info"];
      return order.indexOf(a) - order.indexOf(b);
    });
  }, [slices]);
  if (!dist.length) return null;
  const max = Math.max(...dist.map(([, c]) => c), 1);
  return (
    <div className="bg-slate-800/40 border border-slate-700 rounded-lg p-4">
      <h3 className="text-xs text-slate-500 uppercase mb-3">Severity Distribution</h3>
      <div className="space-y-2">
        {dist.map(([sev, count]) => (
          <div key={sev} className="flex items-center gap-2">
            <span className="w-14 text-right text-[10px] text-slate-500 capitalize">{sev}</span>
            <div className="flex-1 h-3 bg-slate-700/60 rounded-full overflow-hidden">
              <div className={`h-full rounded-full ${SEV_BAR_COLORS[sev] || "bg-slate-500"} opacity-80`}
                style={{ width: `${(count / max) * 100}%` }} />
            </div>
            <span className="w-6 text-right text-[10px] text-slate-400">{count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// 10️⃣ Mini network flow diagram
function FlowDiagram({ hostIps }: { hostIps: string[] }) {
  if (hostIps.length < 2) return null;
  // Show first IP as source, rest as destinations (simplified)
  const src = hostIps[0];
  const dests = hostIps.slice(1, 5);
  const extra = hostIps.length - 5;
  return (
    <div className="bg-slate-800/40 border border-slate-700 rounded p-3">
      <h4 className="text-[10px] text-slate-500 uppercase mb-2">Network Flow</h4>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="px-2 py-1 text-[10px] font-mono bg-cyan-900/40 text-cyan-300 rounded border border-cyan-800">{src}</span>
        <span className="text-slate-600 text-xs">→</span>
        <div className="flex flex-wrap gap-1">
          {dests.map(ip => (
            <span key={ip} className="px-2 py-1 text-[10px] font-mono bg-slate-700 text-slate-300 rounded border border-slate-600">{ip}</span>
          ))}
          {extra > 0 && <span className="px-2 py-1 text-[10px] text-slate-500">+{extra} more</span>}
        </div>
      </div>
    </div>
  );
}

// 8️⃣ Related theories cross-link
function RelatedTheories({ slice, theories, jobId }: { slice: SliceItem; theories: TheoryItem[]; jobId: string }) {
  const related = useMemo(() => {
    const sliceIps = new Set(slice.host_ips);
    return theories.filter(t => {
      // Match by host IP overlap (theory scope_id is host IP for host theories)
      if (t.scope_id && sliceIps.has(t.scope_id)) return true;
      // Match by hypothesis type ↔ slice type
      const typeMap: Record<string, string> = { c2: "c2_session", recon: "recon_phase", lateral_movement: "lateral", exfiltration: "exfil" };
      if (typeMap[t.hypothesis_type] === slice.slice_type) return true;
      return false;
    });
  }, [slice, theories]);
  if (!related.length) return null;
  return (
    <div>
      <span className="text-xs text-slate-500 uppercase">Related Theories</span>
      <div className="flex flex-wrap gap-1 mt-1">
        {related.map(t => (
          <Link key={t.theory_id} to={`/jobs/${jobId}/theories`}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-xs bg-purple-900/30 text-purple-400 hover:bg-purple-900/50 rounded">
            {t.label.slice(0, 40)}
          </Link>
        ))}
      </div>
    </div>
  );
}


// 1️⃣ Collapsible slice card
function SliceCard({ slice, jobId, theories, defaultExpanded, alertNameMap, findingNameMap, iocNameMap }: {
  slice: SliceItem; jobId: string; theories: TheoryItem[]; defaultExpanded: boolean;
  alertNameMap: NameMap; findingNameMap: NameMap; iocNameMap: NameMap;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const tag = TYPE_LABELS[slice.slice_type] || "ATK";
  const sevClass = SEVERITY_COLORS[slice.severity] || SEVERITY_COLORS.info;
  const dur = durationStr(slice.time_start, slice.time_end);

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg hover:border-slate-500 transition-colors">
      {/* Compact header — always visible */}
      <button className="w-full text-left p-4 flex items-start gap-3" onClick={() => setExpanded(e => !e)}>
        <span className="text-xs font-mono font-bold text-slate-400 bg-slate-800 rounded px-1.5 py-0.5">{tag}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="text-xs text-slate-500 font-mono">#{slice.rank}</span>
            <h3 className="text-sm font-semibold text-slate-100 truncate">{slice.label}</h3>
            <MitreBadge sliceType={slice.slice_type} />
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${sevClass}`}>
              {slice.severity.toUpperCase()}
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500">Confidence:</span>
              <ConfidenceBar confidence={slice.confidence} />
            </div>
            {/* Evidence count summary */}
            <div className="flex gap-2 text-[10px] text-slate-500">
              {slice.alert_ids.length > 0 && <span>{slice.alert_ids.length} alerts</span>}
              {slice.finding_ids.length > 0 && <span>{slice.finding_ids.length} findings</span>}
              {slice.ioc_ids.length > 0 && <span>{slice.ioc_ids.length} IOCs</span>}
            </div>
            {/* 6️⃣ Human-readable time range */}
            {(slice.time_start || slice.time_end) && (
              <span className="text-[10px] text-slate-500 ml-auto">
                {fmtTime(slice.time_start)} → {fmtTime(slice.time_end)}{dur && ` (${dur})`}
              </span>
            )}
          </div>
        </div>
        <span className="text-slate-500 text-xs mt-1">{expanded ? "▲" : "▼"}</span>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-800 pt-3">
          {slice.summary && (
            <p className="text-xs text-slate-400 leading-relaxed">{slice.summary}</p>
          )}

          {/* Host IPs */}
          {slice.host_ips.length > 0 && (
            <div>
              <span className="text-xs text-slate-500 uppercase">Hosts</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {slice.host_ips.map(ip => (
                  <Link key={ip} to={`/jobs/${jobId}/hosts/${encodeURIComponent(ip)}`}
                    className="text-[10px] px-1.5 py-0.5 bg-cyan-900/30 text-cyan-300 rounded hover:bg-cyan-900/50">
                    {ip}
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* 2️⃣ Clickable evidence detail */}
          {slice.alert_ids.length > 0 && (
            <div>
              <span className="text-xs text-slate-500 uppercase">Alerts</span>
              <div className="mt-1"><EvidenceChips ids={slice.alert_ids} type="alert" jobId={jobId} nameMap={alertNameMap} /></div>
            </div>
          )}
          {slice.finding_ids.length > 0 && (
            <div>
              <span className="text-xs text-slate-500 uppercase">Findings</span>
              <div className="mt-1"><EvidenceChips ids={slice.finding_ids} type="finding" jobId={jobId} nameMap={findingNameMap} /></div>
            </div>
          )}
          {slice.ioc_ids.length > 0 && (
            <div>
              <span className="text-xs text-slate-500 uppercase">IOCs</span>
              <div className="mt-1"><EvidenceChips ids={slice.ioc_ids} type="ioc" jobId={jobId} nameMap={iocNameMap} /></div>
            </div>
          )}

          {/* 10️⃣ Network flow diagram */}
          <FlowDiagram hostIps={slice.host_ips} />

          {/* 8️⃣ Related theories */}
          <RelatedTheories slice={slice} theories={theories} jobId={jobId} />
        </div>
      )}
    </div>
  );
}



// ── Main page ────────────────────────────────────────────────────────────────

export function SlicesPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const { addToast } = useToast();

  // 4️⃣ Slice type filter
  const [typeFilter, setTypeFilter] = useState<string>("");
  // 9️⃣ Temporal tabs
  const [activeLabel, setActiveLabel] = useState<string | null>(null);

  // Fetch job detail for pcap labels
  const { data: jobData } = useQuery({
    queryKey: ["job-detail", jobId],
    queryFn: () => api.getJobDetail(jobId!),
    enabled: !!jobId,
  });

  const pcapLabels = useMemo(() => {
    const labels = (jobData?.job?.pcaps ?? []).map(p => p.label).filter(Boolean) as string[];
    return [...new Set(labels)];
  }, [jobData]);

  // Fetch slices
  const { data, isLoading, error } = useQuery({
    queryKey: ["slices", jobId, activeLabel],
    queryFn: () => api.listSlices(jobId!, activeLabel ? { pcap_label: activeLabel } : {}),
    enabled: !!jobId,
  });

  // 8️⃣ Fetch theories for cross-linking
  const { data: theoryData } = useQuery({
    queryKey: ["theories", jobId, "job"],
    queryFn: () => api.listJobTheories(jobId!),
    enabled: !!jobId,
  });

  // Fetch alerts, findings, IOCs for friendly name display
  const { data: alertData } = useQuery({
    queryKey: ["alerts", jobId],
    queryFn: () => api.listAlerts(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });
  const { data: findingData } = useQuery({
    queryKey: ["findings", jobId],
    queryFn: () => api.listFindings(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });
  const { data: iocData } = useQuery({
    queryKey: ["iocs", jobId],
    queryFn: () => api.listIocs(jobId!, { limit: 200 }),
    enabled: !!jobId,
  });

  // Build lookup maps: id → friendly name
  const alertNameMap = useMemo<NameMap>(() => {
    const m: NameMap = {};
    for (const a of alertData?.items ?? []) m[a.alert_id] = a.signature;
    return m;
  }, [alertData]);
  const findingNameMap = useMemo<NameMap>(() => {
    const m: NameMap = {};
    for (const f of findingData?.items ?? []) m[f.finding_id] = f.title;
    return m;
  }, [findingData]);
  const iocNameMap = useMemo<NameMap>(() => {
    const m: NameMap = {};
    for (const i of iocData?.items ?? []) m[i.ioc_id] = `${i.type}: ${i.value}`;
    return m;
  }, [iocData]);

  const theories: TheoryItem[] = theoryData?.items ?? [];
  const allSlices: SliceItem[] = data?.items ?? [];

  // 4️⃣ Apply type filter
  const slices = useMemo(() => {
    if (!typeFilter) return allSlices;
    return allSlices.filter(s => s.slice_type === typeFilter);
  }, [allSlices, typeFilter]);

  // Get distinct types for filter dropdown
  const sliceTypes = useMemo(() => {
    const types = new Set(allSlices.map(s => s.slice_type));
    return [...types].sort();
  }, [allSlices]);

  const regenerate = useMutation({
    mutationFn: () => api.generateSlices(jobId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["slices", jobId] });
      addToast({ severity: "info", title: "Slices regenerated", body: "Incident slices have been recalculated." });
    },
    onError: () => addToast({ severity: "high", title: "Failed to generate slices", body: "Check backend connectivity." }),
  });

  if (isLoading) return <div className="p-6"><CardGridSkeleton count={4} /></div>;
  if (error) return <div className="p-6 text-red-400">Error loading slices</div>;

  return (
    <div className="flex gap-6 items-start p-6">
      <div className="max-w-4xl mx-auto flex-1 min-w-0 space-y-4">
        {/* Breadcrumb */}
        <nav className="text-sm text-slate-400">
          <Link to="/jobs" className="hover:text-white">Jobs</Link>
          <span className="mx-1">/</span>
          <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
          <span className="mx-1">/</span>
          <span className="text-slate-200">Slices</span>
        </nav>

        {/* Title row */}
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className={`text-lg font-bold text-slate-100 ${labelHint("slices", activeHelpField)}`}
            onClick={() => toggleHelp("slices")}>
            Incident Slices <span className="text-slate-500 text-sm font-normal ml-2">({slices.length})</span>
          </h2>
          <button onClick={() => regenerate.mutate()} disabled={regenerate.isPending}
            className="text-xs px-3 py-1.5 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 disabled:opacity-50">
            {regenerate.isPending ? "Generating…" : "↻ Regenerate"}
          </button>
        </div>

        <p className="text-sm text-slate-400">
          Attack threads grouped by shared network conversations, host overlap, and temporal proximity.
        </p>

        {/* 4️⃣ Type filter + 9️⃣ Temporal tabs */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Type filter */}
          {sliceTypes.length > 1 && (
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1.5 text-xs text-slate-300">
              <option value="">All types</option>
              {sliceTypes.map(t => (
                <option key={t} value={t}>{TYPE_FULL[t] || t}</option>
              ))}
            </select>
          )}

          {/* 9️⃣ Temporal label tabs */}
          {pcapLabels.length > 1 && (
            <div className="flex bg-slate-800 rounded overflow-hidden border border-slate-700 ml-auto">
              <button onClick={() => setActiveLabel(null)}
                className={`px-3 py-1.5 text-xs ${activeLabel === null ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-white"}`}>
                All
              </button>
              {pcapLabels.map(lbl => (
                <button key={lbl} onClick={() => setActiveLabel(lbl)}
                  className={`px-3 py-1.5 text-xs ${activeLabel === lbl ? "bg-cyan-600 text-white" : "text-slate-400 hover:text-white"}`}>
                  {lbl}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* 5️⃣ Evidence summary bar */}
        <EvidenceSummaryBar slices={slices} />

        {slices.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            No slices generated yet. Click "Regenerate" or run a job analysis.
          </div>
        ) : (
          <>
            {/* 7️⃣ Severity distribution chart */}
            <SeverityChart slices={slices} />

            {/* 1️⃣ Collapsible slice cards */}
            <div className="space-y-3">
              {slices.map((s, i) => (
                <SliceCard key={s.slice_id} slice={s} jobId={jobId!} theories={theories}
                  defaultExpanded={i < 2} alertNameMap={alertNameMap} findingNameMap={findingNameMap} iocNameMap={iocNameMap} />
              ))}
            </div>
          </>
        )}
      </div>
      <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
    </div>
  );
}
