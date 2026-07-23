import React, { useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { api, type RawEventItem, type RawEventSearchParams } from "../api";
import { JobBreadcrumbs } from "../components/Breadcrumbs";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { BucketBarChart } from "../components/charts/BucketBarChart";
import { FlowDiagram } from "../components/charts/FlowDiagram";

type Mode = "events" | "breakdown" | "flow";

const PAGE_SIZE = 100;

/** Top-N links per stage the flow endpoint returns (matches the backend
 *  default). Passed to the query and the diagram so the "top flows" note
 *  reflects the actual cap rather than a guess. */
const FLOW_LINK_LIMIT = 50;

/** Fields the backend allows grouping by (see _AGG_FIELDS in events.py). */
const AGG_FIELDS = [
  "event_type", "source_type", "source_system", "hostname", "username",
  "src_ip", "src_port", "dest_ip", "dest_port", "proto", "evidence_status",
] as const;

/** Of those, the ones the search endpoint also accepts as a filter. */
const DRILLABLE = new Set(["event_type", "source_type", "src_ip", "dest_ip", "hostname"]);

export const EventsExplorerPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const mode = (searchParams.get("mode") as Mode) || "events";
  const aggField = searchParams.get("field") ?? "event_type";
  const [showTable, setShowTable] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const filters: RawEventSearchParams = {
    q: searchParams.get("q") || undefined,
    event_type: searchParams.get("event_type") || undefined,
    source_type: searchParams.get("source_type") || undefined,
    src_ip: searchParams.get("src_ip") || undefined,
    dest_ip: searchParams.get("dest_ip") || undefined,
    hostname: searchParams.get("hostname") || undefined,
  };
  const offset = Number(searchParams.get("offset") ?? 0) || 0;

  const setParam = (key: string, val: string | undefined) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (val) next.set(key, val); else next.delete(key);
      if (key !== "offset") next.delete("offset"); // any filter change resets paging
      return next;
    }, { replace: key === "q" });
  };

  const activeFilters = Object.entries(filters).filter(([, v]) => v) as [string, string][];

  // ── Data ──
  const eventsQ = useQuery({
    queryKey: ["job", jobId, "raw-events", filters, offset],
    queryFn: () => api.searchRawEvents(jobId!, { ...filters, limit: PAGE_SIZE, offset }),
    enabled: !!jobId && mode === "events",
    placeholderData: keepPreviousData,
  });

  const aggQ = useQuery({
    queryKey: ["job", jobId, "raw-events-agg", aggField],
    queryFn: () => api.aggregateRawEvents(jobId!, aggField),
    enabled: !!jobId && mode === "breakdown",
  });

  const flowQ = useQuery({
    queryKey: ["job", jobId, "raw-events-flow", FLOW_LINK_LIMIT],
    queryFn: () => api.getRawEventFlow(jobId!, FLOW_LINK_LIMIT),
    enabled: !!jobId && mode === "flow",
  });

  /** Clicking a bucket filters the event list by that value, if drillable. */
  const drillInto = (value: string | null) => {
    if (!DRILLABLE.has(aggField) || value == null) return;
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set(aggField, value);
      next.set("mode", "events");
      next.delete("offset");
      return next;
    });
  };

  if (!jobId) return <p className="text-red-400">Missing job ID</p>;

  const events = eventsQ.data?.items ?? [];
  const total = eventsQ.data?.total ?? 0;

  return (
    <>
      <div className="flex gap-6 items-start">
        <div className="space-y-4 flex-1 min-w-0">
          <JobBreadcrumbs jobId={jobId} trail={[{ label: "Raw Events" }]} />

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h1
              className={`text-xl font-semibold text-slate-100 ${labelHint("raw_events", activeHelpField)}`}
              onClick={() => toggleHelp("raw_events")}
            >
              Raw Events
            </h1>
            <div className="flex rounded border border-slate-700 overflow-hidden">
              {(["events", "breakdown", "flow"] as Mode[]).map((m) => (
                <button
                  key={m}
                  onClick={() => setParam("mode", m === "events" ? undefined : m)}
                  data-testid={`events-mode-${m}`}
                  className={`px-3 py-1 text-xs capitalize transition-colors ${
                    mode === m ? "bg-blue-600 text-white" : "bg-slate-800 text-slate-400 hover:text-slate-100"
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <p className="text-sm text-slate-500">
            Every normalized event from every source, before correlation. Search it, group it to see
            what the capture is mostly made of, or trace who talked to whom.
          </p>

          {/* Active filters — shared across modes so a drill-down is visible. */}
          {activeFilters.length > 0 && (
            <div className="flex flex-wrap items-center gap-2" data-testid="events-active-filters">
              <span className="text-xs uppercase tracking-wider text-slate-500">Filters</span>
              {activeFilters.map(([k, v]) => (
                <span
                  key={k}
                  className="inline-flex items-center gap-1 rounded bg-blue-500/15 px-2 py-0.5 text-xs text-blue-300"
                >
                  {k.replace(/_/g, " ")}: <span className="font-mono">{v}</span>
                  <button
                    onClick={() => setParam(k, undefined)}
                    className="ml-0.5 text-blue-400 hover:text-slate-50"
                    aria-label={`Remove ${k} filter`}
                  >
                    ✕
                  </button>
                </span>
              ))}
              <button
                onClick={() =>
                  setSearchParams((prev) => {
                    const next = new URLSearchParams(prev);
                    ["q", ...DRILLABLE].forEach((k) => next.delete(k));
                    next.delete("offset");
                    return next;
                  })
                }
                className="text-xs text-slate-500 hover:text-slate-300 underline"
              >
                Clear all
              </button>
            </div>
          )}

          {/* ── Events ── */}
          {mode === "events" && (
            <>
              <input
                type="text"
                value={filters.q ?? ""}
                onChange={(e) => setParam("q", e.target.value || undefined)}
                placeholder="Search hostnames, users, IPs, protocols, raw payload…"
                data-testid="events-search"
                className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder-slate-600"
              />

              {eventsQ.isLoading && <p className="text-slate-400 animate-pulse">Loading events…</p>}
              {eventsQ.error && <p className="text-red-400">Failed to load events.</p>}
              {!eventsQ.isLoading && events.length === 0 && (
                <p className="rounded border border-slate-800 bg-slate-900/50 p-6 text-center text-sm text-slate-400">
                  No events matched.
                </p>
              )}

              {events.length > 0 && (
                <>
                  <div className="text-xs text-slate-500">
                    {total.toLocaleString()} event{total === 1 ? "" : "s"}
                    {total > PAGE_SIZE && ` · showing ${offset + 1}–${Math.min(offset + events.length, total)}`}
                  </div>
                  <div className="overflow-x-auto rounded border border-slate-800">
                    <table className="w-full text-xs" data-testid="events-table">
                      <thead className="bg-slate-900 text-slate-500 uppercase">
                        <tr>
                          <th className="px-2 py-1.5 text-left font-medium">Time</th>
                          <th className="px-2 py-1.5 text-left font-medium">Type</th>
                          <th className="px-2 py-1.5 text-left font-medium">Source</th>
                          <th className="px-2 py-1.5 text-left font-medium">Host / User</th>
                          <th className="px-2 py-1.5 text-left font-medium">Endpoints</th>
                        </tr>
                      </thead>
                      <tbody>
                        {events.map((e: RawEventItem) => (
                          <React.Fragment key={e.event_id}>
                            <tr
                              onClick={() => setExpanded(expanded === e.event_id ? null : e.event_id)}
                              className={`cursor-pointer border-t border-slate-800/60 hover:bg-slate-800/40 ${
                                expanded === e.event_id ? "bg-slate-800/60" : ""
                              }`}
                            >
                              <td className="px-2 py-1.5 font-mono text-slate-500 whitespace-nowrap">
                                {e.timestamp.replace("T", " ").replace(/\.\d+Z?$/, "")}
                              </td>
                              <td className="px-2 py-1.5 text-slate-300">{e.event_type}</td>
                              <td className="px-2 py-1.5 text-slate-400">
                                {e.source_system || e.source_type}
                              </td>
                              <td className="px-2 py-1.5 text-slate-400">
                                {e.hostname ?? "—"}
                                {e.username ? ` / ${e.username}` : ""}
                              </td>
                              <td className="px-2 py-1.5 font-mono text-slate-400">
                                {e.src_ip
                                  ? `${e.src_ip}${e.src_port ? `:${e.src_port}` : ""} → ${e.dest_ip ?? "?"}${e.dest_port ? `:${e.dest_port}` : ""}`
                                  : "—"}
                              </td>
                            </tr>
                            {expanded === e.event_id && (
                              <tr>
                                <td colSpan={5} className="bg-slate-950/60 px-3 py-2">
                                  {e.tags.length > 0 && (
                                    <div className="mb-2 flex flex-wrap gap-1">
                                      {e.tags.map((t) => (
                                        <span key={t} className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                                          {t}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                  <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words text-[11px] leading-5 text-slate-400">
                                    {JSON.stringify(e.data, null, 2)}
                                  </pre>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {total > PAGE_SIZE && (
                    <div className="flex items-center justify-between text-xs">
                      <button
                        disabled={offset === 0}
                        onClick={() => setParam("offset", String(Math.max(0, offset - PAGE_SIZE)))}
                        className="rounded border border-slate-700 px-3 py-1.5 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
                      >
                        ← Previous
                      </button>
                      <button
                        disabled={offset + PAGE_SIZE >= total}
                        onClick={() => setParam("offset", String(offset + PAGE_SIZE))}
                        className="rounded border border-slate-700 px-3 py-1.5 text-slate-300 hover:bg-slate-800 disabled:opacity-40"
                      >
                        Next →
                      </button>
                    </div>
                  )}
                </>
              )}
            </>
          )}

          {/* ── Breakdown ── */}
          {mode === "breakdown" && (
            <>
              <div className="flex flex-wrap items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-slate-400">
                  Group by
                  <select
                    value={aggField}
                    onChange={(e) => setParam("field", e.target.value)}
                    data-testid="events-agg-field"
                    className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
                  >
                    {AGG_FIELDS.map((f) => (
                      <option key={f} value={f}>{f.replace(/_/g, " ")}</option>
                    ))}
                  </select>
                </label>
                <button
                  onClick={() => setShowTable((v) => !v)}
                  className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-400 hover:text-slate-100"
                >
                  {showTable ? "Show chart" : "Show table"}
                </button>
                {DRILLABLE.has(aggField) && (
                  <span className="text-xs text-slate-500">Click a bar to filter the event list</span>
                )}
              </div>

              {aggQ.isLoading && <p className="text-slate-400 animate-pulse">Aggregating…</p>}
              {aggQ.error && <p className="text-red-400">Failed to aggregate events.</p>}

              {aggQ.data && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                  {showTable ? (
                    <table className="w-full text-xs" data-testid="events-agg-table">
                      <thead className="text-slate-500 uppercase">
                        <tr>
                          <th className="px-2 py-1.5 text-left font-medium">{aggField.replace(/_/g, " ")}</th>
                          <th className="px-2 py-1.5 text-right font-medium">Events</th>
                          <th className="px-2 py-1.5 text-right font-medium">Share</th>
                        </tr>
                      </thead>
                      <tbody>
                        {aggQ.data.buckets.map((b, i) => (
                          <tr key={i} className="border-t border-slate-800/60">
                            <td className="px-2 py-1.5 font-mono text-slate-300">{b.value ?? "(none)"}</td>
                            <td className="px-2 py-1.5 text-right tabular-nums text-slate-400">
                              {b.count.toLocaleString()}
                            </td>
                            <td className="px-2 py-1.5 text-right tabular-nums text-slate-500">
                              {aggQ.data!.total_events > 0
                                ? `${((b.count / aggQ.data!.total_events) * 100).toFixed(1)}%`
                                : "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <BucketBarChart
                      buckets={aggQ.data.buckets}
                      totalEvents={aggQ.data.total_events}
                      onSelect={DRILLABLE.has(aggField) ? drillInto : undefined}
                      selectedValue={(filters as any)[aggField] ?? null}
                    />
                  )}
                </div>
              )}
            </>
          )}

          {/* ── Flow ── */}
          {mode === "flow" && (
            <>
              {flowQ.isLoading && <p className="text-slate-400 animate-pulse">Building flow…</p>}
              {flowQ.error && <p className="text-red-400">Failed to load flow.</p>}
              {flowQ.data && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
                  <FlowDiagram flow={flowQ.data} linkLimit={FLOW_LINK_LIMIT} />
                </div>
              )}
            </>
          )}
        </div>
        <HelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
      </div>
      <JobSubPageNav jobId={jobId} currentPath="raw-events" />
    </>
  );
};
