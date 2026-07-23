import React, { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type SigmaAnalyzeResponse, type SigmaDetectionItem } from "../api";
import { JobBreadcrumbs } from "../components/Breadcrumbs";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { useToast } from "../components/ToastProvider";
import { severityClass, SEVERITY_ORDER } from "../theme/colors";

export const SigmaPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const [sevFilter, setSevFilter] = useState("");
  const [lastRun, setLastRun] = useState<SigmaAnalyzeResponse | null>(null);

  const listQ = useQuery({
    queryKey: ["job", jobId, "sigma"],
    queryFn: () => api.listSigmaDetections(jobId!),
    enabled: !!jobId,
  });

  const analyzeMut = useMutation({
    mutationFn: () => api.analyzeSigma(jobId!),
    onSuccess: (res) => {
      setLastRun(res);
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "sigma"] });
      // Detections are persisted as findings, so those views are stale too.
      queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] });
      queryClient.invalidateQueries({ queryKey: ["investigation-queue", jobId] });
      addToast({
        severity: res.detections_created ? "medium" : "info",
        title: "Sigma analysis complete",
        body: res.detections_created
          ? `${res.detections_created} new detection(s) from ${res.rules_evaluated} rules.`
          : `No new detections across ${res.events_scanned.toLocaleString()} events.`,
      });
    },
    onError: () => addToast({ severity: "high", title: "Sigma analysis failed" }),
  });

  const detections = listQ.data?.items ?? [];

  const filtered = useMemo(
    () => (sevFilter ? detections.filter((d) => d.severity === sevFilter) : detections),
    [detections, sevFilter],
  );

  /** Severities actually present, in canonical order — no empty filter options. */
  const presentSeverities = useMemo(
    () => SEVERITY_ORDER.filter((s) => detections.some((d) => d.severity === s)),
    [detections],
  );

  if (!jobId) return <p className="text-red-400">Missing job ID</p>;

  return (
    <>
      <div className="flex gap-6 items-start">
        <div className="space-y-4 flex-1 min-w-0">
          <JobBreadcrumbs jobId={jobId} trail={[{ label: "Sigma" }]} />

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h1
              className={`text-xl font-semibold text-slate-100 ${labelHint("sigma", activeHelpField)}`}
              onClick={() => toggleHelp("sigma")}
            >
              Sigma Detections
            </h1>
            <button
              onClick={() => analyzeMut.mutate()}
              disabled={analyzeMut.isPending}
              data-testid="sigma-run"
              className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
            >
              {analyzeMut.isPending ? "Running…" : "Run Sigma rules"}
            </button>
          </div>

          <p className="text-sm text-slate-500">
            Sigma rules evaluated against this job's normalized log events. Every hit is persisted as
            a first-class finding, so it also appears in Findings and the investigation queue.
          </p>

          {/* Last-run summary — a KPI row, not a chart. */}
          {lastRun && (
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4" data-testid="sigma-run-summary">
              {[
                { label: "Rules evaluated", value: lastRun.rules_evaluated },
                { label: "Events scanned", value: lastRun.events_scanned },
                { label: "New detections", value: lastRun.detections_created },
                { label: "Total detections", value: lastRun.detections_total },
              ].map((s) => (
                <div key={s.label} className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                  <div className="text-lg font-bold text-slate-100">{s.value.toLocaleString()}</div>
                  <div className="text-xs text-slate-500">{s.label}</div>
                </div>
              ))}
            </div>
          )}

          {lastRun && lastRun.events_scanned === 0 && (
            <div className="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-300">
              No normalized events exist for this job, so the rules had nothing to match against.
              Sigma reads parsed log events — a PCAP-only job produces none.
            </div>
          )}

          {presentSeverities.length > 1 && (
            <div className="flex items-center gap-2">
              <select
                value={sevFilter}
                onChange={(e) => setSevFilter(e.target.value)}
                data-testid="sigma-severity-filter"
                className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200"
              >
                <option value="">All severities</option>
                {presentSeverities.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              <span className="text-xs text-slate-500">
                {filtered.length} of {detections.length}
              </span>
            </div>
          )}

          {listQ.isLoading && <p className="text-slate-400 animate-pulse">Loading detections…</p>}
          {listQ.error && <p className="text-red-400">Failed to load Sigma detections.</p>}

          {!listQ.isLoading && detections.length === 0 && (
            <p
              className="rounded border border-slate-800 bg-slate-900/50 p-6 text-center text-sm text-slate-400"
              data-testid="sigma-empty"
            >
              No Sigma detections yet. Run the rules to evaluate this job's events.
            </p>
          )}

          <div className="space-y-2">
            {filtered.map((d: SigmaDetectionItem) => (
              <div key={d.finding_id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded px-2 py-0.5 text-xs font-medium ${severityClass(d.severity)}`}>
                    {d.severity.toUpperCase()}
                  </span>
                  <h3 className="text-sm font-semibold text-slate-200">{d.title}</h3>
                  <code className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                    {d.rule_id}
                  </code>
                  {d.tags.map((t) => (
                    <span key={t} className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-500">
                      {t}
                    </span>
                  ))}
                  {/* Detections are findings, so the detail view already exists. */}
                  <Link
                    to={`/jobs/${jobId}/findings/${encodeURIComponent(d.finding_id)}`}
                    className="ml-auto rounded border border-slate-700 bg-slate-800 px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-blue-300 hover:border-blue-500/30"
                  >
                    View finding
                  </Link>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-3 text-[11px] text-slate-500">
                  {d.hostname && <span>host: <span className="text-slate-400">{d.hostname}</span></span>}
                  {d.timestamp && (
                    <span>
                      at <span className="text-slate-400">{d.timestamp.replace("T", " ").replace(/\.\d+Z?$/, "")}</span>
                    </span>
                  )}
                  {d.event_id && (
                    <Link
                      to={`/jobs/${jobId}/telemetry/${encodeURIComponent(d.event_id)}`}
                      className="text-cyan-400 hover:underline"
                    >
                      source event →
                    </Link>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
        <HelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
      </div>
      <JobSubPageNav jobId={jobId} currentPath="sigma" />
    </>
  );
};
