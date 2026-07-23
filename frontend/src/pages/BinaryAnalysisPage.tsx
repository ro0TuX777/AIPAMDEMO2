import React, { useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type BinaryAnalysisItem, type BinaryAnalysisResponse } from "../api";
import { JobBreadcrumbs } from "../components/Breadcrumbs";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { useToast } from "../components/ToastProvider";

/** Above this, a file is almost certainly packed, compressed or encrypted. */
const ENTROPY_SUSPICIOUS = 7.2;

function fmtBytes(n: number): string {
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(2)} GB`;
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

/** Entropy meter — a single ratio against a limit, so a meter not a chart. */
const EntropyMeter: React.FC<{ value: number }> = ({ value }) => {
  const pct = Math.min((value / 8) * 100, 100);
  const hot = value >= ENTROPY_SUSPICIOUS;
  return (
    <div className="space-y-1">
      <div className="flex items-baseline gap-2">
        <span className={`font-mono text-sm ${hot ? "text-amber-400" : "text-slate-300"}`}>
          {value.toFixed(2)}
        </span>
        <span className="text-[10px] text-slate-500">/ 8.00</span>
        {hot && (
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
            likely packed or encrypted
          </span>
        )}
      </div>
      <div className="h-1.5 w-40 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full ${hot ? "bg-amber-500" : "bg-blue-500"}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
};

const HashRow: React.FC<{ label: string; value?: string | null }> = ({ label, value }) =>
  value ? (
    <div className="flex items-baseline gap-2">
      <span className="w-14 shrink-0 text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
      <code className="break-all font-mono text-[11px] text-slate-300">{value}</code>
    </div>
  ) : null;

const AnalysisCard: React.FC<{ a: BinaryAnalysisItem }> = ({ a }) => (
  <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-3">
    <div className="flex flex-wrap items-center gap-2">
      <h3 className="text-sm font-semibold text-slate-200">{a.filename || "(unnamed)"}</h3>
      {a.format && (
        <span className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
          {a.format}
        </span>
      )}
      {a.artifact_class && (
        <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[10px] text-violet-300">
          {a.artifact_class}
        </span>
      )}
      <span className="ml-auto text-[11px] text-slate-500">{fmtBytes(a.size_bytes)}</span>
    </div>

    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      <div className="space-y-1">
        <HashRow label="SHA256" value={a.sha256} />
        <HashRow label="SHA1" value={a.sha1} />
        <HashRow label="MD5" value={a.md5} />
      </div>
      {a.entropy != null && (
        <div>
          <div className="mb-1 text-[10px] uppercase tracking-wider text-slate-500">Entropy</div>
          <EntropyMeter value={a.entropy} />
        </div>
      )}
    </div>

    <div>
      <div className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500">
        YARA matches ({a.yara_matches.length})
      </div>
      {a.yara_matches.length === 0 ? (
        <p className="text-xs text-slate-500">No rules matched.</p>
      ) : (
        <div className="space-y-2" data-testid="yara-matches">
          {a.yara_matches.map((m) => (
            <div key={m.rule} className="rounded border border-red-900/40 bg-red-950/20 p-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-xs font-semibold text-red-300">{m.rule}</span>
                {m.tags.map((t) => (
                  <span key={t} className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                    {t}
                  </span>
                ))}
              </div>
              {Object.keys(m.meta ?? {}).length > 0 && (
                <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[11px]">
                  {Object.entries(m.meta).map(([k, v]) => (
                    <React.Fragment key={k}>
                      <dt className="text-slate-500">{k}</dt>
                      <dd className="text-slate-400">{String(v)}</dd>
                    </React.Fragment>
                  ))}
                </dl>
              )}
              {m.strings?.length > 0 && (
                <details className="mt-1.5">
                  <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-slate-300">
                    {m.strings.length} matched string{m.strings.length === 1 ? "" : "s"}
                  </summary>
                  <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-slate-950 p-2 text-[10px] text-slate-400">
                    {m.strings.join("\n")}
                  </pre>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  </div>
);

export const BinaryAnalysisPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

  const [persist, setPersist] = useState(true);
  const [pct, setPct] = useState(0);
  /**
   * The last analysis and whether it was persisted. Shown directly rather than
   * waiting on the list refetch: the POST response is richer than the list
   * entry, which drops sha1 and remaps format/artifact_class from the stored
   * File columns.
   */
  const [result, setResult] = useState<{ res: BinaryAnalysisResponse; persisted: boolean } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const listQ = useQuery({
    queryKey: ["job", jobId, "binary"],
    queryFn: () => api.listBinaryAnalyses(jobId!),
    enabled: !!jobId,
  });

  const analyzeMut = useMutation({
    mutationFn: (file: File) =>
      api.analyzeBinary(file, {
        jobId: persist ? jobId : undefined,
        onProgress: setPct,
      }),
    // Capture the mode at submit time — the checkbox may change mid-upload.
    onMutate: () => ({ persisted: persist }),
    onSuccess: (res, _file, ctx) => {
      setPct(0);
      const persisted = (ctx as { persisted: boolean } | undefined)?.persisted ?? persist;
      setResult({ res, persisted });
      if (persisted) {
        queryClient.invalidateQueries({ queryKey: ["job", jobId, "binary"] });
        // YARA matches become findings, so those views are stale too.
        queryClient.invalidateQueries({ queryKey: ["job", jobId, "findings"] });
        queryClient.invalidateQueries({ queryKey: ["investigation-queue", jobId] });
        addToast({
          severity: res.findings_created ? "medium" : "info",
          title: "Binary analyzed",
          body: res.findings_created
            ? `${res.findings_created} finding(s) created from YARA matches.`
            : "No YARA matches; no findings created.",
        });
      }
    },
    onError: (err: Error) => {
      setPct(0);
      addToast({ severity: "high", title: "Analysis failed", body: err.message });
    },
  });

  const onPick = (f: File | undefined) => {
    if (f) analyzeMut.mutate(f);
  };

  if (!jobId) return <p className="text-red-400">Missing job ID</p>;

  const items = listQ.data?.items ?? [];
  const engine = result?.res;

  return (
    <>
      <div className="flex gap-6 items-start">
        <div className="space-y-4 flex-1 min-w-0">
          <JobBreadcrumbs jobId={jobId} trail={[{ label: "Binary" }]} />

          <h1
            className={`text-xl font-semibold text-slate-100 ${labelHint("binary", activeHelpField)}`}
            onClick={() => toggleHelp("binary")}
          >
            Binary Analysis
          </h1>
          <p className="text-sm text-slate-500">
            Hash, measure and YARA-scan a file. Attach it to the job so matches become findings, or
            inspect it without persisting anything.
          </p>

          {/* Engine status — an air-gapped host may have no yara module at all. */}
          {engine && (!engine.yara_available || !engine.rules_compiled) && (
            <div
              className="rounded border border-amber-700/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-300"
              data-testid="yara-engine-warning"
            >
              {!engine.yara_available
                ? "The yara module is not installed on the server — hashing, entropy and format detection still ran, but no rules were evaluated."
                : "No YARA rules could be compiled from the server's rules directory, so nothing was matched against."}
            </div>
          )}

          {/* ── Upload ── */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-3">
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={persist}
                onChange={(e) => setPersist(e.target.checked)}
                data-testid="binary-persist"
                className="rounded border-slate-600"
              />
              Attach to this job and create findings from matches
              <span className="text-slate-600">
                (uncheck to inspect without storing anything)
              </span>
            </label>

            <input
              ref={fileRef}
              type="file"
              className="hidden"
              data-testid="binary-file-input"
              onChange={(e) => {
                onPick(e.target.files?.[0]);
                e.target.value = "";
              }}
            />
            <div
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
              onDrop={(e) => { e.preventDefault(); onPick(e.dataTransfer.files?.[0]); }}
              data-testid="binary-dropzone"
              className="cursor-pointer rounded-lg border-2 border-dashed border-slate-600 p-6 text-center text-sm text-slate-400 transition-colors hover:border-slate-400"
            >
              {analyzeMut.isPending
                ? `Analyzing… ${pct}%`
                : "Drop a file here or click to browse"}
            </div>
            {analyzeMut.isPending && pct > 0 && (
              <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${pct}%` }} />
              </div>
            )}
          </div>

          {/* ── Latest result ── */}
          {result && (
            <div className="space-y-2" data-testid="binary-scratch-result">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold text-slate-300">
                  {result.persisted ? "Analysis result" : "Inspection result"}
                </h2>
                <span
                  className={`rounded px-1.5 py-0.5 text-[10px] ${
                    result.persisted
                      ? "bg-emerald-500/15 text-emerald-300"
                      : "bg-slate-800 text-slate-400"
                  }`}
                >
                  {result.persisted
                    ? `saved · ${result.res.findings_created ?? 0} finding(s)`
                    : "not saved"}
                </span>
                <button
                  onClick={() => setResult(null)}
                  className="ml-auto text-xs text-slate-500 hover:text-slate-300"
                >
                  Dismiss
                </button>
              </div>
              <AnalysisCard a={result.res.analysis} />
            </div>
          )}

          {/* ── Persisted analyses ── */}
          <div className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-300">
              Analyzed in this job ({items.length})
            </h2>
            {listQ.isLoading && <p className="text-slate-400 animate-pulse">Loading…</p>}
            {listQ.error && <p className="text-red-400">Failed to load binary analyses.</p>}
            {!listQ.isLoading && items.length === 0 && (
              <p className="rounded border border-slate-800 bg-slate-900/50 p-6 text-center text-sm text-slate-400">
                No binaries analyzed for this job yet.
              </p>
            )}
            {items.map((a) => (
              <AnalysisCard key={a.file_id} a={a} />
            ))}
          </div>
        </div>
        <HelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
      </div>
      <JobSubPageNav jobId={jobId} currentPath="binary" />
    </>
  );
};
