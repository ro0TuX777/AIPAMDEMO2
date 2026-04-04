import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { JobSubPageNav } from "../components/JobSubPageNav";

const STATUS_COLORS: Record<string, string> = {
  confirmed: "bg-emerald-900/40 text-emerald-400 border-emerald-700",
  corroborated: "bg-cyan-900/40 text-cyan-400 border-cyan-700",
  observed: "bg-slate-800 text-slate-400 border-slate-600",
};

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
      <span className="text-sm text-slate-200 break-all">{value}</span>
    </div>
  );
}

export function TelemetryEventDetailPage() {
  const { jobId, eventId } = useParams<{ jobId: string; eventId: string }>();

  const { data: evt, isLoading, error } = useQuery({
    queryKey: ["telemetry-event", jobId, eventId],
    queryFn: () => api.getTelemetryEventDetail(jobId!, eventId!),
    enabled: !!jobId && !!eventId,
  });

  if (isLoading) return <div className="p-6 text-slate-400">Loading event…</div>;
  if (error || !evt) return <div className="p-6 text-red-400">Telemetry event not found.</div>;

  const statusClass = STATUS_COLORS[evt.evidence_status] || STATUS_COLORS.observed;
  const hasData = evt.data && Object.keys(evt.data).length > 0;
  const hasCorrKeys = evt.correlation_keys && Object.keys(evt.correlation_keys).length > 0;

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-5xl mx-auto">
      <JobSubPageNav jobId={jobId!} currentPath="theories" />

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono bg-slate-800 text-slate-400 px-2 py-0.5 rounded">TEL</span>
            <h1 className="text-lg font-semibold text-slate-100">
              {evt.event_type.replace("_", " ").replace(/\b\w/g, c => c.toUpperCase())}
            </h1>
          </div>
          <p className="text-xs text-slate-500 font-mono">{evt.event_id}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 text-xs rounded border ${statusClass}`}>{evt.evidence_status}</span>
          {evt.pcap_label && (
            <span className="px-2 py-0.5 text-xs rounded bg-indigo-900/40 text-indigo-300 border border-indigo-700">{evt.pcap_label}</span>
          )}
        </div>
      </div>

      {/* Provenance */}
      <section className="border border-slate-700 rounded-lg p-4 space-y-3 bg-slate-900/50">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Provenance</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Field label="Source System" value={evt.source_system} />
          <Field label="Source File" value={evt.source_filename} />
          <Field label="Source Type" value={evt.source_type} />
          <Field label="Parser" value={evt.parser_name ? `${evt.parser_name} v${evt.parser_version || "?"}` : null} />
          <Field label="Timestamp" value={evt.timestamp} />
          <Field label="Corroboration Score" value={evt.corroboration_score > 0 ? evt.corroboration_score.toFixed(2) : null} />
        </div>
      </section>

      {/* Network / Identity */}
      <section className="border border-slate-700 rounded-lg p-4 space-y-3 bg-slate-900/50">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Network &amp; Identity</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Field label="Source IP" value={evt.src_ip ? `${evt.src_ip}${evt.src_port ? `:${evt.src_port}` : ""}` : null} />
          <Field label="Destination IP" value={evt.dest_ip ? `${evt.dest_ip}${evt.dest_port ? `:${evt.dest_port}` : ""}` : null} />
          <Field label="Protocol" value={evt.proto} />
          <Field label="Community ID" value={evt.community_id} />
          <Field label="Hostname" value={evt.hostname} />
          <Field label="Username" value={evt.username} />
          <Field label="Session ID" value={evt.session_id} />
          <Field label="Process GUID" value={evt.process_guid} />
        </div>
      </section>

      {/* Correlation Keys */}
      {hasCorrKeys && (
        <section className="border border-slate-700 rounded-lg p-4 space-y-3 bg-slate-900/50">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Correlation Keys</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {Object.entries(evt.correlation_keys).map(([k, v]) => (
              <Field key={k} label={k} value={String(v)} />
            ))}
          </div>
        </section>
      )}

      {/* Event Data Payload */}
      {hasData && (
        <section className="border border-slate-700 rounded-lg p-4 space-y-3 bg-slate-900/50">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Event Data</h2>
          <pre className="text-xs text-slate-300 bg-slate-950 rounded p-3 overflow-x-auto max-h-96">
            {JSON.stringify(evt.data, null, 2)}
          </pre>
        </section>
      )}

      {/* Tags */}
      {evt.tags.length > 0 && (
        <section className="border border-slate-700 rounded-lg p-4 space-y-3 bg-slate-900/50">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Tags</h2>
          <div className="flex flex-wrap gap-1">
            {evt.tags.map((tag, i) => (
              <span key={i} className="px-2 py-0.5 text-xs rounded bg-slate-800 text-slate-300 border border-slate-700">{tag}</span>
            ))}
          </div>
        </section>
      )}

      {/* Raw Reference */}
      {evt.raw_ref && (
        <section className="border border-slate-700 rounded-lg p-4 space-y-2 bg-slate-900/50">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Raw Reference</h2>
          <pre className="text-xs text-slate-400 bg-slate-950 rounded p-3 overflow-x-auto">{evt.raw_ref}</pre>
        </section>
      )}

      <div className="pt-2">
        <Link to={`/jobs/${jobId}/theories`} className="text-xs text-cyan-400 hover:underline">← Back to Theories</Link>
      </div>
    </div>
  );
}
