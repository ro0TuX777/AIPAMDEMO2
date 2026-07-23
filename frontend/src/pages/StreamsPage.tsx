import React, { useMemo, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  api,
  type ConnectionItem,
  type StreamSelector,
} from "../api";
import { JobBreadcrumbs } from "../components/Breadcrumbs";
import { JobSubPageNav } from "../components/JobSubPageNav";
import { HelpPanel, labelHint, usePageHelp } from "../components/HelpPanel";
import { useToast } from "../components/ToastProvider";

type ViewMode = "ascii" | "hex";

/** Row cap for the host and connection pickers. Both the request and the
 *  "showing first N" note read this, so they cannot drift apart. */
const PICKER_LIMIT = 200;

/**
 * Raw stream forensics — "follow stream" for a job's PCAPs.
 *
 * The backend identifies a stream by its 4-tuple plus protocol but has no
 * endpoint that enumerates streams, so the selection is driven from the job's
 * own connection records: pick a host, pick one of its connections. The tuple
 * also lives in the query string, which makes a followed stream shareable and
 * lets other pages (host connections, alerts) deep-link straight into it.
 */

function isCompleteSelector(s: Partial<StreamSelector>): s is StreamSelector {
  return (
    !!s.src && !!s.dst &&
    typeof s.sport === "number" && !Number.isNaN(s.sport) &&
    typeof s.dport === "number" && !Number.isNaN(s.dport) &&
    (s.proto === "tcp" || s.proto === "udp")
  );
}

function fmtBytes(n: number): string {
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export const StreamsPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();
  const { addToast } = useToast();

  const [view, setView] = useState<ViewMode>("ascii");
  const [pickerHost, setPickerHost] = useState<string>("");
  const [carving, setCarving] = useState(false);

  // ── Selected stream lives in the URL so it can be shared / deep-linked ──
  const selector: Partial<StreamSelector> = useMemo(() => {
    const sport = Number(searchParams.get("sport"));
    const dport = Number(searchParams.get("dport"));
    const proto = searchParams.get("proto");
    return {
      src: searchParams.get("src") ?? undefined,
      dst: searchParams.get("dst") ?? undefined,
      sport: Number.isFinite(sport) && searchParams.get("sport") ? sport : undefined,
      dport: Number.isFinite(dport) && searchParams.get("dport") ? dport : undefined,
      proto: proto === "udp" ? "udp" : proto === "tcp" ? "tcp" : undefined,
      pcap: searchParams.get("pcap") ?? undefined,
    };
  }, [searchParams]);

  const active = isCompleteSelector(selector) ? selector : null;

  const selectStream = (s: StreamSelector) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("src", s.src);
      next.set("sport", String(s.sport));
      next.set("dst", s.dst);
      next.set("dport", String(s.dport));
      next.set("proto", s.proto);
      if (s.pcap) next.set("pcap", s.pcap);
      return next;
    });
  };

  const setPcap = (name: string) => {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      if (name) next.set("pcap", name); else next.delete("pcap");
      return next;
    }, { replace: true });
  };

  // ── Data ──
  const pcapsQ = useQuery({
    queryKey: ["job", jobId, "stream-pcaps"],
    queryFn: () => api.listStreamPcaps(jobId!),
    enabled: !!jobId,
  });
  const pcaps = pcapsQ.data?.items ?? [];

  const hostsQ = useQuery({
    queryKey: ["job", jobId, "hosts"],
    queryFn: () => api.listHosts(jobId!, { limit: PICKER_LIMIT }),
    enabled: !!jobId,
  });
  const hosts = hostsQ.data?.items ?? [];
  const hostsTruncated = hostsQ.data?.page?.has_more ?? false;

  const connsQ = useQuery({
    queryKey: ["job", jobId, "hosts", pickerHost, "connections"],
    queryFn: () => api.listConnections(jobId!, pickerHost, { limit: PICKER_LIMIT }),
    enabled: !!jobId && !!pickerHost,
  });
  const connections = connsQ.data?.items ?? [];
  const connsTruncated = connsQ.data?.page?.has_more ?? false;

  const asciiQ = useQuery({
    queryKey: ["job", jobId, "stream-ascii", active],
    queryFn: () => api.getStreamAscii(jobId!, active!),
    enabled: !!jobId && !!active && view === "ascii",
    retry: false,
  });

  const hexQ = useQuery({
    queryKey: ["job", jobId, "stream-hex", active],
    queryFn: () => api.getStreamHexdump(jobId!, active!),
    enabled: !!jobId && !!active && view === "hex",
    retry: false,
  });

  const handleCarve = async () => {
    if (!active) return;
    setCarving(true);
    try {
      await api.downloadStreamPcap(jobId!, active);
      addToast({ severity: "info", title: "Stream carved", body: "PCAP download started." });
    } catch (err: any) {
      addToast({ severity: "high", title: "Carve failed", body: err?.message ?? "Could not carve stream." });
    } finally {
      setCarving(false);
    }
  };

  const connIsSelected = (c: ConnectionItem) =>
    active?.src === c.src_ip && active?.dst === c.dest_ip &&
    active?.sport === c.src_port && active?.dport === c.dest_port;

  /** Connections the stream tools can act on — needs a full tuple and tcp/udp. */
  const followable = connections.filter(
    (c) => c.src_port != null && c.dest_port != null &&
      ["tcp", "udp"].includes((c.proto ?? "").toLowerCase()),
  );

  const activeError = (view === "ascii" ? asciiQ.error : hexQ.error) as Error | null;
  const activeLoading = view === "ascii" ? asciiQ.isLoading : hexQ.isLoading;

  if (!jobId) return <p className="text-red-400">Missing job ID</p>;

  return (
    <>
      <div className="flex gap-6 items-start">
        <div className="space-y-4 flex-1 min-w-0">
          <JobBreadcrumbs jobId={jobId} trail={[{ label: "Streams" }]} />

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h1
              className={`text-xl font-semibold text-slate-100 ${labelHint("streams", activeHelpField)}`}
              onClick={() => toggleHelp("streams")}
            >
              Streams
            </h1>
            {pcaps.length > 1 && (
              <label className="flex items-center gap-2 text-xs text-slate-400">
                PCAP
                <select
                  value={selector.pcap ?? ""}
                  onChange={(e) => setPcap(e.target.value)}
                  data-testid="stream-pcap-select"
                  className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200"
                >
                  <option value="">{pcaps[0].name} (default)</option>
                  {pcaps.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name} — {fmtBytes(p.size_bytes)}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>

          <p className="text-sm text-slate-500">
            Reassemble a single conversation from the capture — read it as text, inspect the raw
            bytes, or carve it out as its own PCAP. Pick a host to see its conversations.
          </p>

          {pcapsQ.isLoading && <p className="text-slate-400 animate-pulse">Loading capture files…</p>}
          {!pcapsQ.isLoading && pcaps.length === 0 && (
            <p className="rounded border border-slate-800 bg-slate-900/50 p-4 text-sm text-slate-400">
              No PCAP files are available for this job, so there are no streams to follow.
            </p>
          )}

          {pcaps.length > 0 && (
            <>
              {/* ── Stream picker ── */}
              <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <label className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                    Host
                  </label>
                  <select
                    value={pickerHost}
                    onChange={(e) => setPickerHost(e.target.value)}
                    data-testid="stream-host-select"
                    className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200 min-w-[14rem]"
                  >
                    <option value="">— Select a host —</option>
                    {hosts.map((h) => (
                      <option key={h.ip} value={h.ip}>
                        {h.ip} ({h.conn_count} conversations)
                      </option>
                    ))}
                  </select>
                  {connsQ.isLoading && <span className="text-xs text-slate-500 animate-pulse">Loading…</span>}
                </div>

                {hostsTruncated && (
                  <p className="text-xs text-amber-400" data-testid="stream-hosts-truncated">
                    ⚠ Showing the first {PICKER_LIMIT} hosts; more exist. Use the Hosts page to find a
                    host that is not listed here.
                  </p>
                )}

                {pickerHost && !connsQ.isLoading && followable.length === 0 && (
                  <p className="text-xs text-slate-500">
                    No TCP/UDP conversations with a complete port pair on this host.
                  </p>
                )}

                {connsTruncated && (
                  <p className="text-xs text-amber-400" data-testid="stream-conns-truncated">
                    ⚠ Showing the first {PICKER_LIMIT} conversations for this host; more exist.
                  </p>
                )}

                {followable.length > 0 && (
                  <div className="max-h-64 overflow-y-auto rounded border border-slate-800">
                    <table className="w-full text-xs">
                      <thead className="sticky top-0 bg-slate-900 text-slate-500 uppercase">
                        <tr>
                          <th className="text-left px-2 py-1.5 font-medium">Conversation</th>
                          <th className="text-left px-2 py-1.5 font-medium">Proto</th>
                          <th className="text-left px-2 py-1.5 font-medium">Service</th>
                          <th className="text-right px-2 py-1.5 font-medium">Bytes</th>
                          <th className="px-2 py-1.5" />
                        </tr>
                      </thead>
                      <tbody data-testid="stream-connection-rows">
                        {followable.map((c) => {
                          const sel = connIsSelected(c);
                          return (
                            <tr
                              key={c.connection_id}
                              className={`border-t border-slate-800/60 ${sel ? "bg-blue-500/10" : "hover:bg-slate-800/40"}`}
                            >
                              <td className="px-2 py-1.5 font-mono text-slate-300">
                                {c.src_ip}:{c.src_port} → {c.dest_ip}:{c.dest_port}
                              </td>
                              <td className="px-2 py-1.5 uppercase text-slate-400">{c.proto}</td>
                              <td className="px-2 py-1.5 text-slate-400">{c.service ?? "—"}</td>
                              <td className="px-2 py-1.5 text-right text-slate-400">
                                {fmtBytes((c.bytes_sent ?? 0) + (c.bytes_recv ?? 0))}
                              </td>
                              <td className="px-2 py-1.5 text-right">
                                <button
                                  onClick={() =>
                                    selectStream({
                                      src: c.src_ip,
                                      sport: c.src_port!,
                                      dst: c.dest_ip,
                                      dport: c.dest_port!,
                                      proto: c.proto.toLowerCase() as "tcp" | "udp",
                                      pcap: selector.pcap,
                                    })
                                  }
                                  className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider transition-colors ${
                                    sel
                                      ? "border-blue-500/50 bg-blue-500/20 text-blue-300"
                                      : "border-slate-700 bg-slate-800 text-slate-400 hover:text-blue-300 hover:border-blue-500/30"
                                  }`}
                                >
                                  {sel ? "Following" : "Follow"}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* ── Stream viewer ── */}
              {!active ? (
                <p
                  className="rounded border border-dashed border-slate-700 p-8 text-center text-sm text-slate-500"
                  data-testid="stream-empty-state"
                >
                  Select a conversation above to follow it.
                </p>
              ) : (
                <div className="rounded-lg border border-slate-800 bg-slate-900/50" data-testid="stream-viewer">
                  {/* Viewer header */}
                  <div className="flex items-center justify-between gap-3 flex-wrap border-b border-slate-800 px-4 py-2">
                    <span className="font-mono text-xs text-slate-300">
                      {active.src}:{active.sport} → {active.dst}:{active.dport}
                      <span className="ml-2 uppercase text-slate-500">{active.proto}</span>
                    </span>
                    <div className="flex items-center gap-2">
                      <div className="flex rounded border border-slate-700 overflow-hidden">
                        {(["ascii", "hex"] as ViewMode[]).map((m) => (
                          <button
                            key={m}
                            onClick={() => setView(m)}
                            data-testid={`stream-view-${m}`}
                            className={`px-3 py-1 text-xs transition-colors ${
                              view === m
                                ? "bg-blue-600 text-white"
                                : "bg-slate-800 text-slate-400 hover:text-slate-100"
                            }`}
                          >
                            {m === "ascii" ? "Transcript" : "Hexdump"}
                          </button>
                        ))}
                      </div>
                      <button
                        onClick={handleCarve}
                        disabled={carving}
                        data-testid="stream-carve"
                        className="px-3 py-1 rounded border border-slate-700 bg-slate-800 text-xs text-slate-300 hover:text-slate-100 hover:border-slate-600 disabled:opacity-50"
                      >
                        {carving ? "Carving…" : "⬇ Save as PCAP"}
                      </button>
                    </div>
                  </div>

                  {/* Viewer body */}
                  <div className="p-4">
                    {activeLoading && (
                      <p className="text-sm text-slate-400 animate-pulse">
                        Reassembling stream — this shells out to {view === "ascii" ? "tshark" : "tcpdump"} and
                        can take a moment on large captures…
                      </p>
                    )}
                    {activeError && (
                      <p className="text-sm text-red-400" data-testid="stream-error">
                        {activeError.message || "Failed to extract the stream."}
                      </p>
                    )}

                    {view === "ascii" && asciiQ.data && (
                      <>
                        {asciiQ.data.truncated && (
                          <p className="mb-2 text-xs text-amber-400">
                            ⚠ Transcript truncated at {asciiQ.data.byte_count.toLocaleString()} characters.
                            Save as PCAP for the complete stream.
                          </p>
                        )}
                        {asciiQ.data.transcript.trim() ? (
                          <pre
                            data-testid="stream-transcript"
                            className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-3 text-xs leading-5 text-slate-300"
                          >
                            {asciiQ.data.transcript}
                          </pre>
                        ) : (
                          <p className="text-sm text-slate-500">
                            No payload data was reassembled for this conversation.
                          </p>
                        )}
                      </>
                    )}

                    {view === "hex" && hexQ.data && (
                      <>
                        {hexQ.data.truncated && (
                          <p className="mb-2 text-xs text-amber-400">
                            ⚠ Output truncated. Save as PCAP for the complete stream.
                          </p>
                        )}
                        {hexQ.data.packets.length > 0 ? (
                          <div
                            data-testid="stream-hexdump"
                            className="max-h-[32rem] space-y-3 overflow-auto rounded bg-slate-950 p-3"
                          >
                            {hexQ.data.packets.map((pkt, i) => (
                              <div key={i}>
                                <div className="font-mono text-[11px] text-cyan-400">{pkt.header}</div>
                                <pre className="font-mono text-[11px] leading-5 text-slate-400">
                                  {pkt.lines.join("\n")}
                                </pre>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-sm text-slate-500">No packets matched this conversation.</p>
                        )}
                      </>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        <HelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
      </div>
      <JobSubPageNav jobId={jobId} currentPath="streams" />
    </>
  );
};
