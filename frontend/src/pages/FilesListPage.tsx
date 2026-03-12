import React from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type FileItem } from "../api";

export const FilesListPage: React.FC = () => {
    const { jobId } = useParams<{ jobId: string }>();

    const { data, isLoading, error } = useQuery({
        queryKey: ["job", jobId, "files"],
        queryFn: () => api.listFiles(jobId!, { limit: 200 }),
        enabled: !!jobId,
    });

    const files = data?.items ?? [];

    return (
        <div className="space-y-4">
            <nav className="text-sm text-slate-400">
                <Link to="/jobs" className="hover:text-white">Jobs</Link>
                <span className="mx-1">/</span>
                <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
                <span className="mx-1">/</span>
                <span className="text-slate-200">Files</span>
            </nav>

            <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Extracted Files ({files.length})</h1>
            </div>

            {isLoading && <p className="text-slate-400 animate-pulse">Loading files…</p>}
            {error && <p className="text-red-400">Failed to load files.</p>}

            {!isLoading && files.length === 0 && (
                <p className="text-slate-500">No files extracted for this job.</p>
            )}

            {files.length > 0 && (
                <div className="space-y-3">
                    {files.map((f: FileItem) => (
                        <div key={f.file_id} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
                            <div className="flex items-start justify-between gap-4">
                                <div className="flex-1 space-y-2">
                                    <div className="flex items-center gap-3">
                                        <h3 className="text-sm font-semibold text-slate-200 truncate" title={f.filename ?? undefined}>
                                            {f.filename || "unknown_file"}
                                        </h3>
                                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-500 border border-slate-700">
                                            {f.mime || "application/octet-stream"}
                                        </span>
                                        {f.pcap_label && f.pcap_label !== "primary" && (
                                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                                                {f.pcap_label}
                                            </span>
                                        )}
                                    </div>

                                    {/* Network context: connection info from Zeek */}
                                    {f.extracted_path && (
                                        <div className="flex items-center gap-2 text-[11px]">
                                            <span className="text-slate-500 text-[10px] uppercase tracking-tighter">Connection:</span>
                                            <span className="font-mono text-cyan-300">{f.extracted_path}</span>
                                        </div>
                                    )}

                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-y-1 gap-x-4 text-[11px]">
                                        <div className="flex flex-col">
                                            <span className="text-slate-500 uppercase tracking-tighter">SHA256</span>
                                            <span className="text-slate-300 font-mono truncate" title={f.sha256}>{f.sha256}</span>
                                        </div>
                                        <div className="flex flex-col">
                                            <span className="text-slate-500 uppercase tracking-tighter">Size</span>
                                            <span className="text-slate-300">{(f.size_bytes / 1024).toFixed(1)} KB</span>
                                        </div>
                                        <div className="flex flex-col">
                                            <span className="text-slate-500 uppercase tracking-tighter">Source</span>
                                            <span className="text-slate-300 capitalize">{f.source || "unknown"}</span>
                                        </div>
                                        {f.ts && (
                                            <div className="flex flex-col">
                                                <span className="text-slate-500 uppercase tracking-tighter">Timestamp</span>
                                                <span className="text-slate-300">{new Date(f.ts).toLocaleString()}</span>
                                            </div>
                                        )}
                                    </div>

                                    {f.yara_matches && f.yara_matches.length > 0 && (
                                        <div className="mt-2 flex flex-wrap gap-1.5">
                                            <span className="text-[10px] text-red-400 font-bold uppercase self-center mr-1">YARA Matches:</span>
                                            {f.yara_matches.map((m, i) => (
                                                <span key={i} className="px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-[10px] font-mono">
                                                    {m}
                                                </span>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                <div className="flex flex-col items-end gap-2 shrink-0">
                                    <span className="text-[10px] text-slate-600 font-mono italic">{f.ts ? new Date(f.ts).toLocaleTimeString() : ""}</span>
                                    <button
                                        className="text-[10px] text-blue-400 hover:text-blue-300 underline"
                                        onClick={() => {
                                            api.downloadExtractedFile(jobId!, f.file_id, f.filename || f.file_id).catch(err => {
                                                console.error("Download failed:", err);
                                                alert("Download failed. Please try again.");
                                            });
                                        }}
                                    >
                                        ⬇ Download
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};
