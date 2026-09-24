import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  downloadMnemosEvidenceReceipt,
  getMnemosEvidenceReceipt,
  listMnemosEvidenceReceipts,
  type MnemosEvidenceReceipt,
} from "../api/chat";

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export const MnemosReceiptsPage: React.FC = () => {
  const { receiptId } = useParams<{ receiptId?: string }>();
  const [receipts, setReceipts] = useState<MnemosEvidenceReceipt[]>([]);
  const [selected, setSelected] = useState<MnemosEvidenceReceipt | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setError(null);
    setLoading(true);
    if (receiptId) {
      setSelected(null);
      getMnemosEvidenceReceipt(receiptId)
        .then(receipt => { if (active) setSelected(receipt); })
        .catch((reason: unknown) => {
          if (active) setError(reason && typeof reason === "object" && "status" in reason && reason.status === 404 ? "not-found" : "detail-error");
        })
        .finally(() => { if (active) setLoading(false); });
    } else {
      setReceipts([]);
      setNextCursor(null);
      listMnemosEvidenceReceipts(50)
        .then(result => {
          if (active) {
            setReceipts(result.items);
            setNextCursor(result.page.next_cursor);
          }
        })
        .catch(() => { if (active) setError("list-error"); })
        .finally(() => { if (active) setLoading(false); });
    }
    return () => { active = false; };
  }, [receiptId]);

  const loadMore = async () => {
    if (!nextCursor || loadingMore) return;
    setLoadingMore(true);
    setError(null);
    try {
      const result = await listMnemosEvidenceReceipts(50, nextCursor);
      setReceipts(current => {
        const known = new Set(current.map(receipt => receipt.receipt_id));
        return [...current, ...result.items.filter(receipt => !known.has(receipt.receipt_id))];
      });
      setNextCursor(result.page.next_cursor);
    } catch {
      setError("page-error");
    } finally {
      setLoadingMore(false);
    }
  };

  if (receiptId) {
    if (loading) return <p role="status" className="text-sm text-slate-400">Loading evidence receipt…</p>;
    if (error === "not-found") return <section><h1 className="text-xl font-semibold">Evidence receipt not found</h1><Link className="mt-4 inline-block text-cyan-300 underline" to="/mnemos/receipts">Back to receipt history</Link></section>;
    if (error || !selected) return <section><h1 className="text-xl font-semibold">Could not load evidence receipt</h1><Link className="mt-4 inline-block text-cyan-300 underline" to="/mnemos/receipts">Back to receipt history</Link></section>;
    return <article className="mx-auto max-w-5xl space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Evidence Receipt</h1>
        <div className="flex items-center gap-4"><Link className="text-cyan-300 underline" to="/mnemos/receipts">Back to receipt history</Link>
          <button className="rounded border border-slate-600 px-3 py-1.5 text-sm hover:bg-slate-800" onClick={async () => {
            setDownloadError(null);
            try { await downloadMnemosEvidenceReceipt(selected.receipt_id); } catch { setDownloadError("Could not download evidence receipt JSON"); }
          }}>Download JSON</button>
        </div>
      </div>
      {downloadError && <p role="alert" className="text-sm text-red-300">{downloadError}</p>}
      <div className="grid gap-3 rounded-lg border border-slate-800 bg-slate-900 p-4 sm:grid-cols-2">
        <p><span className="text-slate-400">Created:</span> {formatDate(selected.created_at)}</p>
        <p><span className="text-slate-400">Receipt ID:</span> <code>{selected.receipt_id}</code></p>
        <p><span className="text-slate-400">Model:</span> {selected.model_id || "Unknown"}</p>
        <p><span className="text-slate-400">Retrieval status:</span> {selected.retrieval_status || "Unknown"}</p>
        <p><span className="text-slate-400">Content hash:</span> <code className="break-all">{selected.content_hash}</code></p>
        <p><span className="text-slate-400">Runtime:</span> {selected.runtime?.provider ? String(selected.runtime.provider) : "Unknown"}</p>
      </div>
      <section className="space-y-2"><h2 className="text-lg font-medium">Question</h2><p className="whitespace-pre-wrap rounded border border-slate-800 p-3">{selected.query}</p></section>
      <section className="space-y-2"><h2 className="text-lg font-medium">Answer</h2><p className="whitespace-pre-wrap rounded border border-slate-800 p-3">{selected.answer}</p></section>
      <section className="space-y-2"><h2 className="text-lg font-medium">Citations</h2>{selected.citations.length ? <ul className="list-disc space-y-1 pl-5">{selected.citations.map((citation, index) => <li key={`${citation.id ?? "citation"}-${index}`}>{citation.snippet || citation.id || JSON.stringify(citation)}</li>)}</ul> : <p className="text-slate-400">No citations recorded.</p>}</section>
      <section className="space-y-2"><h2 className="text-lg font-medium">Evidence references</h2>{selected.evidence_refs.length ? <pre className="overflow-auto rounded border border-slate-800 p-3 text-xs">{JSON.stringify(selected.evidence_refs, null, 2)}</pre> : <p className="text-slate-400">No evidence references recorded.</p>}</section>
      <section className="space-y-2"><h2 className="text-lg font-medium">Generation details</h2><pre className="overflow-auto rounded border border-slate-800 p-3 text-xs">{JSON.stringify(selected.generation, null, 2)}</pre></section>
    </article>;
  }

  return <section className="mx-auto max-w-6xl space-y-5">
    <div><h1 className="text-2xl font-semibold">MNEMOS Evidence Receipts</h1><p className="mt-1 text-sm text-slate-400">Completed MNEMOS answers and their supporting evidence.</p><p className="text-xs text-slate-500">Active and archived receipts</p></div>
    {loading && <p role="status" className="text-sm text-slate-400">Loading evidence receipts…</p>}
    {error === "list-error" && <p role="alert" className="text-sm text-red-300">Could not load evidence receipts</p>}
    {error === "page-error" && <p role="alert" className="text-sm text-red-300">Could not load the next page of evidence receipts</p>}
    {!loading && !error && receipts.length === 0 && <p className="rounded border border-slate-800 p-5 text-slate-400">No evidence receipts yet</p>}
    {receipts.length > 0 && <div className="overflow-x-auto rounded-lg border border-slate-800"><table className="w-full text-left text-sm"><thead className="bg-slate-900 text-slate-300"><tr><th className="p-3">Created</th><th className="p-3">Question</th><th className="p-3">Model</th><th className="p-3">Retrieval</th><th className="p-3">Sources</th></tr></thead><tbody>{receipts.map(receipt => <tr key={receipt.receipt_id} className="border-t border-slate-800"><td className="whitespace-nowrap p-3">{formatDate(receipt.created_at)}</td><td className="max-w-md p-3"><Link className="text-cyan-300 underline" to={`/mnemos/receipts/${encodeURIComponent(receipt.receipt_id)}`}>{receipt.query}</Link><div className="mt-1 text-xs text-slate-500">{receipt.receipt_id}</div></td><td className="p-3">{receipt.model_id || "Unknown"}</td><td className="p-3">{receipt.retrieval_status || "Unknown"}</td><td className="p-3">{receipt.citations.length + receipt.evidence_refs.length}</td></tr>)}</tbody></table></div>}
    {nextCursor && <button disabled={loadingMore} onClick={loadMore} className="rounded border border-slate-600 px-4 py-2 text-sm disabled:opacity-50">{loadingMore ? "Loading…" : "Load more"}</button>}
  </section>;
};
