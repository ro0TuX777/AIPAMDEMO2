import React, { useState } from "react";
import type { AnalystStatus } from "../api";

interface ReviewNotesPanelProps {
  currentStatus: string | null | undefined;
  analystNotes: string | null | undefined;
  reviewedAt: string | null | undefined;
  reviewerId: string | null | undefined;
  onStatusChange: (status: AnalystStatus, notes?: string) => void;
  isPending?: boolean;
}

const STATUS_CONFIG: { value: AnalystStatus; label: string; icon: string; color: string; bg: string }[] = [
  { value: "confirmed", label: "Confirmed", icon: "✓", color: "text-emerald-300", bg: "bg-emerald-800 hover:bg-emerald-700 border-emerald-600" },
  { value: "false_positive", label: "False Positive", icon: "✗", color: "text-red-300", bg: "bg-red-900 hover:bg-red-800 border-red-700" },
  { value: "needs_review", label: "Needs Review", icon: "👁", color: "text-purple-300", bg: "bg-purple-900 hover:bg-purple-800 border-purple-700" },
  { value: "deferred", label: "Deferred", icon: "⏸", color: "text-yellow-300", bg: "bg-yellow-900 hover:bg-yellow-800 border-yellow-700" },
];

const STATUS_BADGE: Record<string, { label: string; cls: string }> = {
  unreviewed: { label: "Unreviewed", cls: "bg-slate-700 text-slate-300 border-slate-600" },
  confirmed: { label: "Confirmed", cls: "bg-emerald-900/60 text-emerald-300 border-emerald-700" },
  false_positive: { label: "False Positive", cls: "bg-red-900/60 text-red-300 border-red-700" },
  needs_review: { label: "Needs Review", cls: "bg-purple-900/60 text-purple-300 border-purple-700" },
  deferred: { label: "Deferred", cls: "bg-yellow-900/60 text-yellow-300 border-yellow-700" },
};

export const ReviewNotesPanel: React.FC<ReviewNotesPanelProps> = ({
  currentStatus,
  analystNotes,
  reviewedAt,
  reviewerId,
  onStatusChange,
  isPending,
}) => {
  const [notes, setNotes] = useState(analystNotes ?? "");
  const [showNotes, setShowNotes] = useState(false);
  const effectiveStatus = currentStatus ?? "unreviewed";
  const badge = STATUS_BADGE[effectiveStatus] ?? STATUS_BADGE.unreviewed;

  const handleStatusChange = (status: AnalystStatus) => {
    onStatusChange(status, notes || undefined);
  };

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900/60 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Review Status</h3>
        <span className={`px-2 py-0.5 rounded text-xs font-medium border ${badge.cls}`}>{badge.label}</span>
      </div>

      {/* Status change buttons */}
      <div className="flex flex-wrap gap-1.5">
        {STATUS_CONFIG.filter((s) => s.value !== effectiveStatus).map((s) => (
          <button
            key={s.value}
            onClick={() => handleStatusChange(s.value)}
            disabled={isPending}
            className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors ${s.bg} ${s.color} disabled:opacity-50`}
          >
            {s.icon} {s.label}
          </button>
        ))}
      </div>

      {/* Notes toggle + editor */}
      <div>
        <button
          onClick={() => setShowNotes(!showNotes)}
          className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
        >
          {showNotes ? "▾ Hide notes" : "▸ Add notes"}
        </button>
        {showNotes && (
          <div className="mt-2 space-y-2">
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Analyst notes…"
              rows={3}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm text-slate-300 placeholder-slate-600 resize-y"
            />
            {notes !== (analystNotes ?? "") && (
              <button
                onClick={() => onStatusChange(effectiveStatus as AnalystStatus, notes)}
                disabled={isPending}
                className="px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded text-xs text-slate-200 disabled:opacity-50"
              >
                Save notes
              </button>
            )}
          </div>
        )}
      </div>

      {/* Review metadata */}
      {reviewedAt && (
        <div className="text-[11px] text-slate-600 space-x-3">
          <span>Reviewed: {new Date(reviewedAt).toLocaleString()}</span>
          {reviewerId && <span>by {reviewerId}</span>}
        </div>
      )}
    </div>
  );
};

