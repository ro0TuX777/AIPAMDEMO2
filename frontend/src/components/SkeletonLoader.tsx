import React from "react";

/* ── Primitive shimmer bar ─────────────────────────────────────────────── */
interface BarProps {
  className?: string;
}
export const SkeletonBar: React.FC<BarProps> = ({ className = "h-4 w-full" }) => (
  <div className={`rounded bg-slate-700/60 animate-pulse ${className}`} />
);

/* ── Table skeleton (header + N rows) ──────────────────────────────────── */
interface TableSkeletonProps {
  rows?: number;
  cols?: number;
}
export const TableSkeleton: React.FC<TableSkeletonProps> = ({ rows = 5, cols = 4 }) => (
  <div className="w-full space-y-2">
    {/* header */}
    <div className="flex gap-4 px-4 py-3 border-b border-slate-700/50">
      {Array.from({ length: cols }).map((_, i) => (
        <SkeletonBar key={i} className="h-3 flex-1" />
      ))}
    </div>
    {/* rows */}
    {Array.from({ length: rows }).map((_, r) => (
      <div key={r} className="flex gap-4 px-4 py-3">
        {Array.from({ length: cols }).map((_, c) => (
          <SkeletonBar key={c} className={`h-3 flex-1 ${c === 0 ? "max-w-[180px]" : ""}`} />
        ))}
      </div>
    ))}
  </div>
);

/* ── Card skeleton ─────────────────────────────────────────────────────── */
interface CardSkeletonProps {
  lines?: number;
}
export const CardSkeleton: React.FC<CardSkeletonProps> = ({ lines = 3 }) => (
  <div className="rounded-lg border border-slate-700/50 bg-slate-800/40 p-4 space-y-3">
    <SkeletonBar className="h-5 w-1/3" />
    {Array.from({ length: lines }).map((_, i) => (
      <SkeletonBar key={i} className={`h-3 ${i === lines - 1 ? "w-2/3" : "w-full"}`} />
    ))}
  </div>
);

/* ── Detail page skeleton (title + metadata + content blocks) ────────── */
export const DetailSkeleton: React.FC = () => (
  <div className="space-y-6 p-6">
    <SkeletonBar className="h-7 w-2/5" />
    <div className="flex gap-3">
      <SkeletonBar className="h-5 w-24" />
      <SkeletonBar className="h-5 w-32" />
      <SkeletonBar className="h-5 w-20" />
    </div>
    <div className="space-y-3">
      <SkeletonBar className="h-4 w-full" />
      <SkeletonBar className="h-4 w-full" />
      <SkeletonBar className="h-4 w-4/5" />
    </div>
    <div className="grid grid-cols-2 gap-4 pt-2">
      <CardSkeleton />
      <CardSkeleton />
    </div>
  </div>
);

/* ── Grid of card skeletons ────────────────────────────────────────────── */
interface CardGridSkeletonProps {
  count?: number;
}
export const CardGridSkeleton: React.FC<CardGridSkeletonProps> = ({ count = 6 }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
    {Array.from({ length: count }).map((_, i) => (
      <CardSkeleton key={i} />
    ))}
  </div>
);

