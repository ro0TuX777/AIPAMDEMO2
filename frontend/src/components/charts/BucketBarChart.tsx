import React, { useState } from "react";
import type { AggregationBucket } from "../../api";

interface BucketBarChartProps {
  buckets: AggregationBucket[];
  /** Total across all events, used for the share-of-total in the tooltip. */
  totalEvents: number;
  /** Clicking a bar drills into the event list filtered by this value. */
  onSelect?: (value: string | null) => void;
  /** Value currently used as a filter, highlighted as selected. */
  selectedValue?: string | null;
}

const ROW_H = 26;
const BAR_H = 14;
const LABEL_W = 190;
const VALUE_W = 76;

/**
 * Horizontal bars for grouped event counts.
 *
 * Horizontal because the categories are long and free-text (IPs, hostnames,
 * event types) — vertical columns would force rotated labels. Every bar uses
 * the same hue: these categories are nominal, so a darker-where-bigger ramp
 * would double-encode length as colour and burn the only free channel.
 */
export const BucketBarChart: React.FC<BucketBarChartProps> = ({
  buckets,
  totalEvents,
  onSelect,
  selectedValue,
}) => {
  const [hovered, setHovered] = useState<number | null>(null);

  if (buckets.length === 0) {
    return <p className="text-sm text-slate-500">No values to group.</p>;
  }

  const max = Math.max(...buckets.map((b) => b.count), 1);
  const height = buckets.length * ROW_H;
  const plotW = 520;
  const width = LABEL_W + plotW + VALUE_W;

  return (
    <div className="viz relative overflow-x-auto">
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={`Event counts by value, ${buckets.length} groups`}
        data-testid="bucket-bar-chart"
      >
        {buckets.map((b, i) => {
          const y = i * ROW_H;
          const w = Math.max((b.count / max) * plotW, 2);
          const label = b.value ?? "(none)";
          const isSelected = selectedValue != null && b.value === selectedValue;
          const isHovered = hovered === i;
          return (
            <g
              key={`${label}-${i}`}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onSelect?.(b.value)}
              className={onSelect ? "cursor-pointer" : undefined}
            >
              {/* Hit target spans the full row, not just the bar. */}
              <rect x={0} y={y} width={width} height={ROW_H} fill="transparent" />
              <text
                x={LABEL_W - 8}
                y={y + ROW_H / 2}
                textAnchor="end"
                dominantBaseline="middle"
                className={`text-[11px] ${isSelected ? "font-medium" : ""}`}
                fill={isSelected ? "var(--viz-label-strong)" : "var(--viz-label)"}
              >
                {label.length > 28 ? `${label.slice(0, 27)}…` : label}
              </text>
              <rect
                x={LABEL_W}
                y={y + (ROW_H - BAR_H) / 2}
                width={w}
                height={BAR_H}
                rx={4}
                fill="var(--viz-series-1)"
                opacity={isSelected || isHovered || selectedValue == null ? 1 : 0.45}
              />
              <text
                x={LABEL_W + w + 8}
                y={y + ROW_H / 2}
                dominantBaseline="middle"
                className="text-[11px] tabular-nums" fill="var(--viz-label)"
              >
                {b.count.toLocaleString()}
              </text>
              <title>
                {`${label} — ${b.count.toLocaleString()} events` +
                  (totalEvents > 0 ? ` (${((b.count / totalEvents) * 100).toFixed(1)}% of ${totalEvents.toLocaleString()})` : "")}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
