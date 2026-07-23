import React, { useMemo, useState } from "react";
import type { EventFlowResponse, FlowNode } from "../../api";

interface FlowDiagramProps {
  flow: EventFlowResponse;
  /** Top-N links per stage the endpoint returned. When a stage comes back with
   *  exactly this many links, lower-volume flows were dropped — surfaced as a
   *  note so the diagram isn't read as the complete picture. */
  linkLimit?: number;
}

/** The three stages the backend emits, in left-to-right order. */
const KINDS = ["src", "host", "port"] as const;
type Kind = (typeof KINDS)[number];

const KIND_LABEL: Record<Kind, string> = {
  src: "Source IP",
  host: "Destination host",
  port: "Destination port",
};

/** Categorical slots 1–3 — the three that validate on the all-pairs list. */
const KIND_COLOR: Record<Kind, string> = {
  src: "var(--viz-series-1)",
  host: "var(--viz-series-2)",
  port: "var(--viz-series-3)",
};

const NODE_W = 12;
const NODE_GAP = 6;
const MIN_NODE_H = 4;
const COL_GAP = 190;
const PAD_Y = 12;
const LABEL_PAD = 8;
/** Left gutter for the source column's labels, which sit outside the plot. */
const LEFT_GUTTER = 120;
/** Minimum distance between node centres so adjacent labels cannot collide. */
const MIN_LABEL_PITCH = 16;

interface Placed {
  node: FlowNode;
  index: number;
  x: number;
  y: number;
  h: number;
  total: number;
}

/**
 * Layered flow diagram: source IP → destination host → destination port.
 *
 * A hand-rolled SVG layout rather than d3-sankey, which is not a dependency of
 * this project — adding one to an air-gapped build is not a decision to make
 * silently. Node height encodes throughput, ribbons encode per-link volume.
 */
export const FlowDiagram: React.FC<FlowDiagramProps> = ({ flow, linkLimit }) => {
  const [hoveredNode, setHoveredNode] = useState<number | null>(null);

  // A stage saturates when it returns exactly the requested top-N — the sign
  // that lower-volume flows in that stage were dropped. Stage 1 = src→host,
  // stage 2 = host→port, keyed off the source node's kind.
  const truncated = useMemo(() => {
    if (!linkLimit) return false;
    let stage1 = 0;
    let stage2 = 0;
    for (const l of flow.links) {
      const kind = flow.nodes[l.source]?.kind;
      if (kind === "src") stage1 += 1;
      else if (kind === "host") stage2 += 1;
    }
    return stage1 >= linkLimit || stage2 >= linkLimit;
  }, [flow, linkLimit]);

  const layout = useMemo(() => {
    const totals = new Map<number, number>();
    for (const l of flow.links) {
      totals.set(l.source, (totals.get(l.source) ?? 0) + l.value);
      totals.set(l.target, (totals.get(l.target) ?? 0) + l.value);
    }

    const columns: Placed[][] = KINDS.map((kind) =>
      flow.nodes
        .map((node, index) => ({ node, index }))
        .filter((n) => n.node.kind === kind)
        .map((n) => ({ ...n, x: 0, y: 0, h: 0, total: totals.get(n.index) ?? 0 }))
        .sort((a, b) => b.total - a.total),
    );

    // Scale so the busiest column fills the available height.
    const maxColTotal = Math.max(
      ...columns.map((c) => c.reduce((s, n) => s + n.total, 0)),
      1,
    );
    const tallestCount = Math.max(...columns.map((c) => c.length), 1);
    const plotH = Math.max(240, tallestCount * (MIN_NODE_H + NODE_GAP));
    const scale = (plotH - tallestCount * NODE_GAP) / maxColTotal;

    const placed = new Map<number, Placed>();
    let maxY = 0;
    columns.forEach((col, ci) => {
      let y = PAD_Y;
      let prevCentre = -Infinity;
      for (const n of col) {
        const h = Math.max(n.total * scale, MIN_NODE_H);
        // Small nodes can end up closer together than their labels are tall.
        // Push down until this node's centre clears the previous one.
        if (y + h / 2 - prevCentre < MIN_LABEL_PITCH) {
          y = prevCentre + MIN_LABEL_PITCH - h / 2;
        }
        const p = { ...n, x: LEFT_GUTTER + ci * COL_GAP, y, h };
        placed.set(n.index, p);
        prevCentre = y + h / 2;
        y += h + NODE_GAP;
        maxY = Math.max(maxY, y);
      }
    });

    const height = Math.max(maxY, plotH) + PAD_Y * 2;

    return { columns, placed, height };
  }, [flow]);

  if (flow.nodes.length === 0) {
    return (
      <p className="text-sm text-slate-500">
        No events carried both a source and destination IP, so there is no flow to draw.
      </p>
    );
  }

  const width = LEFT_GUTTER + (KINDS.length - 1) * COL_GAP + NODE_W + 150;

  // Ribbons: cubic beziers between the right edge of source and left of target.
  const ribbons = flow.links.map((l, i) => {
    const s = layout.placed.get(l.source);
    const t = layout.placed.get(l.target);
    if (!s || !t) return null;
    const x1 = s.x + NODE_W;
    const x2 = t.x;
    const y1 = s.y + s.h / 2;
    const y2 = t.y + t.h / 2;
    const mid = (x1 + x2) / 2;
    const active = hoveredNode === l.source || hoveredNode === l.target;
    const dim = hoveredNode != null && !active;
    return (
      <path
        key={i}
        d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
        fill="none"
        stroke="var(--viz-link)"
        strokeWidth={Math.max(1, Math.min(l.value / 4, 14))}
        opacity={dim ? 0.15 : active ? 0.9 : 1}
      >
        <title>
          {`${flow.nodes[l.source]?.label} → ${flow.nodes[l.target]?.label}: ${l.value.toLocaleString()} events`}
        </title>
      </path>
    );
  });

  return (
    <div className="viz space-y-3">
      {/* Legend — three series, so identity is never colour-alone. */}
      <div className="flex flex-wrap gap-4" data-testid="flow-legend">
        {KINDS.map((k) => (
          <span key={k} className="flex items-center gap-1.5 text-xs text-slate-400">
            <span
              className="inline-block h-2.5 w-2.5 rounded-sm"
              style={{ backgroundColor: KIND_COLOR[k] }}
            />
            {KIND_LABEL[k]}
          </span>
        ))}
      </div>

      <div className="overflow-x-auto">
        <svg
          width={width}
          height={layout.height}
          role="img"
          aria-label="Flow from source IP to destination host to destination port"
          data-testid="flow-diagram"
        >
          <g>{ribbons}</g>
          {[...layout.placed.values()].map((p) => {
            const kind = p.node.kind as Kind;
            const dim = hoveredNode != null && hoveredNode !== p.index;
            return (
              <g
                key={p.index}
                onMouseEnter={() => setHoveredNode(p.index)}
                onMouseLeave={() => setHoveredNode(null)}
                opacity={dim ? 0.4 : 1}
              >
                <rect
                  x={p.x}
                  y={p.y}
                  width={NODE_W}
                  height={p.h}
                  rx={3}
                  fill={KIND_COLOR[kind] ?? "var(--viz-series-1)"}
                />
                {/* Always-on labels: the light-mode palette WARNs on contrast,
                    which obligates visible labels rather than hover-only.
                    The source column labels sit in the left gutter so they do
                    not land on top of their own outgoing ribbons; the halo
                    keeps the inner columns legible where ribbons pass behind. */}
                <text
                  x={kind === "src" ? p.x - LABEL_PAD : p.x + NODE_W + LABEL_PAD}
                  y={p.y + p.h / 2}
                  textAnchor={kind === "src" ? "end" : "start"}
                  dominantBaseline="middle"
                  className="text-[10px]" fill="var(--viz-label)"
                  style={{ paintOrder: "stroke", stroke: "var(--viz-halo)", strokeWidth: 3 }}
                >
                  {p.node.label.length > 20 ? `${p.node.label.slice(0, 19)}…` : p.node.label}
                </text>
                <title>{`${KIND_LABEL[kind]} ${p.node.label} — ${p.total.toLocaleString()} events`}</title>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="text-xs text-slate-500">
        {flow.flows_considered.toLocaleString()} events with both endpoints considered · node
        height and ribbon width scale with event count
      </p>
      {truncated && (
        <p className="text-xs text-amber-400" data-testid="flow-truncated">
          ⚠ Showing the {linkLimit} highest-volume paths per stage; lower-volume flows are not
          drawn.
        </p>
      )}
    </div>
  );
};
