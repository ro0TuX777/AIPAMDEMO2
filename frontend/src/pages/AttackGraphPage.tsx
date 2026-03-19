import React, { useRef, useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import * as d3 from "d3";
import { api, type GraphNode, type GraphEdge, type ProofItem, type ProofItemEntry, type ProofNarrativeResponse } from "../api";
import { PageHelpPanel, labelHint, usePageHelp } from "../components/PageHelpPanel";
import { useToast } from "../components/ToastProvider";

interface D3Node extends d3.SimulationNodeDatum, GraphNode { }
interface D3Link extends d3.SimulationLinkDatum<D3Node> {
    source: string | D3Node;
    target: string | D3Node;
    type: string;
    weight?: number;
}

type ViewMode = "topology" | "evidence";

const NODE_TYPES = [
    { key: "host", label: "Host", color: "#3b82f6", shape: "circle" },
    { key: "alert", label: "Alert", color: "#f59e0b", shape: "diamond" },
    { key: "finding", label: "Finding", color: "#8b5cf6", shape: "square" },
    { key: "theory", label: "Theory", color: "#10b981", shape: "triangle" },
    { key: "slice", label: "Slice", color: "#06b6d4", shape: "hexagon" },
    { key: "ioc", label: "IOC", color: "#ef4444", shape: "star" },
    { key: "annotation", label: "Annotation", color: "#f97316", shape: "pentagon" },
    { key: "external", label: "External", color: "#94a3b8", shape: "circle" },
] as const;

const TYPE_COLOR: Record<string, string> = Object.fromEntries(
    NODE_TYPES.map(t => [t.key, t.color])
);

const SEV_BORDER: Record<string, string> = {
    critical: "#dc2626",
    high: "#f43f5e",
    medium: "#f59e0b",
    low: "#3b82f6",
    info: "#475569",
};

// Severity levels ordered from most to least severe (for filtering)
const SEV_LEVELS = ["critical", "high", "medium", "low", "info"] as const;
type SeverityLevel = typeof SEV_LEVELS[number];
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function nodeRadius(d: D3Node): number {
    if (d.type === "host") return 12;
    if (d.type === "theory" || d.type === "slice") return 10;
    return 7;
}

function nodeColor(d: D3Node): string {
    const base = TYPE_COLOR[d.type] || "#94a3b8";
    if (d.type === "host" && d.severity === "high") return "#f43f5e";
    return base;
}

/** Map node type to D3 symbol for distinct shapes */
const TYPE_SHAPE: Record<string, d3.SymbolType> = {
    host: d3.symbolCircle,
    alert: d3.symbolDiamond,
    finding: d3.symbolSquare,
    theory: d3.symbolTriangle,
    slice: d3.symbolCross,
    ioc: d3.symbolStar,
    annotation: d3.symbolWye,
    external: d3.symbolCircle,
};

function nodeSymbolSize(d: D3Node): number {
    if (d.type === "host") return 350;
    if (d.type === "theory" || d.type === "slice") return 250;
    return 150;
}

function buildTooltip(d: D3Node): string {
    const lines = [`${d.type.toUpperCase()}: ${d.label}`];
    if (d.severity) lines.push(`Severity: ${d.severity}`);
    if (d.meta) {
        for (const [k, v] of Object.entries(d.meta)) {
            if (v != null) lines.push(`${k}: ${v}`);
        }
    }
    return lines.join("\n");
}

/** Check if a node passes the minimum severity filter.
 *  Hosts and types without severity always pass. */
function passesSeverityFilter(d: GraphNode, minSev: SeverityLevel): boolean {
    // Hosts, theories, slices always shown (they derive severity from children)
    if (d.type === "host" || d.type === "theory" || d.type === "slice" || d.type === "external") return true;
    const nodeSev = d.severity || "info";
    return (SEV_RANK[nodeSev] ?? 4) <= (SEV_RANK[minSev] ?? 4);
}

export const AttackGraphPage: React.FC = () => {
    const { jobId } = useParams<{ jobId: string }>();
    const svgRef = useRef<SVGSVGElement>(null);
    const [mode, setMode] = useState<ViewMode>("evidence");
    const [selectedNode, setSelectedNode] = useState<D3Node | null>(null);
    const [enabledTypes, setEnabledTypes] = useState<Set<string>>(
        new Set(NODE_TYPES.map(t => t.key))
    );
    const [minSeverity, setMinSeverity] = useState<SeverityLevel>("medium");
    const [zoomScale, setZoomScale] = useState(1);

    const topologyQuery = useQuery({
        queryKey: ["job", jobId, "graph"],
        queryFn: () => api.getJobGraph(jobId!),
        enabled: !!jobId && mode === "topology",
    });

    const evidenceQuery = useQuery({
        queryKey: ["job", jobId, "evidence-graph"],
        queryFn: () => api.getEvidenceGraph(jobId!),
        enabled: !!jobId && mode === "evidence",
    });

    const activeData = mode === "topology" ? topologyQuery.data : evidenceQuery.data;
    const isLoading = mode === "topology" ? topologyQuery.isLoading : evidenceQuery.isLoading;
    const error = mode === "topology" ? topologyQuery.error : evidenceQuery.error;

    // ── Proof Builder state ─────────────────────────────────────────────────
    const queryClient = useQueryClient();
    const [proofPanelOpen, setProofPanelOpen] = useState(false);
    const [activeProofId, setActiveProofId] = useState<string | null>(null);
    const [newProofTitle, setNewProofTitle] = useState("");

    const proofsQuery = useQuery({
        queryKey: ["job", jobId, "proofs"],
        queryFn: () => api.listProofs(jobId!),
        enabled: !!jobId && proofPanelOpen,
    });

    const proofItemsQuery = useQuery({
        queryKey: ["job", jobId, "proof-items", activeProofId],
        queryFn: () => api.listProofItems(jobId!, activeProofId!),
        enabled: !!jobId && !!activeProofId,
    });

    const createProofMut = useMutation({
        mutationFn: (title: string) => api.createProof(jobId!, { title }),
        onSuccess: (data) => {
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proofs"] });
            setActiveProofId(data.item.proof_id);
            setNewProofTitle("");
        },
    });

    const addItemMut = useMutation({
        mutationFn: (body: { entity_type: string; entity_id: string; role?: string; analyst_note?: string }) =>
            api.addProofItem(jobId!, activeProofId!, body),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proof-items", activeProofId] });
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proofs"] });
        },
    });

    const removeItemMut = useMutation({
        mutationFn: (itemId: string) => api.removeProofItem(jobId!, activeProofId!, itemId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proof-items", activeProofId] });
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proofs"] });
        },
    });

    const { addToast } = useToast();

    const deleteProofMut = useMutation({
        mutationFn: (proofId: string) => api.deleteProof(jobId!, proofId),
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proofs"] });
            if (activeProofId) setActiveProofId(null);
            addToast({ severity: "info", title: "Proof deleted" });
        },
        onError: () => addToast({ severity: "high", title: "Failed to delete proof" }),
    });

    const updateProofMut = useMutation({
        mutationFn: (body: { proofId: string } & Record<string, unknown>) => {
            const { proofId, ...rest } = body;
            return api.updateProof(jobId!, proofId, rest);
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["job", jobId, "proofs"] });
            addToast({ severity: "info", title: "Proof updated", duration: 3000 });
        },
        onError: () => addToast({ severity: "high", title: "Failed to update proof" }),
    });

    const narrativeMut = useMutation({
        mutationFn: (proofId: string) => api.renderProofNarrative(jobId!, proofId),
        onError: () => addToast({ severity: "high", title: "Failed to render narrative" }),
    });

    // Extra UI state
    const [pinNote, setPinNote] = useState("");
    const [narrativeModal, setNarrativeModal] = useState(false);
    const [editConclusion, setEditConclusion] = useState(false);
    const [conclusionDraft, setConclusionDraft] = useState("");
    const [editMeta, setEditMeta] = useState(false);
    const [metaSeverity, setMetaSeverity] = useState("info");
    const [metaConfidence, setMetaConfidence] = useState(0);
    const [metaStatus, setMetaStatus] = useState("draft");

    const activeProof = proofsQuery.data?.items.find(p => p.proof_id === activeProofId) ?? null;

    const pinSelectedNode = useCallback((role: string = "supports") => {
        if (!selectedNode || !activeProofId) return;
        addItemMut.mutate({
            entity_type: selectedNode.type,
            entity_id: selectedNode.id,
            role,
            ...(pinNote.trim() ? { analyst_note: pinNote.trim() } : {}),
        });
        setPinNote("");
    }, [selectedNode, activeProofId, addItemMut, pinNote]);

    const toggleType = useCallback((key: string) => {
        setEnabledTypes(prev => {
            const next = new Set(prev);
            if (next.has(key)) next.delete(key);
            else next.add(key);
            return next;
        });
    }, []);

    // ── D3 rendering ─────────────────────────────────────────────────────────
    useEffect(() => {
        if (!activeData || !svgRef.current) return;

        const width = 900;
        const height = 650;

        // Filter nodes by enabled types AND severity
        const filteredNodes = activeData.nodes.filter(
            n => enabledTypes.has(n.type) && passesSeverityFilter(n, minSeverity)
        );
        const filteredNodeIds = new Set(filteredNodes.map(n => n.id));
        const filteredEdges = activeData.edges.filter(
            e => filteredNodeIds.has(e.source as string) && filteredNodeIds.has(e.target as string)
        );

        // Build adjacency map for neighbor highlight
        const neighbors = new Map<string, Set<string>>();
        for (const e of filteredEdges) {
            const s = e.source as string;
            const t = e.target as string;
            if (!neighbors.has(s)) neighbors.set(s, new Set());
            if (!neighbors.has(t)) neighbors.set(t, new Set());
            neighbors.get(s)!.add(t);
            neighbors.get(t)!.add(s);
        }

        const svg = d3.select(svgRef.current);
        svg.selectAll("*").remove();

        const defs = svg.append("defs");
        defs.append("marker")
            .attr("id", "arrowhead")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 20)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("fill", "#475569");

        const g = svg.append("g");

        let currentZoom = 1;
        const zoom = d3.zoom<SVGSVGElement, unknown>()
            .scaleExtent([0.2, 5])
            .on("zoom", (event) => {
                g.attr("transform", event.transform);
                currentZoom = event.transform.k;
                setZoomScale(currentZoom);
                // Semantic zoom: toggle label visibility
                const showLabels = currentZoom >= 0.8;
                labels.attr("visibility", showLabels ? "visible" : "hidden");
                if (linkLabels) {
                    linkLabels.attr("visibility", currentZoom >= 1.2 ? "visible" : "hidden");
                }
            });

        svg.call(zoom);

        const simulation = d3.forceSimulation<D3Node>(filteredNodes as D3Node[])
            .force("link", d3.forceLink<D3Node, D3Link>(filteredEdges as D3Link[])
                .id(d => d.id)
                .distance(mode === "evidence" ? 120 : 100))
            .force("charge", d3.forceManyBody().strength(mode === "evidence" ? -400 : -300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => nodeRadius(d as D3Node) + 8));

        // Links
        const link = g.append("g")
            .attr("class", "links")
            .attr("stroke-opacity", 0.5)
            .selectAll("line")
            .data(filteredEdges as D3Link[])
            .join("line")
            .attr("stroke", "#475569")
            .attr("stroke-width", d => Math.sqrt(d.weight || 1))
            .attr("marker-end", mode === "evidence" ? "url(#arrowhead)" : null);

        // Link labels (evidence mode only) — hidden by default until zoom >= 1.2
        let linkLabels: d3.Selection<any, D3Link, SVGGElement, unknown> | null = null;
        if (mode === "evidence") {
            linkLabels = g.append("g")
                .selectAll("text")
                .data(filteredEdges as D3Link[])
                .join("text")
                .attr("fill", "#64748b")
                .attr("font-size", "8px")
                .attr("text-anchor", "middle")
                .attr("pointer-events", "none")
                .attr("visibility", "hidden")
                .text(d => d.type.replace(/_/g, " "));
        }

        // Nodes — render as distinct shapes using d3.symbol
        const nodeGroup = g.append("g").attr("class", "nodes");
        const node = nodeGroup
            .selectAll<SVGPathElement, D3Node>("path")
            .data(filteredNodes as D3Node[])
            .join("path")
            .attr("d", d => {
                const sym = d3.symbol().type(TYPE_SHAPE[d.type] || d3.symbolCircle).size(nodeSymbolSize(d));
                return sym() || "";
            })
            .attr("fill", d => nodeColor(d))
            .attr("stroke", d => SEV_BORDER[d.severity || "info"] || "#475569")
            .attr("stroke-width", 2)
            .attr("cursor", "pointer")
            .on("click", (_event, d) => setSelectedNode(d))
            .on("mouseenter", (_event, d) => {
                // Neighbor highlight: dim non-neighbors
                const neighborSet = neighbors.get(d.id) || new Set();
                node.attr("opacity", n => n.id === d.id || neighborSet.has(n.id) ? 1 : 0.12);
                link.attr("opacity", e => {
                    const sId = typeof e.source === "string" ? e.source : (e.source as D3Node).id;
                    const tId = typeof e.target === "string" ? e.target : (e.target as D3Node).id;
                    return sId === d.id || tId === d.id ? 1 : 0.05;
                });
                labels.attr("opacity", n => n.id === d.id || neighborSet.has(n.id) ? 1 : 0.08);
                if (linkLabels) linkLabels.attr("opacity", 0.08);
            })
            .on("mouseleave", () => {
                // Restore all
                node.attr("opacity", 1);
                link.attr("opacity", 1);
                labels.attr("opacity", 1);
                if (linkLabels) linkLabels.attr("opacity", 1);
            })
            .call(drag(simulation) as any);

        node.append("title").text(d => buildTooltip(d));

        // Labels — hidden by default until zoom >= 0.8 (semantic zoom)
        const labels = g.append("g")
            .selectAll("text")
            .data(filteredNodes as D3Node[])
            .join("text")
            .attr("dx", d => nodeRadius(d) + 6)
            .attr("dy", 4)
            .text(d => d.label.length > 30 ? d.label.slice(0, 28) + "…" : d.label)
            .attr("fill", "#cbd5e1")
            .attr("font-size", "10px")
            .attr("pointer-events", "none")
            .attr("visibility", "hidden");

        simulation.on("tick", () => {
            link
                .attr("x1", d => (d.source as any).x)
                .attr("y1", d => (d.source as any).y)
                .attr("x2", d => (d.target as any).x)
                .attr("y2", d => (d.target as any).y);

            if (linkLabels) {
                linkLabels
                    .attr("x", d => ((d.source as any).x + (d.target as any).x) / 2)
                    .attr("y", d => ((d.source as any).y + (d.target as any).y) / 2 - 4);
            }

            // Position shape nodes via transform (path elements use translate)
            node.attr("transform", d => `translate(${d.x},${d.y})`);
            labels.attr("x", d => d.x!).attr("y", d => d.y!);
        });

        function drag(sim: d3.Simulation<D3Node, undefined>) {
            return d3.drag<SVGPathElement, D3Node>()
                .on("start", (event) => {
                    if (!event.active) sim.alphaTarget(0.3).restart();
                    event.subject.fx = event.subject.x;
                    event.subject.fy = event.subject.y;
                })
                .on("drag", (event) => {
                    event.subject.fx = event.x;
                    event.subject.fy = event.y;
                })
                .on("end", (event) => {
                    if (!event.active) sim.alphaTarget(0);
                    event.subject.fx = null;
                    event.subject.fy = null;
                });
        }

        return () => { simulation.stop(); };
    }, [activeData, enabledTypes, mode, minSeverity]);

    // ── Node count summary ────────────────────────────────────────────────
    const typeCounts: Record<string, number> = {};
    if (activeData) {
        for (const n of activeData.nodes) {
            typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
        }
    }

    const { activeHelpField, setActiveHelpField, toggleHelp } = usePageHelp();

    return (
        <div className="space-y-4 h-full flex flex-col">
            <nav className="text-sm text-slate-400">
                <Link to="/jobs" className="hover:text-white">Jobs</Link>
                <span className="mx-1">/</span>
                <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
                <span className="mx-1">/</span>
                <span className="text-slate-200">Attack Graph</span>
            </nav>

            {/* Header with mode toggle */}
            <div className="flex items-center justify-between">
                <h1 className={`text-xl font-semibold ${labelHint(mode === "evidence" ? "evidence_graph" : "network_topology", activeHelpField)}`} onClick={() => toggleHelp(mode === "evidence" ? "evidence_graph" : "network_topology")}>
                    {mode === "evidence" ? "Evidence Graph" : "Network Topology"}
                </h1>
                <div className="flex items-center gap-2">
                    <div className="flex bg-slate-800 rounded-lg p-0.5">
                        <button
                            onClick={() => setMode("topology")}
                            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${mode === "topology"
                                ? "bg-slate-600 text-white"
                                : "text-slate-400 hover:text-white"
                                }`}
                        >
                            Network Topology
                        </button>
                        <button
                            onClick={() => setMode("evidence")}
                            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${mode === "evidence"
                                ? "bg-slate-600 text-white"
                                : "text-slate-400 hover:text-white"
                                }`}
                        >
                            Evidence Graph
                        </button>
                    </div>
                </div>
            </div>

            {/* Legend / type filter + severity filter (evidence mode) */}
            {mode === "evidence" && (
                <div className="flex items-center gap-3 flex-wrap text-xs">
                    {NODE_TYPES.filter(t => t.key !== "external").map(t => (
                        <button
                            key={t.key}
                            onClick={() => toggleType(t.key)}
                            className={`flex items-center gap-1.5 px-2 py-1 rounded border transition-colors ${enabledTypes.has(t.key)
                                ? "border-slate-600 bg-slate-800"
                                : "border-slate-700 bg-slate-900 opacity-40"
                                }`}
                        >
                            <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: t.color }}
                            />
                            <span className="text-slate-300">
                                {t.label}
                                {typeCounts[t.key] ? ` (${typeCounts[t.key]})` : ""}
                            </span>
                        </button>
                    ))}
                    {/* Severity filter */}
                    <div className="ml-auto flex items-center gap-1.5">
                        <span className="text-slate-500">Min severity:</span>
                        <select
                            value={minSeverity}
                            onChange={e => setMinSeverity(e.target.value as SeverityLevel)}
                            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
                        >
                            {SEV_LEVELS.map(s => (
                                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                            ))}
                        </select>
                        <span className="text-slate-600 ml-2">
                            Zoom: {zoomScale.toFixed(1)}×
                        </span>
                    </div>
                </div>
            )}

            {/* Topology mode legend */}
            {mode === "topology" && (
                <div className="flex items-center gap-4 text-xs">
                    <div className="flex items-center gap-1.5">
                        <div className="w-3 h-3 rounded-full bg-blue-500" />
                        <span className="text-slate-400">Internal Host</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <div className="w-3 h-3 rounded-full bg-rose-500" />
                        <span className="text-slate-400">High Risk</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <div className="w-3 h-3 rounded-full bg-slate-400" />
                        <span className="text-slate-400">External</span>
                    </div>
                </div>
            )}

            <div className="flex-1 flex gap-4 min-h-[600px]">
                {/* Graph canvas */}
                <div className="flex-1 bg-slate-950 border border-slate-800 rounded-lg overflow-hidden relative">
                    {isLoading && (
                        <div className="absolute inset-0 flex items-center justify-center bg-slate-950/50 z-10">
                            <p className="text-slate-400 animate-pulse">
                                {mode === "evidence" ? "Building evidence graph…" : "Computing topology…"}
                            </p>
                        </div>
                    )}
                    {error && (
                        <div className="absolute inset-0 flex items-center justify-center bg-slate-950/50 z-10">
                            <p className="text-red-400">Failed to load graph data.</p>
                        </div>
                    )}
                    <svg
                        ref={svgRef}
                        className="w-full h-full cursor-move"
                        viewBox="0 0 900 650"
                        preserveAspectRatio="xMidYMid meet"
                    />
                    {activeData && (
                        <div className="absolute bottom-3 left-3 text-xs text-slate-500">
                            {(() => {
                                const shown = activeData.nodes.filter(
                                    n => enabledTypes.has(n.type) && passesSeverityFilter(n, minSeverity)
                                ).length;
                                return shown < activeData.nodes.length
                                    ? `${shown} / ${activeData.nodes.length} nodes`
                                    : `${activeData.nodes.length} nodes`;
                            })()} · {activeData.edges.length} edges
                            {zoomScale < 0.8 && <span className="ml-2 text-amber-500/70">Zoom in to see labels</span>}
                        </div>
                    )}
                </div>

                {/* Detail panel */}
                {selectedNode && mode === "evidence" && (
                    <div className="w-72 bg-slate-900 border border-slate-800 rounded-lg p-4 overflow-y-auto">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="text-sm font-semibold text-white">Node Details</h3>
                            <button
                                onClick={() => setSelectedNode(null)}
                                className="text-slate-500 hover:text-white text-xs"
                            >
                                ✕
                            </button>
                        </div>
                        <div className="space-y-2 text-xs">
                            <div className="flex items-center gap-2">
                                <div
                                    className="w-3 h-3 rounded-full"
                                    style={{ backgroundColor: nodeColor(selectedNode) }}
                                />
                                <span className="text-slate-300 font-medium">
                                    {selectedNode.type.toUpperCase()}
                                </span>
                            </div>
                            <div>
                                <span className="text-slate-500">Label:</span>{" "}
                                <span className="text-slate-200">{selectedNode.label}</span>
                            </div>
                            <div>
                                <span className="text-slate-500">ID:</span>{" "}
                                <span className="text-slate-200 font-mono text-[10px]">{selectedNode.id}</span>
                            </div>
                            {selectedNode.severity && (
                                <div>
                                    <span className="text-slate-500">Severity:</span>{" "}
                                    <span className={`font-medium ${selectedNode.severity === "critical" || selectedNode.severity === "high"
                                        ? "text-red-400"
                                        : selectedNode.severity === "medium"
                                            ? "text-yellow-400"
                                            : "text-slate-300"
                                        }`}>
                                        {selectedNode.severity}
                                    </span>
                                </div>
                            )}
                            {selectedNode.meta && Object.entries(selectedNode.meta).map(([k, v]) => (
                                v != null && (
                                    <div key={k}>
                                        <span className="text-slate-500">{k}:</span>{" "}
                                        <span className="text-slate-200">{String(v)}</span>
                                    </div>
                                )
                            ))}

                            {/* Pin to Proof actions */}
                            {activeProofId && (
                                <div className="mt-3 pt-3 border-t border-slate-700 space-y-1.5">
                                    <p className="text-[10px] text-slate-500 uppercase tracking-wide">Pin to Proof</p>
                                    <textarea
                                        value={pinNote}
                                        onChange={e => setPinNote(e.target.value)}
                                        placeholder="Analyst note (optional)…"
                                        rows={2}
                                        className="w-full text-[10px] px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-500 resize-none"
                                    />
                                    <div className="flex gap-1">
                                        <button onClick={() => pinSelectedNode("supports")}
                                            className="flex-1 text-[10px] px-2 py-1 rounded bg-emerald-900/50 text-emerald-300 hover:bg-emerald-800/60">
                                            + Supports
                                        </button>
                                        <button onClick={() => pinSelectedNode("contradicts")}
                                            className="flex-1 text-[10px] px-2 py-1 rounded bg-red-900/50 text-red-300 hover:bg-red-800/60">
                                            − Contradicts
                                        </button>
                                        <button onClick={() => pinSelectedNode("context")}
                                            className="flex-1 text-[10px] px-2 py-1 rounded bg-blue-900/50 text-blue-300 hover:bg-blue-800/60">
                                            ℹ️ Context
                                        </button>
                                    </div>
                                    {addItemMut.isSuccess && (
                                        <p className="text-[10px] text-emerald-400">✓ Pinned!</p>
                                    )}
                                    {addItemMut.isPending && (
                                        <p className="text-[10px] text-slate-400 animate-pulse">Pinning…</p>
                                    )}
                                </div>
                            )}
                            {!activeProofId && proofPanelOpen && (
                                <p className="mt-3 pt-3 border-t border-slate-700 text-[10px] text-slate-500 italic">
                                    Select a proof in the sidebar to pin this node.
                                </p>
                            )}
                        </div>
                    </div>
                )}

                {/* Proof Builder sidebar */}
                {proofPanelOpen && mode === "evidence" && (
                    <div className="w-72 bg-slate-900 border border-slate-800 rounded-lg p-4 overflow-y-auto">
                        <div className="flex items-center justify-between mb-3">
                            <h3 className="text-sm font-semibold text-white">Proof Builder</h3>
                            <button onClick={() => setProofPanelOpen(false)}
                                className="text-slate-500 hover:text-white text-xs">✕</button>
                        </div>

                        {/* Create new proof */}
                        <div className="mb-3">
                            <div className="flex gap-1">
                                <input
                                    value={newProofTitle}
                                    onChange={e => setNewProofTitle(e.target.value)}
                                    placeholder="New proof title…"
                                    className="flex-1 text-xs px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-500"
                                    onKeyDown={e => e.key === "Enter" && newProofTitle.trim() && createProofMut.mutate(newProofTitle.trim())}
                                />
                                <button
                                    onClick={() => newProofTitle.trim() && createProofMut.mutate(newProofTitle.trim())}
                                    className="text-xs px-2 py-1 rounded bg-cyan-900/50 text-cyan-300 hover:bg-cyan-800/60"
                                >+</button>
                            </div>
                        </div>

                        {/* Proof list */}
                        <div className="space-y-1.5 mb-3">
                            {proofsQuery.data?.items.map(p => (
                                <button key={p.proof_id}
                                    onClick={() => setActiveProofId(p.proof_id)}
                                    className={`w-full text-left text-xs px-2 py-1.5 rounded border ${activeProofId === p.proof_id
                                        ? "border-cyan-500 bg-cyan-900/30 text-cyan-200"
                                        : "border-slate-700 bg-slate-800 text-slate-300 hover:border-slate-600"
                                        }`}>
                                    <div className="font-medium truncate">{p.title}</div>
                                    <div className="text-[10px] text-slate-500">
                                        {p.item_count} items · {p.status} · {p.severity}
                                    </div>
                                </button>
                            ))}
                            {proofsQuery.data?.items.length === 0 && (
                                <p className="text-[10px] text-slate-500 text-center py-2">
                                    No proofs yet. Create one above.
                                </p>
                            )}
                        </div>

                        {/* Active proof details */}
                        {activeProofId && activeProof && (
                            <div className="space-y-3">
                                {/* Proof metadata bar */}
                                <div className="flex items-center gap-1 text-[10px]">
                                    <span className={`px-1.5 py-0.5 rounded ${activeProof.status === "final" ? "bg-emerald-900/50 text-emerald-300" : activeProof.status === "archived" ? "bg-slate-700 text-slate-400" : "bg-amber-900/40 text-amber-300"}`}>
                                        {activeProof.status}
                                    </span>
                                    <span className={`px-1.5 py-0.5 rounded ${activeProof.severity === "critical" || activeProof.severity === "high" ? "bg-red-900/40 text-red-300" : activeProof.severity === "medium" ? "bg-amber-900/40 text-amber-300" : "bg-slate-700 text-slate-400"}`}>
                                        {activeProof.severity}
                                    </span>
                                    <span className="text-slate-500">{(activeProof.confidence * 100).toFixed(0)}%</span>
                                    <div className="flex-1" />
                                    <button onClick={() => { setEditMeta(true); setMetaSeverity(activeProof.severity); setMetaConfidence(activeProof.confidence); setMetaStatus(activeProof.status); }}
                                        className="text-slate-500 hover:text-white" title="Edit metadata">⚙</button>
                                    <button onClick={() => { if (confirm("Delete this proof?")) deleteProofMut.mutate(activeProofId); }}
                                        className="text-slate-500 hover:text-red-400" title="Delete proof">Del</button>
                                </div>

                                {/* Metadata editor */}
                                {editMeta && (
                                    <div className="p-2 rounded border border-slate-700 bg-slate-800/50 space-y-2 text-[10px]">
                                        <div className="flex items-center gap-2">
                                            <label className="text-slate-400 w-16">Status</label>
                                            <select value={metaStatus} onChange={e => setMetaStatus(e.target.value)}
                                                className="flex-1 bg-slate-800 border border-slate-700 rounded px-1 py-0.5 text-slate-200">
                                                <option value="draft">Draft</option>
                                                <option value="final">Final</option>
                                                <option value="archived">Archived</option>
                                            </select>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <label className="text-slate-400 w-16">Severity</label>
                                            <select value={metaSeverity} onChange={e => setMetaSeverity(e.target.value)}
                                                className="flex-1 bg-slate-800 border border-slate-700 rounded px-1 py-0.5 text-slate-200">
                                                {["info", "low", "medium", "high", "critical"].map(s => <option key={s} value={s}>{s}</option>)}
                                            </select>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <label className="text-slate-400 w-16">Confidence</label>
                                            <input type="range" min={0} max={100} value={metaConfidence * 100}
                                                onChange={e => setMetaConfidence(Number(e.target.value) / 100)}
                                                className="flex-1" />
                                            <span className="text-slate-300 w-8 text-right">{(metaConfidence * 100).toFixed(0)}%</span>
                                        </div>
                                        <div className="flex gap-1 justify-end">
                                            <button onClick={() => setEditMeta(false)}
                                                className="px-2 py-0.5 rounded bg-slate-700 text-slate-300 hover:bg-slate-600">Cancel</button>
                                            <button onClick={() => {
                                                updateProofMut.mutate({ proofId: activeProofId, status: metaStatus, severity: metaSeverity, confidence: metaConfidence });
                                                setEditMeta(false);
                                            }} className="px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 hover:bg-cyan-800/60">Save</button>
                                        </div>
                                    </div>
                                )}

                                {/* Conclusion */}
                                <div>
                                    <div className="flex items-center justify-between mb-1">
                                        <h4 className="text-[10px] text-slate-500 uppercase tracking-wide">Conclusion</h4>
                                        <button onClick={() => { setEditConclusion(!editConclusion); setConclusionDraft(activeProof.conclusion || ""); }}
                                            className="text-[10px] text-slate-500 hover:text-white">{editConclusion ? "Cancel" : "✏ Edit"}</button>
                                    </div>
                                    {editConclusion ? (
                                        <div className="space-y-1">
                                            <textarea value={conclusionDraft} onChange={e => setConclusionDraft(e.target.value)}
                                                rows={3} className="w-full text-[10px] px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-500 resize-none"
                                                placeholder="Write your conclusion…" />
                                            <button onClick={() => {
                                                updateProofMut.mutate({ proofId: activeProofId, conclusion: conclusionDraft });
                                                setEditConclusion(false);
                                            }} className="text-[10px] px-2 py-0.5 rounded bg-cyan-900/50 text-cyan-300 hover:bg-cyan-800/60">Save</button>
                                        </div>
                                    ) : (
                                        <p className="text-[10px] text-slate-300 italic">
                                            {activeProof.conclusion || "No conclusion yet — click Edit to add one."}
                                        </p>
                                    )}
                                </div>

                                {/* Pinned items */}
                                <div>
                                    <h4 className="text-[10px] text-slate-500 uppercase tracking-wide mb-1">
                                        Pinned Evidence ({proofItemsQuery.data?.items.length ?? 0})
                                    </h4>
                                    <div className="space-y-1">
                                        {proofItemsQuery.data?.items.map(it => (
                                            <div key={it.item_id}
                                                className="flex items-start gap-1 text-[10px] px-2 py-1 rounded bg-slate-800 border border-slate-700">
                                                <span>{it.role === "supports" ? "+" : it.role === "contradicts" ? "−" : "i"}</span>
                                                <div className="flex-1 min-w-0">
                                                    <span className="text-slate-400">{it.entity_type.toUpperCase()}</span>{" "}
                                                    <span className="text-slate-200 truncate block">{it.label || it.entity_id}</span>
                                                    {it.analyst_note && (
                                                        <span className="text-slate-500 italic block truncate">{it.analyst_note}</span>
                                                    )}
                                                </div>
                                                <button onClick={() => removeItemMut.mutate(it.item_id)}
                                                    className="text-slate-600 hover:text-red-400 shrink-0">✕</button>
                                            </div>
                                        ))}
                                        {(proofItemsQuery.data?.items.length ?? 0) === 0 && (
                                            <p className="text-[10px] text-slate-500 text-center py-2">
                                                Click a node on the graph, then pin it here.
                                            </p>
                                        )}
                                    </div>
                                </div>

                                {/* Render Narrative button */}
                                <button
                                    onClick={() => { narrativeMut.mutate(activeProofId); setNarrativeModal(true); }}
                                    disabled={narrativeMut.isPending || (proofItemsQuery.data?.items.length ?? 0) === 0}
                                    className="w-full text-xs px-3 py-2 rounded border border-cyan-700 bg-cyan-900/30 text-cyan-300 hover:bg-cyan-800/40 disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    {narrativeMut.isPending ? "Rendering…" : "Render Narrative"}
                                </button>
                            </div>
                        )}
                    </div>
                )}
            </div>

            {/* Proof Builder toggle */}
            {mode === "evidence" && (
                <div className="flex justify-end">
                    <button
                        onClick={() => setProofPanelOpen(!proofPanelOpen)}
                        className={`text-xs px-3 py-1.5 rounded border ${proofPanelOpen
                            ? "border-cyan-500 bg-cyan-900/30 text-cyan-300"
                            : "border-slate-700 bg-slate-800 text-slate-400 hover:text-white hover:border-slate-600"
                            }`}
                    >
                        {proofPanelOpen ? "Hide" : "Show"} Proof Builder
                    </button>
                </div>
            )}

            {/* Narrative Preview Modal */}
            {narrativeModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => setNarrativeModal(false)}>
                    <div className="bg-slate-900 border border-slate-700 rounded-lg w-[700px] max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700">
                            <h3 className="text-sm font-semibold text-white">Proof Narrative</h3>
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={() => {
                                        if (narrativeMut.data?.narrative_markdown) {
                                            navigator.clipboard.writeText(narrativeMut.data.narrative_markdown);
                                        }
                                    }}
                                    className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
                                >Copy</button>
                                <button onClick={() => setNarrativeModal(false)}
                                    className="text-slate-500 hover:text-white text-xs">✕</button>
                            </div>
                        </div>
                        <div className="flex-1 overflow-y-auto p-4">
                            {narrativeMut.isPending && (
                                <p className="text-slate-400 animate-pulse text-center py-8">Rendering narrative…</p>
                            )}
                            {narrativeMut.isError && (
                                <p className="text-red-400 text-center py-8">Failed to render narrative.</p>
                            )}
                            {narrativeMut.data && (
                                <pre className="text-xs text-slate-200 whitespace-pre-wrap font-mono leading-relaxed">
                                    {narrativeMut.data.narrative_markdown}
                                </pre>
                            )}
                        </div>
                    </div>
                </div>
            )}
            <PageHelpPanel activeField={activeHelpField} onClose={() => setActiveHelpField(null)} />
        </div>
    );
};
