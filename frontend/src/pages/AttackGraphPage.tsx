import React, { useRef, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import * as d3 from "d3";
import { api, type GraphNode, type GraphEdge } from "../api";

interface D3Node extends d3.SimulationNodeDatum, GraphNode { }
interface D3Link extends d3.SimulationLinkDatum<D3Node> {
    source: string | D3Node;
    target: string | D3Node;
    type: string;
    weight?: number;
}

export const AttackGraphPage: React.FC = () => {
    const { jobId } = useParams<{ jobId: string }>();
    const svgRef = useRef<SVGSVGElement>(null);

    const { data, isLoading, error } = useQuery({
        queryKey: ["job", jobId, "graph"],
        queryFn: () => api.getJobGraph(jobId!),
        enabled: !!jobId,
    });

    useEffect(() => {
        if (!data || !svgRef.current) return;

        const width = 800;
        const height = 600;

        const svg = d3.select(svgRef.current);
        svg.selectAll("*").remove();

        const g = svg.append("g");

        const zoom = d3.zoom<SVGSVGElement, unknown>().on("zoom", (event) => {
            g.attr("transform", event.transform);
        });

        svg.call(zoom);

        const simulation = d3.forceSimulation<D3Node>(data.nodes as D3Node[])
            .force("link", d3.forceLink<D3Node, D3Link>(data.edges as D3Link[]).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(40));

        const link = g.append("g")
            .attr("stroke", "#475569")
            .attr("stroke-opacity", 0.6)
            .selectAll("line")
            .data(data.edges as D3Link[])
            .join("line")
            .attr("stroke-width", d => Math.sqrt(d.weight || 1));

        const node = g.append("g")
            .attr("stroke", "#1e293b")
            .attr("stroke-width", 1.5)
            .selectAll("circle")
            .data(data.nodes as D3Node[])
            .join("circle")
            .attr("r", d => d.type === "host" ? 8 : 5)
            .attr("fill", d => {
                if (d.type === "host") return d.severity === "high" ? "#f43f5e" : "#3b82f6";
                return "#94a3b8";
            })
            .call(drag(simulation) as any);

        node.append("title")
            .text(d => `${d.label} (${d.type})`);

        const labels = g.append("g")
            .selectAll("text")
            .data(data.nodes as D3Node[])
            .join("text")
            .attr("dx", 10)
            .attr("dy", 4)
            .text(d => d.label)
            .attr("fill", "#94a3b8")
            .attr("font-size", "10px")
            .attr("pointer-events", "none");

        simulation.on("tick", () => {
            link
                .attr("x1", d => (d.source as any).x)
                .attr("y1", d => (d.source as any).y)
                .attr("x2", d => (d.target as any).x)
                .attr("y2", d => (d.target as any).y);

            node
                .attr("cx", d => d.x!)
                .attr("cy", d => d.y!);

            labels
                .attr("x", d => d.x!)
                .attr("y", d => d.y!);
        });

        function drag(simulation: d3.Simulation<D3Node, undefined>) {
            function dragstarted(event: any) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                event.subject.fx = event.subject.x;
                event.subject.fy = event.subject.y;
            }

            function dragged(event: any) {
                event.subject.fx = event.x;
                event.subject.fy = event.y;
            }

            function dragended(event: any) {
                if (!event.active) simulation.alphaTarget(0);
                event.subject.fx = null;
                event.subject.fy = null;
            }

            return d3.drag<SVGCircleElement, D3Node>()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended);
        }

        return () => {
            simulation.stop();
        };
    }, [data]);

    return (
        <div className="space-y-4 h-full flex flex-col">
            <nav className="text-sm text-slate-400">
                <Link to="/jobs" className="hover:text-white">Jobs</Link>
                <span className="mx-1">/</span>
                <Link to={`/jobs/${jobId}`} className="hover:text-white">{jobId?.slice(0, 8)}</Link>
                <span className="mx-1">/</span>
                <span className="text-slate-200">Attack Graph</span>
            </nav>

            <div className="flex items-center justify-between">
                <h1 className="text-xl font-semibold">Attack Graph</h1>
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
            </div>

            <div className="flex-1 bg-slate-950 border border-slate-800 rounded-lg overflow-hidden relative min-h-[600px]">
                {isLoading && (
                    <div className="absolute inset-0 flex items-center justify-center bg-slate-950/50 z-10">
                        <p className="text-slate-400 animate-pulse">Computing topology…</p>
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
                    viewBox="0 0 800 600"
                    preserveAspectRatio="xMidYMid meet"
                />
            </div>
        </div>
    );
};
