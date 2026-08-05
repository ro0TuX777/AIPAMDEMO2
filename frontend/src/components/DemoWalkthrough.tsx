import React, { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

interface DemoStep {
  id: string;
  title: string;
  body: string;
  route: string;
}

const COMPLETED_JOB_ID = "a7f3c2e1-9b04-4d17-8e62-3fc51a0d7b88";
const RUNNING_JOB_ID = "c41d8b60-27ae-4f93-a5d1-6b7e90c2f314";

const DEMO_STEPS: DemoStep[] = [
  {
    id: "dashboard",
    title: "1 · Dashboard",
    route: "/jobs",
    body: "Every analysis run appears here. Status colors mirror live behavior and only completed/failed runs expose cleanup actions.",
  },
  {
    id: "new-upload",
    title: "2 · New Analysis — Upload PCAP",
    route: "/new?demo_tab=upload",
    body: "Upload path for PCAP/PCAPNG/CAP with execution profile and optional evidence bundle labels.",
  },
  {
    id: "new-so",
    title: "3 · New Analysis — Security Onion",
    route: "/new?demo_tab=security_onion",
    body: "Pull a time window from Security Onion using API credentials and sensor selection.",
  },
  {
    id: "new-arkime",
    title: "4 · New Analysis — Arkime",
    route: "/new?demo_tab=arkime",
    body: "Submit an Arkime session expression for source-agnostic ingest into the same downstream pipeline.",
  },
  {
    id: "job-running",
    title: "5 · Job In Progress — Early Insights",
    route: `/jobs/${RUNNING_JOB_ID}`,
    body: "Pipeline and sensor progress update in real time; partial host, alert, and anomaly signals appear before LLM completion.",
  },
  {
    id: "job-overview",
    title: "6 · Completed Job — Executive Summary",
    route: `/jobs/${COMPLETED_JOB_ID}`,
    body: "Terminal state shows headline outcome, top signals, recommendations, and cross-linked evidence surfaces.",
  },
  {
    id: "job-mitre",
    title: "7 · ATT&CK-Oriented Context",
    route: `/jobs/${COMPLETED_JOB_ID}/findings?demo_focus=mitre`,
    body: "Findings prioritize behavior and mapped investigative context over fragile family-name attribution.",
  },
  {
    id: "job-chain",
    title: "8 · Attack Chain Timeline",
    route: `/jobs/${COMPLETED_JOB_ID}/timeline`,
    body: "Timeline assembles alert/finding sequence so each stage is supported by timestamped, inspectable evidence.",
  },
  {
    id: "job-anomaly",
    title: "9 · Behavioral Anomaly Detection",
    route: `/jobs/${COMPLETED_JOB_ID}/findings?demo_focus=anomaly`,
    body: "Heuristic detectors expose beacon, DNS entropy, lateral movement, and volume anomalies with confidence and rationale.",
  },
  {
    id: "job-llm-anomaly",
    title: "10 · Model-Assisted Reasoning",
    route: `/jobs/${COMPLETED_JOB_ID}/theories`,
    body: "LLM-driven theory synthesis is kept inspectable and evidence-linked, separate from deterministic detector output.",
  },
  {
    id: "job-hosts",
    title: "11 · Hosts",
    route: `/jobs/${COMPLETED_JOB_ID}/hosts`,
    body: "Per-host triage separates confirmed compromise from contested lateral targets and preserves nuance for analysts.",
  },
  {
    id: "job-raw",
    title: "12 · Raw Events",
    route: `/jobs/${COMPLETED_JOB_ID}/raw-events`,
    body: "Normalized raw events are always available for drill-down, aggregation, and flow reconstruction.",
  },
  {
    id: "job-report",
    title: "13 · Generated Report",
    route: `/jobs/${COMPLETED_JOB_ID}/report`,
    body: "Analyst and executive reports are generated artifacts, preserving the exact evidence snapshot used for handoff.",
  },
  {
    id: "job-chat",
    title: "14 · Ask Questions",
    route: `/jobs/${COMPLETED_JOB_ID}/chat`,
    body: "Case-scoped chat answers with citations, confidence boundaries, and follow-up prompts rooted in case evidence.",
  },
  {
    id: "settings",
    title: "15 · Settings",
    route: "/settings",
    body: "Model endpoint, role assignment, integrations, and storage controls are configurable without leaving the platform.",
  },
  {
    id: "training",
    title: "16 · Training Intelligence",
    route: "/training",
    body: "Training ledger, live progress, distillation controls, and export readiness stay visible for model lifecycle governance.",
  },
];

function normalize(path: string): string {
  return path.replace(/\/$/, "") || "/";
}

function routeMatch(route: string, pathname: string, search: string): boolean {
  const [routePath, routeQuery = ""] = route.split("?");
  if (normalize(routePath) !== pathname) return false;
  if (!routeQuery) return true;

  const routeParams = new URLSearchParams(routeQuery);
  const currentParams = new URLSearchParams(search);

  for (const [key, value] of routeParams.entries()) {
    if (currentParams.get(key) !== value) return false;
  }
  return true;
}

export const DemoWalkthrough: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [index, setIndex] = useState(0);

  const pathname = normalize(location.pathname);
  const search = location.search;

  const matchedIndex = useMemo(() => {
    const idx = DEMO_STEPS.findIndex((s) => routeMatch(s.route, pathname, search));
    return idx >= 0 ? idx : null;
  }, [pathname, search]);

  useEffect(() => {
    if (matchedIndex !== null) setIndex(matchedIndex);
  }, [matchedIndex]);

  const step = DEMO_STEPS[index];
  const atStart = index === 0;
  const atEnd = index === DEMO_STEPS.length - 1;

  const goTo = (nextIndex: number) => {
    const safe = Math.max(0, Math.min(DEMO_STEPS.length - 1, nextIndex));
    setIndex(safe);
    navigate(DEMO_STEPS[safe].route);
  };

  return (
    <div className="mb-4 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/30 p-4" data-testid="demo-walkthrough">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-[11px] uppercase tracking-[0.18em] text-cyan-300">Static Demo · Fictional Dataset</div>
          <h2 className="text-lg font-semibold text-slate-100">AIPAM Interactive Walkthrough</h2>
          <p className="mt-1 max-w-3xl text-sm text-slate-300">{step.title}: {step.body}</p>
        </div>
        <div className="flex items-center gap-2">
          <span className="rounded border border-slate-700 bg-slate-900/80 px-2 py-1 text-[11px] text-slate-400">{index + 1} / {DEMO_STEPS.length}</span>
          <button
            onClick={() => goTo(index - 1)}
            disabled={atStart}
            className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Prev
          </button>
          <button
            onClick={() => goTo(index + 1)}
            disabled={atEnd}
            className="rounded bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {DEMO_STEPS.map((s, i) => (
          <button
            key={s.id}
            onClick={() => goTo(i)}
            className={`h-2.5 w-2.5 rounded-full transition-all ${i === index ? "bg-cyan-400" : "bg-slate-600 hover:bg-slate-500"}`}
            aria-label={`Go to step ${i + 1}`}
            title={s.title}
          />
        ))}
      </div>

      <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
        <span className="rounded border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-amber-300">Static demo</span>
        <span className="rounded border border-sky-500/20 bg-sky-500/10 px-2 py-0.5 text-sky-300">No upload</span>
        <span className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-emerald-300">No inference</span>
        <span className="rounded border border-fuchsia-500/20 bg-fuchsia-500/10 px-2 py-0.5 text-fuchsia-300">Precomputed data</span>
        <span className="rounded border border-rose-500/20 bg-rose-500/10 px-2 py-0.5 text-rose-300">Fictional traffic</span>
      </div>
    </div>
  );
};
