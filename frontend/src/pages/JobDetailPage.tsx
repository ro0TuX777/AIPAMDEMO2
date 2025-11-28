import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api, JobStatusResponse, JobResultResponse } from "../api";

type JobDetailTabId = "overview" | "hosts" | "raw" | "report";


export const JobDetailPage: React.FC = () => {
  const { jobId } = useParams<{ jobId: string }>();
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const [result, setResult] = useState<JobResultResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<JobDetailTabId>("overview");

  useEffect(() => {
    if (!jobId) return;

    let pollInterval: NodeJS.Timeout;

    const fetchStatus = async () => {
      try {
        const jobData = await api.getJob(jobId);
        setJob(jobData);

        if (jobData.status === "completed" && !result) {
          const resultData = await api.getJobResult(jobId);
          setResult(resultData);
        } else if (jobData.status === "failed") {
          setError(jobData.error_message || "Job failed");
        }
      } catch (err) {
        console.error(err);
        setError("Failed to load job details");
      }
    };

    fetchStatus();
    pollInterval = setInterval(fetchStatus, 3000);

    return () => clearInterval(pollInterval);
  }, [jobId, result]);

  if (error) {
    return (
      <div className="p-4 text-red-400 border border-red-900/50 rounded bg-red-900/10">
        Error: {error}
        <div className="mt-2">
          <Link to="/" className="text-sm text-slate-400 hover:text-white underline">Back to Dashboard</Link>
        </div>
      </div>
    );
  }

  if (!job) {
    return <div className="text-slate-400 animate-pulse">Loading job details...</div>;
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-2xl font-semibold text-slate-100">Analysis Report</h1>
            <span className={`px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide
              ${job.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400' :
                job.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                  'bg-blue-500/20 text-blue-400'}`}>
              {job.status}
            </span>
          </div>
          <div className="text-sm text-slate-400 font-mono">ID: {job.job_id}</div>
        </div>
        <Link to="/" className="text-sm text-slate-400 hover:text-white transition-colors">
          ← Back to Dashboard
        </Link>
      </div>

      {/* Progress Steps */}
      <div className="grid grid-cols-5 gap-4">
        {job.steps.map((step, idx) => (
          <div key={step.name} className="relative">
            <div className={`h-1 w-full rounded-full mb-2
              ${step.status === 'completed' ? 'bg-emerald-500' :
                step.status === 'running' ? 'bg-blue-500 animate-pulse' :
                  step.status === 'failed' ? 'bg-red-500' : 'bg-slate-800'}`}
            />
            <div className="text-xs font-medium text-slate-300 uppercase tracking-wider">{step.name}</div>
            <div className="text-[10px] text-slate-500 mt-0.5 capitalize">{step.status}</div>
          </div>
        ))}
      </div>

      {/* Results Tabs */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-500">
          {/* Tab List */}
          <div className="border-b border-slate-800 flex gap-4 text-sm" data-testid="jobdetail-tabs">
            <button
              type="button"
              data-testid="tab-overview"
              onClick={() => setActiveTab("overview")}
              className={
                activeTab === "overview"
                  ? "border-b-2 border-emerald-400 text-emerald-400 pb-2"
                  : "border-b-2 border-transparent text-slate-400 hover:text-slate-200 pb-2"
              }
            >
              Overview
            </button>
            <button
              type="button"
              data-testid="tab-hosts"
              onClick={() => setActiveTab("hosts")}
              className={
                activeTab === "hosts"
                  ? "border-b-2 border-emerald-400 text-emerald-400 pb-2"
                  : "border-b-2 border-transparent text-slate-400 hover:text-slate-200 pb-2"
              }
            >
              Hosts
            </button>
            <button
              type="button"
              data-testid="tab-raw-json"
              onClick={() => setActiveTab("raw")}
              className={
                activeTab === "raw"
                  ? "border-b-2 border-emerald-400 text-emerald-400 pb-2"
                  : "border-b-2 border-transparent text-slate-400 hover:text-slate-200 pb-2"
              }
            >
              Raw JSON
            </button>
            <button
              type="button"
              data-testid="tab-report"
              onClick={() => setActiveTab("report")}
              className={
                activeTab === "report"
                  ? "border-b-2 border-emerald-400 text-emerald-400 pb-2"
                  : "border-b-2 border-transparent text-slate-400 hover:text-slate-200 pb-2"
              }
            >
              Report
            </button>
          </div>

          {/* Tab Panels */}
          {activeTab === "overview" && (
            <div data-testid="tab-panel-overview" className="space-y-6">
              {/* Summary Card */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-slate-100 mb-4">Executive Summary</h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="p-4 bg-slate-950 rounded border border-slate-800">
                    <div className="text-sm text-slate-400 mb-1">Overall Severity</div>
                    <div
                      className={`text-2xl font-bold capitalize
                      ${
                        result.summary.severity === "high" || result.summary.severity === "critical"
                          ? "text-red-400"
                          : result.summary.severity === "medium"
                            ? "text-orange-400"
                            : "text-emerald-400"
                      }`}
                    >
                      {result.summary.severity}
                    </div>
                  </div>
                  <div className="col-span-2 space-y-2">
                    <div className="text-sm text-slate-400">Key Findings</div>
                    <ul className="list-disc list-inside text-sm text-slate-300 space-y-1">
                      {result.summary.key_findings.map((finding: any, i: number) => (
                        <li key={i}>{String(finding)}</li>
                      ))}
                      {result.summary.key_findings.length === 0 && (
                        <li>No key findings reported.</li>
                      )}
                    </ul>
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-slate-100 mb-4">MITRE ATT&CK Techniques</h2>
                <div className="flex flex-wrap gap-2">
                  {result.summary.mitre_techniques.map((tech: any, i: number) => (
                    <div
                      key={i}
                      className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 flex items-center gap-2"
                    >
                      <span className="font-mono text-emerald-400">{tech.id}</span>
                      <span>{tech.name}</span>
                    </div>
                  ))}
                  {result.summary.mitre_techniques.length === 0 && (
                    <div className="text-slate-500 text-sm">No techniques mapped.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === "hosts" && (
            <div data-testid="tab-panel-hosts" className="bg-slate-900/50 border border-slate-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-slate-100 mb-4">Host Findings</h2>
              {(!result.hosts || result.hosts.length === 0) && (
                <div className="text-sm text-slate-400">No host-level findings reported.</div>
              )}
              {result.hosts && result.hosts.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="text-left text-slate-400 border-b border-slate-800">
                        <th className="py-2 pr-4">IP</th>
                        <th className="py-2 pr-4">Role</th>
                        <th className="py-2 pr-4">Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.hosts.map((host: any, idx: number) => (
                        <tr key={idx} className="border-b border-slate-800/60 align-top">
                          <td className="py-2 pr-4 font-mono text-slate-200">{host.ip}</td>
                          <td className="py-2 pr-4 text-slate-300">{host.role}</td>
                          <td className="py-2 pr-4 text-slate-300">
                            <ul className="list-disc list-inside space-y-1">
                              {(host.findings || []).map((f: string, i: number) => (
                                <li key={i}>{f}</li>
                              ))}
                            </ul>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeTab === "raw" && (
            <div data-testid="tab-panel-raw-json" className="bg-slate-950 border border-slate-800 rounded-lg p-4">
              <h2 className="text-sm font-semibold text-slate-100 mb-2">Raw Job Result JSON</h2>
              <pre className="mt-2 text-xs font-mono text-slate-400 overflow-auto max-h-96">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
          )}

          {activeTab === "report" && (
            <div data-testid="tab-panel-report" className="bg-slate-900/50 border border-slate-800 rounded-lg p-6 space-y-4">
              <h2 className="text-lg font-semibold text-slate-100">Generated Report</h2>
              {(!result.report_urls || Object.keys(result.report_urls).length === 0) && (
                <div className="text-sm text-slate-400">No report URLs available for this job.</div>
              )}
              {result.report_urls && Object.keys(result.report_urls).length > 0 && (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-2 text-sm">
                    {result.report_urls.html && (
                      <a
                        href={result.report_urls.html}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-100 hover:bg-slate-700"
                        data-testid="link-report-html"
                      >
                        Open HTML Report
                      </a>
                    )}
                    {result.report_urls.markdown && (
                      <a
                        href={result.report_urls.markdown}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-slate-100 hover:bg-slate-700"
                        data-testid="link-report-markdown"
                      >
                        Open Markdown Report
                      </a>
                    )}
                  </div>
                  {result.report_urls.html && (
                    <div className="border border-slate-800 rounded-lg overflow-hidden h-96">
                      <iframe
                        src={result.report_urls.html}
                        title="Job HTML Report"
                        className="w-full h-full bg-slate-950"
                        data-testid="iframe-report-html"
                      />
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
