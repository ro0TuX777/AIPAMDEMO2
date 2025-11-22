import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, JobStatusResponse } from "../api";

export const DashboardPage: React.FC = () => {
  const [jobs, setJobs] = useState<JobStatusResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getJobs()
      .then(setJobs)
      .catch((err) => {
        console.error(err);
        setError("Failed to load jobs");
      })
      .finally(() => setLoading(false));
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "text-emerald-400 bg-emerald-400/10";
      case "running": return "text-blue-400 bg-blue-400/10";
      case "failed": return "text-red-400 bg-red-400/10";
      default: return "text-slate-400 bg-slate-400/10";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-slate-100">Dashboard</h1>
        <Link
          to="/new"
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-md text-sm font-medium transition-colors"
        >
          New Analysis
        </Link>
      </div>

      {loading ? (
        <div className="text-slate-400 animate-pulse">Loading jobs...</div>
      ) : error ? (
        <div className="text-red-400">{error}</div>
      ) : jobs.length === 0 ? (
        <div className="text-slate-400 border border-slate-800 rounded-lg p-8 text-center">
          No analysis jobs yet. Start a new one!
        </div>
      ) : (
        <div className="border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/50 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Job ID</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3 font-medium">Updated</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {jobs.map((job) => (
                <tr key={job.job_id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-4 py-3 font-mono text-slate-300">
                    {job.job_id.slice(0, 8)}...
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(job.status)}`}>
                      {job.status.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {new Date(job.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-slate-400">
                    {new Date(job.updated_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/jobs/${job.job_id}`}
                      className="text-emerald-400 hover:text-emerald-300 font-medium"
                    >
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

