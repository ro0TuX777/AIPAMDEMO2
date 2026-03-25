import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, FeedbackMetricsResponse, SensorTrustProfile, NoisySignature, DailyReviewCount } from "../api";

const TRUST_BAR_COLORS: Record<string, string> = {
  high: "bg-emerald-500",
  medium: "bg-yellow-500",
  low: "bg-red-500",
};

function trustLevel(rate: number): string {
  if (rate >= 0.7) return "high";
  if (rate >= 0.4) return "medium";
  return "low";
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

export const AdminFeedbackPage: React.FC = () => {
  const { data, isLoading, error } = useQuery<FeedbackMetricsResponse>({
    queryKey: ["admin", "feedback-metrics"],
    queryFn: () => api.getFeedbackMetrics(),
    refetchInterval: 30_000,
  });

  if (isLoading) return <p className="text-slate-400 animate-pulse p-8">Loading feedback metrics…</p>;
  if (error) return <p className="text-red-400 p-8">Failed to load feedback metrics.</p>;
  if (!data) return null;

  const { sensor_trust, noisy_signatures, overall_stats, time_series } = data;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link to="/jobs" className="text-xs text-slate-500 hover:text-slate-300">← Jobs</Link>
          <h1 className="text-xl font-semibold text-slate-100">📊 Feedback Analytics</h1>
          <p className="text-xs text-slate-500 mt-1">
            Cross-job analyst feedback patterns — used to tune Investigation Queue ranking.
          </p>
        </div>
      </div>

      {/* Overall Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Total Items", value: overall_stats.total_items, color: "text-slate-200" },
          { label: "Reviewed", value: overall_stats.total_reviewed, color: "text-cyan-400" },
          { label: "Confirm Rate", value: pct(overall_stats.confirmation_rate), color: "text-emerald-400" },
          { label: "FP Rate", value: pct(overall_stats.false_positive_rate), color: "text-red-400" },
        ].map((s) => (
          <div key={s.label} className="bg-slate-900/50 border border-slate-800 rounded-lg p-3 text-center">
            <div className={`text-lg font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-500">{s.label}</div>
          </div>
        ))}
      </div>
      {overall_stats.most_trusted_sensor && (
        <div className="flex gap-4 text-xs text-slate-400">
          <span>🏆 Most trusted: <span className="text-emerald-400 font-medium">{overall_stats.most_trusted_sensor}</span></span>
          {overall_stats.noisiest_sensor && (
            <span>🔊 Noisiest: <span className="text-red-400 font-medium">{overall_stats.noisiest_sensor}</span></span>
          )}
        </div>
      )}

      {/* Sensor Trust Table */}
      <section>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Sensor Trust Profiles</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left text-xs text-slate-500 uppercase">
                <th className="p-2">Sensor</th>
                <th className="p-2 w-20">Total</th>
                <th className="p-2 w-20">Confirmed</th>
                <th className="p-2 w-20">FP</th>
                <th className="p-2 w-32">Confirm Rate</th>
                <th className="p-2 w-24">Trust</th>
              </tr>
            </thead>
            <tbody>
              {sensor_trust.map((s: SensorTrustProfile) => {
                const level = trustLevel(s.confirmation_rate);
                return (
                  <tr key={s.sensor_name} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                    <td className="p-2 text-slate-200 font-medium">{s.sensor_name}</td>
                    <td className="p-2 text-slate-400 font-mono">{s.total_items}</td>
                    <td className="p-2 text-emerald-400 font-mono">{s.confirmed}</td>
                    <td className="p-2 text-red-400 font-mono">{s.false_positive}</td>
                    <td className="p-2">
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${TRUST_BAR_COLORS[level]}`}
                            style={{ width: `${Math.round(s.confirmation_rate * 100)}%` }} />
                        </div>
                        <span className="text-xs text-slate-400 font-mono">{pct(s.confirmation_rate)}</span>
                      </div>
                    </td>
                    <td className="p-2">
                      <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                        level === "high" ? "bg-emerald-900/50 text-emerald-300" :
                        level === "medium" ? "bg-yellow-900/50 text-yellow-300" :
                        "bg-red-900/50 text-red-300"
                      }`}>{level}</span>
                    </td>
                  </tr>
                );
              })}
              {sensor_trust.length === 0 && (
                <tr><td colSpan={6} className="p-4 text-center text-slate-500">No sensor data yet — review items to build trust profiles.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Noisy Signatures */}
      <section>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Noisy Signatures</h2>
        <p className="text-xs text-slate-500 mb-2">Signatures with ≥50% false-positive rate (minimum 3 reviews) are penalized in ranking.</p>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left text-xs text-slate-500 uppercase">
                <th className="p-2">Signature</th>
                <th className="p-2 w-24">Category</th>
                <th className="p-2 w-16">Total</th>
                <th className="p-2 w-16">FP</th>
                <th className="p-2 w-24">FP Rate</th>
                <th className="p-2 w-24">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {noisy_signatures.map((n: NoisySignature) => (
                <tr key={n.signature_name} className="border-b border-slate-800/50 hover:bg-slate-900/60">
                  <td className="p-2 text-slate-200 font-medium truncate max-w-xs" title={n.signature_name}>{n.signature_name}</td>
                  <td className="p-2 text-slate-400 text-xs">{n.category ?? "—"}</td>
                  <td className="p-2 text-slate-400 font-mono">{n.total_occurrences}</td>
                  <td className="p-2 text-red-400 font-mono">{n.false_positive_count}</td>
                  <td className="p-2">
                    <span className={`font-mono text-xs ${n.false_positive_rate >= 0.5 ? "text-red-400" : "text-yellow-400"}`}>
                      {pct(n.false_positive_rate)}
                    </span>
                  </td>
                  <td className="p-2 text-slate-500 text-xs">{n.last_seen ? n.last_seen.slice(0, 10) : "—"}</td>
                </tr>
              ))}
              {noisy_signatures.length === 0 && (
                <tr><td colSpan={6} className="p-4 text-center text-slate-500">No noisy signatures detected yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Daily Review Chart (simple bar chart) */}
      <section>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">Daily Reviews (Last 30 Days)</h2>
        {time_series.daily_reviews.length === 0 ? (
          <p className="text-xs text-slate-500">No review data yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <div className="flex items-end gap-1 h-32 min-w-[400px]">
              {time_series.daily_reviews.map((d: DailyReviewCount) => {
                const total = d.confirmed + d.false_positive + d.deferred + d.needs_review;
                const maxTotal = Math.max(...time_series.daily_reviews.map(
                  (x: DailyReviewCount) => x.confirmed + x.false_positive + x.deferred + x.needs_review
                ), 1);
                const heightPct = (total / maxTotal) * 100;
                const confPct = total > 0 ? (d.confirmed / total) * 100 : 0;
                const fpPct = total > 0 ? (d.false_positive / total) * 100 : 0;
                return (
                  <div key={d.date} className="flex-1 flex flex-col items-center group relative" title={`${d.date}: ${total} reviews`}>
                    <div className="w-full rounded-t overflow-hidden" style={{ height: `${heightPct}%` }}>
                      <div className="h-full flex flex-col-reverse">
                        <div className="bg-emerald-500" style={{ height: `${confPct}%` }} />
                        <div className="bg-red-500" style={{ height: `${fpPct}%` }} />
                        <div className="bg-slate-600 flex-1" />
                      </div>
                    </div>
                    <div className="absolute -bottom-5 text-[9px] text-slate-600 rotate-45 origin-left whitespace-nowrap">
                      {d.date.slice(5)}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex gap-4 mt-8 text-xs text-slate-500">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-emerald-500 inline-block" /> Confirmed</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-red-500 inline-block" /> False Positive</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded bg-slate-600 inline-block" /> Other</span>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};

