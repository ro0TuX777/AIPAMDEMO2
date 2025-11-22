import React from "react";
import { Link, Route, Routes, useNavigate } from "react-router-dom";
import { DashboardPage } from "./pages/DashboardPage";
import { NewAnalysisPage } from "./pages/NewAnalysisPage";
import { JobDetailPage } from "./pages/JobDetailPage";
import { SettingsPage } from "./pages/SettingsPage";

export const App: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="font-semibold tracking-tight">AIPAM</span>
          <nav className="flex gap-4 text-sm text-slate-300">
            <Link to="/">Dashboard</Link>
            <Link to="/new">New Analysis</Link>
            <Link to="/settings">Settings</Link>
          </nav>
        </div>
      </header>
      <main className="p-6">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/new" element={<NewAnalysisPage />} />
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  );
};

