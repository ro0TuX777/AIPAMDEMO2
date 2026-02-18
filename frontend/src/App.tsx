import React, { useEffect, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { DashboardPage } from "./pages/DashboardPage";
import { NewAnalysisPage } from "./pages/NewAnalysisPage";
import { JobDetailPage } from "./pages/JobDetailPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TrainingPage } from "./pages/TrainingPage";
import { ModelSetupModal } from "./components/ModelSetupModal";
import { api } from "./api";

export const App: React.FC = () => {
  const [showSetup, setShowSetup] = useState(false);
  const [checkingSetup, setCheckingSetup] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const status = await api.getSetupStatus();
        if (!status.model_configured) {
          setShowSetup(true);
        }
      } catch {
        // If backend is unreachable, don't block the UI
      } finally {
        setCheckingSetup(false);
      }
    })();
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100" data-testid="app-root">
      {/* Model setup modal (first-boot) */}
      {showSetup && !checkingSetup && (
        <ModelSetupModal onComplete={() => setShowSetup(false)} />
      )}

      <header
        className="border-b border-slate-800 px-6 py-3 flex items-center justify-between"
        data-testid="header"
      >
        <div className="flex items-center gap-3">
          <span className="font-semibold tracking-tight" data-testid="brand">
            AIPAM
          </span>
          <nav className="flex gap-4 text-sm text-slate-300" data-testid="nav-main">
            <Link to="/" data-testid="nav-dashboard">
              Dashboard
            </Link>
            <Link to="/new" data-testid="nav-new-analysis">
              New Analysis
            </Link>
            <Link to="/settings" data-testid="nav-settings">
              Settings
            </Link>
            <Link to="/training" data-testid="nav-training">
              Training
            </Link>
          </nav>
        </div>
      </header>
      <main className="p-6" data-testid="main-content">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/new" element={<NewAnalysisPage />} />
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/training" element={<TrainingPage />} />
        </Routes>
      </main>
    </div>
  );
};

