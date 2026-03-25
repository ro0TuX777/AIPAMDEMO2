import React, { useEffect, useState } from "react";
import { Link, Navigate, Route, Routes } from "react-router-dom";
import { JobListPage } from "./pages/JobListPage";
import { NewAnalysisPage } from "./pages/NewAnalysisPage";
import { JobDetailPage } from "./pages/JobDetailPage";
import { HostListPage } from "./pages/HostListPage";
import { HostDetailPage, HostSubTab } from "./pages/HostDetailPage";
import { AlertsListPage } from "./pages/AlertsListPage";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { FindingsListPage } from "./pages/FindingsListPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { TimelinePage } from "./pages/TimelinePage";
import { IocsListPage } from "./pages/IocsListPage";
import { FilesListPage } from "./pages/FilesListPage";
import { AttackGraphPage } from "./pages/AttackGraphPage";
import { ArtifactsPage } from "./pages/ArtifactsPage";
import { ReportPage } from "./pages/ReportPage";
import { ChatPage } from "./pages/ChatPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TrainingPage } from "./pages/TrainingPage";
import { RulesManagementPage } from "./pages/RulesManagementPage";
import { AdminFeedbackPage } from "./pages/AdminFeedbackPage";
import { TheoriesPage } from "./pages/TheoriesPage";
import { SlicesPage } from "./pages/SlicesPage";
import { AnnotationsPage } from "./pages/AnnotationsPage";
import { InvestigationQueuePage } from "./pages/InvestigationQueuePage";
import { ComparePage } from "./pages/ComparePage";
import { ProofBuilderPage } from "./pages/ProofBuilderPage";
import { GlobalHostsPage } from "./pages/GlobalHostsPage";
import { GlobalHostDetailPage } from "./pages/GlobalHostDetailPage";
import { ModelSetupModal } from "./components/ModelSetupModal";
import { ToastProvider } from "./components/ToastProvider";
import { ThemeProvider, useTheme } from "./components/ThemeProvider";
import { api } from "./api";

const ThemeToggleButton: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  return (
    <button
      onClick={toggleTheme}
      className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      data-testid="theme-toggle"
      title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
    >
      {theme === "dark" ? (
        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" /></svg>
      ) : (
        <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" /></svg>
      )}
    </button>
  );
};

export const App: React.FC = () => {
  const [showSetup, setShowSetup] = useState(false);
  const [checkingSetup, setCheckingSetup] = useState(true);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

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
    <ThemeProvider>
    <ToastProvider>
    <div className="min-h-screen bg-slate-950 text-slate-100" data-testid="app-root">
      {/* Model setup modal (first-boot) */}
      {showSetup && !checkingSetup && (
        <ModelSetupModal onComplete={() => setShowSetup(false)} />
      )}

      <header
        className="border-b border-slate-800 px-4 sm:px-6 py-3 flex items-center justify-between"
        data-testid="header"
      >
        <div className="flex items-center gap-3">
          <span className="font-semibold tracking-tight" data-testid="brand">
            AIPAM
          </span>
          {/* Desktop nav */}
          <nav className="hidden md:flex gap-4 text-sm text-slate-300" data-testid="nav-main">
            <Link to="/jobs" data-testid="nav-jobs">Jobs</Link>
            <Link to="/new" data-testid="nav-new-analysis">New Analysis</Link>
            <Link to="/settings" data-testid="nav-settings">Settings</Link>
            <Link to="/training" data-testid="nav-training">Training</Link>
            <Link to="/rules" data-testid="nav-rules">Detection Rules</Link>
            <Link to="/hosts" data-testid="nav-global-hosts">Global Hosts</Link>
          </nav>
        </div>
        <div className="flex items-center gap-2">
          {/* Theme toggle */}
          <ThemeToggleButton />
          {/* Hamburger button (mobile only) */}
          <button
            className="md:hidden text-slate-300 hover:text-white p-1"
            onClick={() => setMobileNavOpen((v) => !v)}
            aria-label="Toggle navigation"
            data-testid="nav-hamburger"
          >
            {mobileNavOpen ? (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>
            )}
          </button>
        </div>
      </header>
      {/* Mobile nav dropdown */}
      {mobileNavOpen && (
        <nav className="md:hidden border-b border-slate-800 bg-slate-900 px-4 py-3 flex flex-col gap-2 text-sm text-slate-300" data-testid="nav-mobile">
          <Link to="/jobs" onClick={() => setMobileNavOpen(false)}>Jobs</Link>
          <Link to="/new" onClick={() => setMobileNavOpen(false)}>New Analysis</Link>
          <Link to="/settings" onClick={() => setMobileNavOpen(false)}>Settings</Link>
          <Link to="/training" onClick={() => setMobileNavOpen(false)}>Training</Link>
          <Link to="/rules" onClick={() => setMobileNavOpen(false)}>Detection Rules</Link>
          <Link to="/hosts" onClick={() => setMobileNavOpen(false)}>Global Hosts</Link>
        </nav>
      )}
      <main className="p-3 sm:p-6" data-testid="main-content">
        <Routes>
          {/* / → redirect to /jobs */}
          <Route path="/" element={<Navigate to="/jobs" replace />} />

          {/* Job list */}
          <Route path="/jobs" element={<JobListPage />} />

          {/* Job detail (summary tab default) */}
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />

          {/* Job sub-resources */}
          <Route path="/jobs/:jobId/investigation" element={<InvestigationQueuePage />} />
          <Route path="/jobs/:jobId/theories" element={<TheoriesPage />} />
          <Route path="/jobs/:jobId/slices" element={<SlicesPage />} />
          <Route path="/jobs/:jobId/annotations" element={<AnnotationsPage />} />
          <Route path="/jobs/:jobId/hosts" element={<HostListPage />} />
          <Route path="/jobs/:jobId/hosts/:ip" element={<HostDetailPage />}>
            <Route index element={<Navigate to="connections" replace />} />
            <Route path="connections" element={<HostSubTab label="Connections" />} />
            <Route path="dns" element={<HostSubTab label="DNS Queries" />} />
            <Route path="tls" element={<HostSubTab label="TLS Sessions" />} />
            <Route path="alerts" element={<HostSubTab label="Alerts" />} />
            <Route path="files" element={<HostSubTab label="Files" />} />
          </Route>
          <Route path="/jobs/:jobId/alerts" element={<AlertsListPage />} />
          <Route path="/jobs/:jobId/alerts/:alertId" element={<AlertDetailPage />} />
          <Route path="/jobs/:jobId/findings" element={<FindingsListPage />} />
          <Route path="/jobs/:jobId/findings/:findingId" element={<FindingDetailPage />} />
          <Route path="/jobs/:jobId/timeline" element={<TimelinePage />} />
          <Route path="/jobs/:jobId/iocs" element={<IocsListPage />} />
          <Route path="/jobs/:jobId/files" element={<FilesListPage />} />
          <Route path="/jobs/:jobId/graph" element={<AttackGraphPage />} />
          <Route path="/jobs/:jobId/artifacts" element={<ArtifactsPage />} />
          <Route path="/jobs/:jobId/chat" element={<ChatPage />} />
          <Route path="/jobs/:jobId/report" element={<ReportPage />} />
          <Route path="/jobs/:jobId/compare" element={<ComparePage />} />
          <Route path="/jobs/:jobId/proof" element={<ProofBuilderPage />} />
          <Route path="/jobs/:jobId/proof/:proofId" element={<ProofBuilderPage />} />

          {/* New analysis (V1 upload flow) */}
          <Route path="/new" element={<NewAnalysisPage />} />

          {/* Settings & Training (V1 pages, preserved) */}
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/training" element={<TrainingPage />} />
          <Route path="/rules" element={<RulesManagementPage />} />
          <Route path="/admin/feedback" element={<AdminFeedbackPage />} />

          {/* Global Hosts (cross-job forensics) */}
          <Route path="/hosts" element={<GlobalHostsPage />} />
          <Route path="/hosts/:ip" element={<GlobalHostDetailPage />} />
        </Routes>
      </main>
    </div>
    </ToastProvider>
    </ThemeProvider>
  );
};

