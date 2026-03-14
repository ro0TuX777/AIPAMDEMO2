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
import { TheoriesPage } from "./pages/TheoriesPage";
import { SlicesPage } from "./pages/SlicesPage";
import { AnnotationsPage } from "./pages/AnnotationsPage";
import { GlobalHostsPage } from "./pages/GlobalHostsPage";
import { GlobalHostDetailPage } from "./pages/GlobalHostDetailPage";
import { ModelSetupModal } from "./components/ModelSetupModal";
import { ToastProvider } from "./components/ToastProvider";
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
    <ToastProvider>
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
            <Link to="/jobs" data-testid="nav-jobs">
              Jobs
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
            <Link to="/rules" data-testid="nav-rules">
              Detection Rules
            </Link>
            <Link to="/hosts" data-testid="nav-global-hosts">
              Global Hosts
            </Link>
          </nav>
        </div>
      </header>
      <main className="p-6" data-testid="main-content">
        <Routes>
          {/* / → redirect to /jobs */}
          <Route path="/" element={<Navigate to="/jobs" replace />} />

          {/* Job list */}
          <Route path="/jobs" element={<JobListPage />} />

          {/* Job detail (summary tab default) */}
          <Route path="/jobs/:jobId" element={<JobDetailPage />} />

          {/* Job sub-resources */}
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
          <Route path="/jobs/:jobId/timeline" element={<TimelinePage />} />
          <Route path="/jobs/:jobId/iocs" element={<IocsListPage />} />
          <Route path="/jobs/:jobId/files" element={<FilesListPage />} />
          <Route path="/jobs/:jobId/graph" element={<AttackGraphPage />} />
          <Route path="/jobs/:jobId/artifacts" element={<ArtifactsPage />} />
          <Route path="/jobs/:jobId/chat" element={<ChatPage />} />
          <Route path="/jobs/:jobId/report" element={<ReportPage />} />

          {/* New analysis (V1 upload flow) */}
          <Route path="/new" element={<NewAnalysisPage />} />

          {/* Settings & Training (V1 pages, preserved) */}
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/training" element={<TrainingPage />} />
          <Route path="/rules" element={<RulesManagementPage />} />

          {/* Global Hosts (cross-job forensics) */}
          <Route path="/hosts" element={<GlobalHostsPage />} />
          <Route path="/hosts/:ip" element={<GlobalHostDetailPage />} />
        </Routes>
      </main>
    </div>
    </ToastProvider>
  );
};

