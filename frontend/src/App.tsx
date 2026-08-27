import React, { lazy, Suspense, useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ModelSetupModal } from "./components/ModelSetupModal";
import { ToastProvider } from "./components/ToastProvider";
import { CommandPalette } from "./components/CommandPalette";
import { KeyboardShortcuts } from "./components/KeyboardShortcuts";
import { RouteErrorBoundary } from "./components/RouteErrorBoundary";
import { ThemeProvider, useTheme } from "./components/ThemeProvider";
import { DemoWalkthrough } from "./components/DemoWalkthrough";
import { api, isDemoMode } from "./api";

// Pages are route-level code-split: each becomes its own chunk loaded on
// demand, so the initial bundle no longer carries every screen (and their
// heavy deps -- d3 for the graph, react-markdown for chat/report) up front.
const JobListPage = lazy(() => import("./pages/JobListPage").then((m) => ({ default: m.JobListPage })));
const NewAnalysisPage = lazy(() => import("./pages/NewAnalysisPage").then((m) => ({ default: m.NewAnalysisPage })));
const JobDetailPage = lazy(() => import("./pages/JobDetailPage").then((m) => ({ default: m.JobDetailPage })));
const HostListPage = lazy(() => import("./pages/HostListPage").then((m) => ({ default: m.HostListPage })));
const HostDetailPage = lazy(() => import("./pages/HostDetailPage").then((m) => ({ default: m.HostDetailPage })));
const HostSubTab = lazy(() => import("./pages/HostDetailPage").then((m) => ({ default: m.HostSubTab })));
const AlertsListPage = lazy(() => import("./pages/AlertsListPage").then((m) => ({ default: m.AlertsListPage })));
const AlertDetailPage = lazy(() => import("./pages/AlertDetailPage").then((m) => ({ default: m.AlertDetailPage })));
const FindingsListPage = lazy(() => import("./pages/FindingsListPage").then((m) => ({ default: m.FindingsListPage })));
const FindingDetailPage = lazy(() => import("./pages/FindingDetailPage").then((m) => ({ default: m.FindingDetailPage })));
const TimelinePage = lazy(() => import("./pages/TimelinePage").then((m) => ({ default: m.TimelinePage })));
const IocsListPage = lazy(() => import("./pages/IocsListPage").then((m) => ({ default: m.IocsListPage })));
const FilesListPage = lazy(() => import("./pages/FilesListPage").then((m) => ({ default: m.FilesListPage })));
const AttackGraphPage = lazy(() => import("./pages/AttackGraphPage").then((m) => ({ default: m.AttackGraphPage })));
const ArtifactsPage = lazy(() => import("./pages/ArtifactsPage").then((m) => ({ default: m.ArtifactsPage })));
const ReportPage = lazy(() => import("./pages/ReportPage").then((m) => ({ default: m.ReportPage })));
const ChatPage = lazy(() => import("./pages/ChatPage").then((m) => ({ default: m.ChatPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));
const TrainingPage = lazy(() => import("./pages/TrainingPage").then((m) => ({ default: m.TrainingPage })));
const RulesManagementPage = lazy(() => import("./pages/RulesManagementPage").then((m) => ({ default: m.RulesManagementPage })));
const AdminFeedbackPage = lazy(() => import("./pages/AdminFeedbackPage").then((m) => ({ default: m.AdminFeedbackPage })));
const TheoriesPage = lazy(() => import("./pages/TheoriesPage").then((m) => ({ default: m.TheoriesPage })));
const StorylinePage = lazy(() => import("./pages/StorylinePage").then((m) => ({ default: m.StorylinePage })));
const StreamsPage = lazy(() => import("./pages/StreamsPage").then((m) => ({ default: m.StreamsPage })));
const EventsExplorerPage = lazy(() => import("./pages/EventsExplorerPage").then((m) => ({ default: m.EventsExplorerPage })));
const BinaryAnalysisPage = lazy(() => import("./pages/BinaryAnalysisPage").then((m) => ({ default: m.BinaryAnalysisPage })));
const SigmaPage = lazy(() => import("./pages/SigmaPage").then((m) => ({ default: m.SigmaPage })));
const SlicesPage = lazy(() => import("./pages/SlicesPage").then((m) => ({ default: m.SlicesPage })));
const AnnotationsPage = lazy(() => import("./pages/AnnotationsPage").then((m) => ({ default: m.AnnotationsPage })));
const InvestigationQueuePage = lazy(() => import("./pages/InvestigationQueuePage").then((m) => ({ default: m.InvestigationQueuePage })));
const ComparePage = lazy(() => import("./pages/ComparePage").then((m) => ({ default: m.ComparePage })));
const ProofBuilderPage = lazy(() => import("./pages/ProofBuilderPage").then((m) => ({ default: m.ProofBuilderPage })));
const TelemetryEventDetailPage = lazy(() => import("./pages/TelemetryEventDetailPage").then((m) => ({ default: m.TelemetryEventDetailPage })));
const TemporalCorrelationsPage = lazy(() => import("./pages/TemporalCorrelationsPage").then((m) => ({ default: m.TemporalCorrelationsPage })));
const GlobalHostsPage = lazy(() => import("./pages/GlobalHostsPage").then((m) => ({ default: m.GlobalHostsPage })));
const GlobalHostDetailPage = lazy(() => import("./pages/GlobalHostDetailPage").then((m) => ({ default: m.GlobalHostDetailPage })));

/** Shown while a route's code chunk is fetched. Kept minimal so the swap to
 *  the real page is not visually jarring on a fast connection. */
const RouteFallback: React.FC = () => (
  <div className="flex items-center gap-2 text-sm text-slate-500" data-testid="route-loading">
    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-700 border-t-slate-400" />
    Loading…
  </div>
);

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

/**
 * Single source of truth for the global navigation.
 * Rendered twice (desktop bar + mobile dropdown) so the two can never drift.
 */
const NAV_ITEMS = [
  { to: "/jobs", label: "Jobs", testId: "nav-jobs" },
  { to: "/new", label: "New Analysis", testId: "nav-new-analysis" },
  { to: "/settings", label: "Settings", testId: "nav-settings" },
  { to: "/training", label: "Training", testId: "nav-training" },
  { to: "/rules", label: "Detection Rules", testId: "nav-rules" },
  { to: "/hosts", label: "Global Hosts", testId: "nav-global-hosts" },
] as const;

/** Active-aware nav link. `variant` controls the active treatment only. */
const MainNavLink: React.FC<{
  to: string;
  label: string;
  testId: string;
  variant: "desktop" | "mobile";
  onClick?: () => void;
}> = ({ to, label, testId, variant, onClick }) => (
  <NavLink
    to={to}
    data-testid={testId}
    onClick={onClick}
    className={({ isActive }) =>
      variant === "desktop"
        ? `pb-0.5 border-b-2 transition-colors ${
            isActive
              ? "border-emerald-400 text-emerald-400 font-medium"
              : "border-transparent hover:text-slate-100"
          }`
        : `px-2 py-1 rounded transition-colors ${
            isActive ? "bg-slate-800 text-emerald-400 font-medium" : "hover:text-slate-100"
          }`
    }
  >
    {label}
  </NavLink>
);

export const App: React.FC = () => {
  const location = useLocation();
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
            {NAV_ITEMS.map((item) => (
              <MainNavLink key={item.to} {...item} variant="desktop" />
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-2">
          {/* Global search / command palette (Ctrl/Cmd+K) */}
          <button
            onClick={() => window.dispatchEvent(new Event("aipam:open-command-palette"))}
            data-testid="open-command-palette"
            aria-label="Search (Control or Command K)"
            title="Search — Ctrl/⌘ K"
            className="flex items-center gap-2 rounded-md border border-slate-700 bg-slate-900 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-100 hover:border-slate-600 transition-colors"
          >
            <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <span className="hidden sm:inline">Search</span>
            <kbd className="hidden sm:inline rounded border border-slate-700 px-1 text-[10px] text-slate-500">⌘K</kbd>
          </button>
          {/* Theme toggle */}
          <ThemeToggleButton />
          {/* Hamburger button (mobile only) */}
          <button
            className="md:hidden text-slate-300 hover:text-slate-50 p-1"
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
          {NAV_ITEMS.map((item) => (
            <MainNavLink
              key={item.to}
              to={item.to}
              label={item.label}
              /* suffixed so desktop + mobile testids stay unique in the DOM */
              testId={`${item.testId}-mobile`}
              variant="mobile"
              onClick={() => setMobileNavOpen(false)}
            />
          ))}
        </nav>
      )}
      <main className="p-3 sm:p-6" data-testid="main-content">
        {isDemoMode() && <DemoWalkthrough />}

        {/* Boundary is keyed on the path so navigating away from a broken route
            clears the error; Suspense sits inside so a lazy-chunk rejection is
            caught here rather than unmounting the whole app. */}
        <RouteErrorBoundary resetKey={location.pathname}>
        <Suspense fallback={<RouteFallback />}>
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
          <Route path="/jobs/:jobId/streams" element={<StreamsPage />} />
          <Route path="/jobs/:jobId/raw-events" element={<EventsExplorerPage />} />
          <Route path="/jobs/:jobId/binary" element={<BinaryAnalysisPage />} />
          <Route path="/jobs/:jobId/sigma" element={<SigmaPage />} />
          <Route path="/jobs/:jobId/storyline" element={<StorylinePage />} />
          <Route path="/jobs/:jobId/graph" element={<AttackGraphPage />} />
          <Route path="/jobs/:jobId/artifacts" element={<ArtifactsPage />} />
          <Route path="/jobs/:jobId/chat" element={<ChatPage />} />
          <Route path="/jobs/:jobId/report" element={<ReportPage />} />
          <Route path="/jobs/:jobId/compare" element={<ComparePage />} />
          <Route path="/jobs/:jobId/proof" element={<ProofBuilderPage />} />
          <Route path="/jobs/:jobId/proof/:proofId" element={<ProofBuilderPage />} />
          <Route path="/jobs/:jobId/telemetry/:eventId" element={<TelemetryEventDetailPage />} />
          <Route path="/jobs/:jobId/correlations" element={<TemporalCorrelationsPage />} />

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
        </Suspense>
        </RouteErrorBoundary>
      </main>
      <CommandPalette />
      <KeyboardShortcuts />
    </div>
    </ToastProvider>
    </ThemeProvider>
  );
};

