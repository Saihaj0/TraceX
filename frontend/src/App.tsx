import React from 'react';
import { HashRouter, Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from './components/Layout';
import { ToastStack } from './components/ui';
import { AppProvider, useApp } from './state';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { InvestigationsPage } from './pages/Investigations';
import { TimelinePage } from './pages/Timeline';
import { EvidenceExplorer } from './pages/EvidenceExplorer';
import { AntiForensics } from './pages/AntiForensics';
import { SuspicionChains } from './pages/SuspicionChains';
import { ForensicGraph } from './pages/ForensicGraph';
import { ReportsPage } from './pages/Reports';
import { AdminPage } from './pages/Admin';
import { SettingsPage } from './pages/Settings';

const Shell: React.FC = () => {
  const { toasts, dismissToast } = useApp();
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/investigations" element={<InvestigationsPage />} />
        <Route path="/timeline" element={<TimelinePage />} />
        <Route path="/evidence" element={<EvidenceExplorer />} />
        <Route path="/anti-forensics" element={<AntiForensics />} />
        <Route path="/chains" element={<SuspicionChains />} />
        <Route path="/graph" element={<ForensicGraph />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/admin" element={<AdminRoute />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <ToastStack toasts={toasts} onDismiss={dismissToast} />
    </Layout>
  );
};

// Admin gate: the backend enforces administrator rights on every /admin
// call; this just keeps non-admins from landing on the page at all.
const AdminRoute: React.FC = () => {
  const { user } = useApp();
  if (!user?.is_admin) return <Navigate to="/" replace />;
  return <AdminPage />;
};

// Route guard: while the auth status probe is in flight show nothing (the
// boot check is fast); when a session is required and absent, show Login
// instead of the app shell.
const Gate: React.FC = () => {
  const { authReady, authRequired, user } = useApp();
  if (!authReady) {
    return (
      <div className="auth-screen">
        <div className="faint">Checking session…</div>
      </div>
    );
  }
  if (authRequired && !user) return <Login />;
  return <Shell />;
};

export const App: React.FC = () => (
  <AppProvider>
    <HashRouter>
      <Gate />
    </HashRouter>
  </AppProvider>
);