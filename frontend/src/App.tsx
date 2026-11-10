import type { ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ShieldOff } from 'lucide-react';
import { AuthProvider, useAuth } from './auth/AuthContext';
import { EventStreamProvider } from './hooks/useEventStream';
import { Layout } from './components/Layout';
import { Spinner } from './components/ui';
import { LoginPage } from './pages/Login';
import { DashboardPage } from './pages/Dashboard';
import { RiskMatrixPage } from './pages/RiskMatrixPage';
import { AcceptancesPage } from './pages/AcceptancesPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { RemediationPage } from './pages/RemediationPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { ParametersPage } from './pages/ParametersPage';
import { AuditPage } from './pages/AuditPage';
import { CompliancePage } from './pages/CompliancePage';
import { AdminPage } from './pages/AdminPage';
import { ConfigurationPage } from './pages/ConfigurationPage';

function Guard({ permission, children }: { permission: string; children: ReactNode }) {
  const { can } = useAuth();
  if (!can(permission)) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24 text-center text-slate-400">
        <ShieldOff className="h-10 w-10 text-slate-500" />
        <div className="text-lg font-medium text-slate-200">Access restricted</div>
        <p className="max-w-md text-sm">Your role does not grant access to this area. Requests are logged.</p>
      </div>
    );
  }
  return <>{children}</>;
}

function Protected() {
  const { me, loading } = useAuth();
  if (loading) return <Spinner label="Verifying session…" />;
  if (!me) return <Navigate to="/login" replace />;
  return (
    <EventStreamProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Guard permission="dashboard:read"><DashboardPage /></Guard>} />
          <Route path="risk" element={<Guard permission="risk:read"><RiskMatrixPage /></Guard>} />
          <Route path="acceptances" element={<Guard permission="risk:read"><AcceptancesPage /></Guard>} />
          <Route path="threats" element={<Guard permission="threat:read"><ThreatsPage /></Guard>} />
          <Route path="incidents" element={<Guard permission="incident:read"><IncidentsPage /></Guard>} />
          <Route path="remediation" element={<Guard permission="vuln:read"><RemediationPage /></Guard>} />
          <Route path="integrations" element={<Guard permission="integration:read"><IntegrationsPage /></Guard>} />
          <Route path="parameters" element={<Guard permission="kri:read"><ParametersPage /></Guard>} />
          <Route path="audit" element={<Guard permission="audit:read"><AuditPage /></Guard>} />
          <Route path="compliance" element={<Guard permission="compliance:read"><CompliancePage /></Guard>} />
          <Route path="admin" element={<Guard permission="users:read"><AdminPage /></Guard>} />
          <Route path="configuration" element={<Guard permission="config:read"><ConfigurationPage /></Guard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </EventStreamProvider>
  );
}

function LoginRoute() {
  const { me, loading } = useAuth();
  if (loading) return <Spinner />;
  return me ? <Navigate to="/" replace /> : <LoginPage />;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginRoute />} />
          <Route path="/*" element={<Protected />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
