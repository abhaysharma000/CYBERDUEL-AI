import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { Layout } from "./components/layout/Layout";

import { OverviewPage } from "./pages/OverviewPage";
import { RedAiPage } from "./pages/RedAiPage";
import { BlueAiPage } from "./pages/BlueAiPage";
import { EvaluationsPage } from "./pages/EvaluationsPage";
import { ReleasesPage } from "./pages/ReleasesPage";
import { ClientsPage } from "./pages/ClientsPage";
import { IntelligencePage } from "./pages/IntelligencePage";
import { AuditPage } from "./pages/AuditPage";
import { SystemHealthPage } from "./pages/SystemHealthPage";
import { LoginPage } from "./pages/LoginPage";

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="lab" element={<RedAiPage />} />
            <Route path="blue" element={<BlueAiPage />} />
            <Route path="evaluations" element={<EvaluationsPage />} />
            <Route path="releases" element={<ReleasesPage />} />
            <Route path="clients" element={<ClientsPage />} />
            <Route path="intelligence" element={<IntelligencePage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="system" element={<SystemHealthPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};

export default App;

