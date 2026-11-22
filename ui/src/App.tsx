// App.tsx — SPA root for the Provenance v2 Admin Console.

import type { ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";

import { RequireAuth } from "~/components/shared/RequireAuth";
import { Sidebar } from "~/components/shared/Sidebar";
import { createAuditConsoleQueryClient } from "~/lib/api";
import { ADMIN_BASE, routes, stripBasename } from "~/lib/routes";
import Dashboard from "~/pages/Dashboard";
import Login from "~/pages/Login";
import McpRegistry from "~/pages/McpRegistry";
import McpRegistryDetail from "~/pages/McpRegistryDetail";
import PolicySimulator from "~/pages/PolicySimulator";
import RecordDetail from "~/pages/RecordDetail";
import TimelinePage from "~/pages/TimelinePage";

const queryClient = createAuditConsoleQueryClient();

function AuthenticatedShell({ children }: { children: ReactNode }): JSX.Element {
  return (
    <RequireAuth>
      <div
        data-testid="authenticated-shell"
        className="flex h-screen w-screen overflow-hidden bg-r5e-bg font-sans text-r5e-text"
      >
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          {children}
        </div>
      </div>
    </RequireAuth>
  );
}

function AppRoutes(): JSX.Element {
  return (
    <Routes>
      <Route path={stripBasename(routes.login)} element={<Login />} />
      <Route
        path="/"
        element={<Navigate to={stripBasename(routes.dashboard)} replace />}
      />

      <Route
        path={stripBasename(routes.dashboard)}
        element={
          <AuthenticatedShell>
            <Dashboard />
          </AuthenticatedShell>
        }
      >
        <Route path="records/:ref" element={<RecordDetail />} />
      </Route>

      <Route
        path={stripBasename(routes.timeline)}
        element={
          <AuthenticatedShell>
            <TimelinePage />
          </AuthenticatedShell>
        }
      >
        <Route path="records/:ref" element={<RecordDetail />} />
      </Route>

      <Route
        path={stripBasename(routes.policySimulator)}
        element={
          <AuthenticatedShell>
            <PolicySimulator />
          </AuthenticatedShell>
        }
      >
        <Route path="records/:ref" element={<RecordDetail />} />
      </Route>

      <Route
        path={stripBasename(routes.mcpRegistry)}
        element={
          <AuthenticatedShell>
            <McpRegistry />
          </AuthenticatedShell>
        }
      />
      <Route
        path={stripBasename(routes.mcpRegistryDetail)}
        element={
          <AuthenticatedShell>
            <McpRegistryDetail />
          </AuthenticatedShell>
        }
      />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename={ADMIN_BASE}>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}
