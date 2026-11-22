// Single source of truth for backend API path strings used by the v2 Admin Console SPA.
// Targets the Provenance v2 gateway API (`/v1/evidence/*`, `/v1/policies/*`, `/v1/deployment`).

export const apiPaths = {
  auth: {
    me: "/v1/auth/me",
    loginStart: "/admin/login/start",
    logout: "/admin/logout",
  },
  deployment: "/v1/deployment",
  evidence: {
    records: "/v1/evidence/records",
    recordDetail: (ref: string) =>
      `/v1/evidence/records/${encodeURIComponent(ref)}`,
    recordContent: (recordRef: string, bytesRef: string) =>
      `/v1/evidence/records/${encodeURIComponent(recordRef)}/content/${encodeURIComponent(bytesRef)}`,
    session: (sessionId: string) =>
      `/v1/evidence/sessions/${encodeURIComponent(sessionId)}`,
    export: "/v1/evidence/export",
    verify: "/v1/evidence/verify",
  },
  policies: {
    active: "/v1/policies/active",
    simulate: "/v1/policies/simulate",
    replay: "/v1/policies/replay",
    drafts: "/v1/policies/drafts",
    draftDetail: (id: string) =>
      `/v1/policies/drafts/${encodeURIComponent(id)}`,
    fromRecord: "/v1/policies/drafts/from-record",
    dryRun: (id: string) =>
      `/v1/policies/drafts/${encodeURIComponent(id)}/dry-run`,
  },
  mcp: {
    registry: "/v1/mcp/registry",
    detail: (id: string) => `/v1/mcp/registry/${encodeURIComponent(id)}`,
  },
  liveTail: (filters?: { kind?: string; session?: string; actor?: string }) => {
    const params = new URLSearchParams();
    if (filters?.kind) params.set("kind", filters.kind);
    if (filters?.session) params.set("session", filters.session);
    if (filters?.actor) params.set("actor", filters.actor);
    const qs = params.toString();
    return qs ? `/v1/evidence/tail?${qs}` : "/v1/evidence/tail";
  },
} as const;
