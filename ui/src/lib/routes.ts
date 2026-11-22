// Single source-of-truth for SPA route paths in the v2 Admin Console.

export const ADMIN_BASE = "/admin";

export const routes = {
  login: "/admin/login",
  dashboard: "/admin/dashboard",
  recordDetail: "/admin/dashboard/records/:ref",
  timeline: "/admin/timeline",
  timelineRecordDetail: "/admin/timeline/records/:ref",
  policySimulator: "/admin/policy-simulator",
  policySimulatorRecordDetail: "/admin/policy-simulator/records/:ref",
  mcpRegistry: "/admin/mcp-registry",
  mcpRegistryDetail: "/admin/mcp-registry/:id",
} as const;

export type RouteKey = keyof typeof routes;

export function stripBasename(path: string): string {
  if (path.startsWith(ADMIN_BASE)) {
    const rest = path.slice(ADMIN_BASE.length);
    return rest.length === 0 ? "/" : rest;
  }
  return path;
}

export function mcpRegistryDetailPath(id: string): string {
  return stripBasename(`/admin/mcp-registry/${encodeURIComponent(id)}`);
}

export interface TimelineScope {
  actor?: string;
  session?: string;
  ref?: string;
  since?: string;
  until?: string;
}

export function timelinePath(scope: TimelineScope = {}): string {
  const params = new URLSearchParams();
  if (scope.actor) params.set("actor", scope.actor);
  if (scope.session) params.set("session", scope.session);
  if (scope.ref) params.set("ref", scope.ref);
  if (scope.since) params.set("since", scope.since);
  if (scope.until) params.set("until", scope.until);
  const qs = params.toString();
  const base = stripBasename(routes.timeline);
  return qs ? `${base}?${qs}` : base;
}

export function recordDetailPath(ref: string): string {
  return stripBasename(`/admin/dashboard/records/${encodeURIComponent(ref)}`);
}

export function timelineRecordDetailPath(ref: string): string {
  return stripBasename(`/admin/timeline/records/${encodeURIComponent(ref)}`);
}

export function policySimulatorRecordDetailPath(ref: string): string {
  return stripBasename(`/admin/policy-simulator/records/${encodeURIComponent(ref)}`);
}
