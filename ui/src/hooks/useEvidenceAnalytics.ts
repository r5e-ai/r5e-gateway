// Hooks for server-side histogram (`GET /v1/evidence/histogram`) and
// disjunctive facets (`GET /v1/evidence/facets`). Gracefully return `null` on
// 404/501 so the Dashboard falls back cleanly to loaded rows.

import { useQuery } from "@tanstack/react-query";

import type { EvidenceFilter } from "~/hooks/useEvidenceRecords";
import { apiPaths } from "~/lib/apiPaths";
import type {
  EvidenceFacetsResponse,
  EvidenceHistogramResponse,
} from "~/lib/evidenceTypes";

function buildAnalyticsParams(filter: EvidenceFilter): URLSearchParams {
  const params = new URLSearchParams();
  if (filter.kind) params.set("kind", filter.kind);
  if (filter.policyOutcome) params.set("policyOutcome", filter.policyOutcome);
  if (filter.target) params.set("target", filter.target);
  if (filter.reason) params.set("reason", filter.reason);
  if (filter.q) params.set("q", filter.q);
  if (filter.actor) params.set("actor", filter.actor);
  if (filter.session) params.set("session", filter.session);
  if (filter.since) params.set("since", filter.since);
  if (filter.until) params.set("until", filter.until);
  return params;
}

async function fetchOptionalJson<T>(url: string): Promise<T | null> {
  const resp = await fetch(url, { credentials: "include" });
  if (resp.status === 404 || resp.status === 501) return null;
  if (!resp.ok) {
    let detail = `HTTP ${resp.status}`;
    try {
      const body = (await resp.json()) as { message?: string; error?: string };
      if (typeof body.message === "string" && body.message) detail = body.message;
      else if (typeof body.error === "string" && body.error) detail = body.error;
    } catch {
      // ignore non-JSON error bodies
    }
    throw new Error(detail);
  }
  return (await resp.json()) as T;
}

export function useEvidenceHistogram(
  filter: EvidenceFilter,
  windowRange: { since?: string; until?: string },
  buckets = 48,
) {
  const effectiveSince = filter.since ?? windowRange.since;
  const effectiveUntil = filter.until ?? windowRange.until;
  const params = buildAnalyticsParams({
    ...filter,
    since: effectiveSince,
    until: effectiveUntil,
  });
  params.set("buckets", String(buckets));
  const qs = params.toString();
  const url = `${apiPaths.evidence.histogram}?${qs}`;

  return useQuery<EvidenceHistogramResponse | null, Error>({
    queryKey: ["evidence-histogram", qs] as const,
    queryFn: () => fetchOptionalJson<EvidenceHistogramResponse>(url),
    enabled: Boolean(effectiveSince && effectiveUntil),
    staleTime: 10_000,
    retry: false,
  });
}

export function useEvidenceFacets(filter: EvidenceFilter) {
  const qs = buildAnalyticsParams(filter).toString();
  const url = qs ? `${apiPaths.evidence.facets}?${qs}` : apiPaths.evidence.facets;
  return useQuery<EvidenceFacetsResponse | null, Error>({
    queryKey: ["evidence-facets", qs] as const,
    queryFn: () => fetchOptionalJson<EvidenceFacetsResponse>(url),
    staleTime: 10_000,
    retry: false,
  });
}
