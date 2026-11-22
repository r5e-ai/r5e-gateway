// useEvidenceRecords — TanStack-Query infinite hook for `GET /v1/evidence/records`.
// Provenance v2 list contract: keyset cursor over `(capturedAt, ref)`, limit default 50 max 200,
// server-side filters: full `kind` path, `session`, `actor`, `since`, `until`.

import { useInfiniteQuery, type InfiniteData } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type { EvidenceListResponse } from "~/lib/evidenceTypes";

export interface EvidenceFilter {
  /** Open-string full kind path (e.g. "provenance.r5e.io/v2/ToolCall"). */
  kind?: string;
  actor?: string;
  session?: string;
  since?: string;
  until?: string;
}

const DEFAULT_PAGE_SIZE = 50;

export function evidenceQueryKey(filter: EvidenceFilter): readonly unknown[] {
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(filter).sort()) {
    const value = filter[key as keyof EvidenceFilter];
    if (value !== undefined && value !== "") sorted[key] = String(value);
  }
  return ["evidence-records", sorted] as const;
}

const ALLOWED_FILTER_KEYS = ["kind", "actor", "session", "since", "until"] as const;

function buildPath(filter: EvidenceFilter, cursor: string | undefined): string {
  const params = new URLSearchParams();
  for (const key of ALLOWED_FILTER_KEYS) {
    const value = filter[key];
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  if (cursor !== undefined) params.set("cursor", cursor);
  params.set("limit", String(DEFAULT_PAGE_SIZE));
  const qs = params.toString();
  return qs ? `${apiPaths.evidence.records}?${qs}` : apiPaths.evidence.records;
}

export interface UseEvidenceRecordsOptions {
  enabled?: boolean;
}

export function useEvidenceRecords(
  filter: EvidenceFilter,
  options: UseEvidenceRecordsOptions = {},
) {
  return useInfiniteQuery<
    EvidenceListResponse,
    Error,
    InfiniteData<EvidenceListResponse, string | undefined>,
    readonly unknown[],
    string | undefined
  >({
    queryKey: evidenceQueryKey(filter),
    queryFn: ({ pageParam }) =>
      api.get<EvidenceListResponse>(buildPath(filter, pageParam)),
    initialPageParam: undefined,
    getNextPageParam: (lastPage) => lastPage.cursor ?? undefined,
    enabled: options.enabled ?? true,
    staleTime: 5_000,
  });
}
