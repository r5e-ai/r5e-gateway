// Single-record, session-records, and deployment hooks for Provenance v2.

import { useQuery } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type {
  DeploymentInfo,
  EvidenceRecordEntry,
  SessionEvidenceResponse,
} from "~/lib/evidenceTypes";

export function evidenceRecordQueryKey(ref: string): readonly unknown[] {
  return ["evidence-record", ref] as const;
}

export function useEvidenceRecord(ref: string | undefined) {
  return useQuery<EvidenceRecordEntry, Error>({
    queryKey: evidenceRecordQueryKey(ref ?? ""),
    queryFn: () => api.get<EvidenceRecordEntry>(apiPaths.evidence.recordDetail(ref ?? "")),
    enabled: !!ref,
    staleTime: 30_000,
  });
}

export function useSessionEvidence(sessionId: string | undefined) {
  return useQuery<SessionEvidenceResponse, Error>({
    queryKey: ["evidence-session", sessionId ?? ""] as const,
    queryFn: () =>
      api.get<SessionEvidenceResponse>(apiPaths.evidence.session(sessionId ?? "")),
    enabled: !!sessionId,
    staleTime: 10_000,
  });
}

export function useDeployment() {
  return useQuery<DeploymentInfo, Error>({
    queryKey: ["deployment"] as const,
    queryFn: () => api.get<DeploymentInfo>(apiPaths.deployment),
    staleTime: 60_000,
  });
}
