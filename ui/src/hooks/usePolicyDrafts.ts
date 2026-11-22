// Policy hooks for Provenance v2 / CedarToolUseGate (`/v1/policies/*`, camelCase contract).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type {
  ActivePolicyBundle,
  PolicyDraft,
  PolicyDraftConditionKind,
  PolicyDraftConditionMetadata,
  PolicyDraftScopeMetadata,
} from "~/lib/evidenceTypes";

export type {
  ActivePolicyBundle,
  PolicyDraft,
  PolicyDraftConditionKind,
  PolicyDraftConditionMetadata,
  PolicyDraftScopeMetadata,
};

export interface PolicyDraftsListResponse {
  drafts: PolicyDraft[];
}

export function useActivePolicy() {
  return useQuery<ActivePolicyBundle, Error>({
    queryKey: ["policies-active"] as const,
    queryFn: () => api.get<ActivePolicyBundle>(apiPaths.policies.active),
    staleTime: 15_000,
  });
}

export function usePolicyDrafts() {
  return useQuery<PolicyDraftsListResponse, Error>({
    queryKey: ["policies-drafts"] as const,
    queryFn: () => api.get<PolicyDraftsListResponse>(apiPaths.policies.drafts),
    staleTime: 10_000,
  });
}

export function usePolicyDraft(id: string | null | undefined) {
  return useQuery<PolicyDraft, Error>({
    queryKey: ["policies-draft", id ?? ""] as const,
    queryFn: () => api.get<PolicyDraft>(apiPaths.policies.draftDetail(id ?? "")),
    enabled: !!id,
    staleTime: 10_000,
  });
}

export function useCreatePolicyDraft() {
  const qc = useQueryClient();
  return useMutation<
    PolicyDraft,
    Error,
    {
      name: string;
      cedarSource: string;
      sourceRecordRef?: string | null;
      scopeMetadata?: PolicyDraftScopeMetadata | null;
      conditionMetadata?: PolicyDraftConditionMetadata[];
    }
  >({
    mutationFn: (payload) => api.post<PolicyDraft>(apiPaths.policies.drafts, payload),
    onSuccess: (draft) => {
      qc.setQueryData(["policies-draft", draft.id], draft);
      void qc.invalidateQueries({ queryKey: ["policies-drafts"] });
    },
  });
}

export function useUpdatePolicyDraft() {
  const qc = useQueryClient();
  return useMutation<
    PolicyDraft,
    Error,
    {
      id: string;
      name?: string;
      cedarSource?: string;
      scopeMetadata?: PolicyDraftScopeMetadata | null;
      conditionMetadata?: PolicyDraftConditionMetadata[];
    }
  >({
    mutationFn: ({ id, ...body }) =>
      api.patch<PolicyDraft>(apiPaths.policies.draftDetail(id), body),
    onSuccess: (draft) => {
      qc.setQueryData(["policies-draft", draft.id], draft);
      void qc.invalidateQueries({ queryKey: ["policies-drafts"] });
    },
  });
}

export function useDeletePolicyDraft() {
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id) => api.delete<void>(apiPaths.policies.draftDetail(id)),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["policies-drafts"] });
    },
  });
}

export function useDraftFromRecord() {
  const qc = useQueryClient();
  return useMutation<PolicyDraft, Error, { ref: string; decision?: "permit" | "forbid" }>({
    mutationFn: (payload) => api.post<PolicyDraft>(apiPaths.policies.fromRecord, payload),
    onSuccess: (draft) => {
      qc.setQueryData(["policies-draft", draft.id], draft);
      void qc.invalidateQueries({ queryKey: ["policies-drafts"] });
    },
  });
}
