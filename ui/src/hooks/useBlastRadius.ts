// useBlastRadius — runs `POST /v1/policies/drafts/:id/dry-run` against historical
// Provenance v2 `ToolCall` records using `CedarToolUseGate` semantics.

import { useMutation } from "@tanstack/react-query";

import { api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type { BlastRadiusReport } from "~/lib/evidenceTypes";

export type { BlastRadiusReport };

export function useBlastRadius() {
  return useMutation<
    BlastRadiusReport,
    Error,
    { draftId: string; cedarSource?: string }
  >({
    mutationFn: ({ draftId, cedarSource }) =>
      api.post<BlastRadiusReport>(apiPaths.policies.dryRun(draftId), {
        cedarSource,
      }),
  });
}
