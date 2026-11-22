// ExportBundleButton — exports a Provenance v2 session bundle via
// `POST /v1/evidence/export` (`{"session": "<id>", "content": boolean}`).

import { useMutation } from "@tanstack/react-query";
import { Download } from "lucide-react";

import { ApiError, useApiErrorHandler } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import type { ProvenanceExportV2 } from "~/lib/evidenceTypes";

export interface ExportBundleRequest {
  session: string;
  content?: boolean;
}

export async function fetchEvidenceBundle(
  request: ExportBundleRequest,
): Promise<ProvenanceExportV2> {
  const response = await fetch(apiPaths.evidence.export, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      session: request.session,
      content: request.content ?? true,
    }),
  });

  if (!response.ok) {
    let envelope: Record<string, unknown> = {};
    try {
      envelope = (await response.json()) as Record<string, unknown>;
    } catch {
      // Non-JSON error body
    }
    throw new ApiError({
      error: typeof envelope.error === "string" ? envelope.error : "export_failed",
      error_description:
        typeof envelope.error_description === "string"
          ? envelope.error_description
          : typeof envelope.message === "string"
            ? envelope.message
            : `HTTP ${response.status}`,
      correlation_id:
        typeof envelope.correlation_id === "string"
          ? envelope.correlation_id
          : "unknown",
      attested_run_id: null,
      status: response.status,
    });
  }

  return (await response.json()) as ProvenanceExportV2;
}

export async function downloadEvidenceBundle(
  request: ExportBundleRequest,
): Promise<ProvenanceExportV2> {
  const bundle = await fetchEvidenceBundle(request);
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `evidence-${stamp}.v2.json`;
  const blob = new Blob([JSON.stringify(bundle, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1_000);
  }
  return bundle;
}

interface Props {
  session?: string | null;
  label?: string;
}

export function ExportBundleButton({
  session,
  label = "Export session v2 bundle",
}: Props): JSX.Element {
  const handleApiError = useApiErrorHandler();
  const mutation = useMutation<ProvenanceExportV2, Error, void>({
    mutationFn: () => {
      if (!session) throw new Error("This record is not attached to a session.");
      return downloadEvidenceBundle({ session, content: true });
    },
    onError: handleApiError,
  });

  return (
    <button
      type="button"
      data-testid="export-bundle-btn"
      onClick={() => mutation.mutate()}
      disabled={mutation.isPending || !session}
      title={session ? `Export session ${session}` : "No session attached to this record"}
      className="inline-flex items-center gap-1.5 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1.5 text-xs text-r5e-text hover:bg-r5e-bg disabled:opacity-50"
    >
      <Download className="h-3.5 w-3.5" aria-hidden="true" />
      <span>{mutation.isPending ? "Exporting…" : label}</span>
    </button>
  );
}
