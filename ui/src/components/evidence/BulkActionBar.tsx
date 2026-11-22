// BulkActionBar — sticky selection toolbar for the v2 Evidence Dashboard.
// Uses per-session `POST /v1/evidence/export` and `?mode=draft&ref=`.

import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { downloadEvidenceBundle } from "~/components/evidence/ExportBundleButton";
import { ApiError } from "~/lib/api";
import { routes, stripBasename } from "~/lib/routes";

interface Props {
  selectedRefs: string[];
  firstSelectedSession: string | null;
  role: "tenant_auditor" | "platform_operator";
  onClearSelection: () => void;
  onOpenDetail: (ref: string) => void;
}

type ExportStatus = "idle" | "in-flight" | "ok" | "error";

export function BulkActionBar({
  selectedRefs,
  firstSelectedSession,
  role,
  onClearSelection,
  onOpenDetail,
}: Props): JSX.Element | null {
  const navigate = useNavigate();
  const [exportStatus, setExportStatus] = useState<ExportStatus>("idle");
  const [exportError, setExportError] = useState<string | null>(null);

  if (selectedRefs.length === 0) return null;

  const canDraft = role === "platform_operator";
  const firstRef = selectedRefs[0];

  function handleOpen(): void {
    if (firstRef) onOpenDetail(firstRef);
  }

  function handleDraft(): void {
    const params = new URLSearchParams();
    params.set("mode", "draft");
    if (firstRef) params.set("ref", firstRef);
    navigate(`${stripBasename(routes.policySimulator)}?${params.toString()}`);
  }

  async function handleExport(): Promise<void> {
    if (!firstSelectedSession) {
      setExportStatus("error");
      setExportError("Selected record has no session to export.");
      return;
    }
    setExportStatus("in-flight");
    setExportError(null);
    try {
      await downloadEvidenceBundle({ session: firstSelectedSession, content: true });
      setExportStatus("ok");
    } catch (err) {
      setExportStatus("error");
      if (err instanceof ApiError) setExportError(err.error_description);
      else if (err instanceof Error) setExportError(err.message);
    }
  }

  return (
    <div
      role="toolbar"
      aria-label="Bulk actions"
      data-testid="bulk-action-bar"
      className="sticky bottom-0 z-20 flex flex-wrap items-center gap-3 border-t border-r5e-border bg-r5e-surface/95 px-4 py-3 shadow-lg backdrop-blur"
    >
      <span className="text-xs text-r5e-muted">{selectedRefs.length} selected</span>

      <button
        type="button"
        onClick={handleOpen}
        className="rounded border border-r5e-border bg-r5e-surface px-3 py-1.5 text-xs text-r5e-text hover:bg-r5e-bg"
      >
        Open in detail
      </button>

      {canDraft && (
        <button
          type="button"
          onClick={handleDraft}
          data-testid="bulk-draft-policy-btn"
          className="rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs text-r5e-accent hover:bg-r5e-accent/25"
        >
          Draft policy from selection
        </button>
      )}

      <button
        type="button"
        onClick={handleExport}
        disabled={exportStatus === "in-flight" || !firstSelectedSession}
        data-testid="bulk-export-btn"
        className="rounded border border-r5e-border bg-r5e-surface px-3 py-1.5 text-xs text-r5e-text hover:bg-r5e-bg disabled:cursor-not-allowed disabled:opacity-60"
      >
        {exportStatus === "in-flight" ? "Exporting…" : "Export session v2 bundle"}
      </button>

      {exportStatus === "ok" && (
        <span className="text-xs text-r5e-success">Exported v2 JSON bundle</span>
      )}
      {exportError && (
        <span className="text-xs text-r5e-danger" role="alert">
          {exportError}
        </span>
      )}

      <button
        type="button"
        onClick={onClearSelection}
        className="ml-auto text-xs text-r5e-muted hover:text-r5e-text"
      >
        Clear
      </button>
    </div>
  );
}
