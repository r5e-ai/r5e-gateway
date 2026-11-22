// BlastRadiusPanel — 4-cell impact matrix for historical Provenance v2 `ToolCall`
// dry-runs (camelCase Provenance v2 API contract).

import { useState } from "react";
import { Link } from "react-router-dom";

import { Pill } from "~/components/shared/Pill";
import type { BlastRadiusReport, BlastRadiusSample } from "~/lib/evidenceTypes";
import { truncateRef } from "~/lib/evidenceTypes";
import { policySimulatorRecordDetailPath } from "~/lib/routes";

interface Props {
  report: BlastRadiusReport | null;
  isLoading: boolean;
  error: string | null;
  onRunDryRun: () => void;
}

type CellKey = "matchesIntent" | "unintended" | "wouldHaveAllowed" | "noChange";

const CELLS: ReadonlyArray<{
  key: CellKey;
  label: string;
  description: string;
  tone: "success" | "danger" | "warning" | "muted";
}> = [
  {
    key: "matchesIntent",
    label: "Matches intent",
    description: "Previously allowed calls that this draft now denies.",
    tone: "success",
  },
  {
    key: "unintended",
    label: "Unintended impact",
    description: "Calls whose outcome flipped unexpectedly.",
    tone: "danger",
  },
  {
    key: "wouldHaveAllowed",
    label: "Would have allowed",
    description: "Previously denied calls that this draft would now allow.",
    tone: "warning",
  },
  {
    key: "noChange",
    label: "No change",
    description: "Historical calls keeping the same verdict.",
    tone: "muted",
  },
];

export function BlastRadiusPanel({
  report,
  isLoading,
  error,
  onRunDryRun,
}: Props): JSX.Element {
  const [activeCell, setActiveCell] = useState<CellKey>("matchesIntent");

  const samples: BlastRadiusSample[] = report ? report.samples[activeCell] : [];

  return (
    <section
      data-testid="blast-radius-panel"
      className="flex flex-col gap-3 rounded-lg border border-r5e-border bg-r5e-surface p-4"
    >
      <div className="flex items-center justify-between gap-2">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
            03 Impact / Blast Radius
          </h3>
          <p className="mt-0.5 text-xs text-r5e-muted">
            Evaluates draft Cedar against historical Provenance v2{" "}
            <code className="font-mono text-r5e-text">ToolCall</code> records.
          </p>
        </div>
        <button
          type="button"
          data-testid="run-blast-radius-btn"
          onClick={onRunDryRun}
          disabled={isLoading}
          className="rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs font-medium text-r5e-accent hover:bg-r5e-accent/25 disabled:opacity-50"
        >
          {isLoading ? "Evaluating…" : "Run blast radius"}
        </button>
      </div>

      {error && (
        <div
          role="alert"
          className="rounded border border-r5e-danger/40 bg-r5e-danger/10 px-3 py-2 text-xs text-r5e-danger"
        >
          {error}
        </div>
      )}

      {report ? (
        <>
          <div className="flex flex-wrap items-center gap-2 text-xs text-r5e-muted">
            <span>
              Evaluated <strong className="text-r5e-text">{report.totalEvaluated}</strong>{" "}
              historical ToolCalls
            </span>
            {report.incompleteCount > 0 && (
              <Pill tone="warning" testId="blast-radius-incomplete">
                {report.incompleteCount} incomplete (disposed or over-threshold args)
              </Pill>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2">
            {CELLS.map((cell) => {
              const count = report[cell.key];
              const isSelected = activeCell === cell.key;
              return (
                <button
                  key={cell.key}
                  type="button"
                  data-testid={`blast-cell-${cell.key}`}
                  onClick={() => setActiveCell(cell.key)}
                  className={[
                    "flex flex-col items-start rounded-md border p-3 text-left transition-colors",
                    isSelected
                      ? "border-r5e-accent bg-r5e-accent/10"
                      : "border-r5e-border bg-r5e-bg/60 hover:bg-r5e-bg",
                  ].join(" ")}
                >
                  <div className="flex w-full items-center justify-between">
                    <span className="text-xs font-medium text-r5e-text">{cell.label}</span>
                    <Pill tone={cell.tone}>{count}</Pill>
                  </div>
                  <span className="mt-1 text-[11px] text-r5e-muted">{cell.description}</span>
                </button>
              );
            })}
          </div>

          {samples.length > 0 && (
            <div className="mt-1 flex flex-col gap-1.5">
              <h4 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-muted">
                Sample records ({samples.length})
              </h4>
              <div className="divide-y divide-r5e-border rounded border border-r5e-border bg-r5e-bg">
                {samples.map((s) => (
                  <div
                    key={s.ref}
                    className="flex items-center justify-between gap-2 px-3 py-2 text-xs"
                  >
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="font-mono text-r5e-text">{s.tool}</span>
                      <span className="truncate text-r5e-muted">{s.actor}</span>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="font-mono text-[11px] text-r5e-muted">
                        {s.originalOutcome} → {s.draftOutcome}
                      </span>
                      <Link
                        to={policySimulatorRecordDetailPath(s.ref)}
                        className="font-mono text-[11px] text-r5e-accent hover:underline"
                      >
                        {truncateRef(s.ref, 8)}
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      ) : (
        <p className="text-xs text-r5e-muted">
          Click <strong>Run blast radius</strong> to evaluate this draft Cedar policy against
          recorded Provenance v2 tool calls.
        </p>
      )}
    </section>
  );
}
