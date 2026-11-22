// ColumnPicker — toolbar popover for toggling visibility, reordering columns
// left/right, and resetting defaults on the Evidence Table.

import { ArrowLeft, ArrowRight, Columns3, RotateCcw } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import {
  COLUMN_DEF_BY_ID,
  type EvidenceColumnId,
  type EvidenceColumnPrefs,
} from "~/lib/evidenceColumns";

interface Props {
  prefs: EvidenceColumnPrefs;
  onToggle: (id: EvidenceColumnId) => void;
  onMove: (id: EvidenceColumnId, direction: "left" | "right") => void;
  onReset: () => void;
}

export function ColumnPicker({
  prefs,
  onToggle,
  onMove,
  onReset,
}: Props): JSX.Element {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const visibleCount = prefs.order.filter((id) => prefs.visible[id]).length;

  useEffect(() => {
    if (!open) return;
    function handleOutside(e: MouseEvent): void {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    function handleKey(e: KeyboardEvent): void {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", handleOutside);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleOutside);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        data-testid="column-picker-button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1.5 text-xs font-medium text-r5e-text/90 hover:bg-r5e-bg hover:text-r5e-text"
      >
        <Columns3 className="h-3.5 w-3.5 text-r5e-text/80" aria-hidden="true" />
        <span>Columns</span>
        <span className="rounded bg-r5e-bg px-1.5 py-0.5 font-mono text-[10px] text-r5e-text/80">
          {visibleCount}/{prefs.order.length}
        </span>
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Configure table columns"
          data-testid="column-picker-popover"
          className="absolute right-0 z-30 mt-1.5 w-72 rounded-md border border-r5e-border bg-r5e-surface p-3 shadow-xl"
        >
          <div className="mb-2 flex items-center justify-between border-b border-r5e-border pb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-r5e-text/85">
              Table Columns
            </span>
            <button
              type="button"
              data-testid="column-picker-reset"
              onClick={onReset}
              className="inline-flex items-center gap-1 text-[11px] text-r5e-accent hover:underline"
            >
              <RotateCcw className="h-3 w-3" aria-hidden="true" />
              Reset defaults
            </button>
          </div>

          <ul className="flex flex-col gap-1">
            {prefs.order.map((id, idx) => {
              const def = COLUMN_DEF_BY_ID[id];
              const isVisible = prefs.visible[id];
              const isOnlyVisible = isVisible && visibleCount <= 1;
              return (
                <li
                  key={id}
                  data-testid={`column-picker-row-${id}`}
                  className="flex items-center justify-between gap-2 rounded px-2 py-1.5 text-xs hover:bg-r5e-bg/70"
                >
                  <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-r5e-text/90">
                    <input
                      type="checkbox"
                      data-testid={`column-toggle-${id}`}
                      checked={isVisible}
                      disabled={isOnlyVisible}
                      onChange={() => onToggle(id)}
                    />
                    <span className="truncate">{def.label}</span>
                  </label>
                  <div className="flex shrink-0 items-center gap-0.5">
                    <button
                      type="button"
                      data-testid={`column-move-left-${id}`}
                      aria-label={`Move ${def.label} left`}
                      disabled={idx === 0}
                      onClick={() => onMove(id, "left")}
                      className="rounded p-1 text-r5e-text/80 hover:bg-r5e-bg hover:text-r5e-text disabled:opacity-30"
                    >
                      <ArrowLeft className="h-3 w-3" />
                    </button>
                    <button
                      type="button"
                      data-testid={`column-move-right-${id}`}
                      aria-label={`Move ${def.label} right`}
                      disabled={idx === prefs.order.length - 1}
                      onClick={() => onMove(id, "right")}
                      className="rounded p-1 text-r5e-text/80 hover:bg-r5e-bg hover:text-r5e-text disabled:opacity-30"
                    >
                      <ArrowRight className="h-3 w-3" />
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
          <p className="mt-2 border-t border-r5e-border pt-2 text-[11px] text-r5e-text/70">
            Drag column headers to reorder or drag header edges to resize.
          </p>
        </div>
      )}
    </div>
  );
}
