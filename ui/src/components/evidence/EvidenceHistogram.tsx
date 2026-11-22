// EvidenceHistogram — Datadog/Kibana-style compact stacked time-bucket
// histogram (`Allow`, `Deny`, `Other`) with click-and-drag time-brush
// selection that sets `since` and `until` on `GET /v1/evidence/records`,
// time-range presets (`15m`, `1h`, `24h`, `7d`, `All`), and graceful fallback
// to loaded rows with a `"showing loaded window"` badge when the server
// histogram endpoint is unavailable.

import { useMemo, useRef, useState } from "react";

import {
  formatTimestamp,
  formatUtcTimestamp,
  type EvidenceHistogramResponse,
  type PolicyOutcome,
  type TimeDisplayMode,
} from "~/lib/evidenceTypes";

export interface LoadedHistogramRow {
  capturedAt: string;
  outcome: PolicyOutcome | null;
}

export interface NormalizedBucket {
  start: string;
  end: string;
  allow: number;
  deny: number;
  other: number;
  total: number;
}

interface Props {
  serverHistogram: EvidenceHistogramResponse | null | undefined;
  analyticsError?: string | null;
  loadedRows: readonly LoadedHistogramRow[];
  since?: string;
  until?: string;
  timeMode?: TimeDisplayMode;
  onSelectRange: (since: string | null, until: string | null) => void;
}

type PresetKey = "15m" | "1h" | "24h" | "7d" | "all";

const PRESETS: ReadonlyArray<{ key: PresetKey; label: string; ms: number | null }> = [
  { key: "15m", label: "15m", ms: 15 * 60_000 },
  { key: "1h", label: "1h", ms: 60 * 60_000 },
  { key: "24h", label: "24h", ms: 24 * 60 * 60_000 },
  { key: "7d", label: "7d", ms: 7 * 24 * 60 * 60_000 },
  { key: "all", label: "All", ms: null },
];

const DEFAULT_BUCKET_COUNT = 24;

export function normalizeServerHistogram(
  resp: EvidenceHistogramResponse,
): NormalizedBucket[] {
  const stepMs = Math.max(0.001, resp.bucketSeconds) * 1000;
  return resp.buckets.map((b, i) => {
    const nextStart = resp.buckets[i + 1]?.start;
    const startMs = Date.parse(b.start);
    const end =
      nextStart ??
      (resp.until ||
        (Number.isFinite(startMs) ? new Date(startMs + stepMs).toISOString() : b.start));
    const byOutcome = b.byOutcome ?? {};
    const allow = byOutcome.allow ?? 0;
    const deny = (byOutcome.deny ?? 0) + (byOutcome.error ?? 0);
    const sumByOutcome = Object.values(byOutcome).reduce(
      (acc, n) => acc + (typeof n === "number" ? n : 0),
      0,
    );
    const other = Math.max(0, b.count - sumByOutcome);
    return {
      start: b.start,
      end,
      allow,
      deny,
      other,
      total: b.count,
    };
  });
}

export function buildBucketsFromRows(
  rows: readonly LoadedHistogramRow[],
  bucketCount = DEFAULT_BUCKET_COUNT,
): NormalizedBucket[] {
  const parsed = rows
    .map((r) => ({ ms: Date.parse(r.capturedAt), outcome: r.outcome }))
    .filter((r) => Number.isFinite(r.ms));

  if (parsed.length === 0) return [];

  let minMs = parsed[0]!.ms;
  let maxMs = parsed[0]!.ms;
  for (const r of parsed) {
    if (r.ms < minMs) minMs = r.ms;
    if (r.ms > maxMs) maxMs = r.ms;
  }

  const span = Math.max(60_000, maxMs - minMs);
  const startMs = minMs;
  const step = span / bucketCount;

  const buckets: NormalizedBucket[] = Array.from({ length: bucketCount }, (_, i) => ({
    start: new Date(startMs + i * step).toISOString(),
    end: new Date(startMs + (i + 1) * step).toISOString(),
    allow: 0,
    deny: 0,
    other: 0,
    total: 0,
  }));

  for (const r of parsed) {
    const rawIdx = Math.floor((r.ms - startMs) / step);
    const idx = Math.max(0, Math.min(bucketCount - 1, rawIdx));
    const b = buckets[idx]!;
    if (r.outcome === "allow") b.allow += 1;
    else if (r.outcome === "deny" || r.outcome === "error") b.deny += 1;
    else b.other += 1;
    b.total += 1;
  }

  return buckets;
}

function formatAxisTime(iso: string, mode: TimeDisplayMode): { display: string; utc: string } {
  const utc = formatUtcTimestamp(iso);
  if (mode === "utc") return { display: utc.slice(5), utc };
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return { display: iso, utc };
  try {
    const display = new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(new Date(ms));
    return { display, utc };
  } catch {
    return { display: utc.slice(5), utc };
  }
}

export function EvidenceHistogram({
  serverHistogram,
  analyticsError,
  loadedRows,
  since,
  until,
  timeMode = "local",
  onSelectRange,
}: Props): JSX.Element {
  const isServerBacked = Boolean(
    serverHistogram && Array.isArray(serverHistogram.buckets) && serverHistogram.buckets.length > 0,
  );
  const buckets = useMemo(
    () =>
      isServerBacked && serverHistogram
        ? normalizeServerHistogram(serverHistogram)
        : buildBucketsFromRows(loadedRows),
    [isServerBacked, serverHistogram, loadedRows],
  );

  const maxTotal = useMemo(() => {
    let m = 1;
    for (const b of buckets) {
      if (b.total > m) m = b.total;
    }
    return m;
  }, [buckets]);

  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);
  const [brushStartIdx, setBrushStartIdx] = useState<number | null>(null);
  const [brushEndIdx, setBrushEndIdx] = useState<number | null>(null);
  const brushStartRef = useRef<number | null>(null);
  const brushEndRef = useRef<number | null>(null);
  const [activePreset, setActivePreset] = useState<PresetKey | null>(
    !since && !until ? "all" : null,
  );
  const barAreaRef = useRef<HTMLDivElement>(null);

  function indexFromClientX(clientX: number): number {
    const el = barAreaRef.current;
    if (!el || buckets.length === 0) return 0;
    const rect = el.getBoundingClientRect();
    const ratio = (clientX - rect.left) / Math.max(1, rect.width);
    return Math.max(0, Math.min(buckets.length - 1, Math.floor(ratio * buckets.length)));
  }

  function commitBrush(startIdx: number, endIdx: number): void {
    if (buckets.length === 0) return;
    const lo = Math.min(startIdx, endIdx);
    const hi = Math.max(startIdx, endIdx);
    const first = buckets[lo];
    const last = buckets[hi];
    if (first && last) {
      setActivePreset(null);
      onSelectRange(first.start, last.end);
    }
  }

  function handlePreset(preset: { key: PresetKey; ms: number | null }): void {
    setActivePreset(preset.key);
    if (preset.ms === null) {
      onSelectRange(null, null);
      return;
    }
    const now = Date.now();
    onSelectRange(new Date(now - preset.ms).toISOString(), new Date(now).toISOString());
  }

  const selLo =
    brushStartIdx !== null && brushEndIdx !== null
      ? Math.min(brushStartIdx, brushEndIdx)
      : null;
  const selHi =
    brushStartIdx !== null && brushEndIdx !== null
      ? Math.max(brushStartIdx, brushEndIdx)
      : null;

  const hovered = hoveredIdx !== null ? buckets[hoveredIdx] : null;

  return (
    <section
      data-testid="evidence-histogram"
      aria-label="Evidence volume over time"
      className="border-b border-r5e-border bg-r5e-surface/40 px-5 py-2.5"
    >
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="font-semibold text-r5e-text/90">Timeline</span>
          {analyticsError ? (
            <span
              data-testid="histogram-error-badge"
              title={analyticsError}
              className="rounded border border-r5e-danger/50 bg-r5e-danger/15 px-1.5 py-0.5 font-mono text-[10px] text-r5e-danger"
            >
              histogram error: {analyticsError}
            </span>
          ) : !isServerBacked ? (
            <span
              data-testid="histogram-source-badge"
              className="rounded border border-r5e-border bg-r5e-bg px-1.5 py-0.5 font-mono text-[10px] text-r5e-text/80"
            >
              showing loaded window
            </span>
          ) : null}
          <div className="flex items-center gap-3 text-[11px] text-r5e-text/80">
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm bg-r5e-success" /> Allow
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm bg-r5e-danger" /> Deny / Error
            </span>
            <span className="inline-flex items-center gap-1">
              <span className="h-2 w-2 rounded-sm bg-r5e-accent/80" /> Other
            </span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {(since || until) && (
            <button
              type="button"
              data-testid="clear-time-range-btn"
              onClick={() => {
                setActivePreset("all");
                onSelectRange(null, null);
              }}
              className="rounded border border-r5e-accent/50 bg-r5e-accent/15 px-2 py-0.5 font-mono text-[11px] text-r5e-text hover:bg-r5e-accent/25"
            >
              Clear time range ×
            </button>
          )}
          <div className="inline-flex rounded border border-r5e-border bg-r5e-bg p-0.5">
            {PRESETS.map((p) => (
              <button
                key={p.key}
                type="button"
                data-testid={`time-preset-${p.key}`}
                onClick={() => handlePreset(p)}
                className={[
                  "rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                  activePreset === p.key
                    ? "bg-r5e-accent/25 text-r5e-text"
                    : "text-r5e-text/75 hover:text-r5e-text",
                ].join(" ")}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {buckets.length === 0 ? (
        <div className="flex h-12 items-center justify-center rounded border border-dashed border-r5e-border text-xs text-r5e-text/70">
          No timestamped records in current view
        </div>
      ) : (
        <div className="select-none">
          <div className="flex items-stretch gap-1.5">
            {/* Light Y-axis count scale */}
            <div
              aria-hidden="true"
              data-testid="histogram-y-scale"
              className="flex w-7 shrink-0 flex-col justify-between py-0.5 text-right font-mono text-[10px] leading-none text-r5e-text/60"
            >
              <span>{maxTotal}</span>
              <span>0</span>
            </div>

            <div
              ref={barAreaRef}
              data-testid="histogram-brush-area"
              role="region"
              aria-label="Drag across bars to select a time range"
              onMouseDown={(e) => {
                const idx = indexFromClientX(e.clientX);
                brushStartRef.current = idx;
                brushEndRef.current = idx;
                setBrushStartIdx(idx);
                setBrushEndIdx(idx);
              }}
              onMouseMove={(e) => {
                const idx = indexFromClientX(e.clientX);
                setHoveredIdx(idx);
                if (brushStartRef.current !== null) {
                  brushEndRef.current = idx;
                  setBrushEndIdx(idx);
                }
              }}
              onMouseUp={(e) => {
                if (brushStartRef.current !== null) {
                  const start = brushStartRef.current;
                  const endIdx = indexFromClientX(e.clientX);
                  brushStartRef.current = null;
                  brushEndRef.current = null;
                  setBrushStartIdx(null);
                  setBrushEndIdx(null);
                  commitBrush(start, endIdx);
                }
              }}
              onMouseLeave={() => {
                setHoveredIdx(null);
                if (brushStartRef.current !== null && brushEndRef.current !== null) {
                  const start = brushStartRef.current;
                  const endIdx = brushEndRef.current;
                  brushStartRef.current = null;
                  brushEndRef.current = null;
                  setBrushStartIdx(null);
                  setBrushEndIdx(null);
                  commitBrush(start, endIdx);
                }
              }}
              className={[
                "relative flex h-14 min-w-0 flex-1 cursor-crosshair items-end gap-0.5 rounded border px-1.5 pt-1.5",
                since || until
                  ? "border-r5e-accent/50 bg-r5e-accent/10"
                  : "border-r5e-border bg-r5e-bg/80",
              ].join(" ")}
            >
              {buckets.map((b, i) => {
                const heightPct =
                  b.total > 0 ? Math.max(8, Math.round((b.total / maxTotal) * 100)) : 0;
                const allowPct = b.total > 0 ? (b.allow / b.total) * 100 : 0;
                const denyPct = b.total > 0 ? (b.deny / b.total) * 100 : 0;
                const otherPct = b.total > 0 ? Math.max(0, 100 - allowPct - denyPct) : 0;
                const inBrush = selLo !== null && selHi !== null && i >= selLo && i <= selHi;
                const ts = formatTimestamp(b.start, timeMode);

                return (
                  <div
                    key={b.start}
                    data-testid={`histogram-bar-${i}`}
                    data-bucket-count={b.total}
                    title={`${ts.display} (${ts.utc}) — total:${b.total} (allow:${b.allow}, deny/error:${b.deny}, other:${b.other})`}
                    className={[
                      "flex h-full flex-1 flex-col items-center justify-end rounded-t-sm transition-colors",
                      inBrush ? "bg-r5e-accent/25" : hoveredIdx === i ? "bg-r5e-surface" : "",
                    ].join(" ")}
                  >
                    {b.total > 0 && (
                      <div
                        className="flex w-full max-w-[20px] flex-col overflow-hidden rounded-t-sm"
                        style={{ height: `${heightPct}%` }}
                      >
                        {b.deny > 0 && (
                          <div
                            className="w-full bg-r5e-danger"
                            style={{ height: `${denyPct}%`, minHeight: "2px" }}
                          />
                        )}
                        {b.allow > 0 && (
                          <div
                            className="w-full bg-r5e-success"
                            style={{ height: `${allowPct}%`, minHeight: "2px" }}
                          />
                        )}
                        {b.other > 0 && (
                          <div
                            className="w-full bg-r5e-accent/80"
                            style={{ height: `${otherPct}%`, minHeight: "2px" }}
                          />
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          {(() => {
            const leftAxis = formatAxisTime(buckets[0]!.start, timeMode);
            const rightAxis = formatAxisTime(buckets[buckets.length - 1]!.end, timeMode);
            const hoveredAxis = hovered ? formatAxisTime(hovered.start, timeMode) : null;
            return (
              <div className="mt-1 flex items-center justify-between gap-2 pl-8 font-mono text-[10px] text-r5e-text/75">
                <span className="shrink-0" title={leftAxis.utc}>
                  {leftAxis.display}
                </span>
                <span
                  data-testid="histogram-hover-readout"
                  className="truncate text-r5e-text/80"
                  title={hoveredAxis?.utc}
                >
                  {hovered && hoveredAxis
                    ? `${hoveredAxis.display} — ${hovered.total} records (allow:${hovered.allow} deny/err:${hovered.deny} other:${hovered.other})`
                    : since || until
                      ? "Showing selected range — drag again to refine"
                      : "Drag across bars to filter time range"}
                </span>
                <span className="shrink-0" title={rightAxis.utc}>
                  {rightAxis.display}
                </span>
              </div>
            );
          })()}
        </div>
      )}
    </section>
  );
}
