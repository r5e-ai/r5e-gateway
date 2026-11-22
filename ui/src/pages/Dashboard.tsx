// Dashboard — Provenance v2 Policy Checks & Evidence Table (`/admin/dashboard`).
//
// Features:
//   - Server-side filters (`kind`, `policyOutcome`, `target`, `q`, `actor`, `session`, `since`, `until`)
//   - Disjunctive server facets (`GET /v1/evidence/facets`) with graceful fallback to loaded rows
//   - Stacked interactive time-brush histogram (`GET /v1/evidence/histogram`) with drag-to-zoom
//   - Resizable, reorderable, show/hide Evidence Table columns persisted in localStorage
//   - High-contrast dark-mode typography and horizontal scroll container

import { Radio, Search, ShieldCheck, ShieldX } from "lucide-react";
import { useCallback, useMemo, useRef, useState } from "react";
import { Outlet, useNavigate, useSearchParams } from "react-router-dom";

import { BulkActionBar } from "~/components/evidence/BulkActionBar";
import { ColumnPicker } from "~/components/evidence/ColumnPicker";
import { EvidenceHistogram } from "~/components/evidence/EvidenceHistogram";
import { Pill } from "~/components/shared/Pill";
import { TopBar } from "~/components/shared/TopBar";
import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
import { useAuth } from "~/hooks/useAuth";
import {
  useEvidenceFacets,
  useEvidenceHistogram,
} from "~/hooks/useEvidenceAnalytics";
import { useDeployment } from "~/hooks/useEvidenceRecord";
import {
  useEvidenceRecords,
  type EvidenceFilter,
} from "~/hooks/useEvidenceRecords";
import {
  mergeEvidenceRows,
  useEvidenceTail,
} from "~/hooks/useEvidenceTail";
import {
  COLUMN_DEF_BY_ID,
  defaultColumnPrefs,
  loadColumnPrefs,
  reorderColumnIds,
  saveColumnPrefs,
  type EvidenceColumnId,
  type EvidenceColumnPrefs,
} from "~/lib/evidenceColumns";
import {
  decodeEvidencePayload,
  formatActorShort,
  policyEvaluationOf,
  policyOutcomeOf,
  shortKindName,
  targetDetailOf,
  truncateRef,
  type EvidenceRecordEntry,
  type PolicyOutcome,
} from "~/lib/evidenceTypes";
import { recordDetailPath } from "~/lib/routes";

export default function Dashboard(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const auth = useAuth();
  const role = auth.status === "authenticated" ? auth.role : "tenant_auditor";

  const [selectedRefs, setSelectedRefs] = useState<string[]>([]);
  const [liveTailEnabled, setLiveTailEnabled] = useState<boolean>(false);
  const [customKindInput, setCustomKindInput] = useState<string>(
    searchParams.get("kind") ?? "",
  );
  const [searchInput, setSearchInput] = useState<string>(
    searchParams.get("q") ?? "",
  );
  const [columnPrefs, setColumnPrefs] = useState<EvidenceColumnPrefs>(() =>
    loadColumnPrefs(),
  );
  const [dragColId, setDragColId] = useState<EvidenceColumnId | null>(null);
  const resizeStateRef = useRef<{
    id: EvidenceColumnId;
    startX: number;
    startWidth: number;
  } | null>(null);

  const filter: EvidenceFilter = useMemo(() => {
    const rawOutcome = searchParams.get("policyOutcome");
    const policyOutcome: PolicyOutcome | undefined =
      rawOutcome === "allow" || rawOutcome === "deny" || rawOutcome === "error"
        ? rawOutcome
        : undefined;
    return {
      kind: searchParams.get("kind") || undefined,
      policyOutcome,
      target: searchParams.get("target") || undefined,
      q: searchParams.get("q") || undefined,
      actor: searchParams.get("actor") || undefined,
      session: searchParams.get("session") || undefined,
      since: searchParams.get("since") || undefined,
      until: searchParams.get("until") || undefined,
    };
  }, [searchParams]);

  const deploymentQuery = useDeployment();
  const recordsQuery = useEvidenceRecords(filter);
  const facetsQuery = useEvidenceFacets(filter);

  const refetchOnTailOpen = useCallback(() => {
    void recordsQuery.refetch();
  }, [recordsQuery]);

  const tail = useEvidenceTail(
    liveTailEnabled,
    {
      kind: filter.kind,
      session: filter.session,
      actor: filter.actor,
    },
    refetchOnTailOpen,
  );

  const fetchedRows: EvidenceRecordEntry[] = useMemo(
    () => recordsQuery.data?.pages.flatMap((p) => p.records) ?? [],
    [recordsQuery.data],
  );

  const rawRows: EvidenceRecordEntry[] = useMemo(
    () => mergeEvidenceRows(tail.liveRecords, fetchedRows),
    [tail.liveRecords, fetchedRows],
  );

  const decodedRows = useMemo(
    () =>
      rawRows.map((entry) => {
        const payload = decodeEvidencePayload(entry.envelope);
        const policy = policyEvaluationOf(payload);
        const outcome: PolicyOutcome | null =
          entry.policyOutcome ?? policyOutcomeOf(payload);
        const detail = targetDetailOf(payload);
        const targetPrimary = entry.target || detail.primary;
        const targetSecondary =
          entry.target && detail.primary !== entry.target
            ? detail.secondary ?? detail.primary
            : detail.secondary;
        return {
          entry,
          payload,
          policy,
          outcome,
          targetPrimary,
          targetSecondary,
        };
      }),
    [rawRows],
  );

  // Derive a default histogram window from loaded rows when URL has no explicit since/until
  const fallbackWindow = useMemo(() => {
    if (decodedRows.length === 0) return {};
    let minMs = Infinity;
    let maxMs = -Infinity;
    for (const r of decodedRows) {
      const ms = Date.parse(r.entry.capturedAt);
      if (Number.isFinite(ms)) {
        if (ms < minMs) minMs = ms;
        if (ms > maxMs) maxMs = ms;
      }
    }
    if (!Number.isFinite(minMs) || !Number.isFinite(maxMs)) return {};
    const paddedMax = Math.max(maxMs + 1000, minMs + 60_000);
    return {
      since: new Date(minMs).toISOString(),
      until: new Date(paddedMax).toISOString(),
    };
  }, [decodedRows]);

  const histogramQuery = useEvidenceHistogram(filter, fallbackWindow, 36);

  const serverFacets = facetsQuery.data;
  const usingServerFacets = Boolean(serverFacets);

  const kindFacetRows = useMemo(() => {
    if (serverFacets?.facets?.kind) {
      return serverFacets.facets.kind.map((b) => [b.value, b.count] as const);
    }
    const counts = new Map<string, number>();
    for (const { entry } of decodedRows) {
      counts.set(entry.kind, (counts.get(entry.kind) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [serverFacets, decodedRows]);

  const outcomeCounts = useMemo(() => {
    const counts: Record<PolicyOutcome, number> = { allow: 0, deny: 0, error: 0 };
    if (serverFacets?.facets?.policyOutcome) {
      for (const b of serverFacets.facets.policyOutcome) {
        if (b.value === "allow" || b.value === "deny" || b.value === "error") {
          counts[b.value] = b.count;
        }
      }
      return counts;
    }
    for (const r of decodedRows) {
      if (r.outcome) counts[r.outcome]++;
    }
    return counts;
  }, [serverFacets, decodedRows]);

  const targetFacetRows = useMemo(() => {
    if (serverFacets?.facets?.target) {
      return serverFacets.facets.target.slice(0, 12).map((b) => [b.value, b.count] as const);
    }
    const counts = new Map<string, number>();
    for (const r of decodedRows) {
      if (r.targetPrimary && r.targetPrimary !== "—") {
        counts.set(r.targetPrimary, (counts.get(r.targetPrimary) ?? 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12);
  }, [serverFacets, decodedRows]);

  const stats = useMemo(() => {
    const total = serverFacets ? serverFacets.total : decodedRows.length;
    const allowed = outcomeCounts.allow;
    const denied = outcomeCounts.deny + outcomeCounts.error;
    return {
      total,
      policyChecks: allowed + denied,
      allowed,
      denied,
    };
  }, [serverFacets, decodedRows.length, outcomeCounts]);

  const visibleColumns = useMemo(
    () => columnPrefs.order.filter((id) => columnPrefs.visible[id]),
    [columnPrefs],
  );

  const totalTableWidth = useMemo(
    () =>
      40 +
      visibleColumns.reduce(
        (sum, id) => sum + (columnPrefs.widths[id] ?? COLUMN_DEF_BY_ID[id].defaultWidth),
        0,
      ),
    [visibleColumns, columnPrefs.widths],
  );

  const firstSelectedSession = useMemo(() => {
    const first = selectedRefs[0];
    if (!first) return null;
    const found = decodedRows.find((r) => r.entry.ref === first);
    return found?.entry.session ?? found?.payload?.session ?? null;
  }, [selectedRefs, decodedRows]);

  function updatePrefs(updater: (prev: EvidenceColumnPrefs) => EvidenceColumnPrefs): void {
    setColumnPrefs((prev) => {
      const next = updater(prev);
      saveColumnPrefs(next);
      return next;
    });
  }

  function handleToggleColumn(id: EvidenceColumnId): void {
    updatePrefs((prev) => ({
      ...prev,
      visible: { ...prev.visible, [id]: !prev.visible[id] },
    }));
  }

  function handleMoveColumn(id: EvidenceColumnId, direction: "left" | "right"): void {
    updatePrefs((prev) => {
      const idx = prev.order.indexOf(id);
      if (idx < 0) return prev;
      const targetIdx = direction === "left" ? idx - 1 : idx + 1;
      if (targetIdx < 0 || targetIdx >= prev.order.length) return prev;
      const targetId = prev.order[targetIdx]!;
      return { ...prev, order: reorderColumnIds(prev.order, id, targetId) };
    });
  }

  function handleResetColumns(): void {
    updatePrefs(() => defaultColumnPrefs());
  }

  function startResize(id: EvidenceColumnId, clientX: number): void {
    const def = COLUMN_DEF_BY_ID[id];
    const startWidth = columnPrefs.widths[id] ?? def.defaultWidth;
    resizeStateRef.current = { id, startX: clientX, startWidth };

    function onMove(ev: MouseEvent): void {
      const st = resizeStateRef.current;
      if (!st) return;
      const delta = ev.clientX - st.startX;
      const clamped = Math.max(def.minWidth, Math.min(800, Math.round(st.startWidth + delta)));
      updatePrefs((prev) => ({
        ...prev,
        widths: { ...prev.widths, [st.id]: clamped },
      }));
    }

    function onUp(): void {
      resizeStateRef.current = null;
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    }

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }

  function updateParam(key: string, value: string | null): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (!value) next.delete(key);
        else next.set(key, value);
        return next;
      },
      { replace: true },
    );
  }

  function updateTimeRange(since: string | null, until: string | null): void {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (since) next.set("since", since);
        else next.delete("since");
        if (until) next.set("until", until);
        else next.delete("until");
        return next;
      },
      { replace: true },
    );
  }

  function toggleRow(ref: string): void {
    setSelectedRefs((prev) =>
      prev.includes(ref) ? prev.filter((r) => r !== ref) : [...prev, ref],
    );
  }

  function toggleAll(): void {
    if (selectedRefs.length === decodedRows.length) {
      setSelectedRefs([]);
    } else {
      setSelectedRefs(decodedRows.map((r) => r.entry.ref));
    }
  }

  const hasActiveFilter = Boolean(
    filter.kind ||
      filter.policyOutcome ||
      filter.target ||
      filter.q ||
      filter.session ||
      filter.actor ||
      filter.since ||
      filter.until,
  );

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar
        pageContent={
          <div className="flex min-w-0 items-center gap-3">
            <h1 className="truncate text-sm font-semibold text-r5e-text">
              Policy Checks &amp; Evidence
            </h1>
            {deploymentQuery.data?.chain && (
              <span
                data-testid="deployment-chain-badge"
                className="hidden items-center gap-1.5 rounded-full border border-r5e-border bg-r5e-surface px-2.5 py-0.5 font-mono text-[11px] text-r5e-text/80 xl:inline-flex"
                title={deploymentQuery.data.chain}
              >
                chain: {truncateRef(deploymentQuery.data.chain, 10)}
              </span>
            )}
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            {tail.statusDetail && (
              <span
                data-testid="live-tail-status-detail"
                className="hidden text-[11px] text-r5e-warning lg:inline"
              >
                {tail.statusDetail}
              </span>
            )}
            <button
              type="button"
              data-testid="live-tail-toggle"
              onClick={() => setLiveTailEnabled((v) => !v)}
              className={[
                "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded border px-2.5 py-1 text-xs font-medium transition-colors",
                tail.status === "connected"
                  ? "border-r5e-success/50 bg-r5e-success/15 text-r5e-success"
                  : liveTailEnabled
                    ? "border-r5e-warning/50 bg-r5e-warning/10 text-r5e-warning"
                    : "border-r5e-border bg-r5e-surface text-r5e-text/85 hover:text-r5e-text",
              ].join(" ")}
            >
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              <span>
                {tail.status === "connected"
                  ? "Live tail: on"
                  : tail.status === "connecting"
                    ? "Connecting…"
                    : tail.status === "not_capturing"
                      ? "Not capturing"
                      : liveTailEnabled
                        ? "Reconnecting"
                        : "Live tail"}
              </span>
            </button>
          </div>
        }
      />

      <div className="flex min-h-0 flex-1 overflow-hidden">
        {/* Left filter rail (high-contrast dark-mode typography) */}
        <aside
          aria-label="Evidence filters"
          className="flex w-[240px] shrink-0 flex-col gap-5 overflow-y-auto border-r border-r5e-border bg-r5e-surface/60 p-4"
        >
          {facetsQuery.isError && (
            <div
              data-testid="facets-error-banner"
              className="rounded border border-r5e-danger/50 bg-r5e-danger/15 px-2.5 py-1.5 text-[11px] text-r5e-danger"
            >
              Facets unavailable: {facetsQuery.error.message}
            </div>
          )}
          {/* Policy Outcome facet */}
          <div>
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-text/80">
              Policy Outcome{usingServerFacets ? "" : " (loaded)"}
            </h2>
            <div className="mt-2 flex flex-col gap-1">
              {(["allow", "deny", "error"] as const).map((outcome) => {
                const active = filter.policyOutcome === outcome;
                return (
                  <button
                    key={outcome}
                    type="button"
                    data-testid={`filter-outcome-${outcome}`}
                    onClick={() =>
                      updateParam("policyOutcome", active ? null : outcome)
                    }
                    className={[
                      "flex items-center justify-between rounded px-2.5 py-1.5 text-xs transition-colors",
                      active
                        ? "bg-r5e-accent/25 font-medium text-r5e-text"
                        : "text-r5e-text/85 hover:bg-r5e-bg hover:text-r5e-text",
                    ].join(" ")}
                  >
                    <span className="capitalize">{outcome}</span>
                    <span className="font-mono text-[11px] text-r5e-text/80">
                      {outcomeCounts[outcome]}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Open-string full kind path facet */}
          <div>
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-text/80">
              Record Kind
            </h2>
            <form
              className="mt-2 flex gap-1"
              onSubmit={(e) => {
                e.preventDefault();
                updateParam("kind", customKindInput.trim() || null);
              }}
            >
              <input
                type="text"
                value={customKindInput}
                onChange={(e) => setCustomKindInput(e.target.value)}
                placeholder="provenance.r5e.io/v2/…"
                data-testid="open-kind-filter-input"
                className="min-w-0 flex-1 rounded border border-r5e-border bg-r5e-bg px-2 py-1 font-mono text-[11px] text-r5e-text placeholder:text-r5e-text/55"
              />
              <button
                type="submit"
                className="rounded border border-r5e-border bg-r5e-surface px-2 py-1 text-[11px] font-medium text-r5e-text hover:bg-r5e-bg"
              >
                Go
              </button>
            </form>
            <div className="mt-2 flex flex-col gap-1">
              {kindFacetRows.map(([kindPath, count]) => {
                const active = filter.kind === kindPath;
                return (
                  <button
                    key={kindPath}
                    type="button"
                    data-testid={`filter-kind-${shortKindName(kindPath)}`}
                    onClick={() => {
                      const next = active ? null : kindPath;
                      setCustomKindInput(next ?? "");
                      updateParam("kind", next);
                    }}
                    title={kindPath}
                    className={[
                      "flex items-center justify-between gap-2 rounded px-2.5 py-1.5 text-left text-xs transition-colors",
                      active
                        ? "bg-r5e-accent/25 font-medium text-r5e-text"
                        : "text-r5e-text/85 hover:bg-r5e-bg hover:text-r5e-text",
                    ].join(" ")}
                  >
                    <span className="truncate font-mono text-[11px]">
                      {shortKindName(kindPath)}
                    </span>
                    <span className="shrink-0 font-mono text-[11px] text-r5e-text/80">
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Target / Tool facet */}
          {targetFacetRows.length > 0 && (
            <div>
              <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-text/80">
                Target / Tool
              </h2>
              <div className="mt-2 flex flex-col gap-1">
                {targetFacetRows.map(([targetVal, count]) => {
                  const active = filter.target === targetVal;
                  return (
                    <button
                      key={targetVal}
                      type="button"
                      data-testid={`filter-target-${targetVal}`}
                      onClick={() =>
                        updateParam("target", active ? null : targetVal)
                      }
                      title={targetVal}
                      className={[
                        "flex items-center justify-between gap-2 rounded px-2.5 py-1.5 text-left text-xs transition-colors",
                        active
                          ? "bg-r5e-accent/25 font-medium text-r5e-text"
                          : "text-r5e-text/85 hover:bg-r5e-bg hover:text-r5e-text",
                      ].join(" ")}
                    >
                      <span className="truncate font-mono text-[11px]">
                        {targetVal}
                      </span>
                      <span className="shrink-0 font-mono text-[11px] text-r5e-text/80">
                        {count}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {hasActiveFilter && (
            <button
              type="button"
              data-testid="clear-filters-btn"
              onClick={() => {
                setCustomKindInput("");
                setSearchInput("");
                setSearchParams({}, { replace: true });
              }}
              className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 text-xs font-medium text-r5e-text/90 hover:text-r5e-text"
            >
              Clear all filters
            </button>
          )}
        </aside>

        {/* Main content column */}
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
          {/* KPI strip + search + Column Picker */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-r5e-border bg-r5e-bg px-5 py-3">
            <div className="flex flex-wrap items-center gap-2.5 text-xs">
              <StatChip label="Records" value={stats.total} testId="stat-total" />
              <StatChip label="Policy Checks" value={stats.policyChecks} />
              <StatChip
                label="Allowed"
                value={stats.allowed}
                tone="success"
                icon={<ShieldCheck className="h-3.5 w-3.5 text-r5e-success" />}
              />
              <StatChip
                label="Denied"
                value={stats.denied}
                tone="danger"
                icon={<ShieldX className="h-3.5 w-3.5 text-r5e-danger" />}
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <form
                className="relative flex w-64 items-center"
                onSubmit={(e) => {
                  e.preventDefault();
                  updateParam("q", searchInput.trim() || null);
                }}
              >
                <Search className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-r5e-text/70" />
                <input
                  type="search"
                  maxLength={200}
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  placeholder="Search actor, session, kind, target…"
                  data-testid="evidence-search-input"
                  className="w-full rounded border border-r5e-border bg-r5e-surface py-1.5 pl-8 pr-3 text-xs text-r5e-text placeholder:text-r5e-text/55"
                />
              </form>

              <ColumnPicker
                prefs={columnPrefs}
                onToggle={handleToggleColumn}
                onMove={handleMoveColumn}
                onReset={handleResetColumns}
              />
            </div>
          </div>

          {/* Interactive Time-Brush Histogram */}
          <EvidenceHistogram
            serverHistogram={histogramQuery.data}
            analyticsError={histogramQuery.isError ? histogramQuery.error.message : null}
            loadedRows={decodedRows.map((r) => ({
              capturedAt: r.entry.capturedAt,
              outcome: r.outcome,
            }))}
            since={filter.since}
            until={filter.until}
            onSelectRange={updateTimeRange}
          />

          {/* Horizontally scrollable, resizable, reorderable table */}
          <div className="min-h-0 flex-1 overflow-x-auto overflow-y-auto">
            {recordsQuery.isLoading && (
              <div className="p-5">
                <Skeleton.Rows rows={8} />
              </div>
            )}

            {recordsQuery.isError && (
              <div className="p-5">
                <ErrorState
                  title="Failed to load Provenance v2 records"
                  detail={recordsQuery.error.message}
                  retry={{ onClick: () => void recordsQuery.refetch() }}
                />
              </div>
            )}

            {!recordsQuery.isLoading &&
              !recordsQuery.isError &&
              decodedRows.length === 0 && (
                <div className="p-8">
                  <EmptyState
                    title="No matching evidence records"
                    body="Adjust your kind, policy outcome, time range, or search filter."
                  />
                </div>
              )}

            {decodedRows.length > 0 && (
              <table
                data-testid="evidence-table"
                style={{ width: `${totalTableWidth}px` }}
                className="min-w-full table-fixed border-collapse text-left text-xs"
              >
                <colgroup>
                  <col style={{ width: 40 }} />
                  {visibleColumns.map((colId) => (
                    <col
                      key={colId}
                      style={{
                        width:
                          columnPrefs.widths[colId] ??
                          COLUMN_DEF_BY_ID[colId].defaultWidth,
                      }}
                    />
                  ))}
                </colgroup>
                <thead className="sticky top-0 z-10 border-b border-r5e-border bg-r5e-surface text-[11px] font-semibold uppercase tracking-wider text-r5e-text/85">
                  <tr>
                    <th className="w-10 px-3 py-2.5">
                      <input
                        type="checkbox"
                        aria-label="Select all records"
                        checked={
                          decodedRows.length > 0 &&
                          selectedRefs.length === decodedRows.length
                        }
                        onChange={toggleAll}
                      />
                    </th>
                    {visibleColumns.map((colId) => {
                      const def = COLUMN_DEF_BY_ID[colId];
                      return (
                        <th
                          key={colId}
                          data-testid={`col-header-${colId}`}
                          draggable
                          onDragStart={() => setDragColId(colId)}
                          onDragOver={(e) => e.preventDefault()}
                          onDrop={(e) => {
                            e.preventDefault();
                            if (dragColId && dragColId !== colId) {
                              updatePrefs((prev) => ({
                                ...prev,
                                order: reorderColumnIds(prev.order, dragColId, colId),
                              }));
                            }
                            setDragColId(null);
                          }}
                          onDragEnd={() => setDragColId(null)}
                          className="relative select-none truncate px-3 py-2.5 cursor-grab active:cursor-grabbing"
                          title="Drag to reorder column; drag right edge to resize"
                        >
                          <span className="truncate">{def.label}</span>
                          <span
                            role="separator"
                            aria-orientation="vertical"
                            aria-label={`Resize ${def.label} column`}
                            data-testid={`col-resize-${colId}`}
                            onMouseDown={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              startResize(colId, e.clientX);
                            }}
                            onClick={(e) => e.stopPropagation()}
                            className="absolute right-0 top-0 h-full w-1.5 cursor-col-resize hover:bg-r5e-accent/60"
                          />
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody className="divide-y divide-r5e-border/70">
                  {decodedRows.map(
                    ({
                      entry,
                      payload,
                      policy,
                      outcome,
                      targetPrimary,
                      targetSecondary,
                    }) => {
                      const checked = selectedRefs.includes(entry.ref);
                      const fullActor = entry.actor ?? payload?.actor ?? "";
                      const fullSession = entry.session ?? payload?.session ?? "";
                      return (
                        <tr
                          key={entry.ref}
                          data-testid={`evidence-row-${shortKindName(entry.kind)}`}
                          onClick={() => navigate(recordDetailPath(entry.ref))}
                          className="cursor-pointer transition-colors hover:bg-r5e-surface/90"
                        >
                          <td
                            className="px-3 py-2.5"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <input
                              type="checkbox"
                              aria-label={`Select ${entry.ref}`}
                              checked={checked}
                              onChange={() => toggleRow(entry.ref)}
                            />
                          </td>
                          {visibleColumns.map((colId) => {
                            switch (colId) {
                              case "captured":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-r5e-text/85"
                                    title={entry.capturedAt}
                                  >
                                    {formatShortTime(entry.capturedAt)}
                                  </td>
                                );
                              case "kind":
                                return (
                                  <td key={colId} className="truncate whitespace-nowrap px-3 py-2.5">
                                    <span
                                      className="rounded border border-r5e-border bg-r5e-surface px-2 py-0.5 font-mono text-[11px] text-r5e-text"
                                      title={entry.kind}
                                    >
                                      {shortKindName(entry.kind)}
                                    </span>
                                  </td>
                                );
                              case "policy":
                                return (
                                  <td key={colId} className="whitespace-nowrap px-3 py-2.5">
                                    {outcome ? (
                                      <OutcomePill
                                        outcome={outcome}
                                        reason={policy?.reason}
                                      />
                                    ) : (
                                      <span className="text-r5e-text/60">—</span>
                                    )}
                                  </td>
                                );
                              case "target":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate px-3 py-2.5"
                                    title={
                                      targetSecondary
                                        ? `${targetPrimary} — ${targetSecondary}`
                                        : targetPrimary
                                    }
                                  >
                                    <div className="truncate font-mono text-xs text-r5e-text">
                                      {targetPrimary}
                                    </div>
                                    {targetSecondary && (
                                      <div className="truncate font-mono text-[10px] text-r5e-text/70">
                                        {targetSecondary}
                                      </div>
                                    )}
                                  </td>
                                );
                              case "actor":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate px-3 py-2.5 font-mono text-[11px] text-r5e-text/85"
                                    title={fullActor || undefined}
                                  >
                                    {formatActorShort(fullActor)}
                                  </td>
                                );
                              case "session":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate px-3 py-2.5 font-mono text-[11px] text-r5e-text/80"
                                    title={fullSession || undefined}
                                  >
                                    {fullSession
                                      ? fullSession.replace(/^urn:r5e:session:/, "")
                                      : "—"}
                                  </td>
                                );
                              case "ref":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-r5e-accent"
                                    title={entry.ref}
                                  >
                                    {truncateRef(entry.ref, 10)}
                                  </td>
                                );
                              case "streamSeq":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate px-3 py-2.5 font-mono text-[11px] text-r5e-text/80"
                                    title={`${entry.stream} #${entry.seq}`}
                                  >
                                    {entry.stream.replace(/^urn:r5e:stream:/, "")} #{entry.seq}
                                  </td>
                                );
                            }
                          })}
                        </tr>
                      );
                    },
                  )}
                </tbody>
              </table>
            )}

            {recordsQuery.hasNextPage && (
              <div className="flex justify-center p-4">
                <button
                  type="button"
                  onClick={() => recordsQuery.fetchNextPage()}
                  disabled={recordsQuery.isFetchingNextPage}
                  className="rounded border border-r5e-border bg-r5e-surface px-4 py-1.5 text-xs font-medium text-r5e-text hover:bg-r5e-bg disabled:opacity-50"
                >
                  {recordsQuery.isFetchingNextPage ? "Loading…" : "Load more records"}
                </button>
              </div>
            )}
          </div>

          <BulkActionBar
            selectedRefs={selectedRefs}
            firstSelectedSession={firstSelectedSession}
            role={role}
            onClearSelection={() => setSelectedRefs([])}
            onOpenDetail={(ref) => navigate(recordDetailPath(ref))}
          />
        </main>
      </div>

      <Outlet />
    </div>
  );
}

function OutcomePill({
  outcome,
  reason,
}: {
  outcome: PolicyOutcome;
  reason?: string;
}): JSX.Element {
  return (
    <span title={reason}>
      <Pill
        tone={
          outcome === "allow"
            ? "success"
            : outcome === "deny"
              ? "danger"
              : "warning"
        }
      >
        {outcome}
      </Pill>
    </span>
  );
}

function StatChip({
  label,
  value,
  tone,
  icon,
  testId,
}: {
  label: string;
  value: number;
  tone?: "success" | "danger";
  icon?: JSX.Element;
  testId?: string;
}): JSX.Element {
  return (
    <div
      data-testid={testId}
      className="inline-flex items-center gap-1.5 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1"
    >
      {icon}
      <span className="text-r5e-text/80">{label}:</span>
      <span
        className={[
          "font-mono font-semibold",
          tone === "success"
            ? "text-r5e-success"
            : tone === "danger"
              ? "text-r5e-danger"
              : "text-r5e-text",
        ].join(" ")}
      >
        {value}
      </span>
    </div>
  );
}

function formatShortTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
  } catch {
    return iso;
  }
}
