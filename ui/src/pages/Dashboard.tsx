// Dashboard — Audit Evidence table, facets, and interactive time-brush histogram
// (`/admin/dashboard`).

import { Check, Copy, Radio, Search, ShieldCheck, ShieldX } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Outlet, useLocation, useNavigate, useSearchParams } from "react-router-dom";

import { ColumnPicker } from "~/components/evidence/ColumnPicker";
import { EvidenceHistogram } from "~/components/evidence/EvidenceHistogram";
import { Pill } from "~/components/shared/Pill";
import { TopBar } from "~/components/shared/TopBar";
import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
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
  ACTIVITY_KIND_PARAM,
  decodeEvidencePayload,
  formatIdentityDisplay,
  formatTimestamp,
  policyEvaluationOf,
  policyOutcomeOf,
  reasonOf,
  serverTargetOf,
  shortKindName,
  truncateRef,
  type EvidenceRecordEntry,
  type PolicyOutcome,
  type TimeDisplayMode,
} from "~/lib/evidenceTypes";
import { recordDetailPath } from "~/lib/routes";

const TIME_MODE_STORAGE_KEY = "r5e.v2.timeMode";

function loadTimeMode(): TimeDisplayMode {
  if (typeof window === "undefined") return "local";
  try {
    return window.localStorage?.getItem(TIME_MODE_STORAGE_KEY) === "utc"
      ? "utc"
      : "local";
  } catch {
    return "local";
  }
}

export default function Dashboard(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();

  const [liveTailEnabled, setLiveTailEnabled] = useState<boolean>(false);
  const [customKindInput, setCustomKindInput] = useState<string>(
    searchParams.get("kind") ?? "",
  );
  const [showOtherKindInput, setShowOtherKindInput] = useState<boolean>(false);
  const [searchInput, setSearchInput] = useState<string>(
    searchParams.get("q") ?? "",
  );
  const [columnPrefs, setColumnPrefs] = useState<EvidenceColumnPrefs>(() =>
    loadColumnPrefs(),
  );
  const [timeMode, setTimeMode] = useState<TimeDisplayMode>(() => loadTimeMode());
  const [dragColId, setDragColId] = useState<EvidenceColumnId | null>(null);
  const [copiedActorRef, setCopiedActorRef] = useState<string | null>(null);
  const resizeStateRef = useRef<{
    id: EvidenceColumnId;
    startX: number;
    startWidth: number;
  } | null>(null);

  // View mode: Activity (default) vs All records vs explicit single kind
  const explicitKind = searchParams.get("kind") || undefined;
  const viewParam = searchParams.get("view");
  const isAllRecordsView = !explicitKind && viewParam === "all";
  const isActivityView = !explicitKind && viewParam !== "all";

  const filter: EvidenceFilter = useMemo(() => {
    const rawOutcome = searchParams.get("policyOutcome");
    const policyOutcome: PolicyOutcome | undefined =
      rawOutcome === "allow" || rawOutcome === "deny" || rawOutcome === "error"
        ? rawOutcome
        : undefined;
    return {
      kind: explicitKind ?? (isActivityView ? ACTIVITY_KIND_PARAM : undefined),
      policyOutcome,
      target: searchParams.get("target") || undefined,
      reason: searchParams.get("reason") || undefined,
      q: searchParams.get("q") || undefined,
      actor: searchParams.get("actor") || undefined,
      session: searchParams.get("session") || undefined,
      since: searchParams.get("since") || undefined,
      until: searchParams.get("until") || undefined,
    };
  }, [searchParams, explicitKind, isActivityView]);

  const deploymentQuery = useDeployment();
  const recordsQuery = useEvidenceRecords(filter);
  const facetsQuery = useEvidenceFacets(filter);

  const refetchOnTailOpen = useCallback(() => {
    void recordsQuery.refetch();
  }, [recordsQuery]);

  const tail = useEvidenceTail(
    liveTailEnabled,
    {
      kind: explicitKind,
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
        const target =
          entry.target !== undefined ? entry.target : serverTargetOf(payload);
        const reason =
          entry.reason !== undefined ? entry.reason : reasonOf(payload);
        return {
          entry,
          payload,
          policy,
          outcome,
          target,
          reason,
        };
      }),
    [rawRows],
  );

  // Keep a pinned baseline time window when "All" is active so filtering by
  // outcome/kind/target/reason doesn't collapse the histogram's X-axis span.
  const [baselineWindow, setBaselineWindow] = useState<{
    since?: string;
    until?: string;
  }>({});
  const hasNarrowingFilter = Boolean(
    filter.policyOutcome ||
      explicitKind ||
      filter.target ||
      filter.reason ||
      filter.q ||
      filter.actor ||
      filter.session,
  );

  useEffect(() => {
    if (decodedRows.length === 0) return;
    if (hasNarrowingFilter && baselineWindow.since && baselineWindow.until) {
      return;
    }
    let minMs = Infinity;
    let maxMs = -Infinity;
    for (const r of decodedRows) {
      const ms = Date.parse(r.entry.capturedAt);
      if (Number.isFinite(ms)) {
        if (ms < minMs) minMs = ms;
        if (ms > maxMs) maxMs = ms;
      }
    }
    if (!Number.isFinite(minMs) || !Number.isFinite(maxMs)) return;
    const paddedMax = Math.max(maxMs + 1000, minMs + 60_000);
    const nextSince = new Date(minMs).toISOString();
    const nextUntil = new Date(paddedMax).toISOString();
    setBaselineWindow((prev) =>
      prev.since === nextSince && prev.until === nextUntil
        ? prev
        : { since: nextSince, until: nextUntil },
    );
  }, [decodedRows, hasNarrowingFilter, baselineWindow.since, baselineWindow.until]);

  const histogramQuery = useEvidenceHistogram(filter, baselineWindow, 36);

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
      if (r.target) {
        counts.set(r.target, (counts.get(r.target) ?? 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12);
  }, [serverFacets, decodedRows]);

  const reasonFacetRows = useMemo(() => {
    if (serverFacets?.facets?.reason) {
      return serverFacets.facets.reason.slice(0, 12).map((b) => [b.value, b.count] as const);
    }
    const counts = new Map<string, number>();
    for (const r of decodedRows) {
      if (r.reason) {
        counts.set(r.reason, (counts.get(r.reason) ?? 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 12);
  }, [serverFacets, decodedRows]);

  // Top summary strip reflects ONE consistent scope: the current filtered view.
  const stats = useMemo(() => {
    const total = serverFacets ? serverFacets.total : decodedRows.length;
    if (filter.policyOutcome === "allow") {
      return {
        total,
        policyChecks: outcomeCounts.allow,
        allowed: outcomeCounts.allow,
        denied: 0,
      };
    }
    if (filter.policyOutcome === "deny") {
      return {
        total,
        policyChecks: outcomeCounts.deny,
        allowed: 0,
        denied: outcomeCounts.deny,
      };
    }
    if (filter.policyOutcome === "error") {
      return {
        total,
        policyChecks: outcomeCounts.error,
        allowed: 0,
        denied: outcomeCounts.error,
      };
    }
    const allowed = outcomeCounts.allow;
    const denied = outcomeCounts.deny + outcomeCounts.error;
    return {
      total,
      policyChecks: allowed + denied,
      allowed,
      denied,
    };
  }, [serverFacets, decodedRows.length, outcomeCounts, filter.policyOutcome]);

  const visibleColumns = useMemo(
    () => columnPrefs.order.filter((id) => columnPrefs.visible[id]),
    [columnPrefs],
  );

  const totalTableWidth = useMemo(
    () =>
      visibleColumns.reduce(
        (sum, id) => sum + (columnPrefs.widths[id] ?? COLUMN_DEF_BY_ID[id].defaultWidth),
        0,
      ),
    [visibleColumns, columnPrefs.widths],
  );

  function toggleTimeMode(next: TimeDisplayMode): void {
    setTimeMode(next);
    try {
      window.localStorage?.setItem(TIME_MODE_STORAGE_KEY, next);
    } catch {
      // ignore storage failures
    }
  }

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

  function autoFitColumn(id: EvidenceColumnId): void {
    const def = COLUMN_DEF_BY_ID[id];
    let maxChars = def.label.length + 2;
    for (const row of decodedRows) {
      let text = "";
      switch (id) {
        case "captured":
          text = formatTimestamp(row.entry.capturedAt, timeMode).display;
          break;
        case "kind":
          text = shortKindName(row.entry.kind);
          break;
        case "policy":
          text = row.outcome ?? "—";
          break;
        case "target":
          text = row.target ?? "—";
          break;
        case "reason":
          text = row.reason ?? "—";
          break;
        case "actor":
          text = formatIdentityDisplay(row.entry.actor ?? row.payload?.actor);
          break;
        case "session":
          text = (row.entry.session ?? row.payload?.session ?? "—").replace(
            /^urn:r5e:session:/,
            "",
          );
          break;
        case "ref":
          text = truncateRef(row.entry.ref, 10);
          break;
        case "streamSeq":
          text = `${row.entry.stream.replace(/^urn:r5e:stream:/, "")} #${row.entry.seq}`;
          break;
      }
      if (text.length > maxChars) maxChars = text.length;
    }
    const fitted = Math.max(def.minWidth, Math.min(520, Math.round(maxChars * 7.5 + 34)));
    updatePrefs((prev) => ({
      ...prev,
      widths: { ...prev.widths, [id]: fitted },
    }));
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
        if (key === "kind" && value) next.delete("view");
        return next;
      },
      { replace: true },
    );
  }

  function selectViewMode(mode: "activity" | "all"): void {
    setCustomKindInput("");
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete("kind");
        if (mode === "all") next.set("view", "all");
        else next.delete("view");
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

  const hasActiveFilter = Boolean(
    explicitKind ||
      filter.policyOutcome ||
      filter.target ||
      filter.reason ||
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
              Audit Evidence
            </h1>
            {deploymentQuery.data?.chain && (
              <span
                className="hidden shrink-0 rounded-full border border-r5e-border bg-r5e-bg px-2.5 py-0.5 font-mono text-[11px] text-r5e-text/80 xl:inline"
                title={`Deployment audit chain anchor: ${deploymentQuery.data.chain}`}
                data-testid="deployment-chain-badge"
              >
                Chain anchor: {truncateRef(deploymentQuery.data.chain, 10)}
              </span>
            )}
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              data-testid="live-tail-toggle"
              onClick={() => setLiveTailEnabled((v) => !v)}
              className={[
                "inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded border px-2.5 py-1 text-xs font-medium transition-colors",
                liveTailEnabled
                  ? "border-r5e-success/60 bg-r5e-success/15 text-r5e-success"
                  : "border-r5e-border bg-r5e-surface text-r5e-text/85 hover:text-r5e-text",
              ].join(" ")}
            >
              <Radio className="h-3.5 w-3.5" />
              <span>
                {liveTailEnabled
                  ? tail.status === "connected"
                    ? "Live tail"
                    : tail.status === "unavailable"
                      ? "Live tail unavailable"
                      : "Reconnecting…"
                  : "Live tail"}
              </span>
            </button>
          </div>
        }
      />

      <div className="flex min-h-0 flex-1 overflow-hidden">
        {/* Left filter sidebar */}
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

          {/* Record Kind facet */}
          <div>
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-text/80">
              Record Kind
            </h2>
            <div className="mt-2 flex flex-col gap-1">
              {kindFacetRows.map(([kindPath, count]) => {
                const active = explicitKind === kindPath;
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

            {!showOtherKindInput ? (
              <button
                type="button"
                data-testid="other-kind-toggle"
                onClick={() => setShowOtherKindInput(true)}
                className="mt-2 text-[11px] text-r5e-text/65 hover:text-r5e-text hover:underline"
              >
                Other kind…
              </button>
            ) : (
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
                  data-testid="custom-kind-input"
                  className="min-w-0 flex-1 rounded border border-r5e-border bg-r5e-bg px-2 py-1 font-mono text-[11px] text-r5e-text placeholder:text-r5e-text/50"
                />
                <button
                  type="submit"
                  className="rounded border border-r5e-border bg-r5e-bg px-2 py-1 text-[11px] font-medium text-r5e-text hover:border-r5e-accent"
                >
                  Go
                </button>
              </form>
            )}
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

          {/* Reason facet */}
          {reasonFacetRows.length > 0 && (
            <div>
              <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-text/80">
                Reason
              </h2>
              <div className="mt-2 flex flex-col gap-1">
                {reasonFacetRows.map(([reasonVal, count]) => {
                  const active = filter.reason === reasonVal;
                  return (
                    <button
                      key={reasonVal}
                      type="button"
                      data-testid={`filter-reason-${reasonVal.slice(0, 32)}`}
                      onClick={() =>
                        updateParam("reason", active ? null : reasonVal)
                      }
                      title={reasonVal}
                      className={[
                        "flex items-center justify-between gap-2 rounded px-2.5 py-1.5 text-left text-xs transition-colors",
                        active
                          ? "bg-r5e-accent/25 font-medium text-r5e-text"
                          : "text-r5e-text/85 hover:bg-r5e-bg hover:text-r5e-text",
                      ].join(" ")}
                    >
                      <span className="truncate text-[11px]">{reasonVal}</span>
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
                setSearchParams(
                  isAllRecordsView ? { view: "all" } : {},
                  { replace: true },
                );
              }}
              className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 text-xs font-medium text-r5e-text/90 hover:text-r5e-text"
            >
              Clear all filters
            </button>
          )}
        </aside>

        {/* Main content column */}
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
          {/* View toggle + KPI strip + search + Time toggle + Column Picker */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-r5e-border bg-r5e-bg px-5 py-3">
            <div
              className="flex flex-wrap items-center gap-2 text-xs"
              title={
                hasActiveFilter
                  ? "Counts for the current filtered view"
                  : isActivityView
                    ? "Counts for agent activity records"
                    : "Counts for all records"
              }
            >
              {/* Activity vs All records segmented toggle */}
              <div
                role="group"
                aria-label="Record view scope"
                data-testid="view-scope-toggle"
                className="inline-flex rounded border border-r5e-border bg-r5e-surface p-0.5"
              >
                <button
                  type="button"
                  data-testid="view-mode-activity"
                  onClick={() => selectViewMode("activity")}
                  className={[
                    "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                    isActivityView
                      ? "bg-r5e-accent/25 text-r5e-text"
                      : "text-r5e-text/75 hover:text-r5e-text",
                  ].join(" ")}
                >
                  Activity
                </button>
                <button
                  type="button"
                  data-testid="view-mode-all"
                  onClick={() => selectViewMode("all")}
                  className={[
                    "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                    isAllRecordsView
                      ? "bg-r5e-accent/25 text-r5e-text"
                      : "text-r5e-text/75 hover:text-r5e-text",
                  ].join(" ")}
                >
                  All records
                </button>
              </div>

              <StatChip
                label={hasActiveFilter ? "Matching" : "Records"}
                value={stats.total}
                testId="stat-total"
              />
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
                className="relative flex w-56 items-center"
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
                  placeholder="Search actor, tool, reason…"
                  data-testid="evidence-search-input"
                  className="w-full rounded border border-r5e-border bg-r5e-surface py-1.5 pl-8 pr-3 text-xs text-r5e-text placeholder:text-r5e-text/55"
                />
              </form>

              <div
                role="group"
                aria-label="Timestamp timezone"
                data-testid="time-mode-toggle"
                className="inline-flex rounded border border-r5e-border bg-r5e-surface p-0.5 text-[11px]"
              >
                <button
                  type="button"
                  data-testid="time-mode-local"
                  onClick={() => toggleTimeMode("local")}
                  className={[
                    "rounded px-2 py-1 font-medium transition-colors",
                    timeMode === "local"
                      ? "bg-r5e-accent/25 text-r5e-text"
                      : "text-r5e-text/70 hover:text-r5e-text",
                  ].join(" ")}
                >
                  Local
                </button>
                <button
                  type="button"
                  data-testid="time-mode-utc"
                  onClick={() => toggleTimeMode("utc")}
                  className={[
                    "rounded px-2 py-1 font-medium transition-colors",
                    timeMode === "utc"
                      ? "bg-r5e-accent/25 text-r5e-text"
                      : "text-r5e-text/70 hover:text-r5e-text",
                  ].join(" ")}
                >
                  UTC
                </button>
              </div>

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
            timeMode={timeMode}
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
                  title="Failed to load evidence records"
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
                    body="Adjust your view, kind, policy outcome, time range, or search filter."
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
                          title="Drag to reorder column; drag divider to resize; double-click divider to auto-fit"
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
                            onDoubleClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              autoFitColumn(colId);
                            }}
                            onClick={(e) => e.stopPropagation()}
                            className="group/resize absolute -right-1 top-0 z-10 flex h-full w-2.5 cursor-col-resize items-center justify-center"
                          >
                            <span className="h-4 w-px bg-r5e-border transition-all group-hover/resize:h-full group-hover/resize:w-0.5 group-hover/resize:bg-r5e-accent" />
                          </span>
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody className="divide-y divide-r5e-border/70">
                  {decodedRows.map(
                    ({ entry, payload, policy, outcome, target, reason }) => {
                      const fullActor = entry.actor ?? payload?.actor ?? "";
                      const actorDisplay = formatIdentityDisplay(fullActor);
                      const fullSession = entry.session ?? payload?.session ?? "";
                      const ts = formatTimestamp(entry.capturedAt, timeMode);
                      return (
                        <tr
                          key={entry.ref}
                          data-testid={`evidence-row-${shortKindName(entry.kind)}`}
                          onClick={() =>
                            navigate({
                              pathname: recordDetailPath(entry.ref),
                              search: location.search,
                            })
                          }
                          className="cursor-pointer transition-colors hover:bg-r5e-surface/90"
                        >
                          {visibleColumns.map((colId) => {
                            switch (colId) {
                              case "captured":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-r5e-text/85"
                                    title={ts.utc}
                                  >
                                    {ts.display}
                                  </td>
                                );
                              case "kind":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate whitespace-nowrap px-3 py-2.5"
                                    title={entry.kind}
                                  >
                                    <span className="rounded border border-r5e-border bg-r5e-surface px-2 py-0.5 font-mono text-[11px] text-r5e-text">
                                      {shortKindName(entry.kind)}
                                    </span>
                                  </td>
                                );
                              case "policy":
                                return (
                                  <td
                                    key={colId}
                                    className="whitespace-nowrap px-3 py-2.5"
                                    title={policy?.reason ?? outcome ?? undefined}
                                  >
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
                                    className="truncate px-3 py-2.5 font-mono text-xs text-r5e-text"
                                    title={target ?? undefined}
                                  >
                                    {target ?? (
                                      <span className="text-r5e-text/50">—</span>
                                    )}
                                  </td>
                                );
                              case "reason":
                                return (
                                  <td
                                    key={colId}
                                    className="truncate px-3 py-2.5 text-xs text-r5e-text/85"
                                    title={reason ?? undefined}
                                  >
                                    {reason ?? (
                                      <span className="text-r5e-text/50">—</span>
                                    )}
                                  </td>
                                );
                              case "actor":
                                return (
                                  <td
                                    key={colId}
                                    className="group/actor px-3 py-2.5 font-mono text-[11px] text-r5e-text/85"
                                    title={fullActor || undefined}
                                  >
                                    <div className="flex items-center gap-1">
                                      <span className="min-w-0 flex-1 truncate">
                                        {actorDisplay}
                                      </span>
                                      {fullActor && (
                                        <button
                                          type="button"
                                          aria-label={`Copy full actor identifier ${fullActor}`}
                                          title={
                                            copiedActorRef === entry.ref
                                              ? "Copied"
                                              : `Copy ${fullActor}`
                                          }
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            void navigator.clipboard?.writeText(fullActor);
                                            setCopiedActorRef(entry.ref);
                                            setTimeout(
                                              () =>
                                                setCopiedActorRef((cur) =>
                                                  cur === entry.ref ? null : cur,
                                                ),
                                              1_200,
                                            );
                                          }}
                                          className="shrink-0 rounded p-0.5 text-r5e-text/50 opacity-0 transition-opacity hover:bg-r5e-bg hover:text-r5e-text group-hover/actor:opacity-100"
                                        >
                                          {copiedActorRef === entry.ref ? (
                                            <Check className="h-3 w-3 text-r5e-success" />
                                          ) : (
                                            <Copy className="h-3 w-3" />
                                          )}
                                        </button>
                                      )}
                                    </div>
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
        </main>
      </div>

      {/* RecordDetail slide-over drawer */}
      <Outlet />
    </div>
  );
}

function OutcomePill({
  outcome,
  reason,
}: {
  outcome: PolicyOutcome;
  reason?: string | null;
}): JSX.Element {
  return (
    <span title={reason ?? undefined}>
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
