// Dashboard — Provenance v2 Policy Checks & Evidence Table (`/admin/dashboard`).
//
// Provenance v2 Evidence Dashboard contract:
//   - Reads `GET /v1/evidence/records` returning `{ref, stream, seq, kind, capturedAt, actor, session, envelope}`
//   - Decodes signed `envelope.payload` client-side (no `index_meta` or `sealed` in list rows)
//   - Server-side filters: full `kind` path, `session`, `actor`, `since`, `until`
//   - Client-side filters over loaded rows: `policyOutcome` (`allow | deny | error`) and text search `q`

import { Radio, Search, ShieldCheck, ShieldX } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { Outlet, useNavigate, useSearchParams } from "react-router-dom";

import { BulkActionBar } from "~/components/evidence/BulkActionBar";
import { Pill } from "~/components/shared/Pill";
import { TopBar } from "~/components/shared/TopBar";
import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
import { useAuth } from "~/hooks/useAuth";
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
  decodeEvidencePayload,
  policyEvaluationOf,
  policyOutcomeOf,
  shortKindName,
  targetDisplayOf,
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

  // Server-side Phase 1 filters
  const serverFilter: EvidenceFilter = useMemo(
    () => ({
      kind: searchParams.get("kind") || undefined,
      actor: searchParams.get("actor") || undefined,
      session: searchParams.get("session") || undefined,
    }),
    [searchParams],
  );

  // Client-side Phase 1 filters over loaded rows
  const outcomeFilter = useMemo<PolicyOutcome | undefined>(() => {
    const v = searchParams.get("policyOutcome");
    return v === "allow" || v === "deny" || v === "error" ? v : undefined;
  }, [searchParams]);
  const qFilter = (searchParams.get("q") ?? "").trim().toLowerCase();

  const deploymentQuery = useDeployment();
  const recordsQuery = useEvidenceRecords(serverFilter);
  const refetchOnTailOpen = useCallback(() => {
    void recordsQuery.refetch();
  }, [recordsQuery]);

  const tail = useEvidenceTail(
    liveTailEnabled,
    {
      kind: serverFilter.kind,
      session: serverFilter.session,
      actor: serverFilter.actor,
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

  const allDecoded = useMemo(
    () =>
      rawRows.map((entry) => {
        const payload = decodeEvidencePayload(entry.envelope);
        const policy = policyEvaluationOf(payload);
        const outcome = policyOutcomeOf(payload);
        return { entry, payload, policy, outcome };
      }),
    [rawRows],
  );

  const decodedRows = useMemo(() => {
    return allDecoded.filter(({ entry, payload, policy, outcome }) => {
      if (outcomeFilter && outcome !== outcomeFilter) return false;
      if (qFilter) {
        const hay = [
          entry.ref,
          entry.kind,
          entry.actor ?? payload?.actor ?? "",
          targetDisplayOf(payload),
          policy?.reason ?? "",
        ]
          .join(" ")
          .toLowerCase();
        if (!hay.includes(qFilter)) return false;
      }
      return true;
    });
  }, [allDecoded, outcomeFilter, qFilter]);

  const kindCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const { entry } of allDecoded) {
      counts.set(entry.kind, (counts.get(entry.kind) ?? 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [allDecoded]);

  const outcomeCounts = useMemo(() => {
    const counts: Record<PolicyOutcome, number> = { allow: 0, deny: 0, error: 0 };
    for (const r of allDecoded) {
      if (r.outcome) counts[r.outcome]++;
    }
    return counts;
  }, [allDecoded]);

  const stats = useMemo(() => {
    let allowed = 0;
    let denied = 0;
    for (const r of decodedRows) {
      if (r.outcome === "allow") allowed++;
      if (r.outcome === "deny" || r.outcome === "error") denied++;
    }
    return {
      total: decodedRows.length,
      policyChecks: allowed + denied,
      allowed,
      denied,
    };
  }, [decodedRows]);

  const firstSelectedSession = useMemo(() => {
    const first = selectedRefs[0];
    if (!first) return null;
    const found = allDecoded.find((r) => r.entry.ref === first);
    return found?.entry.session ?? found?.payload?.session ?? null;
  }, [selectedRefs, allDecoded]);

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

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar
        pageContent={
          <div className="flex min-w-0 items-center gap-3">
            <h1 className="text-sm font-semibold text-r5e-text">
              Policy Checks &amp; Evidence
            </h1>
            {deploymentQuery.data?.chain && (
              <span
                data-testid="deployment-chain-badge"
                className="hidden items-center gap-1.5 rounded-full border border-r5e-border bg-r5e-surface px-2.5 py-0.5 font-mono text-[11px] text-r5e-muted md:inline-flex"
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
                className="text-[11px] text-r5e-warning"
              >
                {tail.statusDetail}
              </span>
            )}
            <button
              type="button"
              data-testid="live-tail-toggle"
              onClick={() => setLiveTailEnabled((v) => !v)}
              className={[
                "inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-xs transition-colors",
                tail.status === "connected"
                  ? "border-r5e-success/50 bg-r5e-success/15 text-r5e-success"
                  : liveTailEnabled
                    ? "border-r5e-warning/50 bg-r5e-warning/10 text-r5e-warning"
                    : "border-r5e-border bg-r5e-surface text-r5e-muted hover:text-r5e-text",
              ].join(" ")}
            >
              <Radio className="h-3.5 w-3.5" aria-hidden="true" />
              <span>
                {tail.status === "connected"
                  ? "Live tail: on"
                  : tail.status === "connecting"
                    ? "Live tail: connecting…"
                    : tail.status === "not_capturing"
                      ? "Live tail: not capturing"
                      : liveTailEnabled
                        ? "Live tail: unavailable"
                        : "Live tail"}
              </span>
            </button>
          </div>
        }
      />

      <div className="flex min-h-0 flex-1 overflow-hidden">
        {/* Left filter rail */}
        <aside
          aria-label="Evidence filters"
          className="flex w-[240px] shrink-0 flex-col gap-5 overflow-y-auto border-r border-r5e-border bg-r5e-surface/50 p-4"
        >
          {/* Client-side Policy Outcome filter */}
          <div>
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-muted">
              Policy outcome (in loaded rows)
            </h2>
            <div className="mt-2 flex flex-col gap-1">
              {(["allow", "deny", "error"] as const).map((outcome) => {
                const active = outcomeFilter === outcome;
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
                        ? "bg-r5e-accent/15 text-r5e-text"
                        : "text-r5e-muted hover:bg-r5e-bg hover:text-r5e-text",
                    ].join(" ")}
                  >
                    <span className="capitalize">{outcome}</span>
                    <span className="font-mono text-[11px]">
                      {outcomeCounts[outcome]}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Open-string full kind path filter */}
          <div>
            <h2 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-muted">
              Record Kind (open string)
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
                className="min-w-0 flex-1 rounded border border-r5e-border bg-r5e-bg px-2 py-1 font-mono text-[11px] text-r5e-text placeholder:text-r5e-muted"
              />
              <button
                type="submit"
                className="rounded border border-r5e-border bg-r5e-surface px-2 py-1 text-[11px] text-r5e-text hover:bg-r5e-bg"
              >
                Go
              </button>
            </form>
            <div className="mt-2 flex flex-col gap-1">
              {kindCounts.map(([kindPath, count]) => {
                const active = serverFilter.kind === kindPath;
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
                        ? "bg-r5e-accent/15 text-r5e-text"
                        : "text-r5e-muted hover:bg-r5e-bg hover:text-r5e-text",
                    ].join(" ")}
                  >
                    <span className="truncate font-mono text-[11px]">
                      {shortKindName(kindPath)}
                    </span>
                    <span className="shrink-0 font-mono text-[11px]">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {(serverFilter.kind || outcomeFilter || qFilter || serverFilter.session || serverFilter.actor) && (
            <button
              type="button"
              data-testid="clear-filters-btn"
              onClick={() => {
                setCustomKindInput("");
                setSearchInput("");
                setSearchParams({}, { replace: true });
              }}
              className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 text-xs text-r5e-muted hover:text-r5e-text"
            >
              Clear all filters
            </button>
          )}
        </aside>

        {/* Main content column */}
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-r5e-border bg-r5e-bg px-5 py-3">
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <StatChip label="Records" value={stats.total} />
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

            <form
              className="relative flex w-full max-w-xs items-center"
              onSubmit={(e) => {
                e.preventDefault();
                updateParam("q", searchInput.trim() || null);
              }}
            >
              <Search className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-r5e-muted" />
              <input
                type="search"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Search loaded rows (ref, actor, tool)…"
                data-testid="evidence-search-input"
                className="w-full rounded border border-r5e-border bg-r5e-surface py-1.5 pl-8 pr-3 text-xs text-r5e-text placeholder:text-r5e-muted"
              />
            </form>
          </div>

          <div className="min-h-0 flex-1 overflow-auto">
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
                    body="Adjust your kind, policy outcome, or search filter."
                  />
                </div>
              )}

            {decodedRows.length > 0 && (
              <table
                data-testid="evidence-table"
                className="w-full border-collapse text-left text-xs"
              >
                <thead className="sticky top-0 z-10 border-b border-r5e-border bg-r5e-surface text-[11px] uppercase tracking-wider text-r5e-muted">
                  <tr>
                    <th className="w-9 px-3 py-2.5">
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
                    <th className="px-3 py-2.5">Captured</th>
                    <th className="px-3 py-2.5">Kind</th>
                    <th className="px-3 py-2.5">Policy</th>
                    <th className="px-3 py-2.5">Target / Tool</th>
                    <th className="px-3 py-2.5">Actor</th>
                    <th className="px-3 py-2.5">Record Ref</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-r5e-border/70">
                  {decodedRows.map(({ entry, payload, policy, outcome }) => {
                    const checked = selectedRefs.includes(entry.ref);
                    return (
                      <tr
                        key={entry.ref}
                        data-testid={`evidence-row-${shortKindName(entry.kind)}`}
                        onClick={() => navigate(recordDetailPath(entry.ref))}
                        className="cursor-pointer transition-colors hover:bg-r5e-surface/80"
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
                        <td className="whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-r5e-muted">
                          {formatShortTime(entry.capturedAt)}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5">
                          <span
                            className="rounded border border-r5e-border bg-r5e-surface px-2 py-0.5 font-mono text-[11px] text-r5e-text"
                            title={entry.kind}
                          >
                            {shortKindName(entry.kind)}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5">
                          {outcome ? (
                            <OutcomePill outcome={outcome} reason={policy?.reason} />
                          ) : (
                            <span className="text-r5e-muted">—</span>
                          )}
                        </td>
                        <td className="max-w-[220px] truncate px-3 py-2.5 font-mono text-r5e-text">
                          {targetDisplayOf(payload)}
                        </td>
                        <td className="max-w-[200px] truncate px-3 py-2.5 font-mono text-[11px] text-r5e-muted">
                          {entry.actor ?? payload?.actor ?? "—"}
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5 font-mono text-[11px] text-r5e-accent">
                          {truncateRef(entry.ref, 10)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}

            {recordsQuery.hasNextPage && (
              <div className="flex justify-center p-4">
                <button
                  type="button"
                  onClick={() => recordsQuery.fetchNextPage()}
                  disabled={recordsQuery.isFetchingNextPage}
                  className="rounded border border-r5e-border bg-r5e-surface px-4 py-1.5 text-xs text-r5e-text hover:bg-r5e-bg disabled:opacity-50"
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
}: {
  label: string;
  value: number;
  tone?: "success" | "danger";
  icon?: JSX.Element;
}): JSX.Element {
  return (
    <div className="inline-flex items-center gap-1.5 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1">
      {icon}
      <span className="text-r5e-muted">{label}:</span>
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
