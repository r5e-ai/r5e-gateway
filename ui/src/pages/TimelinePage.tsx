// TimelinePage — Provenance v2 Session & Actor Investigation Timeline (`/admin/timeline`).
//
// Reads `GET /v1/evidence/sessions/:session_id` when `?session=` is set, or
// `GET /v1/evidence/records` grouped by session/stream otherwise.

import { useMemo } from "react";
import { Outlet, useNavigate, useSearchParams } from "react-router-dom";

import { ExportBundleButton } from "~/components/evidence/ExportBundleButton";
import { Pill } from "~/components/shared/Pill";
import { TopBar } from "~/components/shared/TopBar";
import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
import { useSessionEvidence } from "~/hooks/useEvidenceRecord";
import { useEvidenceRecords } from "~/hooks/useEvidenceRecords";
import {
  decodeEvidencePayload,
  policyOutcomeOf,
  shortKindName,
  targetDisplayOf,
  truncateRef,
  type EvidenceRecordEntry,
} from "~/lib/evidenceTypes";
import { timelineRecordDetailPath } from "~/lib/routes";

export default function TimelinePage(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const sessionParam = searchParams.get("session") || undefined;
  const actorParam = searchParams.get("actor") || undefined;

  const sessionQuery = useSessionEvidence(sessionParam);
  const listQuery = useEvidenceRecords(
    { actor: actorParam },
    { enabled: !sessionParam },
  );

  const records: EvidenceRecordEntry[] = useMemo(() => {
    if (sessionParam) return sessionQuery.data?.records ?? [];
    return listQuery.data?.pages.flatMap((p) => p.records) ?? [];
  }, [sessionParam, sessionQuery.data, listQuery.data]);

  const groups = useMemo(() => {
    const map = new Map<string, EvidenceRecordEntry[]>();
    for (const r of records) {
      const payload = decodeEvidencePayload(r.envelope);
      const key = payload?.session ?? r.stream;
      const list = map.get(key) ?? [];
      list.push(r);
      map.set(key, list);
    }
    return Array.from(map.entries()).map(([groupKey, items]) => ({
      groupKey,
      items: items.slice().sort((a, b) => a.seq - b.seq),
    }));
  }, [records]);

  const isLoading = sessionParam ? sessionQuery.isLoading : listQuery.isLoading;
  const error = sessionParam ? sessionQuery.error : listQuery.error;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar
        pageContent={
          <div className="flex items-center gap-3">
            <h1 className="text-sm font-semibold text-r5e-text">
              Investigation Timeline
            </h1>
            {sessionParam && (
              <span className="inline-flex items-center gap-2 rounded-full border border-r5e-border bg-r5e-surface px-2.5 py-0.5 font-mono text-[11px] text-r5e-muted">
                session: {sessionParam}
                <button
                  type="button"
                  onClick={() => setSearchParams({}, { replace: true })}
                  className="text-r5e-accent hover:underline"
                >
                  clear
                </button>
              </span>
            )}
          </div>
        }
        actions={
          sessionParam ? (
            <ExportBundleButton session={sessionParam} label="Export session bundle" />
          ) : undefined
        }
      />

      <main className="min-h-0 flex-1 overflow-y-auto p-5">
        {isLoading && <Skeleton.Rows rows={6} />}

        {error && (
          <ErrorState
            title="Failed to load timeline evidence"
            detail={error.message}
            retry={{ onClick: () => void (sessionParam ? sessionQuery.refetch() : listQuery.refetch()) }}
          />
        )}

        {!isLoading && !error && groups.length === 0 && (
          <EmptyState
            title="No timeline events"
            body="No Provenance v2 records matched this timeline scope."
          />
        )}

        <div className="flex flex-col gap-6" data-testid="timeline-groups">
          {groups.map(({ groupKey, items }) => (
            <section
              key={groupKey}
              className="rounded-lg border border-r5e-border bg-r5e-surface p-4"
            >
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-r5e-border pb-2">
                <div className="font-mono text-xs font-semibold text-r5e-text break-all">
                  {groupKey}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-r5e-muted">
                    {items.length} records
                  </span>
                  {groupKey.startsWith("urn:r5e:session:") && !sessionParam && (
                    <button
                      type="button"
                      onClick={() =>
                        setSearchParams({ session: groupKey }, { replace: true })
                      }
                      className="text-xs text-r5e-accent hover:underline"
                    >
                      Focus session
                    </button>
                  )}
                </div>
              </div>

              <ol className="relative ml-2 border-l border-r5e-border pl-4">
                {items.map((entry) => {
                  const payload = decodeEvidencePayload(entry.envelope);
                  const outcome = policyOutcomeOf(payload);
                  return (
                    <li
                      key={entry.ref}
                      onClick={() => navigate(timelineRecordDetailPath(entry.ref))}
                      className="mb-3 cursor-pointer rounded border border-r5e-border/70 bg-r5e-bg p-3 transition-colors last:mb-0 hover:border-r5e-accent/60"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[11px] text-r5e-muted">
                            #{entry.seq}
                          </span>
                          <span className="font-mono font-medium text-r5e-text">
                            {shortKindName(entry.kind)}
                          </span>
                          {outcome && (
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
                          )}
                          <span className="font-mono text-r5e-muted">
                            {targetDisplayOf(payload)}
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-r5e-accent">
                          {truncateRef(entry.ref, 10)}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-3 font-mono text-[11px] text-r5e-muted">
                        <span>{entry.capturedAt}</span>
                        <span>actor: {payload?.actor ?? "—"}</span>
                      </div>
                    </li>
                  );
                })}
              </ol>
            </section>
          ))}
        </div>
      </main>

      <Outlet />
    </div>
  );
}
