// RecordDetail — Provenance v2 Record Inspector drawer (`/admin/*/records/:ref`).
//
// Provenance v2 Record Inspector contract:
//   - Content fetch uses `GET /v1/evidence/records/:ref/content/:bytes_ref`
//   - Export & Verify operate on the record's session bundle (`POST /v1/evidence/export`
//     with `{session, content: true}` -> `POST /v1/evidence/verify` with client-pinned `trustedChain`)
//   - Optional `sealRef` shown on detail when present

import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, HelpCircle, ShieldAlert, X, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  ExportBundleButton,
  fetchEvidenceBundle,
} from "~/components/evidence/ExportBundleButton";
import { Pill } from "~/components/shared/Pill";
import { ErrorState, Skeleton } from "~/components/shared/states";
import { useAuth } from "~/hooks/useAuth";
import { useEvidenceRecord } from "~/hooks/useEvidenceRecord";
import { ApiError, api } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import {
  DEFAULT_TRUSTED_CHAIN,
  contentRefOf,
  decodeEvidencePayload,
  policyEvaluationOf,
  shortKindName,
  truncateRef,
  type VerifyFinding,
  type VerifyReportV2,
} from "~/lib/evidenceTypes";
import { routes, stripBasename, timelinePath } from "~/lib/routes";

type TabKey = "identity" | "body" | "policy" | "proof" | "content" | "verify";

const TABS: ReadonlyArray<{ key: TabKey; label: string }> = [
  { key: "identity", label: "Identity" },
  { key: "body", label: "Body" },
  { key: "policy", label: "Policy" },
  { key: "proof", label: "Proof" },
  { key: "content", label: "Content" },
  { key: "verify", label: "Verify" },
];

export default function RecordDetail(): JSX.Element {
  const { ref } = useParams<{ ref: string }>();
  const decodedRef = ref ? decodeURIComponent(ref) : undefined;
  const navigate = useNavigate();
  const auth = useAuth();
  const principal = auth.status === "authenticated" ? auth.principal : "operator";

  const [activeTab, setActiveTab] = useState<TabKey>("identity");
  const [trustedChain, setTrustedChain] = useState<string>(DEFAULT_TRUSTED_CHAIN);
  const [blobContent, setBlobContent] = useState<string | null>(null);
  const [blobDisposed, setBlobDisposed] = useState<boolean>(false);

  const query = useEvidenceRecord(decodedRef);
  const entry = query.data;
  const payload = useMemo(
    () => (entry ? decodeEvidencePayload(entry.envelope) : null),
    [entry],
  );
  const policyEval = useMemo(() => policyEvaluationOf(payload), [payload]);
  const contentRef = useMemo(() => contentRefOf(payload), [payload]);
  const contentMediaType = useMemo(() => {
    const mt = payload?.body?.mediaType;
    return typeof mt === "string" && mt.length > 0 ? mt : "application/octet-stream";
  }, [payload]);
  const sessionUrn = entry?.session ?? payload?.session ?? null;

  const blobMutation = useMutation<string, Error, { recordRef: string; bytesRef: string }>({
    mutationFn: async ({ recordRef, bytesRef }) => {
      const resp = await fetch(
        apiPaths.evidence.recordContent(recordRef, bytesRef),
        { credentials: "include" },
      );
      if (resp.status === 404) {
        throw new ApiError({
          error: "ERR_NOT_FOUND",
          error_description: "Content blob not found.",
          correlation_id: "unknown",
          attested_run_id: null,
          status: 404,
        });
      }
      if (resp.status === 410) {
        setBlobDisposed(true);
        throw new ApiError({
          error: "ERR_CONTENT_DISPOSED",
          error_description: "Content blob was erased via PayloadDisposition.",
          correlation_id: "unknown",
          attested_run_id: null,
          status: 410,
        });
      }
      if (resp.status === 503) {
        throw new ApiError({
          error: "ERR_UNAVAILABLE",
          error_description: "Content store is temporarily unavailable. Retry shortly.",
          correlation_id: "unknown",
          attested_run_id: null,
          status: 503,
        });
      }
      if (!resp.ok) {
        throw new Error(`Failed to fetch content blob (HTTP ${resp.status})`);
      }
      const text = await resp.text();
      if (contentMediaType.includes("json")) {
        try {
          return JSON.stringify(JSON.parse(text), null, 2);
        } catch {
          return text;
        }
      }
      try {
        return JSON.stringify(JSON.parse(text), null, 2);
      } catch {
        return text;
      }
    },
    onSuccess: (text) => {
      setBlobDisposed(false);
      setBlobContent(text);
    },
  });

  const verifyMutation = useMutation<VerifyReportV2, Error, void>({
    mutationFn: async () => {
      if (!sessionUrn) {
        throw new Error("Session export is required for full bundle verification.");
      }
      const bundle = await fetchEvidenceBundle({ session: sessionUrn, content: true });
      const body: Record<string, unknown> = { bundle };
      if (trustedChain.trim()) {
        body.trustedChain = trustedChain.trim();
      }
      return api.post<VerifyReportV2>(apiPaths.evidence.verify, body);
    },
  });

  function close(): void {
    navigate("..");
  }

  return (
    <aside
      data-testid="record-detail-drawer"
      aria-label="Evidence record detail"
      className="fixed inset-y-0 right-0 z-30 flex w-full max-w-[740px] flex-col border-l border-r5e-border bg-r5e-bg shadow-2xl"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3 border-b border-r5e-border bg-r5e-surface px-5 py-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-semibold text-r5e-text">
              {entry ? shortKindName(entry.kind) : "Evidence Record"}
            </span>
            {policyEval && (
              <Pill
                tone={
                  policyEval.outcome === "allow"
                    ? "success"
                    : policyEval.outcome === "deny"
                      ? "danger"
                      : "warning"
                }
                testId="detail-policy-outcome"
              >
                {policyEval.outcome}
              </Pill>
            )}
            {entry?.sealRef && <Pill tone="accent">sealed</Pill>}
          </div>
          <p
            className="mt-1 truncate font-mono text-xs text-r5e-muted"
            title={decodedRef}
            data-testid="detail-record-ref"
          >
            {decodedRef}
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <ExportBundleButton session={sessionUrn} label="Export v2 bundle" />
          <button
            type="button"
            onClick={close}
            aria-label="Close record drawer"
            data-testid="close-drawer-btn"
            className="rounded p-1.5 text-r5e-muted hover:bg-r5e-bg hover:text-r5e-text"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Tab strip */}
      <nav
        aria-label="Record inspector tabs"
        className="flex gap-1 border-b border-r5e-border bg-r5e-surface/60 px-5 pt-2"
      >
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            data-testid={`detail-tab-${t.key}`}
            onClick={() => setActiveTab(t.key)}
            className={[
              "border-b-2 px-3 py-2 text-xs font-medium transition-colors",
              activeTab === t.key
                ? "border-r5e-accent text-r5e-text"
                : "border-transparent text-r5e-muted hover:text-r5e-text",
            ].join(" ")}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5">
        {query.isLoading && <Skeleton.Rows rows={6} />}

        {query.isError && (
          <ErrorState
            title="Failed to load evidence record"
            detail={query.error.message}
            retry={{ onClick: () => void query.refetch() }}
          />
        )}

        {entry && payload && activeTab === "identity" && (
          <div className="flex flex-col gap-4" data-testid="tab-panel-identity">
            <dl className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-2">
              <Field label="Record Ref" value={entry.ref} mono full />
              <Field label="Kind Path" value={entry.kind} mono full />
              <Field label="API Version" value={payload.apiVersion} mono />
              <Field label="Captured At" value={payload.capturedAt} mono />
              <Field label="Stream" value={entry.stream} mono full />
              <Field label="Sequence" value={String(entry.seq)} mono />
              <Field
                label="Previous"
                value={payload.previous ?? "null (stream start)"}
                mono
              />
              <Field label="Actor" value={payload.actor} mono full />
              {payload.onBehalfOf && (
                <Field label="On Behalf Of" value={payload.onBehalfOf} mono full />
              )}
              {sessionUrn && (
                <div className="sm:col-span-2">
                  <dt className="text-[11px] uppercase tracking-wider text-r5e-muted">
                    Session
                  </dt>
                  <dd className="mt-0.5 flex items-center gap-2 font-mono text-xs text-r5e-text">
                    <span className="break-all">{sessionUrn}</span>
                    <Link
                      to={timelinePath({ session: sessionUrn })}
                      className="shrink-0 text-r5e-accent hover:underline"
                    >
                      View timeline →
                    </Link>
                  </dd>
                </div>
              )}
              <Field label="Issuer Key" value={payload.issuer} mono full />
              <Field label="Schema Ref" value={payload.schemaRef} mono full />
              <Field label="Profile Ref" value={payload.profileRef} mono full />
            </dl>
          </div>
        )}

        {entry && payload && activeTab === "body" && (
          <div className="flex flex-col gap-3" data-testid="tab-panel-body">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
              Provenance v2 Body ({shortKindName(entry.kind)})
            </h3>
            <pre className="overflow-x-auto rounded border border-r5e-border bg-r5e-surface p-3 font-mono text-xs text-r5e-text">
              {JSON.stringify(payload.body, null, 2)}
            </pre>
          </div>
        )}

        {entry && payload && activeTab === "policy" && (
          <div className="flex flex-col gap-4" data-testid="tab-panel-policy">
            {policyEval ? (
              <>
                <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-r5e-border bg-r5e-surface p-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-r5e-muted">Recorded Outcome:</span>
                    <Pill
                      tone={
                        policyEval.outcome === "allow"
                          ? "success"
                          : policyEval.outcome === "deny"
                            ? "danger"
                            : "warning"
                      }
                    >
                      {policyEval.outcome}
                    </Pill>
                  </div>
                  <div className="flex items-center gap-2">
                    <Link
                      to={`${stripBasename(routes.policySimulator)}?mode=replay&ref=${encodeURIComponent(entry.ref)}`}
                      data-testid="detail-replay-link"
                      className="rounded border border-r5e-accent bg-r5e-accent/15 px-2.5 py-1 text-xs text-r5e-accent hover:bg-r5e-accent/25"
                    >
                      Replay in Simulator
                    </Link>
                    <Link
                      to={`${stripBasename(routes.policySimulator)}?mode=draft&ref=${encodeURIComponent(entry.ref)}`}
                      data-testid="detail-draft-link"
                      className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1 text-xs text-r5e-text hover:bg-r5e-surface"
                    >
                      Draft policy from record
                    </Link>
                  </div>
                </div>

                <dl className="grid grid-cols-1 gap-2.5 text-xs">
                  <Field label="Policy Ref" value={policyEval.policyRef} mono full />
                  {policyEval.reason && (
                    <Field label="Reason" value={policyEval.reason} full />
                  )}
                  {policyEval.evaluatorRef && (
                    <Field label="Evaluator Ref" value={policyEval.evaluatorRef} mono full />
                  )}
                  {policyEval.activationRef && (
                    <Field label="Activation Ref" value={policyEval.activationRef} mono full />
                  )}
                  {policyEval.decisionRef && (
                    <Field label="Decision Ref" value={policyEval.decisionRef} mono full />
                  )}
                  <div>
                    <dt className="text-[11px] uppercase tracking-wider text-r5e-muted">
                      Input Refs ({policyEval.inputRefs.length})
                    </dt>
                    <dd className="mt-1 flex flex-col gap-1 font-mono text-xs text-r5e-text">
                      {policyEval.inputRefs.map((r) => (
                        <span key={r} className="break-all">
                          {r}
                        </span>
                      ))}
                    </dd>
                  </div>
                </dl>
              </>
            ) : (
              <p className="text-xs text-r5e-muted">
                This {shortKindName(entry.kind)} record does not carry an inline policy
                evaluation.
              </p>
            )}
          </div>
        )}

        {entry && payload && activeTab === "proof" && (
          <div className="flex flex-col gap-4" data-testid="tab-panel-proof">
            <dl className="grid grid-cols-1 gap-2.5 text-xs">
              <Field label="DSSE Payload Type" value={entry.envelope.payloadType} mono full />
              <Field
                label="Stream Hash Chain"
                value={`${payload.previous ? truncateRef(payload.previous, 10) : "GENESIS"} → ${truncateRef(entry.ref, 10)} (seq ${entry.seq})`}
                mono
                full
              />
              {entry.sealRef && (
                <Field label="Epoch Seal Ref" value={entry.sealRef} mono full />
              )}
            </dl>

            <div>
              <h3 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-muted">
                DSSE Signatures ({entry.envelope.signatures.length})
              </h3>
              <div className="mt-1.5 flex flex-col gap-2">
                {entry.envelope.signatures.map((s) => (
                  <div
                    key={s.keyid}
                    className="rounded border border-r5e-border bg-r5e-surface p-3 font-mono text-xs"
                  >
                    <div className="break-all text-r5e-text">{s.keyid}</div>
                    <div className="mt-1 truncate text-[11px] text-r5e-muted">
                      sig: {s.sig}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {entry && payload && activeTab === "content" && (
          <div className="flex flex-col gap-3" data-testid="tab-panel-content">
            {!contentRef ? (
              <div className="rounded border border-r5e-border bg-r5e-surface p-3 text-xs text-r5e-muted">
                This record has no external <code className="font-mono">contentRef</code>{" "}
                blob. All fields are inside the signed Provenance v2 body.
              </div>
            ) : (
              <>
                <div className="rounded border border-r5e-border bg-r5e-surface p-3 text-xs">
                  <p className="text-r5e-text">
                    Fetching content as <span className="font-mono">{principal}</span> via{" "}
                    <code className="font-mono">
                      GET /v1/evidence/records/:ref/content/:bytes_ref
                    </code>{" "}
                    (Cedar <code className="font-mono">ReadPayload</code> gated).
                  </p>
                  <p className="mt-1 break-all font-mono text-[11px] text-r5e-muted">
                    contentRef: {contentRef} • mediaType: {contentMediaType}
                  </p>
                  <button
                    type="button"
                    data-testid="fetch-content-btn"
                    onClick={() =>
                      blobMutation.mutate({ recordRef: entry.ref, bytesRef: contentRef })
                    }
                    disabled={blobMutation.isPending}
                    className="mt-2.5 rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs text-r5e-accent hover:bg-r5e-accent/25 disabled:opacity-50"
                  >
                    {blobMutation.isPending ? "Fetching content…" : "Fetch content blob"}
                  </button>
                </div>

                {blobDisposed && (
                  <div
                    role="note"
                    data-testid="content-disposed-banner"
                    className="rounded border border-r5e-warning/40 bg-r5e-warning/10 p-3 text-xs text-r5e-warning"
                  >
                    Content blob was erased via{" "}
                    <code className="font-mono">PayloadDisposition</code> (HTTP 410). The
                    signed Provenance v2 envelope remains verifiable offline.
                  </div>
                )}

                {blobMutation.isError && !blobDisposed && (
                  <div
                    role="alert"
                    className="rounded border border-r5e-danger/40 bg-r5e-danger/10 p-3 text-xs text-r5e-danger"
                  >
                    {blobMutation.error.message}
                  </div>
                )}

                {blobContent !== null && (
                  <pre
                    data-testid="content-blob-json"
                    className="overflow-x-auto rounded border border-r5e-border bg-r5e-surface p-3 font-mono text-xs text-r5e-text"
                  >
                    {blobContent}
                  </pre>
                )}
              </>
            )}
          </div>
        )}

        {entry && payload && activeTab === "verify" && (
          <div className="flex flex-col gap-4" data-testid="tab-panel-verify">
            <div className="flex flex-col gap-2 rounded border border-r5e-border bg-r5e-surface p-3 text-xs">
              <label
                htmlFor="trusted-chain-input"
                className="text-[11px] font-semibold uppercase tracking-wider text-r5e-muted"
              >
                Pinned Trusted Chain Anchor (client config)
              </label>
              <input
                id="trusted-chain-input"
                type="text"
                value={trustedChain}
                onChange={(e) => setTrustedChain(e.target.value)}
                className="w-full rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-xs text-r5e-text"
              />
              <div className="flex items-center justify-between gap-2 pt-1">
                <span className="text-[11px] text-r5e-muted">
                  Exports this session&apos;s{" "}
                  <code className="font-mono">r5e.provenance-export/v2</code> bundle and
                  runs 3-layer verification.
                </span>
                <button
                  type="button"
                  data-testid="run-verify-btn"
                  onClick={() => verifyMutation.mutate()}
                  disabled={verifyMutation.isPending || !sessionUrn}
                  className="rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs font-medium text-r5e-accent hover:bg-r5e-accent/25 disabled:opacity-50"
                >
                  {verifyMutation.isPending ? "Verifying…" : "Verify v2 bundle"}
                </button>
              </div>
            </div>

            {verifyMutation.isError && (
              <div
                role="alert"
                className="rounded border border-r5e-danger/40 bg-r5e-danger/10 p-3 text-xs text-r5e-danger"
              >
                {verifyMutation.error.message}
              </div>
            )}

            {verifyMutation.data && <VerifyReportView report={verifyMutation.data} />}
          </div>
        )}
      </div>
    </aside>
  );
}

function Field({
  label,
  value,
  mono,
  full,
}: {
  label: string;
  value: string;
  mono?: boolean;
  full?: boolean;
}): JSX.Element {
  return (
    <div className={full ? "sm:col-span-2" : ""}>
      <dt className="text-[11px] uppercase tracking-wider text-r5e-muted">{label}</dt>
      <dd
        className={[
          "mt-0.5 break-all text-xs text-r5e-text",
          mono ? "font-mono" : "",
        ].join(" ")}
      >
        {value}
      </dd>
    </div>
  );
}

const LAYER_LABELS: Record<1 | 2 | 3, string> = {
  1: "Layer 1 — Identity & Signature",
  2: "Layer 2 — Definition, Profile, Stream & Content",
  3: "Layer 3 — Epoch Seal & Membership Proof",
};

function VerifyReportView({ report }: { report: VerifyReportV2 }): JSX.Element {
  const byLayer: Record<1 | 2 | 3, VerifyFinding[]> = { 1: [], 2: [], 3: [] };
  for (const f of report.findings) {
    byLayer[f.layer]?.push(f);
  }

  return (
    <div className="flex flex-col gap-3" data-testid="verify-report">
      <div className="flex flex-wrap items-center gap-2">
        <Pill tone="success" testId="verify-ok-count">
          ok: {report.summary.ok}
        </Pill>
        <Pill
          tone={report.summary.failed > 0 ? "danger" : "muted"}
          testId="verify-failed-count"
        >
          failed: {report.summary.failed}
        </Pill>
        <Pill
          tone={report.summary.incomplete > 0 ? "warning" : "muted"}
          testId="verify-incomplete-count"
        >
          incomplete: {report.summary.incomplete}
        </Pill>
      </div>

      {([1, 2, 3] as const).map((layer) => (
        <div
          key={layer}
          className="rounded border border-r5e-border bg-r5e-surface p-3"
        >
          <h4 className="text-[11px] font-semibold uppercase tracking-wider text-r5e-muted">
            {LAYER_LABELS[layer]} ({byLayer[layer].length})
          </h4>
          {byLayer[layer].length === 0 ? (
            <p className="mt-1.5 text-xs text-r5e-muted">No findings for this layer.</p>
          ) : (
            <ul className="mt-2 max-h-60 divide-y divide-r5e-border/60 overflow-y-auto">
              {byLayer[layer].slice(0, 40).map((f, idx) => (
                <li
                  key={`${f.subject}-${f.check}-${idx}`}
                  className="flex items-start justify-between gap-2 py-1.5 text-xs"
                >
                  <div className="flex min-w-0 items-start gap-2">
                    {f.result === "ok" ? (
                      <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-r5e-success" />
                    ) : f.result === "failed" ? (
                      <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-r5e-danger" />
                    ) : (
                      <HelpCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-r5e-warning" />
                    )}
                    <div className="min-w-0">
                      <div className="font-mono text-r5e-text">
                        {f.check} <span className="text-r5e-muted">({f.code})</span>
                      </div>
                      <div className="truncate font-mono text-[11px] text-r5e-muted">
                        {truncateRef(f.subject, 12)}
                        {f.about ? ` → ${truncateRef(f.about, 10)}` : ""}
                      </div>
                    </div>
                  </div>
                  <Pill
                    tone={
                      f.result === "ok"
                        ? "success"
                        : f.result === "failed"
                          ? "danger"
                          : "warning"
                    }
                  >
                    {f.result}
                  </Pill>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}

      {report.summary.failed > 0 && (
        <div className="flex items-center gap-2 rounded border border-r5e-danger/40 bg-r5e-danger/10 p-2.5 text-xs text-r5e-danger">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          <span>One or more verification checks failed. Inspect findings above.</span>
        </div>
      )}
    </div>
  );
}
