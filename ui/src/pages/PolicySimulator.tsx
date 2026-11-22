// PolicySimulator — Cedar 4.9.1 Policy Simulator & Editor aligned to `CedarToolUseGate`
// (`User`, `Action::"invoke_tool"`, `ToolUse`, `context.tool_args`) over the
// `/v1/policies/*` camelCase API contract.

import { Suspense, lazy, useEffect, useMemo, useState } from "react";
import { Copy, Download, FileCode2, Play, RotateCcw, Save } from "lucide-react";
import { Outlet, useSearchParams } from "react-router-dom";

import { BlastRadiusPanel } from "~/components/policy/BlastRadiusPanel";
import CedarEditorBoundary from "~/components/policy/CedarEditorBoundary";
import { ConditionBuilder } from "~/components/policy/ConditionBuilder";
import {
  DecisionToggle,
  type PolicyDecisionVerdict,
} from "~/components/policy/DecisionToggle";
import { Pill } from "~/components/shared/Pill";
import { TopBar } from "~/components/shared/TopBar";
import { useBlastRadius } from "~/hooks/useBlastRadius";
import {
  useActivePolicy,
  useCreatePolicyDraft,
  useDraftFromRecord,
  useUpdatePolicyDraft,
  type PolicyDraftConditionMetadata,
} from "~/hooks/usePolicyDrafts";
import { api, ApiError } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import {
  truncateRef,
  type PolicyReplayResponse,
  type ToolUseSimulateRequest,
  type ToolUseSimulateResponse,
} from "~/lib/evidenceTypes";

const CedarEditor = lazy(() => import("~/components/policy/CedarEditor"));
const CedarDiffEditor = lazy(() => import("~/components/policy/CedarDiffEditor"));

type Mode = "simulate" | "replay" | "draft";

const DEFAULT_CEDAR = `// CedarToolUseGate policy (Cedar 4.9.1)
// Principal: User::"<id>", Action: Action::"invoke_tool", Resource: ToolUse::"<tool>"

@id("allow-default-tools")
permit(
  principal,
  action == Action::"invoke_tool",
  resource
);

@id("forbid-destructive-shell")
@reason("Destructive recursive delete commands are blocked by policy")
@suggested_alternative("Use a targeted path without -rf")
forbid(
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  context has tool_args &&
  context.tool_args has command &&
  context.tool_args.command like "*rm -rf*"
};
`;

const MODES: ReadonlyArray<{ key: Mode; label: string }> = [
  { key: "simulate", label: "Mode 1: Simulate" },
  { key: "replay", label: "Mode 2: Replay" },
  { key: "draft", label: "Mode 3: Draft & Blast Radius" },
];

export default function PolicySimulator(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();

  const mode: Mode = useMemo(() => {
    const m = searchParams.get("mode");
    if (m === "replay" || m === "draft") return m;
    return "simulate";
  }, [searchParams]);

  const incomingRef = searchParams.get("ref") ?? "";

  const activePolicyQuery = useActivePolicy();
  const createDraft = useCreatePolicyDraft();
  const updateDraft = useUpdatePolicyDraft();
  const draftFromRecord = useDraftFromRecord();
  const blastRadius = useBlastRadius();

  const [cedarSource, setCedarSource] = useState<string>(DEFAULT_CEDAR);
  const [copiedBanner, setCopiedBanner] = useState<boolean>(false);

  // Mode 1: Simulate inputs
  const [simPrincipalId, setSimPrincipalId] = useState("alice@r5e.dev");
  const [simPrincipalKind, setSimPrincipalKind] = useState<
    "obo_human" | "service_account" | "autonomous"
  >("obo_human");
  const [simGroups, setSimGroups] = useState("eng,platform");
  const [simTool, setSimTool] = useState("shell");
  const [simModel, setSimModel] = useState("claude-sonnet-4-5");
  const [simTenant, setSimTenant] = useState("r5e-dev");
  const [simUpstream, setSimUpstream] = useState("api.anthropic.com");
  const [simTokens, setSimTokens] = useState("1200");
  const [simArgsJson, setSimArgsJson] = useState(
    '{\n  "command": "rm -rf /tmp/build"\n}',
  );
  const [simResult, setSimResult] = useState<ToolUseSimulateResponse | null>(null);
  const [simError, setSimError] = useState<string | null>(null);
  const [simRunning, setSimRunning] = useState(false);

  // Mode 2: Replay inputs
  const [replayRef, setReplayRef] = useState(incomingRef);
  const [replayAgainst, setReplayAgainst] = useState<"draft" | "active" | "recorded">(
    "draft",
  );
  const [showDiff, setShowDiff] = useState(true);
  const [replayResult, setReplayResult] = useState<PolicyReplayResponse | null>(null);
  const [replayError, setReplayError] = useState<string | null>(null);
  const [replayRunning, setReplayRunning] = useState(false);

  // Mode 3: Draft & Blast Radius state
  const [draftId, setDraftId] = useState<string | null>(null);
  const [draftName, setDraftName] = useState("Tool-use guardrail draft");
  const [decisionVerdict, setDecisionVerdict] =
    useState<PolicyDecisionVerdict>("deny");
  const [scopeTool, setScopeTool] = useState("shell");
  const [conditions, setConditions] = useState<PolicyDraftConditionMetadata[]>([]);
  const [draftSavedNotice, setDraftSavedNotice] = useState<string | null>(null);

  useEffect(() => {
    if (incomingRef) {
      setReplayRef(incomingRef);
    }
  }, [incomingRef]);

  useEffect(() => {
    if (mode === "draft" && incomingRef && !draftId && !draftFromRecord.isPending) {
      draftFromRecord.mutate(
        { ref: incomingRef, decision: decisionVerdict === "allow" ? "permit" : "forbid" },
        {
          onSuccess: (draft) => {
            setDraftId(draft.id);
            setDraftName(draft.name);
            setCedarSource(draft.cedarSource);
            setConditions(draft.conditionMetadata ?? []);
          },
        },
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, incomingRef]);

  function selectMode(next: Mode): void {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        if (next === "simulate") params.delete("mode");
        else params.set("mode", next);
        return params;
      },
      { replace: true },
    );
  }

  function loadActivePolicy(): void {
    if (activePolicyQuery.data?.source) {
      setCedarSource(activePolicyQuery.data.source);
    }
  }

  function copyCedar(): void {
    void navigator.clipboard?.writeText(cedarSource);
    setCopiedBanner(true);
    setTimeout(() => setCopiedBanner(false), 1_500);
  }

  function downloadCedar(): void {
    const blob = new Blob([cedarSource], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    try {
      const a = document.createElement("a");
      a.href = url;
      a.download = "bundle.cedar";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1_000);
    }
  }

  async function handleSimulate(): Promise<void> {
    setSimRunning(true);
    setSimError(null);
    let parsedArgs: Record<string, unknown> | undefined;
    if (simArgsJson.trim()) {
      try {
        parsedArgs = JSON.parse(simArgsJson) as Record<string, unknown>;
      } catch (e) {
        setSimRunning(false);
        setSimError(`Invalid toolArgs JSON: ${(e as Error).message}`);
        return;
      }
    }

    const req: ToolUseSimulateRequest = {
      cedarSource,
      principal: {
        id: simPrincipalId.trim() || "anonymous",
        kind: simPrincipalKind,
        groups: simGroups
          .split(",")
          .map((g) => g.trim())
          .filter(Boolean),
      },
      action: 'Action::"invoke_tool"',
      resource: { tool: simTool.trim() },
      context: {
        model: simModel.trim() || "claude-sonnet-4-5",
        tenant: simTenant.trim() || "r5e-dev",
        sessionId: "urn:r5e:session:r5e-dev:simulator",
        upstreamDomain: simUpstream.trim() || "api.anthropic.com",
        transport: "https_sse",
        estimatedCompletionTokens: Number.parseInt(simTokens, 10) || 0,
        toolArgs: parsedArgs,
      },
    };

    try {
      const res = await api.post<ToolUseSimulateResponse>(
        apiPaths.policies.simulate,
        req,
      );
      setSimResult(res);
    } catch (err) {
      if (err instanceof ApiError) setSimError(err.error_description);
      else if (err instanceof Error) setSimError(err.message);
    } finally {
      setSimRunning(false);
    }
  }

  async function handleReplay(): Promise<void> {
    if (!replayRef.trim()) {
      setReplayError("Enter an evidence:sha256:... record ref to replay.");
      return;
    }
    setReplayRunning(true);
    setReplayError(null);
    try {
      const res = await api.post<PolicyReplayResponse>(apiPaths.policies.replay, {
        ref: replayRef.trim(),
        replayedAgainst: replayAgainst,
        cedarSource: replayAgainst === "draft" ? cedarSource : undefined,
      });
      setReplayResult(res);
    } catch (err) {
      if (err instanceof ApiError) setReplayError(err.error_description);
      else if (err instanceof Error) setReplayError(err.message);
    } finally {
      setReplayRunning(false);
    }
  }

  function applyDraftBuilderToCedar(): void {
    const clauses: string[] = [];
    for (const c of conditions) {
      if (c.kind === "eq") {
        const val = typeof c.value === "string" ? JSON.stringify(c.value) : String(c.value);
        if (c.attr.startsWith("context.tool_args.")) {
          const key = c.attr.slice("context.tool_args.".length);
          clauses.push(
            `context has tool_args && context.tool_args has ${key} && context.tool_args.${key} == ${val}`,
          );
        } else {
          clauses.push(`${c.attr} == ${val}`);
        }
      } else if (c.kind === "neq") {
        const val = typeof c.value === "string" ? JSON.stringify(c.value) : String(c.value);
        clauses.push(`${c.attr} != ${val}`);
      } else if (c.kind === "in" && Array.isArray(c.value)) {
        clauses.push(`${c.attr} in ${JSON.stringify(c.value)}`);
      }
    }

    const resourceClause = scopeTool.trim()
      ? `resource == ToolUse::${JSON.stringify(scopeTool.trim())}`
      : "resource";
    const whenClause =
      clauses.length > 0 ? ` when {\n  ${clauses.join(" &&\n  ")}\n}` : "";

    const cedarEffect = decisionVerdict === "allow" ? "permit" : "forbid";
    const generated = `// Generated from Scope & Conditions (${cedarEffect})
@id("draft-rule")
${cedarEffect}(
  principal,
  action == Action::"invoke_tool",
  ${resourceClause}
)${whenClause};
`;
    setCedarSource(
      cedarEffect === "forbid"
        ? `permit(\n  principal,\n  action == Action::"invoke_tool",\n  resource\n);\n\n${generated}`
        : generated,
    );
  }

  async function handleSaveDraft(): Promise<string | null> {
    setDraftSavedNotice(null);
    if (draftId) {
      const updated = await updateDraft.mutateAsync({
        id: draftId,
        name: draftName,
        cedarSource,
        scopeMetadata: scopeTool ? { toolNames: [scopeTool] } : null,
        conditionMetadata: conditions,
      });
      setDraftSavedNotice(`Saved draft ${updated.id}`);
      return updated.id;
    }
    const created = await createDraft.mutateAsync({
      name: draftName,
      cedarSource,
      sourceRecordRef: incomingRef || null,
      scopeMetadata: scopeTool ? { toolNames: [scopeTool] } : null,
      conditionMetadata: conditions,
    });
    setDraftId(created.id);
    setDraftSavedNotice(`Created draft ${created.id}`);
    return created.id;
  }

  async function handleRunBlastRadius(): Promise<void> {
    const id = draftId ?? (await handleSaveDraft()) ?? "draft-preview";
    blastRadius.mutate({ draftId: id, cedarSource });
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar
        pageContent={
          <div className="flex items-center gap-3">
            <h1 className="text-sm font-semibold text-r5e-text">
              Policy Simulator &amp; Cedar Editor
            </h1>
            <nav aria-label="Simulator modes" className="flex items-center gap-1">
              {MODES.map((m) => (
                <button
                  key={m.key}
                  type="button"
                  data-testid={`mode-tab-${m.key}`}
                  onClick={() => selectMode(m.key)}
                  className={[
                    "rounded px-2.5 py-1 text-xs font-medium transition-colors",
                    mode === m.key
                      ? "bg-r5e-accent/20 text-r5e-text"
                      : "text-r5e-muted hover:bg-r5e-surface hover:text-r5e-text",
                  ].join(" ")}
                >
                  {m.label}
                </button>
              ))}
            </nav>
          </div>
        }
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadActivePolicy}
              disabled={!activePolicyQuery.data}
              data-testid="load-active-policy-btn"
              className="inline-flex items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1 text-xs text-r5e-text hover:bg-r5e-bg disabled:opacity-50"
            >
              <FileCode2 className="h-3.5 w-3.5" />
              Load active
            </button>
            <button
              type="button"
              onClick={copyCedar}
              className="inline-flex items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1 text-xs text-r5e-text hover:bg-r5e-bg"
            >
              <Copy className="h-3.5 w-3.5" />
              {copiedBanner ? "Copied" : "Copy"}
            </button>
            <button
              type="button"
              onClick={downloadCedar}
              className="inline-flex items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1 text-xs text-r5e-text hover:bg-r5e-bg"
            >
              <Download className="h-3.5 w-3.5" />
              Export .cedar
            </button>
          </div>
        }
      />

      {activePolicyQuery.data ? (
        <div
          data-testid="active-policy-banner"
          className="flex flex-wrap items-center justify-between gap-2 border-b border-r5e-border bg-r5e-surface/60 px-5 py-2 text-xs text-r5e-muted"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-r5e-text">Active Bundle (read-only):</span>
            <span className="font-mono">
              {truncateRef(activePolicyQuery.data.bundleRef, 12)}
            </span>
            <Pill tone="muted">{activePolicyQuery.data.sourceMode}</Pill>
            {activePolicyQuery.data.sourceRef && (
              <span className="font-mono text-[11px]">
                {activePolicyQuery.data.sourceRef}
              </span>
            )}
            <span>activated {activePolicyQuery.data.activatedAt}</span>
          </div>
          <span className="text-[11px]">
            Cedar 4.9.1 • <code className="font-mono">Action::&quot;invoke_tool&quot;</code> •
            live HTTP activation deferred
          </span>
        </div>
      ) : activePolicyQuery.isError &&
        activePolicyQuery.error instanceof ApiError &&
        activePolicyQuery.error.status === 503 ? (
        <div
          data-testid="active-policy-unavailable"
          className="flex items-center justify-between border-b border-r5e-warning/40 bg-r5e-warning/10 px-5 py-2 text-xs text-r5e-warning"
        >
          <span>No active Cedar policy bundle is currently loaded on the gateway (503).</span>
        </div>
      ) : null}

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-y-auto p-5 lg:grid-cols-12">
        <section className="flex flex-col gap-2 lg:col-span-6">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
              01 Policy as Code (Cedar 4.9.1)
            </h2>
            {mode === "draft" && (
              <button
                type="button"
                onClick={() => void handleSaveDraft()}
                data-testid="save-draft-btn"
                className="inline-flex items-center gap-1 rounded border border-r5e-border bg-r5e-surface px-2.5 py-1 text-xs text-r5e-text hover:bg-r5e-bg"
              >
                <Save className="h-3.5 w-3.5" />
                Save draft
              </button>
            )}
          </div>
          {draftSavedNotice && (
            <p className="text-xs text-r5e-success" data-testid="draft-saved-notice">
              {draftSavedNotice}
            </p>
          )}
          <div className="min-h-[380px] flex-1">
            <CedarEditorBoundary value={cedarSource} onChange={setCedarSource}>
              <Suspense
                fallback={
                  <div className="flex h-[380px] items-center justify-center rounded border border-r5e-border bg-r5e-surface text-xs text-r5e-muted">
                    Loading Cedar editor…
                  </div>
                }
              >
                <CedarEditor
                  value={cedarSource}
                  onChange={setCedarSource}
                  validationEndpoint={apiPaths.policies.simulate}
                />
              </Suspense>
            </CedarEditorBoundary>
          </div>
        </section>

        <section className="flex flex-col gap-4 lg:col-span-6">
          {mode === "simulate" && (
            <div
              data-testid="simulate-panel"
              className="flex flex-col gap-3 rounded-lg border border-r5e-border bg-r5e-surface p-4"
            >
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
                  CedarToolUseGate Sandbox Input
                </h2>
                <button
                  type="button"
                  data-testid="run-simulate-btn"
                  onClick={() => void handleSimulate()}
                  disabled={simRunning}
                  className="inline-flex items-center gap-1.5 rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs font-medium text-r5e-accent hover:bg-r5e-accent/25 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {simRunning ? "Simulating…" : "Run simulation"}
                </button>
              </div>

              <div className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-2">
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">User ID (`User::&quot;…&quot;`)</span>
                  <input
                    type="text"
                    value={simPrincipalId}
                    onChange={(e) => setSimPrincipalId(e.target.value)}
                    data-testid="sim-principal-id"
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">Principal Kind</span>
                  <select
                    value={simPrincipalKind}
                    onChange={(e) =>
                      setSimPrincipalKind(
                        e.target.value as "obo_human" | "service_account" | "autonomous",
                      )
                    }
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  >
                    <option value="obo_human">obo_human</option>
                    <option value="service_account">service_account</option>
                    <option value="autonomous">autonomous</option>
                  </select>
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">Tool (`ToolUse::&quot;…&quot;`)</span>
                  <input
                    type="text"
                    value={simTool}
                    onChange={(e) => setSimTool(e.target.value)}
                    data-testid="sim-tool-input"
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">Principal Groups (comma-separated)</span>
                  <input
                    type="text"
                    value={simGroups}
                    onChange={(e) => setSimGroups(e.target.value)}
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">Model</span>
                  <input
                    type="text"
                    value={simModel}
                    onChange={(e) => setSimModel(e.target.value)}
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">Tenant / Upstream</span>
                  <div className="flex gap-1.5">
                    <input
                      type="text"
                      value={simTenant}
                      onChange={(e) => setSimTenant(e.target.value)}
                      className="w-1/2 rounded border border-r5e-border bg-r5e-bg px-2 py-1.5 font-mono text-r5e-text"
                    />
                    <input
                      type="text"
                      value={simUpstream}
                      onChange={(e) => setSimUpstream(e.target.value)}
                      className="w-1/2 rounded border border-r5e-border bg-r5e-bg px-2 py-1.5 font-mono text-r5e-text"
                    />
                  </div>
                </label>
                <label className="flex flex-col gap-1 sm:col-span-2">
                  <span className="text-r5e-muted">Estimated Completion Tokens</span>
                  <input
                    type="number"
                    value={simTokens}
                    onChange={(e) => setSimTokens(e.target.value)}
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>
                <label className="flex flex-col gap-1 sm:col-span-2">
                  <span className="text-r5e-muted">
                    context.tool_args (JSON; omitted if &gt; 10,000 bytes)
                  </span>
                  <textarea
                    rows={4}
                    value={simArgsJson}
                    onChange={(e) => setSimArgsJson(e.target.value)}
                    data-testid="sim-tool-args-input"
                    className="rounded border border-r5e-border bg-r5e-bg p-2.5 font-mono text-xs text-r5e-text"
                  />
                </label>
              </div>

              {simError && (
                <div
                  role="alert"
                  className="rounded border border-r5e-danger/40 bg-r5e-danger/10 p-2.5 text-xs text-r5e-danger"
                >
                  {simError}
                </div>
              )}

              {simResult && (
                <div
                  data-testid="simulate-result"
                  className="flex flex-col gap-2 rounded border border-r5e-border bg-r5e-bg p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-r5e-muted">Verdict:</span>
                    <Pill
                      tone={
                        simResult.decision === "allow"
                          ? "success"
                          : simResult.decision === "deny"
                            ? "danger"
                            : "warning"
                      }
                      testId="simulate-verdict-pill"
                    >
                      {simResult.decision}
                    </Pill>
                    {simResult.ruleId && (
                      <span className="font-mono text-r5e-muted">
                        rule: {simResult.ruleId}
                      </span>
                    )}
                    <span className="ml-auto font-mono text-[11px] text-r5e-muted">
                      tool_args: {simResult.toolArgsSizeBytes}B (
                      {simResult.toolArgsInlined ? "inlined" : "hash-only"})
                    </span>
                  </div>
                  {simResult.reason && <p className="text-r5e-text">{simResult.reason}</p>}
                  {simResult.suggestedAlternative && (
                    <p className="text-r5e-muted">
                      Suggested alternative: {simResult.suggestedAlternative}
                    </p>
                  )}
                  {simResult.diagnostics.errors.length > 0 && (
                    <ul className="list-disc pl-4 font-mono text-r5e-danger">
                      {simResult.diagnostics.errors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          )}

          {mode === "replay" && (
            <div
              data-testid="replay-panel"
              className="flex flex-col gap-3 rounded-lg border border-r5e-border bg-r5e-surface p-4"
            >
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
                  Historical Record Replay (`evidence:sha256:…`)
                </h2>
                <button
                  type="button"
                  data-testid="run-replay-btn"
                  onClick={() => void handleReplay()}
                  disabled={replayRunning}
                  className="inline-flex items-center gap-1.5 rounded border border-r5e-accent bg-r5e-accent/15 px-3 py-1.5 text-xs font-medium text-r5e-accent hover:bg-r5e-accent/25 disabled:opacity-50"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  {replayRunning ? "Replaying…" : "Run replay"}
                </button>
              </div>

              <div className="grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-3">
                <label className="flex flex-col gap-1 sm:col-span-2">
                  <span className="text-r5e-muted">Record Ref</span>
                  <input
                    type="text"
                    value={replayRef}
                    onChange={(e) => setReplayRef(e.target.value)}
                    placeholder="evidence:sha256:..."
                    data-testid="replay-ref-input"
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="text-r5e-muted">Evaluate against</span>
                  <select
                    value={replayAgainst}
                    onChange={(e) =>
                      setReplayAgainst(
                        e.target.value as "draft" | "active" | "recorded",
                      )
                    }
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  >
                    <option value="draft">Draft (editor)</option>
                    <option value="active">Active bundle</option>
                    <option value="recorded">Recorded snapshot</option>
                  </select>
                </label>
              </div>

              {replayError && (
                <div
                  role="alert"
                  className="rounded border border-r5e-danger/40 bg-r5e-danger/10 p-2.5 text-xs text-r5e-danger"
                >
                  {replayError}
                </div>
              )}

              {replayResult && (
                <div
                  data-testid="replay-result"
                  className="flex flex-col gap-3 rounded border border-r5e-border bg-r5e-bg p-3 text-xs"
                >
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex items-center gap-1.5">
                      <span className="text-r5e-muted">Recorded:</span>
                      <Pill
                        tone={
                          replayResult.originalOutcome === "allow"
                            ? "success"
                            : replayResult.originalOutcome === "deny"
                              ? "danger"
                              : "warning"
                        }
                      >
                        {replayResult.originalOutcome}
                      </Pill>
                    </div>
                    <span className="text-r5e-muted">→</span>
                    <div className="flex items-center gap-1.5">
                      <span className="text-r5e-muted">
                        Replayed ({replayResult.replayedAgainst}):
                      </span>
                      <Pill
                        tone={
                          replayResult.replayedOutcome === "allow"
                            ? "success"
                            : replayResult.replayedOutcome === "deny"
                              ? "danger"
                              : "warning"
                        }
                        testId="replay-outcome-pill"
                      >
                        {replayResult.replayedOutcome}
                      </Pill>
                    </div>
                  </div>

                  {replayResult.replayedOutcome === "incomplete" && (
                    <div
                      role="note"
                      data-testid="replay-incomplete-banner"
                      className="rounded border border-r5e-warning/40 bg-r5e-warning/10 p-2 text-r5e-warning"
                    >
                      Incomplete replay: {replayResult.incompleteReason}
                    </div>
                  )}

                  {replayResult.reason && (
                    <p className="text-r5e-text">{replayResult.reason}</p>
                  )}

                  {replayResult.recordedPolicyRef && (
                    <p className="font-mono text-[11px] text-r5e-muted">
                      recordedPolicyRef: {replayResult.recordedPolicyRef}
                    </p>
                  )}

                  {replayResult.recordedCedarSource && (
                    <div className="flex flex-col gap-2">
                      <label className="inline-flex items-center gap-2 text-[11px] text-r5e-muted">
                        <input
                          type="checkbox"
                          checked={showDiff}
                          onChange={(e) => setShowDiff(e.target.checked)}
                        />
                        Compare recorded bundle snapshot vs editor draft
                      </label>
                      {showDiff && (
                        <div className="h-[220px]">
                          <Suspense
                            fallback={
                              <div className="text-xs text-r5e-muted">
                                Loading diff…
                              </div>
                            }
                          >
                            <CedarDiffEditor
                              original={replayResult.recordedCedarSource}
                              modified={cedarSource}
                              onModifiedChange={setCedarSource}
                            />
                          </Suspense>
                        </div>
                      )}
                    </div>
                  )}

                  {replayResult.hydratedInput && (
                    <details className="rounded border border-r5e-border p-2">
                      <summary className="cursor-pointer text-[11px] font-medium text-r5e-muted">
                        Hydrated CedarToolUseGate input
                      </summary>
                      <pre className="mt-2 overflow-x-auto font-mono text-[11px] text-r5e-text">
                        {JSON.stringify(replayResult.hydratedInput, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              )}
            </div>
          )}

          {mode === "draft" && (
            <div className="flex flex-col gap-4" data-testid="draft-panel">
              <div className="flex flex-col gap-3 rounded-lg border border-r5e-border bg-r5e-surface p-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-r5e-muted">
                    02 Scope &amp; Conditions
                  </h2>
                  <button
                    type="button"
                    onClick={applyDraftBuilderToCedar}
                    data-testid="apply-conditions-btn"
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1 text-xs text-r5e-text hover:bg-r5e-surface"
                  >
                    Generate Cedar
                  </button>
                </div>

                <label className="flex flex-col gap-1 text-xs">
                  <span className="text-r5e-muted">Draft Name</span>
                  <input
                    type="text"
                    value={draftName}
                    onChange={(e) => setDraftName(e.target.value)}
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 text-r5e-text"
                  />
                </label>

                <DecisionToggle
                  value={decisionVerdict}
                  onChange={setDecisionVerdict}
                />

                <label className="flex flex-col gap-1 text-xs">
                  <span className="text-r5e-muted">
                    Target Tool (`ToolUse::&quot;…&quot;`, blank for any tool)
                  </span>
                  <input
                    type="text"
                    value={scopeTool}
                    onChange={(e) => setScopeTool(e.target.value)}
                    className="rounded border border-r5e-border bg-r5e-bg px-2.5 py-1.5 font-mono text-r5e-text"
                  />
                </label>

                <ConditionBuilder value={conditions} onChange={setConditions} />
              </div>

              <BlastRadiusPanel
                report={blastRadius.data ?? null}
                isLoading={blastRadius.isPending}
                error={blastRadius.error?.message ?? null}
                onRunDryRun={() => void handleRunBlastRadius()}
              />
            </div>
          )}
        </section>
      </div>

      <Outlet />
    </div>
  );
}
