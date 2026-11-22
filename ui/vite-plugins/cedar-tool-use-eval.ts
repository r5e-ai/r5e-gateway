// Real Cedar 4.9.1 evaluator for Vite dev-mocks & tests, mirroring
// `Recurse.Gateway.LlmProxy.CedarToolUseGate` (`priv/cedar/schema.cedarschema.json`).
// Uses camelCase API request/response fields matching the Provenance v2 gateway API.

import { createHash } from "node:crypto";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";

export const DEFAULT_ARGS_INLINE_THRESHOLD_BYTES = 10_000;
const VALID_TOOL_NAME_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

export interface ToolUsePrincipalInput {
  id: string;
  kind?: "obo_human" | "service_account" | "autonomous";
  chatgptAccountId?: string;
  groups?: string[];
}

export interface ToolUseContextInput {
  model?: string;
  tenant?: string;
  sessionId?: string;
  promptHash?: string;
  responseSoFarHash?: string;
  estimatedCompletionTokens?: number;
  cedarBundleHash?: string;
  upstreamDomain?: string;
  transport?: "wss" | "https_sse";
  startedAt?: string;
  parallelToolCallIndex?: number;
  toolArgs?: Record<string, unknown>;
  toolArgsSizeBytes?: number;
  toolArgsHash?: string;
  argsInlineThresholdBytes?: number;
}

export interface ToolUseSimulateInput {
  cedarSource: string;
  principal: ToolUsePrincipalInput;
  action?: string;
  resource: { tool: string };
  context?: ToolUseContextInput;
}

export interface ToolUseSimulateResult {
  ok: boolean;
  parseError?: string;
  decision: "allow" | "deny" | "error";
  determiningPolicies: string[];
  ruleId: string | null;
  reason: string | null;
  suggestedAlternative: string | null;
  toolArgsInlined: boolean;
  toolArgsSizeBytes: number;
  diagnostics: {
    errors: string[];
  };
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function extractAnnotationForPolicy(
  source: string,
  policyIndex: number,
  annotation: string,
): string | null {
  const statements = source.split(/;\s*(?=\n|$)/).filter((s) => /\b(permit|forbid)\s*\(/.test(s));
  const stmt = statements[policyIndex];
  if (!stmt) return null;
  const re = new RegExp(`@${annotation}\\s*\\(\\s*"([^"]*)"\\s*\\)`);
  const m = re.exec(stmt);
  return m?.[1] ?? null;
}

export function checkCedarSyntax(source: string): { ok: true } | { ok: false; message: string } {
  const res = cedar.checkParsePolicySet({ staticPolicies: source });
  if (res.type === "success") return { ok: true };
  const first = res.errors[0];
  return { ok: false, message: `cedar parse error: ${first?.message ?? "syntax error"}` };
}

export function evaluateToolUseCedar(input: ToolUseSimulateInput): ToolUseSimulateResult {
  const source = input.cedarSource ?? "";
  const ctx = input.context ?? {};
  const threshold =
    typeof ctx.argsInlineThresholdBytes === "number" && ctx.argsInlineThresholdBytes > 0
      ? ctx.argsInlineThresholdBytes
      : DEFAULT_ARGS_INLINE_THRESHOLD_BYTES;

  const parseCheck = checkCedarSyntax(source);
  if (!parseCheck.ok) {
    return {
      ok: false,
      parseError: parseCheck.message,
      decision: "error",
      determiningPolicies: [],
      ruleId: null,
      reason: "cedar_parse_error",
      suggestedAlternative: null,
      toolArgsInlined: false,
      toolArgsSizeBytes: 0,
      diagnostics: { errors: [parseCheck.message] },
    };
  }

  const toolName = input.resource?.tool ?? "";
  if (!VALID_TOOL_NAME_RE.test(toolName)) {
    return {
      ok: true,
      decision: "deny",
      determiningPolicies: [],
      ruleId: "invalid_tool_name",
      reason: "invalid_tool_name",
      suggestedAlternative: null,
      toolArgsInlined: false,
      toolArgsSizeBytes: 0,
      diagnostics: { errors: [] },
    };
  }

  const serializedArgs =
    ctx.toolArgs !== undefined ? JSON.stringify(ctx.toolArgs) : "{}";
  const measuredSize =
    typeof ctx.toolArgsSizeBytes === "number"
      ? ctx.toolArgsSizeBytes
      : Buffer.byteLength(serializedArgs, "utf8");
  const argsHash = ctx.toolArgsHash ?? sha256Hex(serializedArgs);
  const inlineArgs = ctx.toolArgs !== undefined && measuredSize <= threshold;

  const principalKind = input.principal?.kind ?? "obo_human";
  const principalGroups = Array.isArray(input.principal?.groups)
    ? input.principal.groups
    : [];
  const chatgptAccountId = input.principal?.chatgptAccountId ?? "";
  const principalId = input.principal?.id || "anonymous";

  // Cedar context attributes match `priv/cedar/schema.cedarschema.json` (snake_case inside Cedar).
  const cedarContext: Record<string, unknown> = {
    tool_args_hash: argsHash,
    tool_args_size_bytes: measuredSize,
    model: ctx.model ?? "claude-sonnet-4-5",
    tenant: ctx.tenant ?? "r5e-dev",
    session_id: ctx.sessionId ?? "urn:r5e:session:r5e-dev:sim-001",
    prompt_hash: ctx.promptHash ?? "0".repeat(64),
    response_so_far_hash: ctx.responseSoFarHash ?? "0".repeat(64),
    estimated_completion_tokens: ctx.estimatedCompletionTokens ?? 0,
    cedar_bundle_hash: ctx.cedarBundleHash ?? sha256Hex(source),
    upstream_domain: ctx.upstreamDomain ?? "api.anthropic.com",
    transport: ctx.transport ?? "https_sse",
    started_at: ctx.startedAt ?? new Date().toISOString(),
    principal_kind: principalKind,
    chatgpt_account_id: chatgptAccountId,
    principal_groups: principalGroups,
    parallel_tool_call_index: ctx.parallelToolCallIndex ?? -1,
  };

  if (inlineArgs && ctx.toolArgs !== undefined) {
    cedarContext.tool_args = ctx.toolArgs;
  }

  const authz = cedar.isAuthorized({
    principal: { type: "User", id: principalId },
    action: { type: "Action", id: "invoke_tool" },
    resource: { type: "ToolUse", id: toolName },
    context: cedarContext as cedar.Context,
    policies: { staticPolicies: source },
    entities: [
      {
        uid: { type: "User", id: principalId },
        attrs: {
          kind: principalKind,
          chatgpt_account_id: chatgptAccountId,
          groups: principalGroups,
        },
        parents: [],
      },
      {
        uid: { type: "ToolUse", id: toolName },
        attrs: {},
        parents: [],
      },
    ],
  });

  if (authz.type === "failure") {
    return {
      ok: true,
      decision: "error",
      determiningPolicies: [],
      ruleId: null,
      reason: "cedar_eval_error",
      suggestedAlternative: null,
      toolArgsInlined: inlineArgs,
      toolArgsSizeBytes: measuredSize,
      diagnostics: { errors: authz.errors.map((e) => e.message) },
    };
  }

  const decision = authz.response.decision === "allow" ? "allow" : "deny";
  const determining = authz.response.diagnostics.reason ?? [];
  const evalErrors = (authz.response.diagnostics.errors ?? []).map((e) => e.error.message);

  let ruleId: string | null = determining[0] ?? null;
  let reason: string | null = null;
  let suggestedAlternative: string | null = null;

  const firstDetermining = determining[0];
  if (firstDetermining) {
    const idxMatch = /^policy(\d+)$/.exec(firstDetermining);
    if (idxMatch && idxMatch[1] !== undefined) {
      const idx = Number.parseInt(idxMatch[1], 10);
      ruleId = extractAnnotationForPolicy(source, idx, "id") ?? firstDetermining;
      reason = extractAnnotationForPolicy(source, idx, "reason");
      suggestedAlternative = extractAnnotationForPolicy(source, idx, "suggested_alternative");
    }
  }

  if (decision === "deny" && !reason) {
    reason =
      determining.length > 0
        ? `Denied by ${ruleId ?? determining[0]}`
        : "Default deny (no matching permit policy)";
  } else if (decision === "allow" && !reason) {
    reason = `Allowed by ${ruleId ?? determining[0] ?? "permit"}`;
  }

  return {
    ok: true,
    decision,
    determiningPolicies: determining,
    ruleId,
    reason,
    suggestedAlternative,
    toolArgsInlined: inlineArgs,
    toolArgsSizeBytes: measuredSize,
    diagnostics: { errors: evalErrors },
  };
}
