// Canonical Provenance v2 & CedarToolUseGate TypeScript types (camelCase wire contract).
//
// Matches:
//   - r5e-spec/schemas/evidence-envelope.schema.json
//   - r5e-spec/schemas/export.schema.json (format: "r5e.provenance-export/v2")
//   - apps/recurse_gateway/lib/recurse_gateway/evidence/api_handler.ex
//   - Provenance v2 gateway API contract (camelCase)

export type PolicyOutcome = "allow" | "deny" | "error";

export interface DsseSignature {
  keyid: string;
  sig: string;
}

export interface SignedEvidenceEnvelope {
  payloadType: "application/vnd.r5e.provenance-evidence+json;v=2";
  payload: string; // Base64-encoded canonical Provenance v2 Evidence JSON
  signatures: DsseSignature[];
}

export interface PolicyEvaluation {
  policyRef: string;
  outcome: PolicyOutcome;
  inputRefs: string[];
  reason?: string;
  evaluatorRef?: string;
  activationRef?: string;
  decisionRef?: string;
}

export interface EvidenceEnvelopePayload {
  apiVersion: string;
  kind: string; // Bare kind name, e.g. "ToolCall", "PolicyDecision", or custom kind
  schemaRef: string;
  profileRef: string;
  issuer: string;
  actor: string;
  onBehalfOf?: string;
  session?: string;
  stream: string;
  seq: number;
  previous: string | null;
  capturedAt: string;
  occurredAt?: string;
  causes?: string[];
  contextRefs?: string[];
  identityRef?: string;
  subject?: string;
  body: Record<string, unknown>;
}

/**
 * Phase 1 list row shape (`GET /v1/evidence/records`) & detail shape (`GET /v1/evidence/records/:ref`).
 * Strictly `{ref, stream, seq, kind, capturedAt, actor, session, envelope}` in list rows;
 * optional `sealRef` only on single-record detail when sealed.
 */
export interface EvidenceRecordEntry {
  ref: string; // evidence:sha256:<64hex>
  stream: string;
  seq: number;
  kind: string; // Full kind_path, e.g. "provenance.r5e.io/v2/ToolCall"
  capturedAt: string;
  actor?: string | null;
  session?: string | null;
  envelope: SignedEvidenceEnvelope;
  /** Only populated on single-record detail (`GET /v1/evidence/records/:ref`), never on list rows. */
  sealRef?: string | null;
}

export interface EvidenceListResponse {
  records: EvidenceRecordEntry[];
  cursor: string | null;
}

export interface SessionEvidenceResponse {
  session: string;
  records: EvidenceRecordEntry[];
}

export interface DeploymentInfo {
  chain: string;
  bootstrapKey?: {
    algorithm: string;
    bytes: string;
    keyid: string;
  };
  state?: string;
}

/** `r5e.provenance-export/v2` offline verification bundle (`export.schema.json`). */
export interface ProvenanceExportV2 {
  format: "r5e.provenance-export/v2";
  scope: {
    query: unknown;
    at: Array<{ stream: string; seq: number; event: string }>;
  };
  records: Array<{ ref: string; envelope: SignedEvidenceEnvelope }>;
  blobs: Array<{ ref: string; base64: string; mediaType?: string }>;
  keys: Array<{ keyid: string; algorithm: "ed25519" | "es256" | "es384"; bytes: string }>;
  seals: string[];
  checkpoints: string[];
  proofs: Array<{ record: string; seal: string; index: number; siblings: string[] }>;
  publicationProofs: Array<{
    targetProfileRef: string;
    commitment: string;
    proofRef: string;
  }>;
  omissions: Array<{
    ref: string;
    reason: "unavailable" | "withheld" | "expired" | "not-selected" | "unsupported";
    detail?: string;
  }>;
}

export interface VerifyFinding {
  layer: 1 | 2 | 3;
  subject: string;
  check: string;
  result: "ok" | "failed" | "incomplete";
  code: string;
  about: string | null;
}

export interface VerifyReportV2 {
  format: string;
  start?: unknown;
  summary: {
    ok: number;
    failed: number;
    incomplete: number;
  };
  findings: VerifyFinding[];
}

// --- Policy (CedarToolUseGate) camelCase wire shapes ---

export interface ActivePolicyBundle {
  bundleRef: string;
  source: string;
  sourceMode: "filesystem" | "oci";
  sourceRef: string | null;
  activatedAt: string;
}

export type LiveTailFrame =
  | { type: "record"; record: EvidenceRecordEntry }
  | { type: "ping" }
  | { type: "pong" };

export interface ToolUsePrincipal {
  id: string;
  kind: "obo_human" | "service_account" | "autonomous";
  chatgptAccountId?: string;
  groups: string[];
}

export interface ToolUseSimulateRequest {
  cedarSource: string;
  principal: ToolUsePrincipal;
  action: 'Action::"invoke_tool"';
  resource: { tool: string };
  context: {
    model: string;
    tenant: string;
    sessionId: string;
    upstreamDomain: string;
    transport: "wss" | "https_sse";
    estimatedCompletionTokens: number;
    toolArgs?: Record<string, unknown>;
    argsInlineThresholdBytes?: number;
  };
}

export interface ToolUseSimulateResponse {
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

export interface PolicyReplayResponse {
  ref: string;
  originalOutcome: PolicyOutcome;
  replayedOutcome: PolicyOutcome | "incomplete";
  incompleteReason: string | null;
  replayedAgainst: "recorded" | "draft" | "active";
  recordedPolicyRef: string | null;
  recordedCedarSource: string | null;
  activePolicyRef: string | null;
  activeCedarSource: string | null;
  determiningPolicies: string[];
  ruleId: string | null;
  reason: string | null;
  suggestedAlternative: string | null;
  hydratedInput: {
    principal: ToolUsePrincipal;
    action: 'Action::"invoke_tool"';
    resource: { tool: string };
    context: Record<string, unknown>;
  } | null;
}

export type PolicyDraftConditionKind = "eq" | "neq" | "in" | "time_window" | "group_member";

export interface PolicyDraftConditionMetadata {
  kind: PolicyDraftConditionKind;
  attr: string;
  value: unknown;
}

export interface PolicyDraftScopeMetadata {
  principalKind?: "obo_human" | "service_account" | "autonomous" | "any";
  principalGroups?: string[];
  toolNames?: string[];
  models?: string[];
}

export interface PolicyDraft {
  id: string;
  name: string;
  cedarSource: string;
  sourceRecordRef: string | null;
  scopeMetadata: PolicyDraftScopeMetadata | null;
  conditionMetadata: PolicyDraftConditionMetadata[];
  createdAt: string;
  updatedAt: string;
}

export interface BlastRadiusSample {
  ref: string;
  tool: string;
  actor: string;
  capturedAt: string;
  originalOutcome: PolicyOutcome;
  draftOutcome: PolicyOutcome | "incomplete";
}

export interface BlastRadiusReport {
  draftId: string;
  totalEvaluated: number;
  incompleteCount: number;
  matchesIntent: number;
  unintended: number;
  wouldHaveAllowed: number;
  noChange: number;
  samples: {
    matchesIntent: BlastRadiusSample[];
    unintended: BlastRadiusSample[];
    wouldHaveAllowed: BlastRadiusSample[];
    noChange: BlastRadiusSample[];
  };
}

// --- Client-side decoding & projection helpers ---

export function decodeEvidencePayload(
  envelope: SignedEvidenceEnvelope | undefined | null,
): EvidenceEnvelopePayload | null {
  if (!envelope?.payload) return null;
  try {
    let raw: string;
    if (typeof atob === "function") {
      const bin = atob(envelope.payload);
      const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      raw = new TextDecoder("utf-8").decode(bytes);
    } else {
      raw = Buffer.from(envelope.payload, "base64").toString("utf8");
    }
    return JSON.parse(raw) as EvidenceEnvelopePayload;
  } catch {
    return null;
  }
}

export function shortKindName(kindPath: string): string {
  const idx = kindPath.lastIndexOf("/");
  return idx >= 0 ? kindPath.slice(idx + 1) : kindPath;
}

export function policyEvaluationOf(
  payload: EvidenceEnvelopePayload | null,
): PolicyEvaluation | null {
  if (!payload?.body) return null;
  const body = payload.body;
  const candidate =
    (body.policy as PolicyEvaluation | undefined) ??
    (body.evaluation as PolicyEvaluation | undefined);
  if (
    candidate &&
    typeof candidate === "object" &&
    (candidate.outcome === "allow" ||
      candidate.outcome === "deny" ||
      candidate.outcome === "error") &&
    typeof candidate.policyRef === "string"
  ) {
    return candidate;
  }
  return null;
}

export function policyOutcomeOf(
  decoded: EvidenceEnvelopePayload | null,
): PolicyOutcome | null {
  return policyEvaluationOf(decoded)?.outcome ?? null;
}

export function contentRefOf(payload: EvidenceEnvelopePayload | null): string | null {
  const ref = payload?.body?.contentRef;
  return typeof ref === "string" && ref.startsWith("bytes:sha256:") ? ref : null;
}

export function targetDisplayOf(payload: EvidenceEnvelopePayload | null): string {
  if (!payload?.body) return "—";
  const body = payload.body;
  if (typeof body.tool === "string") return body.tool;
  if (typeof body.model === "string") {
    const provider = typeof body.provider === "string" ? `${body.provider}/` : "";
    return `${provider}${body.model}`;
  }
  if (typeof body.call === "string") return truncateRef(body.call);
  if (typeof body.subject === "string") return truncateRef(body.subject);
  if (typeof body.about === "string") return truncateRef(body.about);
  if (typeof body.outcome === "string") return body.outcome;
  if (typeof body.reason === "string") return body.reason;
  return "—";
}

export function truncateRef(ref: string, keep = 12): string {
  if (!ref) return "";
  const idx = ref.lastIndexOf(":");
  if (idx >= 0 && ref.length - idx > keep + 4) {
    const prefix = ref.slice(0, idx + 1);
    const hash = ref.slice(idx + 1);
    return `${prefix}${hash.slice(0, keep)}…${hash.slice(-4)}`;
  }
  return ref.length > 28 ? `${ref.slice(0, 24)}…` : ref;
}

/**
 * Default client-pinned `trustedChain` anchor for bundle verification.
 * Never blindly fetched from `/v1/deployment` on the same gateway.
 */
export const DEFAULT_TRUSTED_CHAIN: string =
  (import.meta.env?.VITE_TRUSTED_CHAIN as string | undefined) ||
  "evidence:sha256:b1c6b5aa26e4205c79a3e44fd2e899e49c1920e4e37422166f739cf040fcdb20";
