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
  policyOutcome?: PolicyOutcome | null;
  target?: string | null;
  reason?: string | null;
  envelope: SignedEvidenceEnvelope;
  /** Only populated on single-record detail (`GET /v1/evidence/records/:ref`), never on list rows. */
  sealRef?: string | null;
}

export const ACTIVITY_KINDS: ReadonlyArray<string> = [
  "provenance.r5e.io/v2/ModelCall",
  "provenance.r5e.io/v2/ModelResponse",
  "provenance.r5e.io/v2/ToolCall",
  "provenance.r5e.io/v2/ToolResult",
  "provenance.r5e.io/v2/PolicyDecision",
  "provenance.r5e.io/v2/SessionOpened",
  "provenance.r5e.io/v2/SessionClosed",
  "provenance.r5e.io/v2/Disclosure",
  "provenance.r5e.io/v2/PayloadDisposition",
  "provenance.r5e.io/v2/RetentionHold",
  "provenance.r5e.io/v2/RetentionHoldRelease",
];

export const ACTIVITY_KIND_PARAM = ACTIVITY_KINDS.join(",");

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

export interface EvidenceHistogramBucket {
  start: string;
  count: number;
  byOutcome?: Record<string, number>;
}

export interface EvidenceHistogramResponse {
  since: string;
  until: string;
  bucketSeconds: number;
  buckets: EvidenceHistogramBucket[];
}

export interface EvidenceFacetBucket {
  value: string;
  count: number;
}

export interface EvidenceFacetsResponse {
  total: number;
  facets: {
    kind: EvidenceFacetBucket[];
    policyOutcome: EvidenceFacetBucket[];
    target: EvidenceFacetBucket[];
    reason?: EvidenceFacetBucket[];
  };
}

export interface TargetDisplay {
  primary: string;
  secondary?: string;
}

export function reasonOf(payload: EvidenceEnvelopePayload | null): string | null {
  if (!payload?.body) return null;
  const evalObj = policyEvaluationOf(payload);
  if (evalObj?.reason && evalObj.reason.trim().length > 0) {
    return evalObj.reason.trim();
  }
  return null;
}

/**
 * Matches the server's `target` label extraction 1-to-1:
 * `body.tool || body.details.target || provider/model || model`.
 */
export function serverTargetOf(payload: EvidenceEnvelopePayload | null): string | null {
  if (!payload?.body) return null;
  const body = payload.body;
  if (typeof body.tool === "string" && body.tool.trim().length > 0) {
    return body.tool.trim();
  }
  const details =
    body.details && typeof body.details === "object"
      ? (body.details as Record<string, unknown>)
      : null;
  if (typeof details?.target === "string" && details.target.trim().length > 0) {
    return details.target.trim();
  }
  if (typeof body.model === "string" && body.model.trim().length > 0) {
    const provider =
      typeof body.provider === "string" && body.provider.trim().length > 0
        ? `${body.provider.trim()}/`
        : "";
    return `${provider}${body.model.trim()}`;
  }
  return null;
}

export function targetDetailOf(payload: EvidenceEnvelopePayload | null): TargetDisplay {
  const canonical = serverTargetOf(payload);
  if (canonical) return { primary: canonical };
  return { primary: "—" };
}

export function targetDisplayOf(payload: EvidenceEnvelopePayload | null): string {
  return targetDetailOf(payload).primary;
}

export function safeDecodeUri(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/**
 * Decodes URL-encoded URNs into a concise operator-readable identity:
 *   - `urn:r5e:principal:r5e-dev:alice%40example.test` -> `alice@example.test`
 *   - `urn:r5e:user:alice%40example.test` -> `alice@example.test`
 *   - `urn:r5e:workload:r5e-dev:edtech-tutor:97e9adbf4d3a` -> `edtech-tutor`
 */
export function formatIdentityDisplay(raw: string | null | undefined): string {
  if (!raw) return "—";
  const decoded = safeDecodeUri(raw);
  if (!decoded.startsWith("urn:r5e:")) return decoded;
  const parts = decoded.slice("urn:r5e:".length).split(":");
  const kind = parts[0];
  if ((kind === "principal" || kind === "user") && parts.length >= 2) {
    return parts[parts.length - 1] || decoded;
  }
  if (kind === "workload" && parts.length >= 3) {
    return parts[2] || parts[parts.length - 1] || decoded;
  }
  if (kind === "student" && parts.length >= 3) {
    return `student:${truncateRef(parts.slice(2).join(":"), 8)}`;
  }
  return parts.join(":");
}

export function formatActorShort(actor: string | null | undefined): string {
  return formatIdentityDisplay(actor);
}

export type TimeDisplayMode = "local" | "utc";

export function formatUtcTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    if (!Number.isFinite(d.getTime())) return iso;
    return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
  } catch {
    return iso;
  }
}

export function formatTimestamp(
  iso: string,
  mode: TimeDisplayMode,
  nowMs = Date.now(),
): { display: string; utc: string } {
  const utc = formatUtcTimestamp(iso);
  if (mode === "utc") return { display: utc, utc };
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return { display: iso, utc };
  const diffMs = nowMs - ms;
  if (diffMs >= 0 && diffMs < 24 * 60 * 60_000) {
    const secs = Math.floor(diffMs / 1000);
    if (secs < 45) return { display: "just now", utc };
    const mins = Math.floor(secs / 60);
    if (mins < 60) return { display: `${mins} min ago`, utc };
    const hrs = Math.floor(mins / 60);
    return { display: `${hrs} hr ago`, utc };
  }
  try {
    const formatted = new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(new Date(ms));
    return { display: formatted, utc };
  } catch {
    return { display: utc, utc };
  }
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
