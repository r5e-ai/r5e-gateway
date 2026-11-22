// Vite dev-mocks middleware (`VITE_DEV_MOCKS=1 pnpm dev`).
//
// Backed by:
//   1. Real signed `r5e-dev` Provenance v2 bundle (`fixtures/r5e-dev-snapshot.json`,
//      15 real signed records, zero fabricated signatures or hand-made session URNs)
//   2. Real `recurse_verify` Rust verifier binary for `POST /v1/evidence/verify`
//      (if unavailable, reports `incomplete: verifier_unavailable` — never fabricates `ok`)
//   3. Real `@cedar-policy/cedar-wasm@4.9.1` (`cedar-tool-use-eval.ts`) for `/v1/policies/*`
//
// Serves the camelCase Provenance v2 gateway API contract for offline local preview.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Plugin } from "vite";

import { evaluateToolUseCedar } from "./cedar-tool-use-eval";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT_PATH = resolve(__dirname, "fixtures/r5e-dev-snapshot.json");
const DEFAULT_VERIFY_BIN = resolve(
  __dirname,
  "../../../r5e-verify-rs/target/release/recurse_verify",
);
const R5E_DEV_CHAIN_REF =
  "evidence:sha256:b1c6b5aa26e4205c79a3e44fd2e899e49c1920e4e37422166f739cf040fcdb20";

function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

interface SignedEnvelope {
  payloadType: "application/vnd.r5e.provenance-evidence+json;v=2";
  payload: string;
  signatures: Array<{ keyid: string; sig: string }>;
}

interface RawBundle {
  format: "r5e.provenance-export/v2";
  scope: { query: unknown; at: Array<{ stream: string; seq: number; event: string }> };
  records: Array<{ ref: string; envelope: SignedEnvelope }>;
  blobs: Array<{ ref: string; base64: string; mediaType?: string }>;
  keys: Array<{ keyid: string; algorithm: string; bytes: string }>;
  seals: string[];
  checkpoints: string[];
  proofs: unknown[];
  publicationProofs: unknown[];
  omissions: Array<{ ref: string; reason: string; detail?: string }>;
}

interface IndexedRecord {
  ref: string;
  stream: string;
  seq: number;
  kind: string; // Full kind_path, e.g. "provenance.r5e.io/v2/ToolCall"
  capturedAt: string;
  actor: string | null;
  session: string | null;
  policyOutcome: "allow" | "deny" | "error" | null;
  target: string | null;
  envelope: SignedEnvelope;
  _decoded: Record<string, unknown>;
}

const RAW_SNAPSHOT: RawBundle = JSON.parse(readFileSync(SNAPSHOT_PATH, "utf8")) as RawBundle;
const BLOB_BY_REF = new Map(RAW_SNAPSHOT.blobs.map((b) => [b.ref, b]));

function extractRowMeta(decoded: Record<string, unknown>): {
  policyOutcome: "allow" | "deny" | "error" | null;
  target: string | null;
} {
  const body = (decoded.body ?? {}) as Record<string, unknown>;
  const pol = (body.policy ?? body.evaluation) as Record<string, unknown> | undefined;
  const rawOutcome = pol?.outcome;
  const policyOutcome =
    rawOutcome === "allow" || rawOutcome === "deny" || rawOutcome === "error"
      ? rawOutcome
      : null;

  const details =
    body.details && typeof body.details === "object"
      ? (body.details as Record<string, unknown>)
      : null;
  const target =
    typeof body.tool === "string"
      ? body.tool
      : typeof details?.tool === "string"
        ? details.tool
        : typeof details?.action === "string"
          ? details.action
          : typeof details?.target === "string"
            ? details.target
            : typeof body.model === "string"
              ? body.model
              : null;

  return { policyOutcome, target };
}

const SNAPSHOT_RECORDS: IndexedRecord[] = RAW_SNAPSHOT.records.map((r) => {
  const decoded = JSON.parse(
    Buffer.from(r.envelope.payload, "base64").toString("utf8"),
  ) as Record<string, unknown>;
  const apiVersion = String(decoded.apiVersion ?? "provenance.r5e.io/v2");
  const bareKind = String(decoded.kind ?? "Unknown");
  const { policyOutcome, target } = extractRowMeta(decoded);
  return {
    ref: r.ref,
    stream: String(decoded.stream ?? ""),
    seq: Number(decoded.seq ?? 1),
    kind: `${apiVersion}/${bareKind}`,
    capturedAt: String(decoded.capturedAt ?? ""),
    actor: typeof decoded.actor === "string" ? decoded.actor : null,
    session: typeof decoded.session === "string" ? decoded.session : null,
    policyOutcome,
    target,
    envelope: r.envelope,
    _decoded: decoded,
  };
});

const RECORD_BY_REF = new Map(SNAPSHOT_RECORDS.map((r) => [r.ref, r]));

const ACTIVE_CEDAR_SOURCE = `// Active CedarToolUseGate bundle on r5e-dev (Cedar 4.9.1)
@id("allow-default-tools")
permit(
  principal,
  action == Action::"invoke_tool",
  resource
);

@id("forbid-destructive-shell")
@reason("Destructive recursive delete commands are blocked by policy")
@suggested_alternative("Use a targeted file path without -rf")
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

const ACTIVE_POLICY_SHA = sha256(ACTIVE_CEDAR_SOURCE);
const ACTIVE_POLICY_REF = `bytes:sha256:${ACTIVE_POLICY_SHA}`;

interface MockDraft {
  id: string;
  name: string;
  cedarSource: string;
  sourceRecordRef: string | null;
  scopeMetadata: Record<string, unknown> | null;
  conditionMetadata: Array<{ kind: string; attr: string; value: unknown }>;
  createdAt: string;
  updatedAt: string;
}

const FIRST_TOOL_CALL = SNAPSHOT_RECORDS.find(
  (r) => r.kind === "provenance.r5e.io/v2/ToolCall",
);

const DRAFTS = new Map<string, MockDraft>([
  [
    "draft-1",
    {
      id: "draft-1",
      name: "Block destructive shell commands",
      cedarSource: ACTIVE_CEDAR_SOURCE,
      sourceRecordRef: FIRST_TOOL_CALL?.ref ?? null,
      scopeMetadata: { toolNames: ["shell"] },
      conditionMetadata: [],
      createdAt: "2026-11-22T07:00:00Z",
      updatedAt: "2026-11-22T07:00:00Z",
    },
  ],
]);

const MCP_SERVERS = [
  {
    id: "mcp-filesystem",
    name: "filesystem-mcp",
    publisher: "r5e-ai",
    trust_tier: "verified" as const,
    version: "1.4.2",
    transport: "stdio" as const,
    source: "github.com/r5e-ai/mcp-filesystem",
    description: "Workspace-scoped read/write filesystem MCP server with Cedar path guards.",
    capabilities: {
      tools: [
        { name: "read_file", description: "Read file contents within workspace root" },
        { name: "list_dir", description: "List directory entries" },
      ],
    },
    policy_constraints: {
      cedar_policies: [ACTIVE_CEDAR_SOURCE],
      rate_limit_per_minute: 120,
    },
    sbom: {
      format: "CycloneDX 1.5",
      digest: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      components: [{ name: "tokio", version: "1.43.0", license: "MIT", vulnerabilities: [] }],
    },
  },
];

function toListRow(r: IndexedRecord) {
  return {
    ref: r.ref,
    stream: r.stream,
    seq: r.seq,
    kind: r.kind,
    capturedAt: r.capturedAt,
    actor: r.actor,
    session: r.session,
    policyOutcome: r.policyOutcome,
    target: r.target,
    envelope: r.envelope,
  };
}

function matchesSharedFilters(
  r: IndexedRecord,
  params: URLSearchParams,
  ignore?: "kind" | "policyOutcome" | "target",
): boolean {
  const kind = ignore === "kind" ? "" : params.get("kind")?.trim() ?? "";
  const policyOutcome =
    ignore === "policyOutcome" ? "" : params.get("policyOutcome")?.trim() ?? "";
  const target = ignore === "target" ? "" : params.get("target")?.trim() ?? "";
  const actor = params.get("actor")?.trim() ?? "";
  const session = params.get("session")?.trim() ?? "";
  const since = params.get("since")?.trim() ?? "";
  const until = params.get("until")?.trim() ?? "";
  const q = params.get("q")?.trim().toLowerCase() ?? "";

  if (kind && r.kind !== kind) return false;
  if (policyOutcome && r.policyOutcome !== policyOutcome) return false;
  if (target && r.target !== target) return false;
  if (actor && r.actor !== actor) return false;
  if (session && r.session !== session) return false;
  if (since) {
    const sinceMs = Date.parse(since);
    const capMs = Date.parse(r.capturedAt);
    if (Number.isFinite(sinceMs) && Number.isFinite(capMs)) {
      if (capMs < sinceMs) return false;
    } else if (r.capturedAt < since) {
      return false;
    }
  }
  if (until) {
    const untilMs = Date.parse(until);
    const capMs = Date.parse(r.capturedAt);
    if (Number.isFinite(untilMs) && Number.isFinite(capMs)) {
      if (capMs >= untilMs) return false;
    } else if (r.capturedAt >= until) {
      return false;
    }
  }
  if (q) {
    const hay = [r.actor ?? "", r.session ?? "", r.kind, r.target ?? "", r.ref]
      .join(" ")
      .toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function runRealVerifier(bundle: Record<string, unknown>, trustedChain?: string) {
  const verifyBin = process.env.R5E_VERIFY_RS_BIN || DEFAULT_VERIFY_BIN;
  if (!existsSync(verifyBin)) {
    const records = Array.isArray(bundle.records)
      ? (bundle.records as Array<{ ref: string }>)
      : [];
    const findings = records.map((r) => ({
      layer: 1 as const,
      subject: r.ref,
      check: "signature",
      result: "incomplete" as const,
      code: "verifier_unavailable",
      about: null,
    }));
    return {
      format: "r5e.provenance-verify-report/v2",
      summary: { ok: 0, failed: 0, incomplete: findings.length },
      findings,
    };
  }

  const workDir = mkdtempSync(join(tmpdir(), "r5e-ui-verify-"));
  const bundlePath = join(workDir, "bundle.json");
  const reportPath = join(workDir, "report.json");
  try {
    writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
    const args = [bundlePath, "--report", reportPath, "--allow-incomplete"];
    if (trustedChain) {
      args.push("--chain", trustedChain);
    }
    try {
      execFileSync(verifyBin, args, { stdio: "pipe", timeout: 10_000 });
    } catch {
      // `recurse_verify` exits non-zero when findings include failures,
      // but still writes the complete structured JSON report to `--report`.
    }
    if (existsSync(reportPath)) {
      return JSON.parse(readFileSync(reportPath, "utf8"));
    }
    throw new Error("Verifier did not emit a report");
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

function hydrateToolCall(rec: IndexedRecord) {
  const body = (rec._decoded.body ?? {}) as Record<string, unknown>;
  const contentRef = typeof body.contentRef === "string" ? body.contentRef : null;
  const blob = contentRef ? BLOB_BY_REF.get(contentRef) : undefined;
  const details = (body.details ?? {}) as Record<string, unknown>;
  const actor = String(rec._decoded.actor ?? "urn:r5e:user:anonymous");
  const tool = typeof body.tool === "string" ? body.tool : "exec";

  let toolArgs: Record<string, unknown> | undefined;
  if (blob) {
    try {
      toolArgs = JSON.parse(Buffer.from(blob.base64, "base64").toString("utf8")) as Record<
        string,
        unknown
      >;
    } catch {
      toolArgs = undefined;
    }
  }

  return {
    missingBlob: Boolean(contentRef && !blob),
    input: {
      principal: {
        id: actor.replace(/^urn:r5e:(user|workload):/, ""),
        kind: actor.includes(":workload:") ? ("service_account" as const) : ("obo_human" as const),
        groups: ["eng"],
      },
      action: 'Action::"invoke_tool"' as const,
      resource: { tool },
      context: {
        model: String(details.model ?? "claude-sonnet-4-5"),
        tenant: String(details.tenant ?? "r5e-dev"),
        sessionId: String(rec.session ?? "urn:r5e:session:r5e-dev:unknown"),
        upstreamDomain: String(details.upstream_domain ?? "api.anthropic.com"),
        transport: "https_sse" as const,
        estimatedCompletionTokens: 420,
        ...(toolArgs ? { toolArgs } : {}),
      },
    },
  };
}

export function devMocksPlugin(): Plugin {
  return {
    name: "r5e-v2-dev-mocks",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        const url = new URL(req.url ?? "/", "http://localhost");
        const pathname = url.pathname;
        const method = (req.method ?? "GET").toUpperCase();

        // Auth
        if (method === "GET" && pathname === "/v1/auth/me") {
          return sendJson(res, 200, {
            principal_subject: "user_01KR1ZGCJHV0AZ5793SQWNAGST",
            display_name: "operator@r5e.dev",
            email: "operator@r5e.dev",
            recurse_role: "platform_operator",
            tenant_id: "r5e-dev",
            browser_session_id: "dev-mock-session",
            session_expires_at: "2026-11-23T00:00:00Z",
            session_idle_timeout_at: "2026-11-22T09:00:00Z",
          });
        }

        // Deployment metadata (from real r5e-dev snapshot)
        if (method === "GET" && pathname === "/v1/deployment") {
          return sendJson(res, 200, {
            state: "claimed",
            chain: R5E_DEV_CHAIN_REF,
            bootstrapKey: RAW_SNAPSHOT.keys[0],
          });
        }

        // GET /v1/evidence/records (keyset cursor on capturedAt,ref; open-string full kind path; 400 on unknown params)
        if (method === "GET" && pathname === "/v1/evidence/records") {
          const allowedParams = new Set([
            "kind",
            "policyOutcome",
            "target",
            "q",
            "actor",
            "session",
            "since",
            "until",
            "limit",
            "cursor",
          ]);
          for (const key of url.searchParams.keys()) {
            if (!allowedParams.has(key)) {
              return sendJson(res, 400, {
                error: "ERR_BAD_REQUEST",
                message: `unknown query parameter: ${key}`,
              });
            }
          }
          const limit = Math.min(
            200,
            Math.max(1, Number.parseInt(url.searchParams.get("limit") ?? "50", 10) || 50),
          );

          const filtered = SNAPSHOT_RECORDS.filter((r) =>
            matchesSharedFilters(r, url.searchParams),
          ).sort((a, b) => {
            if (a.capturedAt !== b.capturedAt) return a.capturedAt < b.capturedAt ? 1 : -1;
            return a.ref < b.ref ? 1 : -1;
          });

          return sendJson(res, 200, {
            records: filtered.slice(0, limit).map(toListRow),
            cursor: null,
          });
        }

        // GET /v1/evidence/facets (disjunctive counts)
        if (method === "GET" && pathname === "/v1/evidence/facets") {
          const total = SNAPSHOT_RECORDS.filter((r) =>
            matchesSharedFilters(r, url.searchParams),
          ).length;

          const countAxis = (
            axis: "kind" | "policyOutcome" | "target",
            extract: (r: IndexedRecord) => string | null,
          ) => {
            const map = new Map<string, number>();
            for (const r of SNAPSHOT_RECORDS) {
              if (!matchesSharedFilters(r, url.searchParams, axis)) continue;
              const v = extract(r);
              if (v) map.set(v, (map.get(v) ?? 0) + 1);
            }
            return Array.from(map.entries())
              .sort((a, b) => b[1] - a[1])
              .map(([value, count]) => ({ value, count }));
          };

          return sendJson(res, 200, {
            total,
            facets: {
              kind: countAxis("kind", (r) => r.kind),
              policyOutcome: countAxis("policyOutcome", (r) => r.policyOutcome),
              target: countAxis("target", (r) => r.target),
            },
          });
        }

        // GET /v1/evidence/histogram (`since` & `until` required; `buckets` default 60 max 240)
        if (method === "GET" && pathname === "/v1/evidence/histogram") {
          const sinceStr = url.searchParams.get("since")?.trim() ?? "";
          const untilStr = url.searchParams.get("until")?.trim() ?? "";
          const sinceMs = Date.parse(sinceStr);
          const untilMs = Date.parse(untilStr);
          if (!Number.isFinite(sinceMs) || !Number.isFinite(untilMs) || untilMs <= sinceMs) {
            return sendJson(res, 400, {
              error: "ERR_BAD_REQUEST",
              message: "since and until RFC 3339 timestamps are required with until > since",
            });
          }
          const bucketCount = Math.min(
            240,
            Math.max(1, Number.parseInt(url.searchParams.get("buckets") ?? "60", 10) || 60),
          );
          const spanMs = untilMs - sinceMs;
          const bucketMs = Math.max(1, spanMs / bucketCount);
          const bucketSeconds = bucketMs / 1000;

          const buckets = Array.from({ length: bucketCount }, (_, i) => ({
            start: new Date(sinceMs + i * bucketMs).toISOString(),
            count: 0,
            byOutcome: {} as Record<string, number>,
          }));

          for (const r of SNAPSHOT_RECORDS) {
            if (!matchesSharedFilters(r, url.searchParams)) continue;
            const ms = Date.parse(r.capturedAt);
            if (!Number.isFinite(ms) || ms < sinceMs || ms >= untilMs) continue;
            const idx = Math.max(
              0,
              Math.min(bucketCount - 1, Math.floor((ms - sinceMs) / bucketMs)),
            );
            const b = buckets[idx]!;
            b.count += 1;
            if (r.policyOutcome) {
              b.byOutcome[r.policyOutcome] = (b.byOutcome[r.policyOutcome] ?? 0) + 1;
            }
          }

          return sendJson(res, 200, {
            since: sinceStr,
            until: untilStr,
            bucketSeconds,
            buckets,
          });
        }

        // GET /v1/evidence/records/:ref/content/:bytes_ref (octet-stream download + nosniff + X-R5E-Content-Ref)
        const contentMatch = /^\/v1\/evidence\/records\/([^/]+)\/content\/([^/]+)$/.exec(
          pathname,
        );
        if (method === "GET" && contentMatch && contentMatch[2]) {
          const bytesRef = decodeURIComponent(contentMatch[2]);
          const blob = BLOB_BY_REF.get(bytesRef);
          if (!blob) return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/octet-stream");
          res.setHeader("Cache-Control", "no-store, private");
          res.setHeader("X-Content-Type-Options", "nosniff");
          res.setHeader("X-R5E-Content-Ref", bytesRef);
          res.setHeader(
            "Content-Disposition",
            `attachment; filename="${bytesRef.replace(/[:/]/g, "_")}"`,
          );
          res.end(Buffer.from(blob.base64, "base64"));
          return;
        }

        // Single evidence record
        if (method === "GET" && pathname.startsWith("/v1/evidence/records/")) {
          const ref = decodeURIComponent(pathname.slice("/v1/evidence/records/".length));
          const rec = RECORD_BY_REF.get(ref);
          if (!rec) return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
          return sendJson(res, 200, { ...toListRow(rec), sealRef: null });
        }

        // Session evidence records
        if (method === "GET" && pathname.startsWith("/v1/evidence/sessions/")) {
          const sessionId = decodeURIComponent(
            pathname.slice("/v1/evidence/sessions/".length),
          );
          const recs = SNAPSHOT_RECORDS.filter((r) => r.session === sessionId);
          if (recs.length === 0) return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
          return sendJson(res, 200, {
            session: sessionId,
            records: recs.map(toListRow),
          });
        }

        // Per-session export (`POST /v1/evidence/export`) returning real signed r5e-dev bundle
        if (method === "POST" && pathname === "/v1/evidence/export") {
          const body = await readJsonBody(req);
          const sessionId = typeof body.session === "string" ? body.session : "";
          const hasSession = SNAPSHOT_RECORDS.some((r) => r.session === sessionId);
          if (!hasSession) {
            return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
          }
          if (body.content === false) {
            return sendJson(res, 200, {
              ...RAW_SNAPSHOT,
              blobs: [],
              omissions: RAW_SNAPSHOT.blobs.map((b) => ({
                ref: b.ref,
                reason: "withheld",
                detail: "content=false",
              })),
            });
          }
          return sendJson(res, 200, RAW_SNAPSHOT);
        }

        // Real verification via `recurse_verify` (`POST /v1/evidence/verify`)
        if (method === "POST" && pathname === "/v1/evidence/verify") {
          const body = await readJsonBody(req);
          if (!body.bundle || typeof body.bundle !== "object") {
            return sendJson(res, 400, { error: "ERR_BAD_REQUEST" });
          }
          const trustedChain =
            typeof body.trustedChain === "string" ? body.trustedChain : undefined;
          return sendJson(
            res,
            200,
            runRealVerifier(body.bundle as Record<string, unknown>, trustedChain),
          );
        }

        // Read-only active policy (`GET /v1/policies/active`)
        if (method === "GET" && pathname === "/v1/policies/active") {
          return sendJson(res, 200, {
            bundleRef: ACTIVE_POLICY_REF,
            source: ACTIVE_CEDAR_SOURCE,
            sourceMode: "filesystem",
            sourceRef: "/policy/bundle.cedar",
            activatedAt: "2026-11-22T06:00:00Z",
          });
        }

        // Phase 2: Policy simulate (`POST /v1/policies/simulate`)
        if (method === "POST" && pathname === "/v1/policies/simulate") {
          const body = await readJsonBody(req);
          const result = evaluateToolUseCedar({
            cedarSource: String(body.cedarSource ?? ""),
            principal: (body.principal as {
              id: string;
              kind?: "obo_human" | "service_account" | "autonomous";
              groups?: string[];
            }) ?? { id: "anonymous", kind: "obo_human", groups: [] },
            action: String(body.action ?? 'Action::"invoke_tool"'),
            resource: (body.resource as { tool: string }) ?? { tool: "" },
            context: (body.context as Record<string, unknown>) ?? {},
          });
          if (!result.ok && result.parseError) {
            return sendJson(res, 400, {
              error: "cedar_parse_error",
              error_description: result.parseError,
            });
          }
          return sendJson(res, 200, result);
        }

        // Phase 2: Policy replay (`POST /v1/policies/replay`)
        if (method === "POST" && pathname === "/v1/policies/replay") {
          const body = await readJsonBody(req);
          const ref = String(body.ref ?? "");
          const rec = RECORD_BY_REF.get(ref);
          if (!rec) {
            return sendJson(res, 404, {
              error: "ERR_NOT_FOUND",
              error_description: `Record ${ref} not found in snapshot.`,
            });
          }
          const recBody = (rec._decoded.body ?? {}) as Record<string, unknown>;
          const pol = (recBody.policy ?? recBody.evaluation ?? {}) as Record<string, unknown>;
          const originalOutcome =
            pol.outcome === "allow" || pol.outcome === "deny" || pol.outcome === "error"
              ? pol.outcome
              : "allow";
          const recordedPolicyRef =
            typeof pol.policyRef === "string" ? pol.policyRef : ACTIVE_POLICY_REF;

          const against =
            body.replayedAgainst === "active" || body.replayedAgainst === "recorded"
              ? body.replayedAgainst
              : "draft";
          const cedarToRun =
            against === "draft" && typeof body.cedarSource === "string"
              ? body.cedarSource
              : ACTIVE_CEDAR_SOURCE;

          const { missingBlob, input } = hydrateToolCall(rec);
          if (missingBlob) {
            return sendJson(res, 200, {
              ref: rec.ref,
              originalOutcome,
              replayedOutcome: "incomplete",
              incompleteReason:
                "contentRef blob is unavailable or disposed (HTTP 410); tool_args unavailable for deterministic replay.",
              replayedAgainst: against,
              recordedPolicyRef,
              recordedCedarSource: ACTIVE_CEDAR_SOURCE,
              activePolicyRef: ACTIVE_POLICY_REF,
              activeCedarSource: ACTIVE_CEDAR_SOURCE,
              determiningPolicies: [],
              ruleId: null,
              reason: "Incomplete replay — content blob unavailable",
              suggestedAlternative: null,
              hydratedInput: input,
            });
          }

          const evalRes = evaluateToolUseCedar({
            cedarSource: cedarToRun,
            principal: input.principal,
            action: input.action,
            resource: input.resource,
            context: input.context,
          });
          if (!evalRes.ok && evalRes.parseError) {
            return sendJson(res, 400, {
              error: "cedar_parse_error",
              error_description: evalRes.parseError,
            });
          }

          return sendJson(res, 200, {
            ref: rec.ref,
            originalOutcome,
            replayedOutcome: evalRes.decision,
            incompleteReason: null,
            replayedAgainst: against,
            recordedPolicyRef,
            recordedCedarSource: ACTIVE_CEDAR_SOURCE,
            activePolicyRef: ACTIVE_POLICY_REF,
            activeCedarSource: ACTIVE_CEDAR_SOURCE,
            determiningPolicies: evalRes.determiningPolicies,
            ruleId: evalRes.ruleId,
            reason: evalRes.reason,
            suggestedAlternative: evalRes.suggestedAlternative,
            hydratedInput: input,
          });
        }

        // Phase 2: Policy drafts CRUD + from-record + dry-run (`/v1/policies/drafts*`)
        if (method === "GET" && pathname === "/v1/policies/drafts") {
          return sendJson(res, 200, { drafts: Array.from(DRAFTS.values()) });
        }

        if (method === "POST" && pathname === "/v1/policies/drafts") {
          const body = await readJsonBody(req);
          const id = `draft-${DRAFTS.size + 1}`;
          const now = new Date().toISOString();
          const draft: MockDraft = {
            id,
            name: String(body.name ?? "Untitled draft"),
            cedarSource: String(body.cedarSource ?? ACTIVE_CEDAR_SOURCE),
            sourceRecordRef:
              typeof body.sourceRecordRef === "string" ? body.sourceRecordRef : null,
            scopeMetadata: (body.scopeMetadata as Record<string, unknown>) ?? null,
            conditionMetadata: Array.isArray(body.conditionMetadata)
              ? (body.conditionMetadata as MockDraft["conditionMetadata"])
              : [],
            createdAt: now,
            updatedAt: now,
          };
          DRAFTS.set(id, draft);
          return sendJson(res, 201, draft);
        }

        if (method === "POST" && pathname === "/v1/policies/drafts/from-record") {
          const body = await readJsonBody(req);
          const ref = String(body.ref ?? "");
          const rec = RECORD_BY_REF.get(ref);
          const tool =
            rec && typeof (rec._decoded.body as Record<string, unknown>)?.tool === "string"
              ? String((rec._decoded.body as Record<string, unknown>).tool)
              : "shell";
          const decision = body.decision === "permit" ? "permit" : "forbid";
          const id = `draft-${DRAFTS.size + 1}`;
          const now = new Date().toISOString();
          const cedar =
            decision === "forbid"
              ? `permit(principal, action == Action::"invoke_tool", resource);\n\n@id("draft-from-record")\nforbid(\n  principal,\n  action == Action::"invoke_tool",\n  resource == ToolUse::"${tool}"\n);\n`
              : `@id("draft-from-record")\npermit(\n  principal,\n  action == Action::"invoke_tool",\n  resource == ToolUse::"${tool}"\n);\n`;
          const draft: MockDraft = {
            id,
            name: `Draft from ${tool} (${ref.slice(-6)})`,
            cedarSource: cedar,
            sourceRecordRef: ref,
            scopeMetadata: { toolNames: [tool] },
            conditionMetadata: [],
            createdAt: now,
            updatedAt: now,
          };
          DRAFTS.set(id, draft);
          return sendJson(res, 201, draft);
        }

        if (
          pathname.startsWith("/v1/policies/drafts/") &&
          pathname.endsWith("/dry-run") &&
          method === "POST"
        ) {
          const id = decodeURIComponent(
            pathname.slice("/v1/policies/drafts/".length, -"/dry-run".length),
          );
          const body = await readJsonBody(req);
          const draft = DRAFTS.get(id);
          const cedarSource =
            typeof body.cedarSource === "string"
              ? body.cedarSource
              : draft?.cedarSource ?? ACTIVE_CEDAR_SOURCE;

          const toolCalls = SNAPSHOT_RECORDS.filter(
            (r) =>
              r.kind === "provenance.r5e.io/v2/ToolCall" ||
              r.kind === "provenance.r5e.io/v2/PolicyDecision",
          );

          const samples = {
            matchesIntent: [] as unknown[],
            unintended: [] as unknown[],
            wouldHaveAllowed: [] as unknown[],
            noChange: [] as unknown[],
          };
          let incompleteCount = 0;

          for (const tc of toolCalls) {
            const recBody = (tc._decoded.body ?? {}) as Record<string, unknown>;
            const pol = (recBody.policy ?? recBody.evaluation ?? {}) as Record<
              string,
              unknown
            >;
            const orig =
              pol.outcome === "allow" || pol.outcome === "deny" || pol.outcome === "error"
                ? pol.outcome
                : "allow";
            const { missingBlob, input } = hydrateToolCall(tc);
            const baseSample = {
              ref: tc.ref,
              tool: input.resource.tool,
              actor: tc.actor ?? "",
              capturedAt: tc.capturedAt,
              originalOutcome: orig,
            };

            if (missingBlob) {
              incompleteCount++;
              continue;
            }

            const evalRes = evaluateToolUseCedar({
              cedarSource,
              principal: input.principal,
              action: input.action,
              resource: input.resource,
              context: input.context,
            });
            if (!evalRes.ok && evalRes.parseError) {
              return sendJson(res, 400, {
                error: "cedar_parse_error",
                error_description: evalRes.parseError,
              });
            }

            const sample = { ...baseSample, draftOutcome: evalRes.decision };
            if (orig === evalRes.decision) {
              samples.noChange.push(sample);
            } else if (orig === "allow" && evalRes.decision === "deny") {
              samples.matchesIntent.push(sample);
            } else if (orig === "deny" && evalRes.decision === "allow") {
              samples.wouldHaveAllowed.push(sample);
            } else {
              samples.unintended.push(sample);
            }
          }

          return sendJson(res, 200, {
            draftId: id,
            totalEvaluated: toolCalls.length,
            incompleteCount,
            matchesIntent: samples.matchesIntent.length,
            unintended: samples.unintended.length,
            wouldHaveAllowed: samples.wouldHaveAllowed.length,
            noChange: samples.noChange.length,
            samples,
          });
        }

        if (pathname.startsWith("/v1/policies/drafts/")) {
          const id = decodeURIComponent(pathname.slice("/v1/policies/drafts/".length));
          const existing = DRAFTS.get(id);
          if (method === "GET") {
            if (!existing) return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
            return sendJson(res, 200, existing);
          }
          if (method === "PATCH") {
            if (!existing) return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
            const body = await readJsonBody(req);
            const updated: MockDraft = {
              ...existing,
              name: typeof body.name === "string" ? body.name : existing.name,
              cedarSource:
                typeof body.cedarSource === "string"
                  ? body.cedarSource
                  : existing.cedarSource,
              scopeMetadata:
                body.scopeMetadata !== undefined
                  ? (body.scopeMetadata as Record<string, unknown> | null)
                  : existing.scopeMetadata,
              conditionMetadata: Array.isArray(body.conditionMetadata)
                ? (body.conditionMetadata as MockDraft["conditionMetadata"])
                : existing.conditionMetadata,
              updatedAt: new Date().toISOString(),
            };
            DRAFTS.set(id, updated);
            return sendJson(res, 200, updated);
          }
          if (method === "DELETE") {
            DRAFTS.delete(id);
            res.statusCode = 204;
            res.end();
            return;
          }
        }

        // MCP Registry
        if (method === "GET" && pathname === "/v1/mcp/registry") {
          return sendJson(res, 200, {
            version: "1.0.0",
            generated_at: "2026-11-22T07:00:00Z",
            entries: MCP_SERVERS,
          });
        }
        if (pathname.startsWith("/v1/mcp/registry/")) {
          const id = decodeURIComponent(pathname.slice("/v1/mcp/registry/".length));
          const idx = MCP_SERVERS.findIndex((s) => s.id === id);
          if (idx < 0) return sendJson(res, 404, { error: "ERR_NOT_FOUND" });
          if (method === "GET") {
            return sendJson(res, 200, MCP_SERVERS[idx]);
          }
          if (method === "PATCH") {
            const body = await readJsonBody(req);
            if (typeof body.trust_tier === "string") {
              (MCP_SERVERS[idx] as { trust_tier: string }).trust_tier = body.trust_tier;
            }
            return sendJson(res, 200, MCP_SERVERS[idx]);
          }
        }

        next();
      });
    },
  };
}
