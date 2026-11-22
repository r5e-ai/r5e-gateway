# Recurse Enterprise — Architecture Overview (for Recurse engineers)

**Audience**: new Recurse engineers, onboarding in week 1.
**Scope**: orientation for Feature 001 Phase-1. Deep references live in
`specs/001-api-jido-foundations/`.
**Authority**: Constitution v1.3.0 (`.specify/memory/constitution.md`), Feature 001 spec
(`specs/001-api-jido-foundations/spec.md`).

Read this once. After that, you'll mostly be in the three matrices this document cross-
references, plus the FR list in the spec.

---

## 1. Two OTP applications, one BEAM node

Per **FR-034** and **Constitution Principle I**, Recurse Phase-1 ships a **single codebase
with two OTP applications** (`:recurse_gateway`, `:recurse_runtime`) and a small set of
shared support apps (`:recurse_shared`, `:recurse_providers`). In every Governance-tier
deployment (Managed SaaS, VPC Runner, Air-Gapped Appliance) they run **co-located on one BEAM
node per customer** — single-BEAM-per-customer is a hard invariant (FR-019). There is
**no in-BEAM multi-tenancy**. A customer's tenant identity is a fixed deployment-config value.

The split is **functional, not networked**. Both apps share the BEAM, share `Phoenix.PubSub`,
share an `Ecto.Repo`, and share the code tree. The split exists for two reasons:

1. **Supervision hygiene**: Gateway is hot-path / restart-with-care; Runtime owns batch
   pipelines and long-lived processes with different restart semantics.
2. **Shape variance** (FR-050): the **Standalone AI Gateway** shape ships the Gateway app
   alone — no Runtime, no netns, no Broadway ledger pipeline. Separate OTP apps make that
   shape drop-in trivial; you don't start `:recurse_runtime` at release time.

**Rule of thumb**: if your subsystem needs to be fast and stateless-per-request, it lives in
`:recurse_gateway`. If it owns durable state or batch pipelines, it lives in
`:recurse_runtime`. If it's both (hot-path read, async write), it's
`gateway-with-runtime-delegation` — look up your placement in
`specs/001-api-jido-foundations/contracts/gateway_runtime_matrix.md` (Deliverable D, the
authoritative subsystem → app mapping per FR-035).

The directory layout mirrors this split:

```
apps/
  recurse_shared/       # types, ULID, IdentityContext, attestation structs (FR-026, FR-021)
  recurse_providers/    # seven Provider Interface behaviours (FR-003)
  recurse_gateway/      # :recurse_gateway OTP app — Data/Control/Governance/Audit planes
  recurse_runtime/      # :recurse_runtime OTP app — sessions, netns, ledger pipeline
  recurse_integration/  # cross-app integration tests
native/
  recurse_cedar/        # Rustler NIF for Cedar policy eval (FR-039 / Deliverable O)
```

Within the Gateway app, plane boundaries live at the top of the module tree:

```
apps/recurse_gateway/lib/recurse_gateway/
  planes/
    data/         # OpenAI-compat + MCP SSE (FR-043 accept path)
    control/      # orchestration, spawn, observability
    governance/   # policy authoring, simulate, blast-radius (FR-049)
    audit/        # receipt query, payload broker (FR-030), export evidence (FR-048)
```

Any new HTTP surface lands under one of these four subtrees. If you're unsure which, read
the plane taxonomy (§3 below).

---

## 2. Deployment shapes — Governance vs. Standalone

Per **FR-050**, Phase 1 ships multiple deployment shapes from the same codebase:

| Shape | Gateway app | Runtime app | netns enforcement | Completeness |
|-------|-------------|-------------|--------------------|--------------|
| **Managed SaaS** (AWS EKS, Recurse-hosted, BYOC containers) | yes | yes | yes (kernel-level, Principle II) | `complete` |
| **VPC Runner** (customer AWS account) | yes | yes | yes | `complete` |
| **Air-Gapped Appliance** | yes | yes | yes | `complete` |
| **Standalone AI Gateway** (on-prem, LLM-call-audit-only) | yes | **no** | no (customer routes traffic to Gateway by DNS/config) | `advisory` |

In Standalone:

- Runtime is absent. Session lifecycle, interim commits, and global-ledger pipeline do not
  run. The Gateway emits **per-call attestations** against a **per-request local CAS**
  (`gateway-stub` cells in the Matrix) and ships them to the ledger synchronously.
- Completeness is `advisory`: without netns, Recurse cannot claim kernel-level observation of
  every egress — we attest what traverses the Gateway, and the customer-configuration decides
  what that is. The FR-053 **Standalone Identity Broker** supplies a lightweight IdP so the
  Standalone shape still produces IdentityContexts without requiring a full customer IdP
  integration on day one.
- Discovery-to-Policy (FR-049.2, Wiz pattern) **ships in Standalone** — it is the shape's
  primary commercial wedge.

The shape-specific behavior is **response-content level, not path level** (FR-008). All
endpoints have the same path / method / request shape across shapes; differences surface via
response content (e.g., `tier_completeness_advisory`), endpoint activation state (FR-024),
or tier-scoped sub-fields. Clients written against Governance tiers work unmodified against
Standalone.

---

## 3. Plane taxonomy (Data / Control / Governance / Audit)

All public HTTP surface lives in one of four **API Planes** per FR-001. Planes are not
security boundaries — they are **reviewer shorthand** for what a given endpoint is for. Keep
them crisp.

- **Data Plane** — the hot path the agent actually calls during a turn. OpenAI-compatible
  chat completions and MCP SSE are Data Plane. Latency is user-visible. Every Data Plane
  request terminates in exactly one signed attestation per FR-021 / FR-026. Lives in
  `apps/recurse_gateway/lib/recurse_gateway/planes/data/`.

- **Control Plane** — operator orchestration: session spawn, readyz, operational metrics,
  tier configuration introspection (FR-015). Latency is tolerable; security posture is
  fail-closed on anything that affects Data Plane integrity (see `failure_matrix.md`). Lives
  in `apps/recurse_gateway/lib/recurse_gateway/planes/control/`.

- **Governance Plane** — the policy-author surfaces per **FR-049**: Cedar Playground
  simulate API, Discovery-to-Policy generator, blast-radius simulation. None of these mutate
  production state (blast-radius is a read-only replay against historical attestations).
  Lives in `apps/recurse_gateway/lib/recurse_gateway/planes/governance/`.

- **Audit Plane** — the three auditor surfaces per **FR-048**: SIEM Log Forwarder, Export
  Evidence zip builder, and CLI Verifier artifacts. Plus the FR-030 Audit Payload Broker.
  Audit Plane is the degradable path — fail-open policy is acceptable here because the
  underlying receipts are already on the ledger. Lives in
  `apps/recurse_gateway/lib/recurse_gateway/planes/audit/`.

Rule: every endpoint belongs to exactly one plane. When unsure, ask "what persona calls this?"
(agent → Data; operator → Control; AppSec → Governance; auditor → Audit).

---

## 4. Intra-node coordination primitives

We deliberately don't define an internal RPC layer. The two OTP apps share a BEAM, so they
share BEAM primitives:

- **`GenServer.call/cast`** — synchronous request/response between subsystems on the same
  node. Default choice for "Gateway asks Runtime for X" on the hot path.
- **`Phoenix.PubSub`** — fan-out. Most notably `"attestations:emitted"`: the attestation
  envelope constructor publishes, and SIEM forwarder, Audit Payload Broker, and the Runtime
  session accumulator all subscribe. Decouples producers from consumer count.
- **`Broadway`** — batch / pipelined work with retry and backpressure. The global-ledger
  commit pipeline is Broadway (FR-040 bounded retry is implemented at this layer).
- **`Oban`** — scheduled jobs. Interim-commit scheduler per FR-037 is Oban.
- **`Ecto.Multi`** — atomic local CAS writes bundled with session-state transitions
  (FR-044). If two operations must succeed together or not at all, they are in the same
  `Multi`.
- **`Registry`** — per-session process lookup (`{:via, Registry, {Recurse.Runtime.Sessions,
  session_id}}`). Every session gets a Registry-addressed GenServer in Runtime.

**No cross-node messaging** is used in Phase 1. Federation and Phase-2 dist-BEAM are future
work (see `feedback_vcs_conventions` memory).

---

## 5. Further reading — the three matrices

This document is narrative. The normative details live in three machine-referable matrices
under `specs/001-api-jido-foundations/contracts/`:

- **`gateway_runtime_matrix.md` (Deliverable D, T069)** — the authoritative subsystem → app
  placement reference per FR-035. Every v1.0 subsystem has a row. New subsystems must add a
  row here *before* landing code. This is where you find out whether your new module is
  Gateway, Runtime, or delegated.

- **`completeness_boundary.md` (Deliverable M, T070)** — the per-protocol L3/L4/L7
  accept/drop/attest matrix for FR-043. Read this when working on anything that touches
  egress, ingress ACLs, denial attestations, or the "how do we claim 'complete' in v1.0"
  conversation. Includes the honest framing of why netns-level packet observability is
  sufficient for the completeness claim without full Code Mode.

- **`failure_matrix.md` (Deliverable N, T071)** — fail-open / fail-closed posture per
  Provider Interface and per ledger condition. When your code needs to decide "what happens
  if X provider is unreachable," this table is the answer. Default is fail-closed for
  security-affecting conditions; fail-open is only acceptable for audit-path degradation.

Cross-cutting authority documents:

- **`spec.md`** (feature spec v6.1) — functional requirements (FR-001 through FR-053) with
  tier-scoped shipping matrix.
- **`data-model.md`** — domain entities + Ecto schemas.
- **`contracts/attestation.schema.json`** — the authoritative JSON Schema for the
  attestation envelope (FR-021 signed predicate + outer container).
- **`.specify/memory/constitution.md`** — non-negotiable principles; Principles I (two
  OTP apps), II (kernel enforcement in Governance tiers), III (cryptographic provenance),
  IV (detached payloads), V (Provider Interface neutrality), VI (test-first).
- **`plan.md`** — implementation plan with the full project layout.

---

## 6. Where the boundaries live in code

Shortest-path orientation for "where do I put this":

| You are adding… | It lives here |
|-----------------|---------------|
| A new HTTP endpoint agents hit on the hot path | `apps/recurse_gateway/lib/recurse_gateway/planes/data/` |
| A new HTTP endpoint operators hit | `apps/recurse_gateway/lib/recurse_gateway/planes/control/` |
| A new policy-authoring API | `apps/recurse_gateway/lib/recurse_gateway/planes/governance/` |
| A new auditor surface | `apps/recurse_gateway/lib/recurse_gateway/planes/audit/` |
| Anything stateful across sessions | `apps/recurse_runtime/lib/recurse_runtime/session/` or `ledger/` |
| netns / iptables programming | `apps/recurse_runtime/lib/recurse_runtime/netns/` |
| A new Provider Interface implementation | `apps/recurse_providers/lib/recurse_providers/impls/` |
| A new shared type (struct, parser, serialization) | `apps/recurse_shared/lib/recurse_shared/` |
| Cedar NIF work | `native/recurse_cedar/src/` |

When in doubt: read `gateway_runtime_matrix.md` and place your subsystem in a new row there
before opening a PR.

---

## 7. What is *not* in Phase-1

To keep you oriented on the commercial line:

- **No Jido** — de-committed in Constitution v1.3.0. Runtime uses vanilla OTP.
- **No federation, no multi-node** — Phase-2+.
- **No visual policy builder** — Cedar Playground + Discovery-to-Policy generator + blast-
  radius are the three authoring surfaces; visual builder is Phase-2.
- **No proprietary auditor dashboard** — SIEM forwarder + Export Evidence zip + OSS CLI
  verifier are the three auditor surfaces (FR-048). Recurse is not a SIEM.
- **No full Code Mode intercept** — netns-level completeness is what Phase 1 claims; see
  `completeness_boundary.md` for the honest framing.
- **No Wasm / Firecracker / Extism isolation** — netns is the Phase-1 isolation primitive;
  we compete on visibility/audit, not on "strongest sandbox."

When you're unsure whether a request belongs in Phase 1 or a later feature, ask: does the
spec FR list it? If not, it's out of scope.
