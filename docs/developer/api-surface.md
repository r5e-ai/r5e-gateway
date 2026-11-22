# API Surface (T058 — developer onboarding entry point)

This is the first document a new Recurse engineer should read. In under 10
minutes (SC-001) you should be able to answer, for any Phase-1 endpoint:

  - which deployment tier(s) activate it,
  - which OTP application owns it (Gateway vs Runtime vs Gateway-with-delegation),
  - what authentication it requires (machine identity + principal identity),
  - what error envelope it returns (Recurse uniform vs protocol-native),
  - what streaming policy it follows (sync / sse / ws),
  - whether it requires an `Idempotency-Key`.

The **authoritative** machine-readable source is
`specs/001-api-jido-foundations/contracts/openapi.yaml` (T049). Every claim in
this narrative file is grounded there; when they drift, the YAML wins and
`mix recurse.contracts.validate` fails CI.

## Four planes

The v1.0 API surface is organized into four planes, each with a distinct
integration audience and a distinct error-envelope posture.

| Plane        | Audience                          | Primary integration                                  | Error envelope                           |
|--------------|-----------------------------------|-------------------------------------------------------|------------------------------------------|
| Data         | Agent code in the netns / customer agent app | OpenAI-compatible LLM client / MCP SSE       | Protocol-native (OpenAI or MCP) per FR-016 |
| Control      | Platform operators & orchestrator | spawn / cancel / list managed sessions; observability | Recurse uniform (FR-010)                 |
| Governance   | AppSec / Cloud IAM / GRC         | Cedar policy bundle distribution; author UX (US5)    | Recurse uniform (FR-010)                 |
| Audit        | Compliance auditors / SOC teams  | Receipt query; payload broker; Export Evidence        | Recurse uniform (FR-010)                 |

**Observability endpoints** (`/healthz`, `/readyz`, `/metrics`) are mounted at
the deployment root (NOT under `/v1`) per FR-014 / FR-032. They are strictly
operator-facing and unauthenticated except for `/metrics` (scrape bearer).

## Endpoint summary table

All paths are relative to the deployment host. Protocol is HTTPS.

### Observability (root-mounted per FR-014)

| Method | Path       | Owner   | Auth                 | Streaming | Tiers                                                         |
|--------|------------|---------|----------------------|-----------|---------------------------------------------------------------|
| GET    | /healthz   | gateway | none                 | sync      | all                                                           |
| GET    | /readyz    | gateway | none                 | sync      | all                                                           |
| GET    | /metrics   | gateway | scrape bearer        | sync      | all                                                           |

### Data Plane (FR-025, FR-041, FR-043)

| Method | Path                                   | Owner                          | Auth                              | Streaming | Tiers                                      |
|--------|----------------------------------------|--------------------------------|-----------------------------------|-----------|--------------------------------------------|
| POST   | /v1/chat/completions                   | gateway                        | mTLS SPIFFE OR X-Observed-Identity JWT | sse\*   | managed_saas, standalone_gateway, vpc_runner |
| POST   | /v1/embeddings                         | gateway                        | mTLS SPIFFE OR X-Observed-Identity JWT | sync    | managed_saas, standalone_gateway, vpc_runner |
| GET    | /v1/models                             | gateway                        | mTLS SPIFFE OR X-Observed-Identity JWT | sync    | managed_saas, standalone_gateway, vpc_runner |
| GET    | /v1/mcp/{server_name}/sse              | gateway-with-runtime-delegation | mTLS SPIFFE OR X-Observed-Identity JWT | sse     | managed_saas, standalone_gateway, vpc_runner |
| POST   | /v1/mcp/{server_name}/messages         | gateway-with-runtime-delegation | mTLS SPIFFE OR X-Observed-Identity JWT | sync    | managed_saas, standalone_gateway, vpc_runner |

\* `sse` when `stream: true`, `sync` otherwise; protocol-native OpenAI semantics.

### Control Plane (FR-002, FR-005, FR-011, FR-024, FR-028, FR-029, FR-044)

| Method | Path                                                | Owner                          | Auth                    | Streaming | Idempotency-Key | Tiers                                       |
|--------|-----------------------------------------------------|--------------------------------|-------------------------|-----------|-----------------|---------------------------------------------|
| POST   | /v1/orchestrator/spawn                              | gateway-with-runtime-delegation | SPIFFE-JWT-SVID bearer  | sync      | required        | managed_saas, vpc_runner, appliance         |
| GET    | /v1/orchestrator/sessions                           | runtime                        | SPIFFE-JWT-SVID bearer  | sync      | n/a             | managed_saas, vpc_runner, appliance         |
| POST   | /v1/orchestrator/sessions/{session_id}/cancel       | runtime                        | SPIFFE-JWT-SVID bearer  | sync      | required        | managed_saas, vpc_runner, appliance         |
| GET    | /v1/version                                         | gateway                        | none                    | sync      | n/a             | all                                         |

Any Runtime-owned endpoint returns HTTP 501 `ERR_TIER_MISMATCH` in the
`standalone_gateway` shape because Runtime is absent per FR-050.

### Governance Plane (FR-039, FR-049 — simulate/propose/blast are US5's scope T085)

| Method | Path                                                | Owner   | Auth                   | Streaming | Idempotency-Key | Tiers                                                         |
|--------|-----------------------------------------------------|---------|------------------------|-----------|-----------------|---------------------------------------------------------------|
| POST   | /v1/governance/policy/bundle                        | gateway | SPIFFE-JWT-SVID bearer | sync      | required        | all                                                           |
| GET    | /v1/governance/policy/bundle                        | gateway | SPIFFE-JWT-SVID bearer | sync      | n/a             | all                                                           |
| GET    | /v1/governance/policy/{policy_bundle_digest}        | gateway | SPIFFE-JWT-SVID bearer | sync      | n/a             | all                                                           |
| POST   | /v1/governance/policy/simulate                      | (T085)  | —                      | sync      | —               | T085 will add per FR-049 surface 1                            |
| POST   | /v1/governance/policy/propose-from-event            | (T085)  | —                      | sync      | —               | T085 will add per FR-049 surface 2                            |
| POST   | /v1/governance/policy/blast-radius                  | (T085)  | —                      | sync      | —               | T085 will add per FR-049 surface 3                            |

### Audit Plane (FR-021, FR-022, FR-030, FR-044, FR-048)

| Method | Path                                           | Owner   | Auth                   | Streaming | Tiers |
|--------|------------------------------------------------|---------|------------------------|-----------|-------|
| GET    | /v1/audit/receipts                             | gateway | SPIFFE-JWT-SVID bearer | sync      | all   |
| GET    | /v1/audit/receipts/{run_id}/{step_id}          | gateway | SPIFFE-JWT-SVID bearer | sync      | all   |
| GET    | /v1/audit/sessions/{session_id}                | gateway | SPIFFE-JWT-SVID bearer | sync      | all   |
| GET    | /v1/audit/broker/{payload_uri_hash}            | gateway | SPIFFE-JWT-SVID bearer | sync      | all   |
| POST   | /v1/audit/export                               | (T089)  | —                      | sync      | T089 will add per FR-048 surface 2 |
| POST   | /v1/audit/forward                              | (T089)  | —                      | sync      | T089 will add per FR-048 surface 1 |

## Authentication quick reference

- **Data Plane, Governance shapes (managed_saas / vpc_runner / appliance)**:
  mTLS via netns + SPIFFE peer cert (FR-025). The agent's SVID is the peer
  cert; netns routing guarantees only the provisioned agent reaches the
  Gateway's Data Plane listener.
- **Data Plane, Standalone Gateway**: `X-Observed-Identity` JWT (FR-017).
  See `specs/001-api-jido-foundations/contracts/x_observed_identity.schema.json`
  and the JWKS rotation flow in `x_observed_identity_flow.md`.
- **Control / Governance / Audit**: `Authorization: Bearer <SPIFFE-JWT-SVID>`
  (FR-011). Invalid / expired → `ERR_AUTH_FAILED`.
- **Principal identity** (second identity layer, per FR-026): resolved once at
  ingress by the configured `PrincipalProvider` from the inbound
  machine-identity claims. Three `kind` values: `obo_human`, `service_account`,
  `autonomous`.
- **Observability** (`/healthz`, `/readyz`, `/metrics`): see FR-032.

## Error handling quick reference

- **Data Plane**: NEVER the Recurse uniform envelope. Failure categories per
  FR-016a–f are all protocol-native — Cedar denials surface as synthetic
  OpenAI tool-role messages or MCP error frames; upstream 5xx is passed
  through; malformed requests use the protocol's own validation-error shape.
- **Control / Governance / Audit**: uniform envelope
  `{code, message, correlation_id, details?}` per FR-010. Twelve codes total;
  see `contracts/error_codes.md` for the complete enum + HTTP mapping and
  `apps/recurse_shared/lib/recurse_shared/error_codes.ex` for the Elixir
  source of truth.

## Where to look next

| Question                                                              | Artifact                                                                          |
|-----------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| Exact request/response shapes?                                        | `specs/001-api-jido-foundations/contracts/openapi.yaml`                           |
| Streaming classification + terminal frames?                           | `specs/001-api-jido-foundations/contracts/streaming_policy_matrix.md`             |
| All error codes with worked examples?                                 | `specs/001-api-jido-foundations/contracts/error_codes.md`                         |
| Standalone Gateway JWT contract + broker spec?                        | `contracts/x_observed_identity.schema.json` + `standalone_identity_broker.md`     |
| Attestation receipt envelope?                                         | `contracts/attestation.schema.json`                                               |
| Tier Configuration reference YAMLs?                                   | `config/{managed_saas,standalone_gateway,vpc_runner,appliance}.reference.yml`     |
| Gateway / Runtime split — who owns a new subsystem?                   | Deliverable D (T069) — `contracts/gateway_runtime_matrix.md` (US3)                |
| Provider Interface contracts?                                         | `apps/recurse_providers/lib/recurse_providers/*_provider.ex`                      |
| Cedar pin + stability fixture?                                        | `apps/recurse_shared/priv/test_fixtures/cedar_stability/`                         |

## Versioning

The API surface is governed by semantic versioning anchored at v1.0 (FR-006).
The only metadata endpoint allowed by v1.0 is the static `/v1/version`
(FR-005); runtime-reflective / self-describing endpoints are explicitly out of
scope for Phase 1. Build-time generated artifacts (notably `contracts/openapi.json`
produced by `mix recurse.contracts.openapi`) are permitted and encouraged.
