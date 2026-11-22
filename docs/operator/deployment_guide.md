# Operator Deployment Guide — Recurse Enterprise Phase 1

**Audience**: SRE / Platform engineer deploying Recurse. Two shipping shapes in Phase 1:

1. **Managed SaaS on AWS EKS** (commercial offering #1)
2. **Standalone AI Gateway on-prem** (commercial offering #2)

VPC Runner is contract-preview in Phase 1 (API surface + Helm chart ship; full operational
support lands in Phase 1.5). Air-Gapped Appliance ships in Phase 2.

---

## Prerequisites (both shapes)

| Tool | Version | Notes |
|---|---|---|
| Linux kernel | 5.10+ | For `netns` + `iptables` in Governance shapes. macOS is dev-only. |
| Elixir / OTP | See `.tool-versions` | 1.19.5 / OTP 28 in current release. |
| Rust | See `.tool-versions` | 1.92 in current release; required for Cedar + SPIFFE NIFs. |
| Postgres | 16+ | Tested against 17.9 locally. |
| SPIRE | Any recent | Recurse ships SPIRE alongside; customers don't need pre-existing SPIFFE infra. |

---

## Managed SaaS on AWS EKS (offering #1)

**Topology**: Recurse-hosted BYOC agent containers in netns; full Governance tier. Each
customer gets a dedicated EKS node group (BEAM-per-customer; no in-BEAM multi-tenancy per
FR-019).

### Helm chart layout (scaffold — Feature 002+ fills deployment details)

```
helm/recurse-managed-saas/
├── Chart.yaml
├── values.yaml                          # tier, tenant_id, IdP config, KMS refs
├── values.schema.json                   # validates against tier_config.schema.json
└── templates/
    ├── namespace.yaml
    ├── serviceaccount-irsa.yaml         # IRSA binding for S3/KMS/Trillian access
    ├── gateway-deployment.yaml          # :recurse_gateway, 2+ replicas, NetworkPolicy
    ├── gateway-service.yaml             # Gateway Service (internal ALB for agent netns)
    ├── gateway-hpa.yaml                 # HorizontalPodAutoscaler on request rate
    ├── runtime-statefulset.yaml         # :recurse_runtime, session-affinity needed
    ├── runtime-service.yaml
    ├── spire-server.yaml                # Trust-domain: customer.recurse.ai
    ├── spire-agent-daemonset.yaml       # Per-node SPIRE agent; workload API UDS
    ├── postgres.yaml                    # RDS or in-cluster; ecto_repos config
    ├── trillian-deployment.yaml         # Trillian log + Trillian map for the ledger
    ├── s3-storage-external.yaml         # IRSA + bucket policy for StorageProvider
    ├── secrets-provider-config.yaml     # AWS Secrets Manager or KMS
    ├── principal-provider-config.yaml   # Okta / Entra / Auth0 OIDC endpoints
    ├── cedar-policy-bundle-job.yaml     # Initial OCI pull + supersede watcher
    └── observability/
        ├── prometheus-servicemonitor.yaml
        └── grafana-dashboard-configmap.yaml
```

### Critical deployment notes

- **Cedar policy bundles via OCI**: push to ECR under the customer's AWS account; Recurse's
  `PolicyProvider` pulls via IRSA — no cross-account IAM needed.
- **Trust domain**: one SPIRE trust domain per customer deployment (e.g.,
  `spiffe://acme.recurse.ai`). Cross-customer trust is explicitly NOT federated in Phase 1
  (FR-034 Constitution Reconciliation §1).
- **Network policies**: `gateway-deployment` accepts ONLY from the agent-container
  NetworkPolicy-labeled pods + from the Gateway's own ingress (customer ALB). Runtime
  accepts ONLY from Gateway pods.
- **Agent containers**: spawned by Runtime via `/v1/orchestrator/spawn`. Each runs in its
  own netns with iptables rules enforcing `0.0.0.0/0 → Gateway only`. SPIRE workload attestation
  uses the netns selector for cryptographic binding (FR-025).
- **KMS integration for FR-046**: AWS KMS keys for long-lived Gateway signing keys. Key
  rotation quarterly per policy; old key versions preserved forever (constitutional Principle III).
- **Observability**: Prometheus scrape on `/metrics` (bearer-auth per FR-032); Grafana
  dashboard ships with baseline panels (Gateway request rate, Cedar eval p99, ledger commit
  latency, SVID rotation events).

### Runbook snippets

**Rotate Gateway signing key** (scheduled quarterly per FR-046):
```bash
kubectl exec -it deploy/recurse-gateway -- \
  mix recurse.signing_key.rotate --reason="quarterly-rotation-2026Q2"
# New key version minted; old version marked rotated but retained for verification.
```

**Re-bake Cedar stability fixture** (on Cedar minor-version bump):
See `specs/001-api-jido-foundations/contracts/cedar_pin.md` upgrade procedure.

**Force supersede notification** (after policy bundle upload):
```bash
curl -sk https://gateway.example.com/v1/governance/policy/bundle \
  -H "Authorization: Bearer $(spire-agent api fetch jwt -audience gateway.example.com)" \
  -H "Idempotency-Key: $(./scripts/ulid)" \
  --data-binary @bundle.tar.gz
```

---

## Standalone AI Gateway on-prem (offering #2)

**Topology**: single-tenant binary (mix release tarball) on customer on-prem VM or bare
metal. Runtime application disabled via Tier Configuration; only Gateway runs. Customer
redirects their existing agent infrastructure's LLM traffic to the Gateway via
`OPENAI_BASE_URL`.

### Install via tarball + systemd

```bash
# Fetch the release tarball
curl -LO https://releases.recurse.ai/recurse-enterprise-v1.0.0-linux-x86_64.tar.gz
sha256sum -c recurse-enterprise-v1.0.0-linux-x86_64.tar.gz.sha256

# Extract to /opt/recurse
sudo mkdir -p /opt/recurse
sudo tar -xzf recurse-enterprise-v1.0.0-linux-x86_64.tar.gz -C /opt/recurse

# Lay down Tier Configuration (out-of-band hash per FR-033)
sudo cp standalone_gateway.yml /etc/recurse/tier-config.yml
sudo sha256sum /etc/recurse/tier-config.yml | awk '{print $1}' > /etc/recurse/tier-config.yml.sha256

# Install systemd unit
sudo tee /etc/systemd/system/recurse-gateway.service >/dev/null <<'EOF'
[Unit]
Description=Recurse Enterprise Gateway (Standalone)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=exec
User=recurse
Group=recurse
Environment=RECURSE_TIER_CONFIG=/etc/recurse/tier-config.yml
Environment=RECURSE_TIER_CONFIG_HASH_FILE=/etc/recurse/tier-config.yml.sha256
Environment=OPENAI_API_KEY_FILE=/etc/recurse/openai-api-key
Environment=RECURSE_STORAGE_S3_BUCKET=customer-audit-bucket
ExecStart=/opt/recurse/bin/recurse start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now recurse-gateway
sudo systemctl status recurse-gateway
```

### Tier Configuration — Standalone AI Gateway

See `config/standalone_gateway.reference.yml` for the authoritative reference. Key fields:

```yaml
tier: standalone_gateway
topology: single_node                    # federated reserved-not-permitted in Phase 1
tenant_id: example-tenant-001
runtime:
  enabled: false                         # no orchestrated agents in Standalone
gateway:
  enabled: true
auth:
  anchors:
    netns: false                         # no netns in Standalone
    observed_identity: true              # X-Observed-Identity JWT (FR-017)
  identity_broker:
    mode: recurse_shipped_broker         # OR customer_supplied_jwt_issuer
    sso_webhook: https://sso.customer.example.com/webhook
session:
  interim_commit_event_count: 10000
  interim_commit_threshold_minutes: 60
policy:
  cedar_version: "4.9.1"
  cedar_crate_digest: sha256:50368b44367cd7664627bbee9bfe5721d10ab2433daf77645833645e8eb746da
```

### Tier-config integrity hash (FR-033)

Supplied out-of-band. The sibling `.sha256` file OR env var `RECURSE_TIER_CONFIG_HASH`
MUST match the file's SHA-256 on load and reload. Mismatch → Gateway fails into safe-closed
state (only `/healthz` responds 503).

**Honest framing**: this mechanism detects accidental corruption (truncation, partial
overwrite). It is NOT tamper resistance — an attacker with write access to both files can
modify both consistently. Cryptographic signing of tier-config is deferred to Phase 2
(FR-033 — documented deferral).

### Customer integration — three paths

**Path A — redirect OPENAI_BASE_URL** (easiest; no SDK changes):
```bash
export OPENAI_BASE_URL=https://gateway.customer.example.com/v1
export X_OBSERVED_IDENTITY=$(cat ~/.recurse-dev/observed_identity.jwt)
# Agent code unchanged; HTTP client points at Gateway.
```

**Path B — customer SSO → Standalone Identity Broker webhook**:
The customer's SSO calls the broker's webhook on session start. Broker mints
`X-Observed-Identity` JWT + returns to agent infra via the SSO response. See
`contracts/standalone_identity_broker.md`.

**Path C — customer-supplied JWT issuer**:
Customer already has a JWT issuer (e.g., internal auth service). Point it at the Gateway
audience. No broker component runs. See `contracts/standalone_identity_broker.md` BYO path.

---

## SIEM integration (all shapes)

See `docs/operator/siem_integration.md` for Splunk HEC / Datadog Logs / Microsoft Sentinel
setup. SIEM Log Forwarder emits structured NDJSON per `contracts/siem_log_forwarder.md`.

---

## Common operations

### Tail audit receipts
```bash
curl -sk https://gateway.example.com/v1/audit/receipts?limit=20 \
  -H "Authorization: Bearer $(spire-agent api fetch jwt -audience gateway.example.com)" \
  | jq '.items[] | {run_id, step_id, verification_level, tier_completeness_advisory, policy_decision: .signed.policy_canonical_hash[0:12]}'
```

### Export evidence zip (for auditor)
```bash
curl -sk https://gateway.example.com/v1/audit/export \
  -H "Authorization: Bearer $(spire-agent api fetch jwt -audience gateway.example.com)" \
  -H "Content-Type: application/json" \
  -d '{"run_ids": ["run_01H..."]}' \
  --output evidence.zip
./docs/auditor/recurse-verify evidence.zip
```

### Check Cedar stability fixture
```bash
mix recurse.cedar.stability_check
# ✓ Cedar stability fixture OK (4.9.1, digest sha256:50368b44, hash 44ea666a...)
```

---

## Upgrade path

Phase-1 → Phase-1.5 (VPC Runner full operational support):
- New Helm chart variant; Tier Configuration `tier: vpc_runner`.
- No breaking API changes; receipts remain verifiable across the upgrade.

Phase-1 → Phase 2 (Federation + Appliance + JIT minting):
- `topology: federated` becomes permitted (currently reserved).
- Appliance Burrito binary.
- Intent-aware JIT token minting (Provider Interfaces extend at that time per
  `feedback_no_premature_metaapi.md`).

---

## Troubleshooting

- **Gateway fails to start, `tier-config hash mismatch`**: regenerate the sidecar `.sha256`
  file — `sha256sum tier-config.yml > tier-config.yml.sha256`.
- **Cedar NIF fails to load**: run `mix recurse.cedar.stability_check` — if it fails, check
  Cargo.lock for `cedar-policy` version drift; see `contracts/cedar_pin.md`.
- **SVID rotation failures**: check `spire-agent` UDS path accessibility from the Gateway
  process; in Kubernetes this is usually a hostPath volume mount.
- **Ledger commit stuck at `commit_retry_exhausted`**: check Postgres / Trillian connectivity;
  see `failure_matrix.md`. Receipts at `local_inclusion_verified` are still trustworthy —
  they're just not yet globally committed.
