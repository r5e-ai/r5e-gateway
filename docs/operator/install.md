# Production Install — Recurse Standalone AI Gateway

**Audience**: platform operator deploying the Recurse Gateway + Standalone
Identity Broker to **production** on a single Linux host.
**Scope**: F002 Phase-1 Standalone AI Gateway. Single-node only — federation,
HA pairs, and multi-AZ topologies ship in Phase-2+.
**Related specs**: F002 spec §FR-004, FR-027, FR-029, FR-031; SC-006, SC-012.
**Relationship to `specs/.../quickstart.md`**: the quickstart is a 30-min demo
walkthrough; this runbook is the production-hardened superset. Sections marked
**(quickstart ref)** cross-reference instead of duplicating.

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [TLS cert management](#2-tls-cert-management)
3. [Postgres sizing + tuning](#3-postgres-sizing--tuning)
4. [S3 lifecycle automation](#4-s3-lifecycle-automation)
5. [Log rotation + SIEM pipeline](#5-log-rotation--siem-pipeline)
6. [Health checks + monitoring](#6-health-checks--monitoring)
7. [Broker key management](#7-broker-key-management)
8. [Config integrity check (FR-027)](#8-config-integrity-check-fr-027)
9. [Backup + restore](#9-backup--restore)
10. [First-boot checklist](#10-first-boot-checklist)

---

## 1. Prerequisites

### Host OS

Supported in Phase-1:

| OS | Version | Notes |
|---|---|---|
| Ubuntu LTS | 22.04 | Reference target; all runbooks assume this. |
| RHEL / Rocky / Alma | 9.x | Tested; SELinux in enforcing mode is fine. |
| Amazon Linux | 2023 | Tested; `dnf`-based. |

Other Linux distros **may** work but are not part of Phase-1 release testing.
Windows Server + macOS as Gateway host are **unsupported** in Phase-1.

### Required packages

```bash
# Ubuntu 22.04
sudo apt update
sudo apt install -y \
  ca-certificates curl gnupg lsb-release \
  jq openssl logrotate
```

### Docker + Compose

Docker Engine 24+ with the `docker compose` v2 plugin. Confirm:

```bash
docker --version      # Docker version 24.x or newer
docker compose version # Docker Compose version v2.x.x
```

Rootless Docker is **supported but not required**. If running rootless, the
Gateway container must still be able to bind port 443 (or use `setcap` /
`authbind`).

### Disk

Minimum 50 GB free on the Postgres volume:

- Postgres data: 30 GB (see §3 for the 10M attestations/month sizing math).
- Postgres WAL archive (if PITR enabled): 10 GB working set.
- Vector sidecar spool: 5 GB (circular; bounded by `vector.toml`).
- Broker signing keys + config: < 10 MB (trivial).
- Docker images + container state: 5 GB.

Recommend the Postgres data volume be a dedicated block device (EBS gp3 / equivalent),
not the root filesystem.

### Network

Outbound:

- `443 → api.openai.com` (or your chosen LLMProvider endpoint)
- `443 → kms.<region>.amazonaws.com`
- `443 → s3.<region>.amazonaws.com`
- `443 → <your-idp-issuer>` (Okta / Auth0 / Azure AD / etc.)
- `443 → <your-SIEM-HEC-endpoint>` if using Vector → Splunk HEC
- `443 → api.github.com` + `443 → ghcr.io` (image pulls only at install time)

Inbound:

- **`443/tcp` — Data Plane.** Chat-completion + tool-call traffic from your agents.
- **`444/tcp` — Audit Plane.** Receipts, export-evidence, and admin endpoints. **Must be on a separate port** from the Data Plane per F002 FR-017a (cross-plane admin bleeding is a review blocker).
- `4001/tcp` — Standalone Identity Broker. **Internal-only** — do not expose beyond the Gateway host; agents authenticate via the Gateway, which calls the Broker over the Docker bridge.

If the host sits behind an NLB or cloud firewall, **both** 443 and 444 must be
reachable by the intended client populations; the Data Plane is for agent
runtime, the Audit Plane is for auditors + the Export Evidence CLI.

### AWS prerequisites

Per quickstart, but production-hardened:

- **S3 bucket** with Object Lock **compliance mode**, default retention 2555
  days (7 years). Enable versioning. MFA delete optional but recommended.
  See §4 for the lifecycle policy.
- **KMS asymmetric key**: `ECC_NIST_P256`, key usage `SIGN_VERIFY`. Enable
  key rotation (annual AWS-managed) or document your manual rotation cadence.
  See `docs/operator/kms-rotation.md`.
- **IAM role** (prefer instance profile / IRSA over static access keys). Policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:HeadObject"
      ],
      "Resource": "arn:aws:s3:::<your-bucket>/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:GetBucketLifecycleConfiguration"],
      "Resource": "arn:aws:s3:::<your-bucket>"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:<region>:<acct>:key/<key-id>"
    }
  ]
}
```

No `s3:DeleteObject`. No `kms:Decrypt`. Recurse is sign-and-verify only.

---

## 2. TLS cert management

The Gateway terminates TLS on both planes (443 Data, 444 Audit). **No
cleartext HTTP** is permitted in production. Two supported patterns:

### Option A — Sidecar Caddy + Let's Encrypt (recommended for single-tenant)

A `caddy` sidecar in the compose stack handles ACME challenges and hot-reloads
certs on renewal. Caddy serves 443 + 444 and reverse-proxies to the Gateway's
internal ports.

```yaml
# docker-compose.yaml additions (illustrative)
services:
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "443:443"
      - "444:444"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - gateway
```

```caddyfile
# Caddyfile
gateway.example.com:443 {
  reverse_proxy gateway:4000
}

audit.example.com:444 {
  reverse_proxy gateway:4002
}
```

Caddy reloads certs automatically; zero-downtime by design.

### Option B — BYO cert mounted into the Gateway

For air-gapped or internal-CA deployments:

1. Obtain a cert + chain + private key in PEM format.
2. Mount into the container under a read-only volume:

   ```yaml
   services:
     gateway:
       volumes:
         - ./tls/fullchain.pem:/etc/recurse/tls/fullchain.pem:ro
         - ./tls/privkey.pem:/etc/recurse/tls/privkey.pem:ro
   ```

3. Point the Gateway at the paths via env:

   ```bash
   RECURSE_TLS_CERT_PATH=/etc/recurse/tls/fullchain.pem
   RECURSE_TLS_KEY_PATH=/etc/recurse/tls/privkey.pem
   ```

### Zero-downtime cert rotation drill

Quarterly at minimum, or immediately after cert material changes:

1. Replace `fullchain.pem` + `privkey.pem` on disk (atomic `mv` from a staging dir).
2. `docker compose kill -s HUP gateway` — Bandit watches the cert path and reloads on SIGHUP.
3. Verify from a client host:

   ```bash
   echo | openssl s_client -servername gateway.example.com \
     -connect gateway.example.com:443 2>/dev/null \
     | openssl x509 -noout -enddate -issuer
   ```

4. Check `/healthz` still returns 200 immediately after SIGHUP.
5. If step 3 shows the old cert, inspect `docker compose logs gateway | grep tls.reload`.

---

## 3. Postgres sizing + tuning

### Retention math

F002 FR-027 requires that the Postgres ledger **retains every receipt for the
entire tier-declared retention window**. Default: 7 years for Standalone
Gateway. Compute:

```
rows_per_month = target_qps × 86400 × 30
avg_row_bytes  = ~4 KB (attestations row) + ~500 B (merkle_node rows × log₂(tree_size))
                ≈ 6 KB per receipt under one-run-one-session
monthly_growth = rows_per_month × avg_row_bytes
```

Worked example at **10M attestations/month**:

| Item | Size |
|---|---|
| 10M attestations × 6 KB | 60 GB/month |
| merkle_nodes (log₂(10M) ≈ 24) | 12 GB/month |
| global_ledger_entries | < 1 GB/month |
| Indexes (~35% overhead) | 25 GB/month |
| **Total** | **~100 GB/month** |
| **Annual** | **~1.2 TB/year** |
| **7 yr retention** | **~8.5 TB** |

At this scale, plan for S3-archival of older partitions (Phase-2 feature) or
pg_dump + cold storage for years 2–7. Phase-1 operators running < 10M/month
can keep 7 years on a single 10 TB gp3 EBS volume.

Below 100K receipts/month, a 50 GB volume is fine for the life of the deployment.

### `postgresql.conf` defaults

Recurse-specific tuning for a 32 GB RAM / 8 vCPU host:

```ini
# Connections
max_connections = 200
# Gateway pool = 20, Broker pool = 5, migrations + ops overhead = 25;
# 200 leaves generous headroom for pg_dump + replicas.

# Memory
shared_buffers = 8GB         # 25% of RAM
effective_cache_size = 24GB  # 75% of RAM
work_mem = 32MB              # per-sort/hash; multiply by max_parallel_workers

# WAL + checkpoints
wal_level = replica          # required for PITR
max_wal_size = 4GB
min_wal_size = 1GB
checkpoint_completion_target = 0.9
archive_mode = on
archive_command = 'test ! -f /var/lib/postgresql/wal-archive/%f && cp %p /var/lib/postgresql/wal-archive/%f'

# Autovacuum — attestations.inserted_at index dominates write load
autovacuum = on
autovacuum_max_workers = 4
autovacuum_vacuum_scale_factor = 0.05
autovacuum_analyze_scale_factor = 0.02

# Durability
synchronous_commit = on
fsync = on
full_page_writes = on
```

**Do not** disable `synchronous_commit` or `fsync` — attestations are the
customer's evidence record, and silent data loss violates F002 FR-015.

### WAL archive → S3 (optional but recommended)

Using `wal-g`:

```bash
# /etc/wal-g/wal-g.env
WALG_S3_PREFIX=s3://recurse-wal-archive/prod
WALG_COMPRESSION_METHOD=brotli
AWS_REGION=us-east-1
```

```ini
# postgresql.conf
archive_command = 'wal-g wal-push %p'
restore_command = 'wal-g wal-fetch %f %p'
```

Run `wal-g backup-push /var/lib/postgresql/data` nightly. See §9 for the full
backup procedure.

---

## 4. S3 lifecycle automation

Every row in `payload_outbox` / every successful upload writes a payload to
`s3://<bucket>/tenants/<tenant_id>/runs/<YYYYMMDD>/<run_id>.json`. The row's
`payload_uri` column records the S3 key.

Set a lifecycle policy that **mirrors** the database retention class:

```json
{
  "Rules": [
    {
      "ID": "recurse-standard-to-glacier",
      "Status": "Enabled",
      "Filter": { "Prefix": "tenants/" },
      "Transitions": [
        {
          "Days": 90,
          "StorageClass": "GLACIER_IR"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ],
      "Expiration": {
        "Days": 2555
      }
    }
  ]
}
```

Apply:

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket <your-bucket> \
  --lifecycle-configuration file://lifecycle.json
```

Verify:

```bash
aws s3api get-bucket-lifecycle-configuration --bucket <your-bucket>
```

Notes:

- Object Lock compliance-mode retention is **enforced by S3**, separate from the
  lifecycle. `Expiration.Days` above (2555) aligns with the Object Lock default.
- `recurse-verify` will fetch payloads from Glacier tiers at auditor cost —
  there is no Gateway-side warm-up. Document this trade-off with your auditor.

---

## 5. Log rotation + SIEM pipeline

The Gateway writes NDJSON to its container stdout per F002 FR-024/FR-025. Two
concerns:

### Container log rotation (host-side)

Default Docker behaviour accumulates container logs in
`/var/lib/docker/containers/<id>/*-json.log` forever. Rotate:

```json
// /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "10",
    "compress": "true"
  }
}
```

Restart Docker: `sudo systemctl restart docker`.

### SIEM forwarding (Vector sidecar)

Already covered in detail in `docs/operator/vector-tuning.md`. Key points:

- Vector runs as a sibling container, tails Gateway stdout via `docker_logs` source.
- On-disk spool at `/var/lib/vector/buffers/` — **must** be a persistent volume,
  not ephemeral tmpfs. Sizing: `buffer.max_size = 1GB` handles a 12-hour SIEM
  outage at 10M attestations/month.
- Switch `vector.toml` to point at your real HEC endpoint before going live.

Do not re-ship Gateway logs via host syslog + SIEM forwarder **and** Vector at
the same time — you'll double-count events.

---

## 6. Health checks + monitoring

### HTTP endpoints (T091)

| Path | Port | Auth | Purpose |
|---|---|---|---|
| `/healthz` | 4000 | none | Liveness — 200 OK if process is up |
| `/readyz` | 4000 | none | Readiness — 200 OK iff Postgres + KMS + S3 reachable |
| `/metrics` | 4000 | optional | Prometheus exposition format (FR-029 alerting metrics) |

Example Prometheus scrape:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: recurse-gateway
    metrics_path: /metrics
    static_configs:
      - targets: ['gateway.example.com:4000']
```

### Alert rules (F002 FR-029 minimums)

```yaml
# prometheus-rules.yml
groups:
  - name: recurse-gateway
    rules:
      - alert: RecurseGatewayDown
        expr: up{job="recurse-gateway"} == 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Gateway /healthz unreachable"

      - alert: RecursePolicyDenyRateHigh
        expr: rate(recurse_policy_decisions_total{decision="deny"}[5m]) > 0.1
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Policy deny rate > 10% for 5m"

      - alert: RecurseLedgerCommitStalled
        expr: recurse_ledger_commit_pending_count > 100
        for: 10m
        labels: { severity: critical }
        annotations:
          summary: "payload_outbox backlog > 100 rows for 10m"

      - alert: RecurseBrokerTokenExchangeFailureRate
        expr: rate(recurse_broker_token_exchange_failures_total[5m]) > 0.05
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Token-exchange failure rate > 5%"

      - alert: RecurseKmsSignFailureRate
        expr: rate(recurse_kms_sign_failures_total[1m]) > 0
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "KMS Sign returning errors — signing halted"
```

### Grafana dashboard

Reference dashboard JSON: upstream at
`github.com/r5e-ai/grafana-dashboards/recurse-gateway.json` (placeholder — ship
when published). Includes panels for:

- Chat-completion p50/p95/p99 latency
- Policy decision rate (allow/deny split)
- Ledger commit queue depth
- DSSE-signing p95
- SIEM forwarder buffer fill %

---

## 7. Broker key management

The Standalone Identity Broker signs the `X-Observed-Identity` JWT with an
operator-controlled key (separate from the KMS key that signs attestations).

### Signing key setup

```bash
mkdir -p /etc/recurse/secrets
chmod 700 /etc/recurse/secrets

# Generate an EC P-256 private key. Rotate quarterly.
openssl ecparam -name prime256v1 -genkey -noout \
  -out /etc/recurse/secrets/broker-signing-key.pem
chmod 400 /etc/recurse/secrets/broker-signing-key.pem
```

Configure the Broker:

```bash
# .env.broker
BROKER_JWT_SIGNING_KEY_PATH=/etc/recurse/secrets/broker-signing-key.pem
BROKER_JWT_AUDIENCE=recurse-gateway-<deployment-name>
BROKER_OIDC_ISSUERS=https://your-tenant.okta.com,https://login.microsoftonline.com/<tid>/v2.0
BROKER_KEY_ID=broker-2026q2
```

The `BROKER_KEY_ID` ("kid") is included in the JWT header so the Gateway's
JWKS client knows which key to verify with. Rotate `kid` with every new key.

### Broker key rotation procedure

1. Generate the new key under a new `kid`:

   ```bash
   openssl ecparam -name prime256v1 -genkey -noout \
     -out /etc/recurse/secrets/broker-signing-key-2026q3.pem
   ```

2. Add the new key alongside the old one (Broker supports N-key verification,
   single-key signing). Edit `.env.broker`:

   ```bash
   BROKER_JWT_SIGNING_KEY_PATH=/etc/recurse/secrets/broker-signing-key-2026q3.pem
   BROKER_JWT_VERIFY_KEY_PATHS=/etc/recurse/secrets/broker-signing-key-2026q2.pem,/etc/recurse/secrets/broker-signing-key-2026q3.pem
   BROKER_KEY_ID=broker-2026q3
   ```

3. `docker compose restart broker`. Gateway picks up new JWKS on next cache refresh (60s).

4. Wait for all issued-pre-rotation tokens to expire (default `expires_in` =
   900s, so 15 min is safe).

5. Remove the old key path from `BROKER_JWT_VERIFY_KEY_PATHS` and delete the
   old PEM.

Attestation-signing KMS key rotation is a different animal — see
`docs/operator/kms-rotation.md`.

---

## 8. Config integrity check (FR-027)

F002 FR-027 requires a signed out-of-band integrity record for the
tier-configuration YAML that the Gateway compares against at boot. If the live
`tier-config.yaml` does not match the committed hash, the Gateway
**fail-safe-closes** — refuses to start.

### Compute the hash

```bash
./scripts/compute-tier-config-hash.sh tier-config.yaml > tier-config.sha256
# tier-config.sha256 contents:
#   <64-hex-digits>  tier-config.yaml
```

Commit `tier-config.sha256` to your deployment repo alongside `tier-config.yaml`.
Rotate the hash file at the same time as any config change; the Gateway boots
only if `sha256sum -c tier-config.sha256` returns success.

### Boot-time verification

The Gateway container entrypoint runs:

```bash
cd /etc/recurse
sha256sum -c tier-config.sha256 || {
  echo "TIER_CONFIG_INTEGRITY_MISMATCH — aborting boot"
  exit 87
}
```

Exit code 87 in `docker compose logs gateway` means the hash file disagrees
with the YAML. Recompute after any intentional change:

```bash
vim tier-config.yaml
./scripts/compute-tier-config-hash.sh tier-config.yaml > tier-config.sha256
git commit -am "rotate tier-config hash for <change>"
```

### Audit trail

Each boot with a successful integrity check emits a `tier_config.integrity_ok`
log line including the hash value, host hostname, and timestamp. Forward to
SIEM for longitudinal audit. A gap in the log series is a signal that an
operator disabled the check.

---

## 9. Backup + restore

Backup setup + restore procedure is owned by `docs/operator/restore-drill.md`
— cross-ref that doc for:

- Recommended `pg_basebackup + wal-g` pipeline.
- Minimum-viable `pg_dump -Fc` + cron fallback.
- Payload bucket mirror-to-DR bucket using S3 Cross-Region Replication.
- Quarterly drill checklist with `recurse-verify` end-to-end verification.
- Timing targets (1-hour SC-012 floor).
- Automation: T103 `sc012_restore_drill_test.exs` is the nightly CI drill.

---

## 10. First-boot checklist

Walk this list after every initial bring-up and after any major upgrade. Each
step takes < 2 minutes; the whole checklist completes in ~15 minutes.

### 10.1 Liveness

```bash
curl -f -s -o /dev/null -w "%{http_code}\n" http://localhost:4000/healthz
# expected: 200
```

### 10.2 Readiness

```bash
curl -s http://localhost:4000/readyz | jq .
# expected: {"status":"ready","postgres":"ok","kms":"ok","s3":"ok"}
```

### 10.3 End-to-end chat completion + attestation

```bash
# Fetch an X-Observed-Identity JWT from the Broker first (quickstart ref §4).
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer $XOBS" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}' \
  -o /tmp/completion.json -w "%{http_code}\n"
# expected: 200 and /tmp/completion.json has a non-empty choices[0].message

# Receipt query:
curl -s "http://localhost:4000/v1/audit/receipts?limit=1" \
  -H "Authorization: Bearer $XOBS" | jq '.receipts[0].outer_container.verification_level'
# expected: "global_inclusion_verified"
```

### 10.4 Export evidence + offline verification

```bash
RUN_ID=$(curl -s "http://localhost:4000/v1/audit/receipts?limit=1" \
  -H "Authorization: Bearer $XOBS" | jq -r '.receipts[0].run_id')

curl -s -X POST "http://localhost:4000/v1/audit/export" \
  -H "Authorization: Bearer $XOBS_PLATFORM_OPERATOR" \
  -H "Content-Type: application/json" \
  -d "{\"run_ids\":[\"$RUN_ID\"]}" \
  -o /tmp/evidence.zip

./docs/auditor/recurse-verify --zip /tmp/evidence.zip \
  --trust-anchor /etc/recurse/expected-public-key.pem
# expected: exit 0
```

### 10.5 JWT exchange round-trip

```bash
# Confirm Broker issues tokens + Gateway accepts them. The commands in
# 10.3 already exercise this path end-to-end; this separate check is for
# isolating failures when 10.3 fails.
curl -X POST http://localhost:4001/token/exchange \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$ID_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "audience=recurse-gateway-local" \
  | jq '.access_token' | head -c 20
# expected: begins with "eyJ"
```

### 10.6 SIEM NDJSON arriving

```bash
# If Vector sink is HEC: query Splunk for `index=recurse_audit | head 1`.
# If Vector sink is console (dev): tail the container.
docker compose logs --tail 20 vector | grep "\"run_id\""
# expected: at least one JSON line containing the run_id from step 10.3.
```

### 10.7 Config integrity on current config

```bash
cd /etc/recurse && sha256sum -c tier-config.sha256
# expected: "tier-config.yaml: OK"
```

### 10.8 First-boot sign-off

If all seven checks pass: file a deployment receipt in your change-management
system referencing:

- Git SHA of the deployed `r5e-enterprise` tag
- `tier-config.sha256` hash value
- `BROKER_KEY_ID` in use
- KMS key ARN + current `key_version`
- S3 bucket ARN
- Operator name + date

This receipt is what an auditor asks for under SOC 2 CC6.8 / ISO 27001 A.8.32.

---

## Next steps

- **Rotate the KMS key quarterly** → `docs/operator/kms-rotation.md`
- **Tune Vector for your SIEM volume** → `docs/operator/vector-tuning.md`
- **Run a quarterly restore drill** → `docs/operator/restore-drill.md`
- **Author real Cedar policies** → `apps/recurse_gateway/priv/cedar/schema.cedarschema.json`
  + `priv/reference_policies/*.cedar`
