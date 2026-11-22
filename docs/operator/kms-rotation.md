# KMS Signing-Key Rotation — Recurse Standalone AI Gateway

**Audience**: platform operators responsible for the Recurse Standalone
Gateway deployment.
**Scope**: rotating the long-lived document-signing key that the Gateway
uses to sign attestation DSSE envelopes.
**Related specs**: F001 FR-046, F002 FR-015, F002 spec §US5, SC-006;
`specs/001-api-jido-foundations/contracts/signing_key_archive.md`.

---

## TL;DR

1. Pick a rotation cadence — quarterly is the default (F001 FR-046).
2. Either enable AWS-managed automatic rotation (simplest) **or** run
   the manual `create-key` / migrate-IAM / retire-old procedure.
3. Verify: a new row appears in the `signing_keys` archive table with a
   new `key_version`; receipts produced after the rotation carry the
   new version in their `signer.key_version` field; old receipts still
   verify against the retained archive row for the previous version.
4. Log rotation dates in your change-management system.

The Gateway's `KmsRotationWatcher` GenServer polls the configured
`SecretsProvider` every 60 s. Rotations are detected automatically —
the operator's job is to **perform** the rotation; the Gateway
**records** it.

---

## Why rotate

Long-lived signing keys are a compliance liability. Three reasons to
rotate on a fixed cadence:

- **Crypto hygiene** — limits the blast-radius of an unnoticed key
  compromise to the pre-rotation window.
- **Compliance** — SOC 2, ISO 27001, and most industry-specific audit
  frameworks mandate periodic signing-key rotation.
- **Rotation rehearsal** — an organization that rotates quarterly
  knows the process works; an organization that has never rotated
  discovers its rotation bugs during an incident.

Recurse's durability contract (Constitution Principle III) means
**rotation never invalidates old receipts**: the retired signing-key
version is retained in the `signing_keys` archive with its public key
PEM indefinitely, and `recurse-verify --trust-anchor` continues to
validate historical DSSE signatures against the retired archive row.

---

## Cadence

| Trigger | Action |
|---------|--------|
| Scheduled quarterly (default, F001 FR-046) | Follow this runbook. |
| Suspected key compromise | Rotate **immediately**; see [Emergency rotation](#emergency-rotation). |
| KMS key deletion pending | Rotate before AWS's `PendingDeletion` window expires (default 30 days). |
| Policy / algorithm change | Create a new key with the desired algorithm; migrate; retire the old. |

---

## Option A — AWS-managed automatic rotation (recommended)

If your KMS key is a symmetric customer managed key (CMK) AND your
`SecretsProvider` impl supports reading the current `KeyManager` /
version (the reference `AwsKmsSecretsProvider` does), AWS can rotate
the underlying key material on a fixed schedule while the ARN stays
stable.

```bash
# One-time setup — enable rotation (default: every 365 days).
aws kms enable-key-rotation \
  --key-id arn:aws:kms:us-east-1:111122223333:key/abcd1234-...

# Verify it's enabled.
aws kms get-key-rotation-status \
  --key-id arn:aws:kms:us-east-1:111122223333:key/abcd1234-...
# → { "KeyRotationEnabled": true }
```

**Note**: AWS's built-in rotation rotates the **key material**
transparently under the same ARN. The public key retrieved via
`kms:GetPublicKey` does NOT change; only the signing material behind
the ARN rotates. For Recurse's purposes this is invisible to
downstream verifiers — the ARN + public key tuple they trust stays
valid.

If your compliance regime requires **observable** key-version
churn in the archive (distinct `signer.key_version` per quarter), use
Option B instead.

---

## Option B — Manual key rotation (observable new key_version)

Use this when you want each rotation to produce a distinct
`{kms_key_id, key_version}` tuple in the archive.

### 1. Mint the new key

```bash
NEW_KEY_ARN=$(aws kms create-key \
  --description "Recurse Standalone Gateway signing key $(date +%Y-Q%q)" \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --query KeyMetadata.Arn \
  --output text)

# Tag for discoverability.
aws kms tag-resource \
  --key-id "$NEW_KEY_ARN" \
  --tags TagKey=app,TagValue=recurse \
         TagKey=role,TagValue=signing \
         TagKey=rotation_epoch,TagValue="$(date +%Y-Q%q)"
```

### 2. Copy the IAM key policy

Download the old key's policy, copy it to the new key, and confirm
that the Gateway's IAM role (or SPIFFE-bound IRSA role) has
`kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on the new ARN:

```bash
OLD_KEY_ARN="arn:aws:kms:us-east-1:111122223333:key/abcd1234-..."

aws kms get-key-policy \
  --key-id "$OLD_KEY_ARN" \
  --policy-name default \
  --output text > /tmp/kms-policy.json

aws kms put-key-policy \
  --key-id "$NEW_KEY_ARN" \
  --policy-name default \
  --policy file:///tmp/kms-policy.json
```

### 3. Update the Gateway's Tier Configuration

Open `config/reference/tier-config.standalone_gateway.yaml` (or your
per-deployment override):

```yaml
providers:
  secrets:
    kind: aws_kms
    config:
      # OLD: key_arn: arn:aws:kms:us-east-1:111122223333:key/abcd1234-...
      key_arn: arn:aws:kms:us-east-1:111122223333:key/NEW-KEY-ARN-HERE
      algorithm: ECDSA_SHA_256
      region: us-east-1
      finch_pool: :kms_pool
```

Re-deploy the Tier Configuration per your ops process (`kubectl
rollout`, `docker compose up -d`, etc).

### 4. Send SIGHUP for immediate refresh

The `KmsRotationWatcher` polls every 60 s by default, so it will
detect the new key within one minute. To force an immediate poll
(e.g. during a change-management window that demands sub-minute
attestation of the new key):

```bash
# Single-container deployment.
docker kill -s SIGHUP <gateway-container-id>

# Kubernetes Pod.
kubectl exec <gateway-pod> -- kill -HUP 1
```

The Gateway's SIGHUP handler flips `KmsRotationWatcher.poll_now/0`
synchronously — the next attestation emitted after SIGHUP is
guaranteed to reference the new key_version.

### 5. Retire (schedule deletion of) the old key

**Only after** you have verified new receipts carry the new
`key_version` AND old receipts still verify via the retained
`signing_keys` archive row:

```bash
# Schedule deletion with a 30-day window (minimum). Receipts signed
# under the old key remain verifiable via the archive row's public_key_pem
# regardless of whether the underlying KMS key is later deleted.
aws kms schedule-key-deletion \
  --key-id "$OLD_KEY_ARN" \
  --pending-window-in-days 30
```

**Recommended: do NOT delete the old KMS key at all.** Leave it in
`Disabled` state. KMS key retention has negligible cost; losing the
online `kms:GetPublicKey` endpoint for a key you signed with forces
auditors onto the `signing_keys` archive path (which works fine), but
there is no upside to eliminating that redundancy.

---

## Verification

After steps 1–4 complete, run these checks in order.

### Check 1 — New row in the archive

```sql
SELECT kms_key_id, key_version, first_seen_at, algorithm
FROM signing_keys
ORDER BY first_seen_at DESC
LIMIT 5;
```

You should see the new `(kms_key_id, key_version)` tuple as the most
recent row. `first_seen_at` ≈ the time of the SIGHUP.

### Check 2 — Rotation telemetry

Check your metrics backend (Prometheus, Datadog, ...) for the event
`recurse.gateway.kms_rotation_detected` — one counter increment per
detected rotation. Label `new_key_version` should match the value from
Check 1.

### Check 3 — New attestations carry the new version

Issue a single test request through the Gateway, then query:

```sql
SELECT run_id, signer_kms_key_id, signer_key_version, timestamp
FROM attestations
ORDER BY timestamp DESC
LIMIT 5;
```

The most recent row's `signer_key_version` should match Check 1.

### Check 4 — Old receipts still verify

Pick a `run_id` from **before** the rotation:

```bash
cd <repo-root>
./docs/auditor/recurse-verify \
  --trust-anchor "$OLD_KEY_ARN" \
  --run-id <old-run-id> \
  --zip /path/to/export-evidence-<old-run-id>.zip
# → PASS
```

The wrapper resolves the anchor via `kms:GetPublicKey` against the
OLD ARN (still readable even if the key is disabled), matches it
against the archive row for the old `key_version`, and verifies the
DSSE signature. This is the SC-006 contract.

### Check 5 — Archive chain integrity

The `KmsRotationWatcher` recomputes the archive's hash chain at boot.
To force a re-check without restarting the Gateway:

```elixir
# Remote IEx into the Gateway node.
iex(recurse_gateway@host)> Recurse.Gateway.KmsRotationWatcher.verify_archive_chain()
:ok
```

Any `{:error, {:archive_integrity_violation, row_id}}` return means a
row's `chain_hash` doesn't match the recomputed value from the
preceding row — treat this as a **severity-1 incident** (the
append-only invariant has been violated; the DB may have been
tampered with or a trigger bypassed).

---

## Emergency rotation

If a key compromise is suspected:

1. **Immediately** disable the old key to stop further signing:

   ```bash
   aws kms disable-key --key-id "$OLD_KEY_ARN"
   ```

   The Gateway's `SecretsProvider.sign/3` calls will start failing;
   `/healthz` reports `secrets: down`; in-flight chat completions
   return `502 ERR_KMS_UNAVAILABLE` per FR-016.

2. Follow Option B steps 1–4 to mint and cut over to the new key.

3. Retain the old key (do NOT schedule deletion). You want its public
   key PEM to remain fetchable as long as any pre-compromise receipt
   could still be audited. The `signing_keys` archive retains the
   public PEM regardless, but keeping the KMS key alive gives
   auditors a second source of truth.

4. Post-incident: audit every attestation signed under the
   compromised `key_version`. The Audit Plane's
   `/v1/audit/receipts?signer_key_version=<compromised>` lists them.

5. Consider a fleet-wide trust-store refresh — if customers or
   partners have cached the compromised public key out-of-band, they
   need to re-fetch.

---

## Rollback

True rollback (unsigning + re-signing receipts) is impossible by
design — the ledger is append-only (Constitution Principle III).
What you CAN do after a botched rotation:

- **Revert the Tier Configuration** to point at the OLD ARN. Receipts
  signed in the window between cutover and revert keep their
  `key_version` metadata; they remain verifiable via the archive row
  that the watcher wrote for them.
- **Re-enable the old KMS key** if you disabled it:
  `aws kms enable-key --key-id "$OLD_KEY_ARN"`.
- **Cancel pending deletion**:
  `aws kms cancel-key-deletion --key-id "$NEW_KEY_ARN"`.
- **Investigate why the rotation failed** — most common causes:
  - Missing IAM permissions on the new key.
  - Stale Tier Configuration cache (need a fresh SIGHUP).
  - Finch `:kms_pool` exhaustion during peak traffic (bump
    `finch_pool` size).

If the rotation failure left the Gateway in a non-bootable state (e.g.
the `signing_keys` archive chain-integrity check failed on restart),
the Gateway will refuse to serve and emit
`archive_integrity: compromised` from `/healthz`. At that point the
only path forward is a forensic review of the DB — the archive
invariant exists precisely to detect this class of tampering.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `KmsRotationWatcher` never advances past v1 | Polling disabled or misconfigured | Verify `config :recurse_gateway, :kms_rotation_watcher, enabled: true`; check Gateway logs for watcher startup. |
| New receipts still reference old version 60s+ after cutover | SIGHUP not routed to Gateway | Confirm container PID 1 is the BEAM VM, not a shell wrapper; send SIGHUP to the BEAM PID directly. |
| `/healthz` reports `archive_integrity: compromised` | Archive chain-hash mismatch | Do NOT attempt to "repair" — escalate to the Recurse team; this is a tampering signal. |
| `recurse-verify` fails on old receipts after rotation | Trust anchor mismatch | Confirm `--trust-anchor` points at the KMS ARN that signed the receipt (may be the OLD ARN); check `aws kms describe-key --key-id ...` responds. |
| `kms:Sign` returns `ThrottlingException` during normal load | `:kms_pool` too small OR AWS account quota | Raise `:kms_pool` size in `RecurseGateway.Application`; request KMS quota increase from AWS. |

---

## Cross-references

- `apps/recurse_gateway/lib/recurse_gateway/kms_rotation_watcher.ex`
  — the watcher GenServer.
- `apps/recurse_providers/lib/recurse_providers/impls/aws_kms_secrets_provider.ex`
  — the AWS KMS `SecretsProvider` impl.
- `apps/recurse_providers/lib/recurse_providers/impls/postgres_merkle_ledger/schemas/signing_key.ex`
  — the `signing_keys` archive schema + chain-hash helpers.
- `specs/001-api-jido-foundations/contracts/signing_key_archive.md`
  — the durable signing-key archive contract.
- `specs/002-standalone-gateway-vertical-slice/spec.md` §US5 + FR-015.
- `docs/operator/deployment_guide.md` — broader operator deployment
  context.
- `docs/auditor/recurse-verify` — the CLI verifier that consumes the
  archive material.
