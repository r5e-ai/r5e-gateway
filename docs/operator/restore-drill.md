# Postgres Backup + Restore Drill — Recurse Standalone AI Gateway

**Audience**: platform operator responsible for the Recurse Gateway's
backup pipeline and disaster-recovery posture.
**Scope**: verifying that Postgres + S3 backups restore to a usable Gateway
**and** that the restored state passes end-to-end cryptographic verification
via `recurse-verify` against receipts captured before the drill.
**Related specs**: F002 spec §FR-027, SC-012; SOC 2 CC9.1.
**Frequency**: quarterly minimum. The CI equivalent (T103) runs nightly and
scales down the drill to a smoke-test, but does **not** replace the human-
operated quarterly exercise.

---

## 1. Rationale

Recurse's entire value proposition depends on receipts being retrievable +
verifiable **years after** the fact. Three failure modes will take you down:

1. **Postgres dies** and the last backup is stale, corrupt, or never actually
   ran (the classic "we have a backup cron, nobody ever tested restore" story).
2. **S3 objects are deleted** (accidental, policy misconfiguration, rogue
   actor) and the payload referenced by `payload_uri` is unrecoverable.
3. **Broker signing keys are lost** and the JWT trust-anchor disappears; old
   receipts still validate against KMS, but new receipts cannot be issued.

F002 FR-027 mandates that operators **periodically verify their backup
pipeline actually restores a usable Gateway**. This drill proves all three
pieces simultaneously. SC-012 sets the ceiling at 1 hour for a full drill.

---

## 2. Backup pipeline

### 2.1 Recommended: `pg_basebackup` + WAL archiving via `wal-g`

Continuous-protection setup suitable for 10M+ attestations/month.

```bash
# /etc/systemd/system/wal-g-basebackup.service
[Unit]
Description=Recurse Postgres base backup

[Service]
Type=oneshot
User=postgres
EnvironmentFile=/etc/wal-g/wal-g.env
ExecStart=/usr/local/bin/wal-g backup-push /var/lib/postgresql/data

# /etc/systemd/system/wal-g-basebackup.timer
[Unit]
Description=Nightly Recurse base backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

`wal-g.env` per `docs/operator/install.md` §3.

### 2.2 Minimum-viable: `pg_dump` + cron

Acceptable for < 100K attestations/month deployments:

```bash
# /etc/cron.d/recurse-pgdump
0 2 * * * postgres \
  pg_dump -Fc -d recurse -f /var/backups/recurse/$(date +\%Y\%m\%d).dump \
  && find /var/backups/recurse -name '*.dump' -mtime +35 -delete
```

Upload the dump to S3 (or an off-host location) — a backup on the same host as
the DB is not a backup.

```bash
aws s3 sync /var/backups/recurse/ s3://<backup-bucket>/postgres/ \
  --storage-class STANDARD_IA
```

### 2.3 Payload bucket replication

Enable Cross-Region Replication on the payload bucket so a regional AWS outage
doesn't take out the audit record:

```bash
aws s3api put-bucket-replication \
  --bucket <primary-bucket> \
  --replication-configuration file://replication.json
```

### 2.4 Broker signing keys

Broker PEM files are **not** automatically backed up by anything that reads
the filesystem — they live under `/etc/recurse/secrets/` with mode 400. Back
them up separately:

- **Recommended**: AWS Secrets Manager, rotate-on-schedule, access log enabled.
- **Acceptable**: a root-only `tar`-then-gpg archive, held offline.

Do **not** commit broker keys to the same backup stream as DB + payloads.
If your backups are ever disclosed, the broker key is the weakest link — an
attacker with the broker key + a stolen DB dump + KMS trust-anchor could
forge receipts backdated into the retention window.

---

## 3. Drill procedure

### 3.1 Pre-drill: pick + record your known-good receipts

**Before** taking anything offline, capture 5 canonical receipts. Save them
somewhere outside the blast radius (your laptop, a separate S3 prefix):

```bash
mkdir -p ./drill-$(date +%Y%m%d)
cd ./drill-$(date +%Y%m%d)

# Export the 5 most-recent receipts into a reference zip.
RUN_IDS=$(curl -s "http://localhost:4000/v1/audit/receipts?limit=5" \
  -H "Authorization: Bearer $XOBS_PLATFORM_OPERATOR" \
  | jq -r '[.receipts[].run_id] | join(",")')
echo "$RUN_IDS" > known-good-run-ids.txt

curl -s -X POST "http://localhost:4000/v1/audit/export" \
  -H "Authorization: Bearer $XOBS_PLATFORM_OPERATOR" \
  -H "Content-Type: application/json" \
  -d "{\"run_ids\":[\"$(echo $RUN_IDS | tr ',' '\",\"')\"]}" \
  -o known-good-evidence.zip

# Resolve trust anchor from KMS — save locally.
aws kms get-public-key --key-id <kms-arn> --output text --query PublicKey \
  | base64 -d | openssl pkey -pubin -inform DER -out expected-public-key.pem
```

### 3.2 Backup snapshots

```bash
# Postgres
sudo -u postgres pg_dump -Fc recurse -f ./drill-snapshot.dump

# Payloads — mirror the bucket (or the subset you care about) to a drill bucket.
aws s3 sync s3://<primary-bucket>/ s3://<drill-bucket>/ --only-show-errors
```

### 3.3 Teardown

```bash
docker compose down
# Drop ledger schema — we want a genuinely empty DB for the restore test.
sudo -u postgres psql -d recurse -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
```

Alternative, safer variant: bring up a **second** Postgres on port 5433 and
point a replica Gateway at it. This avoids touching the live DB at all and
lets you do the drill without downtime. Recommended for production.

### 3.4 Restore

```bash
# Postgres
sudo -u postgres createdb recurse     # if dropped in 3.3
sudo -u postgres pg_restore -d recurse ./drill-snapshot.dump

# Payloads — either leave as-is (primary bucket was not touched) or flip
# the Gateway's storage_provider.s3.bucket to the drill bucket in
# tier-config.yaml. If you flip, recompute tier-config.sha256 afterward.
```

### 3.5 Bring up

```bash
docker compose up -d
# Wait for readiness.
while ! curl -sf http://localhost:4000/readyz > /dev/null; do
  sleep 2
done
```

### 3.6 End-to-end verify — the actual test

For each run_id saved in step 3.1:

```bash
RUN_IDS=$(cat ./drill-$(date +%Y%m%d)/known-good-run-ids.txt)
mkdir -p /tmp/drill-exports

for rid in $(echo $RUN_IDS | tr ',' ' '); do
  echo "=== $rid ==="
  curl -s -X POST "http://localhost:4000/v1/audit/export" \
    -H "Authorization: Bearer $XOBS_PLATFORM_OPERATOR" \
    -H "Content-Type: application/json" \
    -d "{\"run_ids\":[\"$rid\"]}" \
    -o "/tmp/drill-exports/${rid}.zip"

  ./docs/auditor/recurse-verify \
    --zip "/tmp/drill-exports/${rid}.zip" \
    --trust-anchor ./drill-$(date +%Y%m%d)/expected-public-key.pem

  echo "exit: $?"
done
```

**Pass criteria**: all five `recurse-verify` invocations exit 0.

If any exit non-zero, stop and triage (§5).

---

## 4. Timing targets (SC-012)

For a deployment at the 1M attestations/month scale:

| Step | Target |
|---|---|
| 3.1 Pre-drill capture | 2 min |
| 3.2 Backup snapshots | 5 min (pg_dump) or < 1 min (basebackup reference) |
| 3.3 Teardown | 1 min |
| 3.4 Restore | 10–20 min (scales with DB size) |
| 3.5 Bring up + readiness | 2 min |
| 3.6 Verify 5 receipts | 2 min |
| **Total** | **< 45 min** |

At 10M/month, restore step expands to 30–60 min; the drill exceeds the SC-012
floor. Options at that scale:

- Restore to a side-by-side Postgres (§3.3 alternative) so downtime is zero.
- Pre-stage a nightly restore in a sandbox account so quarterly drill is just
  re-running `recurse-verify` against that already-restored instance.

---

## 5. Troubleshooting

### `recurse-verify` fails step `[1] DSSE signature`

- **Likely cause**: the trust anchor PEM in `--trust-anchor` is from a
  different KMS key than the one that signed the receipt. Check
  `signed_predicate.signer` in the receipt JSON for the expected KMS ARN,
  re-resolve the public key with `aws kms get-public-key --key-id <arn>`.
- **Less likely**: backup is from before a KMS key rotation and the restored
  `signing_keys` table is missing the newer key_version. Cross-check the
  `signing_keys` table count before + after restore.

### `recurse-verify` fails step `[2] RFC 9162 local inclusion`

- **Likely cause**: `merkle_nodes` table partially restored. Check count:
  `SELECT count(*) FROM merkle_nodes;` in source vs target. Re-restore if
  counts differ.

### `recurse-verify` fails step `[3] RFC 9162 global inclusion`

- **Likely cause**: `global_ledger_entries` out of sync with source. Often
  caused by concurrent writes during the backup — prefer `pg_basebackup` over
  `pg_dump` for databases with active writes during backup.

### `recurse-verify` fails step `[5] payload_hash`

- **Likely cause**: payload was not mirrored to the drill bucket, or the
  payload S3 object was deleted/corrupted. Check `aws s3 ls s3://<bucket>/tenants/<tid>/runs/<date>/<run_id>.json`.
- **Less likely**: Object Lock protected the object from deletion but
  lifecycle transitioned it to Glacier and the verifier didn't wait for
  restore. Use `--glacier-restore-wait` flag on `recurse-verify`.

### `recurse-verify` exits 2 — warning only

- Exit code 2 means "cryptographic pass **without** trust anchor" — the
  receipt is consistent with itself but you did not supply `--trust-anchor`.
  In a drill this is a **fail** even though the exit code is a warning.
  Always supply `--trust-anchor`.

### Gateway boots but `/readyz` returns 503 with `postgres: unreachable`

- Verify `DATABASE_URL` in `.env.gateway` points at the restored Postgres.
- Check pg_hba.conf allows the Gateway container's IP.
- Check `docker compose logs postgres` for restore-side crash loops.

---

## 6. Frequency + sign-off

- **Quarterly**: full drill per §3, human-operated, signed off by the
  platform-operations on-call lead. File the drill-completion receipt with
  your change-management system — this is audit evidence for SOC 2 CC9.1
  and ISO 27001 A.8.13.
- **Nightly**: the CI-equivalent drill runs automatically as
  `test/integration/sc012_restore_drill_test.exs` (T103). It uses a
  scaled-down fixture set (3 synthetic receipts), an ephemeral Docker compose
  stack, and asserts the same `recurse-verify` end-state. A failure breaks
  `main` and pages the on-call.
- **On major version upgrade**: run the drill immediately before and after.
  Schema migrations + restore-path changes are the #1 source of drill failures.

Record drill outcomes in:

```
docs/operator/drill-log.csv
# header: date,operator,receipts_tested,duration_min,outcome,notes
2026-04-24,tjones,5,38,pass,first post-F002 drill
```

---

## 7. Automation — CI-equivalent drill

`test/integration/sc012_restore_drill_test.exs` (T103) is the automated
nightly drill. It:

1. Spins up a pair of Postgres containers (`source` + `restore-target`) under
   `docker compose -f test/integration/sc012-compose.yaml up`.
2. Seeds 3 receipts against `source` via the Gateway commit pipeline.
3. Runs `pg_dump -Fc source | pg_restore -d restore-target`.
4. Flips the Gateway's `DATABASE_URL` to `restore-target` and reboots.
5. Calls `/v1/audit/export` for each of the 3 run_ids.
6. Shells out to `recurse-verify` and asserts exit 0.

When the human-operated quarterly drill fails, run the automated drill first
— if it passes, the bug is in your **production** backup pipeline (infra,
credentials, lifecycle policy). If it fails, the bug is in the Recurse code
or schema.
