# fable-demo — local demo runbook (recording script)

Everything runs on this machine: local Homebrew Postgres, software ES256
signer, filesystem CAS, echo LLM provider. No Docker, no AWS, no OpenAI key.
Originally run from a scratch workspace (`r5e-enterprise.fable-demo`); these
scripts were ported back to main as the record of the verified-by-running
demo. They are dev-only — nothing here is loaded by the app.

The flow on camera: **allowed tool call → activate deny bundle → same call
denied → both receipts in the audit console → evidence export → offline
cryptographic verification (exit 0)**.

---

## 0. One-time setup (before recording day)

```bash
cd ~/Documents/repos/r5e-enterprise.fable-demo

# Toolchain sanity (all already satisfied on this machine):
#   elixir 1.19.5-otp-28 / erlang 28.0 / rust 1.92.0 (.tool-versions)
#   Homebrew postgresql@16 running on :5432 with a `recurse` role
mix deps.get && MIX_ENV=dev mix compile
MIX_ENV=dev mix do ecto.create, ecto.migrate

# Broker/internal-JWT ES256 keypair (collapsed-broker; signs session JWTs):
./scripts/gen-broker-key.sh        # no-op if secrets/ already has it

# UI deps (pnpm 11 needs the build-script approval once):
cd ui && pnpm install && pnpm approve-builds --all && cd ..

# Vendored offline Cedar canonicalizer for recurse-verify Step 4
# (same pinned cedar-policy crate as the Gateway NIF):
cd native/recurse_cedar && cargo build --release --bin cedar-canonical-hash
cp target/release/cedar-canonical-hash ../../docs/auditor/ && cd ../..
```

If you want the ledger EMPTY for the recording:

```bash
MIX_ENV=dev mix do ecto.drop, ecto.create, ecto.migrate
```

## 1. Terminal A — boot the gateway BEAM

```bash
cd ~/Documents/repos/r5e-enterprise.fable-demo
./scripts/fable_demo/boot.sh
```

This exports the env (`R5E_START_HTTP=true PORT=4000`, broker key path,
`BROWSER_OIDC_PROVIDER=oidc`, BundleLoader paths) and drops you into iex
with the `FableDemo` helpers preloaded. Then, in iex:

```elixir
FableDemo.setup!()                  # seeds tenant, installs dev providers
FableDemo.use_permissive_bundle!()  # loads the permissive Cedar bundle
```

Sanity check from any shell: `curl -s localhost:4000/healthz` — every
component `ok` (kms = the local ES256 software signer, storage = local
filesystem CAS, ledger = local Postgres-Merkle).

> Non-interactive alternative (stages the whole allow→deny sequence at
> boot and leaves the BEAM up):
> `... same env ... mix run --no-halt -e 'Code.require_file("scripts/fable_demo/stage.exs")'`
> (exact command in `boot.sh`'s comment output).

## 2. Terminal B — audit console UI

```bash
cd ~/Documents/repos/r5e-enterprise.fable-demo/ui && pnpm dev
```

Open http://localhost:5173/admin/login in the browser.

## 3. Log in (dev login endpoint — no IdP)

In the browser devtools console (any page on localhost:5173):

```js
fetch('/admin/test/login', {method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({principal_subject: 'operator@local.dev',
                        recurse_role: 'platform_operator'})})
  .then(r => r.ok && (window.location.href = '/admin/dashboard'));
```

`POST /admin/test/login` is the MIX_ENV=dev-gated server-side cookie mint
(`DevLoginHandler`; 404s unless `:dev_login_enabled?` is set in
config/dev.exs). It mints the same broker-shaped internal JWT + HttpOnly
`r5e_session` cookie a real login produces. Or from a shell:

```bash
curl -c /tmp/r5e.cookies -X POST localhost:4000/admin/test/login \
  -H 'Content-Type: application/json' \
  -d '{"principal_subject":"operator@local.dev","recurse_role":"platform_operator"}'
curl -b /tmp/r5e.cookies localhost:4000/v1/auth/me
```

Fallback if the endpoint is ever unavailable: `FableDemo.mint_cookie()` in
iex prints a `document.cookie = ...` one-liner to paste in devtools.

## 4. The allow beat

In iex (Terminal A):

```elixir
FableDemo.ToolDemo.run("ls -la /tmp")
```

This drives a full Codex-shaped WebSocket session through the live
`WebSocketBridge` (mock OpenAI-Responses upstream, in-BEAM): the model
"asks" to run `ls -la /tmp`, Cedar allows, the function_call frames are
forwarded, and on session close a DSSE-signed `:llm_call_attested` receipt
commits to the ledger. The iex output prints `synthetic denial injected:
false / function_call forwarded: true`.

Browser: refresh the dashboard — the new LLM_CALL row is at the top.
Click the row → receipt drawer (IDENTITY / PREDICATE / PROOF / POLICY /
PAYLOAD / VERIFY tabs; verification badge `global_inclusion_verified`).

Optionally also fire an allowed chat completion (prints a copy-paste curl):

```elixir
FableDemo.print_curl()
```

## 5. The denial beat

In iex:

```elixir
FableDemo.use_deny_bundle!()
```

This overwrites the file the filesystem BundleLoader watches with
`scripts/fable_demo/deny_destructive.cedar` (permit-all + forbids on
`shell`/`exec_command` tool calls whose args match `*rm -rf*` or
`*DROP DATABASE*`) and triggers the loader's SIGHUP reload path; iex
prints the new active bundle hash. Then:

```elixir
FableDemo.ToolDemo.run("rm -rf /tmp/test-dir")
```

Output: `function_call forwarded: false / synthetic denial injected: true`
— the destructive tool call never reached the client; it got a synthetic
assistant message naming the rule, tenant, principal, bundle hash, and
appeal path. Two receipts committed: the parent `:llm_call_attested` and a
`:tool_use_denied`.

Browser: refresh — the POLICY_DENIED (red) row is at the top. Click it for
the drawer; the PREDICATE tab carries the signed denial detail.

## 6. Export + offline verification (the closer)

From any shell — grab the latest run_ids and export:

```bash
cd ~/Documents/repos/r5e-enterprise.fable-demo
JWT=$(...)   # printed by FableDemo.print_curl(), or export from the UI instead
RUN=$(psql -h localhost -U recurse -d recurse_dev -tAc \
  "SELECT run_id FROM attestations WHERE event_kind='tool_use_denied' ORDER BY inserted_at DESC LIMIT 1")

curl -s -X POST localhost:4000/v1/audit/export \
  -H "Authorization: Bearer $JWT" -H "Content-Type: application/json" \
  -d "{\"run_ids\":[\"$RUN\"]}" -o /tmp/evidence.zip

# Pull the signer pubkey out as the trust anchor (in a real engagement the
# auditor brings this independently):
unzip -o -d /tmp/anchor /tmp/evidence.zip signing_key.pem

./docs/auditor/recurse-verify --zip /tmp/evidence.zip \
  --trust-anchor /tmp/anchor/signing_key.pem
# → VERIFY: PASS (strict, anchored); exit 0
```

The UI's `EXPORT EVIDENCE (.ZIP)` button in the receipt drawer downloads
the same zip if you prefer to do this from the browser (multi-select on
the table wraps them in an outer zip — unzip once first).

What the verifier proves, fully offline: trust-anchor match, DSSE ES256
signature over the predicate, RFC 9162 local + global Merkle inclusion
against the ledger roots, policy-bundle binding (dual-rule: Cedar-canonical
JCS hash via the vendored `cedar-canonical-hash`, raw-bytes F002 compat,
or the system-event sentinel for predicate-only kinds), payload hash (or
an explicit stated N/A for predicate-only receipts), and the
verification-level / completeness-advisory interpretation.

## Reset between takes

```elixir
FableDemo.use_permissive_bundle!()   # back to allow-everything
```

```bash
MIX_ENV=dev mix do ecto.drop, ecto.create, ecto.migrate   # empty ledger (BEAM stopped)
```

The session cookie survives BEAM restarts (deterministic dev cookie key +
persisted broker PEM) — no re-login needed between takes.

## Known rough edges (on camera)

* The receipt drawer's POLICY DECISION panel on a `tool_use_denied`
  receipt shows the OUTER container's decision — `ALLOW` (the parent
  call's verdict). The denial itself is in the PREDICATE tab. Narrate it
  as "the signed denial detail", or keep the drawer on the PREDICATE tab.
* The drawer's REQUEST SUMMARY says "Unattested action" for 009 receipts
  (F004's summary extractor predates them).
* `Live-tail` toggle exists on the dashboard — untested in this workspace;
  prefer manual refresh on camera.
* The histogram's time axis compresses everything staged in one session
  into a single bucket; zoom (drag across bars) if you want it to look
  less empty.
