# fable-demo — REAL Codex through the local gateway

The other runbook in this directory (`README.md`) drives the demo with
`FableDemo.ToolDemo.run/1`: a mock OpenAI-Responses upstream inside the
BEAM. It produces real receipts and real Cedar decisions, but the model
never actually asked for anything — the tool call is scripted.

**This runbook is the real thing.** Unmodified Codex CLI, real OpenAI
upstream, real model-chosen tool calls, Cedar enforcing in the middle,
signed receipts in the local ledger and visible in the audit console.

Everything is local except OpenAI itself. Nothing is committed or pushed.

---

## The shape of it

```
codex CLI ──TLS──► 127.0.0.1:443 ──► 127.0.0.1:4443 ──► real chatgpt.com
   ▲                (socat)          (Recurse gateway)          │
   │                                        │                   │
   │                                   Cedar gate ◄─────────────┘
   │                                        │
   └── allowed frames, or a synthetic ──────┤
       denial that names the rule           │
                                            ▼
                                  local Postgres ledger
                                            │
                                            ▼
                                  audit console :5173
```

Two DNS facts make this work, and they point opposite directions:

- `/etc/hosts` sends **Codex's** `chatgpt.com` to `127.0.0.1`.
- `BypassDnsResolver` resolves **the gateway's own** `chatgpt.com`
  against public DNS (8.8.8.8 / 1.1.1.1), so the gateway still reaches
  real OpenAI.

That asymmetry is the product's whole DNS-override wedge (spec 009
FR-007 / R-011): the client is unmodified and doesn't know it's proxied.

---

## 0. One-time, before demo day

```bash
brew install --cask codex   # CLI (0.149.1 at time of writing)
brew install socat          # 443 -> 4443 bridge
```

**Log in to Codex first, with the /etc/hosts override NOT yet in
place.** OAuth against real OpenAI, no MITM in the path:

```bash
codex login
cat ~/.codex/auth.json | jq '.tokens | keys'   # access_token, id_token, refresh_token
```

Doing login before the override is deliberate. `AuthPassthrough` does
proxy `auth.openai.com` correctly, but debugging an OAuth redirect
through a MITM on demo day is a bad trade for a step you only do once.

---

## 1. Terminal A — the gateway

```bash
cd ~/Documents/repos/r5e-enterprise.fable-demo
./scripts/fable_demo/boot-real.sh
```

Brings up, in order: dev TLS cert → broker key + permissive Cedar
bundle → `ecto.create/migrate` → seed the real-OpenAI
`LlmProviderConfig` rows → BEAM with **both** listeners:

- `http://localhost:4000` — audit plane (dashboard API)
- `https://localhost:4443` — LLM proxy (what Codex will hit)

It also installs the dev providers, so proxied calls commit signed
receipts. That is the piece `scripts/dev/llm-proxy-up.sh` was missing —
it brought up the proxy but left `ProviderRegistry` uninstalled, so the
BEAM logged `skipping attestation emit` and the ledger stayed empty.

Everything runs under one tenant (`01TEN_FABLE_DEMO_LOCAL`) so the
receipts Codex produces are the ones the dashboard cookie can read.

Sanity check from any shell:

```bash
curl -s localhost:4000/healthz; curl -sk https://localhost:4443/healthz
```

## 2. Terminal B — audit console

```bash
cd ~/Documents/repos/r5e-enterprise.fable-demo/ui && pnpm dev
```

Open **http://localhost:5173/admin/** — not `/admin/login`. Vite proxies
`/admin/login` to the gateway, which serves it from the built SPA bundle
at `priv/static/admin/`; that bundle isn't built in this workspace, so
the route 500s with `{:error, :enoent}`. Harmless, and irrelevant here —
local login is the dev cookie mint below, not the OIDC page.

From the devtools console on that page:

```js
fetch('/admin/test/login', {method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({principal_subject: 'operator@local.dev',
                        recurse_role: 'platform_operator'})})
  .then(r => r.ok && (window.location.href = '/admin/dashboard'));
```

## 3. Terminal C — turn the MITM on

```bash
sudo ./scripts/fable_demo/mitm-on.sh
```

Adds the three `/etc/hosts` entries, flushes the DNS cache, and runs a
`socat` bridge from `:443` to `:4443` in the foreground. **Ctrl-C
reverts the hosts entries as well as stopping the bridge** — the script
traps its own exit, so closing the terminal can't leave the machine
half-MITMed. If it ever does exit uncleanly:

```bash
sudo ./scripts/fable_demo/mitm-off.sh
```

`socat` rather than the `pfctl rdr` rule the older runbooks use: pfctl
redirects are unreliable for locally-originated loopback traffic on
current macOS, and a foreground process you Ctrl-C beats a firewall
rule you have to remember to flush.

## 4. Terminal D — Codex

```bash
export CODEX_CA_CERTIFICATE=~/Documents/repos/r5e-enterprise.fable-demo/_build/audit-dev/recurse-gateway-llm-proxy-ca.pem
mkdir -p /tmp/codex-demo && cd /tmp/codex-demo
codex
```

Codex ships its own root store and ignores the macOS keychain, so the
env var is how it trusts the demo CA. No system trust store change.

**Point it at the CA (`...-ca.pem`), not the served chain
(`...-cert.pem`).** The CA is the trust anchor; the chain is what the
gateway presents.

If Codex still says **unknown issuer**, the env var didn't reach it —
0.149 does still honour `CODEX_CA_CERTIFICATE` (it's in the binary), but
only for processes started after the export, and only in that shell.
Two more robust options:

```bash
# Per-shell, and keeps the rest of the internet trusted.
# boot-real.sh writes this bundle: macOS system roots + the demo CA.
export SSL_CERT_FILE=~/Documents/repos/r5e-enterprise.fable-demo/_build/audit-dev/codex-ca-bundle.pem
```

```bash
# Machine-wide, survives new terminals and GUI-launched apps.
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/Documents/repos/r5e-enterprise.fable-demo/_build/audit-dev/recurse-gateway-llm-proxy-ca.pem
```

Do **not** set `SSL_CERT_FILE` to the bare CA file — that *replaces* the
trust store instead of extending it, so Codex would trust the gateway
and nothing else (its non-proxied calls, like the `codex_apps` MCP
endpoint, would then fail). Use the bundle.

Undo the machine-wide trust afterwards with:

```bash
sudo security delete-certificate -c "Recurse Enterprise LLM Proxy CA (audit-dev)" \
  /Library/Keychains/System.keychain
```

### Why two certificates

`scripts/dev/llm-proxy-cert.sh` — which the older local runbooks call —
emits a single self-signed certificate carrying `CA:TRUE` and serves it
as the leaf. curl and OpenSSL clients accept that. Codex is Rust, and
rustls enforces the CA-vs-end-entity distinction, so it rejects the
handshake:

```
invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))
```

Codex then falls back from WebSockets to HTTPS, fails the same way, and
parks in `Reconnecting... waiting for network`.

`boot-real.sh` therefore generates TLS material with
`scripts/dev/llm-proxy-cert-generate-and-push.sh <env> --dry-run`, which
already builds the correct two-tier PKI (that script's comments name
this exact bug). `--dry-run` keeps it local — no AWS call, no
credentials. The `audit-dev` argument only picks an output directory
here. `boot-real.sh` also hard-fails at startup if the cert it is about
to serve is CA-marked, so this can't silently regress.

### The allow beat

```
> hi codex, can you list this directory for me?
```

Codex asks to run `ls -la`. Cedar permits. The `function_call` frames
forward byte-identical, Codex runs it, output appears.

Terminal A shows the upstream connect, the principal extraction, and
the Cedar allow. Refresh the dashboard: a new `LLM_CALL` row is on top.
Click it for the receipt drawer.

### Swap policy

From any terminal (does not disturb Terminal A):

```bash
./scripts/fable_demo/swap-bundle.sh deny
```

Prints the newly-active bundle hash. Also available as
`FableDemo.use_deny_bundle!()` inside Terminal A's iex.

### The deny beat

**Open a new Codex session** (new window) so the swap is unambiguous,
and ask for the same thing:

```
> hi codex, can you list this directory for me?
```

Now the gate denies. Codex never receives the `function_call` frames —
they're suppressed byte-precisely — and instead gets a synthetic
assistant message naming the rule, bundle hash, tenant, principal, and
appeal path. Codex displays it inline and continues its loop without
running the command.

Dashboard: a red `POLICY_DENIED` row on top. The signed denial detail
is on the **PREDICATE** tab (the POLICY DECISION panel shows the outer
call's verdict — a known F004 rough edge).

Reset between takes:

```bash
./scripts/fable_demo/swap-bundle.sh permissive
```

---

## Which bundle denies what

`scripts/fable_demo/deny_destructive.cedar` is the demo's deny bundle.
Cedar is deny-by-default, so it carries a baseline `permit` and then
`forbid` rules that override it.

The tool name and argument key Codex uses have moved across releases —
`shell`/`command` pre-0.125, `exec_command`/`cmd` on 0.125+, and 0.149
also ships `local_shell` and `unified_exec` shapes. The bundle covers
the shapes we've confirmed; if a Codex upgrade moves them again, the
symptom is a call that sails through when it should have been denied.

**The drift detector is in Terminal A.** These lines mean the parser saw
a shape it doesn't extract intents from, so Cedar was never consulted:

```
OpenaiResponses parser: unhandled output_item type=...
OpenaiResponses parser: unhandled event type=...
```

If a deny doesn't fire, read those first — they name the new shape.

---

## Cleanup

Ctrl-C Terminal C — that reverts `/etc/hosts` and stops the bridge in
one move. To be sure:

```bash
sudo ./scripts/fable_demo/mitm-off.sh   # idempotent; prints what resolves now
```

Codex tokens stay in `~/.codex/auth.json`. To re-run later, just
`sudo ./scripts/fable_demo/mitm-on.sh` again.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Codex: TLS handshake / cert error | `CODEX_CA_CERTIFICATE` unset or stale | Re-export the absolute path; cert is 30-day, regenerate with `scripts/dev/llm-proxy-cert.sh` |
| Codex hangs on connect | bridge not running, or `/etc/hosts` line missing | `dscacheutil -q host -a name chatgpt.com` should say `127.0.0.1`; check Terminal C is still up (`dig` bypasses `/etc/hosts` on macOS — don't trust it here) |
| `502 ERR_NO_UPSTREAM_CONFIG` | provider rows seeded under a different tenant | Re-run `boot-real.sh`; it seeds under `01TEN_FABLE_DEMO_LOCAL` |
| Dashboard empty after a real call | tenant mismatch, or providers not installed | Terminal A should say `providers installed`; never `skipping attestation emit` |
| Deny doesn't fire | Codex changed its tool-call shape | Read the `unhandled ...` lines in Terminal A, then extend the bundle + parser |
| `could not connect to r5e_demo@...` from swap-bundle.sh | BEAM started outside `boot-real.sh` | Restart via `boot-real.sh` (it names the node) |
