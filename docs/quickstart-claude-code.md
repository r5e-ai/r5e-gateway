# Quickstart with Claude Code

For someone with Docker and Claude Code on their own machine who wants to see a model call become a receipt, a destructive command get denied, and the evidence verify offline. About 15 minutes.

Docker with Compose v2, Claude Code signed in, `curl`, `jq`, `unzip`, `openssl`, and `xxd`; `cargo` only for `bin/r5e evidence verify`.

<!-- Every output block below is pasted from a run on 2026-09-02 against the image built from this checkout, with three substitutions: the dashboard port (captured on 4100 because 4000 was taken on that machine, shown as the default 4000), the checkout path (shown as /path/to/r5e-enterprise), and the Claude Code account id (shown as <your-account-id>). -->

## 1. Clone and configure

```
bin/r5e init
```
```
r5e init: wrote .env with generated SECRET_KEY_BASE + GATEWAY_ADMIN_SESSION_SECRET_KEY_BASE
next: docker compose up -d
```

The stack publishes ports 4000 (dashboard) and 4443 (proxy) on loopback; `init` checks both and names the variable to set in `.env` (`R5E_GATEWAY_PORT` or `R5E_PROXY_PORT`) if one is taken. Docker volumes are keyed by the compose project name `r5e`, so a second checkout on the same machine shares the ledger and signing key; run `docker compose down -v` first for a clean ledger.

## 2. Start the stack

```
docker compose up -d
bin/r5e status
```
```
/healthz {"components":{"broker_jwks":"ok","cedar_policy":"ok","gateway":"ok","kms":"ok","ledger":"ok","storage":"ok"},"status":"ok"}
/readyz  not ready: jwks_warm pending until the first login (bin/r5e login)
```

The first `up` builds the gateway image, which takes several minutes. `status` exits 0 with exactly these two lines; after the sign-in below the `/readyz` line becomes the endpoint's JSON.

## 3. Sign in and open the dashboard

```
bin/r5e login
```
```
r5e login: {"dev_login":true,"principal_subject":"local-dev@r5e","recurse_role":"platform_operator","tenant_id":"01TEN_LOCAL"}
r5e login: /v1/auth/me -> {"browser_session_id":"c203e20e6c7796ae80c4d2a52793a141","principal_subject":"local-dev@r5e","recurse_role":"platform_operator","session_expires_at":"2026-09-03T06:08:34Z","session_idle_timeout_at":"2026-09-02T23:08:34Z","tenant_id":"01TEN_LOCAL"}
r5e login: GET /v1/audit/receipts?limit=1 -> HTTP 200

cookie jar: /path/to/r5e-enterprise/.r5e/cookies.txt (curl -b /path/to/r5e-enterprise/.r5e/cookies.txt http://localhost:4000/v1/audit/receipts)
dashboard:  http://localhost:4000/admin/dashboard
  The cookie above is in curl's jar, not in your browser. To sign the browser in:
  open http://localhost:4000/healthz, open the devtools console, paste the line below,
  then open http://localhost:4000/admin/dashboard.
  fetch('/admin/test/login',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"principal_subject":"local-dev@r5e","recurse_role":"platform_operator"}'}).then(r=>r.status)
```

## 4. Point Claude Code at the gateway

```
bin/r5e claude-code setup
```
```
# Claude Code -> r5e gateway (proxy listener on http://localhost:4443)
export ANTHROPIC_BASE_URL=http://localhost:4443
export NO_PROXY=localhost,127.0.0.1
# Then: claude -p "reply with the single word ok"   (existing claude.ai login or API key is forwarded as-is)
# Persist for the Claude desktop app's Code tab: bin/r5e claude-code setup --write-settings
```

## 5. A first prompt

```
echo "reply with the single word ok" | DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 claude -p
```
```
ok
```

The two variables keep the CLI from updating itself or phoning home during the demo; both of those go directly to Anthropic, not through the gateway. Every model call is a receipt, and a prompt can be more than one call (the turn, a session title, a side query). The newest one, the dashboard's newest `LLM_CALL` row, names the account id Claude Code sends; yours differs:

```
curl -s -b .r5e/cookies.txt "http://localhost:4000/v1/audit/receipts?limit=1&event_kind=llm_call_attested" | jq -r '.receipts[0].signed_predicate | [.event_kind, .principal.subject] | @tsv'
```
```
llm_call_attested	claude-code:<your-account-id>
```

## 6. A denied command

The shipped `policy/bundle.cedar` forbids the `Bash` tool when the command contains `rm -rf`. Make a scratch directory and ask for exactly that:

```
mkdir -p scratch
echo "Run exactly this shell command and tell me what happened: rm -rf scratch" | DISABLE_AUTOUPDATER=1 DISABLE_TELEMETRY=1 claude -p --allowedTools Bash
```
```
Tool call 'Bash' (call_id: toolu_013KGk3GZPDHnjCrxGunxgaf) was blocked by org policy.
- Rule: policy6
- Reason: denied_by_cedar_policy
- Policy bundle: 0c20ff0161f7
- Tenant: 01TEN_LOCAL
- Principal: claude-code:<your-account-id> (obo_human)
- Session: 01TEN_LOCAL:01M1J2NT8FWQ8BCCD75T6D0J8F
```

The gateway replaced the tool call in the response stream with that text, so Claude Code never ran the command and `scratch` still exists. On the dashboard a denial is two red rows: the `tool_use_denied` receipt, and the model call it was extracted from, whose policy decision is deny. The same two from the API:

```
curl -s -b .r5e/cookies.txt "http://localhost:4000/v1/audit/receipts?limit=1&event_kind=tool_use_denied" | jq -r '.receipts[0].signed_predicate | [.event_kind, .policy_canonical_hash] | @tsv'
curl -s -b .r5e/cookies.txt "http://localhost:4000/v1/audit/receipts?limit=1&event_kind=llm_call_attested" | jq -r '.receipts[0] | [.signed_predicate.event_kind, .outer_container.policy_decision] | @tsv'
```
```
tool_use_denied	0c20ff0161f7e3a18a2b8c7efecb7a9c3a794f5158307a2c13ed98e2e122a7e2
llm_call_attested	deny
```

## 7. Export the evidence and verify it offline

```
bin/r5e evidence export
bin/r5e evidence verify
```

Output, with verifier steps 0 to 4 and 7 omitted:

```
r5e evidence export: run_id=71d585be-a012-4c22-a9fa-451eb1434fc6 event_kind=tool_use_denied
r5e evidence export: wrote /path/to/r5e-enterprise/.r5e/evidence.zip (131630 bytes)
[5] payload_hash
    MATCH (predicate body predicate/71d585be-a012-4c22-a9fa-451eb1434fc6.json, 1301 bytes, hashes to payload_hash)
[6] verification_level + tier_completeness_advisory
    tier_completeness_advisory: partial — the gateway attests the calls routed through it;
                                coverage is a property of the deployment (see docs/deployment-shapes.md)
VERIFY: PASS (strict, anchored)
```

The zip holds the signed envelope, the predicate body it hashes (`predicate/<run_id>.json`, where `principal_source` lives), the request and response bytes the body hashes, the inclusion proofs, the Cedar source of the bundle that decided, and the signer's public key. The first `verify` builds `cedar-canonical-hash` with `cargo` (about a minute); without `cargo`, step 4 prints `NOT CHECKED` and the verdict is `FAIL`.

## 8. Change the policy

The gateway re-reads `policy/bundle.cedar` within 5 seconds of a change. Append a rule that keeps the agent out of `.env` files and read the bundle hash again:

```
cat >> policy/bundle.cedar <<'EOF'
forbid (principal, action == Action::"invoke_tool", resource == ToolUse::"Read")
when { context has tool_args && context.tool_args has "file_path" && context.tool_args.file_path like "*/.env*" };
EOF
sleep 6; curl -s http://localhost:4000/readyz | jq -r .policy.active_hash
```
```
3e24b38f736ced57f13f8b67e23c0f8449f13e53435d70debeb85af4b9d87609
```

The hash was `0c20ff0161f7…` in step 6; every receipt from now on carries the new one. To take the bundle from a git repository instead, see [policy from a git repository](policy-from-git.md). `docker compose down` stops the stack; the ledger, the signing key, and the receipts stay in the volumes until `docker compose down -v`.
