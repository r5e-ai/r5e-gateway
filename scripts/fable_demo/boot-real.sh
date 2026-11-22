#!/usr/bin/env bash
# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Boot the local BEAM for the REAL-Codex demo flow: the LLM proxy
# listener fronting real OpenAI, PLUS the fable-demo dev providers so
# every proxied call commits a signed receipt to the local ledger and
# shows up in the audit console.
#
# This is the union of the two paths that previously existed separately:
#
#   scripts/fable_demo/boot.sh      — dev providers + receipts, but the
#                                     tool call was a mock in-BEAM
#                                     upstream (FableDemo.ToolDemo).
#   scripts/dev/llm-proxy-up.sh     — real proxy against real OpenAI,
#                                     but no ProviderRegistry, so the
#                                     BEAM logged "skipping attestation
#                                     emit" and the ledger stayed empty.
#
# One tenant is used everywhere (R5E_LLM_PROXY_DEFAULT_TENANT_ID ==
# FableDemo's tenant) so the receipts real Codex produces are the ones
# the dashboard's session cookie can read.
#
# Run from the workspace root:
#   ./scripts/fable_demo/boot-real.sh
#
# Then, in another terminal, the two sudo lines this script prints, and
# `codex login`. Full runbook: scripts/fable_demo/README-real-codex.md
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

# mix/elixir come from mise. An interactive zsh has mise activated, but
# this script is also run non-interactively (CI, `bash script.sh`,
# agent-driven boots), where the shims are not on PATH. Prepend them.
if [ -d "${HOME}/.local/share/mise/shims" ]; then
  export PATH="${HOME}/.local/share/mise/shims:${PATH}"
fi

TENANT="${R5E_LLM_PROXY_DEFAULT_TENANT_ID:-01TEN_FABLE_DEMO_LOCAL}"

# TLS material comes from scripts/dev/llm-proxy-cert-generate-and-push.sh
# in --dry-run mode (generate locally, never touch AWS), NOT from
# scripts/dev/llm-proxy-cert.sh.
#
# The latter emits ONE self-signed cert carrying CA:TRUE and serves it
# as the leaf. curl accepts that; rustls — and therefore Codex CLI —
# does not, failing the handshake with
# `invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))`,
# after which Codex drops from WebSockets to HTTPS, fails identically,
# and parks in "Reconnecting... waiting for network".
#
# The generate-and-push script already builds the correct two-tier PKI
# (CA:TRUE anchor + CA:FALSE serverAuth leaf). Its `<env>` argument only
# selects an output directory and a cert CN here; --dry-run means no
# Secrets Manager call and no AWS credentials needed.
CERT_ENV="${R5E_DEMO_CERT_ENV:-audit-dev}"
CERT_DIR="${REPO_ROOT}/_build/${CERT_ENV}"
CRT="${CERT_DIR}/recurse-gateway-llm-proxy-cert.pem"   # leaf + CA chain — Bandit serves
KEY="${CERT_DIR}/recurse-gateway-llm-proxy-key.pem"    # leaf private key
CA="${CERT_DIR}/recurse-gateway-llm-proxy-ca.pem"      # trust anchor — Codex gets THIS

# Every `mix` invocation below boots the app and evaluates
# config/runtime.exs, so the environment has to be complete BEFORE the
# first one — `mix ecto.create` fails the audit-console boot check
# without BROWSER_OIDC_PROVIDER just as surely as `iex -S mix` does.

# --- Audit plane (dashboard API) ---
export R5E_START_HTTP=true
export PORT="${PORT:-4000}"
export BROKER_JWT_SIGNING_KEY_PATH="${REPO_ROOT}/secrets/broker-signing-key.pem"
export BROWSER_OIDC_PROVIDER=oidc
export RECURSE_POLICY_BUNDLE_PATH="${REPO_ROOT}/_build/dev/fable-demo/active_bundle.cedar"
export RECURSE_POLICY_SCHEMA_PATH="${REPO_ROOT}/apps/recurse_gateway/priv/cedar/schema.cedarschema.json"

# --- LLM proxy listener (the MITM surface Codex connects to) ---
export R5E_LLM_PROXY_ENABLED=true
export R5E_LLM_PROXY_PORT="${R5E_LLM_PROXY_PORT:-4443}"
export R5E_LLM_PROXY_SCHEME=https
export R5E_LLM_PROXY_DEFAULT_TENANT_ID="${TENANT}"
export RECURSE_GATEWAY_LLM_PROXY_CERT="${CRT}"
export RECURSE_GATEWAY_LLM_PROXY_KEY="${KEY}"

export SECRET_KEY_BASE="${SECRET_KEY_BASE:-$(openssl rand -hex 32)}"

echo "[1/4] cert: CA + leaf chain for chatgpt.com / auth.openai.com / api.openai.com"
if [ -f "${CRT}" ] && [ -f "${KEY}" ] && [ -f "${CA}" ] &&
   openssl x509 -in "${CRT}" -checkend 86400 -noout >/dev/null 2>&1; then
  echo "  reusing existing chain in ${CERT_DIR}"
else
  "${REPO_ROOT}/scripts/dev/llm-proxy-cert-generate-and-push.sh" "${CERT_ENV}" --dry-run
fi

# Guard the failure mode that cost us a demo: if what Bandit is about to
# serve is CA-marked, Codex will refuse it. Better to stop here with a
# clear message than to debug it through a TLS handshake later.
if openssl x509 -in "${CRT}" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
  echo "[cert] FATAL: ${CRT} presents a CA:TRUE certificate as the leaf." >&2
  echo "[cert] Codex (rustls) will reject this with CaUsedAsEndEntity." >&2
  echo "[cert] Delete ${CERT_DIR} and re-run to regenerate a proper chain." >&2
  exit 1
fi

# Combined trust bundle: macOS system roots + our demo CA.
#
# Pointing SSL_CERT_FILE at the bare demo CA would REPLACE the trust
# store rather than extend it, so Codex would trust our gateway and
# nothing else on the internet. Codex reaches non-proxied hosts too
# (telemetry, MCP endpoints, update checks), so it needs both.
BUNDLE="${CERT_DIR}/codex-ca-bundle.pem"
if [ ! -f "${BUNDLE}" ] || [ "${CA}" -nt "${BUNDLE}" ]; then
  security find-certificate -a -p \
    /System/Library/Keychains/SystemRootCertificates.keychain > "${BUNDLE}" 2>/dev/null
  cat "${CA}" >> "${BUNDLE}"
  echo "  built trust bundle ($(grep -c 'BEGIN CERTIFICATE' "${BUNDLE}") certs): ${BUNDLE}"
fi

echo
echo "[2/4] keys + policy bundle"
if [ ! -f secrets/broker-signing-key.pem ]; then
  ./scripts/gen-broker-key.sh
fi

mkdir -p _build/dev/fable-demo
if [ ! -f _build/dev/fable-demo/active_bundle.cedar ]; then
  cp apps/recurse_gateway/priv/reference_policies/permissive_all.cedar \
     _build/dev/fable-demo/active_bundle.cedar
fi
echo "  bundle watched at _build/dev/fable-demo/active_bundle.cedar"

echo
echo "[3/4] db + seed: tenant ${TENANT} + real-OpenAI LlmProviderConfig rows"
# The proxy listener is NOT wanted during these one-shot mix tasks —
# they would bind :4443 briefly and race the long-lived BEAM below.
R5E_LLM_PROXY_ENABLED=false R5E_START_HTTP=false MIX_ENV=dev \
  mix do ecto.create, ecto.migrate
R5E_LLM_PROXY_ENABLED=false R5E_START_HTTP=false MIX_ENV=dev \
  mix run scripts/fable_demo/seed_real_upstreams.exs

cat <<EOF

[4/4] booting BEAM

  audit plane (dashboard API):  http://localhost:${PORT}   (/healthz)
  llm proxy listener:           https://localhost:${R5E_LLM_PROXY_PORT}
  tenant (everywhere):          ${TENANT}
  served chain (leaf + CA):     ${CRT}
  trust anchor for Codex:       ${CA}

  Providers install automatically at boot (stage_real.exs) — so proxied
  Codex traffic commits real receipts to the local ledger.

--- operator steps, in ANOTHER terminal ---

  # 1. DNS override so Codex's TLS connections land on this machine.
  sudo sh -c 'echo "127.0.0.1 chatgpt.com auth.openai.com api.openai.com" >> /etc/hosts'

  # 2. Redirect :443 -> :${R5E_LLM_PROXY_PORT} so the BEAM does not need root.
  echo 'rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port ${R5E_LLM_PROXY_PORT}' \\
    | sudo pfctl -ef -

  # 3. Trust the demo CA (Codex ships its own root store).
  #    Point at the CA / bundle, NOT the served chain.
  export CODEX_CA_CERTIFICATE=${CA}
  export SSL_CERT_FILE=${CERT_DIR}/codex-ca-bundle.pem

  #    Or trust it machine-wide instead (survives new terminals):
  #    sudo security add-trusted-cert -d -r trustRoot \\
  #      -k /Library/Keychains/System.keychain ${CA}

  # 4. Log in + drive it.
  codex login
  codex

Full runbook: scripts/fable_demo/README-real-codex.md

EOF

# The BEAM is named so bundle swaps can be driven from outside the iex
# session (scripts/fable_demo/swap-bundle.sh) as well as from inside it.
# That matters on camera: swapping from a second terminal keeps the
# demo's story ("an operator changed policy") separate from the BEAM
# window the audience is watching for Cedar log lines.
export R5E_DEMO_NODE="${R5E_DEMO_NODE:-r5e_demo}"
export R5E_DEMO_COOKIE="${R5E_DEMO_COOKIE:-r5e_fable_demo}"

# `iex` needs a TTY. When there isn't one (agent-driven boot, CI, nohup)
# fall back to a plain non-interactive BEAM — same app, same listeners,
# no shell. Force either way with FABLE_INTERACTIVE=0/1.
if [ -n "${FABLE_INTERACTIVE:-}" ]; then
  interactive="${FABLE_INTERACTIVE}"
elif [ -t 0 ]; then
  interactive=1
else
  interactive=0
fi

if [ "${interactive}" = "1" ]; then
  exec env MIX_ENV=dev iex --sname "${R5E_DEMO_NODE}" --cookie "${R5E_DEMO_COOKIE}" \
    -S mix run --no-halt \
    -e 'Code.require_file("scripts/fable_demo/stage_real.exs")'
else
  echo "[boot-real] no TTY — starting non-interactive BEAM (node ${R5E_DEMO_NODE})."
  echo "[boot-real] swap bundles with: ./scripts/fable_demo/swap-bundle.sh deny|permissive"
  exec env MIX_ENV=dev elixir --sname "${R5E_DEMO_NODE}" --cookie "${R5E_DEMO_COOKIE}" \
    -S mix run --no-halt \
    -e 'Code.require_file("scripts/fable_demo/stage_real.exs")'
fi
