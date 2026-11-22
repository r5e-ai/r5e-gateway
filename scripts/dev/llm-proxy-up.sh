#!/usr/bin/env bash
#
# Spec 009 Phase 3 / T076 — bring up the dev BEAM with the LLM proxy
# operational for the real-Codex demo.
#
# Idempotent:
#   1. Generates the dev TLS cert (if not already present + valid).
#   2. Activates the Cedar fixture bundle (Eddy smoke rules).
#   3. Creates + migrates the dev Postgres DB.
#   4. Seeds the dev tenant + LlmProviderConfig rows pointing at REAL
#      OpenAI.
#   5. Starts `iex -S mix run --no-halt` with the proxy enabled on
#      https://localhost:4443.
#
# After this script prints `[beam] starting`, the operator must:
#   * (one-time) Add an /etc/hosts override redirecting chatgpt.com /
#     auth.openai.com / api.openai.com to 127.0.0.1.
#   * (one-time) Add a pfctl rule redirecting :443 -> :4443 on lo0.
#   * Run `codex login` (separate terminal) — see
#     specs/009-llm-api-proxy/demo-runbook.md for the full step list.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

CERT_DIR="${REPO_ROOT}/_build/dev"
CRT="${CERT_DIR}/recurse-gateway-dev.crt"
KEY="${CERT_DIR}/recurse-gateway-dev.key"

CEDAR_FIXTURE="${REPO_ROOT}/specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/bundle.cedar"
CEDAR_ACTIVE="${REPO_ROOT}/apps/recurse_gateway/priv/cedar/active.cedar"

echo "[1/5] cert: ensuring dev TLS cert exists"
"${REPO_ROOT}/scripts/dev/llm-proxy-cert.sh"

echo "[2/5] cedar: activating Eddy-smoke fixture bundle"
mkdir -p "$(dirname "${CEDAR_ACTIVE}")"
cp "${CEDAR_FIXTURE}" "${CEDAR_ACTIVE}"
echo "  copied ${CEDAR_FIXTURE}"
echo "       -> ${CEDAR_ACTIVE}"

echo "[3/5] db: ecto.create + ecto.migrate"
MIX_ENV=dev mix do ecto.create, ecto.migrate

echo "[4/5] seed: inserting tenant + LlmProviderConfig (real-OpenAI)"
MIX_ENV=dev mix run scripts/seed_009_real_demo.exs

echo "[5/5] beam: starting iex -S mix run --no-halt"
echo
echo "  proxy listener:   https://localhost:4443"
echo "  audit-plane:      http://localhost:4080  (R5E_START_HTTP=true; PORT=4080)"
echo "  cert:             ${CRT}"
echo
echo "[runbook] /etc/hosts override (one-time, sudo):"
echo "  sudo sh -c 'echo \"127.0.0.1 chatgpt.com auth.openai.com api.openai.com\" >> /etc/hosts'"
echo
echo "[runbook] pfctl 443->4443 redirect on lo0 (one-time, sudo):"
echo "  echo 'rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port 4443' \\"
echo "    | sudo pfctl -ef -"
echo
echo "[runbook] codex-side env (per-terminal):"
echo "  export CODEX_CA_CERTIFICATE=${CRT}"
echo
echo "Full step-by-step: specs/009-llm-api-proxy/demo-runbook.md"
echo

# Activate the LLM proxy listener via runtime-config env-var seam (added
# in 2026-05-07 / T028 + T073). REQUIRED — without these the supervisor
# tree will boot but `:llm_proxy_enabled?` defaults to false and the
# 4443 listener is silently absent.
export R5E_LLM_PROXY_ENABLED="true"
export R5E_LLM_PROXY_PORT="${R5E_LLM_PROXY_PORT:-4443}"
export R5E_LLM_PROXY_SCHEME="${R5E_LLM_PROXY_SCHEME:-https}"
export RECURSE_GATEWAY_LLM_PROXY_CERT="${CRT}"
export RECURSE_GATEWAY_LLM_PROXY_KEY="${KEY}"

# Audit-plane (port 4080 default — 4000 is commonly held by other dev
# servers, e.g. the giulia code-intelligence daemon). Optional: set
# R5E_START_HTTP=false to skip.
export R5E_START_HTTP="${R5E_START_HTTP:-true}"
export PORT="${PORT:-4080}"

# Required by config/runtime.exs's :prod block; the dev BEAM doesn't
# enter that block (config_env() == :dev), but we still surface a
# sane SECRET_KEY_BASE for parity if a dev release is ever cut.
export SECRET_KEY_BASE="${SECRET_KEY_BASE:-$(openssl rand -hex 32)}"

exec env MIX_ENV=dev iex -S mix run --no-halt
