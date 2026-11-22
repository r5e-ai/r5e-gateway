#!/usr/bin/env bash
#
# Spec 009 Phase 3 / T073 — generate (or reuse) a self-signed TLS cert
# for the LLM-proxy dev listener.
#
# Idempotent. The cert is valid for 30 days and covers the three Codex CLI
# upstream hostnames + localhost so a single cert serves the whole demo:
#
#   * chatgpt.com           — Codex's WSS data plane
#   * auth.openai.com       — OAuth login redirect target
#   * api.openai.com        — Responses API HTTPS+SSE fallback
#   * localhost / 127.0.0.1 — for `curl -k https://localhost:4443/healthz`
#
# Codex CLI's reqwest+rustls trust bundle ignores the macOS keychain on
# some versions; the runbook tells the operator to set
# `CODEX_CA_CERTIFICATE=$(realpath _build/dev/recurse-gateway-dev.crt)`
# in the codex-side terminal so the dev cert is trusted explicitly.
#
# Outputs (default, overridable via $CERT_DIR):
#   _build/dev/recurse-gateway-dev.key
#   _build/dev/recurse-gateway-dev.crt

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="${CERT_DIR:-${REPO_ROOT}/_build/dev}"
KEY="${CERT_DIR}/recurse-gateway-dev.key"
CRT="${CERT_DIR}/recurse-gateway-dev.crt"

mkdir -p "${CERT_DIR}"

if [ -f "${KEY}" ] && [ -f "${CRT}" ]; then
  # Sanity-check expiry. openssl x509 -checkend N exits non-zero if cert
  # expires within N seconds. 86400 = 1 day.
  if openssl x509 -in "${CRT}" -checkend 86400 -noout >/dev/null 2>&1; then
    echo "[cert] reusing existing cert at ${CERT_DIR} (>=1 day until expiry)"
    echo "  key: ${KEY}"
    echo "  crt: ${CRT}"
    exit 0
  else
    echo "[cert] existing cert at ${CRT} expires within 24h; regenerating"
    rm -f "${KEY}" "${CRT}"
  fi
fi

echo "[cert] generating self-signed cert at ${CERT_DIR}"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${KEY}" -out "${CRT}" -days 30 \
  -subj "/CN=chatgpt.com" \
  -addext "subjectAltName=DNS:chatgpt.com,DNS:auth.openai.com,DNS:api.openai.com,DNS:localhost,IP:127.0.0.1" \
  >/dev/null 2>&1

chmod 600 "${KEY}"
chmod 644 "${CRT}"

echo "[cert] generated:"
echo "  key: ${KEY}"
echo "  crt: ${CRT}"
echo
echo "[cert] for codex CLI:"
echo "  export CODEX_CA_CERTIFICATE=${CRT}"
