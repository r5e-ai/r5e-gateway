#!/usr/bin/env bash
# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Put the machine into "Codex is proxied" mode:
#   1. /etc/hosts sends chatgpt.com / auth.openai.com / api.openai.com
#      to 127.0.0.1.
#   2. socat bridges :443 -> :4443 so the BEAM never runs as root.
#
# Needs sudo (privileged port + /etc/hosts). Runs socat in the
# FOREGROUND: Ctrl-C stops the bridge, and the trap removes the hosts
# entries on the way out — so the machine can't be left half-MITMed
# because a terminal got closed.
#
#   sudo ./scripts/fable_demo/mitm-on.sh
#
# Undo manually (if this exited uncleanly):
#   sudo ./scripts/fable_demo/mitm-off.sh
set -euo pipefail

PROXY_PORT="${R5E_LLM_PROXY_PORT:-4443}"
MARKER="# r5e-fable-demo"
HOSTS=/etc/hosts

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root: sudo $0" >&2
  exit 1
fi

if ! command -v socat >/dev/null 2>&1; then
  echo "socat not found — brew install socat" >&2
  exit 1
fi

remove_hosts_entries() {
  if grep -q "${MARKER}" "${HOSTS}" 2>/dev/null; then
    # Keep a timestamped backup; sed -i '' is macOS-flavoured.
    sed -i '' "/${MARKER}/d" "${HOSTS}"
    echo
    echo "[mitm] /etc/hosts entries removed."
  fi
}

trap remove_hosts_entries EXIT INT TERM

remove_hosts_entries
{
  echo "127.0.0.1 chatgpt.com ${MARKER}"
  echo "127.0.0.1 auth.openai.com ${MARKER}"
  echo "127.0.0.1 api.openai.com ${MARKER}"
} >> "${HOSTS}"

# macOS caches aggressively; without this codex may still resolve the
# real IPs for a while.
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true

cat <<EOF
[mitm] ON

  chatgpt.com / auth.openai.com / api.openai.com -> 127.0.0.1
  bridging :443 -> :${PROXY_PORT}

  In the Codex terminal (point at the CA, not the served chain):
    export CODEX_CA_CERTIFICATE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/_build/${R5E_DEMO_CERT_ENV:-audit-dev}/recurse-gateway-llm-proxy-ca.pem
    codex

  Ctrl-C here to stop the bridge AND revert /etc/hosts.

EOF

exec socat TCP-LISTEN:443,fork,reuseaddr TCP:127.0.0.1:"${PROXY_PORT}"
