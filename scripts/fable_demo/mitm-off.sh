#!/usr/bin/env bash
# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Undo mitm-on.sh: strip the /etc/hosts entries and kill any :443
# bridge left behind. Safe to run when nothing is active.
#
#   sudo ./scripts/fable_demo/mitm-off.sh
set -euo pipefail

MARKER="# r5e-fable-demo"
HOSTS=/etc/hosts

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root: sudo $0" >&2
  exit 1
fi

if grep -q "${MARKER}" "${HOSTS}" 2>/dev/null; then
  sed -i '' "/${MARKER}/d" "${HOSTS}"
  echo "[mitm] /etc/hosts entries removed."
else
  echo "[mitm] no /etc/hosts entries present."
fi

if pkill -f "socat TCP-LISTEN:443" 2>/dev/null; then
  echo "[mitm] :443 bridge stopped."
else
  echo "[mitm] no :443 bridge running."
fi

dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true

echo "[mitm] OFF — codex now talks to real OpenAI directly."

# Belt-and-braces: show what actually resolves now.
echo
echo -n "  chatgpt.com resolves to: "
dscacheutil -q host -a name chatgpt.com 2>/dev/null | awk '/ip_address/{print $2; found=1} END{if(!found) print "(not cached)"}' | head -1
