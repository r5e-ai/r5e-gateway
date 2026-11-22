#!/usr/bin/env bash
# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Swap the active Cedar bundle on a running demo BEAM from OUTSIDE its
# iex session, via distributed-Erlang RPC.
#
#   ./scripts/fable_demo/swap-bundle.sh deny
#   ./scripts/fable_demo/swap-bundle.sh permissive
#   ./scripts/fable_demo/swap-bundle.sh status
#
# Equivalent to calling FableDemo.use_deny_bundle!/0 in the BEAM's iex,
# but usable from a second terminal — which is what you want on camera,
# so the BEAM window stays a clean stream of Cedar decisions while the
# policy change happens somewhere the audience reads as "the operator".
#
# Requires the BEAM to have been started by boot-real.sh (which names
# the node and sets the cookie).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

if [ -d "${HOME}/.local/share/mise/shims" ]; then
  export PATH="${HOME}/.local/share/mise/shims:${PATH}"
fi

NODE="${R5E_DEMO_NODE:-r5e_demo}"
COOKIE="${R5E_DEMO_COOKIE:-r5e_fable_demo}"
TARGET="${NODE}@$(hostname -s)"

case "${1:-}" in
  deny)        CALL="FableDemo.use_deny_bundle!()" ;;
  permissive)  CALL="FableDemo.use_permissive_bundle!()" ;;
  status)      CALL="FableDemo.report_active_bundle()" ;;
  *)
    echo "usage: $0 {deny|permissive|status}" >&2
    exit 64
    ;;
esac

# A short-lived control node attaches, runs the call in the demo BEAM,
# and exits. `--no-halt` is deliberately absent: this is a one-shot.
exec env MIX_ENV=dev elixir \
  --sname "r5e_ctl_$$" --cookie "${COOKIE}" \
  -e "
    target = String.to_atom(\"${TARGET}\")

    case Node.connect(target) do
      true ->
        :ok

      _ ->
        IO.puts(:stderr, \"could not connect to #{inspect(target)} — is boot-real.sh running?\")
        System.halt(1)
    end

    case :rpc.call(target, Code, :eval_string, [\"${CALL}\"]) do
      {:badrpc, reason} ->
        IO.puts(:stderr, \"rpc failed: #{inspect(reason)}\")
        System.halt(1)

      _ ->
        :ok
    end
  "
