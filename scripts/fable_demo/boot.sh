#!/usr/bin/env bash
# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
# Boot the local dev BEAM for the demo flow. Run from the workspace root:
#   ./scripts/fable_demo/boot.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

# 1. Broker/internal-JWT ES256 signing key (collapsed-broker + cookie JWTs).
if [ ! -f secrets/broker-signing-key.pem ]; then
  ./scripts/gen-broker-key.sh
fi

# 2. Active policy bundle file the BundleLoader watches. Start permissive.
mkdir -p _build/dev/fable-demo
if [ ! -f _build/dev/fable-demo/active_bundle.cedar ]; then
  cp apps/recurse_gateway/priv/reference_policies/permissive_all.cedar \
     _build/dev/fable-demo/active_bundle.cedar
fi

export R5E_START_HTTP=true
export PORT=4000
export BROKER_JWT_SIGNING_KEY_PATH="${REPO_ROOT}/secrets/broker-signing-key.pem"
export BROWSER_OIDC_PROVIDER=oidc
export RECURSE_POLICY_BUNDLE_PATH="${REPO_ROOT}/_build/dev/fable-demo/active_bundle.cedar"
export RECURSE_POLICY_SCHEMA_PATH="${REPO_ROOT}/apps/recurse_gateway/priv/cedar/schema.cedarschema.json"

echo "[fable-demo] booting: http://localhost:4000  (healthz: /healthz)"
echo "[fable-demo] FableDemo.* is preloaded — start with: FableDemo.setup!()"
echo "[fable-demo] non-interactive alternative: mix run --no-halt -e 'Code.require_file(\"scripts/fable_demo/stage.exs\")'"
exec env MIX_ENV=dev iex -S mix run --no-halt -e 'Code.require_file("scripts/fable_demo/demo.exs")'
