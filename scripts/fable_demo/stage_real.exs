# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Boot stager for the REAL-Codex flow (scripts/fable_demo/boot-real.sh).
#
# Unlike stage.exs this drives NO synthetic traffic — the tool calls come
# from a real Codex session through the proxy listener. All this does is
# put the BEAM in the state that makes those calls attestable:
#
#   1. Install the dev providers (software ES256 signer, filesystem CAS,
#      local Postgres-Merkle ledger) via FableDemo.setup!/0. Without this
#      the proxy logs "ProviderRegistry not installed; skipping
#      attestation emit" and the ledger stays empty.
#   2. Load the permissive bundle so the first Codex tool call is ALLOWED.
#   3. Print the dashboard login cookie.
#
# The demo's deny beat is driven live from this iex session:
#
#     FableDemo.use_deny_bundle!()

Code.require_file(Path.join(__DIR__, "demo.exs"))

IO.puts("\n[stage-real] ==== 1. providers + tenant ====")
FableDemo.setup!()

IO.puts("\n[stage-real] ==== 2. permissive bundle (allow beat) ====")
FableDemo.use_permissive_bundle!()

IO.puts("\n[stage-real] ==== 3. dashboard auth ====")
_cookie = FableDemo.mint_cookie()

IO.puts("""

[stage-real] ready.

  Proxy listener is up and providers are installed, so a real Codex
  session routed here produces signed receipts in the local ledger.

  Live demo controls in THIS iex session:

    FableDemo.use_deny_bundle!()        # swap to the deny bundle
    FableDemo.use_permissive_bundle!()  # swap back between takes

  Watch this window during a Codex turn — the load-bearing log lines are:

    cedar gate DENY (Phase 6 byte-suppression) tool=... rule=...
    OpenaiResponses parser: unhandled output_item type=...   <-- wire drift
    OpenaiResponses parser: unhandled event type=...         <-- wire drift

  Those two "unhandled" lines are the drift detector: if Codex changed
  its tool-call shape again, they fire and no intent is extracted.
""")
