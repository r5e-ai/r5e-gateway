# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
# Non-interactive stager: runs the full demo sequence at boot, leaves
# the BEAM serving HTTP for curl + the UI. See boot.sh / demo.exs.

Code.require_file(Path.join(__DIR__, "demo.exs"))

IO.puts("\n[stage] ==== 1. providers + tenant ====")
FableDemo.setup!()

IO.puts("\n[stage] ==== 2. tool-use ALLOW under permissive bundle ====")
FableDemo.use_permissive_bundle!()
allow_result = FableDemo.ToolDemo.run("ls -la /tmp")
IO.inspect(allow_result |> elem(1) |> Map.take([:denied, :forwarded]), label: "[stage] allow run")

IO.puts("\n[stage] ==== 3. activate deny-destructive bundle ====")
FableDemo.use_deny_bundle!()

IO.puts("\n[stage] ==== 4. tool-use DENY (rm -rf) under deny bundle ====")
deny_result = FableDemo.ToolDemo.run("rm -rf /tmp/test-dir")
IO.inspect(deny_result |> elem(1) |> Map.take([:denied, :forwarded]), label: "[stage] deny run")

IO.puts("\n[stage] ==== 5. ledger state ====")

import Ecto.Query, only: [from: 2]
alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
alias Recurse.Providers.Repo

rows =
  Repo.all(
    from(a in Attestation,
      order_by: [desc: a.inserted_at],
      limit: 10,
      select: {a.event_kind, a.run_id}
    )
  )

IO.inspect(rows, label: "[stage] latest attestations")

IO.puts("\n[stage] ==== 6. auth material ====")
FableDemo.print_curl()
_cookie = FableDemo.mint_cookie()

IO.puts("[stage] staging complete; BEAM stays up (--no-halt).")
