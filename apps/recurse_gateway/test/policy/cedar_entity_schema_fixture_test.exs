defmodule RecurseGateway.Policy.CedarEntitySchemaFixtureTest do
  @moduledoc """
  Guards the canonical Cedar Entity Schema bundled with the Gateway.

  The SHA-256 pin is a tripwire: any modification to
  `priv/cedar/schema.cedarschema.json` fails this test, forcing a
  deliberate recomputation + code-review sign-off rather than a silent
  drift. The schema is loaded into the live Cedar evaluator at boot
  (T045), so an accidental edit would change runtime policy semantics.
  """
  use ExUnit.Case, async: true

  @schema_path Path.expand("../../priv/cedar/schema.cedarschema.json", __DIR__)
  @expected_sha256 "5be72724d3894bb32849d5012c4912b1f2021e17d24656197fd0d974aaeac02b"

  test "Cedar entity schema file hash is stable" do
    actual =
      :crypto.hash(:sha256, File.read!(@schema_path))
      |> Base.encode16(case: :lower)

    assert actual == @expected_sha256, """
    Cedar entity schema file hash drifted. If this change is intentional,
    recompute the expected hash via:
      openssl dgst -sha256 apps/recurse_gateway/priv/cedar/schema.cedarschema.json
    and update @expected_sha256 in #{__ENV__.file}.
    """
  end
end
