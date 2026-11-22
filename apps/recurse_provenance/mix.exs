defmodule RecurseProvenance.MixProject do
  @moduledoc """
  Provenance v2 evidence: canonical bytes, signed envelopes, per-stream
  chaining, epoch seals, export bundles and their verification.

  A pure library. It owns no HTTP surface, no database and no process; the
  recorder that makes capture durable lives with the store that backs it.

  Canonical JSON, DSSE pre-authentication encoding, key-id derivation, the
  Ed25519 profile and the Merkle tree come from `:recurse_verify`, the Core
  verifier package, so a record is written and checked under one reading of
  the rules.
  """
  use Mix.Project

  def project do
    [
      app: :recurse_provenance,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:telemetry, "~> 1.4"},
      # The Core verifier (Apache-2.0), vendored at a recorded commit; see
      # vendor/recurse_verify/VENDORED.md. `R5E_CORE_VERIFIER_PATH`
      # overrides the location.
      {:recurse_verify,
       path: System.get_env("R5E_CORE_VERIFIER_PATH", "../../vendor/recurse_verify")},
      {:stream_data, "~> 1.3", only: :test}
    ]
  end
end
