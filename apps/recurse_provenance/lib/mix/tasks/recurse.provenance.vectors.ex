defmodule Mix.Tasks.Recurse.Provenance.Vectors do
  @shortdoc "Write the Provenance v2 verifier conformance vectors"
  @moduledoc """
  Writes the conformance vectors for the Provenance v2 verifier.

      mix recurse.provenance.vectors [DIR]

  `DIR` defaults to `test/vectors` in this app. Each case gets a
  directory holding `case.json` (what it shows and which profiles the
  reader trusts), `bundle.json` and `expected-report.json`.

  Run this when the verifier's contract changes, review the diff, and
  commit the result. A changed expected report is a change to what every
  implementation must produce.
  """
  use Mix.Task

  @impl true
  def run(args) do
    dir = List.first(args) || Path.join(File.cwd!(), "test/vectors")
    names = Recurse.Provenance.Vectors.write(dir)
    Mix.shell().info("wrote #{length(names)} vectors to #{dir}")
  end
end
