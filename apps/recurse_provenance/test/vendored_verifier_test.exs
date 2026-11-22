defmodule Recurse.Provenance.VendoredVerifierTest do
  @moduledoc """
  The vendored Core verifier is a copy with one recorded difference.
  When the Core checkout it was taken from is present beside this
  repository, every other vendored file must match it byte for byte.
  """
  use ExUnit.Case, async: true

  @vendored Path.expand("../../../vendor/recurse_verify", __DIR__)
  @reference Path.expand("../../../../api/core/verifier", __DIR__)

  test "vendored files are identical to the Core checkout, but for the recorded one" do
    if File.dir?(@reference) do
      files =
        [Path.join(@vendored, "mix.exs") | Path.wildcard(Path.join(@vendored, "lib/**/*.ex"))]

      assert length(files) > 1

      # The canonical JSON change is carried here ahead of Core; see VENDORED.md.
      changed = ["lib/recurse_verify/canonical.ex"]

      for file <- files, relative = Path.relative_to(file, @vendored), relative not in changed do
        assert File.read!(file) == File.read!(Path.join(@reference, relative)),
               "#{relative} differs from the Core checkout"
      end
    end
  end
end
