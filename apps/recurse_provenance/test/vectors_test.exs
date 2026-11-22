defmodule Recurse.Provenance.VectorsTest do
  @moduledoc """
  The committed conformance vectors, checked against this verifier. A
  failure here means the verifier's output changed: either a bug, or a
  change to the contract that needs the vectors regenerated and reviewed.
  """
  use ExUnit.Case, async: true

  alias Recurse.Provenance.Export

  @dir Path.expand("vectors/cases", __DIR__)
  @cases @dir |> File.ls!() |> Enum.filter(&File.dir?(Path.join(@dir, &1))) |> Enum.sort()

  for name <- @cases do
    test "#{name}" do
      dir = Path.join(@dir, unquote(name))
      read = fn file -> dir |> Path.join(file) |> File.read!() |> Jason.decode!() end

      settings = read.("case.json")

      report =
        Export.verify(read.("bundle.json"),
          trusted_profiles: settings["trustedProfiles"],
          trusted_publishers: settings["trustedPublishers"],
          trusted_roots: settings["trustedRoots"],
          trusted_chain: settings["trustedChain"],
          min_start_seq: settings["minStartSeq"]
        )

      assert Export.report(report) == read.("expected-report.json")
    end
  end

  test "there is a case for every outcome the verifier can name" do
    codes =
      for name <- @cases,
          finding <-
            (Path.join([@dir, name, "expected-report.json"])
             |> File.read!()
             |> Jason.decode!())["findings"],
          into: MapSet.new(),
          do: {finding["check"], finding["result"], finding["code"]}

    for expected <- [
          {"identity", "failed", "payload_hashes_to_another_reference"},
          {"identity", "failed", "payload_not_canonical"},
          {"identity", "failed", "duplicate_signer"},
          {"body", "failed", "signature_count_differs_from_definition"},
          {"signature", "failed", "bad_signature"},
          {"signature", "failed", "key_mismatch"},
          {"signature", "incomplete", "missing_key"},
          {"body", "failed", "body_does_not_match_definition"},
          {"body", "failed", "envelope_does_not_match_schema"},
          {"body", "failed", "definition_is_for_another_kind"},
          {"body", "incomplete", "definition_not_available"},
          {"profile_bounds", "failed", "issuer_not_bound"},
          {"profile_bounds", "failed", "policy_required"},
          {"authority", "incomplete", "profile_not_trusted"},
          {"content", "incomplete", "omitted_withheld"},
          {"content_hash", "failed", "bytes_do_not_match_reference"},
          {"fork", "failed", "two_records_at_one_position"},
          {"previous", "failed", "previous_is_not_the_prior_record"},
          {"sealer", "failed", "unauthorized_seal"},
          {"epoch", "ok", "ok"},
          {"epoch", "failed", "epoch_root"},
          {"membership", "ok", "ok"},
          {"membership", "failed", "position_does_not_match_seal"},
          {"shape", "failed", "malformed_bundle"},
          {"publication", "ok", "ok"},
          {"publication", "failed", "definition_differs_from_published"},
          {"publication", "incomplete", "publisher_not_trusted"},
          {"publication", "incomplete", "publication_not_carried"}
        ] do
      assert expected in codes, "no vector produces #{inspect(expected)}"
    end
  end

  test "each definition document hashes to the reference the index gives it" do
    dir = Path.expand("vectors/definitions", __DIR__)
    index = dir |> Path.join("index.json") |> File.read!() |> Jason.decode!()

    assert map_size(index) == 28
    assert index |> Map.values() |> Enum.uniq() |> length() == 28

    for {path, ref} <- index do
      bytes = File.read!(Path.join(dir, path <> ".json"))
      assert Recurse.Provenance.Ref.bytes(bytes) == ref
      assert %{"format" => "r5e.kind-definition/v1", "kind" => ^path} = Jason.decode!(bytes)
    end
  end
end
