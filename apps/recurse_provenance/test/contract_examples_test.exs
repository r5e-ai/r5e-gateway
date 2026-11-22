defmodule Recurse.Provenance.ContractExamplesTest do
  @moduledoc """
  The October 30 contract's own illustrative examples, checked for shape
  against the definitions this library installs. The examples are
  synthetic, so nothing here exercises signatures or hashes.

  The definitions differ from October 30 in two declared ways (amendment
  A2), and this test holds the difference to exactly those: the four
  kinds that carry content are Artifacts, with one `contentRef` in place
  of a list of references, and a stream's first seal leaves
  `previousSeal` out where October 30 wrote null. Every other example
  must match unchanged.
  """
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{Definitions, Schema}

  @dir Path.expand("fixtures/contract_examples", __DIR__)
  @index @dir
         |> Path.join("index.json")
         |> File.read!()
         |> Jason.decode!()
         |> Map.fetch!("examples")

  defp load(file), do: @dir |> Path.join(file) |> File.read!() |> Jason.decode!()

  @artifacts %{
    "ModelCall" => "inputRefs",
    "ToolCall" => "inputRefs",
    "ModelResponse" => "outputRefs",
    "ToolResult" => "outputRefs"
  }

  defp check(evidence, body) do
    path = Definitions.kind_path(evidence["apiVersion"], evidence["kind"])
    {:ok, %{ref: ref}} = Definitions.fetch(path)
    Definitions.check(path, ref, body)
  end

  for %{"file" => file, "schema" => "evidence.schema.json"} <- @index do
    test "#{file}: common envelope and body against the installed definition" do
      evidence = load(unquote(file))
      assert :ok = Schema.validate(Definitions.envelope_schema(), evidence)
      body = evidence["body"]

      case evidence["kind"] do
        kind when is_map_key(@artifacts, kind) ->
          list = @artifacts[kind]

          assert {:error, violations} = check(evidence, body)

          assert Enum.sort(Enum.map(violations, &{&1.path, &1.code})) ==
                   Enum.sort([
                     {"$.contentRef", "missing_required"},
                     {"$.mediaType", "missing_required"},
                     {"$.size", "missing_required"},
                     {"$.#{list}", "unexpected_property"}
                   ])

          # The same example as an Artifact matches.
          [content | derived] = body[list] ++ [nil]
          content = content || "bytes:sha256:" <> String.duplicate("0", 64)

          as_artifact =
            body
            |> Map.delete(list)
            |> Map.merge(%{
              "contentRef" => content,
              "mediaType" => "application/json",
              "size" => 0,
              "derivedFrom" => Enum.reject(derived, &is_nil/1)
            })

          assert :ok = check(evidence, as_artifact)

        "EpochSeal" ->
          if is_nil(body["previousSeal"]) do
            assert {:error, [%{path: "$.previousSeal", code: "wrong_type"}]} =
                     check(evidence, body)

            assert :ok = check(evidence, Map.delete(body, "previousSeal"))
          else
            assert :ok = check(evidence, body)
          end

        # A release is signed by a second party, whoever is releasing the
        # hold, and names them (amendment A7). The October example has
        # only the recorder.
        "RetentionHoldRelease" ->
          assert {:error, [%{path: "$.releasedBy", code: "missing_required"}]} =
                   check(evidence, body)

          releaser = "key:ed25519:sha256:" <> String.duplicate("a", 64)
          assert :ok = check(evidence, Map.put(body, "releasedBy", releaser))

        _unchanged ->
          assert :ok = check(evidence, body)
      end
    end
  end

  for {schema_file, schema_fun} <- [
        {"evidence-envelope.schema.json", :envelope_schema},
        {"signed-evidence.schema.json", :signed_schema},
        {"capture-profile.schema.json", :profile_schema},
        {"epoch-manifest.schema.json", :manifest_schema},
        {"export.schema.json", :export_schema}
      ],
      %{"file" => file, "schema" => ^schema_file} <- @index do
    test "#{file}: matches #{schema_file}" do
      schema = apply(Definitions, unquote(schema_fun), [])
      assert :ok = Schema.validate(schema, load(unquote(file)))
    end
  end

  test "every base kind has at least one contract example" do
    seen =
      for %{"file" => file, "schema" => "evidence.schema.json"} <- @index,
          into: MapSet.new(),
          do: load(file)["kind"]

    # Kinds added since October 30 have no example in that contract.
    added =
      MapSet.new(~w[DefinitionPublished Principal Endorsement Badge Succession Revocation
                    ChainStarted Deployment RootsChanged RootChangeApproval])

    assert MapSet.difference(MapSet.new(Definitions.kinds()), added) == seen
  end

  test "a body checked as another kind is refused" do
    tool_call = load("tool-call.json")
    assert {:error, [_ | _]} = check(Map.put(tool_call, "kind", "Observation"), tool_call["body"])
  end
end
