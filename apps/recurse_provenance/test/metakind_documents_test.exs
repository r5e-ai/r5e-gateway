defmodule Recurse.Provenance.MetakindDocumentsTest do
  @moduledoc """
  A published definition says which meta-kind it was made under and
  carries what that meta-kind asked of it, and a kind with no meta-kind
  has the document it always had.
  """
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{Definitions, Grammar}

  @fixtures Path.expand("fixtures/grammar", __DIR__)
  @extra ~w[definedBy predicates metric]

  setup_all do
    sources =
      for name <- ~w[r5e.core.huml r5e.harmony.huml r5e.examples.huml],
          do: {name, File.read!(Path.join(@fixtures, name))}

    {:ok, compiled} = Grammar.compile(sources)
    %{documents: Definitions.expand(compiled)}
  end

  test "a metric kind names its meta-kind's document and carries its metric contract", ctx do
    meta = ctx.documents["harmony.r5e.io/v1/MetricDefinition"]
    metric = ctx.documents["examples.r5e.io/v1/DocDiscoveryMetric"].document

    assert metric["definedBy"] == meta.ref
    assert %{"valueField" => field, "unit" => _, "direction" => _} = metric["metric"]
    # What the meta-kind demands is true of the document that claims it.
    assert field in metric["schema"]["required"]
    assert metric["schema"]["properties"][field]["type"] == "integer"
  end

  test "a kind built from a metric kind keeps the meta-kind and the contract", ctx do
    meta = ctx.documents["harmony.r5e.io/v1/MetricDefinition"]
    strict = ctx.documents["examples.r5e.io/v1/StrictDocDiscoveryMetric"].document

    assert strict["definedBy"] == meta.ref
    assert is_map(strict["metric"])
  end

  test "the meta-kind's document carries the rules it lays on kinds made under it", ctx do
    assert [%{"check" => "schemaPropertyType"} | _] =
             ctx.documents["harmony.r5e.io/v1/MetricDefinition"].document["predicates"]
  end

  test "a kind with no meta-kind says nothing about one", ctx do
    for path <- ["harmony.r5e.io/v1/Review", "harmony.r5e.io/v1/Spec", "core.r5e.io/v1/Artifact"] do
      document = ctx.documents[path].document
      assert Enum.filter(@extra, &is_map_key(document, &1)) == [], path
    end
  end

  test "no base definition gained a field, so every base reference is what it was" do
    for %{kind_path: path, bytes: bytes} <- Definitions.documents() do
      document = RecurseVerify.Canonical.decode_json(bytes) |> elem(1)
      assert Enum.filter(@extra, &is_map_key(document, &1)) == [], path
    end
  end
end
