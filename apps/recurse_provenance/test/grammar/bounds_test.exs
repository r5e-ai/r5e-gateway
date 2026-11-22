defmodule Recurse.Provenance.Grammar.BoundsTest do
  @moduledoc """
  The rules that bound an open part of a record: `unique` on an array,
  `keys` and `maxEntries` on an object, `maxLength` on a string, and the
  `evidence` reference form with a chain named by its founding record.
  """
  use ExUnit.Case, async: true

  alias Recurse.Provenance.Grammar.{Schema, Validate}

  @details %{
    "type" => "object",
    "keys" => "^[A-Za-z][A-Za-z0-9_.-]{0,63}$",
    "maxEntries" => 2,
    "values" => %{"type" => ["string", "integer", "boolean"], "maxLength" => 4}
  }

  test "an open object is held to its key pattern, its size and its values" do
    assert :ok = Schema.check_coherence(@details, "details")
    assert :ok = Validate.validate(@details, %{"a" => "abcd", "b.c" => 7})

    assert {:error, [%{path: "$.has space", code: "key_mismatch"}]} =
             Validate.validate(@details, %{"has space" => 1})

    assert {:error, [%{path: "$", code: "too_many_entries"}]} =
             Validate.validate(@details, %{"a" => 1, "b" => 2, "c" => 3})

    assert {:error, [%{path: "$.a", code: "wrong_type"}]} =
             Validate.validate(@details, %{"a" => %{"nested" => 1}})

    assert {:error, [%{path: "$.a", code: "wrong_type"}]} =
             Validate.validate(@details, %{"a" => ["list"]})
  end

  test "maxLength counts bytes of UTF-8, not characters" do
    assert :ok = Validate.validate(@details, %{"a" => "éé"})

    assert {:error, [%{path: "$.a", code: "too_long"}]} =
             Validate.validate(@details, %{"a" => "ééé"})

    assert {:error, [%{path: "$.a", code: "too_long"}]} =
             Validate.validate(@details, %{"a" => "abcde"})
  end

  test "a unique array may not repeat an item, whatever the item is" do
    schema = %{"type" => "array", "unique" => true}
    assert :ok = Schema.check_coherence(schema, "refs")
    assert :ok = Validate.validate(schema, ["a", "b", %{"k" => 1}, %{"k" => 2}])

    assert {:error, [%{path: "$", code: "duplicate_item"}]} =
             Validate.validate(schema, ["a", "b", "a"])

    assert {:error, [%{path: "$", code: "duplicate_item"}]} =
             Validate.validate(schema, [%{"k" => 1, "j" => 2}, %{"j" => 2, "k" => 1}])
  end

  test "a bound that could never apply is refused when the definition is compiled" do
    assert {:error, {:unique_requires_array, "s"}} =
             Schema.check_coherence(%{"type" => "string", "unique" => true}, "s")

    assert {:error, {:unique_must_be_true, "s"}} =
             Schema.check_coherence(%{"type" => "array", "unique" => false}, "s")

    assert {:error, {:max_length_requires_string, "s"}} =
             Schema.check_coherence(%{"type" => "integer", "maxLength" => 3}, "s")

    assert {:error, {:expected_positive_bound, "s.maxLength"}} =
             Schema.check_coherence(%{"type" => "string", "maxLength" => 0}, "s")

    assert {:error, {:expected_positive_bound, "s.maxEntries"}} =
             Schema.check_coherence(%{"type" => "object", "maxEntries" => "many"}, "s")

    assert {:error, {:object_rules_require_object, "s"}} =
             Schema.check_coherence(%{"type" => "string", "keys" => "^a$"}, "s")

    assert {:error, {:invalid_regex_pattern, "s", "("}} =
             Schema.check_coherence(%{"type" => "object", "keys" => "("}, "s")
  end

  test "a narrower node keeps a bound only by being at least as tight" do
    base = %{"type" => "string", "maxLength" => 10}
    assert Schema.property_preserves?(%{"type" => "string", "maxLength" => 10}, base)
    assert Schema.property_preserves?(%{"type" => "string", "maxLength" => 3}, base)
    refute Schema.property_preserves?(%{"type" => "string", "maxLength" => 11}, base)
    refute Schema.property_preserves?(%{"type" => "string"}, base)

    set = %{"type" => "array", "unique" => true}
    assert Schema.property_preserves?(set, set)
    refute Schema.property_preserves?(%{"type" => "array"}, set)
  end

  test "an evidence reference, and a chain named by the record that founded it" do
    record = "evidence:sha256:" <> String.duplicate("a", 64)
    chain = "evidence:sha256:" <> String.duplicate("c", 64)
    here = %{"evidence" => true}
    anywhere = %{"evidence" => true, "crossChain" => true}

    assert :ok = Validate.check_ref(record, here)
    assert :ok = Validate.check_ref(record, anywhere)
    assert :ok = Validate.check_ref("chain:" <> chain <> "/" <> record, anywhere)

    assert {:error, "expected_evidence_ref"} =
             Validate.check_ref("event:sha256:" <> String.duplicate("a", 64), here)

    assert {:error, "cross_chain_forbidden"} =
             Validate.check_ref("chain:" <> chain <> "/" <> record, here)

    assert {:error, "malformed_cross_chain_ref"} =
             Validate.check_ref("chain:r5e-dev/" <> record, anywhere)

    assert {:error, "malformed_cross_chain_ref"} =
             Validate.check_ref("chain:" <> String.upcase(chain) <> "/" <> record, anywhere)
  end
end
