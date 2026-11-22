defmodule Recurse.Provenance.CanonicalJcsTest do
  @moduledoc """
  The canonical encoder produces the bytes RFC 8785 (JCS) does, for
  every value its profile admits, and refuses what the profile leaves
  out. The expected hashes were computed outside this codebase; see
  `fixtures/canonical/README.md`.
  """
  use ExUnit.Case, async: true

  alias RecurseVerify.Canonical

  @dir Path.expand("fixtures/canonical", __DIR__)
  @cases @dir
         |> Path.join("corpus.jsonl")
         |> File.stream!()
         |> Stream.zip(File.stream!(Path.join(@dir, "jcs-reference.sha256")))
         |> Enum.map(fn {line, hash} -> {String.trim_trailing(line, "\n"), String.trim(hash)} end)

  defp class(line), do: Jason.decode!(line)["c"]
  defp sha256(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  # The value as raw JSON text, cut out of the line so no decoder has
  # touched it: `{"c":"<class>","v":<value>}` or the reverse order.
  defp raw_value(line) do
    case Regex.run(~r/\A\{"c":"[^"]*","v":(.*)\}\z/s, line) do
      [_, raw] -> raw
      nil -> line |> Jason.decode!() |> Map.fetch!("v") |> Jason.encode!()
    end
  end

  test "admitted values encode to exactly the JCS bytes" do
    admitted = Enum.filter(@cases, fn {line, _} -> String.first(class(line)) in ~w[1 2 3 4] end)
    assert length(admitted) == 1600

    for {line, expected} <- admitted do
      value = Jason.decode!(line)["v"]
      assert sha256(Canonical.encode(value)) == expected, "differs from JCS for #{line}"

      # And the strict parser reads those bytes back as canonical.
      bytes = Canonical.encode(value)
      assert {:ok, ^value} = Canonical.decode_json(bytes)
    end
  end

  test "a key with a character above U+FFFF is refused, when writing and when reading" do
    mixed = Enum.filter(@cases, fn {line, _} -> String.starts_with?(class(line), "5") end)
    assert length(mixed) == 400

    for {line, expected} <- mixed do
      value = Jason.decode!(line)["v"]

      if line =~ ~r/[\x{10000}-\x{10FFFF}]/u do
        assert_raise ArgumentError, fn -> Canonical.encode(value) end
        assert {:error, _} = Canonical.decode_json(raw_value(line))
      else
        assert sha256(Canonical.encode(value)) == expected
      end
    end
  end

  test "numbers outside the integer profile are refused" do
    numbers = Enum.filter(@cases, fn {line, _} -> String.starts_with?(class(line), "6") end)
    assert length(numbers) == 16

    for {line, _expected} <- numbers do
      assert {:error, _} = Canonical.decode_json(raw_value(line)), "accepted #{line}"
    end

    assert_raise ArgumentError, fn -> Canonical.encode(%{"n" => 9_007_199_254_740_992}) end
    assert Canonical.encode(%{"n" => 9_007_199_254_740_991}) == ~s({"n":9007199254740991})
  end

  test "the five short escapes, and the long form for the other control characters" do
    assert Canonical.encode("a\nb\tc\rd\be\ff") == ~S("a\nb\tc\rd\be\ff")
    assert Canonical.encode(<<1, 0x1F>>) == ~S("\u0001\u001f")
    assert {:ok, "a\nb"} = Canonical.decode_json(~S("a\nb"))
  end
end
