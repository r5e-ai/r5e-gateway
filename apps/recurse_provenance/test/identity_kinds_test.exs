defmodule Recurse.Provenance.IdentityKindsTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{Definitions, Key}

  @base "provenance.r5e.io/v2/"

  defp check(kind, body, signers) do
    {:ok, %{ref: ref}} = Definitions.fetch(@base <> kind)
    Definitions.check(@base <> kind, ref, body, fn _ -> :error end, signers)
  end

  defp public_key(signer),
    do: %{"algorithm" => signer.algorithm, "bytes" => Base.encode64(signer.public_key)}

  defp codes({:error, violations}), do: violations |> Enum.map(& &1.code) |> Enum.sort()

  setup do
    %{a: Key.generate("ed25519"), b: Key.generate("es256"), c: Key.generate("es384")}
  end

  test "a principal introduces the key that signed it", %{a: a, b: b} do
    body = %{"key" => a.key_id, "publicKey" => public_key(a), "holder" => "person"}

    assert :ok = check("Principal", body, [a.key_id])

    # Someone else introducing this key.
    assert ["signer_mismatch"] = codes(check("Principal", body, [b.key_id]))

    # The named id is not the id of the key carried.
    assert ["not_the_key_id_of"] =
             codes(check("Principal", %{body | "publicKey" => public_key(b)}, [a.key_id]))

    assert ["missing_required"] =
             codes(check("Principal", Map.delete(body, "publicKey"), [a.key_id]))
  end

  test "an endorsement is one signature, with a window that runs forwards", %{a: a, b: b} do
    body = %{
      "subject" => b.key_id,
      "kinds" => [@base <> "ToolCall", "acme.example/v1/SafetyReview"],
      "mayEndorse" => false,
      "notBefore" => "2026-11-10T00:00:00Z",
      "notAfter" => "2026-11-11T00:00:00Z"
    }

    assert :ok = check("Endorsement", body, [a.key_id])
    assert {:error, :signature_count_differs} = check("Endorsement", body, [a.key_id, b.key_id])

    assert ["out_of_order"] =
             codes(
               check("Endorsement", %{body | "notAfter" => "2026-11-09T00:00:00Z"}, [a.key_id])
             )

    assert ["empty_value"] = codes(check("Endorsement", %{body | "kinds" => []}, [a.key_id]))

    assert ["pattern_mismatch"] =
             codes(
               check("Endorsement", %{body | "kinds" => ["provenance.r5e.io/v2/*"]}, [a.key_id])
             )
  end

  test "a badge needs its subject to sign second and to be the key it carries", ctx do
    %{a: issuer, b: subject, c: other} = ctx

    body = %{
      "subject" => subject.key_id,
      "subjectKey" => public_key(subject),
      "holder" => "workload",
      "kinds" => [@base <> "ToolCall"],
      "notBefore" => "2026-11-10T00:00:00Z",
      "notAfter" => "2026-11-10T04:00:00Z",
      "parent" => "evidence:sha256:" <> String.duplicate("a", 64)
    }

    assert :ok = check("Badge", body, [issuer.key_id, subject.key_id])
    assert {:error, :signature_count_differs} = check("Badge", body, [issuer.key_id])
    assert ["signer_mismatch"] = codes(check("Badge", body, [issuer.key_id, other.key_id]))

    assert ["not_the_key_id_of"] =
             codes(
               check("Badge", %{body | "subjectKey" => public_key(other)}, [
                 issuer.key_id,
                 subject.key_id
               ])
             )

    # Nothing in a badge lets its subject vouch for others.
    assert ["unexpected_property"] =
             codes(
               check("Badge", Map.put(body, "mayEndorse", true), [issuer.key_id, subject.key_id])
             )
  end

  test "a succession is signed by the old key and then the new", %{a: old, b: new, c: other} do
    body = %{
      "predecessor" => old.key_id,
      "successor" => new.key_id,
      "successorKey" => public_key(new)
    }

    assert :ok = check("Succession", body, [old.key_id, new.key_id])
    assert {:error, :signature_count_differs} = check("Succession", body, [old.key_id])

    assert ["signer_mismatch", "signer_mismatch"] =
             codes(check("Succession", body, [new.key_id, old.key_id]))

    assert ["signer_mismatch"] = codes(check("Succession", body, [old.key_id, other.key_id]))
  end

  test "a revocation names the record it takes back", %{a: a} do
    target = "evidence:sha256:" <> String.duplicate("b", 64)
    assert :ok = check("Revocation", %{"target" => target}, [a.key_id])
    assert ["missing_required"] = codes(check("Revocation", %{}, [a.key_id]))

    assert ["pattern_mismatch"] =
             codes(check("Revocation", %{"target" => "that one"}, [a.key_id]))
  end
end
