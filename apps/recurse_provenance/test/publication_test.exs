defmodule Recurse.Provenance.PublicationTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{Definitions, Export, Key, Publication, Vectors}

  defp publisher do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    Key.local_signer("ed25519", public, private)
  end

  defp sound_bundle do
    %{bundle: bundle, trusted_profiles: profiles} =
      Enum.find(Vectors.all(), &(&1.name == "publication-not-carried"))

    {bundle, profiles}
  end

  defp publication_codes(result) do
    for %{check: :publication, code: code} <- result.findings, uniq: true, do: code
  end

  test "an issued set names every installed definition and checks out" do
    signer = publisher()
    assert {:ok, set} = Publication.issue(signer, name: "meridian")
    assert {:ok, ^set} = Publication.check(set)
    assert Publication.publishers(set) == [signer.key_id]

    assert %{"records" => [_one], "keys" => [%{"keyid" => keyid}], "blobs" => blobs} = set
    assert keyid == signer.key_id
    # The publisher's profile, then one document per definition.
    assert length(blobs) == length(Definitions.documents()) + 1
  end

  test "a carried publication turns 'not carried' into 'ok' for a reader who trusts the publisher" do
    signer = publisher()
    {:ok, set} = Publication.issue(signer)
    {bundle, profiles} = sound_bundle()

    before =
      Export.verify(bundle, trusted_profiles: profiles, trusted_publishers: [signer.key_id])

    assert publication_codes(before) == ["publication_not_carried"]

    carried = Publication.carry(bundle, [set])
    [profile_blob | _] = set["blobs"]

    trusting =
      Export.verify(carried,
        trusted_profiles: profiles ++ [profile_blob["ref"]],
        trusted_publishers: [signer.key_id]
      )

    assert publication_codes(trusting) == ["ok"]
    assert %{failed: 0, incomplete: 0} = trusting.summary

    # The same file, read by someone who has not chosen to trust that key.
    stranger = Export.verify(carried, trusted_profiles: profiles, trusted_publishers: [])
    assert publication_codes(stranger) == ["publisher_not_trusted"]
    assert stranger.summary.failed == 0
  end

  # A hardware token can sign any length with these two, because the token is
  # sent a digest; with ed25519 it is sent the whole message and has a limit.
  for algorithm <- ["es256", "es384"] do
    test "a publisher holding an #{algorithm} key is checked and believed like any other" do
      signer = Key.generate(unquote(algorithm))
      assert {:ok, set} = Publication.issue(signer)
      assert {:ok, ^set} = Publication.check(set)
      assert Publication.publishers(set) == [signer.key_id]
      assert String.starts_with?(signer.key_id, "key:" <> unquote(algorithm) <> ":sha256:")

      {bundle, profiles} = sound_bundle()
      [profile_blob | _] = set["blobs"]

      trusting =
        bundle
        |> Publication.carry([set])
        |> Export.verify(
          trusted_profiles: profiles ++ [profile_blob["ref"]],
          trusted_publishers: [signer.key_id]
        )

      assert publication_codes(trusting) == ["ok"]
      assert %{failed: 0, incomplete: 0} = trusting.summary
    end
  end

  test "carrying twice adds nothing the second time" do
    {:ok, set} = Publication.issue(publisher())
    {bundle, _} = sound_bundle()
    once = Publication.carry(bundle, [set])
    assert Publication.carry(once, [set, set]) == once
  end

  test "a set is refused when its record, key or blob has been altered" do
    {:ok, set} = Publication.issue(publisher())
    {:ok, other} = Publication.issue(publisher())

    # Another publisher's key under this record: the signature cannot be checked.
    assert {:error, :not_a_verifiable_publication} =
             Publication.check(%{set | "keys" => other["keys"]})

    [%{"ref" => ref} | rest] = set["blobs"]
    swapped = [%{"ref" => ref, "base64" => Base.encode64("something else")} | rest]

    assert {:error, :blob_differs_from_its_reference} =
             Publication.check(%{set | "blobs" => swapped})

    [key] = set["keys"]

    assert {:error, :key_differs_from_its_id} =
             Publication.check(%{set | "keys" => [%{key | "bytes" => Base.encode64(<<0::256>>)}]})

    assert {:error, :not_a_carried_set} = Publication.check(%{"records" => "none"})
  end

  test "passing a set on keeps what is well formed and drops the rest" do
    {:ok, set} = Publication.issue(publisher())
    [record] = set["records"]
    [key] = set["keys"]

    mixed = %{
      "records" => [record, %{"ref" => record["ref"], "envelope" => %{}}, "nonsense"],
      "keys" => [key, %{key | "bytes" => Base.encode64(<<0::256>>)}],
      "blobs" => set["blobs"] ++ [%{"ref" => "bytes:sha256:00", "base64" => "AAAA"}]
    }

    assert Publication.readable(mixed) == set
    assert Publication.readable("nonsense") == %{"records" => [], "keys" => [], "blobs" => []}
    assert Publication.readable(%{"records" => "x"})["records"] == []
  end

  test "a record that is not a publication is not carried as one" do
    {bundle, _} = sound_bundle()

    assert {:error, :not_a_verifiable_publication} =
             Publication.check(Map.take(bundle, ["records", "keys", "blobs"]))
  end

  test "a private key file gives the signer its public half names" do
    for {type, curve, algorithm} <- [
          {:eddsa, :ed25519, "ed25519"},
          {:ecdh, :secp256r1, "es256"},
          {:ecdh, :secp384r1, "es384"}
        ] do
      {public, private} = :crypto.generate_key(type, curve)
      oid = :pubkey_cert_records.namedCurves(curve)

      der =
        :public_key.der_encode(
          :ECPrivateKey,
          {:ECPrivateKey, 1, private, {:namedCurve, oid}, :asn1_NOVALUE, :asn1_NOVALUE}
        )

      pem = :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
      assert {:ok, signer} = Key.signer_from_pem(pem)
      assert signer.algorithm == algorithm
      assert signer.public_key == public
      assert {:ok, signature} = signer.sign.("message")
      assert Key.verify(algorithm, "message", signature, public)
    end

    assert {:error, :unreadable_private_key} = Key.signer_from_pem("not a key")
  end
end
