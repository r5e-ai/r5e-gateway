defmodule Recurse.Gateway.Provenance.SessionNameTest do
  use ExUnit.Case, async: true

  alias Recurse.Gateway.LlmProxy.PrincipalExtractor
  alias Recurse.Gateway.Provenance.SessionName

  @alice "urn:r5e:principal:acme:alice%40example.test"
  @bob "urn:r5e:principal:acme:bob%40example.test"

  test "the same id from two people names two sessions, each its owner's" do
    alices = SessionName.for("acme", @alice, "s1")
    bobs = SessionName.for("acme", @bob, "s1")

    assert alices != bobs
    assert SessionName.owned_by?(alices, @alice)
    refute SessionName.owned_by?(alices, @bob)

    assert {:ok, %{tenant: "acme", id: "s1", fingerprint: fingerprint}} =
             SessionName.parts(alices)

    assert fingerprint == SessionName.fingerprint(@alice)
  end

  test "any id the proxy accepts gives a name that reads back" do
    # 128 bytes, every one of which is percent-encoded to three.
    id = String.duplicate("/", 128)
    name = SessionName.for("a:b c", @alice, id)

    assert {:ok, %{tenant: "a%3Ab%20c", id: encoded}} = SessionName.parts(name)
    assert byte_size(encoded) == 384
  end

  test "what is not a recorded name is not read as one" do
    name = SessionName.for("acme", @alice, "s1")

    assert :error = SessionName.parts(name <> "\n")
    assert :error = SessionName.parts("urn:r5e:session:acme:s1")
    assert :error = SessionName.parts("urn:r5e:hold:" <> name)
    assert :error = SessionName.parts(nil)
    refute SessionName.owned_by?("urn:r5e:session:acme:s1", @alice)
  end

  describe "how the proxy names a caller" do
    defp principal(claims, sub),
      do: %{principal_id: sub, principal_kind: :obo_human, claims: claims}

    test "a token from this deployment's broker is named as the authenticated routes name it" do
      assert "ci-runner" ==
               PrincipalExtractor.evidence_id(
                 principal(%{"principal" => %{"account_id" => "ci-runner"}}, "sa:ci-runner")
               )

      assert "spiffe://acme/agent" ==
               PrincipalExtractor.evidence_id(
                 principal(%{"principal" => %{"spiffe_id" => "spiffe://acme/agent"}}, "a-uuid")
               )

      assert "dana@acme.example" ==
               PrincipalExtractor.evidence_id(
                 principal(%{"principal" => %{"subject" => "dana@acme.example"}}, "other")
               )
    end

    test "any other token is named by its sub" do
      assert "user-1" == PrincipalExtractor.evidence_id(principal(%{}, "user-1"))

      assert "user-1" ==
               PrincipalExtractor.evidence_id(principal(%{"principal" => "x"}, "user-1"))

      assert "user-1" ==
               PrincipalExtractor.evidence_id(
                 principal(%{"principal" => %{"subject" => ""}}, "user-1")
               )
    end
  end
end
