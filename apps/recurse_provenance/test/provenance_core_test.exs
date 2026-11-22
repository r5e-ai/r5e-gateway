defmodule Recurse.Provenance.CoreTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{
    Body,
    Definitions,
    Envelope,
    Epoch,
    Evidence,
    Key,
    Profile,
    Ref,
    Schema
  }

  @base "provenance.r5e.io/v2"
  @stream "urn:r5e:stream:test:gateway:incarnation-01"
  @actor "spiffe://example.test/workload/gateway"

  defp profile(signer) do
    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:test:",
            actor_prefixes: ["spiffe://example.test/workload/"],
            issuer_keys: [signer.key_id],
            sealer_keys: [signer.key_id]
          }
        ],
        failure_domain: "test",
        deployment_policy_ref: Ref.bytes("deployment")
      )

    profile
  end

  defp tool_call(signer, profile, seq, previous, outcome \\ "allow") do
    args = Ref.bytes(~s({"command":"ls"}))
    path = @base <> "/ToolCall"
    {:ok, %{ref: schema_ref}} = Definitions.fetch(path)

    Evidence.new(
      kind_path: path,
      schema_ref: schema_ref,
      profile_ref: Profile.ref(profile),
      issuer: signer.key_id,
      actor: @actor,
      stream: @stream,
      seq: seq,
      previous: previous,
      captured_at: ~U[2026-11-09 12:00:00Z],
      session: "urn:r5e:session:test:one",
      body:
        Body.tool_call(
          tool: "shell",
          content_ref: args,
          media_type: "application/json",
          size: 16,
          policy:
            Body.policy_evaluation(
              policy_ref: Ref.bytes("permit(principal, action, resource);"),
              outcome: outcome,
              input_refs: [args]
            )
        )
    )
  end

  describe "definitions" do
    test "each base kind has its own content-addressed definition" do
      refs = Definitions.schema_refs()
      assert map_size(refs) == 26
      assert refs |> Map.values() |> Enum.uniq() |> length() == 26

      for {path, ref} <- refs do
        assert String.starts_with?(path, @base <> "/")
        assert {:ok, %{ref: ^ref, bytes: bytes, document: document}} = Definitions.fetch(path)
        assert Ref.matches?(ref, bytes)

        assert %{"format" => "r5e.kind-definition/v1", "kind" => ^path, "schema" => %{}} =
                 document
      end
    end

    test "a definition is complete on its own: nothing in it is left to resolve" do
      {:ok, %{bytes: bytes, document: document}} = Definitions.fetch(@base <> "/ToolCall")

      # Artifact's fields are in the tool call's own definition.
      assert %{"contentRef" => _, "mediaType" => _, "size" => _, "tool" => _} =
               document["schema"]["properties"]

      refute bytes =~ ~s("use":)
      refute bytes =~ "core.r5e.io/v1/Artifact"
    end

    test "the four kinds that carry content are Artifacts; the rest are not" do
      {:ok, %{ref: artifact}} = Definitions.fetch("core.r5e.io/v1/Artifact")

      for kind <- Definitions.kinds() do
        {:ok, %{document: document}} = Definitions.fetch(@base <> "/" <> kind)
        artifact? = kind in ~w[ModelCall ModelResponse ToolCall ToolResult]

        assert artifact in document["conformsTo"] == artifact?
        assert document["extends"] == artifact == artifact?
      end
    end

    test "a definition does not name its package, so its neighbours cannot change it" do
      for %{bytes: bytes} <- Definitions.documents(),
          %{ref: "bytes:sha256:" <> hex} <- Definitions.manifests() do
        refute bytes =~ hex
      end
    end

    test "a definition using an unsupported keyword is refused" do
      assert {:error, message} = Schema.check(%{"type" => "object", "patternProperties" => %{}})
      assert message =~ "patternProperties"
    end

    test "a definition with a non-local reference is refused" do
      assert {:error, _} = Schema.check(%{"$ref" => "https://example.test/x.json"})
    end
  end

  describe "keys" do
    for algorithm <- ["ed25519", "es256"] do
      test "#{algorithm}: key id is derived from the key, and signatures verify" do
        signer = Key.generate(unquote(algorithm))
        assert {:ok, id} = Key.id(unquote(algorithm), signer.public_key)
        assert id == signer.key_id
        assert String.starts_with?(id, "key:#{unquote(algorithm)}:sha256:")
        assert {:ok, unquote(algorithm)} = Key.algorithm_of(id)

        {:ok, signature} = signer.sign.("message")
        assert byte_size(signature) == 64
        assert Key.verify(unquote(algorithm), "message", signature, signer.public_key)
        refute Key.verify(unquote(algorithm), "other", signature, signer.public_key)
      end
    end

    test "the same bytes under another algorithm are a different key id" do
      ed = Key.generate("ed25519")
      assert {:error, _} = Key.id("es256", ed.public_key)
    end

    test "es256 refuses a high-S signature and a point off the curve" do
      signer = Key.generate("es256")
      {:ok, <<r::256, s::256>>} = signer.sign.("m")
      n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
      refute Key.verify("es256", "m", <<r::256, n - s::256>>, signer.public_key)

      <<4, x::256, y::256>> = signer.public_key
      assert {:error, _} = Key.id("es256", <<4, x::256, y + 1::256>>)
    end

    test "a DER signature converts to the low-S raw form" do
      {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
      der = :crypto.sign(:ecdsa, :sha256, "m", [private, :secp256r1])
      assert {:ok, raw} = Key.es256_raw_from_der(der)
      assert Key.verify("es256", "m", raw, public)
      assert {:error, :invalid_der} = Key.es256_raw_from_der("not der")
    end
  end

  describe "evidence" do
    test "a tool call validates against its definition and has a stable identity" do
      signer = Key.generate("ed25519")
      evidence = tool_call(signer, profile(signer), 1, nil)

      assert {:ok, :validated} = Evidence.validate(evidence)
      assert {:ok, bytes} = Evidence.encode(evidence)
      assert {:ok, ^bytes} = Evidence.encode(Map.new(Enum.reverse(Map.to_list(evidence))))
      assert "evidence:sha256:" <> _ = Evidence.ref(bytes)
    end

    test "position one has no predecessor; later positions must name one" do
      signer = Key.generate("ed25519")
      p = profile(signer)

      assert {:error, _} = Evidence.validate(tool_call(signer, p, 1, Ref.evidence("x")))
      assert {:error, _} = Evidence.validate(tool_call(signer, p, 2, nil))
      assert {:ok, :validated} = Evidence.validate(tool_call(signer, p, 2, Ref.evidence("x")))
    end

    test "a body that does not match its definition is refused, naming the place" do
      signer = Key.generate("ed25519")
      evidence = put_in(tool_call(signer, profile(signer), 1, nil), ["body", "surprise"], true)

      assert {:error, [{"/body.surprise", "unexpected_property"}]} = Evidence.validate(evidence)
    end

    test "a kind citing another kind's definition is refused" do
      signer = Key.generate("ed25519")
      {:ok, %{ref: other}} = Definitions.fetch(@base <> "/ModelCall")
      evidence = Map.put(tool_call(signer, profile(signer), 1, nil), "schemaRef", other)

      assert {:error, [{"/schemaRef", "definition_is_for_another_kind"}]} =
               Evidence.validate(evidence)
    end

    test "an extension kind keeps its own group; its body is unsupported until installed" do
      signer = Key.generate("ed25519")
      %{bytes: definition, ref: schema_ref} = Recurse.Provenance.Vectors.extension_package()

      evidence =
        tool_call(signer, profile(signer), 1, nil)
        |> Map.merge(%{
          "apiVersion" => "acme.example/v1",
          "kind" => "SafetyReview",
          "schemaRef" => schema_ref,
          "body" => %{"verdict" => "pass"}
        })

      assert Evidence.kind_path(evidence) == "acme.example/v1/SafetyReview"
      assert {:ok, :body_unsupported} = Evidence.validate(evidence)

      installed = fn ^schema_ref -> {:ok, definition} end
      assert {:ok, :validated} = Evidence.validate(evidence, definitions: installed)

      bad = put_in(evidence, ["body", "verdict"], "maybe")

      assert {:error, [{"/body.verdict", "enum_mismatch"}]} =
               Evidence.validate(bad, definitions: installed)

      # A definition with a rule this build cannot enforce is not used.
      for extra <- [%{"keyBytes" => true}, %{"somethingNew" => 1}] do
        document = definition |> Jason.decode!() |> update_in(["schema"], &Map.merge(&1, extra))
        bytes = RecurseVerify.Canonical.encode(document)
        cited = Map.put(evidence, "schemaRef", Ref.bytes(bytes))

        assert {:ok, :body_unsupported} =
                 Evidence.validate(cited, definitions: fn _ -> {:ok, bytes} end)
      end

      # Bytes that do not hash to the cited reference are not the definition.
      forged = fn ^schema_ref -> {:ok, definition <> " "} end
      assert {:ok, :body_unsupported} = Evidence.validate(evidence, definitions: forged)
    end

    test "floats have no canonical form" do
      signer = Key.generate("ed25519")

      evidence =
        put_in(tool_call(signer, profile(signer), 1, nil), ["body", "details"], %{
          "latency" => 1.5
        })

      assert {:error, _} = Evidence.encode(evidence)
    end

    test "causes must be sorted and unique" do
      signer = Key.generate("ed25519")
      a = Ref.evidence("a")
      b = Ref.evidence("b")
      [low, high] = Enum.sort([a, b])
      evidence = tool_call(signer, profile(signer), 1, nil)

      assert {:ok, :validated} = Evidence.validate(Map.put(evidence, "causes", [low, high]))

      assert {:error, [{"/causes", _}]} =
               Evidence.validate(Map.put(evidence, "causes", [high, low]))
    end
  end

  describe "envelope" do
    for algorithm <- ["ed25519", "es256"] do
      test "#{algorithm}: sign, open and verify round-trip; identity excludes the signature" do
        signer = Key.generate(unquote(algorithm))
        evidence = tool_call(signer, profile(signer), 1, nil)

        assert {:ok, %{envelope: envelope, ref: ref, payload: payload}} =
                 Envelope.sign(evidence, signer)

        assert Map.keys(envelope) == ["payload", "payloadType", "signatures"]
        assert ref == Ref.evidence(payload)

        assert {:ok, opened} = Envelope.open(envelope)
        assert opened.evidence == evidence
        assert opened.ref == ref

        keys = %{signer.key_id => %{algorithm: unquote(algorithm), bytes: signer.public_key}}
        assert :ok = Envelope.verify(opened, keys)
        assert {:error, :missing_key} = Envelope.verify(opened, %{})
      end
    end

    test "a signer cannot issue a record naming another issuer" do
      signer = Key.generate("ed25519")
      other = Key.generate("ed25519")
      evidence = tool_call(signer, profile(signer), 1, nil)
      assert {:error, :issuer_is_not_signer} = Envelope.sign(evidence, other)
    end

    test "a tampered payload fails verification and changes identity" do
      signer = Key.generate("ed25519")

      {:ok, %{envelope: envelope, ref: ref}} =
        Envelope.sign(tool_call(signer, profile(signer), 1, nil), signer)

      {:ok, tampered_payload} =
        Evidence.encode(tool_call(signer, profile(signer), 1, nil, "deny"))

      tampered = Map.put(envelope, "payload", Base.encode64(tampered_payload))

      assert {:ok, opened} = Envelope.open(tampered)
      refute opened.ref == ref
      keys = %{signer.key_id => %{algorithm: "ed25519", bytes: signer.public_key}}
      assert {:error, :bad_signature} = Envelope.verify(opened, keys)
    end

    test "a payload that is valid JSON but not canonical is refused, not normalised" do
      signer = Key.generate("ed25519")

      {:ok, %{envelope: envelope}} =
        Envelope.sign(tool_call(signer, profile(signer), 1, nil), signer)

      spaced =
        envelope["payload"] |> Base.decode64!() |> String.replace(~s("seq":1), ~s("seq": 1))

      assert {:error, :payload_not_canonical} =
               Envelope.open(Map.put(envelope, "payload", Base.encode64(spaced)))
    end

    test "extra wrapper fields, no signature and a repeated signer are refused" do
      signer = Key.generate("ed25519")

      {:ok, %{envelope: envelope}} =
        Envelope.sign(tool_call(signer, profile(signer), 1, nil), signer)

      assert {:error, {:malformed_envelope, _}} = Envelope.open(Map.put(envelope, "extra", 1))

      assert {:error, {:malformed_envelope, _}} =
               Envelope.open(Map.put(envelope, "signatures", []))

      doubled = Map.update!(envelope, "signatures", &(&1 ++ &1))
      assert {:error, :duplicate_signer} = Envelope.open(doubled)
    end

    test "several signers sign the same message, the issuer first" do
      issuer = Key.generate("ed25519")
      second = Key.generate("es384")
      evidence = tool_call(issuer, profile(issuer), 1, nil)

      keys =
        Map.new([issuer, second], &{&1.key_id, %{algorithm: &1.algorithm, bytes: &1.public_key}})

      {:ok, %{envelope: one, ref: ref}} = Envelope.sign(evidence, issuer)
      {:ok, %{envelope: two, ref: ^ref}} = Envelope.sign(evidence, [issuer, second])

      assert {:ok, opened} = Envelope.open(two)
      assert Envelope.signers(opened) == [issuer.key_id, second.key_id]
      assert [{_, :ok}, {_, :ok}] = Envelope.verify_each(opened, keys)
      assert hd(two["signatures"])["keyid"] == hd(one["signatures"])["keyid"]

      assert [{_, :ok}, {_, {:error, :missing_key}}] =
               Envelope.verify_each(opened, Map.take(keys, [issuer.key_id]))

      assert {:error, :issuer_is_not_signer} = Envelope.sign(evidence, [second, issuer])
      assert {:error, :duplicate_signer} = Envelope.sign(evidence, [issuer, issuer])

      swapped = Map.update!(two, "signatures", &Enum.reverse/1)
      assert {:error, :issuer_is_not_signer} = Envelope.open(swapped)
    end

    test "es384 signs and verifies in its raw low-S form, and refuses the high half" do
      for _ <- 1..20 do
        signer = Key.generate("es384")
        assert byte_size(signer.public_key) == 97
        {:ok, <<r::binary-48, s::unsigned-384>> = signature} = signer.sign.("message")
        assert Key.verify("es384", "message", signature, signer.public_key)
        refute Key.verify("es384", "another", signature, signer.public_key)

        n =
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

        refute Key.verify(
                 "es384",
                 "message",
                 <<r::binary, n - s::unsigned-384>>,
                 signer.public_key
               )
      end

      assert {:error, _} = Key.id("es384", <<4, 0::768>>)
    end

    test "a key filed under the wrong id is a mismatch" do
      signer = Key.generate("ed25519")
      other = Key.generate("ed25519")

      {:ok, %{envelope: envelope}} =
        Envelope.sign(tool_call(signer, profile(signer), 1, nil), signer)

      {:ok, opened} = Envelope.open(envelope)

      keys = %{signer.key_id => %{algorithm: "ed25519", bytes: other.public_key}}
      assert {:error, :key_mismatch} = Envelope.verify(opened, keys)
    end
  end

  describe "profile" do
    test "a record within its profile's bounds passes; outside them it does not" do
      signer = Key.generate("ed25519")
      p = profile(signer)
      evidence = tool_call(signer, p, 1, nil)

      assert :ok = Profile.check(p, evidence)

      assert {:error, :issuer_not_bound} =
               Profile.check(p, Map.put(evidence, "actor", "spiffe://elsewhere.test/x"))

      assert {:error, :issuer_not_bound} =
               Profile.check(p, Map.put(evidence, "stream", "urn:r5e:stream:other:x"))

      assert {:error, :policy_required} =
               Profile.check(p, update_in(evidence, ["body"], &Map.delete(&1, "policy")))

      assert {:error, :kind_not_in_profile} =
               Profile.check(p, Map.put(evidence, "kind", "Unknown"))
    end

    test "sealing authority is separate from issuing authority" do
      signer = Key.generate("ed25519")
      other = Key.generate("ed25519")
      p = profile(signer)

      assert Profile.sealer?(p, @stream, signer.key_id)
      refute Profile.sealer?(p, @stream, other.key_id)
      refute Profile.sealer?(p, "urn:r5e:stream:other:x", signer.key_id)
    end

    test "a policy-required kind must be in the schema map" do
      signer = Key.generate("ed25519")

      assert {:error, [{"/policyRequiredKinds", _}]} =
               Profile.new(
                 bindings: [
                   %{
                     stream_prefix: "urn:x:",
                     actor_prefixes: ["urn:a:"],
                     issuer_keys: [signer.key_id]
                   }
                 ],
                 failure_domain: "test",
                 deployment_policy_ref: Ref.bytes("d"),
                 policy_required_kinds: ["acme.example/v1/Missing"]
               )
    end
  end

  describe "epochs" do
    defp chain(signer, profile, count) do
      Enum.reduce(1..count, {[], nil}, fn seq, {acc, previous} ->
        {:ok, %{envelope: envelope, ref: ref}} =
          Envelope.sign(tool_call(signer, profile, seq, previous), signer)

        {:ok, opened} = Envelope.open(envelope)
        {acc ++ [opened], ref}
      end)
      |> elem(0)
    end

    test "a seal commits to a contiguous run and every member proves inclusion" do
      signer = Key.generate("ed25519")
      records = chain(signer, profile(signer), 5)
      refs = Enum.map(records, & &1.ref)

      {body, manifest_bytes} = Epoch.seal_body(@stream, 1, refs, nil)
      manifest = Jason.decode!(manifest_bytes)

      assert body["lastSeq"] == 5
      assert Ref.matches?(body["manifestRef"], manifest_bytes)
      assert :ok = Epoch.check_complete(body, manifest, records, nil)

      for {ref, index} <- Enum.with_index(refs) do
        {:ok, siblings} = Epoch.proof(refs, index)
        assert Epoch.verify_proof(ref, index, 5, siblings, body["root"])
        refute Epoch.verify_proof(ref, rem(index + 1, 5), 5, siblings, body["root"])
        refute Epoch.verify_proof(ref, index, 5, siblings ++ [body["root"]], body["root"])
      end

      refute Map.has_key?(body, "previousSeal")
      {:ok, %{ref: seal_ref}} = Definitions.fetch(@base <> "/EpochSeal")
      assert :ok = Definitions.check(@base <> "/EpochSeal", seal_ref, body)
    end

    test "the root matches the contract's construction for one, two and three leaves" do
      h = &:crypto.hash(:sha256, &1)
      leaf = fn ref -> h.(<<0>> <> Ref.digest!(ref, :evidence)) end
      node = fn l, r -> h.(<<1>> <> l <> r) end
      hex = &("sha256:" <> Base.encode16(&1, case: :lower))
      [a, b, c] = Enum.map(["a", "b", "c"], &Ref.evidence/1)

      assert Epoch.root([a]) == hex.(leaf.(a))
      assert Epoch.root([a, b]) == hex.(node.(leaf.(a), leaf.(b)))
      assert Epoch.root([a, b, c]) == hex.(node.(node.(leaf.(a), leaf.(b)), leaf.(c)))
    end

    test "a reordered, missing or foreign record breaks the seal" do
      signer = Key.generate("ed25519")
      records = chain(signer, profile(signer), 3)
      refs = Enum.map(records, & &1.ref)
      {body, manifest_bytes} = Epoch.seal_body(@stream, 1, refs, nil)
      manifest = Jason.decode!(manifest_bytes)

      assert {:error, :records_do_not_match_manifest} =
               Epoch.check_complete(body, manifest, Enum.reverse(records), nil)

      assert {:error, :records_do_not_match_manifest} =
               Epoch.check_complete(body, manifest, tl(records), nil)

      assert {:error, :root} =
               Epoch.check_complete(
                 Map.put(body, "root", Epoch.root(tl(refs))),
                 manifest,
                 records,
                 nil
               )

      assert {:error, :previous} =
               Epoch.check_complete(body, manifest, records, Ref.evidence("x"))
    end

    test "a second seal starts after the first and cites it" do
      signer = Key.generate("ed25519")
      records = chain(signer, profile(signer), 4)
      {first, second} = Enum.split(records, 2)
      {body1, _} = Epoch.seal_body(@stream, 1, Enum.map(first, & &1.ref), nil)
      seal1 = Ref.evidence("seal-one")
      {body2, manifest_bytes} = Epoch.seal_body(@stream, 3, Enum.map(second, & &1.ref), seal1)

      assert body1["lastSeq"] == 2
      assert body2["firstSeq"] == 3 and body2["previousSeal"] == seal1

      assert :ok =
               Epoch.check_complete(
                 body2,
                 Jason.decode!(manifest_bytes),
                 second,
                 List.last(first).ref
               )
    end
  end
end
