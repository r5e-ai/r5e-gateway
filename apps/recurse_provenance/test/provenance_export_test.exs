defmodule Recurse.Provenance.ExportTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{
    Body,
    Definitions,
    Envelope,
    Epoch,
    Evidence,
    Export,
    Key,
    Profile,
    Ref
  }

  @base "provenance.r5e.io/v2"
  @stream "urn:r5e:stream:test:gateway:incarnation-01"
  @control "urn:r5e:stream:test:control:incarnation-01"
  @actor "spiffe://example.test/workload/gateway"
  @args ~s({"command":"ls"})
  @policy "permit(principal, action, resource);"

  defp setup_world(count \\ 3) do
    signer = Key.generate("ed25519")

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

    profile_ref = Profile.ref(profile)

    record = fn path, stream, seq, previous, body ->
      {:ok, %{ref: schema_ref}} = Definitions.fetch(path)

      evidence =
        Evidence.new(
          kind_path: path,
          schema_ref: schema_ref,
          profile_ref: profile_ref,
          issuer: signer.key_id,
          actor: @actor,
          stream: stream,
          seq: seq,
          previous: previous,
          captured_at: ~U[2026-11-09 12:00:00Z],
          body: body
        )

      {:ok, signed} = Envelope.sign(evidence, signer)
      signed
    end

    tool_body =
      Body.tool_call(
        tool: "shell",
        content_ref: Ref.bytes(@args),
        media_type: "application/json",
        size: byte_size(@args),
        policy:
          Body.policy_evaluation(
            policy_ref: Ref.bytes(@policy),
            outcome: "allow",
            input_refs: [Ref.bytes(@args)]
          )
      )

    {calls, _} =
      Enum.reduce(1..count, {[], nil}, fn seq, {acc, previous} ->
        signed = record.(@base <> "/ToolCall", @stream, seq, previous, tool_body)
        {acc ++ [signed], signed.ref}
      end)

    refs = Enum.map(calls, & &1.ref)
    {seal_body, manifest_bytes} = Epoch.seal_body(@stream, 1, refs, nil)
    seal = record.(@base <> "/EpochSeal", @control, 1, nil, seal_body)

    %{
      signer: signer,
      profile: profile,
      profile_ref: profile_ref,
      calls: calls,
      refs: refs,
      seal: seal,
      manifest_bytes: manifest_bytes,
      record: record,
      tool_body: tool_body
    }
  end

  defp key(w),
    do: %{key_id: w.signer.key_id, algorithm: "ed25519", public_key: w.signer.public_key}

  defp full_bundle(w, overrides \\ []) do
    fields =
      Keyword.merge(
        [
          query: %{"stream" => @stream},
          records: Enum.map(w.calls, & &1.envelope) ++ [w.seal.envelope],
          blobs: [
            {Profile.encode(w.profile), "application/json"},
            {w.manifest_bytes, nil},
            {@args, nil},
            {@policy, nil}
          ],
          keys: [key(w)],
          seals: [w.seal.ref]
        ],
        overrides
      )

    {:ok, bundle} = Export.build(fields)
    bundle
  end

  defp results(report, check), do: for(f <- report.findings, f.check == check, do: f.result)

  test "a complete bundle verifies offline at every layer when its profile is trusted" do
    w = setup_world()
    report = Export.verify(full_bundle(w), trusted_profiles: [w.profile_ref])

    assert report.summary.failed == 0
    # This bundle carries no publisher's statement, so whose definitions
    # these are is the one thing left unestablished.
    assert Enum.all?(
             Enum.filter(report.findings, &(&1.result == :incomplete)),
             &match?(%{check: :publication, code: "publication_not_carried"}, &1)
           )

    assert Export.sound?(report)
    assert results(report, :signature) == [:ok, :ok, :ok, :ok]
    assert results(report, :epoch) == [:ok]
    assert results(report, :sealer) == [:ok]
    assert Enum.count(results(report, :previous)) == 2
  end

  test "the bundle survives a JSON round trip" do
    w = setup_world()
    bundle = w |> full_bundle() |> Jason.encode!() |> Jason.decode!()
    assert Export.sound?(Export.verify(bundle, trusted_profiles: [w.profile_ref]))
  end

  test "without a trust input, authority is unestablished rather than assumed" do
    w = setup_world()
    report = Export.verify(full_bundle(w))

    assert report.summary.failed == 0
    assert Enum.all?(results(report, :authority), &(&1 == :incomplete))
    assert results(report, :profile_bounds) |> Enum.all?(&(&1 == :ok))
  end

  test "a missing key leaves signatures unchecked, not passed" do
    w = setup_world()
    report = Export.verify(full_bundle(w, keys: []), trusted_profiles: [w.profile_ref])

    assert report.summary.failed == 0
    assert Enum.all?(results(report, :signature), &(&1 == :incomplete))
  end

  test "a record whose bytes do not hash to its reference fails identity" do
    w = setup_world()
    bundle = full_bundle(w)
    [first | rest] = bundle["records"]
    forged = %{first | "ref" => Ref.evidence("something else")}

    report = Export.verify(%{bundle | "records" => [forged | rest]})
    assert :failed in results(report, :identity)
    refute Export.sound?(report)
  end

  test "a signature from another key fails" do
    w = setup_world()
    stranger = Key.generate("ed25519")
    wrong = %{key_id: w.signer.key_id, algorithm: "ed25519", public_key: stranger.public_key}

    report = Export.verify(full_bundle(w, keys: [wrong]))
    assert Enum.all?(results(report, :signature), &(&1 == :failed))
  end

  test "content that is withheld is named, and does not count as verified" do
    w = setup_world()

    bundle =
      full_bundle(w,
        blobs: [{Profile.encode(w.profile), nil}, {w.manifest_bytes, nil}, {@policy, nil}],
        omissions: [%{ref: Ref.bytes(@args), reason: "withheld"}]
      )

    report = Export.verify(bundle, trusted_profiles: [w.profile_ref])
    assert report.summary.failed == 0

    assert Enum.any?(report.findings, fn f ->
             f.check == :content and f.result == :incomplete and
               f.code == "omitted_withheld"
           end)
  end

  test "a blob whose bytes do not match its reference fails" do
    w = setup_world()
    bundle = full_bundle(w)
    [blob | rest] = bundle["blobs"]
    bad = %{blob | "base64" => Base.encode64("tampered")}

    report = Export.verify(%{bundle | "blobs" => [bad | rest]})
    assert :failed in results(report, :content_hash)
  end

  test "one call with a membership proof verifies without the rest of the epoch" do
    w = setup_world(5)
    index = 2
    {:ok, siblings} = Epoch.proof(w.refs, index)
    chosen = Enum.at(w.calls, index)

    {:ok, bundle} =
      Export.build(
        records: [chosen.envelope, w.seal.envelope],
        blobs: [{Profile.encode(w.profile), nil}, {@args, nil}, {@policy, nil}],
        keys: [key(w)],
        seals: [w.seal.ref],
        proofs: [%{record: chosen.ref, seal: w.seal.ref, index: index, siblings: siblings}],
        omissions: Enum.map(List.delete_at(w.refs, index), &%{ref: &1, reason: "not-selected"})
      )

    report = Export.verify(bundle, trusted_profiles: [w.profile_ref])
    assert report.summary.failed == 0
    assert results(report, :membership) == [:ok]
    assert results(report, :epoch) == [:incomplete]

    wrong = put_in(bundle, ["proofs", Access.at(0), "index"], index + 1)
    assert results(Export.verify(wrong), :membership) == [:failed]
  end

  test "two different records at one stream position are reported as a fork" do
    w = setup_world(2)
    other_body = put_in(w.tool_body, ["tool"], "different")
    rival = w.record.(@base <> "/ToolCall", @stream, 2, hd(w.refs), other_body)

    bundle =
      full_bundle(w, records: Enum.map(w.calls, & &1.envelope) ++ [rival.envelope], seals: [])

    report = Export.verify(bundle, trusted_profiles: [w.profile_ref])

    assert results(report, :fork) == [:failed]
  end

  test "a seal by a key the profile does not allow to seal is unauthorized" do
    w = setup_world()

    {:ok, strict} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:test:",
            actor_prefixes: ["spiffe://example.test/workload/"],
            issuer_keys: [w.signer.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "test",
        deployment_policy_ref: Ref.bytes("deployment")
      )

    # Re-issue the seal under the profile that grants no sealing authority.
    {:ok, %{ref: schema_ref}} = Definitions.fetch(@base <> "/EpochSeal")
    {:ok, opened} = Envelope.open(w.seal.envelope)

    evidence = %{opened.evidence | "profileRef" => Profile.ref(strict), "schemaRef" => schema_ref}
    {:ok, seal} = Envelope.sign(evidence, w.signer)

    bundle =
      full_bundle(w,
        records: Enum.map(w.calls, & &1.envelope) ++ [seal.envelope],
        blobs: [
          {Profile.encode(w.profile), nil},
          {Profile.encode(strict), nil},
          {w.manifest_bytes, nil},
          {@args, nil},
          {@policy, nil}
        ],
        seals: [seal.ref]
      )

    report = Export.verify(bundle)
    assert results(report, :sealer) == [:failed]
  end

  test "an extension record carried with its definition is checked; without it, reported unsupported" do
    w = setup_world(1)

    %{kind_path: path, bytes: definition_bytes} = Recurse.Provenance.Vectors.extension_package()

    {:ok, profile} =
      Profile.new(
        schemas: Map.put(Definitions.schema_refs(), path, Ref.bytes(definition_bytes)),
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:test:",
            actor_prefixes: ["spiffe://example.test/workload/"],
            issuer_keys: [w.signer.key_id]
          }
        ],
        failure_domain: "test",
        deployment_policy_ref: Ref.bytes("deployment")
      )

    evidence =
      Evidence.new(
        kind_path: path,
        schema_ref: Ref.bytes(definition_bytes),
        profile_ref: Profile.ref(profile),
        issuer: w.signer.key_id,
        actor: @actor,
        stream: "urn:r5e:stream:test:reviews:incarnation-01",
        seq: 1,
        previous: nil,
        captured_at: ~U[2026-11-09 12:00:00Z],
        body: %{"verdict" => "pass"}
      )

    {:ok, signed} = Envelope.sign(evidence, w.signer)

    {:ok, with_definition} =
      Export.build(
        records: [signed.envelope],
        blobs: [{Profile.encode(profile), nil}, {definition_bytes, nil}],
        keys: [key(w)]
      )

    {:ok, without} =
      Export.build(
        records: [signed.envelope],
        blobs: [{Profile.encode(profile), nil}],
        keys: [key(w)]
      )

    assert results(Export.verify(with_definition), :body) == [:ok]
    assert results(Export.verify(without), :body) == [:incomplete]
  end
end
