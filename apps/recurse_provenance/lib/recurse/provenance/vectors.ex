defmodule Recurse.Provenance.Vectors do
  @moduledoc """
  Conformance vectors for the Provenance v2 verifier.

  Each case is a bundle, the reader's trust input, and the report every
  conforming verifier must produce for them. The cases cover each way a
  bundle can be sound, each failure the verifier names, and each check it
  must report as not performed instead of passed.

  Cases are built from fixed keys and fixed timestamps, so the records,
  their references and the expected reports are the same on every run.
  ES256 signatures are the exception: ECDSA signing is randomised, so
  those signature bytes differ between runs while everything derived
  from the signed payload stays the same.

  `write/1` is what `mix recurse.provenance.vectors` runs.
  """

  alias Recurse.Provenance.{
    Body,
    Definitions,
    Envelope,
    Epoch,
    Evidence,
    Export,
    Grammar,
    Key,
    Profile,
    Ref
  }

  alias RecurseVerify.Canonical

  @base "provenance.r5e.io/v2"
  @stream "urn:r5e:stream:vectors:gateway:0:a1b2c3d4e5f6"
  @control "urn:r5e:stream:vectors:control:a1b2c3d4e5f6"
  @actor "urn:r5e:principal:vectors:alice"
  @at ~U[2026-11-10 12:00:00Z]
  @args ~s({"command":"ls -la"})
  @policy "permit (principal, action == Action::\"invoke_tool\", resource);\n"

  @type vector :: %{
          name: String.t(),
          description: String.t(),
          bundle: map(),
          trusted_profiles: [String.t()],
          trusted_publishers: [String.t()],
          trusted_roots: [String.t()] | nil
        }

  @doc """
  Write the vector set under `dir` and return the case names.

    * `cases/<name>/` — `case.json`, `bundle.json`, `expected-report.json`
    * `definitions/` — the definition document of every base kind, at
      `<group>/<version>/<Kind>.json`, as the exact bytes its `schemaRef`
      is the hash of, and `index.json` mapping kind path to `schemaRef`
    * `schemas/` — the schemas for the envelope, the signed wrapper, a
      capture profile, an epoch manifest and an export bundle
  """
  @spec write(Path.t()) :: [String.t()]
  def write(dir) do
    write_definitions(Path.join(dir, "definitions"))
    write_schemas(Path.join(dir, "schemas"))

    for %{name: name} = vector <- all() do
      path = Path.join([dir, "cases", name])
      File.mkdir_p!(path)

      report =
        Export.verify(vector.bundle,
          trusted_profiles: vector.trusted_profiles,
          trusted_publishers: vector.trusted_publishers,
          trusted_roots: vector.trusted_roots,
          trusted_chain: Map.get(vector, :trusted_chain),
          min_start_seq: Map.get(vector, :min_start_seq)
        )

      File.write!(
        Path.join(path, "case.json"),
        pretty(%{
          "name" => name,
          "description" => vector.description,
          "trustedProfiles" => vector.trusted_profiles,
          "trustedPublishers" => vector.trusted_publishers,
          "trustedRoots" => vector.trusted_roots,
          "trustedChain" => Map.get(vector, :trusted_chain),
          "minStartSeq" => Map.get(vector, :min_start_seq)
        })
      )

      File.write!(Path.join(path, "bundle.json"), pretty(vector.bundle))
      File.write!(Path.join(path, "expected-report.json"), pretty(Export.report(report)))
      name
    end
  end

  # Written byte for byte: a definition's reference is the hash of its file.
  defp write_definitions(dir) do
    for %{kind_path: path, bytes: bytes} <- Definitions.documents() do
      file = Path.join(dir, path <> ".json")
      File.mkdir_p!(Path.dirname(file))
      File.write!(file, bytes)
    end

    File.write!(
      Path.join(dir, "index.json"),
      pretty(Map.new(Definitions.documents(), &{&1.kind_path, &1.ref}))
    )
  end

  defp write_schemas(dir) do
    File.mkdir_p!(dir)

    for {name, schema} <- [
          {"evidence-envelope", Definitions.envelope_schema()},
          {"signed-evidence", Definitions.signed_schema()},
          {"capture-profile", Definitions.profile_schema()},
          {"epoch-manifest", Definitions.manifest_schema()},
          {"export", Definitions.export_schema()}
        ] do
      File.write!(Path.join(dir, name <> ".schema.json"), pretty(schema))
    end
  end

  defp pretty(value),
    do: Jason.encode_to_iodata!(Jason.OrderedObject.new(sorted(value)), pretty: true)

  # Keys in a fixed order so regenerated files differ only where content does.
  defp sorted(map) when is_map(map),
    do: map |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(fn {k, v} -> {k, sort_value(v)} end)

  defp sort_value(map) when is_map(map), do: Jason.OrderedObject.new(sorted(map))
  defp sort_value(list) when is_list(list), do: Enum.map(list, &sort_value/1)
  defp sort_value(other), do: other

  @doc "Every case."
  @spec all() :: [vector()]
  def all do
    ed = signer("ed25519")
    w = world(ed)
    trusted = [w.profile_ref]

    [
      vector(
        "valid-single-record-ed25519",
        "One tool call signed with Ed25519, with its profile, content, key and a trusted profile. Every check holds.",
        single(w),
        trusted
      ),
      es256_case(),
      es384_case(),
      vector(
        "high-s-signature",
        "A valid ES256 signature with s replaced by n - s. The same mathematics verifies; the wire form allows only the low half.",
        high_s(),
        nil
      ),
      small_order_key_case(),
      vector(
        "valid-badge",
        "A short-lived credential: the issuer signs, then the subject, whose key the body carries and names. Every check holds.",
        badge(w, & &1),
        trusted
      ),
      vector(
        "badge-subject-is-not-its-key",
        "A badge whose subject is the second signer, but whose carried public key is some other key. The name must be the id of the key beside it.",
        badge(w, fn body ->
          other = signer("es384")
          Map.put(body, "subjectKey", public_key(other))
        end),
        trusted
      ),
      off_curve_key_case(),
      vector(
        "two-records-one-reference",
        "The same record is listed twice. Findings are reported per reference, so the bundle is refused.",
        update_in(single(w), ["records"], &(&1 ++ &1)),
        trusted
      ),
      vector(
        "valid-sealed-stream",
        "Three chained records and the seal that covers them, with the seal's manifest. The whole epoch is checked.",
        sealed(w),
        trusted
      ),
      vector(
        "valid-membership-proof",
        "One record out of five, its seal, and a membership proof. The epoch is incomplete; the membership holds.",
        membership(w, 2),
        trusted
      ),
      vector(
        "untrusted-profile",
        "A sound bundle read with no trust input. Authority is not established and is reported as not checked.",
        single(w),
        []
      ),
      vector(
        "content-withheld",
        "The record's content is left out and named as withheld. The content check is not performed.",
        withheld(w),
        trusted
      ),
      vector(
        "missing-key",
        "No public key is carried. Signatures are not checked.",
        Map.put(single(w), "keys", []),
        trusted
      ),
      vector(
        "tampered-payload",
        "The payload was replaced after signing. Its bytes no longer hash to the record's reference.",
        tampered(w),
        trusted
      ),
      vector(
        "wrong-key-bytes",
        "The key filed under the issuer's key id is a different key.",
        wrong_key(w),
        trusted
      ),
      vector("bad-signature", "The signature bytes were altered.", bad_signature(w), trusted),
      vector(
        "non-canonical-payload",
        "The payload is valid JSON but not Core canonical bytes. It is refused, not normalised.",
        non_canonical(w),
        trusted
      ),
      vector(
        "extra-signature",
        "A tool call carries a second, valid signature by another key. Its definition asks for exactly one.",
        extra_signature(w),
        trusted
      ),
      vector(
        "no-signature",
        "The envelope carries no signature at all. The bundle does not match the wire shape.",
        put_in(single(w), ["records", Access.at(0), "envelope", "signatures"], []),
        trusted
      ),
      vector(
        "duplicate-signer",
        "The envelope carries the issuer's signature twice. No key signs a record twice.",
        duplicate_signer(w),
        trusted
      ),
      vector(
        "fork",
        "Two different records claim the same position of one stream.",
        fork(w),
        trusted
      ),
      vector(
        "broken-chain",
        "The second record names a predecessor that is not the first record.",
        broken_chain(w),
        trusted
      ),
      vector(
        "unauthorized-seal",
        "The seal is signed by a key its profile does not allow to seal.",
        unauthorized_seal(w),
        trusted
      ),
      vector(
        "issuer-outside-profile",
        "The record's actor is outside every prefix its profile grants the issuer.",
        issuer_outside(w),
        trusted
      ),
      vector(
        "body-fails-definition",
        "The body carries a field its definition does not allow.",
        body_invalid(w),
        trusted
      ),
      vector(
        "definition-for-another-kind",
        "A tool call cites the model call definition.",
        other_definition(w),
        trusted
      ),
      vector(
        "policy-required-missing",
        "The profile requires a policy evaluation on tool calls and the record has none.",
        policy_missing(ed),
        nil
      ),
      vector(
        "content-hash-mismatch",
        "A carried blob's bytes do not hash to its reference.",
        blob_mismatch(w),
        trusted
      ),
      vector(
        "proof-wrong-index",
        "A membership proof is presented at the wrong index.",
        put_in(membership(w, 2), ["proofs", Access.at(0), "index"], 3),
        trusted
      ),
      vector(
        "seal-root-wrong",
        "A seal whose root does not match its manifest.",
        seal_root_wrong(w),
        trusted
      ),
      vector(
        "evidence-fields-invalid",
        "A correctly signed record whose common fields break the envelope schema: position zero.",
        bundle(w, [record(w, 0, nil)]),
        trusted
      ),
      vector(
        "proof-under-unlisted-unauthorized-seal",
        "A membership proof rests on a seal the bundle does not list, signed by a key its profile does not allow to seal. The seal is checked anyway.",
        unlisted_unauthorized_seal(w),
        trusted
      ),
      vector(
        "reference-with-trailing-newline",
        "A correctly signed record whose stream ends in a newline. A pattern's end means the end of the string.",
        bundle(w, [record(w, 1, nil, stream: @stream <> "\n")]),
        trusted
      ),
      extension_case(ed, true),
      extension_case(ed, false)
    ]
    |> Kernel.++(handover_cases(ed))
    |> Kernel.++(closure_cases(w, trusted))
    |> Kernel.++([
      labelled_case(ed),
      astral_name_case(w, trusted),
      overlapping_seals_case(w, trusted)
    ])
    |> Kernel.++(authority_cases())
    |> Kernel.++(retention_cases())
    |> Enum.map(&default_trust/1)
    |> Kernel.++(publication_cases(w, trusted))
    |> Enum.map(&with_publication/1)
  end

  defp vector(name, description, bundle, trusted),
    do: %{
      name: name,
      description: description,
      bundle: bundle,
      trusted_profiles: trusted,
      trusted_publishers: nil,
      trusted_roots: nil
    }

  # Unless a case says otherwise, its bundle also carries the publisher's
  # statement of which definition belongs to each base kind, and the
  # reader trusts that publisher.
  defp with_publication(%{trusted_publishers: nil} = vector) do
    %{record: record, profile: profile, signer: publisher} = publication()

    bundle =
      vector.bundle
      |> Map.update!("records", &(&1 ++ [%{"ref" => record.ref, "envelope" => record.envelope}]))
      |> Map.update!("blobs", &(&1 ++ [blob(Profile.encode(profile))]))
      |> Map.update!("keys", &(&1 ++ [wire_key(publisher)]))

    %{
      vector
      | bundle: bundle,
        trusted_profiles: vector.trusted_profiles ++ trusted_too(vector, Profile.ref(profile)),
        trusted_publishers: [publisher.key_id]
    }
  end

  defp with_publication(vector), do: vector

  # A case that trusts no profile keeps trusting none.
  defp trusted_too(%{trusted_profiles: []}, _ref), do: []
  defp trusted_too(_vector, ref), do: [ref]

  defp blob(bytes), do: %{"ref" => Ref.bytes(bytes), "base64" => Base.encode64(bytes)}

  defp wire_key(signer),
    do: %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }

  # The publisher: its own key, its own profile and stream, and one
  # record naming the definition document of every base kind.
  defp publication(definitions \\ nil) do
    seed = :crypto.hash(:sha256, "r5e provenance vectors publisher")
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    publisher = Key.local_signer("ed25519", public, private)

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:publisher:",
            actor_prefixes: ["urn:r5e:publisher:"],
            issuer_keys: [publisher.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "conformance vectors",
        deployment_policy_ref: Ref.bytes("r5e.deployment/vectors-publisher"),
        policy_required_kinds: []
      )

    path = @base <> "/DefinitionPublished"
    {:ok, %{ref: schema_ref}} = Definitions.fetch(path)
    definitions = definitions || Map.new(Definitions.documents(), &{&1.kind_path, &1.ref})

    evidence =
      Evidence.new(
        kind_path: path,
        schema_ref: schema_ref,
        profile_ref: Profile.ref(profile),
        issuer: publisher.key_id,
        actor: "urn:r5e:publisher:vectors",
        stream: "urn:r5e:stream:publisher:api:a1b2c3d4e5f6",
        seq: 1,
        previous: nil,
        captured_at: @at,
        body: Body.definition_published(definitions: definitions, package: "r5e.provenance")
      )

    {:ok, signed} = Envelope.sign(evidence, publisher)
    %{record: signed, profile: profile, signer: publisher}
  end

  # Cases built under their own profile trust that profile.
  defp default_trust(%{trusted_profiles: nil, bundle: bundle} = vector) do
    refs =
      for %{"envelope" => envelope} <- bundle["records"],
          {:ok, %{evidence: evidence}} <- [Envelope.open(envelope)],
          uniq: true,
          do: evidence["profileRef"]

    %{vector | trusted_profiles: refs}
  end

  defp default_trust(vector), do: vector

  # -- building blocks ---------------------------------------------------

  # A key derived from a fixed seed, so every run uses the same key.
  defp signer("ed25519") do
    seed = :crypto.hash(:sha256, "r5e provenance vectors ed25519")
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    Key.local_signer("ed25519", public, private)
  end

  defp signer("es384") do
    <<private::binary-48, _::binary>> =
      :crypto.hash(:sha512, "r5e provenance vectors es384")

    {public, ^private} = :crypto.generate_key(:ecdh, :secp384r1, private)
    Key.local_signer("es384", public, private)
  end

  defp signer("es256") do
    private = :crypto.hash(:sha256, "r5e provenance vectors es256")
    {public, ^private} = :crypto.generate_key(:ecdh, :secp256r1, private)
    Key.local_signer("es256", public, private)
  end

  defp profile(signer, overrides \\ []) do
    {:ok, profile} =
      Profile.new(
        Keyword.merge(
          [
            bindings: [
              %{
                stream_prefix: "urn:r5e:stream:vectors:",
                actor_prefixes: ["urn:r5e:principal:vectors:", "urn:r5e:gateway:vectors"],
                issuer_keys: [signer.key_id],
                sealer_keys: [signer.key_id]
              }
            ],
            failure_domain: "conformance vectors",
            deployment_policy_ref: Ref.bytes("r5e.deployment/vectors"),
            policy_required_kinds: []
          ],
          overrides
        )
      )

    profile
  end

  defp world(signer) do
    profile = profile(signer)
    %{signer: signer, profile: profile, profile_ref: Profile.ref(profile)}
  end

  defp tool_body(overrides \\ %{}) do
    Body.tool_call(
      tool: "Bash",
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
    |> Map.merge(overrides)
  end

  defp record(w, seq, previous, opts \\ []) do
    path = Keyword.get(opts, :kind_path, @base <> "/ToolCall")
    {:ok, %{ref: base_ref}} = Definitions.fetch(Keyword.get(opts, :definition_of, path))
    schema_ref = Keyword.get(opts, :schema_ref, base_ref)

    evidence =
      Evidence.new(
        kind_path: path,
        schema_ref: Keyword.get(opts, :schema_ref, schema_ref),
        profile_ref: Keyword.get(opts, :profile_ref, w.profile_ref),
        issuer: w.signer.key_id,
        actor: Keyword.get(opts, :actor, @actor),
        stream: Keyword.get(opts, :stream, @stream),
        seq: seq,
        previous: previous,
        captured_at: Keyword.get(opts, :at, DateTime.add(@at, seq, :second)),
        session: "urn:r5e:session:vectors:one",
        body: Keyword.get(opts, :body, tool_body())
      )

    {:ok, signed} = Envelope.sign(evidence, w.signer)
    Map.put(signed, :evidence, evidence)
  end

  defp chain(w, count) do
    {records, _} =
      Enum.reduce(1..count, {[], nil}, fn seq, {acc, previous} ->
        r = record(w, seq, previous)
        {acc ++ [r], r.ref}
      end)

    records
  end

  defp seal(w, records, opts \\ []) do
    {body, manifest} = Epoch.seal_body(@stream, 1, Enum.map(records, & &1.ref), nil)
    body = Map.merge(body, Keyword.get(opts, :body, %{}))

    signed =
      record(w, 1, nil,
        kind_path: @base <> "/EpochSeal",
        stream: Keyword.get(opts, :on, @control),
        actor: "urn:r5e:gateway:vectors",
        body: body,
        profile_ref: Keyword.get(opts, :profile_ref, w.profile_ref),
        at: Keyword.get(opts, :at, DateTime.add(@at, 1, :second))
      )

    {signed, manifest}
  end

  defp key(signer),
    do: %{key_id: signer.key_id, algorithm: signer.algorithm, public_key: signer.public_key}

  defp bundle(w, records, fields \\ []) do
    {:ok, bundle} =
      Export.build(
        Keyword.merge(
          [
            query: %{"session" => "urn:r5e:session:vectors:one"},
            records: Enum.map(records, & &1.envelope),
            blobs: [
              {Profile.encode(w.profile), "application/json"},
              {@args, "application/json"},
              {@policy, "text/plain"}
            ],
            keys: [key(w.signer)]
          ],
          fields
        )
      )

    bundle
  end

  # -- cases -------------------------------------------------------------

  defp single(w), do: bundle(w, [record(w, 1, nil)])

  defp es256_case do
    w = world(signer("es256"))

    vector(
      "valid-single-record-es256",
      "One tool call signed with ES256 (raw r||s, low S). Every check holds.",
      single(w),
      [w.profile_ref]
    )
  end

  defp sealed(w) do
    records = chain(w, 3)
    {seal, manifest} = seal(w, records)

    bundle(w, records ++ [seal],
      blobs: [{Profile.encode(w.profile), nil}, {@args, nil}, {@policy, nil}, {manifest, nil}],
      seals: [seal.ref]
    )
  end

  defp membership(w, index) do
    records = chain(w, 5)
    {seal, _manifest} = seal(w, records)
    refs = Enum.map(records, & &1.ref)
    {:ok, siblings} = Epoch.proof(refs, index)
    chosen = Enum.at(records, index)

    bundle(w, [chosen, seal],
      seals: [seal.ref],
      proofs: [%{record: chosen.ref, seal: seal.ref, index: index, siblings: siblings}],
      omissions: for(ref <- List.delete_at(refs, index), do: %{ref: ref, reason: "not-selected"})
    )
  end

  defp withheld(w) do
    bundle(w, [record(w, 1, nil)],
      blobs: [{Profile.encode(w.profile), nil}, {@policy, nil}],
      omissions: [%{ref: Ref.bytes(@args), reason: "withheld"}]
    )
  end

  defp tampered(w) do
    b = single(w)
    other = record(w, 1, nil, body: tool_body(%{"tool" => "Write"}))
    put_in(b, ["records", Access.at(0), "envelope", "payload"], other.envelope["payload"])
  end

  defp wrong_key(w) do
    seed = :crypto.hash(:sha256, "r5e provenance vectors another key")
    {public, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    put_in(single(w), ["keys", Access.at(0), "bytes"], Base.encode64(public))
  end

  defp bad_signature(w) do
    update_in(
      single(w),
      ["records", Access.at(0), "envelope", "signatures", Access.at(0), "sig"],
      fn sig ->
        <<first, rest::binary>> = Base.decode64!(sig)
        Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
      end
    )
  end

  defp non_canonical(w) do
    update_in(single(w), ["records", Access.at(0), "envelope", "payload"], fn payload ->
      payload |> Base.decode64!() |> String.replace(~s("seq":1), ~s("seq": 1)) |> Base.encode64()
    end)
  end

  defp duplicate_signer(w),
    do: update_in(single(w), ["records", Access.at(0), "envelope", "signatures"], &(&1 ++ &1))

  # A second, valid signature by another key on a kind that asks for one.
  defp extra_signature(w) do
    other = signer("es256")
    {:ok, signed} = Envelope.sign(record(w, 1, nil).evidence, [w.signer, other])
    bundle(w, [signed], keys: [key(w.signer), key(other)])
  end

  @p256_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  defp high_s do
    update_in(
      single(world(signer("es256"))),
      ["records", Access.at(0), "envelope", "signatures", Access.at(0), "sig"],
      fn sig ->
        <<r::binary-32, s::unsigned-256>> = Base.decode64!(sig)
        Base.encode64(<<r::binary, @p256_n - s::unsigned-256>>)
      end
    )
  end

  # The identity point: a well-formed 32 bytes that is not a usable
  # Ed25519 key. Under a verifier that skips the admissibility check, the
  # signature below (R the identity, S zero) verifies for any message.
  defp small_order_key_case do
    public = <<1, 0::248>>
    tag = "ed25519"
    digest = :crypto.hash(:sha256, <<byte_size(tag)>> <> tag <> public)
    key_id = "key:ed25519:sha256:" <> Base.encode16(digest, case: :lower)

    forger = %{
      algorithm: tag,
      key_id: key_id,
      public_key: public,
      sign: fn _message -> {:ok, <<1, 0::248, 0::256>>} end
    }

    w = world(forger)

    vector(
      "ed25519-inadmissible-public-key",
      "The issuer's key is the identity point, filed under the key id its bytes hash to, with a signature that a lax Ed25519 check accepts for any message. The key is not admissible, so it has no key id.",
      single(w),
      [w.profile_ref]
    )
  end

  # Thirty-two bytes that pass the range and small-order checks but are
  # the y of no point on the curve. Some libraries refuse them when
  # loading the key and some only fail to verify.
  defp off_curve_key_case do
    public = off_curve_bytes(0)
    tag = "ed25519"
    digest = :crypto.hash(:sha256, <<byte_size(tag)>> <> tag <> public)

    forger = %{
      algorithm: tag,
      key_id: "key:ed25519:sha256:" <> Base.encode16(digest, case: :lower),
      public_key: public,
      sign: fn _message -> {:ok, <<1, 0::248, 0::256>>} end
    }

    w = world(forger)

    vector(
      "ed25519-key-not-on-curve",
      "The issuer's key bytes are in range and not of small order, but no point on the curve has that y. The key is not admissible, so it has no key id.",
      single(w),
      [w.profile_ref]
    )
  end

  defp off_curve_bytes(counter) do
    <<head::binary-31, last>> =
      :crypto.hash(:sha256, "r5e provenance vectors off curve #{counter}")

    candidate = head <> <<Bitwise.band(last, 0x7F)>>

    case Key.id("ed25519", candidate) do
      {:error, _} -> candidate
      {:ok, _} -> off_curve_bytes(counter + 1)
    end
  end

  defp public_key(signer),
    do: %{"algorithm" => signer.algorithm, "bytes" => Base.encode64(signer.public_key)}

  defp badge(w, change) do
    subject = signer("es256")

    body =
      change.(%{
        "subject" => subject.key_id,
        "subjectKey" => public_key(subject),
        "holder" => "workload",
        "kinds" => [@base <> "/ToolCall"],
        "notBefore" => "2026-11-10T00:00:00Z",
        "notAfter" => "2026-11-10T04:00:00Z",
        "parent" => Ref.evidence("the endorsement the issuer acts under")
      })

    unsigned =
      record(w, 1, nil,
        kind_path: @base <> "/Badge",
        stream: @control,
        actor: "urn:r5e:gateway:vectors",
        body: body
      )

    {:ok, signed} = Envelope.sign(unsigned.evidence, [w.signer, subject])
    bundle(w, [signed], keys: [key(w.signer), key(subject)])
  end

  # -- authority from trusted roots --------------------------------------

  defp named(label) do
    seed = :crypto.hash(:sha256, "r5e provenance vectors " <> label)
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    Key.local_signer("ed25519", public, private)
  end

  # Keeping content, holding it and disposing of it. A gateway records a
  # tool call under a profile that says how long its content must be
  # kept; holds, releases and disposals go on the deployment's retention
  # stream; the tool call's arguments are not in the bundle, and what the
  # reader is told about that depends on what the retention stream shows.
  defp retention_cases do
    root = named("retention root")
    gateway = named("retention gateway")
    counsel = named("retention counsel")
    stranger = named("retention stranger")
    people = [root, gateway, counsel, stranger]
    retention = "urn:r5e:stream:vectors:retention"
    base = @base <> "/"

    kinds =
      Enum.map(
        ~w[ToolCall RetentionHold RetentionHoldRelease PayloadDisposition EpochSeal],
        &(base <> &1)
      )

    session = "urn:r5e:session:vectors:one"
    args = Ref.bytes(@args)

    profile_with = fn retention_rule ->
      profile(root,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:",
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: Enum.map(people, & &1.key_id),
            sealer_keys: [gateway.key_id]
          }
        ],
        retention: retention_rule
      )
    end

    keeps = profile_with.({:keep_for_seconds, 3600})
    forever = profile_with.(nil)

    as = fn signer, profile ->
      %{signer: signer, profile: profile, profile_ref: Profile.ref(profile)}
    end

    at = fn seconds -> DateTime.add(@at, seconds, :second) end

    grant = fn to, label, granted ->
      record(as.(root, keeps), 1, nil,
        kind_path: base <> "Endorsement",
        stream: "urn:r5e:stream:vectors:authority:" <> label,
        actor: "urn:r5e:root-ceremony",
        at: at.(-600),
        body: %{
          "subject" => to.key_id,
          "kinds" => granted,
          "mayEndorse" => false,
          "notBefore" => "2026-11-10T00:00:00Z",
          "notAfter" => "2026-11-11T00:00:00Z"
        }
      )
    end

    to_gateway = grant.(gateway, "gateway", kinds)

    to_counsel =
      grant.(counsel, "counsel", [base <> "RetentionHold", base <> "RetentionHoldRelease"])

    call = fn profile ->
      record(as.(gateway, profile), 1, nil, actor: "urn:r5e:gateway:vectors", at: at.(0))
    end

    on_retention = fn signer, seq, previous, kind, seconds, body, opts ->
      record(as.(signer, keeps), seq, previous,
        kind_path: base <> kind,
        stream: Keyword.get(opts, :stream, retention),
        actor: "urn:r5e:gateway:vectors",
        at: at.(seconds),
        body: body
      )
    end

    hold = fn signer, seq, previous ->
      on_retention.(
        signer,
        seq,
        previous,
        "RetentionHold",
        1800,
        %{"scope" => session, "reason" => "the claim against the depot"},
        []
      )
    end

    dispose = fn seq, previous, seconds, body, opts ->
      on_retention.(
        gateway,
        seq,
        previous,
        "PayloadDisposition",
        seconds,
        Map.merge(
          %{"action" => "expired", "reason" => "kept for the period the profile gives"},
          body
        ),
        opts
      )
    end

    release = fn seq, previous, held, second ->
      unsigned =
        on_retention.(
          gateway,
          seq,
          previous,
          "RetentionHoldRelease",
          3000,
          %{
            "hold" => held.ref,
            "releasedBy" => second.key_id,
            "reason" => "the claim was settled"
          },
          []
        )

      {:ok, signed} = Envelope.sign(unsigned.evidence, [gateway, second])
      Map.put(signed, :evidence, unsigned.evidence)
    end

    # A seal by the gateway over positions of the retention stream.
    sealed = fn records, seconds ->
      first = hd(records).evidence["seq"]

      seal(as.(gateway, keeps), records,
        at: at.(seconds),
        body: %{
          "stream" => hd(records).evidence["stream"],
          "firstSeq" => first,
          "lastSeq" => first + length(records) - 1
        }
      )
    end

    make = fn name, description, tool_call, others, seal_of, opts ->
      {seals, manifests} =
        case seal_of do
          nil ->
            {[], []}

          {records, seconds} ->
            (fn {seal, manifest} -> {[seal], [manifest]} end).(sealed.(records, seconds))
        end

      profiles = Enum.uniq([keeps, forever])
      more = Keyword.get(opts, :more_profiles, [])

      built =
        bundle(as.(gateway, keeps), [tool_call] ++ others ++ seals,
          keys: Enum.map(Keyword.get(opts, :keys, people), &key/1),
          blobs:
            Enum.map(Keyword.get(opts, :profiles, profiles) ++ more, &{Profile.encode(&1), nil}) ++
              [{@policy, nil}] ++ Enum.map(manifests, &{&1, nil}),
          seals: Enum.map(seals, & &1.ref),
          omissions: [%{ref: args, reason: Keyword.get(opts, :reason, "expired")}]
        )

      Map.merge(
        %{
          vector(name, description, built, Enum.map(profiles ++ more, &Profile.ref/1))
          | trusted_publishers: nil,
            trusted_roots: [root.key_id]
        },
        Keyword.get(opts, :trust, %{})
      )
    end

    r = call.(keeps)

    # A second call in the same session, on another stream, made under
    # the profile that never allows disposal.
    under_forever =
      record(as.(gateway, forever), 1, nil,
        actor: "urn:r5e:gateway:vectors",
        stream: "urn:r5e:stream:vectors:endpoint:w1:session-1",
        at: at.(5)
      )

    lawful = dispose.(1, nil, 7200, %{"scope" => session}, [])
    h = hold.(gateway, 1, nil)
    under_hold = dispose.(2, h.ref, 7200, %{"scope" => session}, [])
    freed = release.(2, h.ref, h, counsel)
    after_release = dispose.(3, freed.ref, 7200, %{"scope" => session}, [])
    by_stranger = release.(2, h.ref, h, stranger)
    after_bad_release = dispose.(3, by_stranger.ref, 7200, %{"scope" => session}, [])
    too_soon = dispose.(1, nil, 60, %{"scope" => session}, [])
    counsel_hold = hold.(counsel, 1, nil)
    over_counsel = dispose.(2, counsel_hold.ref, 7200, %{"scope" => session}, [])
    earlier = dispose.(1, nil, -60, %{"targets" => [args]}, [])

    elsewhere =
      dispose.(1, nil, 7200, %{"scope" => session}, stream: "urn:r5e:stream:shadow:retention")

    grants = [to_gateway, to_counsel]

    # A hold that says when it runs out.
    hold_until = fn seconds ->
      on_retention.(
        gateway,
        1,
        nil,
        "RetentionHold",
        1800,
        %{
          "scope" => session,
          "reason" => "kept while the audit runs",
          "until" => DateTime.to_iso8601(at.(seconds))
        },
        []
      )
    end

    ran_out = hold_until.(7200)
    at_the_moment = dispose.(2, ran_out.ref, 7200, %{"scope" => session}, [])
    still_running = hold_until.(7201)
    a_second_early = dispose.(2, still_running.ref, 7200, %{"scope" => session}, [])

    # An unlawful disposal, and a second one made once the period had run.
    again = dispose.(2, too_soon.ref, 7200, %{"scope" => session}, [])

    # A hold that names the content itself, and a "release" that only the
    # gateway signed.
    by_name =
      on_retention.(
        gateway,
        1,
        nil,
        "RetentionHold",
        1800,
        %{"targets" => [args], "reason" => "the claim against the depot"},
        []
      )

    alone =
      (fn ->
         unsigned =
           on_retention.(
             gateway,
             2,
             by_name.ref,
             "RetentionHoldRelease",
             3000,
             %{
               "hold" => by_name.ref,
               "releasedBy" => counsel.key_id,
               "reason" => "the claim was settled"
             },
             []
           )

         {:ok, signed} = Envelope.sign(unsigned.evidence, [gateway])
         Map.put(signed, :evidence, unsigned.evidence)
       end).()

    after_alone = dispose.(3, alone.ref, 7200, %{"scope" => session}, [])

    # A call whose body refers to two pieces of content, neither carried.
    notes = Ref.bytes("the operator's notes on the call")

    two =
      record(as.(gateway, keeps), 1, nil,
        actor: "urn:r5e:gateway:vectors",
        at: at.(0),
        body: Map.put(tool_body(), "details", %{"notes" => notes})
      )

    # The start of the deployment these records belong to, for a reader
    # who pins its chain.
    bootstrap = named("retention bootstrap")
    %{record: published} = publication()
    {:ok, opened_publication} = Envelope.open(published.envelope)

    start_profile =
      profile(bootstrap,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:start",
            actor_prefixes: ["urn:r5e:node:"],
            issuer_keys: [bootstrap.key_id],
            sealer_keys: []
          }
        ]
      )

    starting = as.(bootstrap, start_profile)

    chain_started =
      record(starting, 1, nil,
        kind_path: base <> "ChainStarted",
        stream: "urn:r5e:stream:vectors:start",
        actor: "urn:r5e:node:vectors",
        at: at.(-1200),
        body: %{
          "deployment" => "vectors",
          "bootstrap" => bootstrap.key_id,
          "bootstrapKey" => public_key(bootstrap),
          "publication" => published.ref,
          "publisher" => opened_publication.evidence["issuer"],
          "definitions" => opened_publication.evidence["body"]["definitions"]
        }
      )

    claimed =
      (fn ->
         unsigned =
           record(starting, 2, chain_started.ref,
             kind_path: base <> "Deployment",
             stream: "urn:r5e:stream:vectors:start",
             actor: "urn:r5e:node:vectors",
             at: at.(-900),
             body: %{
               "accepts" => chain_started.ref,
               "bootstrap" => bootstrap.key_id,
               "claimedBy" => root.key_id,
               "roots" => [%{"key" => root.key_id, "publicKey" => public_key(root)}],
               "threshold" => 1
             }
           )

         {:ok, signed} = Envelope.sign(unsigned.evidence, [bootstrap, root])
         Map.put(signed, :evidence, unsigned.evidence)
       end).()

    [
      make.(
        "content-disposed-of-at-the-moment-its-hold-ran-out",
        "A hold on the session said it ran until a stated time, and the disposal is dated at exactly that time. A hold stands up to its time and not at it, so the hold had ended and the disposal is in order.",
        r,
        grants ++ [ran_out, at_the_moment],
        {[ran_out, at_the_moment], 7300},
        []
      ),
      make.(
        "content-disposed-of-a-second-before-its-hold-ran-out",
        "The same, with the hold running one second longer. The disposal came while the hold still stood, and it fails.",
        r,
        grants ++ [still_running, a_second_early],
        {[still_running, a_second_early], 7300},
        []
      ),
      make.(
        "content-disposal-repeated-after-an-unlawful-one",
        "The content was disposed of a minute after the call, long before the hour its profile says it is kept. A second disposal was recorded later, once the hour had run. The first one is the one that happened: recording another afterwards does not make it lawful.",
        r,
        grants ++ [too_soon, again],
        {[too_soon, again], 7300},
        []
      ),
      make.(
        "content-held-by-name-and-released-by-the-gateway-alone",
        "A hold that names the content itself, not a session. The release after it carries only the gateway's signature where the kind requires two, so it is not a release, the hold still stood, and the disposal fails.",
        r,
        grants ++ [by_name, alone, after_alone],
        {[by_name, alone, after_alone], 7300},
        []
      ),
      make.(
        "content-disposed-of-by-record-read-with-trusted-profiles",
        "A lawful, sealed disposal read by someone who names profiles they trust and no root. The same rules apply: the reader is told the content was disposed of under that record.",
        r,
        grants ++ [lawful],
        {[lawful], 7300},
        trust: %{trusted_roots: nil}
      ),
      make.(
        "content-disposed-of-by-record-under-a-pinned-chain",
        "The same disposal, with the two records that began this deployment, read by someone who pins the deployment's chain by name. The gateway's standing to dispose comes from the root the claim declared.",
        r,
        [chain_started, claimed] ++ grants ++ [lawful],
        {[lawful], 7300},
        keys: people ++ [bootstrap],
        more_profiles: [start_profile],
        trust: %{trusted_roots: nil, trusted_chain: claimed.ref}
      ),
      make.(
        "content-disposed-of-in-a-session-recorded-under-two-profiles",
        "Two calls in one session, one under a profile that keeps content for an hour and one under a profile that never allows disposal. The session's content was disposed of after the hour. Each record is judged by the profile it was made under: for the first the reader is told it was disposed of by record, and for the second the disposal fails. A gateway that takes records from elsewhere therefore refuses any whose profile keeps content for a different time than its own.",
        r,
        grants ++ [under_forever, lawful],
        {[lawful], 7300},
        []
      ),
      make.(
        "content-disposed-of-with-two-references-missing",
        "One call refers to two pieces of content and neither is in the bundle. The disposal covers the session, so the reader is told twice, once for each piece.",
        two,
        grants ++ [lawful],
        {[lawful], 7300},
        []
      ),
      make.(
        "content-disposed-of-by-record",
        "A tool call's arguments are not in the bundle. The deployment's retention stream shows why: after the period the call's own profile says its content must be kept, the gateway recorded a disposal of that session's content, no hold came before it, and a seal fixes the disposal in time. The reader is told who disposed of it, when and on what authority. It is still reported as not performed and never as held: the bytes are not there to check.",
        r,
        grants ++ [lawful],
        {[lawful], 7300},
        []
      ),
      make.(
        "content-disposed-of-while-under-a-hold",
        "A hold on the session was recorded, and then a disposal of the same session's content. That is destruction of content that was to be kept, and it fails.",
        r,
        grants ++ [h, under_hold],
        {[h, under_hold], 7300},
        []
      ),
      make.(
        "content-disposed-of-after-its-hold-was-released",
        "A hold, then its release signed by the gateway and by counsel, whose own key has standing to release, then a disposal. The hold no longer stood.",
        r,
        grants ++ [h, freed, after_release],
        {[h, freed, after_release], 7300},
        []
      ),
      make.(
        "content-disposed-of-after-a-release-nobody-had-standing-to-give",
        "The release is signed by the gateway and by a key no root vouches for. Every signer of a record must have authority for it, so the release counts for nothing, the hold still stood, and the disposal after it fails. Whoever holds the gateway's key alone cannot release a hold.",
        r,
        grants ++ [h, by_stranger, after_bad_release],
        {[h, by_stranger, after_bad_release], 7300},
        []
      ),
      make.(
        "content-disposed-of-before-its-keep-until-date",
        "The call's profile says content is kept for an hour. The disposal is dated a minute after the call.",
        r,
        grants ++ [too_soon],
        {[too_soon], 7300},
        []
      ),
      make.(
        "content-disposed-of-when-nothing-allowed-disposal",
        "The call was made under a profile that says nothing about retention, which means its content is never disposed of. A disposal was recorded anyway.",
        call.(forever),
        grants ++ [lawful],
        {[lawful], 7300},
        []
      ),
      make.(
        "content-disposal-dated-after-its-own-seal",
        "The disposal is dated later than the seal that covers it. A recorder cannot have disposed of something at a time after the seal over that act was made; a date pushed forward is how a keep-for period would be stepped past.",
        r,
        grants ++ [lawful],
        {[lawful], 3700},
        []
      ),
      make.(
        "content-disposal-not-sealed",
        "A disposal that no seal covers. Nothing fixes when it was made, so it is not yet a disposal a reader can rely on.",
        r,
        grants ++ [lawful],
        nil,
        []
      ),
      make.(
        "content-disposal-with-a-hold-whose-authority-was-left-out",
        "Counsel placed a hold and the gateway then disposed of the content. The bundle carries both records and leaves out the grant that gives counsel standing, so the hold cannot be counted. That must not make the disposal look clean: the reader is told the holds before it were not all shown.",
        r,
        [to_gateway, counsel_hold, over_counsel],
        {[counsel_hold, over_counsel], 7300},
        []
      ),
      make.(
        "content-disposal-without-the-retention-stream-before-it",
        "The disposal sits at the second position of the retention stream and the first position is not in the bundle. Whatever was there, a hold perhaps, is not shown.",
        r,
        grants ++ [under_hold],
        {[under_hold], 7300},
        []
      ),
      make.(
        "content-disposal-without-the-records-profile",
        "The disposal is in order, but the profile the tool call was made under is not in the bundle, so how long its content had to be kept cannot be seen.",
        r,
        grants ++ [lawful],
        {[lawful], 7300},
        profiles: []
      ),
      make.(
        "content-missing-while-under-a-hold",
        "A hold stands on the session, no disposal was recorded, and the content is not in the bundle because the exporter says it was unavailable. The reader is told the missing content was under a hold.",
        r,
        grants ++ [h],
        nil,
        reason: "unavailable"
      ),
      make.(
        "content-disposal-made-before-the-record-existed",
        "A disposal naming these same bytes was recorded before this tool call was made. The same content often recurs, and a disposal cannot dispose of what did not yet exist, so it says nothing about this record: the content is simply reported as left out.",
        r,
        grants ++ [earlier],
        {[earlier], 7300},
        []
      ),
      make.(
        "content-disposal-on-some-other-retention-stream",
        "A disposal of the session's content recorded on a retention stream that is not this deployment's. Holds and disposals count only on the retention stream of the deployment the record itself belongs to, so an exporter cannot swap in a clean one.",
        r,
        grants ++ [elsewhere],
        {[elsewhere], 7300},
        []
      )
    ]
  end

  # A small company: the root vouches for the gateway and for a sealer;
  # the gateway gives a worker a badge; the worker makes one tool call.
  defp authority_cases do
    root = named("authority root")
    gateway = named("authority gateway")
    worker = named("authority worker")
    sealer = named("authority sealer")
    stranger = named("authority stranger")
    gateway2 = named("authority gateway two")
    root2 = named("authority root two")
    helper = named("authority helper")
    key_a = named("authority a")
    key_b = named("authority b")
    thief = named("authority thief")

    people = [
      root,
      gateway,
      worker,
      sealer,
      stranger,
      gateway2,
      root2,
      helper,
      key_a,
      key_b,
      thief
    ]

    profile =
      profile(root,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:",
            actor_prefixes: ["urn:r5e:principal:vectors:", "urn:r5e:gateway:vectors"],
            issuer_keys: Enum.map(people, & &1.key_id),
            sealer_keys: [sealer.key_id]
          }
        ]
      )

    as = fn signer -> %{signer: signer, profile: profile, profile_ref: Profile.ref(profile)} end
    at = fn seconds -> DateTime.add(@at, seconds, :second) end
    on = fn name -> "urn:r5e:stream:vectors:authority:" <> name end
    window = %{"notBefore" => "2026-11-10T00:00:00Z", "notAfter" => "2026-11-11T00:00:00Z"}
    tool_kind = @base <> "/ToolCall"
    seal_kind = @base <> "/EpochSeal"

    grant = fn signer, name, seconds, kind, body ->
      record(as.(signer), 1, nil,
        kind_path: @base <> "/" <> kind,
        stream: on.(name),
        actor: "urn:r5e:gateway:vectors",
        at: at.(seconds),
        body: Map.merge(window, body)
      )
    end

    e_gateway =
      grant.(root, "gateway", 0, "Endorsement", %{
        "subject" => gateway.key_id,
        "kinds" => [tool_kind],
        "mayEndorse" => true
      })

    e_sealer =
      grant.(root, "sealer", 0, "Endorsement", %{
        "subject" => sealer.key_id,
        "kinds" => [seal_kind],
        "mayEndorse" => false
      })

    badge_unsigned =
      grant.(gateway, "worker", 10, "Badge", %{
        "subject" => worker.key_id,
        "subjectKey" => public_key(worker),
        "holder" => "workload",
        "kinds" => [tool_kind],
        "parent" => e_gateway.ref
      })

    {:ok, badge} = Envelope.sign(badge_unsigned.evidence, [gateway, worker])
    call = record(as.(worker), 1, nil, at: at.(20))

    revoke = fn seconds ->
      record(as.(gateway), 1, nil,
        kind_path: @base <> "/Revocation",
        stream: on.("revocations"),
        actor: "urn:r5e:gateway:vectors",
        at: at.(seconds),
        body: %{"target" => badge.ref, "reason" => "the worker's host was rebuilt"}
      )
    end

    {seal, manifest} = seal(as.(sealer), [call], at: at.(25))

    build = fn records, extra ->
      bundle(
        as.(root),
        records,
        Keyword.merge([keys: Enum.map(people, &key/1)], extra)
      )
    end

    case_of = fn name, description, bundle, roots ->
      %{
        vector(name, description, bundle, [Profile.ref(profile)])
        | trusted_publishers: [],
          trusted_roots: roots
      }
    end

    company = [e_gateway, e_sealer, badge, call]

    sealed_blobs = [
      blobs: [{Profile.encode(profile), nil}, {@args, nil}, {@policy, nil}, {manifest, nil}],
      seals: [seal.ref]
    ]

    endorse = fn signer, label, seconds, subject, extra ->
      grant.(
        signer,
        label,
        seconds,
        "Endorsement",
        Map.merge(
          %{"subject" => subject.key_id, "kinds" => [tool_kind], "mayEndorse" => true},
          extra
        )
      )
    end

    badge_for = fn issuer, label, seconds, subject, parent ->
      unsigned =
        grant.(issuer, label, seconds, "Badge", %{
          "subject" => subject.key_id,
          "subjectKey" => public_key(subject),
          "holder" => "workload",
          "kinds" => [tool_kind],
          "parent" => parent.ref
        })

      {:ok, signed} = Envelope.sign(unsigned.evidence, [issuer, subject])
      signed
    end

    call_by = fn signer, label, seconds ->
      record(as.(signer), 1, nil, stream: on.(label), at: at.(seconds))
    end

    hand_over = fn from, to, label, seconds ->
      unsigned =
        record(as.(from), 1, nil,
          kind_path: @base <> "/Succession",
          stream: on.(label),
          actor: "urn:r5e:gateway:vectors",
          at: at.(seconds),
          body: %{
            "predecessor" => from.key_id,
            "successor" => to.key_id,
            "successorKey" => public_key(to)
          }
        )

      {:ok, signed} = Envelope.sign(unsigned.evidence, [from, to])
      signed
    end

    revoke_by = fn signer, label, seconds, target ->
      record(as.(signer), 1, nil,
        kind_path: @base <> "/Revocation",
        stream: on.(label),
        actor: "urn:r5e:gateway:vectors",
        at: at.(seconds),
        body: %{"target" => target.ref}
      )
    end

    forged =
      update_in(e_gateway, [:envelope, "signatures", Access.at(0), "sig"], fn sig ->
        <<first, rest::binary>> = Base.decode64!(sig)
        Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
      end)

    gateway_call = record(as.(gateway), 1, nil, at: at.(20))
    {gateway_seal, gateway_manifest} = seal(as.(sealer), [gateway_call], at: at.(25))

    more = [
      {"authority-revocation-by-a-key-that-handed-over",
       "The gateway handed over to a new key, and afterwards the old key tries to take the worker's badge back. A key that has handed over no longer revokes.",
       company ++
         [
           hand_over.(gateway, gateway2, "s", 12),
           revoke_by.(gateway, "rv", 15, badge)
         ], []},
      {"authority-parent-carried-but-forged",
       "The gateway's endorsement is in the bundle with a signature that does not verify. A forged parent is not a missing one: the chain fails.",
       [forged, e_sealer, badge, call], []},
      {"authority-parent-carried-key-missing",
       "The root's key is not in the bundle, so the gateway's endorsement cannot be checked. It may yet be valid: the chain could not be established.",
       company, [keys: Enum.map(people -- [root], &key/1)]},
      {"authority-hand-over-loop-with-lead-in",
       "The gateway hands over to A; later A hands to B and B back to A. The loop ends A and B from its first hand-over. The gateway's own hand-over, before the loop, stands: A acted for it in between.",
       [
         e_gateway,
         hand_over.(gateway, key_a, "s1", 12),
         call_by.(key_a, "between", 13),
         hand_over.(key_a, key_b, "s2", 14),
         hand_over.(key_b, key_a, "s3", 16),
         call_by.(key_a, "after", 17)
       ], []},
      {"authority-root-endorses-itself",
       "A trusted root vouches for itself and then signs a tool call. An endorsement of oneself is ignored.",
       [endorse.(root, "self", 0, root, %{}), call_by.(root, "t", 20)], []},
      {"authority-retired-root-endorses",
       "A root writes a hand-over to a new key, and afterwards both keys issue an endorsement. A root's place does not pass by hand-over: only a change of roots on the deployment's start stream makes another key a root. The old key is still the root the reader trusts, so its endorsement stands, and the new key has no standing.",
       [
         hand_over.(root, root2, "s", 5),
         endorse.(root, "old", 8, gateway, %{}),
         endorse.(root2, "new", 8, worker, %{}),
         call_by.(worker, "t", 20)
       ], []},
      {"authority-revocation-ancestor-not-carried",
       "The root takes the worker's badge back, but the endorsement that would show the badge hangs from this root is not in the bundle. A root may take back any grant on its own chain, and whether this badge is on it could not be established.",
       [badge, call, revoke_by.(root, "rv", 15, badge)], []},
      {"authority-child-names-a-kind-its-parent-did-not",
       "The gateway may issue tool calls and vouches for a helper to seal as well. A link never grants more than its parent.",
       [
         e_gateway,
         grant.(gateway, "wide", 10, "Endorsement", %{
           "subject" => helper.key_id,
           "kinds" => [tool_kind, seal_kind],
           "mayEndorse" => false,
           "parent" => e_gateway.ref
         }),
         call_by.(helper, "t", 20)
       ], []},
      {"authority-actor-outside-grant",
       "The helper may name only gateway identities as the actor, and signs a tool call naming a person.",
       [
         endorse.(root, "narrow", 0, helper, %{"actorPrefixes" => ["urn:r5e:gateway:"]}),
         call_by.(helper, "t", 20)
       ], []},
      {"authority-successor-stands-in",
       "The gateway hands over to a new key. The new key signs under the old key's endorsement and gives out a badge under it; the old key, signing after the hand-over, has nothing.",
       [
         e_gateway,
         hand_over.(gateway, gateway2, "s", 12),
         call_by.(gateway2, "new", 20),
         call_by.(gateway, "old", 20),
         badge_for.(gateway2, "b", 14, helper, e_gateway),
         call_by.(helper, "under-badge", 20)
       ], []},
      {"authority-two-successors",
       "The gateway's key is handed over twice, to two different keys. Neither stands in for it.",
       [
         e_gateway,
         hand_over.(gateway, key_a, "s1", 12),
         hand_over.(gateway, key_b, "s2", 13),
         call_by.(key_a, "t", 20)
       ], []},
      {"authority-backdated-hand-over-against-sealed-history",
       "A tool call by the gateway was sealed by someone else. A hand-over of the gateway's key then appears, dated before the call and never sealed. An honest early hand-over followed by misuse, and a thief backdating one, look the same: it cannot be established either way.",
       [e_gateway, e_sealer, gateway_call, gateway_seal, hand_over.(gateway, thief, "s", 5)],
       [
         blobs: [
           {Profile.encode(profile), nil},
           {@args, nil},
           {@policy, nil},
           {gateway_manifest, nil}
         ],
         seals: [gateway_seal.ref]
       ]},
      {"authority-link-minted-after-revocation",
       "The root took the gateway's endorsement back; afterwards the gateway gives out a badge under it, and a tool call under that badge is dated before the revocation. The badge was minted too late, whatever the call's date.",
       [
         e_gateway,
         revoke_by.(root, "rv", 5, e_gateway),
         badge,
         call_by.(worker, "t", 3)
       ], []},
      {"authority-root-replaced",
       "Long after everything else, the root writes a hand-over to a new key. That changes nothing about who the root is. What the root had granted still stands.",
       company ++ [hand_over.(root, root2, "s", 50)], []},
      {"authority-revocation-by-a-stranger",
       "A key with no place in the chain signs a revocation of the worker's badge. It ends nothing.",
       company ++ [revoke_by.(stranger, "rv", 15, badge)], []},
      {"authority-badge-does-not-pass-to-a-successor",
       "The worker's key hands over to another key, which then signs a tool call. A badge dies with its key.",
       company ++ [hand_over.(worker, helper, "s", 12), call_by.(helper, "t", 20)], []}
    ]

    more_cases =
      for {name, description, records, extra} <- more do
        case_of.(name, description, build.(records, extra), [root.key_id])
      end

    # A deployment where the gateway takes a worker's own records and
    # seals them itself: the gateway's grant covers sealing, and its
    # profile names it as the sealer.
    taking =
      profile(root,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:",
            actor_prefixes: ["urn:r5e:principal:vectors:", "urn:r5e:gateway:vectors"],
            issuer_keys: Enum.map(people, & &1.key_id),
            sealer_keys: [gateway.key_id]
          }
        ],
        failure_domain: "the gateway takes and seals what its workers sign"
      )

    by = fn signer -> %{signer: signer, profile: taking, profile_ref: Profile.ref(taking)} end

    grants_sealing =
      record(by.(root), 1, nil,
        kind_path: @base <> "/Endorsement",
        stream: on.("gateway"),
        actor: "urn:r5e:gateway:vectors",
        at: at.(0),
        body:
          Map.merge(window, %{
            "subject" => gateway.key_id,
            "kinds" => [tool_kind, seal_kind],
            "mayEndorse" => true
          })
      )

    workers_badge =
      (fn ->
         unsigned =
           record(by.(gateway), 1, nil,
             kind_path: @base <> "/Badge",
             stream: on.("worker"),
             actor: "urn:r5e:gateway:vectors",
             at: at.(10),
             body:
               Map.merge(window, %{
                 "subject" => worker.key_id,
                 "subjectKey" => public_key(worker),
                 "holder" => "workload",
                 "kinds" => [tool_kind],
                 "parent" => grants_sealing.ref
               })
           )

         {:ok, signed} = Envelope.sign(unsigned.evidence, [gateway, worker])
         Map.put(signed, :evidence, unsigned.evidence)
       end).()

    endpoint = "urn:r5e:stream:vectors:endpoint:w1:session-1"
    gateways_own = record(by.(gateway), 1, nil, actor: "urn:r5e:gateway:vectors", at: at.(18))
    workers_own = record(by.(worker), 1, nil, stream: endpoint, at: at.(20))

    sealed_by_gateway = fn records, seconds, label ->
      seal(by.(gateway), records,
        at: at.(seconds),
        on: "urn:r5e:stream:vectors:control:" <> label,
        body: %{"stream" => hd(records).evidence["stream"]}
      )
    end

    taken_back = fn seconds ->
      record(by.(gateway), 1, nil,
        kind_path: @base <> "/Revocation",
        stream: on.("revocations"),
        actor: "urn:r5e:gateway:vectors",
        at: at.(seconds),
        body: %{"target" => workers_badge.ref, "reason" => "the worker's laptop was lost"}
      )
    end

    taken = fn name, description, records, seals ->
      built =
        bundle(by.(root), records ++ Enum.map(seals, &elem(&1, 0)),
          keys: Enum.map(people, &key/1),
          blobs:
            [{Profile.encode(taking), nil}, {@args, nil}, {@policy, nil}] ++
              Enum.map(seals, &{elem(&1, 1), nil}),
          seals: Enum.map(seals, &elem(&1, 0).ref)
        )

      %{
        vector(name, description, built, [Profile.ref(taking)])
        | trusted_publishers: nil,
          trusted_roots: [root.key_id]
      }
    end

    workload_cases = [
      taken.(
        "session-recorded-by-the-gateway-and-by-a-worker",
        "One session with a record the gateway signed and a record a worker signed under its badge, on a stream of the worker's own. The gateway took the worker's record and sealed both streams. Nothing about a record signed elsewhere needs a rule of its own: every check holds.",
        [grants_sealing, workers_badge, gateways_own, workers_own],
        [
          sealed_by_gateway.([gateways_own], 25, "a"),
          sealed_by_gateway.([workers_own], 26, "b")
        ]
      ),
      taken.(
        "workers-record-sealed-by-the-gateway-before-its-badge-was-taken-back",
        "The gateway sealed the worker's record and afterwards took the worker's badge back. The seal shows the record came first, so it stands.",
        [grants_sealing, workers_badge, workers_own, taken_back.(30)],
        [sealed_by_gateway.([workers_own], 25, "b")]
      ),
      taken.(
        "workers-record-sealed-by-the-gateway-only-after-its-badge-was-taken-back",
        "The worker dated its record before the badge was taken back, and the gateway's seal over it is dated after. Nothing but the worker's own word puts the record first. This is why a gateway seals what it has taken before it records a revocation.",
        [grants_sealing, workers_badge, workers_own, taken_back.(30)],
        [sealed_by_gateway.([workers_own], 35, "b")]
      )
    ]

    [
      case_of.(
        "authority-root-to-badge",
        "The reader trusts one root key. The root vouches for a gateway, the gateway gives a worker a badge, and the worker makes a tool call. Authority is established for each from the records alone.",
        build.(company, []),
        [root.key_id]
      ),
      with_publication(%{
        case_of.(
          "authority-publication-carried",
          "The same bundle, also carrying a publisher's statement of whose definitions these are. The reader trusts the root for authority and, separately, the publisher for definitions. The publisher is outside the root's chain and needs no place in it: its record gets no authority finding, and every check holds.",
          build.(company, []),
          [root.key_id]
        )
        | trusted_publishers: nil
      }),
      %{
        with_publication(%{
          case_of.(
            "authority-publication-from-an-unknown-publisher",
            "The same again, read by someone who trusts the root and no publisher. Carrying a stranger's statement is not a fault: nothing fails, and whose definitions these are is reported as not established.",
            build.(company, []),
            [root.key_id]
          )
          | trusted_publishers: nil
        })
        | trusted_publishers: []
      },
      case_of.(
        "authority-root-not-trusted",
        "The same bundle read by someone who trusts a different key. Nothing in it has standing.",
        build.(company, []),
        [stranger.key_id]
      ),
      case_of.(
        "authority-parent-not-carried",
        "The badge and the tool call without the gateway's endorsement. What is carried holds; the rest could not be checked.",
        build.([e_sealer, badge, call], []),
        [root.key_id]
      ),
      case_of.(
        "authority-revoked-before-record",
        "The gateway took the badge back five seconds before the tool call.",
        build.(company ++ [revoke.(15)], []),
        [root.key_id]
      ),
      case_of.(
        "authority-revoked-after-unsealed-record",
        "The badge was taken back after the tool call's own date, and nobody else sealed the call first. Its date is only the worker's word.",
        build.(company ++ [revoke.(30)], []),
        [root.key_id]
      ),
      case_of.(
        "authority-revoked-after-sealed-record",
        "The same, but a sealer with standing of its own sealed the call before the revocation. The call is shown to have come first.",
        build.(company ++ [seal, revoke.(30)], sealed_blobs),
        [root.key_id]
      )
    ] ++
      more_cases ++
      workload_cases ++
      start_cases(%{
        root: root,
        stranger: stranger,
        company: company,
        profile: profile,
        sealer: sealer
      })
  end

  # How a deployment's chain begins: the node's bootstrap key states what
  # it was built from, and the customer's root accepts it.
  defp start_cases(
         %{root: root, stranger: stranger, company: company, profile: company_profile} = given
       ) do
    bootstrap = named("start bootstrap")
    %{record: published} = publication()
    stream = "urn:r5e:stream:vectors:start"

    profile =
      profile(bootstrap,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:start",
            actor_prefixes: ["urn:r5e:node:"],
            issuer_keys: [bootstrap.key_id],
            sealer_keys: []
          }
        ]
      )

    w = %{signer: bootstrap, profile: profile, profile_ref: Profile.ref(profile)}
    {:ok, opened} = Envelope.open(published.envelope)
    listed = opened.evidence["body"]["definitions"]

    started = fn definitions ->
      record(w, 1, nil,
        kind_path: @base <> "/ChainStarted",
        stream: stream,
        actor: "urn:r5e:node:vectors",
        at: DateTime.add(@at, -120, :second),
        body: %{
          "deployment" => "vectors",
          "bootstrap" => bootstrap.key_id,
          "bootstrapKey" => public_key(bootstrap),
          "publication" => published.ref,
          "publisher" => opened.evidence["issuer"],
          "definitions" => definitions
        }
      )
    end

    first = started.(listed)

    accepted = fn first, signer, change ->
      unsigned =
        record(w, 2, first.ref,
          kind_path: @base <> "/Deployment",
          stream: stream,
          actor: "urn:r5e:node:vectors",
          at: DateTime.add(@at, -60, :second),
          body:
            Map.merge(
              %{
                "accepts" => first.ref,
                "bootstrap" => bootstrap.key_id,
                "claimedBy" => signer.key_id,
                "roots" => [%{"key" => signer.key_id, "publicKey" => public_key(signer)}],
                "threshold" => 1
              },
              change
            )
        )

      {:ok, signed} = Envelope.sign(unsigned.evidence, [bootstrap, signer])
      Map.put(signed, :evidence, unsigned.evidence)
    end

    second = accepted.(first, root, %{})
    people = [bootstrap, root, stranger, named("authority gateway"), named("authority worker")]

    build = fn records ->
      bundle(w, records,
        keys: Enum.map(people, &key/1),
        blobs: [
          {Profile.encode(profile), nil},
          {Profile.encode(company_profile), nil},
          {@args, nil},
          {@policy, nil}
        ]
      )
    end

    make = fn name, description, records, trust ->
      vector(name, description, build.(records), [
        Profile.ref(profile),
        Profile.ref(company_profile)
      ])
      |> Map.merge(%{trusted_publishers: nil, trusted_roots: nil})
      |> with_publication()
      |> Map.merge(Map.new(trust))
    end

    other_chain = Ref.evidence("a different deployment record")

    [
      make.(
        "start-accepted-under-a-pinned-chain",
        "A deployment's first two records and the company's records beneath them. The reader pins the chain by its name, the reference of the deployment record, and names no root key. The start holds, the roots it declares are used, and every record's authority is established from them.",
        [first, second] ++ company,
        trusted_chain: second.ref
      ),
      make.(
        "start-accepted-under-a-trusted-root",
        "The same file, read by someone who names the root key instead of the chain. The start holds because the root that signed the deployment record is one the reader trusts.",
        [first, second] ++ company,
        trusted_roots: [root.key_id]
      ),
      make.(
        "start-by-someone-the-reader-never-chose",
        "The same file, read by someone who trusts a different root. The two start records are well formed and consistent, and that is all they are: anyone can make a bootstrap key and a root. The start is reported as not trusted, and nothing beneath it has standing.",
        [first, second] ++ company,
        trusted_roots: [stranger.key_id]
      ),
      make.(
        "start-with-no-trust-given",
        "The two start records read with neither a chain nor a root named. Nothing fails, and the start is reported as not trusted.",
        [first, second],
        []
      ),
      make.(
        "start-not-handed-over",
        "Only the first record is carried: the node says what it was built from, and no customer has accepted it. Reported as such, not as a start that holds.",
        [first],
        trusted_roots: [root.key_id]
      ),
      make.(
        "start-pinned-and-not-carried",
        "The reader pins a chain and the file does not carry its start. The company's records cannot be traced to anything, and that is reported as not carried, not as a failure.",
        company,
        trusted_chain: second.ref
      ),
      make.(
        "start-pinned-to-another-chain",
        "The reader pinned a different chain from the one in the file. The start fails, and nothing beneath it has standing.",
        [first, second] ++ company,
        trusted_chain: other_chain
      ),
      make.(
        "start-restates-other-definitions-than-its-publication",
        "The first record names a publication and then restates a list of definitions that is not the one the publication gives.",
        (fn ->
           altered = started.(tl(listed))
           [altered, accepted.(altered, root, %{})]
         end).(),
        trusted_roots: [root.key_id]
      ),
      %{
        make.(
          "start-publication-not-carried",
          "The first record names the publication the node was built from, and the file does not carry it.",
          [first, second],
          trusted_roots: [root.key_id]
        )
        | bundle: build.([first, second]),
          trusted_publishers: [opened.evidence["issuer"]]
      },
      make.(
        "start-terms-do-not-hold-together",
        "The deployment record asks for two roots to act together and names one.",
        [first, accepted.(first, root, %{"threshold" => 2})],
        trusted_roots: [root.key_id]
      ),
      make.(
        "start-accepts-something-else",
        "The deployment record says it accepts a record other than the one before it.",
        [first, accepted.(first, root, %{"accepts" => other_chain})],
        trusted_roots: [root.key_id]
      ),
      make.(
        "start-with-two-deployment-records",
        "Two deployment records at the second position, each naming a different root. Neither is the start.",
        [first, second, accepted.(first, stranger, %{})],
        trusted_roots: [root.key_id]
      ),
      make.(
        "start-shorter-than-the-reader-requires",
        "The reader pins the chain and says its start stream must reach at least the third position. The file stops at the second. A file can be cut short without breaking any signature, so this is the reader's protection, and nothing under the start is established.",
        [first, second] ++ company,
        trusted_chain: second.ref,
        min_start_seq: 3
      )
    ] ++
      more_start_cases(%{
        sealer: given.sealer,
        company_profile: company_profile,
        company: company,
        stranger: stranger,
        w: w,
        first: first,
        second: second,
        root: root,
        make: make,
        accepted: accepted,
        opened: opened,
        listed: listed,
        stream: stream
      })
  end

  # One case for each remaining way a start can be wrong.
  defp more_start_cases(c) do
    %{w: w, first: first, second: second, root: root, make: make} = c
    bootstrap = w.signer
    publisher = c.opened.evidence["issuer"]

    start_record = fn seq, previous, stream, change ->
      record(w, seq, previous,
        kind_path: @base <> "/ChainStarted",
        stream: stream,
        actor: "urn:r5e:node:vectors",
        at: DateTime.add(@at, -120, :second),
        body:
          Map.merge(
            %{
              "deployment" => "vectors",
              "bootstrap" => bootstrap.key_id,
              "bootstrapKey" => public_key(bootstrap),
              "publication" => c.opened.ref,
              "publisher" => publisher,
              "definitions" => c.listed
            },
            change
          )
      )
    end

    # A deployment record whose first signer is a different key from the
    # one that signed the start record it accepts.
    other_bootstrap = named("start bootstrap two")

    other_profile =
      profile(other_bootstrap,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:start",
            actor_prefixes: ["urn:r5e:node:"],
            issuer_keys: [other_bootstrap.key_id],
            sealer_keys: []
          }
        ]
      )

    by_another_key =
      (fn ->
         unsigned =
           record(
             %{
               signer: other_bootstrap,
               profile: other_profile,
               profile_ref: Profile.ref(other_profile)
             },
             2,
             first.ref,
             kind_path: @base <> "/Deployment",
             stream: c.stream,
             actor: "urn:r5e:node:vectors",
             at: DateTime.add(@at, -60, :second),
             body: %{
               "accepts" => first.ref,
               "bootstrap" => other_bootstrap.key_id,
               "claimedBy" => root.key_id,
               "roots" => [%{"key" => root.key_id, "publicKey" => public_key(root)}],
               "threshold" => 1
             }
           )

         {:ok, signed} = Envelope.sign(unsigned.evidence, [other_bootstrap, root])
         Map.put(signed, :evidence, unsigned.evidence)
       end).()

    with_other = fn vector ->
      vector
      |> Map.update!(:bundle, fn bundle ->
        bundle
        |> Map.update!("keys", &(&1 ++ [wire_key(other_bootstrap)]))
        |> Map.update!("blobs", &(&1 ++ [blob(Profile.encode(other_profile))]))
      end)
      |> Map.update!(:trusted_profiles, &(&1 ++ [Profile.ref(other_profile)]))
    end

    roots = [trusted_roots: [root.key_id]]

    [
      make.(
        "start-two-start-streams",
        "The file carries the start of the deployment and, on a second stream, another start record. A reader cannot tell which beginning is meant, so neither stands.",
        [first, second, start_record.(1, nil, "urn:r5e:stream:vectors:start-two", %{})],
        roots
      ),
      make.(
        "start-stream-holds-another-kind-of-record",
        "A tool call written at the third position of the start stream. The start stream holds the records of the start and nothing else.",
        [
          first,
          second,
          record(w, 3, second.ref, stream: c.stream, actor: "urn:r5e:node:vectors")
        ],
        roots
      ),
      make.(
        "start-record-at-the-wrong-position",
        "A start record at the second position of its stream.",
        [start_record.(2, first.ref, c.stream, %{})],
        roots
      ),
      make.(
        "start-deployment-without-the-record-it-accepts",
        "The deployment record is carried and the start record it accepts is not. What the customer accepted cannot be seen, so the start is not established.",
        [second],
        roots
      ),
      with_other.(
        make.(
          "start-accepted-by-a-different-first-signer",
          "The deployment record's first signer is not the key that signed the start record. A start is handed over by the key that began it, and by no other.",
          [first, by_another_key],
          roots
        )
      ),
      make.(
        "start-names-a-publisher-that-did-not-sign-its-publication",
        "The start record cites a real publication and names a different key as its publisher.",
        (fn ->
           altered = start_record.(1, nil, c.stream, %{"publisher" => root.key_id})
           [altered, c.accepted.(altered, root, %{})]
         end).(),
        roots
      ),
      Map.update!(
        make.(
          "start-publication-carried-without-its-key",
          "The publication the start record cites is in the file and the publisher's key is not, so its signature cannot be checked. That is reported as not verified, which is a different fact from the publication being absent.",
          [first, second],
          roots
        ),
        :bundle,
        fn bundle ->
          Map.update!(bundle, "keys", &Enum.reject(&1, fn k -> k["keyid"] == publisher end))
        end
      ),
      make.(
        "start-recovery-key-is-also-a-root",
        "The deployment record lists one of its roots as a recovery key as well. A recovery key acts alone, so this would let one root step around the number required to act together.",
        [first, c.accepted.(first, root, %{"recoveryKeys" => [root.key_id]})],
        roots
      )
    ] ++ roots_cases(c)
  end

  # Changing a deployment's roots after it was claimed: by a recovery
  # key, or by a quorum of roots each with the person who holds it.
  defp roots_cases(c) do
    %{first: first, root: root, make: make, stream: stream} = c
    recovery = named("start recovery")
    root_two = named("start root two")
    lena = named("start lena")
    change_at = DateTime.add(@at, 100, :second)

    # Each key that writes on the deployment's streams has a profile of
    # its own binding it to the stream it writes.
    bound = fn signer, prefix ->
      profile(signer,
        bindings: [
          %{
            stream_prefix: prefix,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [signer.key_id],
            sealer_keys: []
          }
        ]
      )
    end

    as = fn signer, prefix ->
      p = bound.(signer, prefix)
      %{signer: signer, profile: p, profile_ref: Profile.ref(p)}
    end

    terms = %{
      "recoveryKeys" => [recovery.key_id],
      "custodians" => [%{"identity" => "mailto:lena@vectors.example", "key" => lena.key_id}]
    }

    claimed = c.accepted.(first, root, terms)

    change = fn signer, authorization, body, opts ->
      record(
        as.(signer, stream),
        Keyword.get(opts, :seq, 3),
        Keyword.get(opts, :after, claimed).ref,
        kind_path: @base <> "/RootsChanged",
        stream: stream,
        actor: "urn:r5e:root-ceremony",
        at: Keyword.get(opts, :at, change_at),
        body:
          Map.merge(
            %{
              "chain" => claimed.ref,
              "replaces" => Keyword.get(opts, :after, claimed).ref,
              "authorization" => authorization,
              "signer" => signer.key_id,
              "signerKey" => public_key(signer),
              "roots" => [%{"key" => root_two.key_id, "publicKey" => public_key(root_two)}],
              "threshold" => 1,
              "reason" => "the first root's hardware key is being retired"
            },
            body
          )
      )
    end

    approve = fn changed, by, who, key, label ->
      prefix = "urn:r5e:stream:vectors:authority:approval:" <> label

      unsigned =
        record(as.(by, prefix), 1, nil,
          kind_path: @base <> "/RootChangeApproval",
          stream: prefix,
          actor: "urn:r5e:root-ceremony",
          at: DateTime.add(change_at, 5, :second),
          body: %{
            "change" => changed.ref,
            "root" => by.key_id,
            "custodian" => who,
            "custodianKey" => key.key_id,
            "custodianPublicKey" => public_key(key)
          }
        )

      {:ok, signed} = Envelope.sign(unsigned.evidence, [by, key])
      {Map.put(signed, :evidence, unsigned.evidence), bound.(by, prefix)}
    end

    with_more = fn vector, signers, profiles ->
      vector
      |> Map.update!(:bundle, fn bundle ->
        bundle
        |> Map.update!(
          "keys",
          &Enum.uniq_by(&1 ++ Enum.map(signers, fn s -> wire_key(s) end), fn k -> k["keyid"] end)
        )
        |> Map.update!(
          "blobs",
          &Enum.uniq_by(&1 ++ Enum.map(profiles, fn p -> blob(Profile.encode(p)) end), fn b ->
            b["ref"]
          end)
        )
      end)
      |> Map.update!(
        :trusted_profiles,
        &Enum.uniq(&1 ++ Enum.map(profiles, fn p -> Profile.ref(p) end))
      )
    end

    by_recovery = change.(recovery, "recovery", %{}, [])
    by_quorum = change.(root, "quorum", %{}, [])

    {approval, approval_profile} =
      approve.(by_quorum, root, "mailto:lena@vectors.example", lena, "one")

    {again, again_profile} = approve.(by_quorum, root, "mailto:lena@vectors.example", lena, "two")

    {unnamed, unnamed_profile} =
      approve.(by_quorum, root, "mailto:someone@vectors.example", lena, "three")

    everyone = [recovery, root_two, lena]
    start_profiles = [bound.(recovery, stream), bound.(root, stream), bound.(c.stranger, stream)]
    pinned = [trusted_chain: claimed.ref]

    case_of = fn name, description, records, trust, profiles ->
      with_more.(make.(name, description, records, trust), everyone, start_profiles ++ profiles)
    end

    late =
      record(as.(root, "urn:r5e:stream:vectors:authority:late"), 1, nil,
        kind_path: @base <> "/Endorsement",
        stream: "urn:r5e:stream:vectors:authority:late",
        actor: "urn:r5e:gateway:vectors",
        at: DateTime.add(change_at, 600, :second),
        body: %{
          "subject" => named("authority gateway").key_id,
          "kinds" => [@base <> "/ToolCall"],
          "mayEndorse" => true,
          "notBefore" => "2026-11-10T00:00:00Z",
          "notAfter" => "2026-11-11T00:00:00Z"
        }
      )

    thief = named("start thief sealer")
    old_grant = hd(c.company)

    taken_back =
      record(as.(root_two, "urn:r5e:stream:vectors:authority:revocations"), 1, nil,
        kind_path: @base <> "/Revocation",
        stream: "urn:r5e:stream:vectors:authority:revocations",
        actor: "urn:r5e:root-ceremony",
        at: DateTime.add(change_at, 30, :second),
        body: %{"target" => old_grant.ref, "reason" => "the old root's grants are withdrawn"}
      )

    # The old root's grant to the gateway, sealed before the change by
    # `sealer`, whom the old root vouched for; and, when `vouched?`, the
    # new root vouching for the same sealer after the change.
    sealed_before = fn name, description, sealer, sealer_profile, vouched? ->
      grant = fn by, label, at ->
        record(as.(by, "urn:r5e:stream:vectors:authority:" <> label), 1, nil,
          kind_path: @base <> "/Endorsement",
          stream: "urn:r5e:stream:vectors:authority:" <> label,
          actor: "urn:r5e:root-ceremony",
          at: at,
          body: %{
            "subject" => sealer.key_id,
            "kinds" => [@base <> "/EpochSeal"],
            "mayEndorse" => false,
            "notBefore" => "2026-11-10T00:00:00Z",
            "notAfter" => "2026-11-11T00:00:00Z"
          }
        )
      end

      by_old = grant.(root, "sealer-by-old-root", DateTime.add(@at, 2, :second))
      by_new = grant.(root_two, "sealer-by-new-root", DateTime.add(change_at, 10, :second))

      {sealed, manifest} =
        seal(
          %{signer: sealer, profile: sealer_profile, profile_ref: Profile.ref(sealer_profile)},
          [old_grant],
          at: DateTime.add(@at, 25, :second),
          body: %{"stream" => old_grant.evidence["stream"]}
        )

      records =
        [first, claimed, by_recovery] ++
          c.company ++ [by_old, sealed] ++ if(vouched?, do: [by_new], else: [])

      profiles = [
        sealer_profile,
        bound.(root, "urn:r5e:stream:vectors:authority:sealer-by-old-root"),
        bound.(root_two, "urn:r5e:stream:vectors:authority:sealer-by-new-root")
      ]

      case_of.(name, description, records, pinned, profiles)
      |> with_more.([sealer], [])
      |> Map.update!(:bundle, fn bundle ->
        bundle
        |> Map.update!("blobs", &(&1 ++ [blob(manifest)]))
        |> Map.put("seals", [sealed.ref])
      end)
    end

    # A second change, after the first. The first names a new recovery
    # key; that key makes the second.
    recovery_two = named("start recovery two")
    root_three = named("start root three")

    first_change = change.(recovery, "recovery", %{"recoveryKeys" => [recovery_two.key_id]}, [])

    second_change = fn body ->
      change.(
        recovery_two,
        "recovery",
        Map.merge(
          %{
            "roots" => [%{"key" => root_three.key_id, "publicKey" => public_key(root_three)}],
            "reason" => "the second root's hardware key is being retired"
          },
          body
        ),
        seq: 4,
        after: first_change,
        at: DateTime.add(change_at, 200, :second)
      )
    end

    twice = fn name, description, body ->
      case_of.(name, description, [first, claimed, first_change, second_change.(body)], pinned, [
        bound.(recovery_two, stream)
      ])
      |> with_more.([recovery_two, root_three], [])
    end

    # A deployment whose terms name a person who may approve, without
    # that person's key. The root says which key is theirs afterwards.
    named_only =
      c.accepted.(first, root, %{
        "custodians" => [%{"identity" => "mailto:lena@vectors.example"}]
      })

    proposed =
      record(as.(root, stream), 3, named_only.ref,
        kind_path: @base <> "/RootsChanged",
        stream: stream,
        actor: "urn:r5e:root-ceremony",
        at: change_at,
        body: %{
          "chain" => named_only.ref,
          "replaces" => named_only.ref,
          "authorization" => "quorum",
          "signer" => root.key_id,
          "signerKey" => public_key(root),
          "roots" => [%{"key" => root_two.key_id, "publicKey" => public_key(root_two)}],
          "threshold" => 1,
          "reason" => "the first root's hardware key is being retired"
        }
      )

    {lenas, lenas_profile} = approve.(proposed, root, "mailto:lena@vectors.example", lena, "four")
    binding = "urn:r5e:stream:vectors:authority:custodian-lena"

    binds =
      record(as.(root, binding), 1, nil,
        kind_path: @base <> "/Endorsement",
        stream: binding,
        actor: "urn:r5e:root-ceremony",
        at: DateTime.add(change_at, -50, :second),
        body: %{
          "subject" => lena.key_id,
          "actsFor" => "mailto:lena@vectors.example",
          "kinds" => [@base <> "/RootChangeApproval"],
          "mayEndorse" => false,
          "notBefore" => "2026-11-10T00:00:00Z",
          "notAfter" => "2026-11-11T00:00:00Z"
        }
      )

    late_bound = fn name, description, sealed? ->
      vouches = "urn:r5e:stream:vectors:authority:sealer-for-custodians"

      for_sealer =
        record(as.(root, vouches), 1, nil,
          kind_path: @base <> "/Endorsement",
          stream: vouches,
          actor: "urn:r5e:root-ceremony",
          at: DateTime.add(@at, 2, :second),
          body: %{
            "subject" => c.sealer.key_id,
            "kinds" => [@base <> "/EpochSeal"],
            "mayEndorse" => false,
            "notBefore" => "2026-11-10T00:00:00Z",
            "notAfter" => "2026-11-11T00:00:00Z"
          }
        )

      {sealed, manifest} =
        seal(
          %{
            signer: c.sealer,
            profile: c.company_profile,
            profile_ref: Profile.ref(c.company_profile)
          },
          [binds],
          at: DateTime.add(change_at, -40, :second),
          body: %{"stream" => binding}
        )

      records =
        [first, named_only, proposed, lenas, binds] ++
          if(sealed?, do: [for_sealer, sealed], else: [])

      built =
        case_of.(name, description, records, [trusted_chain: named_only.ref], [
          lenas_profile,
          bound.(root, binding),
          bound.(root, vouches),
          c.company_profile
        ])

      if sealed? do
        built
        |> with_more.([c.sealer], [])
        |> Map.update!(:bundle, fn bundle ->
          bundle
          |> Map.update!("blobs", &(&1 ++ [blob(manifest)]))
          |> Map.put("seals", [sealed.ref])
        end)
      else
        built
      end
    end

    [
      twice.(
        "roots-changed-twice",
        "The recovery key replaces the root and names a new recovery key. Later that new recovery key replaces the root again. Each change is judged by the terms the one before it left, and the start holds through all four positions.",
        %{}
      ),
      twice.(
        "roots-changed-twice-and-a-used-recovery-key-comes-back",
        "The same two changes, except that the second lists the first change's recovery key as a recovery key again. That key was used at the third position; a used recovery key is never one again, at any later change.",
        %{"recoveryKeys" => [recovery.key_id]}
      ),
      late_bound.(
        "roots-change-approved-with-a-key-the-root-bound-and-sealed-beforehand",
        "The deployment's terms name a person who may approve without saying which key is theirs. Before the change, a root said which key is hers, and the deployment's sealer sealed that statement. Her approval counts and the change holds. The removed root's own statements are then reported as resting on its word about when they were made, because no root now in place vouches for the sealer; that is the ordinary rule for a removed root and does not undo the change.",
        true
      ),
      late_bound.(
        "roots-change-approved-with-a-key-bound-but-never-sealed",
        "The same, without the seal. The root's statement of whose key it is carries a date before the change, but nothing except the root's own word shows it was made then. Whoever later held that root could write the same statement and date it back, so the approval is not yet established.",
        false
      ),
      case_of.(
        "roots-changed-by-the-recovery-key",
        "After the claim, the recovery key the deployment declared replaces the root. It needs nobody else, and its public key is first shown by the record it signs. Read under the pinned chain, the start holds through all three positions.",
        [first, claimed, by_recovery],
        pinned,
        []
      ),
      case_of.(
        "roots-changed-by-a-quorum",
        "One of the roots proposes a change, and the number of roots the terms require approve it, each with the personal key of the person named for it. The proposer's own signature on the change is not one of the approvals.",
        [first, claimed, by_quorum, approval],
        pinned,
        [approval_profile]
      ),
      case_of.(
        "roots-change-without-its-approvals",
        "A change proposed by a root with no approval carried. It is not established, and under a pinned chain nothing beneath the start is established either. It is not reported as failed: the approvals may exist and simply not be in the file.",
        [first, claimed, by_quorum] ++ c.company,
        pinned,
        []
      ),
      case_of.(
        "roots-change-approved-twice-by-one-root",
        "The same root and person approve the same change twice. Repeating an approval is harmless and counts once; it never stops a change that has the approvals it needs.",
        [first, claimed, by_quorum, approval, again],
        pinned,
        [approval_profile, again_profile]
      ),
      case_of.(
        "roots-change-approved-by-someone-not-named",
        "The approval names a person the deployment's terms never listed. The approval fails, and the change is left without the approvals it needs.",
        [first, claimed, by_quorum, unnamed],
        pinned,
        [unnamed_profile]
      ),
      case_of.(
        "roots-change-keeps-its-used-recovery-key",
        "The recovery key replaces the roots and lists itself as a recovery key again. Once used, a recovery key's public half is known, so it may never be one again.",
        [
          first,
          claimed,
          change.(recovery, "recovery", %{"recoveryKeys" => [recovery.key_id]}, [])
        ],
        pinned,
        []
      ),
      case_of.(
        "roots-change-by-a-key-that-was-never-a-recovery-key",
        "A key the terms never declared signs a change and calls itself a recovery key.",
        [first, claimed, change.(c.stranger, "recovery", %{}, [])],
        pinned,
        []
      ),
      case_of.(
        "roots-changed-and-the-old-roots-grants-were-never-sealed",
        "The roots were replaced, and the company's records all hang from a grant the old root gave before that. Nothing shows that grant existed before the change except the old root's own date on it, and a removed root is not believed about when it signed. Its authority, and everything beneath it, rests on the signer's clock.",
        [first, claimed, by_recovery] ++ c.company,
        pinned,
        []
      ),
      case_of.(
        "roots-changed-and-the-old-root-grants-afterwards",
        "After it was replaced, the old root signs a new grant and dates it after the change. It has ended.",
        [first, claimed, by_recovery, late],
        pinned,
        [bound.(root, "urn:r5e:stream:vectors:authority:late")]
      ),
      sealed_before.(
        "roots-changed-and-the-old-roots-grant-was-sealed-by-a-sealer-the-new-root-vouches-for",
        "The roots were replaced. Before that, the deployment's own sealer had sealed the grant the old root gave the gateway, and after the change the new root vouches for that same sealer. The seal shows the grant existed before the change, so it stands, and so does everything beneath it. This is what an honest deployment looks like after replacing a root.",
        c.sealer,
        c.company_profile,
        true
      ),
      sealed_before.(
        "roots-changed-and-the-old-roots-grant-was-sealed-by-a-sealer-only-the-old-root-vouched-for",
        "The same records, but the sealer is one that only the removed root ever vouched for, and its grant and its seal are both dated before the change. Whoever holds a removed root can make exactly this: a sealer of their own and a history dated to suit. No root now in place vouches for that sealer, so its seal shows nothing, and the grant rests on the removed root's own word about when it signed.",
        thief,
        # The thief's own profile names the thief as sealer, so the only
        # thing wrong with the seal is whose word its sealer rests on.
        profile(thief,
          bindings: [
            %{
              stream_prefix: "urn:r5e:stream:vectors:",
              actor_prefixes: ["urn:r5e:"],
              issuer_keys: [thief.key_id],
              sealer_keys: [thief.key_id]
            }
          ]
        ),
        false
      ),
      case_of.(
        "roots-changed-and-the-new-root-takes-back-the-old-roots-grant",
        "After the change, the new root takes back the grant the old root gave the gateway. A root may take back any grant on its own deployment's chain, whoever gave it; otherwise replacing a stolen root would leave its grants beyond reach.",
        [first, claimed, by_recovery, hd(c.company), taken_back],
        pinned,
        [bound.(root_two, "urn:r5e:stream:vectors:authority:revocations")]
      ),
      case_of.(
        "roots-changed-read-by-someone-who-pinned-the-old-root",
        "The same change, read by someone who names the old root key and not the chain. A pinned key never follows a change of roots: the reader is told the new roots are not ones they trust, and the old root's time as a root is over from the change.",
        [first, claimed, by_recovery] ++ c.company,
        [trusted_roots: [root.key_id]],
        []
      )
    ]
  end

  defp es384_case do
    w = world(signer("es384"))

    vector(
      "valid-single-record-es384",
      "One tool call signed with ES384 (raw r||s, low S, SHA-384). Every check holds.",
      single(w),
      [w.profile_ref]
    )
  end

  defp fork(w) do
    [first, second] = chain(w, 2)
    rival = record(w, 2, first.ref, body: tool_body(%{"tool" => "Write"}))
    bundle(w, [first, second, rival])
  end

  defp broken_chain(w) do
    first = record(w, 1, nil)
    second = record(w, 2, Ref.evidence("not the first record"))
    bundle(w, [first, second])
  end

  defp unauthorized_seal(w) do
    strict =
      profile(w.signer,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:",
            actor_prefixes: ["urn:r5e:principal:vectors:", "urn:r5e:gateway:vectors"],
            issuer_keys: [w.signer.key_id],
            sealer_keys: []
          }
        ]
      )

    records = chain(w, 2)
    {seal, manifest} = seal(w, records, profile_ref: Profile.ref(strict))

    bundle(w, records ++ [seal],
      blobs: [
        {Profile.encode(w.profile), nil},
        {Profile.encode(strict), nil},
        {@args, nil},
        {@policy, nil},
        {manifest, nil}
      ],
      seals: [seal.ref]
    )
  end

  # A second publication by a key the reader never chose, restating what
  # the trusted publisher said, beside the trusted one.
  defp stranger_publication(w, trusted) do
    %{signer: publisher} = publication()
    seed = :crypto.hash(:sha256, "r5e provenance vectors stranger publisher")
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    stranger = Key.local_signer("ed25519", public, private)

    {:ok, set} = Recurse.Provenance.Publication.issue(stranger, name: "stranger", at: @at)
    [%{"blobs" => [%{"ref" => stranger_profile} | _]}] = [set]

    base =
      "publication-by-a-stranger-beside-a-trusted-one"
      |> vector(
        "The trusted publisher's statement is carried, and so is a second publication, correctly signed by a key the reader never chose, restating the same definitions. The stranger's record is reported as from a publisher that is not trusted. It does not pass because the trusted publisher published the publication kind.",
        single(w),
        trusted
      )
      |> with_publication()

    %{
      base
      | bundle: Recurse.Provenance.Publication.carry(base.bundle, [set]),
        trusted_profiles: base.trusted_profiles ++ [stranger_profile],
        trusted_publishers: [publisher.key_id]
    }
  end

  # Cases about publication itself set their own trust and are left alone.
  defp publication_cases(w, trusted) do
    %{signer: publisher} = publication()

    not_carried =
      vector(
        "publication-not-carried",
        "A sound record with no statement from any publisher about its definition. Whose definition it is is not established.",
        single(w),
        trusted
      )

    untrusted =
      "publisher-not-trusted"
      |> vector(
        "The publication is carried and correctly signed, and the reader trusts no publisher.",
        single(w),
        trusted
      )
      |> with_publication()

    [
      %{not_carried | trusted_publishers: [publisher.key_id]},
      %{untrusted | trusted_publishers: []},
      stranger_publication(w, trusted),
      %{lookalike_definition(w) | trusted_publishers: [publisher.key_id]}
    ] ++ domain_cases(w, trusted) ++ proposal_cases(w, trusted)
  end

  # A reader may believe a publisher about some domains only.
  defp domain_cases(w, trusted) do
    %{signer: publisher} = publication()
    seed = :crypto.hash(:sha256, "r5e provenance vectors customer publisher")
    {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
    customer = Key.local_signer("ed25519", public, private)

    carried =
      fn name, description ->
        name |> vector(description, single(w), trusted) |> with_publication()
      end

    # The customer's publisher issues its own, looser document under a
    # base kind's name.
    path = @base <> "/ToolCall"
    bytes = loose_tool_call()

    {:ok, set} =
      Recurse.Provenance.Publication.issue(customer,
        name: "customer",
        at: @at,
        package: "acme.reviews",
        documents: [%{kind_path: path, ref: Ref.bytes(bytes), bytes: bytes}]
      )

    [%{"blobs" => [%{"ref" => customer_profile} | _]}] = [set]

    overreach = fn name, description, publishers ->
      base = lookalike_definition(w)

      %{
        base
        | name: name,
          description: description,
          bundle: Recurse.Provenance.Publication.carry(base.bundle, [set]),
          trusted_profiles: base.trusted_profiles ++ [customer_profile],
          trusted_publishers: publishers
      }
    end

    [
      %{
        carried.(
          "publisher-believed-about-its-domain",
          "The reader believes the publisher about kinds under r5e.io, and the record's kind is one."
        )
        | trusted_publishers: [publisher.key_id <> "=r5e.io"]
      },
      %{
        carried.(
          "publisher-believed-about-another-domain",
          "The reader believes the publisher about kinds under example.com only. Its statement about an r5e.io kind is carried and counts for nothing."
        )
        | trusted_publishers: [publisher.key_id <> "=example.com"]
      },
      %{
        carried.(
          "publisher-domain-is-not-a-suffix-match",
          "The reader believes the publisher about notr5e.io. That is not r5e.io, and r5e.io is not under it."
        )
        | trusted_publishers: [publisher.key_id <> "=notr5e.io,5e.io"]
      },
      overreach.(
        "second-publisher-speaks-outside-its-domain",
        "A customer's publisher, believed about acme.example, publishes its own document for an r5e.io kind, and a record cites it. r5e's publisher, believed about r5e.io, published a different document for that kind, so the record fails.",
        [publisher.key_id <> "=r5e.io", customer.key_id <> "=acme.example"]
      ),
      overreach.(
        "second-publisher-believed-about-everything",
        "The same bundle, read by someone who believes both publishers about every kind. The customer's document for the r5e.io kind is then accepted. This is what naming domains prevents.",
        [publisher.key_id, customer.key_id]
      )
    ]
  end

  # A publication may name the record its definitions were proposed in.
  defp proposal_cases(w, trusted) do
    chain = "evidence:sha256:" <> String.duplicate("c", 64)
    proposed = "evidence:sha256:" <> String.duplicate("d", 64)

    with_proposal = fn name, description, proposal ->
      seed = :crypto.hash(:sha256, "r5e provenance vectors ratifying publisher")
      {public, private} = :crypto.generate_key(:eddsa, :ed25519, seed)
      ratifier = Key.local_signer("ed25519", public, private)

      {:ok, set} =
        Recurse.Provenance.Publication.issue(ratifier,
          name: "ratifier",
          at: @at,
          proposal: proposal
        )

      [%{"blobs" => [%{"ref" => profile} | _]}] = [set]
      base = vector(name, description, single(w), trusted)

      %{
        base
        | bundle: Recurse.Provenance.Publication.carry(base.bundle, [set]),
          trusted_profiles: trusted ++ [profile],
          trusted_publishers: [ratifier.key_id <> "=r5e.io"]
      }
    end

    [
      with_proposal.(
        "publication-names-a-proposal-on-another-chain",
        "A publication names the record its definitions were proposed in, on another chain. The reference is well formed. Nothing of that chain is carried, so nothing more is said about it.",
        "chain:" <> chain <> "/" <> proposed
      ),
      with_proposal.(
        "publication-names-a-proposal-on-its-own-chain",
        "A publication names the record its definitions were proposed in, with no chain prefix.",
        proposed
      ),
      with_proposal.(
        "publication-proposal-chain-name-is-a-label",
        "The proposal's chain is given as a label, not as the reference of the record that founded it.",
        "chain:r5e-dev/" <> proposed
      )
    ]
  end

  defp loose_tool_call do
    {:ok, %{document: document}} = Definitions.fetch(@base <> "/ToolCall")

    document
    |> put_in(["schema", "additionalProperties"], true)
    |> pop_in(["schema", "additionalProperties"])
    |> elem(1)
    |> Canonical.encode()
  end

  # An operator carries its own, looser definition under a base kind's
  # name, with a profile that maps the kind to it. The body matches that
  # definition and the profile; the trusted publisher never issued it.
  defp lookalike_definition(w) do
    path = @base <> "/ToolCall"
    bytes = loose_tool_call()

    own = profile(w.signer, schemas: Map.put(Definitions.schema_refs(), path, Ref.bytes(bytes)))
    w = %{w | profile: own, profile_ref: Profile.ref(own)}

    record =
      record(w, 1, nil, schema_ref: Ref.bytes(bytes), body: tool_body(%{"anything" => "goes"}))

    "definition-differs-from-published"
    |> vector(
      "A record cites a looser definition carried in the bundle under a base kind's name. The trusted publisher issued a different document for that kind.",
      bundle(w, [record],
        blobs: [{Profile.encode(own), nil}, {@args, nil}, {@policy, nil}, {bytes, nil}]
      ),
      [w.profile_ref]
    )
    |> with_publication()
  end

  defp unlisted_unauthorized_seal(w) do
    strict =
      profile(w.signer,
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:vectors:",
            actor_prefixes: ["urn:r5e:principal:vectors:", "urn:r5e:gateway:vectors"],
            issuer_keys: [w.signer.key_id],
            sealer_keys: []
          }
        ]
      )

    records = chain(w, 3)
    {seal, _manifest} = seal(w, records, profile_ref: Profile.ref(strict))
    refs = Enum.map(records, & &1.ref)
    {:ok, siblings} = Epoch.proof(refs, 1)
    chosen = Enum.at(records, 1)

    bundle(w, [chosen, seal],
      blobs: [
        {Profile.encode(w.profile), nil},
        {Profile.encode(strict), nil},
        {@args, nil},
        {@policy, nil}
      ],
      seals: [],
      proofs: [%{record: chosen.ref, seal: seal.ref, index: 1, siblings: siblings}],
      omissions:
        for(ref <- List.delete_at(refs, 1), do: %{ref: ref, reason: "not-selected"}) ++
          [%{ref: seal.evidence["body"]["manifestRef"], reason: "not-selected"}]
    )
  end

  defp issuer_outside(w),
    do: bundle(w, [record(w, 1, nil, actor: "urn:r5e:principal:elsewhere:mallory")])

  defp body_invalid(w),
    do: bundle(w, [record(w, 1, nil, body: tool_body(%{"unexpected" => true}))])

  defp other_definition(w),
    do: bundle(w, [record(w, 1, nil, definition_of: @base <> "/ModelCall")])

  defp policy_missing(signer) do
    w0 = world(signer)
    strict = profile(signer, policy_required_kinds: [@base <> "/ToolCall"])
    w = %{w0 | profile: strict, profile_ref: Profile.ref(strict)}
    body = Map.delete(tool_body(), "policy")

    bundle(w, [record(w, 1, nil, body: body)],
      blobs: [{Profile.encode(strict), nil}, {@args, nil}]
    )
  end

  # Rules the base definitions and the verifier gained before the first
  # permanent chain: a stream's seals in one line, bounded details, arrays
  # that are sets, and a tool result tied to its call.
  defp closure_cases(w, trusted) do
    stranger_seal = "evidence:sha256:" <> String.duplicate("5", 64)
    call = record(w, 1, nil, body: Map.put(tool_body(), "callId", "toolu_01"))

    result = fn overrides ->
      output = ~s({"stdout":"total 0\\n"})

      body =
        [
          content_ref: Ref.bytes(output),
          media_type: "application/json",
          size: byte_size(output),
          outcome: "completed",
          call: call.ref,
          call_id: "toolu_01"
        ]
        |> Body.response()
        |> Map.merge(overrides)
        |> Map.reject(fn {_k, v} -> v == :absent end)

      bundle(w, [call, record(w, 2, call.ref, kind_path: @base <> "/ToolResult", body: body)],
        blobs: [
          {Profile.encode(w.profile), nil},
          {@args, nil},
          {@policy, nil},
          {output, "application/json"}
        ]
      )
    end

    with_details = fn details ->
      bundle(w, [record(w, 1, nil, body: Map.put(tool_body(), "details", details))])
    end

    twice = Ref.bytes(@args)
    session = "urn:r5e:session:vectors:one"
    public = "urn:r5e:audience:public"

    disclosed = fn body ->
      bundle(w, [record(w, 1, nil, kind_path: @base <> "/Disclosure", body: body)])
    end

    whole =
      Body.disclosure(
        scope: session,
        excluding: [twice],
        recipient: public,
        outcome: "partial",
        details: %{"scan.rules" => "private-key,provider-token", "scan.flagged" => 1}
      )

    pieces =
      Body.disclosure(
        requested_refs: [twice, Ref.bytes(@policy)],
        provided_refs: [twice],
        recipient: "urn:r5e:principal:vectors:auditor",
        outcome: "partial"
      )

    [
      vector(
        "disclosure-of-a-session",
        "A whole session was provided to the public, with one piece of its content withheld and named.",
        disclosed.(whole),
        trusted
      ),
      vector(
        "disclosure-of-a-session-nothing-withheld",
        "A whole session was provided with nothing withheld. The empty list is present: nothing withheld is said, not left unsaid.",
        disclosed.(%{whole | "excluding" => [], "outcome" => "provided"}),
        trusted
      ),
      vector(
        "disclosure-of-a-session-silent-on-what-was-withheld",
        "A whole session was provided and the record does not say what, if anything, was withheld.",
        disclosed.(Map.delete(whole, "excluding")),
        trusted
      ),
      vector(
        "disclosure-of-named-pieces",
        "Two pieces were asked for and one was provided.",
        disclosed.(pieces),
        trusted
      ),
      vector(
        "disclosure-mixes-both-forms",
        "A record that names a session and also lists pieces asked for and provided. It is one or the other.",
        disclosed.(Map.merge(whole, Map.take(pieces, ["requestedRefs", "providedRefs"]))),
        trusted
      ),
      vector(
        "disclosure-of-pieces-without-what-was-provided",
        "Pieces were asked for and the record does not say which were provided.",
        disclosed.(Map.delete(pieces, "providedRefs")),
        trusted
      ),
      vector(
        "seal-second-follows-first",
        "Two seals of one stream, both carried: the second names the first, whose range ends just before its own begins.",
        two_seals(w, 2, :first),
        trusted
      ),
      vector(
        "seal-second-leaves-a-gap",
        "The second seal starts at position 3 and names a seal that ends at position 1. Position 2 would be sealed by neither.",
        two_seals(w, 1, :first),
        trusted
      ),
      vector(
        "seal-later-names-no-predecessor",
        "A seal that starts at position 3 and names no seal before it.",
        two_seals(w, 2, nil),
        trusted
      ),
      vector(
        "seal-first-names-a-predecessor",
        "A stream's first seal, starting at position 1, names a seal before it.",
        two_seals(w, 2, :first, %{"previousSeal" => stranger_seal}),
        trusted
      ),
      vector(
        "tool-result-names-its-call",
        "A tool call with the id the model gave it, and the tool's result pointing at that call under the same id.",
        result.(%{}),
        trusted
      ),
      vector(
        "tool-result-without-its-call",
        "A tool result that does not say which call it is the result of.",
        result.(%{"call" => :absent}),
        trusted
      ),
      vector(
        "details-with-control-characters",
        "A detail whose value holds a backspace, tab, newline, form feed, carriage return and U+0001. The record's bytes use the short escapes for the first five.",
        with_details.(%{"note" => "a\b\t\n\f\r\u0001z"}),
        trusted
      ),
      vector(
        "details-nested",
        "A detail whose value is an object. Details are named scalars.",
        with_details.(%{"parser" => %{"name" => "anthropic"}}),
        trusted
      ),
      vector(
        "details-name-outside-pattern",
        "A detail whose name has a space in it.",
        with_details.(%{"upstream host" => "api.example"}),
        trusted
      ),
      vector(
        "details-too-many",
        "Sixty-five details, one more than the definition allows.",
        with_details.(Map.new(1..65, &{"k#{&1}", &1})),
        trusted
      ),
      vector(
        "details-value-too-long",
        "A detail whose value is 2,049 bytes, one more than the definition allows.",
        with_details.(%{"note" => String.duplicate("a", 2049)}),
        trusted
      ),
      vector(
        "array-repeats-an-item",
        "A policy evaluation lists the same input twice. The inputs are a set.",
        bundle(w, [
          record(w, 1, nil, body: put_in(tool_body(), ["policy", "inputRefs"], [twice, twice]))
        ]),
        trusted
      )
    ]
  end

  # Four records of one stream under two seals. `split` is how many the
  # first seal covers; the second always starts at position 3. `link`
  # says whether the second names the first.
  defp two_seals(w, split, link, first_body \\ %{}) do
    records = chain(w, 4)
    refs = Enum.map(records, & &1.ref)

    {body_a, manifest_a} = Epoch.seal_body(@stream, 1, Enum.take(refs, split), nil)

    first =
      record(w, 1, nil,
        kind_path: @base <> "/EpochSeal",
        stream: @control,
        actor: "urn:r5e:gateway:vectors",
        body: Map.merge(body_a, first_body)
      )

    {body_b, manifest_b} =
      Epoch.seal_body(@stream, 3, Enum.drop(refs, 2), if(link == :first, do: first.ref))

    second =
      record(w, 2, first.ref,
        kind_path: @base <> "/EpochSeal",
        stream: @control,
        actor: "urn:r5e:gateway:vectors",
        body: body_b
      )

    bundle(w, records ++ [first, second],
      blobs: [
        {Profile.encode(w.profile), nil},
        {@args, nil},
        {@policy, nil},
        {manifest_a, nil},
        {manifest_b, nil}
      ],
      seals: [first.ref, second.ref]
    )
  end

  # A record whose signed bytes hold a property name above U+FFFF. The
  # reference signer refuses such a record, so the bytes are made by hand:
  # a sound record is encoded with a stand-in name, the name is replaced,
  # and the result is signed as it stands. The signature is good; the
  # bytes are not canonical, so the record has no identity.
  defp astral_name_case(w, trusted) do
    evidence =
      Evidence.new(
        kind_path: @base <> "/ToolCall",
        schema_ref: elem(Definitions.fetch(@base <> "/ToolCall"), 1).ref,
        profile_ref: w.profile_ref,
        issuer: w.signer.key_id,
        actor: @actor,
        stream: @stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.add(@at, 1, :second),
        session: "urn:r5e:session:vectors:one",
        body: Map.put(tool_body(), "details", %{"standin" => "v"})
      )

    {:ok, sound} = Evidence.encode(evidence)
    payload = String.replace(sound, ~s("standin"), ~s("\u{1F511}"))
    {:ok, signature} = w.signer.sign.(Envelope.message(payload))
    envelope = Envelope.assemble(payload, [{w.signer.key_id, signature}])

    bundle = single(w)

    vector(
      "name-above-the-basic-plane",
      "A correctly signed record whose bytes hold a property name above U+FFFF (a key emoji). Such a value has no canonical form, so the record has no identity and nothing else about it is checked.",
      put_in(bundle, ["records"], [%{"ref" => Evidence.ref(payload), "envelope" => envelope}]),
      trusted
    )
  end

  # Positions 1 to 4 sealed, and positions 1 to 2 sealed again by a later
  # record of the same control stream. Each seal is sound alone.
  defp overlapping_seals_case(w, trusted) do
    records = chain(w, 4)
    refs = Enum.map(records, & &1.ref)
    {body_a, manifest_a} = Epoch.seal_body(@stream, 1, refs, nil)
    {body_b, manifest_b} = Epoch.seal_body(@stream, 1, Enum.take(refs, 2), nil)

    seal = fn seq, previous, body ->
      record(w, seq, previous,
        kind_path: @base <> "/EpochSeal",
        stream: @control,
        actor: "urn:r5e:gateway:vectors",
        body: body
      )
    end

    first = seal.(1, nil, body_a)
    second = seal.(2, first.ref, body_b)

    vector(
      "seals-of-one-stream-overlap",
      "Two seals of one stream, on an unbroken control stream: one over positions 1 to 4, a later one over positions 1 to 2. Each is sound alone and neither names a predecessor. A stream's seals form one line, so both fail and neither shows anything.",
      bundle(w, records ++ [first, second],
        blobs: [
          {Profile.encode(w.profile), nil},
          {@args, nil},
          {@policy, nil},
          {manifest_a, nil},
          {manifest_b, nil}
        ],
        seals: [first.ref, second.ref]
      ),
      trusted
    )
  end

  # An extension kind with an open map, whose names are outside ASCII.
  # Their order in the signed bytes is byte order, which for names within
  # the Basic Multilingual Plane is also RFC 8785's order.
  defp labelled_case(issuer) do
    %{kind_path: path, bytes: bytes, ref: definition} = extension_kind("Labelled")
    extended = profile(issuer, schemas: Map.put(Definitions.schema_refs(), path, definition))

    evidence =
      Evidence.new(
        kind_path: path,
        schema_ref: definition,
        profile_ref: Profile.ref(extended),
        issuer: issuer.key_id,
        actor: @actor,
        stream: "urn:r5e:stream:vectors:labels:a1b2c3d4e5f6",
        seq: 1,
        previous: nil,
        captured_at: @at,
        body: %{
          "labels" => %{
            "zone" => "a",
            "étage" => "3",
            "区域" => "北",
            "\uFFFD" => "replacement",
            "Zone" => "A"
          }
        }
      )

    {:ok, signed} = Envelope.sign(evidence, issuer)

    {:ok, bundle} =
      Export.build(
        records: [signed.envelope],
        blobs: [{Profile.encode(extended), nil}, {bytes, nil}],
        keys: [key(issuer)]
      )

    vector(
      "names-outside-ascii",
      "An extension kind with an open map whose names include accented, Chinese and U+FFFD characters. The record's bytes order them by their UTF-8 bytes.",
      bundle,
      [Profile.ref(extended)]
    )
  end

  defp blob_mismatch(w) do
    b = single(w)
    index = Enum.find_index(b["blobs"], &(&1["ref"] == Ref.bytes(@args)))
    put_in(b, ["blobs", Access.at(index), "base64"], Base.encode64(~s({"command":"rm -rf /"})))
  end

  defp seal_root_wrong(w) do
    records = chain(w, 3)

    {seal, manifest} =
      seal(w, records, body: %{"root" => Epoch.root(Enum.map(Enum.take(records, 2), & &1.ref))})

    bundle(w, records ++ [seal],
      blobs: [{Profile.encode(w.profile), nil}, {@args, nil}, {@policy, nil}, {manifest, nil}],
      seals: [seal.ref]
    )
  end

  # An extension kind in its own API group, with and without the
  # definition it cites carried in the bundle.
  @extension """
  %HUML v0.2.0
  format: "r5e.contract-package/v2"
  package: "acme.reviews"
  group: "acme.example"
  version: "v1"
  imports::
    core: "r5e.core"

  kinds::
    SafetyReview::
      substrate: "event"
      naming::
        mode: "content"
      description: "A reviewer's verdict."
      schema::
        additionalProperties: false
        required::
          - "verdict"
        properties::
          verdict::
            type: "string"
            enum:: "pass", "fail"

    Handover::
      substrate: "event"
      naming::
        mode: "content"
      description: "Custody of an item passes from the issuer to a receiver, and both sign."
      signatures: 2
      schema::
        additionalProperties: false
        required::
          - "item"
          - "receiver"
        properties::
          item::
            type: "string"
          receiver::
            use: "core.KeyId"
            matchesSigner: 2

    Labelled::
      substrate: "event"
      naming::
        mode: "content"
      description: "Free labels on an item."
      schema::
        additionalProperties: false
        required::
          - "labels"
        properties::
          labels::
            type: "object"
            maxEntries: 16
            values::
              type: "string"
              maxLength: 64
  """

  @doc """
  A kind outside the base set, as an extension author would produce it:
  written in a small package, compiled, and expanded to its definition
  document. Returns the kind path with that document's bytes and
  reference.
  """
  @spec extension_package() :: %{kind_path: String.t(), bytes: binary(), ref: Ref.t()}
  def extension_package, do: extension_kind("SafetyReview")

  defp extension_kind(kind) do
    core = File.read!(Path.join(:code.priv_dir(:recurse_provenance), "definitions/r5e.core.huml"))

    {:ok, compiled} =
      Grammar.compile([{"r5e.core.huml", core}, {"acme.reviews.huml", @extension}])

    path = "acme.example/v1/" <> kind
    %{^path => %{bytes: bytes, ref: ref}} = Definitions.expand(compiled)
    %{kind_path: path, bytes: bytes, ref: ref}
  end

  # A kind whose definition asks for two signatures: the issuer's, and
  # the receiver's, whose key id the body names.
  defp handover_cases(issuer) do
    %{kind_path: path, bytes: bytes, ref: definition} = extension_kind("Handover")
    receiver = signer("es256")
    stranger = signer("es384")

    extended = profile(issuer, schemas: Map.put(Definitions.schema_refs(), path, definition))
    profile_ref = Profile.ref(extended)

    evidence =
      Evidence.new(
        kind_path: path,
        schema_ref: definition,
        profile_ref: profile_ref,
        issuer: issuer.key_id,
        actor: @actor,
        stream: "urn:r5e:stream:vectors:handovers:a1b2c3d4e5f6",
        seq: 1,
        previous: nil,
        captured_at: @at,
        body: %{"item" => "pallet 7", "receiver" => receiver.key_id}
      )

    build = fn signers, change ->
      {:ok, signed} = Envelope.sign(evidence, signers)

      {:ok, bundle} =
        Export.build(
          records: [change.(signed.envelope)],
          blobs: [{Profile.encode(extended), nil}, {bytes, nil}],
          keys: Enum.map([issuer, receiver, stranger], &key/1)
        )

      bundle
    end

    same = & &1

    flip_second = fn envelope ->
      update_in(envelope, ["signatures", Access.at(1), "sig"], fn sig ->
        <<first, rest::binary>> = Base.decode64!(sig)
        Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
      end)
    end

    # The same definition with the receiver made optional. Position 2
    # would then be checked against nothing in a body that leaves it
    # out, so the document is not one a verifier may use.
    loose_bytes =
      bytes
      |> RecurseVerify.Canonical.decode_json()
      |> elem(1)
      |> put_in(["schema", "required"], ["item"])
      |> RecurseVerify.Canonical.encode()

    loose = Ref.bytes(loose_bytes)
    loose_profile = profile(issuer, schemas: Map.put(Definitions.schema_refs(), path, loose))

    loose_evidence =
      evidence
      |> Map.merge(%{"schemaRef" => loose, "profileRef" => Profile.ref(loose_profile)})
      |> put_in(["body"], %{"item" => "pallet 7"})

    {:ok, loose_signed} = Envelope.sign(loose_evidence, [issuer, stranger])

    {:ok, loose_bundle} =
      Export.build(
        records: [loose_signed.envelope],
        blobs: [{Profile.encode(loose_profile), nil}, {loose_bytes, nil}],
        keys: Enum.map([issuer, stranger], &key/1)
      )

    [
      vector(
        "second-signer-bound-to-optional-field",
        "A definition asks for two signatures but names the second signer on a field a body may leave out, and this body does. Any key could have signed second. The definition is not one a verifier may use.",
        loose_bundle,
        [Profile.ref(loose_profile)]
      ),
      vector(
        "valid-two-signatures",
        "A kind whose definition asks for two signatures and names the second signer in the body. Both signed; every check holds.",
        build.([issuer, receiver], same),
        [profile_ref]
      ),
      vector(
        "second-signature-missing",
        "The same record signed by its issuer alone. The definition asks for two signatures.",
        build.([issuer], same),
        [profile_ref]
      ),
      vector(
        "second-signer-not-the-one-named",
        "The second signature is valid but is by a key other than the receiver the body names.",
        build.([issuer, stranger], same),
        [profile_ref]
      ),
      vector(
        "second-signature-bad",
        "The receiver's signature has a flipped bit. The issuer's still verifies; each signature is reported on its own.",
        build.([issuer, receiver], flip_second),
        [profile_ref]
      ),
      vector(
        "third-signature-not-asked-for",
        "Both required signers signed and a third key added its own. The definition asks for exactly two.",
        build.([issuer, receiver, stranger], same),
        [profile_ref]
      )
    ]
  end

  defp extension_case(signer, carried?) do
    %{bytes: bytes, ref: package_ref} = extension_package()

    path = "acme.example/v1/SafetyReview"
    extended = profile(signer, schemas: Map.put(Definitions.schema_refs(), path, package_ref))
    w = %{signer: signer, profile: extended, profile_ref: Profile.ref(extended)}

    evidence =
      Evidence.new(
        kind_path: path,
        schema_ref: package_ref,
        profile_ref: w.profile_ref,
        issuer: signer.key_id,
        actor: @actor,
        stream: "urn:r5e:stream:vectors:reviews:a1b2c3d4e5f6",
        seq: 1,
        previous: nil,
        captured_at: @at,
        body: %{"verdict" => "pass"}
      )

    {:ok, signed} = Envelope.sign(evidence, signer)
    blobs = [{Profile.encode(extended), nil}] ++ if(carried?, do: [{bytes, nil}], else: [])
    {:ok, bundle} = Export.build(records: [signed.envelope], blobs: blobs, keys: [key(signer)])

    if carried?,
      do:
        vector(
          "extension-kind-with-definition",
          "A record of a kind from another package, with that package's manifest carried. The body is checked against it.",
          bundle,
          [w.profile_ref]
        ),
      else:
        vector(
          "extension-kind-without-definition",
          "The same record without the manifest. The envelope is sound; the body is reported as not checked.",
          bundle,
          [w.profile_ref]
        )
  end
end
