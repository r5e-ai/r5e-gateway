defmodule Recurse.Gateway.Evidence.ClaimTest do
  @moduledoc """
  A node begins its own chain, a customer claims it with a root key the
  node never holds, and a reader who pins the resulting chain by name
  can check the start from the records alone.

  `async: false` because evidence capture is node-wide.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Evidence.ClaimHandler
  alias Recurse.Gateway.Provenance.{Claim, Grants, Roots, Runtime}
  alias Recurse.Provenance.{Envelope, Export, Key, Pipeline, Publication}
  alias Recurse.Providers.Impls.PostgresEvidenceStore
  alias Recurse.Providers.Repo

  setup %{tmp_dir: dir} = ctx do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    publisher = Key.generate("ed25519")
    # A publication that leaves one installed definition out, when asked.
    documents =
      if ctx[:short_publication],
        do: tl(Recurse.Provenance.Definitions.documents()),
        else: Recurse.Provenance.Definitions.documents()

    {:ok, published} = Publication.issue(publisher, name: "test-steward", documents: documents)
    deployment = "claim-#{System.unique_integer([:positive])}"

    start_supervised!(
      {Runtime,
       deployment: deployment,
       signer: Key.generate("ed25519"),
       store: {PostgresEvidenceStore, Repo},
       dir: dir,
       partitions: 1,
       flush_interval_ms: 20,
       start_chain?: Map.get(ctx, :start_chain, false),
       publications: if(Map.get(ctx, :published, true), do: [published], else: [])}
    )

    on_exit(fn -> :persistent_term.erase({Runtime, :info}) end)
    %{dir: dir, publisher: publisher, published: published, deployment: deployment}
  end

  defp code(dir), do: dir |> Path.join("claim.code") |> File.read!()

  defp ask(root, code, change \\ %{}) do
    Map.merge(
      %{
        "code" => code,
        "claimedBy" => root.key_id,
        "roots" => [
          %{
            "publicKey" => %{
              "algorithm" => root.algorithm,
              "bytes" => Base.encode64(root.public_key)
            },
            "holder" => "person",
            "custody" => "hardware"
          }
        ],
        "threshold" => 1
      },
      change
    )
  end

  defp signed_by(root, payload64) do
    {:ok, signature} = root.sign.(Envelope.message(Base.decode64!(payload64)))
    %{"keyid" => root.key_id, "sig" => Base.encode64(signature)}
  end

  test "a node starts its chain, a root claims it, and the chain can be pinned and checked",
       %{dir: dir, publisher: publisher, published: published, deployment: deployment} do
    assert %{"state" => "not_started"} = Claim.describe()
    assert :unclaimed = Claim.ensure_started()
    assert :unclaimed = Claim.ensure_started()

    # The two files exist and only their owner can read them.
    for file <- ["bootstrap.key", "claim.code"] do
      assert Bitwise.band(File.stat!(Path.join(dir, file)).mode, 0o077) == 0
    end

    assert %{
             "state" => "unclaimed",
             "chain" => nil,
             "chainStarted" => %{"ref" => started},
             "bootstrapKey" => %{"keyid" => bootstrap}
           } = Claim.describe()

    refute Claim.claimed?()
    root = Key.generate("ed25519")

    assert {:error, :wrong_claim_code} = Claim.prepare(ask(root, "not the code"))

    assert {:ok,
            %{
              "payload" => payload,
              "ticket" => ticket,
              "chainStarted" => %{"ref" => ^started},
              "bootstrapKey" => %{"keyid" => ^bootstrap},
              "publication" => ^published,
              "bootstrapProfile" => %{"ref" => _, "base64" => _}
            }} = Claim.prepare(ask(root, code(dir)))

    # What the operator's tool checks before the root signs anything.
    terms = payload |> Base.decode64!() |> JSON.decode!()
    assert terms["kind"] == "Deployment" and terms["seq"] == 2 and terms["previous"] == started
    assert terms["body"]["accepts"] == started
    assert terms["body"]["claimedBy"] == root.key_id
    assert [%{"key" => key, "holder" => "person"}] = terms["body"]["roots"]
    assert key == root.key_id

    request = %{
      "code" => code(dir),
      "payload" => payload,
      "ticket" => ticket,
      "rootSignature" => signed_by(root, payload)
    }

    # Somebody else's signature, or a signature by the right key over the
    # wrong bytes, claims nothing.
    thief = Key.generate("ed25519")

    assert {:error, :signature_is_not_the_claimants} =
             Claim.finalize(%{request | "rootSignature" => signed_by(thief, payload)})

    assert {:error, :bad_signature} =
             Claim.finalize(%{
               request
               | "rootSignature" => %{
                   "keyid" => root.key_id,
                   "sig" => Base.encode64(:crypto.strong_rand_bytes(64))
                 }
             })

    assert {:ok, :created,
            %{
              "chain" => chain,
              "deploymentRecord" => %{"ref" => chain, "envelope" => envelope},
              "gatewayKey" => %{"keyid" => gateway},
              "streamPrefix" => prefix
            }} = Claim.finalize(request)

    assert gateway == Runtime.info().key_id
    assert prefix == "urn:r5e:stream:#{deployment}:"
    assert [%{"keyid" => ^bootstrap}, %{"keyid" => claimant}] = envelope["signatures"]
    assert claimant == root.key_id

    # The bootstrap key and the code are gone; the claim cannot be made
    # again, and the same request answers the same.
    refute File.exists?(Path.join(dir, "bootstrap.key"))
    refute File.exists?(Path.join(dir, "claim.code"))
    assert Claim.claimed?()
    assert :claimed = Claim.ensure_started()
    assert {:ok, :already, %{"chain" => ^chain}} = Claim.finalize(request)
    assert {:error, :already_claimed} = Claim.prepare(ask(thief, "anything"))

    assert %{"state" => "claimed", "chain" => ^chain, "deploymentRecord" => %{"ref" => ^chain}} =
             described = Claim.describe()

    # A reader holding only the records pins the chain by name.
    {:ok, bare} =
      Export.build(
        records: [described["chainStarted"]["envelope"], envelope],
        keys: [
          %{key_id: root.key_id, algorithm: root.algorithm, public_key: root.public_key},
          %{
            key_id: bootstrap,
            algorithm: "ed25519",
            public_key: Base.decode64!(described["bootstrapKey"]["bytes"])
          }
        ]
      )

    {:ok, profile} = PostgresEvidenceStore.get_blob(Repo, terms["profileRef"])

    bundle =
      Publication.carry(bare, [
        published,
        %{"blobs" => [%{"ref" => terms["profileRef"], "base64" => Base.encode64(profile)}]}
      ])

    report =
      Export.verify(bundle, trusted_chain: chain, trusted_publishers: [publisher.key_id])

    assert [] == Enum.reject(report.findings, &(&1.result == :ok))
    assert [_, _] = Enum.filter(report.findings, &(&1.check == :start))
    assert %{"chain" => ^chain, "headSeq" => 2, "deployment" => ^deployment} = report.start

    # The start stream is sealed like any other.
    assert {:ok, [_ | _]} = Pipeline.seal_all(Runtime.pipeline(), Runtime.info().actor)
  end

  test "the terms of a claim are checked before anything is offered for signing", %{dir: dir} do
    :unclaimed = Claim.ensure_started()
    root = Key.generate("ed25519")
    other = Key.generate("ed25519")
    code = code(dir)

    assert {:error, :claimed_by_is_not_a_root} =
             Claim.prepare(ask(root, code, %{"claimedBy" => other.key_id}))

    assert {:error, :threshold_exceeds_roots} =
             Claim.prepare(ask(root, code, %{"threshold" => 2}))

    assert {:error, :recovery_key_is_a_root} =
             Claim.prepare(ask(root, code, %{"recoveryKeys" => [root.key_id]}))

    assert {:error, :duplicate_root} =
             Claim.prepare(
               ask(root, code, %{"roots" => ask(root, code)["roots"] ++ ask(root, code)["roots"]})
             )

    assert {:error, :unreadable_public_key} =
             Claim.prepare(
               ask(root, code, %{
                 "roots" => [%{"publicKey" => %{"algorithm" => "ed25519", "bytes" => "AAAA"}}]
               })
             )

    assert {:error, :malformed_request} = Claim.prepare(%{"code" => code})

    # A recovery key is declared by its id alone; its public key is not asked for.
    assert {:ok, %{"payload" => payload}} =
             Claim.prepare(ask(root, code, %{"recoveryKeys" => [other.key_id]}))

    assert %{"body" => %{"recoveryKeys" => [recovery]}} =
             payload |> Base.decode64!() |> JSON.decode!()

    assert recovery == other.key_id
  end

  test "over HTTP: the start is public, and the claim steps answer only to the code", %{dir: dir} do
    :unclaimed = Claim.ensure_started()
    root = Key.generate("ed25519")

    call = fn method, path, handler, body ->
      conn = handler.(%{Plug.Test.conn(method, path) | body_params: body})
      {conn.status, JSON.decode!(conn.resp_body)}
    end

    assert {200, %{"state" => "unclaimed", "bootstrapKey" => %{"keyid" => _}}} =
             call.(:get, "/v1/deployment", &ClaimHandler.describe/1, %{})

    assert {403, %{"error" => "wrong_claim_code"}} =
             call.(
               :post,
               "/v1/deployment/claim/prepare",
               &ClaimHandler.prepare/1,
               ask(root, "no")
             )

    assert {400, %{"error" => "malformed_request"}} =
             call.(:post, "/v1/deployment/claim/prepare", &ClaimHandler.prepare/1, %{})

    assert {200, %{"payload" => payload, "ticket" => ticket}} =
             call.(
               :post,
               "/v1/deployment/claim/prepare",
               &ClaimHandler.prepare/1,
               ask(root, code(dir))
             )

    request = %{
      "code" => code(dir),
      "payload" => payload,
      "ticket" => ticket,
      "rootSignature" => signed_by(root, payload)
    }

    assert {201, %{"chain" => chain}} =
             call.(:post, "/v1/deployment/claim/finalize", &ClaimHandler.finalize/1, request)

    assert {200, %{"chain" => ^chain}} =
             call.(:post, "/v1/deployment/claim/finalize", &ClaimHandler.finalize/1, request)

    assert {409, %{"error" => "already_claimed"}} =
             call.(
               :post,
               "/v1/deployment/claim/prepare",
               &ClaimHandler.prepare/1,
               ask(root, "anything")
             )

    assert {200, %{"state" => "claimed", "chain" => ^chain}} =
             call.(:get, "/v1/deployment", &ClaimHandler.describe/1, %{})
  end

  defp eventually(check, tries \\ 100) do
    case check.() do
      nil when tries > 0 ->
        Process.sleep(20)
        eventually(check, tries - 1)

      found ->
        found
    end
  end

  # The record by which a key introduces itself, alone on its own stream.
  defp introduction(person, deployment) do
    "key:ed25519:sha256:" <> hex = person.key_id
    stream = "urn:r5e:stream:#{deployment}:authority:principal:#{hex}"

    {:ok, profile} =
      Recurse.Provenance.Profile.new(
        bindings: [
          %{
            stream_prefix: stream,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [person.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "made by the person",
        deployment_policy_ref: Recurse.Provenance.Ref.bytes("person"),
        policy_required_kinds: []
      )

    path = "provenance.r5e.io/v2/Principal"

    evidence =
      Recurse.Provenance.Evidence.new(
        kind_path: path,
        schema_ref: elem(Recurse.Provenance.Definitions.fetch(path), 1).ref,
        profile_ref: Recurse.Provenance.Profile.ref(profile),
        issuer: person.key_id,
        actor: "urn:r5e:user:someone",
        stream: stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{
          "key" => person.key_id,
          "publicKey" => %{
            "algorithm" => person.algorithm,
            "bytes" => Base.encode64(person.public_key)
          },
          "holder" => "person",
          "custody" => "hardware",
          "identity" => "urn:r5e:user:someone"
        }
      )

    {:ok, signed} = Envelope.sign(evidence, person)
    encoded = Recurse.Provenance.Profile.encode(profile)

    %{
      "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
      "keys" => [
        %{
          "keyid" => person.key_id,
          "algorithm" => person.algorithm,
          "bytes" => Base.encode64(person.public_key)
        }
      ],
      "blobs" => [
        %{"ref" => Recurse.Provenance.Ref.bytes(encoded), "base64" => Base.encode64(encoded)}
      ]
    }
  end

  defp together(sets) do
    for field <- ~w[records keys blobs], into: %{} do
      {field, sets |> Enum.flat_map(& &1[field]) |> Enum.uniq()}
    end
  end

  defp grant(root, deployment, subject, change \\ %{}, at \\ {1, nil}) do
    {seq, previous} = at
    "key:ed25519:sha256:" <> hex = root.key_id
    stream = "urn:r5e:stream:#{deployment}:authority:root:#{hex}"

    {:ok, profile} =
      Recurse.Provenance.Profile.new(
        bindings: [
          %{
            stream_prefix: stream,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [root.key_id],
            sealer_keys: [subject]
          }
        ],
        failure_domain: "made offline by the root",
        deployment_policy_ref: Recurse.Provenance.Ref.bytes("root"),
        policy_required_kinds: []
      )

    base = "provenance.r5e.io/v2/"
    now = DateTime.utc_now()

    evidence =
      Recurse.Provenance.Evidence.new(
        kind_path: base <> "Endorsement",
        schema_ref: elem(Recurse.Provenance.Definitions.fetch(base <> "Endorsement"), 1).ref,
        profile_ref: Recurse.Provenance.Profile.ref(profile),
        issuer: root.key_id,
        actor: "urn:r5e:root-ceremony",
        stream: stream,
        seq: seq,
        previous: previous,
        captured_at: now,
        body:
          Map.merge(
            %{
              "subject" => subject,
              "kinds" => Enum.map(~w[ToolCall ToolResult EpochSeal Badge], &(base <> &1)),
              "streamPrefixes" => ["urn:r5e:stream:#{deployment}:"],
              "mayEndorse" => true,
              "notBefore" =>
                now |> DateTime.add(-60) |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
              "notAfter" =>
                now |> DateTime.add(86_400) |> DateTime.truncate(:second) |> DateTime.to_iso8601()
            },
            change
          )
      )

    {:ok, signed} = Envelope.sign(evidence, root)
    encoded = Recurse.Provenance.Profile.encode(profile)

    %{
      "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
      "keys" => [
        %{
          "keyid" => root.key_id,
          "algorithm" => root.algorithm,
          "bytes" => Base.encode64(root.public_key)
        }
      ],
      "blobs" => [
        %{"ref" => Recurse.Provenance.Ref.bytes(encoded), "base64" => Base.encode64(encoded)}
      ]
    }
  end

  @tag start_chain: true
  test "nothing is sealed until a root has given the gateway a grant, and the grant is recorded and sealed",
       %{dir: dir, deployment: deployment, publisher: publisher} do
    # The node began its chain by itself at start.
    assert %{"state" => "unclaimed"} =
             eventually(fn ->
               with %{"state" => "unclaimed"} = found <- Claim.describe(),
                    do: found,
                    else: (_ -> nil)
             end)

    root = Key.generate("ed25519")
    gateway = Runtime.info().key_id

    # Before the claim the gateway carries no agent traffic; it offers the
    # claim and its own health.
    refute Runtime.serving?()
    through = fn path -> Recurse.Gateway.Router.call(Plug.Test.conn(:get, path), []) end

    assert %{status: 503, resp_body: ~s({"error":"deployment_not_claimed"})} =
             through.("/v1/schemas/index.json")

    assert %{status: 200} = through.("/v1/deployment")

    # Before the claim, grants are not taken and nothing is sealed.
    assert {:error, :not_claimed} = Grants.accept(grant(root, deployment, gateway))
    assert {:ok, []} = Runtime.seal()

    {:ok, %{"payload" => payload, "ticket" => ticket}} = Claim.prepare(ask(root, code(dir)))

    {:ok, :created, %{"chain" => chain}} =
      Claim.finalize(%{
        "code" => code(dir),
        "payload" => payload,
        "ticket" => ticket,
        "rootSignature" => signed_by(root, payload)
      })

    assert Runtime.serving?()
    refute match?(%{status: 503}, through.("/v1/schemas/index.json"))

    # Claimed, and the gateway's key still has no grant: still nothing sealed.
    assert {:ok, []} = Runtime.seal()
    assert Runtime.info().authority == nil

    # What is refused: a grant from a key that is not one of the declared
    # roots, a grant that names some other key, and anything that is not a grant.
    stranger = Key.generate("ed25519")
    assert {:error, :grant_does_not_hold} = Grants.accept(grant(stranger, deployment, gateway))

    assert {:error, :no_grant_names_this_gateway} =
             Grants.accept(grant(root, deployment, stranger.key_id))

    assert {:error, :unreadable_grant} = Grants.accept(%{"records" => [], "keys" => []})

    described = Claim.describe()

    assert {:error, :only_endorsements} =
             Grants.accept(%{
               grant(root, deployment, gateway)
               | "records" => [described["deploymentRecord"]]
             })

    # The root's grant is taken, the gateway acts under it at once, and it
    # is kept for the next start.
    given = grant(root, deployment, gateway)
    assert {:ok, [recorded]} = Grants.accept(given)
    assert %{endorsement: %{ref: ^recorded}} = Runtime.info().authority
    assert File.exists?(Grants.file(dir))

    # The same grant again changes nothing; a different one at the same
    # position is a fork and is refused.
    assert {:ok, [^recorded]} = Grants.accept(given)

    assert {:error, :stream_fork_refused} =
             Grants.accept(grant(root, deployment, gateway, %{"mayEndorse" => false}))

    # A person's key introduces itself. That record is taken with a grant
    # to the same key and not without one.
    person = Key.generate("ed25519")
    introduced = introduction(person, deployment)
    [%{"ref" => introduction}] = introduced["records"]

    assert {:error, :principal_without_its_grant} = Grants.accept(together([given, introduced]))

    to_person = grant(root, deployment, person.key_id, %{"mayEndorse" => false}, {2, recorded})
    assert {:ok, taken} = Grants.accept(together([given, to_person, introduced]))
    assert introduction in taken

    assert {:ok, %{stream: stream, seq: 1}} =
             PostgresEvidenceStore.fetch(Repo, introduction)

    assert String.starts_with?(stream, "urn:r5e:stream:#{deployment}:authority:principal:")

    # Now the start stream and the root's grant are sealed, by a seal made
    # while the gateway's grant is in force.
    assert {:ok, seals} = Runtime.seal()
    assert length(seals) >= 2

    # The start, the grant and the seals over them, read by someone who
    # pins the chain: everything that has authority has it from the roots
    # the claim declared.
    store = {PostgresEvidenceStore, Repo}
    {:ok, start} = PostgresEvidenceStore.range(Repo, Claim.stream(deployment), 1, 2)
    {:ok, granted} = PostgresEvidenceStore.fetch(Repo, recorded)

    sealed =
      for entry <- start ++ [granted],
          {:ok, seal} <- [PostgresEvidenceStore.seal_covering(Repo, entry.stream, entry.seq)],
          uniq: true,
          do: seal

    {:ok, bundle} =
      Recurse.Provenance.Exporter.bundle(store, start ++ [granted] ++ sealed, %{})

    report = Export.verify(bundle, trusted_chain: chain)
    authority = for %{check: :authority} = f <- report.findings, do: {f.result, f.code}

    assert authority != []
    assert Enum.all?(authority, &(&1 == {:ok, "ok"}))
    assert [] == Enum.filter(report.findings, &(&1.result == :failed))

    # Every export carries all of that without being asked: the start, the
    # grant and the seals over both. An export of nothing but what the
    # gateway carries is a complete, checkable account of its standing.
    {:ok, empty} = Export.build(records: [])
    carried = Recurse.Gateway.Provenance.Carried.carry(empty)

    whole =
      Export.verify(carried, trusted_chain: chain, trusted_publishers: [publisher.key_id])

    assert [] == Enum.reject(whole.findings, &(&1.result == :ok))
    assert [_, _ | _] = Enum.filter(whole.findings, &(&1.check == :epoch))
    assert %{"chain" => ^chain, "headSeq" => 2} = whole.start

    # Grants are public once exported, and the route asks for no sign-in.
    # Sending back a grant that has run out must change nothing: the
    # gateway keeps the standing it has.
    standing = Runtime.info().authority
    past = DateTime.utc_now() |> DateTime.add(-3600) |> DateTime.truncate(:second)

    expired =
      grant(Key.generate("ed25519"), deployment, gateway, %{
        "notBefore" => past |> DateTime.add(-3600) |> DateTime.to_iso8601(),
        "notAfter" => DateTime.to_iso8601(past)
      })

    assert {:error, :grant_does_not_hold} = Grants.accept(expired)

    lapsed =
      grant(root, deployment, gateway, %{
        "notBefore" => past |> DateTime.add(-3600) |> DateTime.to_iso8601(),
        "notAfter" => DateTime.to_iso8601(past)
      })

    assert {:error, :grant_not_in_force} = Grants.accept(lapsed)
    assert Runtime.info().authority == standing
    assert %{"gatewayKey" => %{"keyid" => ^gateway}} = Claim.describe()
  end

  defp own_profile(signer, stream) do
    {:ok, profile} =
      Recurse.Provenance.Profile.new(
        bindings: [
          %{
            stream_prefix: stream,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [signer.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "made offline",
        deployment_policy_ref: Recurse.Provenance.Ref.bytes("root"),
        policy_required_kinds: []
      )

    profile
  end

  defp wire_blob(profile) do
    encoded = Recurse.Provenance.Profile.encode(profile)
    %{"ref" => Recurse.Provenance.Ref.bytes(encoded), "base64" => Base.encode64(encoded)}
  end

  defp wire_key(signer),
    do: %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }

  defp public(signer),
    do: %{"algorithm" => signer.algorithm, "bytes" => Base.encode64(signer.public_key)}

  defp start_evidence(kind, signer, stream, seq, previous, body) do
    path = "provenance.r5e.io/v2/" <> kind

    Recurse.Provenance.Evidence.new(
      kind_path: path,
      schema_ref: elem(Recurse.Provenance.Definitions.fetch(path), 1).ref,
      profile_ref: Recurse.Provenance.Profile.ref(own_profile(signer, stream)),
      issuer: signer.key_id,
      actor: "urn:r5e:root-ceremony",
      stream: stream,
      seq: seq,
      previous: previous,
      captured_at: DateTime.utc_now(),
      body: body
    )
  end

  # A change of roots proposed by `signer`, replacing the roots with `new`.
  defp change(signer, authorization, new, deployment, described) do
    stream = Claim.stream(deployment)

    evidence =
      start_evidence(
        "RootsChanged",
        signer,
        stream,
        described["startHead"] + 1,
        described["chain"],
        %{
          "chain" => described["chain"],
          "replaces" => described["chain"],
          "authorization" => authorization,
          "signer" => signer.key_id,
          "signerKey" => public(signer),
          "roots" => [%{"key" => new.key_id, "publicKey" => public(new)}],
          "threshold" => 1,
          "reason" => "the first root is being retired"
        }
      )

    {:ok, signed} = Envelope.sign(evidence, signer)
    {%{"ref" => signed.ref, "envelope" => signed.envelope}, own_profile(signer, stream)}
  end

  defp approve(changed, root, who, key, deployment) do
    stream =
      "urn:r5e:stream:#{deployment}:authority:approval:#{System.unique_integer([:positive])}"

    evidence =
      start_evidence("RootChangeApproval", root, stream, 1, nil, %{
        "change" => changed["ref"],
        "root" => root.key_id,
        "custodian" => who,
        "custodianKey" => key.key_id,
        "custodianPublicKey" => public(key)
      })

    {:ok, signed} = Envelope.sign(evidence, [root, key])
    {%{"ref" => signed.ref, "envelope" => signed.envelope}, own_profile(root, stream)}
  end

  @tag start_chain: true
  test "the customer replaces their root by a quorum, and the record still reads whole",
       %{dir: dir, deployment: deployment, publisher: publisher} do
    eventually(fn ->
      with %{"state" => "unclaimed"} = found <- Claim.describe(), do: found, else: (_ -> nil)
    end)

    root = Key.generate("ed25519")
    lena = Key.generate("ed25519")
    new_root = Key.generate("ed25519")
    gateway = Runtime.info().key_id
    who = "mailto:lena@example.com"

    {:ok, %{"payload" => payload, "ticket" => ticket}} =
      Claim.prepare(
        ask(root, code(dir), %{"custodians" => [%{"identity" => who, "key" => lena.key_id}]})
      )

    {:ok, :created, %{"chain" => chain}} =
      Claim.finalize(%{
        "code" => code(dir),
        "payload" => payload,
        "ticket" => ticket,
        "rootSignature" => signed_by(root, payload)
      })

    # The first root gives the gateway its grant, and it is sealed.
    {:ok, [_]} = Grants.accept(grant(root, deployment, gateway))
    {:ok, [_ | _]} = Runtime.seal()

    described = Claim.describe()
    assert %{"roots" => [first_root], "startHead" => 2} = described
    assert first_root == root.key_id

    {proposed, change_profile} = change(root, "quorum", new_root, deployment, described)
    {approval, approval_profile} = approve(proposed, root, who, lena, deployment)

    sent = fn approvals ->
      %{
        "change" => proposed,
        "approvals" => approvals,
        "keys" => Enum.map([root, lena, new_root], &wire_key/1),
        "blobs" => [wire_blob(change_profile), wire_blob(approval_profile)]
      }
    end

    # Without its approval the change is not taken; nor is one signed by a
    # key that is not a root and calls itself a recovery key.
    assert {:error, {:change_not_in_order, "quorum_not_carried"}} = Roots.accept(sent.([]))

    stranger = Key.generate("ed25519")
    {forged, forged_profile} = change(stranger, "recovery", stranger, deployment, described)

    assert {:error, {:change_not_in_order, "unauthorized_recovery_signer"}} =
             Roots.accept(%{
               "change" => forged,
               "approvals" => [],
               "keys" => [wire_key(stranger)],
               "blobs" => [wire_blob(forged_profile)]
             })

    assert %{"startHead" => 2} = Claim.describe()

    # With it, the change is recorded, approval first.
    assert {:ok, %{"change" => changed, "approvals" => [_one], "chain" => ^chain}} =
             Roots.accept(sent.([approval]))

    assert changed == proposed["ref"]
    assert {:ok, %{"change" => ^changed}} = Roots.accept(sent.([approval]))

    assert %{"roots" => [now_root], "startHead" => 3, "chain" => ^chain} = Claim.describe()
    assert now_root == new_root.key_id

    # The old root can no longer give the gateway a grant; the new one can.
    assert {:error, _} =
             Grants.accept(grant(root, deployment, gateway, %{"mayEndorse" => false}))

    # The new root's grant runs for less time than the old root's, and
    # badges are still issued under it: it comes from a root in place.
    soon = DateTime.utc_now() |> DateTime.add(3600) |> DateTime.truncate(:second)

    assert {:ok, [from_new]} =
             Grants.accept(
               grant(new_root, deployment, gateway, %{"notAfter" => DateTime.to_iso8601(soon)})
             )

    assert %{endorsement: %{ref: ^from_new}, endorsements: [_, _]} = Runtime.info().authority
    {:ok, [_ | _]} = Runtime.seal()

    # Sending a good change again with junk beside it adds nothing to
    # what later exports carry.
    junk = %{"ref" => "bytes:sha256:" <> String.duplicate("0", 64), "base64" => "anVuaw=="}
    poisoned = sent.([approval]) |> Map.update!("blobs", &(&1 ++ [junk]))
    assert {:ok, %{"change" => ^changed}} = Roots.accept(poisoned)
    refute Enum.any?(Roots.carried(dir)["blobs"], &(&1["ref"] == junk["ref"]))

    # Read by someone who pins the chain: the start runs to the third
    # position, and nothing fails. The old root's grant was sealed before
    # the change by a sealer the new root now vouches for, so it stands.
    {:ok, empty} = Export.build(records: [])
    carried = Recurse.Gateway.Provenance.Carried.carry(empty)

    report =
      Export.verify(carried, trusted_chain: chain, trusted_publishers: [publisher.key_id])

    assert %{"headSeq" => 3, "chain" => ^chain} = report.start
    assert [] == Enum.filter(report.findings, &(&1.result == :failed))
    assert [] == Enum.reject(report.findings, &(&1.result == :ok))

    # The new root takes back the grant the old root gave. A stranger
    # cannot, and neither can the old root take back the new root's.
    %{endorsements: held} = Runtime.info().authority
    [from_old] = for %{ref: ref} <- held, ref != from_new, do: ref

    take_back = fn signer, target ->
      stream =
        "urn:r5e:stream:#{deployment}:authority:revocation:#{System.unique_integer([:positive])}"

      evidence =
        start_evidence("Revocation", signer, stream, 1, nil, %{
          "target" => target,
          "reason" => "withdrawn"
        })

      {:ok, signed} = Envelope.sign(evidence, signer)

      %{
        "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
        "keys" => [wire_key(signer)],
        "blobs" => [wire_blob(own_profile(signer, stream))]
      }
    end

    assert {:error, :not_entitled} = Grants.revoke(take_back.(stranger, from_old))
    assert {:error, :not_entitled} = Grants.revoke(take_back.(root, from_new))
    assert {:error, :only_revocations} = Grants.revoke(grant(new_root, deployment, gateway))

    withdrawn = take_back.(new_root, from_old)
    assert {:ok, [_]} = Grants.revoke(withdrawn)
    assert {:ok, [_]} = Grants.revoke(withdrawn)

    # The gateway now acts under the new root's grant alone.
    assert %{endorsement: %{ref: ^from_new}, endorsements: [%{ref: ^from_new}]} =
             Runtime.info().authority

    # Every export says so from now on, and still reads without a failure.
    {:ok, [_ | _]} = Runtime.seal()
    after_it = Recurse.Gateway.Provenance.Carried.carry(empty)
    told = Export.verify(after_it, trusted_chain: chain, trusted_publishers: [publisher.key_id])
    assert [] == Enum.filter(told.findings, &(&1.result == :failed))

    assert Enum.any?(after_it["records"], fn %{"envelope" => envelope} ->
             match?({:ok, %{evidence: %{"kind" => "Revocation"}}}, Envelope.open(envelope))
           end)

    # When its last grant is taken back the gateway has no standing, and
    # stops sealing until a root gives it a new one.
    assert {:ok, [_]} = Grants.revoke(take_back.(new_root, from_new))
    assert Runtime.info().authority == nil
    assert {:ok, []} = Runtime.seal()

    # An operator can see every grant the gateway was given and what
    # became of it.
    assert %{"grants" => listed} = Claim.describe()

    assert [%{"active" => false, "revoked" => true}, %{"active" => false, "revoked" => true}] =
             Enum.sort_by(listed, & &1["ref"])

    # With no standing left, an export still carries the grants the
    # record was made under and the revocations that ended them, so what
    # was recorded while they stood can still be read.
    stripped = Recurse.Gateway.Provenance.Carried.carry(empty)

    kinds =
      for %{"envelope" => e} <- stripped["records"],
          {:ok, o} <- [Envelope.open(e)],
          do: o.evidence["kind"]

    assert Enum.count(kinds, &(&1 == "Endorsement")) == 2
    assert Enum.count(kinds, &(&1 == "Revocation")) == 2

    last = Export.verify(stripped, trusted_chain: chain, trusted_publishers: [publisher.key_id])
    assert [] == Enum.filter(last.findings, &(&1.result == :failed))

    # A revocation that is not the first record of its own stream is refused.
    chained = take_back.(new_root, from_old)

    {:ok, %{evidence: evidence}} = Envelope.open(hd(chained["records"])["envelope"])
    {:ok, second} = Envelope.sign(%{evidence | "seq" => 2, "previous" => from_old}, new_root)

    assert {:error, :stream_not_admissible} =
             Grants.revoke(%{
               chained
               | "records" => [%{"ref" => second.ref, "envelope" => second.envelope}]
             })
  end

  @tag short_publication: true
  test "a node whose publication is not what it has installed does not start a chain" do
    assert {:not_started, :publication_is_not_what_is_installed} = Claim.ensure_started()
    assert %{"state" => "not_started"} = Claim.describe()
  end

  @tag published: false
  test "a node with no publication to cite does not start a chain" do
    assert {:not_started, :no_publication} = Claim.ensure_started()
    assert %{"state" => "not_started"} = Claim.describe()

    assert {:error, :not_started} =
             Claim.prepare(%{"code" => "x", "claimedBy" => "k", "roots" => []})
  end
end
