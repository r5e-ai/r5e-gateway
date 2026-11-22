defmodule Recurse.Gateway.Evidence.RetentionTest do
  @moduledoc """
  Content is held, the hold is released by a person with their own key,
  the content is disposed of, and a reader of a later export is told
  what happened to it, by whom and on what authority.

  `async: false` because evidence capture is node-wide.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Provenance.{Carried, Claim, Grants, Retention, Runtime}
  alias Recurse.Provenance.{Body, Definitions, Envelope, Evidence, Export, Exporter, Key}
  alias Recurse.Provenance.{Pipeline, Profile, Publication, Ref}
  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore}
  alias Recurse.Providers.Repo

  @base "provenance.r5e.io/v2/"
  @args ~s({"command":"ls"})

  setup %{tmp_dir: dir} = ctx do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    key_file = Path.join(dir, "content.key")
    :ok = LocalKeyService.generate(key_file)
    {:ok, keys} = LocalKeyService.open(key_file)
    store = {PostgresEvidenceStore, %{repo: Repo, keys: {LocalKeyService, keys}}}

    publisher = Key.generate("ed25519")
    {:ok, published} = Publication.issue(publisher, name: "test-steward")
    deployment = "keep-#{System.unique_integer([:positive])}"

    start_supervised!(
      {Runtime,
       deployment: deployment,
       signer: Key.generate("ed25519"),
       store: store,
       dir: Path.join(dir, "evidence"),
       partitions: 1,
       flush_interval_ms: 20,
       start_chain?: Map.get(ctx, :start_chain, false),
       retention: Map.get(ctx, :retention, {:keep_for_seconds, 0}),
       publications: [published]}
    )

    on_exit(fn -> :persistent_term.erase({Runtime, :info}) end)

    %{
      dir: Path.join(dir, "evidence"),
      store: store,
      deployment: deployment,
      session: "urn:r5e:session:test:#{deployment}"
    }
  end

  defp capture(session, args \\ @args) do
    {:ok, receipt} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: @base <> "ToolCall",
        actor: "urn:r5e:principal:test:alice",
        session: session,
        attachments: [%{name: "args", bytes: args}],
        body:
          Body.tool_call(
            tool: "Bash",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: byte_size(args)
          )
      })

    :ok = Runtime.flush()
    receipt
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

  defp wire_key(signer),
    do: %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }

  # A grant from the root, at the given position of the root's own stream.
  defp grant(root, deployment, subject, kinds, {seq, previous}, more \\ %{}) do
    "key:ed25519:sha256:" <> hex = root.key_id
    stream = "urn:r5e:stream:#{deployment}:authority:root:#{hex}"

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: stream,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [root.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "made offline by the root",
        deployment_policy_ref: Ref.bytes("root"),
        policy_required_kinds: []
      )

    now = DateTime.utc_now()
    iso = &(now |> DateTime.add(&1) |> DateTime.truncate(:second) |> DateTime.to_iso8601())

    evidence =
      Evidence.new(
        kind_path: @base <> "Endorsement",
        schema_ref: elem(Definitions.fetch(@base <> "Endorsement"), 1).ref,
        profile_ref: Profile.ref(profile),
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
              "kinds" => Enum.map(kinds, &(@base <> &1)),
              "streamPrefixes" => ["urn:r5e:stream:#{deployment}:"],
              "mayEndorse" => false,
              "notBefore" => iso.(-60),
              "notAfter" => iso.(86_400)
            },
            more
          )
      )

    {:ok, signed} = Envelope.sign(evidence, root)
    encoded = Profile.encode(profile)

    %{
      "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
      "keys" => [wire_key(root)],
      "blobs" => [%{"ref" => Ref.bytes(encoded), "base64" => Base.encode64(encoded)}]
    }
  end

  defp claim(dir, root) do
    code = dir |> Path.join("claim.code") |> File.read!()

    {:ok, %{"payload" => payload, "ticket" => ticket}} =
      Claim.prepare(%{
        "code" => code,
        "claimedBy" => root.key_id,
        "roots" => [
          %{
            "publicKey" => Map.take(wire_key(root), ["algorithm", "bytes"]),
            "holder" => "person",
            "custody" => "hardware"
          }
        ],
        "threshold" => 1
      })

    {:ok, signature} = root.sign.(Envelope.message(Base.decode64!(payload)))

    {:ok, :created, %{"chain" => chain}} =
      Claim.finalize(%{
        "code" => code,
        "payload" => payload,
        "ticket" => ticket,
        "rootSignature" => %{"keyid" => root.key_id, "sig" => Base.encode64(signature)}
      })

    chain
  end

  defp signed_release(person, payload, ticket, more \\ %{}) do
    {:ok, signature} = person.sign.(Envelope.message(payload))

    Map.merge(
      %{
        "payload" => Base.encode64(payload),
        "ticket" => ticket,
        "signature" => %{"keyid" => person.key_id, "sig" => Base.encode64(signature)},
        "releasedBy" => Map.take(wire_key(person), ["algorithm", "bytes"])
      },
      more
    )
  end

  @tag start_chain: true
  test "held, released by a person, disposed of, and a reader is told all of it",
       %{dir: dir, store: store, deployment: deployment, session: session} do
    eventually(fn ->
      with %{"state" => "unclaimed"} = found <- Claim.describe(), do: found, else: (_ -> nil)
    end)

    root = Key.generate("ed25519")
    chain = claim(dir, root)
    gateway = Runtime.info().key_id

    # A gateway whose grant does not cover retention records writes none:
    # they would sit on the stream and count for nothing with any reader.
    working = grant(root, deployment, gateway, ~w[ToolCall EpochSeal], {1, nil})
    assert {:ok, [first]} = Grants.accept(working)

    assert {:error, :gateway_may_not_record_this} =
             Retention.hold(%{"scope" => session, "reason" => "litigation"}, nil)

    keeping =
      grant(
        root,
        deployment,
        gateway,
        ~w[RetentionHold RetentionHoldRelease PayloadDisposition],
        {2, first}
      )

    assert {:ok, [second]} = Grants.accept(keeping)

    call = capture(session)

    # A hold on the session: its content gets one more lock.
    assert {:ok, %{"hold" => hold, "seq" => 1, "held" => 1, "lost" => []}} =
             Retention.hold(
               %{"scope" => session, "reason" => "litigation"},
               "urn:r5e:principal:test:counsel"
             )

    # While the hold stands, the session's content is not disposed of and
    # no disposal is recorded.
    assert {:error, {:under_hold, ^hold}} =
             Retention.dispose(%{"scope" => session, "reason" => "housekeeping"}, nil)

    assert %{"disposals" => [], "holds" => [%{"ref" => ^hold, "releasedBy" => nil}]} =
             Retention.list()

    # Releasing takes the person's own signature.
    counsel = Key.generate("ed25519")

    released_by = %{
      "algorithm" => counsel.algorithm,
      "bytes" => Base.encode64(counsel.public_key)
    }

    assert {:error, :no_such_hold} =
             Retention.release_prepare(
               %{"hold" => call.ref, "reason" => "settled", "releasedBy" => released_by},
               nil
             )

    assert {:ok, %{payload: payload, ticket: ticket}} =
             Retention.release_prepare(
               %{"hold" => hold, "reason" => "settled", "releasedBy" => released_by},
               nil
             )

    # Somebody else's signature releases nothing.
    thief = Key.generate("ed25519")

    assert {:error, :signature_is_not_the_releasers} =
             Retention.release_finalize(signed_release(thief, payload, ticket))

    # Nor does the right person's, until a root has said they may.
    assert {:error, :releaser_has_no_standing} =
             Retention.release_finalize(signed_release(counsel, payload, ticket))

    assert %{"holds" => [%{"releasedBy" => nil}]} = Retention.list()

    # A real grant from the root that does not cover releasing is no
    # standing either, and it is not kept: nothing is written unless the
    # release it came with is in order.
    kept = File.read!(Grants.file(dir))
    other = grant(root, deployment, counsel.key_id, ~w[ToolCall], {3, second})

    assert {:error, :releaser_has_no_standing} =
             Retention.release_finalize(
               signed_release(counsel, payload, ticket, %{"authority" => other})
             )

    assert kept == File.read!(Grants.file(dir))
    [%{"ref" => other_ref}] = other["records"]
    assert :error = PostgresEvidenceStore.fetch(elem(store, 1), other_ref)

    may_release =
      grant(root, deployment, counsel.key_id, ~w[RetentionHoldRelease], {3, second})

    assert {:ok, %{"release" => release, "seq" => 2, "hold" => ^hold}} =
             Retention.release_finalize(
               signed_release(counsel, payload, ticket, %{"authority" => may_release})
             )

    counsel_key = counsel.key_id
    assert %{"holds" => [%{"releasedBy" => ^counsel_key}]} = Retention.list()

    assert {:error, :hold_already_released} =
             Retention.release_prepare(
               %{"hold" => hold, "reason" => "again", "releasedBy" => released_by},
               nil
             )

    # With the hold released, and the period the profile gives run, the
    # session's content is disposed of.
    assert {:ok, %{"disposal" => disposal, "seq" => 3, "outcome" => "disposed"}} =
             Retention.dispose(%{"scope" => session, "reason" => "housekeeping"}, nil)

    assert {:ok, _} = Runtime.seal()

    # A reader who pins the chain is told the content was disposed of
    # under that record. Nothing has failed, and nothing is reported as
    # held that is not there.
    {:ok, bundle} = Exporter.session(store, session, content: true)
    report = Export.verify(Carried.carry(bundle), trusted_chain: chain)

    assert [] == Enum.filter(report.findings, &(&1.result == :failed))

    assert [%{result: :incomplete, code: "disposed_by_record", about: ^disposal}] =
             Enum.filter(report.findings, &(&1.subject == call.ref and &1.check == :content))

    # The hold, the release with both its signers, and the disposal all
    # have authority from the customer's root.
    for ref <- [hold, release, disposal] do
      assert [%{result: :ok}] =
               Enum.filter(report.findings, &(&1.subject == ref and &1.check == :authority))
    end
  end

  # A revocation of `target`, signed by `root` and dated `at`.
  defp revocation(root, deployment, target, at) do
    stream =
      "urn:r5e:stream:#{deployment}:authority:revocation:#{System.unique_integer([:positive])}"

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: stream,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [root.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "made offline",
        deployment_policy_ref: Ref.bytes("root"),
        policy_required_kinds: []
      )

    evidence =
      Evidence.new(
        kind_path: @base <> "Revocation",
        schema_ref: elem(Definitions.fetch(@base <> "Revocation"), 1).ref,
        profile_ref: Profile.ref(profile),
        issuer: root.key_id,
        actor: "urn:r5e:root-ceremony",
        stream: stream,
        seq: 1,
        previous: nil,
        captured_at: at,
        body: %{"target" => target, "reason" => "the key was stolen"}
      )

    {:ok, signed} = Envelope.sign(evidence, root)
    encoded = Profile.encode(profile)

    %{
      "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
      "keys" => [wire_key(root)],
      "blobs" => [%{"ref" => Ref.bytes(encoded), "base64" => Base.encode64(encoded)}]
    }
  end

  @tag start_chain: true
  test "a release made with a key the root had already taken back releases nothing",
       %{dir: dir, deployment: deployment, session: session} do
    eventually(fn ->
      with %{"state" => "unclaimed"} = found <- Claim.describe(), do: found, else: (_ -> nil)
    end)

    root = Key.generate("ed25519")
    claim(dir, root)

    kinds = ~w[ToolCall EpochSeal RetentionHold RetentionHoldRelease PayloadDisposition]
    working = grant(root, deployment, Runtime.info().key_id, kinds, {1, nil})
    assert {:ok, [first]} = Grants.accept(working)

    capture(session)
    assert {:ok, %{"hold" => hold}} = Retention.hold(%{"scope" => session, "reason" => "x"}, nil)

    counsel = Key.generate("ed25519")

    released_by = %{
      "algorithm" => counsel.algorithm,
      "bytes" => Base.encode64(counsel.public_key)
    }

    may_release = grant(root, deployment, counsel.key_id, ~w[RetentionHoldRelease], {2, first})
    [%{"ref" => counsel_grant}] = may_release["records"]

    # The root takes counsel's grant back, offline, and the gateway has
    # not been told yet.
    taken_back =
      revocation(root, deployment, counsel_grant, DateTime.add(DateTime.utc_now(), -5, :second))

    # Whoever holds counsel's key releases the hold. As far as the gateway
    # can see the release is in order, and it is recorded and sealed.
    {:ok, %{payload: payload, ticket: ticket}} =
      Retention.release_prepare(
        %{"hold" => hold, "reason" => "settled", "releasedBy" => released_by},
        nil
      )

    assert {:ok, %{"release" => _}} =
             Retention.release_finalize(
               signed_release(counsel, payload, ticket, %{"authority" => may_release})
             )

    counsel_key = counsel.key_id
    assert %{"holds" => [%{"releasedBy" => ^counsel_key}]} = Retention.list()

    # The revocation arrives. It is dated before the release, so no reader
    # counts the release any more, and neither does the gateway: the hold
    # stands again, the content is not disposed of, and someone with
    # standing can still release it properly.
    assert {:ok, [_]} = Grants.revoke(taken_back)
    assert %{"holds" => [%{"ref" => ^hold, "releasedBy" => nil}]} = Retention.list()

    assert {:error, {:under_hold, ^hold}} =
             Retention.dispose(%{"scope" => session, "reason" => "housekeeping"}, nil)

    assert {:ok, %{payload: _, ticket: _}} =
             Retention.release_prepare(
               %{"hold" => hold, "reason" => "settled", "releasedBy" => released_by},
               nil
             )
  end

  @tag start_chain: true
  test "on a claimed deployment a helper's records are taken, and a root can take its badge back",
       %{dir: dir, store: store, deployment: deployment} do
    alias Recurse.Gateway.Provenance.{Admission, Enrolment}

    eventually(fn ->
      with %{"state" => "unclaimed"} = found <- Claim.describe(), do: found, else: (_ -> nil)
    end)

    root = Key.generate("ed25519")
    chain = claim(dir, root)

    kinds = ~w[ToolCall EpochSeal Badge SessionOpened Revocation]

    assert {:ok, [_]} =
             Grants.accept(
               grant(root, deployment, Runtime.info().key_id, kinds, {1, nil}, %{
                 "mayEndorse" => true
               })
             )

    dana = "urn:r5e:principal:test:dana"
    caller = %{tenant: "test", principal: dana}
    helper = Key.generate("ed25519")

    {:ok, %{payload: payload, ticket: ticket}} =
      Enrolment.prepare(
        %{
          "subjectKey" => Map.take(wire_key(helper), ["algorithm", "bytes"]),
          "holder" => "endpoint-helper",
          "requestedKinds" => [@base <> "ToolCall"],
          "requestedTtlSeconds" => 3600
        },
        dana
      )

    {:ok, signature} = helper.sign.(Envelope.message(payload))

    {:ok, %{"badge" => badge, "streamPrefix" => prefix}} =
      Enrolment.finalize(
        %{
          "payload" => Base.encode64(payload),
          "ticket" => ticket,
          "subjectSignature" => %{"keyid" => helper.key_id, "sig" => Base.encode64(signature)}
        },
        dana
      )

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: prefix,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [helper.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "the laptop's disk",
        policy_required_kinds: [],
        deployment_policy_ref: Ref.bytes("helper"),
        retention: {:keep_for_seconds, 0}
      )

    encoded = Profile.encode(profile)
    {:ok, :opened, %{"session" => session}} = Admission.open_session(%{}, caller)

    call = fn seq, previous ->
      evidence =
        Evidence.new(
          kind_path: @base <> "ToolCall",
          schema_ref: elem(Definitions.fetch(@base <> "ToolCall"), 1).ref,
          profile_ref: Profile.ref(profile),
          issuer: helper.key_id,
          actor: "urn:r5e:agent:claude-code",
          stream: prefix <> "s",
          seq: seq,
          previous: previous,
          captured_at: DateTime.utc_now(),
          session: session,
          on_behalf_of: dana,
          body:
            Body.tool_call(
              tool: "Bash",
              content_ref: Ref.bytes(@args),
              media_type: "application/json",
              size: byte_size(@args)
            )
        )

      {:ok, signed} = Envelope.sign(evidence, helper)
      signed
    end

    batch = fn record ->
      %{
        "records" => [%{"envelope" => record.envelope}],
        "keys" => [wire_key(helper)],
        "blobs" =>
          for(
            bytes <- [encoded, @args],
            do: %{"ref" => Ref.bytes(bytes), "base64" => Base.encode64(bytes)}
          )
      }
    end

    # The badge is not sent: the gateway issued it and knows whose it is.
    first = call.(1, nil)

    assert {:ok, [%{"status" => "admitted", "contentHeld" => [_]}]} =
             Admission.submit(batch.(first), caller)

    # Sealed and exported, the helper's record stands under the pinned chain.
    assert {:ok, [_ | _]} = Runtime.seal()
    {:ok, bundle} = Exporter.session(store, session, content: true)
    report = Export.verify(Carried.carry(bundle), trusted_chain: chain)
    assert [] == Enum.reject(report.findings, &(&1.result == :ok or &1.check == :publication))

    assert [%{result: :ok}] =
             Enum.filter(report.findings, &(&1.subject == first.ref and &1.check == :authority))

    # The root takes the badge back through the route roots use. The
    # gateway takes nothing more under it.
    assert {:ok, [_]} =
             Grants.revoke(revocation(root, deployment, badge["ref"], DateTime.utc_now()))

    assert {:error, :authority_ended} = Admission.submit(batch.(call.(2, first.ref)), caller)
  end

  @tag retention: {:keep_for_seconds, 3600}
  test "a record captured a moment ago and not yet in the index still stands in the way",
       %{session: session} do
    {:ok, receipt} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: @base <> "ToolCall",
        actor: "urn:r5e:principal:test:alice",
        session: session,
        attachments: [%{name: "args", bytes: @args}],
        body:
          Body.tool_call(
            tool: "Bash",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: byte_size(@args)
          )
      })

    ref = receipt.ref

    assert {:error, {:kept_until, ^ref}} =
             Retention.dispose(%{"scope" => session, "reason" => "housekeeping"}, nil)

    assert %{"disposals" => []} = Retention.list()
  end

  test "a hold and a disposal recorded but not applied are applied when asked again",
       %{session: session, store: {module, handle}} do
    call = capture(session, ~s({"command":"reconciled"}))
    {:ok, %{evidence: %{"body" => %{"contentRef" => content}}}} = module.fetch(handle, call.ref)
    other = session <> "-held"
    capture(other, ~s({"command":"held"}))

    assert {:ok, %{"hold" => hold}} = Retention.hold(%{"scope" => other, "reason" => "x"}, nil)

    assert {:ok, %{"disposal" => disposal}} =
             Retention.dispose(%{"scope" => session, "reason" => "x"}, nil)

    # As if the gateway had stopped after recording each and before applying it.
    Repo.query!("DELETE FROM evidence_content_locks WHERE scope = $1", ["urn:r5e:hold:" <> hold])

    Repo.query!(
      "UPDATE evidence_content_keys SET wrapped = $2, destroyed_at = NULL, destroyed_reason = NULL WHERE scope = $1",
      [session, <<0>>]
    )

    assert [^session] = PostgresEvidenceStore.live_scopes(handle, [session, other <> "-none"])
    assert :ok = Retention.reconcile()

    assert %{rows: [[1]]} =
             Repo.query!("SELECT count(*) FROM evidence_content_locks WHERE scope = $1", [
               "urn:r5e:hold:" <> hold
             ])

    assert %{rows: [[nil, ^disposal]]} =
             Repo.query!(
               "SELECT wrapped, destroyed_reason FROM evidence_content_keys WHERE scope = $1",
               [session]
             )

    assert :erased == module.content_state(handle, content)

    # The session records again, under a later key. The disposal already
    # carried out is not taken for one still waiting.
    again = capture(session, ~s({"command":"after"}))
    {:ok, %{evidence: %{"body" => %{"contentRef" => later}}}} = module.fetch(handle, again.ref)

    log =
      ExUnit.CaptureLog.capture_log(fn -> assert :ok = Retention.reconcile() end)

    refute log =~ "is not carried out"
    assert :held == module.content_state(handle, later)
  end

  @tag retention: nil
  test "content recorded under a profile that says nothing is never disposed of",
       %{session: session} do
    call = capture(session)

    assert {:error, {:never_disposed_of, ref}} =
             Retention.dispose(%{"scope" => session, "reason" => "housekeeping"}, nil)

    assert ref == call.ref
    assert %{"disposals" => []} = Retention.list()
  end

  test "a hold on named records, and a disposal refused because of it",
       %{session: session, store: store} do
    call = capture(session)

    assert {:error, :malformed_request} =
             Retention.hold(%{"scope" => session, "targets" => [call.ref], "reason" => "x"}, nil)

    # A record this deployment does not hold is said to be lost to the hold.
    missing = Ref.evidence("no such record")

    assert {:ok, %{"hold" => hold, "held" => 1, "lost" => [^missing]}} =
             Retention.hold(%{"targets" => [call.ref, missing], "reason" => "audit"}, nil)

    assert {:error, {:under_hold, ^hold}} =
             Retention.dispose(%{"scope" => session, "reason" => "housekeeping"}, nil)

    # A hold that has run out no longer stands in the way.
    other = session <> "-other"
    past = DateTime.utc_now() |> DateTime.add(-60) |> DateTime.truncate(:second)

    assert {:ok, _} =
             Retention.hold(
               %{"scope" => other, "reason" => "short", "until" => DateTime.to_iso8601(past)},
               nil
             )

    # Content no other session has, so nothing else keeps it.
    late = capture(other, ~s({"command":"only here"}))
    {module, handle} = store
    {:ok, %{evidence: %{"body" => %{"contentRef" => content}}}} = module.fetch(handle, late.ref)
    assert :held == module.content_state(handle, content)

    assert {:ok, %{"outcome" => "disposed"}} =
             Retention.dispose(%{"scope" => other, "reason" => "housekeeping"}, nil)

    # The hold that had run out gave up its lock with the disposal, so
    # the content is gone and not merely out of the session's reach.
    assert :erased == module.content_state(handle, content)
  end
end
