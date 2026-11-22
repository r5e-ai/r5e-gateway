defmodule Recurse.Gateway.Evidence.EnrolmentTest do
  @moduledoc """
  A workload is given a badge over HTTP, in two steps, by a gateway whose
  own standing comes from a root key it does not hold; and what results
  can be traced to that root by someone holding only the records.

  `async: false` because the policy bundle loader, the provider registry
  and evidence capture are node-wide.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Evidence.ApiHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Provenance.{Carried, Runtime}
  alias Recurse.Gateway.Test.JwtTestHelper

  alias Recurse.Provenance.{
    Definitions,
    Envelope,
    Evidence,
    Export,
    Exporter,
    Key,
    Pipeline,
    Publication,
    Ref
  }

  alias Recurse.Providers.Impls.PostgresEvidenceStore
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @base "provenance.r5e.io/v2"
  @tool @base <> "/ToolCall"

  setup %{tmp_dir: tmp_dir} = ctx do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    start_supervised!(
      Supervisor.child_spec(
        {BundleLoader,
         bundle_path: write_bundle(),
         entity_schema_path:
           Path.join([
             Application.app_dir(:recurse_gateway, "priv"),
             "cedar",
             "schema.cedarschema.json"
           ]),
         trap_sighup: false,
         name: nil},
        id: make_ref()
      )
    )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant,
      signer: "observed://gateway/test"
    })

    restore = [
      put_env(:jwt_validator_opts,
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid",
        known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
      ),
      put_env(:browser_session,
        cookie_name: "r5e_session",
        secret_key_base: :crypto.strong_rand_bytes(64),
        secure_cookie?: false,
        absent_cookie_redirect: :always_401
      )
    ]

    root = Key.generate("ed25519")
    gateway = Key.generate("ed25519")
    endorsed = root_endorsement(root, gateway, Map.get(ctx, :grant, %{}))

    stale =
      root_endorsement(
        root,
        gateway,
        Map.merge(Map.take(Map.get(ctx, :grant, %{}), ["mayEndorse"]), %{
          "notBefore" => iso(-86_400),
          "notAfter" => iso(-7200)
        }),
        -80_000
      )

    chain =
      Map.get(ctx, :chain) ||
        %{
          # Last year's endorsement is still in the file, ahead of the live one.
          "records" =>
            for(r <- [stale, endorsed], do: %{"ref" => r.ref, "envelope" => r.envelope}),
          "keys" => [wire(root)]
        }

    publisher = Key.generate("ed25519")
    {:ok, published} = Publication.issue(publisher, name: "test-steward")

    start_supervised!(
      {Runtime,
       [
         publications: if(Map.get(ctx, :published, false), do: [published], else: []),
         deployment: "enrol-#{System.unique_integer([:positive])}",
         signer: gateway,
         store: {PostgresEvidenceStore, Repo},
         dir: tmp_dir,
         partitions: 1,
         flush_interval_ms: 20
       ] ++ if(Map.get(ctx, :standing, true), do: [authority: chain], else: [])}
    )

    on_exit(fn ->
      :persistent_term.erase({Runtime, :info})
      ProviderRegistry.uninstall()
      Enum.each(restore, & &1.())
    end)

    %{root: root, gateway: gateway, endorsed: endorsed, publisher: publisher}
  end

  defp root_endorsement(root, gateway, overrides, issued \\ -3600) do
    evidence =
      Evidence.new(
        kind_path: @base <> "/Endorsement",
        schema_ref: elem(Definitions.fetch(@base <> "/Endorsement"), 1).ref,
        profile_ref: Ref.bytes("the root's own profile"),
        issuer: root.key_id,
        actor: "urn:meridian:security:root-ceremony",
        stream: "urn:meridian:authority:root:#{System.unique_integer([:positive])}",
        seq: 1,
        previous: nil,
        captured_at: DateTime.add(DateTime.utc_now(), issued, :second),
        body:
          Map.merge(
            %{
              "subject" => gateway.key_id,
              "kinds" => [@tool, @base <> "/ToolResult"],
              "mayEndorse" => true,
              "notBefore" => iso(-7200),
              "notAfter" => iso(86_400 * 30)
            },
            overrides
          )
      )

    {:ok, signed} = Envelope.sign(evidence, root)
    signed
  end

  defp iso(seconds),
    do:
      DateTime.utc_now()
      |> DateTime.add(seconds, :second)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

  defp wire(signer),
    do: %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }

  defp put_env(key, value) do
    previous = Application.get_env(:recurse_gateway, key)
    Application.put_env(:recurse_gateway, key, value)

    fn ->
      if previous,
        do: Application.put_env(:recurse_gateway, key, previous),
        else: Application.delete_env(:recurse_gateway, key)
    end
  end

  defp write_bundle do
    source =
      [
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ]
      |> Path.join()
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "enrolment_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp post(handler, body, role \\ "caller", subject \\ "dana@meridian.example") do
    conn = Plug.Test.conn(:post, "/v1/authority/badges/x")

    conn =
      if role do
        token =
          JwtTestHelper.mint_test_jwt(
            recurse_role: role,
            subject: subject,
            audience: "recurse-gateway-test",
            issuer: "https://test-broker.example.invalid"
          )

        Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
      else
        conn
      end

    conn = handler.(Map.merge(conn, %{path_params: %{}, body_params: body}))
    {conn.status, JSON.decode!(conn.resp_body)}
  end

  defp ask(helper, overrides \\ %{}) do
    Map.merge(
      %{
        "subjectKey" => %{
          "algorithm" => helper.algorithm,
          "bytes" => Base.encode64(helper.public_key)
        },
        "holder" => "endpoint-helper",
        "workload" => "urn:meridian:laptop:dana-mbp",
        "requestedKinds" => [@tool, @base <> "/Observation"],
        "requestedTtlSeconds" => 3600
      },
      overrides
    )
  end

  defp countersign(helper, payload64) do
    {:ok, signature} = helper.sign.(Envelope.message(Base.decode64!(payload64)))
    %{"keyid" => helper.key_id, "sig" => Base.encode64(signature)}
  end

  test "a helper is given a badge that traces to the root, cut down to what the gateway may grant",
       %{root: root, endorsed: endorsed} do
    helper = Key.generate("ed25519")

    assert {200, %{"payloadType" => type, "payload" => payload, "ticket" => ticket}} =
             post(&ApiHandler.badge_prepare/1, ask(helper))

    assert type == "application/vnd.r5e.provenance-evidence+json;v=2"

    # What the helper checks before it signs anything.
    badge = payload |> Base.decode64!() |> JSON.decode!()
    assert badge["kind"] == "Badge" and badge["apiVersion"] == @base
    assert badge["body"]["subject"] == helper.key_id
    assert badge["body"]["kinds"] == [@tool]
    assert badge["body"]["parent"] == endorsed.ref
    assert badge["body"]["workload"] == "urn:meridian:laptop:dana-mbp"
    assert "urn:r5e:principal:" <> _ = acts_for = badge["body"]["actsFor"]
    assert [prefix] = badge["body"]["streamPrefixes"]

    assert {201, done} =
             post(&ApiHandler.badge_finalize/1, %{
               "payload" => payload,
               "ticket" => ticket,
               "subjectSignature" => countersign(helper, payload)
             })

    assert %{"badge" => %{"ref" => badge_ref, "envelope" => envelope}, "streamPrefix" => ^prefix} =
             done

    assert [%{"keyid" => _gateway}, %{"keyid" => helper_id}] = envelope["signatures"]
    assert helper_id == helper.key_id

    # The helper signs a tool call under its badge, on its own stream, and
    # carries its own profile. Someone holding only the records and the
    # root's key id can establish authority for it.
    {:ok, profile} =
      Recurse.Provenance.Profile.new(
        bindings: [
          %{
            stream_prefix: prefix,
            actor_prefixes: ["urn:meridian:"],
            issuer_keys: [helper.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "the laptop's disk",
        policy_required_kinds: [],
        deployment_policy_ref: Ref.bytes("helper")
      )

    call =
      Evidence.new(
        kind_path: @tool,
        schema_ref: elem(Definitions.fetch(@tool), 1).ref,
        profile_ref: Recurse.Provenance.Profile.ref(profile),
        issuer: helper.key_id,
        actor: "urn:meridian:agent:claude-code",
        stream: prefix <> "session-1",
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body:
          Recurse.Provenance.Body.tool_call(
            tool: "Bash",
            content_ref: Ref.bytes("{}"),
            media_type: "application/json",
            size: 2
          )
      )
      |> Map.put("onBehalfOf", acts_for)

    {:ok, signed_call} = Envelope.sign(call, helper)

    {:ok, bundle} =
      Export.build(
        records:
          Enum.map(done["authorityChain"], & &1["envelope"]) ++ [envelope, signed_call.envelope],
        blobs: [{Recurse.Provenance.Profile.encode(profile), nil}, {"{}", nil}],
        keys:
          [%{key_id: helper.key_id, algorithm: helper.algorithm, public_key: helper.public_key}] ++
            for(
              k <- done["keys"],
              do: %{
                key_id: k["keyid"],
                algorithm: k["algorithm"],
                public_key: Base.decode64!(k["bytes"])
              }
            )
      )

    report = Export.verify(bundle, trusted_roots: [root.key_id])
    authority = for %{check: :authority} = f <- report.findings, into: %{}, do: {f.subject, f}

    assert %{result: :ok, about: ^badge_ref} = authority[signed_call.ref]
    assert %{result: :ok} = authority[badge_ref]
    assert [] == Enum.filter(report.findings, &(&1.result == :failed))

    # A reader who trusts some other root establishes nothing.
    other = Export.verify(bundle, trusted_roots: [helper.key_id])
    assert Enum.any?(other.findings, &(&1.check == :authority and &1.result == :failed))

    # And without the right on-behalf-of, the badge does not cover the call.
    {:ok, bare} = Envelope.sign(Map.delete(call, "onBehalfOf"), helper)

    bundle =
      put_in(bundle, ["records", Access.at(-1)], %{"ref" => bare.ref, "envelope" => bare.envelope})

    assert Enum.any?(
             Export.verify(bundle, trusted_roots: [root.key_id]).findings,
             &match?(%{check: :authority, code: "not_covered"}, &1)
           )
  end

  # A helper with a badge, and what it needs to sign records of its own.
  defp enrolled(overrides \\ %{}, subject \\ "dana@meridian.example") do
    helper = Key.generate("ed25519")

    {200, %{"payload" => payload, "ticket" => ticket}} =
      post(&ApiHandler.badge_prepare/1, ask(helper), "caller", subject)

    {201, done} =
      post(
        &ApiHandler.badge_finalize/1,
        %{
          "payload" => payload,
          "ticket" => ticket,
          "subjectSignature" => countersign(helper, payload)
        },
        "caller",
        subject
      )

    badge = payload |> Base.decode64!() |> JSON.decode!()
    [prefix] = badge["body"]["streamPrefixes"]

    {:ok, profile} =
      Recurse.Provenance.Profile.new(
        Keyword.merge(
          [
            bindings: [
              %{
                stream_prefix: prefix,
                actor_prefixes: ["urn:meridian:"],
                issuer_keys: [helper.key_id],
                sealer_keys: []
              }
            ],
            failure_domain: "the laptop's disk",
            policy_required_kinds: [],
            deployment_policy_ref: Ref.bytes("helper")
          ],
          Map.to_list(overrides)
        )
      )

    %{
      helper: helper,
      badge: done["badge"],
      prefix: prefix,
      acts_for: badge["body"]["actsFor"],
      profile: profile
    }
  end

  defp helper_call(w, seq, previous, session, args \\ "{}") do
    evidence =
      Evidence.new(
        kind_path: @tool,
        schema_ref: elem(Definitions.fetch(@tool), 1).ref,
        profile_ref: Recurse.Provenance.Profile.ref(w.profile),
        issuer: w.helper.key_id,
        actor: "urn:meridian:agent:claude-code",
        stream: w.prefix <> "session-1",
        seq: seq,
        previous: previous,
        captured_at: DateTime.utc_now(),
        session: session,
        on_behalf_of: w.acts_for,
        body:
          Recurse.Provenance.Body.tool_call(
            tool: "Bash",
            content_ref: Ref.bytes(args),
            media_type: "application/json",
            size: byte_size(args)
          )
      )

    {:ok, signed} = Envelope.sign(evidence, w.helper)
    Map.put(signed, :evidence, evidence)
  end

  defp batch(w, records, contents \\ ["{}"]) do
    encoded = Recurse.Provenance.Profile.encode(w.profile)

    %{
      "records" => for(r <- records, do: %{"ref" => r.ref, "envelope" => r.envelope}),
      "keys" => [wire(w.helper)],
      "blobs" =>
        for(
          bytes <- [encoded | contents],
          do: %{"ref" => Ref.bytes(bytes), "base64" => Base.encode64(bytes)}
        ),
      "authority" => %{"records" => [w.badge]}
    }
  end

  @tag grant: %{
         "kinds" =>
           Enum.map(
             ~w[ToolCall ToolResult EpochSeal SessionOpened Observation Revocation Badge],
             &(@base <> "/" <> &1)
           )
       }
  test "a helper's own records are taken, sealed and exported with its session, and nobody else's",
       %{root: root} do
    w = enrolled()
    submit = fn body -> post(&ApiHandler.submit/1, body) end

    # A session the gateway has not opened is nobody's yet.
    made_up = Recurse.Gateway.Provenance.SessionName.for(@tenant, w.acts_for, "made-up")

    assert {409, %{"error" => "session_not_opened", "session" => ^made_up}} =
             submit.(batch(w, [helper_call(w, 1, nil, made_up)]))

    # The gateway opens one for the caller and makes its name.
    assert {201, %{"session" => session, "ref" => opened}} =
             post(&ApiHandler.open_session/1, %{})

    assert String.starts_with?(session, "urn:r5e:session:#{@tenant}:")
    assert Recurse.Gateway.Provenance.SessionName.owned_by?(session, w.acts_for)

    # A helper that knows only the id its client uses asks for that
    # session by the id, and is given the same recorded name every time.
    assert {201, %{"session" => by_id}} =
             post(&ApiHandler.open_session/1, %{"clientSessionId" => "client-abc"})

    assert by_id == Recurse.Gateway.Provenance.SessionName.for(@tenant, w.acts_for, "client-abc")

    assert {200, %{"session" => ^by_id}} =
             post(&ApiHandler.open_session/1, %{"clientSessionId" => "client-abc"})

    # The same id from someone else is a different session.
    assert {201, %{"session" => eves}} =
             post(
               &ApiHandler.open_session/1,
               %{"clientSessionId" => "client-abc"},
               "caller",
               "eve@meridian.example"
             )

    assert eves != by_id
    first = helper_call(w, 1, nil, session)
    content = Ref.bytes("{}")

    assert {201,
            %{
              "admitted" => [
                %{
                  "status" => "admitted",
                  "seq" => 1,
                  "contentHeld" => [^content],
                  "contentMissing" => []
                }
              ]
            }} = submit.(batch(w, [first]))

    # The same again changes nothing, and the badge need not be sent: the
    # gateway issued it and knows whose it is.
    assert {200, %{"admitted" => [%{"status" => "already_admitted"}]}} =
             submit.(Map.delete(batch(w, [first]), "authority"))

    # A record that is not about the person submitting it is refused,
    # with or without a session; so is one whose fields are not what
    # every later check assumes.
    as_someone_else =
      helper_call(%{w | acts_for: "urn:r5e:principal:#{@tenant}:bob"}, 1, nil, nil)

    assert {422, %{"error" => "record_is_not_about_the_caller"}} =
             submit.(batch(w, [as_someone_else]))

    {:ok, odd} =
      Envelope.sign(Map.put(helper_call(w, 1, nil, nil).evidence, "seq", "1"), w.helper)

    assert {422, %{"error" => "bad_envelope"}} = submit.(batch(w, [odd]))

    # Somebody else, even with the helper's signed record in hand, cannot
    # put it in this session, and cannot open the session's name again.
    second = helper_call(w, 2, first.ref, session, ~s({"n":2}))

    assert {422, %{"error" => "record_is_not_about_the_caller"}} =
             post(
               &ApiHandler.submit/1,
               batch(w, [second], [~s({"n":2})]),
               "caller",
               "eve@meridian.example"
             )

    # Nor can she put a record of her own, under her own badge, into it.
    eve = enrolled(%{}, "eve@meridian.example")

    assert {409, %{"error" => "session_belongs_to_another_principal"}} =
             post(
               &ApiHandler.submit/1,
               batch(eve, [helper_call(eve, 1, nil, session)]),
               "caller",
               "eve@meridian.example"
             )

    # In her own session she may name the same content. Without sending
    # its bytes it is not held for her: knowing a reference to what
    # another session holds is not a way to read it.
    assert {201, %{"admitted" => [%{"contentHeld" => [], "contentMissing" => [^content]}]}} =
             post(
               &ApiHandler.submit/1,
               batch(eve, [helper_call(eve, 1, nil, eves)], []),
               "caller",
               "eve@meridian.example"
             )

    # A record whose content did not come with it is still taken.
    assert {201, %{"admitted" => [%{"seq" => 2, "contentHeld" => [], "contentMissing" => [_]}]}} =
             submit.(batch(w, [second], []))

    # A different record at a position already taken is refused, and
    # noted once: the helper's key has signed two histories.
    rival = helper_call(w, 2, first.ref, session, ~s({"n":"other"}))

    for _ <- 1..2 do
      assert {409, %{"error" => "stream_fork_refused", "seq" => 2, "existingRef" => existing}} =
               submit.(batch(w, [rival], []))

      assert existing == second.ref
    end

    %{store: {module, handle}, deployment: deployment} = Runtime.info()
    {:ok, {1, _}} = module.head(handle, "urn:r5e:stream:#{deployment}:security")

    # Another helper does the same on a stream of its own, so the
    # gateway's notes about the two share a stream and, soon, a seal.
    elsewhere_too = enrolled()
    {201, %{"session" => second_session}} = post(&ApiHandler.open_session/1, %{})
    theirs = helper_call(elsewhere_too, 1, nil, second_session)
    assert {201, _} = submit.(batch(elsewhere_too, [theirs]))

    assert {409, %{"error" => "stream_fork_refused"}} =
             submit.(
               batch(
                 elsewhere_too,
                 [helper_call(elsewhere_too, 1, nil, second_session, ~s({"x":1}))],
                 []
               )
             )

    # Out of turn, outside the helper's own streams, or under a profile
    # that keeps content for a different time than the deployment does.
    assert {409, %{"error" => "not_next_in_stream", "expectedSeq" => 3}} =
             submit.(batch(w, [helper_call(w, 5, second.ref, session)]))

    elsewhere = %{w | prefix: "urn:r5e:stream:#{deployment}:retention"}

    assert {422, %{"error" => "stream_outside_endpoint_namespace"}} =
             submit.(batch(w, [helper_call(elsewhere, 1, nil, session)]))

    other = enrolled(%{retention: {:keep_for_seconds, 60}})

    assert {422, %{"error" => "profile_retention_mismatch"}} =
             submit.(batch(other, [helper_call(other, 1, nil, session)]))

    # Sealed by the gateway and exported with the session: the helper's
    # records stand under the root through the badge the export carries.
    {:ok, [_ | _]} = Runtime.seal()
    {:ok, bundle} = Exporter.session(Runtime.info().store, session)
    exported = Carried.carry(bundle)
    report = Export.verify(exported, trusted_roots: [root.key_id])

    authority =
      for %{check: :authority} = f <- report.findings, into: %{}, do: {f.subject, f.result}

    assert %{^opened => :ok} = authority
    assert authority[first.ref] == :ok and authority[second.ref] == :ok
    assert authority[w.badge["ref"]] == :ok
    assert [] == Enum.filter(report.findings, &(&1.result == :failed))

    # The seal over the gateway's notes covers a note about another
    # helper's stream as well, so the notes are carried whole and the
    # seal over them can be checked in full.
    over_notes =
      for %{"ref" => ref, "envelope" => envelope} <- exported["records"],
          {:ok, %{evidence: %{"kind" => "EpochSeal", "body" => %{"stream" => sealed}}}} <-
            [Envelope.open(envelope)],
          String.ends_with?(sealed, ":security"),
          do: ref

    assert [_ | _] = over_notes

    assert [] ==
             Enum.filter(
               report.findings,
               &(&1.subject in over_notes and &1.check != :publication and &1.result != :ok)
             )

    # What the gateway noted about the helper's stream goes with it: the
    # second record offered at a taken position, with both to hand.
    assert [noted] =
             for(
               %{"envelope" => envelope} <- exported["records"],
               {:ok, %{evidence: %{"kind" => "Observation"} = e}} <- [Envelope.open(envelope)],
               e["body"]["about"] == first.evidence["stream"],
               do: e["body"]
             )

    assert noted["topic"] == "stream_equivocation" and noted["about"] == first.evidence["stream"]
    assert [_existing, offered] = noted["contentRefs"]
    assert offered in Enum.map(exported["blobs"], & &1["ref"])

    # Its own badge taken back, the helper is given nothing more; what it
    # had already handed over still stands, sealed before the revocation.
    assert {201, %{"revocation" => revocation}} =
             post(&ApiHandler.badge_revoke/1, %{
               "badge" => w.badge["ref"],
               "reason" => "laptop lost"
             })

    third = helper_call(w, 3, second.ref, session)
    assert {422, %{"error" => "authority_ended"}} = submit.(batch(w, [third]))

    {:ok, bundle} = Exporter.session(Runtime.info().store, session)
    after_revocation = Export.verify(Carried.carry(bundle), trusted_roots: [root.key_id])
    assert revocation in Enum.map(Carried.carry(bundle)["records"], & &1["ref"])

    assert [:ok, :ok] ==
             for(
               %{check: :authority, subject: subject, result: result} <- after_revocation.findings,
               subject in [first.ref, second.ref],
               do: result
             )

    # Someone else's badge is an operator's to take back.
    mine = enrolled()

    assert {403, _} =
             post(
               &ApiHandler.badge_revoke/1,
               %{"badge" => mine.badge["ref"], "reason" => "x"},
               "caller",
               "eve@meridian.example"
             )

    assert {201, _} =
             post(
               &ApiHandler.badge_revoke/1,
               %{"badge" => mine.badge["ref"], "reason" => "x"},
               "platform_operator",
               "ops@meridian.example"
             )
  end

  @tag published: true
  test "with a publication installed, the reply and every export say whose definitions these are",
       %{root: root, publisher: publisher} do
    helper = Key.generate("ed25519")

    {200, %{"payload" => payload, "ticket" => ticket}} =
      post(&ApiHandler.badge_prepare/1, ask(helper))

    assert {201, done} =
             post(&ApiHandler.badge_finalize/1, %{
               "payload" => payload,
               "ticket" => ticket,
               "subjectSignature" => countersign(helper, payload)
             })

    # The workload is handed the publisher's statement with its badge.
    assert %{"publications" => [%{"ref" => publication, "envelope" => _}]} = done
    assert publisher.key_id in Enum.map(done["keys"], & &1["keyid"])

    # A bundle of only the badge, as the gateway would export it: the
    # gateway adds the chain above the badge and the publication.
    {:ok, bare} =
      Export.build(
        records: [done["badge"]["envelope"]],
        keys: [
          %{key_id: helper.key_id, algorithm: helper.algorithm, public_key: helper.public_key}
        ]
      )

    bundle = Carried.carry(bare)
    refs = Enum.map(bundle["records"], & &1["ref"])
    assert publication in refs
    assert Enum.all?(done["authorityChain"], &(&1["ref"] in refs))

    # The gateway's own key and profile come from the index in a real
    # export; here they are in the reply.
    bundle =
      Publication.carry(bundle, [%{"keys" => done["keys"], "blobs" => done["blobs"]}])

    report =
      Export.verify(bundle, trusted_roots: [root.key_id], trusted_publishers: [publisher.key_id])

    # All that is left unestablished is the root's own profile, which this
    # test's root never wrote down.
    assert ["profile_not_available"] ==
             report.findings
             |> Enum.reject(&(&1.result == :ok))
             |> Enum.map(& &1.code)
             |> Enum.uniq()

    assert ["ok"] ==
             for(%{check: :publication, code: code} <- report.findings, uniq: true, do: code)

    # Without the gateway's additions the same badge establishes neither.
    alone =
      Export.verify(bare, trusted_roots: [root.key_id], trusted_publishers: [publisher.key_id])

    assert Enum.any?(alone.findings, &(&1.code == "publication_not_carried"))
    assert Enum.any?(alone.findings, &(&1.check == :authority and &1.result != :ok))
  end

  @tag published: true
  @tag grant: %{
         "kinds" => [@tool, @base <> "/ToolResult", @base <> "/EpochSeal"]
       }
  test "a session the gateway recorded itself, exported, traces to the root and to the publisher",
       %{root: root, publisher: publisher} do
    session = "urn:r5e:session:enrol:#{System.unique_integer([:positive])}"

    {:ok, %{ref: call}} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: @tool,
        actor: Runtime.info().actor,
        session: session,
        attachments: [%{name: "args", bytes: "{}"}],
        body:
          Recurse.Provenance.Body.tool_call(
            tool: "shell",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: 2
          )
      })

    {:ok, [_ | _]} = Runtime.seal()

    {:ok, bundle} = Exporter.session(Runtime.info().store, session)
    exported = Carried.carry(bundle)

    report =
      Export.verify(exported,
        trusted_roots: [root.key_id],
        trusted_publishers: [publisher.key_id]
      )

    by_check = fn check ->
      for %{check: ^check} = f <- report.findings, into: %{}, do: {f.subject, f.code}
    end

    # The call and the seal over it both stand under the root, through
    # the endorsement the gateway carries.
    assert %{^call => "ok"} = authority = by_check.(:authority)
    assert ["ok"] == authority |> Map.values() |> Enum.uniq()
    assert ["ok"] == by_check.(:publication) |> Map.values() |> Enum.uniq()

    # All that is left unestablished is the root's own profile, which this
    # test's root never wrote down.
    assert ["profile_not_available"] ==
             report.findings
             |> Enum.reject(&(&1.result == :ok))
             |> Enum.map(& &1.code)
             |> Enum.uniq()

    # As the gateway built it, before adding what it carries, the same
    # session has no standing a reader can see.
    bare = Export.verify(bundle, trusted_roots: [root.key_id])
    assert Enum.any?(bare.findings, &(&1.check == :authority and &1.result != :ok))
  end

  test "a helper that did not hear the answer asks again and gets the same badge" do
    helper = Key.generate("ed25519")

    {200, %{"payload" => payload, "ticket" => ticket}} =
      post(&ApiHandler.badge_prepare/1, ask(helper))

    request = %{
      "payload" => payload,
      "ticket" => ticket,
      "subjectSignature" => countersign(helper, payload)
    }

    assert {201, %{"badge" => badge} = first} = post(&ApiHandler.badge_finalize/1, request)
    assert {201, ^first} = post(&ApiHandler.badge_finalize/1, request)

    # After the record has been shipped and sealed, still the same.
    {:ok, [_ | _]} = Runtime.seal()
    assert {201, %{"badge" => ^badge}} = post(&ApiHandler.badge_finalize/1, request)

    # One badge was recorded, not three, and nothing is left to seal.
    assert {:ok, []} = Runtime.seal()
  end

  test "without a publication installed, the reply carries none" do
    helper = Key.generate("ed25519")

    {200, %{"payload" => payload, "ticket" => ticket}} =
      post(&ApiHandler.badge_prepare/1, ask(helper))

    assert {201, %{"publications" => []}} =
             post(&ApiHandler.badge_finalize/1, %{
               "payload" => payload,
               "ticket" => ticket,
               "subjectSignature" => countersign(helper, payload)
             })
  end

  test "the exchange refuses what it should", %{} do
    helper = Key.generate("ed25519")
    thief = Key.generate("ed25519")

    {200, %{"payload" => payload, "ticket" => ticket}} =
      post(&ApiHandler.badge_prepare/1, ask(helper))

    finalize = fn body -> post(&ApiHandler.badge_finalize/1, body) end

    good = %{
      "payload" => payload,
      "ticket" => ticket,
      "subjectSignature" => countersign(helper, payload)
    }

    # Signed by someone other than the subject.
    assert {422, %{"error" => "signature_is_not_the_subjects"}} =
             finalize.(%{good | "subjectSignature" => countersign(thief, payload)})

    # The subject's key id on a signature that is not theirs.
    forged = %{countersign(thief, payload) | "keyid" => helper.key_id}

    assert {422, %{"error" => "bad_signature"}} =
             finalize.(%{good | "subjectSignature" => forged})

    # A payload the gateway did not ticket: here, asking for more.
    wider =
      payload
      |> Base.decode64!()
      |> JSON.decode!()
      |> put_in(["body", "kinds"], [@tool, @base <> "/EpochSeal"])
      |> RecurseVerify.Canonical.encode()
      |> Base.encode64()

    assert {422, %{"error" => "ticket_does_not_match"}} =
             finalize.(%{
               "payload" => wider,
               "ticket" => ticket,
               "subjectSignature" => countersign(helper, wider)
             })

    # Nothing the gateway may grant was asked for; not a key; not allowed to ask.
    assert {422, %{"error" => "no_requested_kind_is_grantable"}} =
             post(
               &ApiHandler.badge_prepare/1,
               ask(helper, %{"requestedKinds" => [@base <> "/EpochSeal"]})
             )

    assert {422, %{"error" => "not_a_public_key"}} =
             post(
               &ApiHandler.badge_prepare/1,
               ask(helper, %{"subjectKey" => %{"algorithm" => "ed25519", "bytes" => "AAAA"}})
             )

    assert {403, _} = post(&ApiHandler.badge_prepare/1, ask(helper), "tenant_auditor")
    assert {401, _} = post(&ApiHandler.badge_prepare/1, ask(helper), nil)

    # Someone else, allowed to enrol, tries to finish Dana's enrolment and
    # walk away with a badge that acts for her.
    assert {422, %{"error" => "caller_does_not_match_prepared_badge"}} =
             post(&ApiHandler.badge_finalize/1, good, "caller", "bob@meridian.example")

    assert {422, %{"error" => "caller_does_not_match_prepared_badge"}} =
             post(&ApiHandler.badge_finalize/1, good, "platform_operator", "ops@meridian.example")

    # The good one still goes through, once.
    assert {201, _} = finalize.(good)
  end

  @tag standing: false
  test "a gateway that was given no standing enrols nobody" do
    helper = Key.generate("ed25519")

    assert {409, %{"error" => "gateway_has_no_endorsement"}} =
             post(&ApiHandler.badge_prepare/1, ask(helper))
  end

  @tag grant: %{"mayEndorse" => false}
  test "nor does one whose endorsement does not let it vouch" do
    helper = Key.generate("ed25519")

    assert {409, %{"error" => "gateway_has_no_endorsement"}} =
             post(&ApiHandler.badge_prepare/1, ask(helper))
  end

  @tag grant: %{"notBefore" => "2999-01-01T00:00:00Z", "notAfter" => "2999-02-01T00:00:00Z"}
  test "an endorsement that is not yet in force issues nothing" do
    assert {422, %{"error" => "gateway_endorsement_not_yet_in_force"}} =
             post(&ApiHandler.badge_prepare/1, ask(Key.generate("ed25519")))
  end

  @tag grant: %{"streamPrefixes" => ["urn:acme:prod:"]}
  test "an endorsement that does not reach the endpoint's streams issues nothing" do
    assert {422, %{"error" => "gateway_endorsement_does_not_cover_endpoint_streams"}} =
             post(&ApiHandler.badge_prepare/1, ask(Key.generate("ed25519")))
  end

  @tag chain: %{
         "records" => [%{"envelope" => %{"nonsense" => true}}],
         "keys" => [%{"keyid" => 1}, "x"]
       }
  test "a malformed authority file leaves the gateway running, enrolling nobody" do
    assert Runtime.running?()

    assert {409, %{"error" => "gateway_has_no_endorsement"}} =
             post(&ApiHandler.badge_prepare/1, ask(Key.generate("ed25519")))
  end
end
