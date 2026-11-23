defmodule Recurse.Gateway.Evidence.SafeguardingHoldTest do
  @moduledoc """
  Admitting a valid `education.r5e.io/v1/SafeguardingFlag` record automatically
  places an idempotent gateway-signed `RetentionHold` on that session so no
  guardian/owner disposal or retention sweep can erase active safeguarding
  evidence before counselor review releases the hold.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Evidence.ApiHandler
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.Provenance.{Published, Retention, Runtime}
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper

  alias Recurse.Provenance.{
    Body,
    Definitions,
    Envelope,
    Evidence,
    Key,
    Pipeline,
    Profile,
    Publication,
    Ref
  }

  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore, PostgresMerkleLedger}
  alias Recurse.Providers.Repo
  alias RecurseVerify.Canonical

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @base "provenance.r5e.io/v2"
  @safeguarding_kind "education.r5e.io/v1/SafeguardingFlag"
  @student_sub "student-0042"
  @student_urn "urn:r5e:principal:#{@tenant}:#{@student_sub}"

  setup %{tmp_dir: tmp_dir} do
    owner = Sandbox.start_owner!(Repo, shared: true)
    on_exit(fn -> Sandbox.stop_owner(owner) end)

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

    key_file = Path.join(tmp_dir, "content.key")
    :ok = LocalKeyService.generate(key_file)
    {:ok, keys} = LocalKeyService.open(key_file)
    store = {PostgresEvidenceStore, %{repo: Repo, keys: {LocalKeyService, keys}}}

    publisher = Key.generate("ed25519")
    deployment = "safeguarding-#{System.unique_integer([:positive])}"
    root = Key.generate("ed25519")
    gateway = Key.generate("ed25519")

    endorsed = root_endorsement(root, gateway)

    chain = %{
      "records" => [%{"ref" => endorsed.ref, "envelope" => endorsed.envelope}],
      "keys" => [wire(root)]
    }

    restore = [
      put_env(:evidence_content_key_file, key_file),
      put_env(:evidence_publishers, "#{publisher.key_id}=education.r5e.io"),
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

    start_supervised!(
      {Runtime,
       deployment: deployment,
       signer: gateway,
       store: store,
       authority: chain,
       retention: {:keep_for_seconds, 0},
       dir: Path.join(tmp_dir, "evidence"),
       partitions: 1,
       flush_interval_ms: 20}
    )

    on_exit(fn ->
      :persistent_term.erase({Runtime, :info})
      Published.unload()
      ProviderRegistry.uninstall()
      Enum.each(restore, & &1.())
    end)

    # Publish the education.r5e.io/v1/SafeguardingFlag kind definition.
    flag_doc = safeguarding_flag_definition()

    {:ok, pub_set} =
      Publication.issue(
        publisher,
        name: "education-pack",
        package: "education.safeguarding",
        documents: [flag_doc],
        stream_prefix: "urn:r5e:stream:#{deployment}:definitions:"
      )

    assert {:ok, [_]} = Published.admit(pub_set)
    assert Published.admitted?(@safeguarding_kind, flag_doc.ref)

    # Enrol a detector workload badge covering SafeguardingFlag.
    detector = Key.generate("ed25519")
    badge = enrol_detector(detector)

    %{
      deployment: deployment,
      store: store,
      detector: detector,
      badge: badge,
      flag_schema_ref: flag_doc.ref
    }
  end

  test "admitting a SafeguardingFlag automatically places a gateway-signed RetentionHold that blocks disposal",
       ctx do
    # Open two student sessions and record encrypted content in both.
    {201, %{"session" => flagged_session}} =
      post(
        &ApiHandler.open_session/1,
        %{"clientSessionId" => "tutor-flagged"},
        "caller",
        @student_sub
      )

    {201, %{"session" => unflagged_session}} =
      post(
        &ApiHandler.open_session/1,
        %{"clientSessionId" => "tutor-other"},
        "caller",
        @student_sub
      )

    flagged_args = ~s({"topic":"fractions"})
    other_args = ~s({"topic":"spelling"})

    flagged_call = capture_call(flagged_session, flagged_args)
    other_call = capture_call(unflagged_session, other_args)
    :ok = Runtime.flush()

    # Submit a valid education.r5e.io/v1/SafeguardingFlag for flagged_session.
    detail_bytes = ~s({"category":"counselor_review","notes":"encrypted"})

    {flag_record, flag_profile_blob, detail_blob} =
      build_safeguarding_flag(ctx, flagged_session, 1, nil, detail_bytes)

    {201, %{"admitted" => [%{"ref" => flag_ref, "status" => "admitted"}]}} =
      post(
        &ApiHandler.submit/1,
        %{
          "records" => [%{"ref" => flag_record.ref, "envelope" => flag_record.envelope}],
          "keys" => [wire(ctx.detector)],
          "blobs" => [flag_profile_blob, detail_blob],
          "authority" => %{"records" => [%{"ref" => ctx.badge.ref}]}
        },
        "caller",
        @student_sub
      )

    # A gateway-signed RetentionHold was placed automatically on flagged_session.
    assert %{"holds" => [hold]} = Retention.list()
    assert hold["scope"] == flagged_session
    assert hold["reason"] == "safeguarding_flag_auto_hold"
    assert hold["releasedBy"] == nil
    hold_ref = hold["ref"]

    # Confirm the hold record itself is signed by the gateway key and records the trigger ref.
    {:ok, %{evidence: hold_evidence}} =
      PostgresEvidenceStore.fetch(elem(ctx.store, 1), hold_ref)

    assert hold_evidence["issuer"] == Runtime.info().key_id
    assert hold_evidence["body"]["details"]["triggerKind"] == @safeguarding_kind
    assert hold_evidence["body"]["details"]["triggerRef"] == flag_ref

    # Direct session disposal is blocked with HTTP 409 under_hold.
    {409, %{"error" => "under_hold", "about" => ^hold_ref}} =
      post(
        &ApiHandler.dispose/1,
        %{"scope" => flagged_session, "reason" => "guardian erasure request"},
        "platform_operator"
      )

    # Owner-based FERPA disposal refuses the flagged session while disposing of unflagged ones.
    {201,
     %{
       "owner" => @student_urn,
       "complete" => false,
       "disposed" => [%{"session" => ^unflagged_session, "outcome" => "disposed"}],
       "refused" => [
         %{
           "session" => ^flagged_session,
           "error" => %{"reason" => "under_hold", "about" => ^hold_ref}
         }
       ]
     }} =
      post(
        &ApiHandler.dispose/1,
        %{"owner" => @student_urn, "reason" => "ferpa erasure request"},
        "platform_operator"
      )

    # Flagged content is preserved while unflagged content is disposed.
    assert {:ok, ^flagged_args} =
             PostgresEvidenceStore.get_content(
               elem(ctx.store, 1),
               Ref.bytes(flagged_args),
               flagged_session
             )

    assert {:ok, ^detail_bytes} =
             PostgresEvidenceStore.get_content(
               elem(ctx.store, 1),
               Ref.bytes(detail_bytes),
               flagged_session
             )

    assert :error =
             PostgresEvidenceStore.get_content(
               elem(ctx.store, 1),
               Ref.bytes(other_args),
               unflagged_session
             )

    assert flagged_call.ref != other_call.ref

    # Idempotency: retrying the same flag OR admitting a second SafeguardingFlag on the
    # same session does not create duplicate RetentionHold records.
    {200, %{"admitted" => [%{"status" => "already_admitted"}]}} =
      post(
        &ApiHandler.submit/1,
        %{
          "records" => [%{"ref" => flag_record.ref, "envelope" => flag_record.envelope}],
          "keys" => [wire(ctx.detector)],
          "blobs" => [flag_profile_blob, detail_blob],
          "authority" => %{"records" => [%{"ref" => ctx.badge.ref}]}
        },
        "caller",
        @student_sub
      )

    detail_bytes_2 = ~s({"category":"counselor_review","notes":"second-alert"})

    {flag_record_2, _, detail_blob_2} =
      build_safeguarding_flag(ctx, flagged_session, 2, flag_record.ref, detail_bytes_2)

    {201, %{"admitted" => [%{"status" => "admitted"}]}} =
      post(
        &ApiHandler.submit/1,
        %{
          "records" => [%{"ref" => flag_record_2.ref, "envelope" => flag_record_2.envelope}],
          "keys" => [wire(ctx.detector)],
          "blobs" => [flag_profile_blob, detail_blob_2],
          "authority" => %{"records" => [%{"ref" => ctx.badge.ref}]}
        },
        "caller",
        @student_sub
      )

    assert %{"holds" => [%{"ref" => ^hold_ref}]} = Retention.list()

    # Once counselor review releases the hold, disposal succeeds.
    counselor = Key.generate("ed25519")

    released_by = %{
      "algorithm" => counselor.algorithm,
      "bytes" => Base.encode64(counselor.public_key)
    }

    assert {:ok, %{payload: payload, ticket: ticket}} =
             Retention.release_prepare(
               %{
                 "hold" => hold_ref,
                 "reason" => "counselor_review_complete",
                 "releasedBy" => released_by
               },
               nil
             )

    {:ok, sig} = counselor.sign.(Envelope.message(payload))

    assert {:ok, %{"hold" => ^hold_ref}} =
             Retention.release_finalize(%{
               "payload" => Base.encode64(payload),
               "ticket" => ticket,
               "signature" => %{"keyid" => counselor.key_id, "sig" => Base.encode64(sig)},
               "releasedBy" => released_by
             })

    {201, %{"outcome" => "disposed"}} =
      post(
        &ApiHandler.dispose/1,
        %{"scope" => flagged_session, "reason" => "post-review erasure"},
        "platform_operator"
      )
  end

  test "a session with only a time-bounded hold receives an indefinite auto-hold on SafeguardingFlag",
       ctx do
    {201, %{"session" => session}} =
      post(
        &ApiHandler.open_session/1,
        %{"clientSessionId" => "tutor-temp-hold"},
        "caller",
        @student_sub
      )

    capture_call(session, ~s({"topic":"algebra"}))
    :ok = Runtime.flush()

    until =
      DateTime.utc_now()
      |> DateTime.add(3600, :second)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

    assert {:ok, %{"hold" => temp_hold}} =
             Retention.hold(
               %{"scope" => session, "reason" => "short_review", "until" => until},
               nil
             )

    detail_bytes = ~s({"category":"counselor_review"})

    {flag_record, flag_profile_blob, detail_blob} =
      build_safeguarding_flag(ctx, session, 1, nil, detail_bytes)

    {201, %{"admitted" => [%{"status" => "admitted"}]}} =
      post(
        &ApiHandler.submit/1,
        %{
          "records" => [%{"ref" => flag_record.ref, "envelope" => flag_record.envelope}],
          "keys" => [wire(ctx.detector)],
          "blobs" => [flag_profile_blob, detail_blob],
          "authority" => %{"records" => [%{"ref" => ctx.badge.ref}]}
        },
        "caller",
        @student_sub
      )

    %{"holds" => holds} = Retention.list()
    assert length(holds) == 2
    assert Enum.any?(holds, &(&1["ref"] == temp_hold and &1["until"] == until))

    assert Enum.any?(
             holds,
             &(&1["scope"] == session and &1["reason"] == "safeguarding_flag_auto_hold" and
                 is_nil(&1["until"]))
           )
  end

  # -- helpers ---------------------------------------------------------------

  defp safeguarding_flag_definition do
    doc = %{
      "format" => "r5e.kind-definition/v1",
      "kind" => @safeguarding_kind,
      "description" => "Student-safety escalation with encrypted details.",
      "substrate" => "event",
      "naming" => %{"mode" => "content"},
      "conformsTo" => [],
      "signatures" => 1,
      "schema" => %{
        "type" => "object",
        "additionalProperties" => false,
        "required" => [
          "topic",
          "contentRefs",
          "session",
          "school",
          "severity",
          "enforcement",
          "assignedTo",
          "detectorRef"
        ],
        "nonEmpty" => ["contentRefs"],
        "properties" => %{
          "topic" => %{"type" => "string", "enum" => ["safeguarding.flag"]},
          "contentRefs" => %{
            "type" => "array",
            "unique" => true,
            "items" => %{
              "type" => "string",
              "pattern" => "^(evidence|bytes|event):sha256:[0-9a-f]{64}$"
            }
          },
          "session" => %{"type" => "string", "pattern" => "^urn:r5e:session:[^\\s]+$"},
          "school" => %{"type" => "string", "pattern" => "^[A-Za-z][A-Za-z0-9+.-]*:[^\\s]+$"},
          "severity" => %{"type" => "string", "enum" => ["low", "medium", "high", "critical"]},
          "enforcement" => %{
            "type" => "string",
            "enum" => ["non-blocking", "session-paused", "session-terminated"]
          },
          "assignedTo" => %{"type" => "string", "pattern" => "^[A-Za-z][A-Za-z0-9+.-]*:[^\\s]+$"},
          "detectorRef" => %{
            "type" => "string",
            "pattern" => "^(evidence|bytes|event):sha256:[0-9a-f]{64}$"
          }
        }
      }
    }

    bytes = Canonical.encode(doc)
    %{kind_path: @safeguarding_kind, ref: Ref.bytes(bytes), bytes: bytes}
  end

  defp enrol_detector(detector) do
    {200, %{"payload" => payload64, "ticket" => ticket}} =
      post(
        &ApiHandler.badge_prepare/1,
        %{
          "subjectKey" => %{
            "algorithm" => detector.algorithm,
            "bytes" => Base.encode64(detector.public_key)
          },
          "holder" => "safeguarding-detector",
          "workload" => "urn:r5e:workload:school-detector",
          "requestedKinds" => [@safeguarding_kind],
          "requestedTtlSeconds" => 3600
        },
        "caller",
        @student_sub
      )

    {:ok, sig} = detector.sign.(Envelope.message(Base.decode64!(payload64)))

    {201, %{"badge" => %{"ref" => badge_ref}}} =
      post(
        &ApiHandler.badge_finalize/1,
        %{
          "payload" => payload64,
          "ticket" => ticket,
          "subjectSignature" => %{"keyid" => detector.key_id, "sig" => Base.encode64(sig)}
        },
        "caller",
        @student_sub
      )

    badge_doc = payload64 |> Base.decode64!() |> JSON.decode!()
    [prefix] = badge_doc["body"]["streamPrefixes"]

    %{ref: badge_ref, prefix: prefix}
  end

  defp build_safeguarding_flag(ctx, session, seq, previous, detail_bytes) do
    stream = ctx.badge.prefix <> "detector"
    detail_ref = Ref.bytes(detail_bytes)

    {:ok, profile} =
      Profile.new(
        schemas: Map.put(Definitions.schema_refs(), @safeguarding_kind, ctx.flag_schema_ref),
        bindings: [
          %{
            stream_prefix: ctx.badge.prefix,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [ctx.detector.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "endpoint detector",
        deployment_policy_ref: Ref.bytes("school-safeguarding-policy"),
        policy_required_kinds: [],
        retention: {:keep_for_seconds, 0}
      )

    profile_bytes = Profile.encode(profile)

    evidence =
      Evidence.new(
        kind_path: @safeguarding_kind,
        schema_ref: ctx.flag_schema_ref,
        profile_ref: Profile.ref(profile),
        issuer: ctx.detector.key_id,
        actor: "urn:r5e:workload:school-detector",
        on_behalf_of: @student_urn,
        session: session,
        stream: stream,
        seq: seq,
        previous: previous,
        captured_at: DateTime.utc_now(),
        body: %{
          "topic" => "safeguarding.flag",
          "contentRefs" => [detail_ref],
          "session" => session,
          "school" => "urn:r5e:school:lincoln-high",
          "severity" => "high",
          "enforcement" => "non-blocking",
          "assignedTo" => "urn:r5e:role:counselor",
          "detectorRef" => Ref.bytes("detector-v1")
        }
      )

    {:ok, signed} = Envelope.sign(evidence, ctx.detector)

    profile_blob = %{"ref" => Ref.bytes(profile_bytes), "base64" => Base.encode64(profile_bytes)}
    detail_blob = %{"ref" => detail_ref, "base64" => Base.encode64(detail_bytes)}
    {signed, profile_blob, detail_blob}
  end

  defp capture_call(session, args) do
    {:ok, receipt} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: @base <> "/ToolCall",
        actor: @student_urn,
        session: session,
        attachments: [%{name: "args", bytes: args}],
        body:
          Body.tool_call(
            tool: "socratic_hint",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: byte_size(args)
          )
      })

    receipt
  end

  defp root_endorsement(root, gateway) do
    evidence =
      Evidence.new(
        kind_path: @base <> "/Endorsement",
        schema_ref: elem(Definitions.fetch(@base <> "/Endorsement"), 1).ref,
        profile_ref: Ref.bytes("root profile"),
        issuer: root.key_id,
        actor: "urn:r5e:root-ceremony",
        stream: "urn:r5e:authority:root:#{System.unique_integer([:positive])}",
        seq: 1,
        previous: nil,
        captured_at: DateTime.add(DateTime.utc_now(), -3600, :second),
        body: %{
          "subject" => gateway.key_id,
          "kinds" => [
            @safeguarding_kind,
            @base <> "/ToolCall",
            @base <> "/EpochSeal",
            @base <> "/RetentionHold",
            @base <> "/RetentionHoldRelease",
            @base <> "/PayloadDisposition"
          ],
          "mayEndorse" => true,
          "notBefore" => iso(-7200),
          "notAfter" => iso(86_400 * 30)
        }
      )

    {:ok, signed} = Envelope.sign(evidence, root)
    signed
  end

  defp iso(seconds) do
    DateTime.utc_now()
    |> DateTime.add(seconds, :second)
    |> DateTime.truncate(:second)
    |> DateTime.to_iso8601()
  end

  defp wire(signer) do
    %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }
  end

  defp post(handler, body, role, subject \\ "operator@lincoln.edu") do
    token =
      JwtTestHelper.mint_test_jwt(
        recurse_role: role,
        subject: subject,
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid"
      )

    conn =
      :post
      |> Plug.Test.conn("/v1/evidence/test")
      |> Plug.Conn.put_req_header("authorization", "Bearer " <> token)
      |> Map.merge(%{path_params: %{}, body_params: body})
      |> handler.()

    {conn.status, JSON.decode!(conn.resp_body)}
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

    path = Path.join(System.tmp_dir!(), "safeguarding_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp put_env(key, value) do
    previous = Application.get_env(:recurse_gateway, key)
    Application.put_env(:recurse_gateway, key, value)

    fn ->
      if previous,
        do: Application.put_env(:recurse_gateway, key, previous),
        else: Application.delete_env(:recurse_gateway, key)
    end
  end
end
