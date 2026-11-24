defmodule Recurse.Gateway.Evidence.ReleaseGateTest do
  @moduledoc """
  Tests for opt-in custody content-release gating
  (`R5E_CUSTODY_REQUIRE_RELEASE_GRANT`, default false):
    * Operator content download & export(content: true) return `403 release_grant_required`
      without a valid admitted `custody.r5e.io/v1/ReleaseGranted`.
    * Return `200` once a matching `ReleaseRequest` (unexpired window) +
      `ReleaseGranted` (`outcome: "released"`) are admitted.
    * Reject denied grants, expired windows, and withdrawn powers.
    * Preserve self-scoped `ReadOwnPayload` reads and D4 `WorkloadTerms`
      routine-debug carveout (without bypassing human `TermsAccepted` sessions).
  """

  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  import Plug.Test

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Evidence.{ApiHandler, ReleaseGate}
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Provenance.{Body, Definitions, Envelope, Evidence, Key, Pipeline, Ref}
  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore, PostgresMerkleLedger}
  alias Recurse.Providers.Repo
  alias RecurseVerify.Canonical

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @base "provenance.r5e.io/v2"
  @user_sub "employee-007"

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
    deployment = "release-gate-#{System.unique_integer([:positive])}"
    root = Key.generate("ed25519")
    gateway = Key.generate("ed25519")

    endorsed = root_endorsement(root, gateway)

    chain = %{
      "records" => [%{"ref" => endorsed.ref, "envelope" => endorsed.envelope}],
      "keys" => [wire(root)]
    }

    restore = [
      put_env(:evidence_content_key_file, key_file),
      put_env(:evidence_publishers, "#{publisher.key_id}=custody.r5e.io"),
      put_env(:evidence_deployment, deployment),
      put_env(:custody_require_release_grant?, true),
      put_env(:jwt_validator_opts,
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid",
        known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
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
      ProviderRegistry.uninstall()
      :persistent_term.erase({Runtime, :info})

      Enum.each(restore, fn
        {k, nil} -> Application.delete_env(:recurse_gateway, k)
        {k, v} -> Application.put_env(:recurse_gateway, k, v)
      end)
    end)

    # Publish minimal custody.r5e.io/v1 kinds into the test deployment
    defs = publish_custody_defs(publisher)

    # Capture a session with encrypted content owned by @user_sub
    {:ok, session, record_ref, bytes_ref} = capture_session_with_content(deployment, store)

    %{
      deployment: deployment,
      store: store,
      defs: defs,
      session: session,
      record_ref: record_ref,
      bytes_ref: bytes_ref,
      gateway: gateway
    }
  end

  test "operator content read and export(content: true) return 403 without ReleaseGranted, then 200 after valid ReleaseGranted",
       %{
         deployment: deployment,
         store: store,
         defs: defs,
         session: session,
         record_ref: record_ref,
         bytes_ref: bytes_ref,
         gateway: gateway
       } do
    # 1. Without ReleaseGranted -> 403 release_grant_required on content download
    c1 =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c1.status == 403
    assert JSON.decode!(c1.resp_body) == %{"error" => "release_grant_required"}

    # 2. Export with content: true -> 403 release_grant_required
    c2 =
      conn(:post, "/v1/evidence/export")
      |> Map.put(:body_params, %{"session" => session, "content" => true})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.export()

    assert c2.status == 403
    assert JSON.decode!(c2.resp_body) == %{"error" => "release_grant_required"}

    # 3. Export with content: false (metadata only) -> 200
    c3 =
      conn(:post, "/v1/evidence/export")
      |> Map.put(:body_params, %{"session" => session, "content" => false})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.export()

    assert c3.status == 200

    # 4. Self-scoped ReadOwnPayload -> preserved (200!)
    c_own =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("employee", @user_sub)
      |> ApiHandler.content()

    assert c_own.status == 200
    assert c_own.resp_body == "secret-session-payload"

    # 5. Admit a DENIED ReleaseGranted -> still 403
    now = DateTime.utc_now()
    terms_ref = Ref.evidence(:crypto.strong_rand_bytes(32))

    req_ref =
      append_custody_record(
        store,
        deployment,
        gateway,
        defs["ReleaseRequest"],
        "ReleaseRequest",
        %{
          "requestId" => "rel_" <> String.duplicate("1", 32),
          "termsRef" => terms_ref,
          "power" => "inspect",
          "targets" => [session],
          "windowStart" => DateTime.to_iso8601(DateTime.add(now, -60, :second)),
          "windowEnd" => DateTime.to_iso8601(DateTime.add(now, 3600, :second))
        }
      )

    append_custody_record(store, deployment, gateway, defs["ReleaseGranted"], "ReleaseGranted", %{
      "requestRef" => req_ref,
      "outcome" => "denied"
    })

    c_denied =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_denied.status == 403

    # 6. Admit a valid RELEASED ReleaseGranted bound to recipient "auditor-1"
    append_custody_record(store, deployment, gateway, defs["ReleaseGranted"], "ReleaseGranted", %{
      "requestRef" => req_ref,
      "outcome" => "released",
      "recipient" => "auditor-1"
    })

    # Wrong recipient ("auditor-2") MUST be rejected (FR-012 recipient binding!)
    c_wrong_recipient =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("platform_operator", "auditor-2")
      |> ApiHandler.content()

    assert c_wrong_recipient.status == 403
    assert JSON.decode!(c_wrong_recipient.resp_body) == %{"error" => "release_grant_required"}

    # Matching recipient ("auditor-1") succeeds on content download and export(content: true)
    c_ok =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_ok.status == 200
    assert c_ok.resp_body == "secret-session-payload"

    c_export_ok =
      conn(:post, "/v1/evidence/export")
      |> Map.put(:body_params, %{"session" => session, "content" => true})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.export()

    assert c_export_ok.status == 200

    # 6b. POST /v1/evidence/disclosures is also gated by ReleaseGate!
    #     Without a grant for "urn:r5e:recipient:external-counsel", disclosure MUST return 403!
    c_disclose_denied =
      conn(:post, "/v1/evidence/disclosures")
      |> Map.put(:body_params, %{
        "records" => [record_ref],
        "recipient" => "urn:r5e:recipient:external-counsel"
      })
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.disclose()

    assert c_disclose_denied.status == 403
    assert JSON.decode!(c_disclose_denied.resp_body) == %{"error" => "release_grant_required"}

    # Once a ReleaseGranted authorizes "urn:r5e:recipient:external-counsel", disclosure succeeds (201)
    append_custody_record(store, deployment, gateway, defs["ReleaseGranted"], "ReleaseGranted", %{
      "requestRef" => req_ref,
      "outcome" => "released",
      "recipient" => "urn:r5e:recipient:external-counsel"
    })

    c_disclose_ok =
      conn(:post, "/v1/evidence/disclosures")
      |> Map.put(:body_params, %{
        "records" => [record_ref],
        "recipient" => "urn:r5e:recipient:external-counsel"
      })
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.disclose()

    assert c_disclose_ok.status == 201

    # 7. Admit a TermsAmendmentProposal power-withdrawal for "inspect" -> reverts to 403!
    append_custody_record(
      store,
      deployment,
      gateway,
      defs["TermsAmendmentProposal"],
      "TermsAmendmentProposal",
      %{
        "termsRef" => terms_ref,
        "proposalKind" => "power-withdrawal",
        "affectedPowers" => ["inspect"]
      }
    )

    c_withdrawn =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_withdrawn.status == 403
  end

  test "D4 WorkloadTerms carveout never bypasses unlinked human sessions, permits bound machine workload sessions, and stops when human TermsAccepted applies",
       %{
         deployment: deployment,
         store: store,
         defs: defs,
         record_ref: human_record_ref,
         bytes_ref: human_bytes_ref,
         gateway: gateway
       } do
    workload_actor = "urn:r5e:workload:nightly-cron"

    append_custody_record(store, deployment, gateway, defs["WorkloadTerms"], "WorkloadTerms", %{
      "workload" => workload_actor,
      "humanSubjectsPresent" => false,
      "powers" => [
        %{
          "power" => "inspect",
          "purposeCode" => "routine-engineer-inspect",
          "approvalMode" => "none"
        }
      ]
    })

    # 1. CRITICAL negative test: existence of a WorkloadTerms on the chain MUST NOT
    #    bypass the release gate for an unlinked human session (even with purpose=routine-debug)!
    c_unlinked_human =
      conn(:get, "/v1/evidence/records/#{human_record_ref}/content/#{human_bytes_ref}")
      |> Plug.Conn.put_req_header("x-r5e-purpose", "routine-debug")
      |> Map.put(:path_params, %{"ref" => human_record_ref, "bytes_ref" => human_bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_unlinked_human.status == 403
    assert JSON.decode!(c_unlinked_human.resp_body)["error"] == "release_grant_required"

    # 2. Dedicated machine-only session positively bound to WorkloadTerms:
    #    - WITHOUT purpose == "routine-debug" -> 403 release_grant_required!
    {:ok, wl_session, wl_record_ref, wl_bytes_ref} =
      capture_session_for_actor(workload_actor, "machine-workload-debug-payload")

    c_wl_no_purpose =
      conn(:get, "/v1/evidence/records/#{wl_record_ref}/content/#{wl_bytes_ref}")
      |> Map.put(:path_params, %{"ref" => wl_record_ref, "bytes_ref" => wl_bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_wl_no_purpose.status == 403

    #    - WITH purpose == "routine-debug" -> 200!
    c_wl =
      conn(:get, "/v1/evidence/records/#{wl_record_ref}/content/#{wl_bytes_ref}")
      |> Plug.Conn.put_req_header("x-r5e-purpose", "routine-debug")
      |> Map.put(:path_params, %{"ref" => wl_record_ref, "bytes_ref" => wl_bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_wl.status == 200

    # 3. Once human-subject TermsAccepted governs the session, carveout no longer applies -> 403
    append_custody_record(
      store,
      deployment,
      gateway,
      defs["TermsAccepted"],
      "TermsAccepted",
      %{"keyCustody" => "customer-kms"},
      wl_session
    )

    c_human =
      conn(:get, "/v1/evidence/records/#{wl_record_ref}/content/#{wl_bytes_ref}")
      |> Plug.Conn.put_req_header("x-r5e-purpose", "routine-debug")
      |> Map.put(:path_params, %{"ref" => wl_record_ref, "bytes_ref" => wl_bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c_human.status == 403
  end

  test "ReleaseGate fails closed with :store_unavailable when withdrawal or terms lookups fail",
       %{session: session} do
    defmodule FailingWithdrawalStore do
      def by_kind(_handle, "custody.r5e.io/v1/TermsAmendmentProposal", _prefix),
        do: {:error, :db_timeout}

      def by_kind(_handle, "custody.r5e.io/v1/ReleaseGranted", _prefix), do: {:ok, []}
      def by_kind(_handle, "custody.r5e.io/v1/WorkloadTerms", _prefix), do: {:ok, []}
      def by_kind(_handle, _kind, _prefix), do: {:error, :db_timeout}
      def by_session(_handle, _session), do: {:ok, []}
      def fetch(_handle, _ref), do: :error
    end

    assert {:error, :store_unavailable} =
             ReleaseGate.authorize({FailingWithdrawalStore, %{}}, session, :all,
               caller: "auditor-1"
             )

    defmodule FailingTermsStore do
      def by_kind(_handle, "custody.r5e.io/v1/WorkloadTerms", _prefix),
        do:
          {:ok,
           [
             %{
               ref: "evidence:sha256:" <> String.duplicate("1", 64),
               evidence: %{
                 "body" => %{
                   "workload" => "urn:r5e:workload:cron",
                   "humanSubjectsPresent" => false,
                   "powers" => [%{"power" => "inspect", "approvalMode" => "none"}]
                 }
               }
             }
           ]}

      def by_kind(_handle, "custody.r5e.io/v1/TermsAccepted", _prefix),
        do: {:error, :db_down}

      def by_session(_handle, _session),
        do: {:ok, [%{evidence: %{"actor" => "urn:r5e:workload:cron", "body" => %{}}}]}

      def fetch(_handle, _ref), do: :error
    end

    assert {:error, :store_unavailable} =
             ReleaseGate.authorize({FailingTermsStore, %{}}, session, :all,
               caller: "auditor-1",
               purpose: "routine-debug"
             )
  end

  test "when R5E_CUSTODY_REQUIRE_RELEASE_GRANT is false (default), operator content read succeeds without ReleaseGranted",
       %{record_ref: record_ref, bytes_ref: bytes_ref} do
    Application.put_env(:recurse_gateway, :custody_require_release_grant?, false)

    c =
      conn(:get, "/v1/evidence/records/#{record_ref}/content/#{bytes_ref}")
      |> Map.put(:path_params, %{"ref" => record_ref, "bytes_ref" => bytes_ref})
      |> bearer("platform_operator", "auditor-1")
      |> ApiHandler.content()

    assert c.status == 200
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp capture_session_with_content(_deployment, _store) do
    actor = "urn:r5e:principal:#{@tenant}:#{@user_sub}"
    capture_session_for_actor(actor, "secret-session-payload")
  end

  defp capture_session_for_actor(actor, bytes) do
    session =
      "urn:r5e:session:#{@tenant}:#{fingerprint(actor)}.s#{System.unique_integer([:positive])}"

    bytes_ref = Ref.bytes(bytes)

    {:ok, receipt} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: "#{@base}/ToolCall",
        actor: actor,
        session: session,
        attachments: [%{name: "args", bytes: bytes}],
        body:
          Body.tool_call(
            tool: "read_file",
            content_ref: "attachment:args",
            media_type: "text/plain",
            size: byte_size(bytes)
          )
      })

    :ok = Runtime.flush()
    {:ok, session, receipt.ref, bytes_ref}
  end

  defp fingerprint(actor) do
    :crypto.hash(:sha256, actor) |> binary_part(0, 8) |> Base.encode16(case: :lower)
  end

  defp publish_custody_defs(_publisher) do
    kinds = ~w(ReleaseRequest ReleaseGranted WorkloadTerms TermsAccepted TermsAmendmentProposal)

    Map.new(kinds, fn k ->
      kind_path = "custody.r5e.io/v1/#{k}"

      doc = %{
        "format" => "r5e.kind-definition/v1",
        "kind" => kind_path,
        "description" => "test #{k}",
        "substrate" => "event",
        "naming" => %{"mode" => "content"},
        "conformsTo" => [],
        "requiresAuthority" => false,
        "signatures" => 1,
        "schema" => %{"type" => "object", "additionalProperties" => true}
      }

      {k, Ref.bytes(Canonical.encode(doc))}
    end)
  end

  defp append_custody_record(
         {mod, handle},
         deployment,
         signer,
         schema_ref,
         kind,
         body,
         session \\ nil
       ) do
    info = Runtime.info()
    stream = "urn:r5e:stream:#{deployment}:custody:#{kind}:#{System.unique_integer([:positive])}"

    ev =
      Evidence.new(
        kind_path: "custody.r5e.io/v1/#{kind}",
        schema_ref: schema_ref,
        profile_ref: info.profile_ref,
        issuer: signer.key_id,
        actor: info.actor,
        stream: stream,
        session: session,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: body
      )

    {:ok, signed} = Envelope.sign(ev, signer)

    :ok =
      mod.append(handle, %{
        ref: signed.ref,
        stream: stream,
        seq: 1,
        kind_path: "custody.r5e.io/v1/#{kind}",
        evidence: ev,
        envelope: signed.envelope,
        blobs: []
      })

    signed.ref
  end

  defp root_endorsement(root, gateway) do
    {:ok, %{ref: schema_ref}} = Definitions.fetch("#{@base}/Endorsement")
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    ev =
      Evidence.new(
        kind_path: "#{@base}/Endorsement",
        schema_ref: schema_ref,
        profile_ref: Ref.bytes("root profile"),
        issuer: root.key_id,
        actor: "urn:r5e:root:test",
        stream: "urn:r5e:stream:test:authority",
        seq: 1,
        previous: nil,
        captured_at: DateTime.add(now, -3600, :second),
        body: %{
          "subject" => gateway.key_id,
          "kinds" => ["#{@base}/ToolCall", "#{@base}/EpochSeal", "#{@base}/Disclosure"],
          "mayEndorse" => true,
          "notBefore" => DateTime.to_iso8601(DateTime.add(now, -7200, :second)),
          "notAfter" => DateTime.to_iso8601(DateTime.add(now, 86_400 * 30, :second))
        }
      )

    {:ok, signed} = Envelope.sign(ev, root)
    signed
  end

  defp wire(key) do
    %{
      "keyid" => key.key_id,
      "algorithm" => key.algorithm,
      "bytes" => Base.encode64(key.public_key)
    }
  end

  defp bearer(conn, role, sub) do
    token =
      JwtTestHelper.mint_test_jwt(
        subject: sub,
        recurse_role: role,
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid"
      )

    Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
  end

  defp write_bundle do
    Path.expand("../../priv/reference_policies/platform_roles.cedar", __DIR__)
  end

  defp put_env(key, val) do
    prev = Application.get_env(:recurse_gateway, key)
    Application.put_env(:recurse_gateway, key, val)
    {key, prev}
  end
end
