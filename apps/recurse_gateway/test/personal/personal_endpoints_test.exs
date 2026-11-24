defmodule Recurse.Gateway.Personal.PersonalEndpointsTest do
  @moduledoc """
  End-to-end tests for opt-in `personal.r5e.io/v1` routes (`R5E_PERSONAL_ENABLED=true`):
    * Uniform 404 fail-closed (authenticated, unauthenticated, malformed) when disabled
    * Strict household selection (`400 household_id_required` when ambiguous) and
      `child` principal mutation refusal (`403 parent_role_required`)
    * Real admitted evidence refs (resolvable via `GET /v1/evidence/records/:ref`)
      and `503 evidence_runtime_unavailable` fail-closed when runtime is stopped
    * Bilateral QR child pairing, closed 5-kind `Badge.kinds` allowlist, honest
      device revocation (`deviceKeyRevoked: true`, `tokensRevoked: false`)
    * Phase-2 `client-e2ee` key wraps & blobs, foreign-wrap overwrite protection,
      verified household `X-R5E-Erasure-Ref`, durable `PayloadDisposition`-first
      erasure, active `RetentionHold` `409 under_hold` blocking, 410 tombstones
    * Two-parent (`threshold: 2`) co-sign across `session`, `member`, `household`,
      settings downgrades, `disable-assisted`, replay blocking, and post-erasure
      `PersonalErasure` admission compatibility
    * D19 metadata-only `GET /recovery-envelope`, server clock-offset cooling-off
      window (with real 86,400s floor), initiator-bound completion, real member
      key rotation, and honest independent completion flags
  """

  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  import Plug.Test

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Personal.Policy
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.Provenance.{Retention, Runtime}
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Provenance.{Envelope, Evidence, Key, Ref}
  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore}
  alias Recurse.Providers.Personal, as: Store
  alias Recurse.Providers.Repo

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @router_opts Router.init([])

  setup %{tmp_dir: tmp_dir} do
    owner = Sandbox.start_owner!(Repo, shared: true)
    on_exit(fn -> Sandbox.stop_owner(owner) end)

    start_supervised!(
      Supervisor.child_spec(
        {BundleLoader,
         bundle_path: Path.expand("../../priv/reference_policies/platform_roles.cedar", __DIR__),
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
      ledger: {Recurse.Gateway.Test.StubLedger, %{}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant,
      signer: "observed://gateway/test"
    })

    key_file = Path.join(tmp_dir, "content.key")
    :ok = LocalKeyService.generate(key_file)
    {:ok, keys} = LocalKeyService.open(key_file)
    store = {PostgresEvidenceStore, %{repo: Repo, keys: {LocalKeyService, keys}}}

    deployment = "personal-test-#{System.unique_integer([:positive])}"
    gateway = Key.generate("ed25519")

    restore = [
      put_env(:personal_enabled?, true),
      put_env(:personal_recovery_cooling_off_seconds, 86_400),
      put_env(:personal_recovery_clock_offset_seconds, 0),
      put_env(:evidence_deployment, deployment),
      put_env(:evidence_content_key_file, key_file),
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

    %{deployment: deployment, store: store}
  end

  test "all /v1/personal/* routes return 404 when R5E_PERSONAL_ENABLED is false regardless of auth or body" do
    Application.put_env(:recurse_gateway, :personal_enabled?, false)

    routes = [
      {:post, "/v1/personal/households", %{}},
      {:get, "/v1/personal/digests", nil},
      {:patch, "/v1/personal/settings", %{}},
      {:post, "/v1/personal/recipient-keys", %{}},
      {:put, "/v1/personal/key-wraps", %{}},
      {:get, "/v1/personal/key-wraps", nil},
      {:delete, "/v1/personal/key-wraps?scope=x", nil},
      {:put, "/v1/personal/blobs/bytes:sha256:" <> String.duplicate("a", 64), %{}},
      {:get, "/v1/personal/blobs/bytes:sha256:" <> String.duplicate("a", 64), nil},
      {:delete, "/v1/personal/blobs/bytes:sha256:" <> String.duplicate("a", 64), nil},
      {:get, "/v1/personal/recovery-envelope", nil},
      {:put, "/v1/personal/recovery-envelope", %{}},
      {:delete, "/v1/personal/recovery-envelope", nil},
      {:post, "/v1/personal/recovery/requests", %{}},
      {:post, "/v1/personal/recovery/disable-assisted", %{}},
      {:post, "/v1/personal/pairings", %{}},
      {:post, "/v1/personal/pairings/pair_123/device-claim", %{}},
      {:post, "/v1/personal/devices/key_1/revoke", %{}},
      {:post, "/v1/personal/erasures", %{}},
      {:post, "/v1/personal/erasures/proposals", %{}}
    ]

    for {method, path, body} <- routes do
      # Authenticated caller -> 404
      c_auth = call_router(method, path, body, role: "owner", sub: "parent-a")
      assert c_auth.status == 404, "#{method} #{path} with auth returned #{c_auth.status}"

      # Unauthenticated caller -> 404 (NEVER 401!)
      c_anon = call_router(method, path, body, auth?: false)
      assert c_anon.status == 404, "#{method} #{path} without auth returned #{c_anon.status}"
    end
  end

  test "ambiguous household selection fails with 400 and child principals cannot mutate household state" do
    child_id = "mem_cccccccccccc"

    c_hh1 =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "custodyMode" => "client-e2ee",
          "recoveryMode" => "r5e_assisted",
          "members" => [
            %{
              "memberId" => child_id,
              "role" => "child",
              "ageBand" => "13-15",
              "authSubject" => "child-user-1"
            }
          ]
        },
        role: "owner",
        sub: "multi-parent"
      )

    c_hh2 =
      call_router(
        :post,
        "/v1/personal/households",
        %{"custodyMode" => "client-e2ee"},
        role: "owner",
        sub: "multi-parent"
      )

    assert c_hh1.status == 201
    assert c_hh2.status == 201
    %{"householdId" => hh1} = JSON.decode!(c_hh1.resp_body)

    # Caller belongs to 2 households and omits x-r5e-household-id -> 400 household_id_required
    c_ambig =
      call_router(:get, "/v1/personal/digests", nil, role: "owner", sub: "multi-parent")

    assert c_ambig.status == 400
    assert JSON.decode!(c_ambig.resp_body)["error"] == "household_id_required"

    # Explicit x-r5e-household-id resolves cleanly
    c_explicit =
      call_router(:get, "/v1/personal/digests", nil,
        role: "owner",
        sub: "multi-parent",
        hh_id: hh1
      )

    assert c_explicit.status == 200

    # Caller with no household membership -> 404 (never falls back to another household!)
    c_stranger = call_router(:get, "/v1/personal/digests", nil, role: "owner", sub: "stranger")
    assert c_stranger.status == 404

    # Child principal is rejected with 403 parent_role_required on EVERY mutating route,
    # even if JWT carries a broad role claim (defense-in-depth beyond Cedar!)
    pub_b64 = Base.encode64(:crypto.strong_rand_bytes(32))
    scope = "urn:r5e:session:#{hh1}:child.chat-1"
    bytes_ref = Ref.bytes("child-upload")

    mutating_calls = [
      {:patch, "/v1/personal/settings", %{"custodyMode" => "gateway-managed"}},
      {:get, "/v1/personal/digests", nil},
      {:post, "/v1/personal/pairings", %{"childMemberId" => child_id}},
      {:post, "/v1/personal/recipient-keys",
       %{
         "recipientKind" => "parent_device",
         "algorithm" => "x25519",
         "publicKeyBase64" => pub_b64
       }},
      {:put, "/v1/personal/key-wraps",
       %{
         "scope" => scope,
         "wraps" => [
           %{
             "recipientKeyId" => "x25519:sha256:" <> String.duplicate("a", 64),
             "wrapAlg" => "x25519-hkdf-sha256-aes256gcm-v1",
             "ephemeralPubKey" => pub_b64,
             "nonce" => Base.encode64(:crypto.strong_rand_bytes(12)),
             "wrappedDek" => Base.encode64(:crypto.strong_rand_bytes(48))
           }
         ]
       }},
      {:delete, "/v1/personal/key-wraps?scope=#{URI.encode_www_form(scope)}", nil},
      {:put, "/v1/personal/blobs/#{bytes_ref}",
       %{
         "scope" => scope,
         "nonce" => Base.encode64(:crypto.strong_rand_bytes(12)),
         "ciphertextBase64" => Base.encode64("child-upload")
       }},
      {:delete, "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}", nil},
      {:post, "/v1/personal/erasures",
       %{
         "scope" => "session",
         "targetId" => scope,
         "erasureMethod" => "client-key-and-blob-deletion"
       }},
      {:post, "/v1/personal/erasures/proposals",
       %{
         "scope" => "household",
         "targetId" => hh1,
         "erasureMethod" => "client-key-and-blob-deletion"
       }},
      {:put, "/v1/personal/recovery-envelope", valid_envelope_payload()},
      {:get, "/v1/personal/recovery-envelope", nil},
      {:delete, "/v1/personal/recovery-envelope", nil},
      {:post, "/v1/personal/recovery/requests",
       %{
         "newRootPublicKey" => key_pub_map(Key.generate("ed25519")),
         "newWorkingPublicKey" => key_pub_map(Key.generate("es256"))
       }},
      {:post, "/v1/personal/recovery/disable-assisted", %{}}
    ]

    for {method, path, body} <- mutating_calls do
      c = call_router(method, path, body, role: "owner", sub: "child-user-1", hh_id: hh1)

      assert c.status == 403,
             "#{method} #{path} allowed child with status #{c.status}: #{c.resp_body}"

      assert JSON.decode!(c.resp_body)["error"] == "parent_role_required"
    end
  end

  test "child QR pairing enforces closed 5-kind allowlist, emits resolvable refs, and revokes honestly" do
    child_id = "mem_111122223333"

    c_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "profileMode" => "family",
          "custodyMode" => "client-e2ee",
          "recoveryMode" => "self_only",
          "members" => [%{"memberId" => child_id, "role" => "child", "ageBand" => "8-12"}]
        },
        role: "owner",
        sub: "parent-a"
      )

    assert c_hh.status == 201
    %{"householdId" => hh_id} = JSON.decode!(c_hh.resp_body)

    # 1. Parent initiates pairing
    c_pair =
      call_router(:post, "/v1/personal/pairings", %{"childMemberId" => child_id},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_pair.status == 201

    %{"challengeId" => cid, "pairingCode" => code, "nonce" => nonce} =
      JSON.decode!(c_pair.resp_body)

    # 2. Child device claims challenge with valid Ed25519 PoP
    child_key = Key.generate("ed25519")
    pop_msg = "r5e.child-pairing-pop/v1:#{cid}:#{nonce}"
    {:ok, pop_sig} = child_key.sign.(pop_msg)
    pub_map = key_pub_map(child_key)

    # Wrong code -> 401
    c_bad_code =
      call_router(
        :post,
        "/v1/personal/pairings/#{cid}/device-claim",
        %{
          "pairingCode" => "wrong-code",
          "devicePublicKey" => pub_map,
          "popSignature" => Base.encode64(pop_sig)
        },
        auth?: false
      )

    assert c_bad_code.status == 401

    # Valid claim -> 200
    c_claim =
      call_router(
        :post,
        "/v1/personal/pairings/#{cid}/device-claim",
        %{
          "pairingCode" => code,
          "devicePublicKey" => pub_map,
          "popSignature" => Base.encode64(pop_sig)
        },
        auth?: false
      )

    assert c_claim.status == 200
    claim_body = JSON.decode!(c_claim.resp_body)
    assert claim_body["deviceKeyId"] == child_key.key_id
    assert claim_body["badgeKinds"] == Policy.child_badge_kinds()

    # Replaying same challenge -> 409
    assert call_router(
             :post,
             "/v1/personal/pairings/#{cid}/device-claim",
             %{
               "pairingCode" => code,
               "devicePublicKey" => pub_map,
               "popSignature" => Base.encode64(pop_sig)
             },
             auth?: false
           ).status == 409

    # 3. Wildcard or parent-only badge kinds MUST fail with 422
    for forbidden_kinds <- [
          ["personal.r5e.io/v1/*"],
          ["personal.r5e.io/v1/FamilyGuardrailSet"],
          ["personal.r5e.io/v1/HouseholdProfile"],
          ["personal.r5e.io/v1/PersonalErasure"],
          Policy.child_badge_kinds() ++ ["personal.r5e.io/v1/FamilyGuardrailSet"]
        ] do
      c_bad_badge =
        call_router(
          :post,
          "/v1/personal/pairings/#{cid}/finalize",
          %{"badgeKinds" => forbidden_kinds},
          role: "owner",
          sub: "parent-a",
          hh_id: hh_id
        )

      assert c_bad_badge.status == 422
      assert JSON.decode!(c_bad_badge.resp_body)["error"] == "invalid_child_badge_kinds"
    end

    # 4. Finalizing with exact 5-kind allowlist succeeds with real resolvable refs!
    c_fin =
      call_router(
        :post,
        "/v1/personal/pairings/#{cid}/finalize",
        %{"badgeKinds" => Policy.child_badge_kinds()},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_fin.status == 201, "expected 201, got #{c_fin.status}: #{c_fin.resp_body}"
    fin_body = JSON.decode!(c_fin.resp_body)
    assert fin_body["deviceKeyId"] == child_key.key_id
    assert_record_resolvable!(fin_body["badgeRef"])
    assert_record_resolvable!(fin_body["pairedRecordRef"])

    # 5. Defense-in-depth admission guard blocks child device submitting parent-only kinds
    guardrail_ev = %{
      "apiVersion" => "personal.r5e.io/v1",
      "kind" => "FamilyGuardrailSet",
      "issuer" => child_key.key_id
    }

    assert {:error, :invalid_child_badge_kinds} =
             Policy.check_admission_batch([%{evidence: guardrail_ev}], nil)

    intervention_ev = %{
      "apiVersion" => "personal.r5e.io/v1",
      "kind" => "SafetyIntervention",
      "issuer" => child_key.key_id
    }

    assert :ok = Policy.check_admission_batch([%{evidence: intervention_ev}], nil)

    # 6. Revoking child device emits a real resolvable revocationRef and reports
    #    deviceKeyRevoked: true, tokensRevoked: false honestly!
    c_rev =
      call_router(
        :post,
        "/v1/personal/devices/#{URI.encode_www_form(child_key.key_id)}/revoke",
        %{},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_rev.status == 200
    rev_body = JSON.decode!(c_rev.resp_body)
    assert rev_body["deviceKeyId"] == child_key.key_id
    assert rev_body["deviceKeyRevoked"] == true
    assert rev_body["tokensRevoked"] == false
    assert_record_resolvable!(rev_body["revocationRef"])

    # Revoked child device is rejected on subsequent evidence admission
    assert {:error, :child_device_revoked} =
             Policy.check_admission_batch([%{evidence: intervention_ev}], nil)

    # 7. Parent can update settings and read digests
    c_set =
      call_router(
        :patch,
        "/v1/personal/settings",
        %{
          "quietHours" => %{"tz" => "America/Los_Angeles", "startMin" => 1230, "endMin" => 420},
          "memberTeenConfidentiality" => %{child_id => "standard"}
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_set.status == 200
    assert JSON.decode!(c_set.resp_body)["quietHours"]["tz"] == "America/Los_Angeles"
  end

  test "client-e2ee enforces cross-household isolation, wrap overwrite protection, verified erasure refs, and RetentionHold blocking" do
    # Household A (with co-parent A2) and Household B
    c_a =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "custodyMode" => "client-e2ee",
          "members" => [
            %{
              "memberId" => "mem_a2a2a2a2a2a2",
              "role" => "parent",
              "ageBand" => "adult",
              "authSubject" => "parent-a2"
            }
          ]
        },
        role: "owner",
        sub: "parent-a"
      )

    c_b =
      call_router(:post, "/v1/personal/households", %{"custodyMode" => "client-e2ee"},
        role: "owner",
        sub: "parent-b"
      )

    %{"householdId" => hh_a} = JSON.decode!(c_a.resp_body)
    %{"householdId" => hh_b} = JSON.decode!(c_b.resp_body)

    # Register X25519 recipient keys for Parent A and Parent A2
    c_rk_a =
      call_router(
        :post,
        "/v1/personal/recipient-keys",
        %{
          "recipientKind" => "parent_device",
          "algorithm" => "x25519",
          "publicKeyBase64" => Base.encode64(:crypto.strong_rand_bytes(32))
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    c_rk_a2 =
      call_router(
        :post,
        "/v1/personal/recipient-keys",
        %{
          "recipientKind" => "parent_device",
          "algorithm" => "x25519",
          "publicKeyBase64" => Base.encode64(:crypto.strong_rand_bytes(32))
        },
        role: "parent",
        sub: "parent-a2",
        hh_id: hh_a
      )

    assert c_rk_a.status == 201
    assert c_rk_a2.status == 201
    %{"recipientKeyId" => rk_a} = JSON.decode!(c_rk_a.resp_body)
    %{"recipientKeyId" => rk_a2} = JSON.decode!(c_rk_a2.resp_body)

    scope = "urn:r5e:session:#{hh_a}:abcdef0123456789.chat-1"
    scope_direct = "urn:r5e:session:#{hh_a}:abcdef0123456789.chat-2"
    scope_held = "urn:r5e:session:#{hh_a}:abcdef0123456789.chat-held"
    ciphertext = "encrypted-e2ee-chat-bytes"
    bytes_ref = Ref.bytes(ciphertext)
    nonce_b64 = Base.encode64(:crypto.strong_rand_bytes(12))

    # Parent A stores initial wraps for both Parent A and Parent A2 -> 201
    assert call_router(
             :put,
             "/v1/personal/key-wraps",
             %{
               "scope" => scope,
               "wraps" => [wrap_payload(rk_a), wrap_payload(rk_a2)]
             },
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a
           ).status == 201

    # Parent A attempting to overwrite Parent A2's existing wrap -> 409 wrap_overwrite_forbidden!
    c_overwrite =
      call_router(
        :put,
        "/v1/personal/key-wraps",
        %{"scope" => scope, "wraps" => [wrap_payload(rk_a2)]},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_overwrite.status == 409
    assert JSON.decode!(c_overwrite.resp_body)["error"] == "wrap_overwrite_forbidden"

    # Parent A CAN update Parent A's own wrap -> 201
    assert call_router(
             :put,
             "/v1/personal/key-wraps",
             %{"scope" => scope, "wraps" => [wrap_payload(rk_a)]},
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a
           ).status == 201

    # Tampered ciphertext -> 422 digest_mismatch
    c_bad_digest =
      call_router(
        :put,
        "/v1/personal/blobs/#{bytes_ref}",
        %{
          "scope" => scope,
          "nonce" => nonce_b64,
          "ciphertextBase64" => Base.encode64(ciphertext <> "tampered")
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_bad_digest.status == 422
    assert JSON.decode!(c_bad_digest.resp_body)["error"] == "digest_mismatch"

    # Store valid blobs on scope, scope_direct, and scope_held
    for s <- [scope, scope_direct, scope_held] do
      assert call_router(
               :put,
               "/v1/personal/blobs/#{bytes_ref}",
               %{
                 "scope" => s,
                 "nonce" => nonce_b64,
                 "ciphertextBase64" => Base.encode64(ciphertext)
               },
               role: "owner",
               sub: "parent-a",
               hh_id: hh_a
             ).status == 201
    end

    # Cross-household read as Parent B -> 404
    assert call_router(
             :get,
             "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}",
             nil,
             role: "owner",
             sub: "parent-b",
             hh_id: hh_a
           ).status == 404

    # Foreign erasure target from Household B against Household A's session -> 404!
    assert call_router(
             :post,
             "/v1/personal/erasures",
             %{
               "scope" => "session",
               "targetId" => scope,
               "erasureMethod" => "client-key-and-blob-deletion"
             },
             role: "owner",
             sub: "parent-b",
             hh_id: hh_b
           ).status == 404

    # Direct DELETE without X-R5E-Erasure-Ref OR with forged ref -> 409 erasure_record_required
    assert call_router(
             :delete,
             "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope_direct)}",
             nil,
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a
           ).status == 409

    forged_ref = Ref.evidence(:crypto.strong_rand_bytes(32))

    assert call_router(
             :delete,
             "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope_direct)}",
             nil,
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a,
             headers: [{"x-r5e-erasure-ref", forged_ref}]
           ).status == 409

    # Household B executes a real erasure on Household B -> gets a real admitted ref for B
    c_erase_b =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "household",
          "targetId" => hh_b,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-b",
        hh_id: hh_b
      )

    assert c_erase_b.status == 201
    %{"erasureRef" => hh_b_erasure_ref} = JSON.decode!(c_erase_b.resp_body)
    assert_record_resolvable!(hh_b_erasure_ref)

    # Household A CANNOT use Household B's real erasureRef to delete A's blob or wraps!
    assert call_router(
             :delete,
             "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope_direct)}",
             nil,
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a,
             headers: [{"x-r5e-erasure-ref", hh_b_erasure_ref}]
           ).status == 409

    assert call_router(
             :delete,
             "/v1/personal/key-wraps?scope=#{URI.encode_www_form(scope)}",
             nil,
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a,
             headers: [{"x-r5e-erasure-ref", hh_b_erasure_ref}]
           ).status == 409

    # A non-erasure Observation belonging to the SAME household is ALSO rejected
    # as X-R5E-Erasure-Ref (must be PayloadDisposition or PersonalErasure)!
    {:ok, obs_ref} =
      Recurse.Gateway.Personal.Ledger.record_observation(
        "personal.erasure.cosign_decision",
        "urn:r5e:principal:test:parent-a",
        %{"householdId" => hh_a, "scope" => "household", "targetId" => hh_a}
      )

    assert call_router(
             :delete,
             "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope_direct)}",
             nil,
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a,
             headers: [{"x-r5e-erasure-ref", obs_ref}]
           ).status == 409

    # Execute client-e2ee erasure on `scope` -> 201, durable PayloadDisposition recorded FIRST
    c_erase =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "session",
          "targetId" => scope,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_erase.status == 201
    erase_body = JSON.decode!(c_erase.resp_body)
    assert erase_body["keyWrapsDeleted"] == 2
    assert erase_body["blobsTombstoned"] == 1
    assert [disp_ref] = erase_body["dispositionRefs"]
    disp_rec = assert_record_resolvable!(disp_ref)
    assert disp_rec["kind"] == "provenance.r5e.io/v2/PayloadDisposition"
    assert_record_resolvable!(erase_body["erasureRef"])

    # Subsequent GET returns 410 for A, 404 for B; re-upload returns 410 (anti-resurrection)
    c_gone =
      call_router(
        :get,
        "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}",
        nil,
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_gone.status == 410
    assert JSON.decode!(c_gone.resp_body)["error"] == "ERR_CONTENT_DISPOSED"

    assert call_router(
             :put,
             "/v1/personal/blobs/#{bytes_ref}",
             %{
               "scope" => scope,
               "nonce" => nonce_b64,
               "ciphertextBase64" => Base.encode64(ciphertext)
             },
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a
           ).status == 410

    # Active RetentionHold on `scope_held` blocks BOTH session and household erasure with
    # 409 under_hold (NEVER 500!), leaving the held blob completely intact!
    {:ok, %{"hold" => hold_ref}} =
      Retention.hold(
        %{"scope" => scope_held, "reason" => "safeguarding_review"},
        "urn:r5e:principal:test:counselor"
      )

    c_held_session =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "session",
          "targetId" => scope_held,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_held_session.status == 409
    held_s_body = JSON.decode!(c_held_session.resp_body)
    assert held_s_body["error"] == "under_hold"
    assert held_s_body["about"] == hold_ref

    c_held_hh =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "household",
          "targetId" => hh_a,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_held_hh.status == 409
    assert JSON.decode!(c_held_hh.resp_body)["error"] == "under_hold"

    # Held blob is STILL readable (200) — nothing was deleted while under hold!
    c_still_intact =
      call_router(
        :get,
        "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope_held)}",
        nil,
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_still_intact.status == 200
    assert c_still_intact.resp_body == ciphertext

    # Household A's own real erasure ref DOES authorize direct DELETE on `scope_direct`
    # when scope_direct has an admitted erasure ref covering it:
    c_erase_direct =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "session",
          "targetId" => scope_direct,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_erase_direct.status == 201
    %{"erasureRef" => direct_erasure_ref} = JSON.decode!(c_erase_direct.resp_body)

    assert call_router(
             :delete,
             "/v1/personal/key-wraps?scope=#{URI.encode_www_form(scope_direct)}",
             nil,
             role: "owner",
             sub: "parent-a",
             hh_id: hh_a,
             headers: [{"x-r5e-erasure-ref", direct_erasure_ref}]
           ).status == 200
  end

  test "two-parent threshold: 2 enforces co-sign across all scopes, disable-assisted, settings, replay prevention, and admission compatibility" do
    child_id = "mem_cccccccc1111"

    c_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "custodyMode" => "client-e2ee",
          "recoveryMode" => "r5e_assisted",
          "threshold" => 2,
          "ownerMemberId" => "mem_aaaaaaaaaaaa",
          "ownerRootKeyId" => "key:ed25519:sha256:" <> String.duplicate("1", 64),
          "ownerWorkingKeyId" => "key:es256:sha256:" <> String.duplicate("2", 64),
          "members" => [
            %{
              "memberId" => "mem_bbbbbbbbbbbb",
              "role" => "parent",
              "ageBand" => "adult",
              "authSubject" => "parent-b",
              "rootKeyId" => "key:ed25519:sha256:" <> String.duplicate("3", 64),
              "workingKeyId" => "key:es256:sha256:" <> String.duplicate("4", 64)
            },
            %{
              "memberId" => child_id,
              "role" => "child",
              "ageBand" => "8-12"
            }
          ]
        },
        role: "owner",
        sub: "parent-a"
      )

    assert c_hh.status == 201
    %{"householdId" => hh_id} = JSON.decode!(c_hh.resp_body)
    session_target = "urn:r5e:session:#{hh_id}:child.s1"

    # 1. Unilateral erasure fails with 409 co_sign_required across ALL 3 scopes!
    for {scope, target} <- [
          {"session", session_target},
          {"member", child_id},
          {"household", hh_id}
        ] do
      c_uni =
        call_router(
          :post,
          "/v1/personal/erasures",
          %{
            "scope" => scope,
            "targetId" => target,
            "erasureMethod" => "client-key-and-blob-deletion"
          },
          role: "owner",
          sub: "parent-a",
          hh_id: hh_id
        )

      assert c_uni.status == 409, "unilateral #{scope} erasure returned #{c_uni.status}"
      assert JSON.decode!(c_uni.resp_body)["error"] == "co_sign_required"
    end

    # 2. Single parent CANNOT downgrade threshold (2 -> 1) OR recoveryMode (r5e_assisted -> self_only)
    for patch_body <- [%{"threshold" => 1}, %{"recoveryMode" => "self_only"}] do
      c_patch =
        call_router(:patch, "/v1/personal/settings", patch_body,
          role: "owner",
          sub: "parent-a",
          hh_id: hh_id
        )

      assert c_patch.status == 409
      assert JSON.decode!(c_patch.resp_body)["error"] == "co_sign_required"
    end

    # 3. Single parent CANNOT call disable-assisted without coSignRef -> 409 co_sign_required
    c_dis_uni =
      call_router(:post, "/v1/personal/recovery/disable-assisted", %{},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_dis_uni.status == 409
    assert JSON.decode!(c_dis_uni.resp_body)["error"] == "co_sign_required"

    # 4. Parent A creates household erasure proposal; self-approval rejected; Parent B approves
    c_prop =
      call_router(
        :post,
        "/v1/personal/erasures/proposals",
        %{
          "scope" => "household",
          "targetId" => hh_id,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_prop.status == 201
    %{"proposalId" => prop_id, "requestDigest" => digest} = JSON.decode!(c_prop.resp_body)

    c_self =
      call_router(
        :post,
        "/v1/personal/erasures/proposals/#{prop_id}/approve",
        %{"requestDigest" => digest},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_self.status == 409
    assert JSON.decode!(c_self.resp_body)["error"] == "self_approval_forbidden"

    c_approve =
      call_router(
        :post,
        "/v1/personal/erasures/proposals/#{prop_id}/approve",
        %{"requestDigest" => digest},
        role: "parent",
        sub: "parent-b",
        hh_id: hh_id
      )

    assert c_approve.status == 201
    %{"coSignRef" => co_sign_ref} = JSON.decode!(c_approve.resp_body)
    assert_record_resolvable!(co_sign_ref)

    # 5. Executing household erasure with coSignRef -> 201 + resolvable refs
    c_exec =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "household",
          "targetId" => hh_id,
          "erasureMethod" => "client-key-and-blob-deletion",
          "coSignRef" => co_sign_ref
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_exec.status == 201
    %{"erasureRef" => erasure_ref} = JSON.decode!(c_exec.resp_body)
    assert_record_resolvable!(erasure_ref)

    # 6. Replaying the already-executed coSignRef on a second erasure -> 409 co_sign_required!
    c_replay =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "household",
          "targetId" => hh_id,
          "erasureMethod" => "client-key-and-blob-deletion",
          "coSignRef" => co_sign_ref
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_replay.status == 409
    assert JSON.decode!(c_replay.resp_body)["error"] == "co_sign_required"

    # 7. Post-erasure PersonalErasure admission compatibility:
    #    The matching executed erasure_ref passes Policy.check_admission_batch,
    #    while an unrelated ref or missing coSignRef fails with :co_sign_required!
    erasure_ev = %{
      "apiVersion" => "personal.r5e.io/v1",
      "kind" => "PersonalErasure",
      "body" => %{
        "scope" => "household",
        "targetId" => hh_id,
        "coSignRef" => co_sign_ref
      }
    }

    assert :ok =
             Policy.check_admission_batch([%{ref: erasure_ref, evidence: erasure_ev}], nil)

    assert {:error, :co_sign_required} =
             Policy.check_admission_batch(
               [%{ref: Ref.evidence(:crypto.strong_rand_bytes(32)), evidence: erasure_ev}],
               nil
             )

    # 8. Two-parent co-signed disable-assisted succeeds and emits real resolvable ref!
    c_prop2 =
      call_router(
        :post,
        "/v1/personal/erasures/proposals",
        %{
          "scope" => "household",
          "targetId" => hh_id,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    %{"proposalId" => prop2_id, "requestDigest" => digest2} = JSON.decode!(c_prop2.resp_body)

    c_app2 =
      call_router(
        :post,
        "/v1/personal/erasures/proposals/#{prop2_id}/approve",
        %{"requestDigest" => digest2},
        role: "parent",
        sub: "parent-b",
        hh_id: hh_id
      )

    %{"coSignRef" => co_sign_ref2} = JSON.decode!(c_app2.resp_body)

    c_dis_ok =
      call_router(
        :post,
        "/v1/personal/recovery/disable-assisted",
        %{"coSignRef" => co_sign_ref2},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_dis_ok.status == 200
    dis_body = JSON.decode!(c_dis_ok.resp_body)
    assert dis_body["recoveryMode"] == "self_only"
    assert_record_resolvable!(dis_body["recoveryCompletedRef"])
  end

  test "D19 recovery enforces metadata-only GET, real 86400s cooling-off with clock offset, initiator binding, and real key rotation" do
    # 1. self_only household rejects recovery-envelope and recovery requests
    c_self_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{"custodyMode" => "client-e2ee", "recoveryMode" => "self_only"},
        role: "owner",
        sub: "self-parent"
      )

    %{"householdId" => self_hh} = JSON.decode!(c_self_hh.resp_body)

    assert call_router(:put, "/v1/personal/recovery-envelope", valid_envelope_payload(),
             role: "owner",
             sub: "self-parent",
             hh_id: self_hh
           ).status == 409

    assert call_router(:get, "/v1/personal/recovery-envelope", nil,
             role: "owner",
             sub: "self-parent",
             hh_id: self_hh
           ).status == 404

    assert call_router(
             :post,
             "/v1/personal/recovery/requests",
             %{
               "newRootPublicKey" => key_pub_map(Key.generate("ed25519")),
               "newWorkingPublicKey" => key_pub_map(Key.generate("es256"))
             },
             role: "owner",
             sub: "self-parent",
             hh_id: self_hh
           ).status == 404

    # 2. r5e_assisted household with co-parent B
    c_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "custodyMode" => "client-e2ee",
          "recoveryMode" => "r5e_assisted",
          "members" => [
            %{
              "memberId" => "mem_d19000000bbb",
              "role" => "parent",
              "ageBand" => "adult",
              "authSubject" => "assisted-parent-b"
            }
          ]
        },
        role: "owner",
        sub: "assisted-parent"
      )

    assert c_hh.status == 201
    %{"householdId" => hh_id, "ownerMemberId" => owner_member_id} = JSON.decode!(c_hh.resp_body)

    # Bogus/missing public key material fails closed with 422 invalid_public_key
    c_bad_key =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => %{"alg" => "ed25519"},
          "newWorkingPublicKey" => %{"alg" => "es256"}
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_bad_key.status == 422
    assert JSON.decode!(c_bad_key.resp_body)["error"] == "invalid_public_key"

    # 3. Never-enrolled envelope: authority rotates ONLY after real 86,400s cooling-off!
    new_root_1 = Key.generate("ed25519")
    new_work_1 = Key.generate("es256")

    c_req_no_env =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => key_pub_map(new_root_1),
          "newWorkingPublicKey" => key_pub_map(new_work_1),
          "coolingOffSeconds" => 0
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_req_no_env.status == 202
    %{"requestId" => req_no_env} = JSON.decode!(c_req_no_env.resp_body)

    # Cooling-off floor (86,400s) CANNOT be bypassed by client coolingOffSeconds: 0!
    c_early =
      call_router(:post, "/v1/personal/recovery/requests/#{req_no_env}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_early.status == 409
    assert JSON.decode!(c_early.resp_body)["error"] == "waiting_window_active"

    # Advance server test clock past 86,400s
    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 86_401)

    # Initiator binding: Parent B CANNOT complete Parent A's recovery request!
    c_wrong_initiator =
      call_router(:post, "/v1/personal/recovery/requests/#{req_no_env}/complete", %{},
        role: "parent",
        sub: "assisted-parent-b",
        hh_id: hh_id
      )

    assert c_wrong_initiator.status == 403
    assert JSON.decode!(c_wrong_initiator.resp_body)["error"] == "recovery_initiator_mismatch"

    # Initiating parent completes -> real DB key rotation + real resolvable ledger refs!
    c_comp_no_env =
      call_router(:post, "/v1/personal/recovery/requests/#{req_no_env}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_comp_no_env.status == 200
    body_no_env = JSON.decode!(c_comp_no_env.resp_body)
    assert body_no_env["authorityRotated"] == true
    assert body_no_env["envelopeReleased"] == false
    assert body_no_env["envelopeStatus"] == "absent_not_enrolled"
    assert body_no_env["recoveryEnvelope"] == nil
    assert_record_resolvable!(body_no_env["rootsChangedRef"])
    assert_record_resolvable!(body_no_env["recoveryCompletedRef"])

    # Verify DB member keys were genuinely rotated!
    {:ok, rotated_member} = Store.get_member(hh_id, owner_member_id)
    assert rotated_member.root_key_id == new_root_1.key_id
    assert rotated_member.working_key_id == new_work_1.key_id

    # 4. Upload parent-locked envelope -> GET returns metadata/status ONLY (NO ciphertext!)
    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 0)

    assert call_router(:put, "/v1/personal/recovery-envelope", valid_envelope_payload(),
             role: "owner",
             sub: "assisted-parent",
             hh_id: hh_id
           ).status == 200

    c_get_meta =
      call_router(:get, "/v1/personal/recovery-envelope", nil,
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_get_meta.status == 200
    meta = JSON.decode!(c_get_meta.resp_body)
    assert meta["enrolled"] == true
    assert meta["envelopeStatus"] == "enrolled"
    assert is_binary(meta["recoveryX25519KeyId"])
    refute Map.has_key?(meta, "envelopeCiphertextBase64")
    refute Map.has_key?(meta, "envelopeNonceBase64")
    refute Map.has_key?(meta, "kdfParams")

    # 5. Cancel pending request -> 200 + real resolvable ref; subsequent complete -> 409
    c_req_cancel =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => key_pub_map(Key.generate("ed25519")),
          "newWorkingPublicKey" => key_pub_map(Key.generate("es256"))
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_cancel} = JSON.decode!(c_req_cancel.resp_body)

    c_cancel =
      call_router(:post, "/v1/personal/recovery/requests/#{req_cancel}/cancel", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_cancel.status == 200
    cancel_body = JSON.decode!(c_cancel.resp_body)
    assert cancel_body["envelopeReleased"] == false
    assert_record_resolvable!(cancel_body["recoveryCompletedRef"])

    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 86_401)

    assert call_router(:post, "/v1/personal/recovery/requests/#{req_cancel}/complete", %{},
             role: "owner",
             sub: "assisted-parent",
             hh_id: hh_id
           ).status == 409

    # 6. Envelope-only completion (rotateAuthority: false) AFTER cooling-off releases raw envelope!
    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 0)

    c_req_env_only =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => key_pub_map(Key.generate("ed25519")),
          "newWorkingPublicKey" => key_pub_map(Key.generate("es256")),
          "rotateAuthority" => false
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_env_only} = JSON.decode!(c_req_env_only.resp_body)
    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 86_401)

    c_comp_env_only =
      call_router(:post, "/v1/personal/recovery/requests/#{req_env_only}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_comp_env_only.status == 200
    body_env_only = JSON.decode!(c_comp_env_only.resp_body)
    assert body_env_only["authorityRotated"] == false
    assert body_env_only["rootsChangedRef"] == nil
    assert body_env_only["envelopeReleased"] == true
    assert body_env_only["envelopeStatus"] == "released"
    assert is_binary(body_env_only["recoveryEnvelope"]["envelopeCiphertextBase64"])
    assert_record_resolvable!(body_env_only["recoveryCompletedRef"])

    # 7. Delete envelope DURING cooling-off window -> NEVER signs envelopeReleased: true!
    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 0)
    new_root_2 = Key.generate("ed25519")
    new_work_2 = Key.generate("es256")

    c_req_del =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => key_pub_map(new_root_2),
          "newWorkingPublicKey" => key_pub_map(new_work_2),
          "rotateAuthority" => true
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_del} = JSON.decode!(c_req_del.resp_body)

    c_req_del_none =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => key_pub_map(Key.generate("ed25519")),
          "newWorkingPublicKey" => key_pub_map(Key.generate("es256")),
          "rotateAuthority" => false
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_del_none} = JSON.decode!(c_req_del_none.resp_body)

    c_del =
      call_router(:delete, "/v1/personal/recovery-envelope", nil,
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_del.status == 200
    assert JSON.decode!(c_del.resp_body)["envelopeStatus"] == "absent_deleted"

    Application.put_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 86_401)

    c_comp_del =
      call_router(:post, "/v1/personal/recovery/requests/#{req_del}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_comp_del.status == 200
    body_del = JSON.decode!(c_comp_del.resp_body)
    assert body_del["authorityRotated"] == true
    assert body_del["envelopeReleased"] == false
    assert body_del["envelopeStatus"] == "absent_deleted"
    assert body_del["recoveryEnvelope"] == nil
    assert_record_resolvable!(body_del["rootsChangedRef"])
    assert_record_resolvable!(body_del["recoveryCompletedRef"])

    # Envelope-only request after deletion -> 409 nothing_to_recover with real ref
    c_comp_none =
      call_router(:post, "/v1/personal/recovery/requests/#{req_del_none}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_comp_none.status == 409
    body_none = JSON.decode!(c_comp_none.resp_body)
    assert body_none["error"] == "nothing_to_recover"
    assert body_none["authorityRotated"] == false
    assert body_none["rootsChangedRef"] == nil
    assert body_none["envelopeReleased"] == false
    assert body_none["envelopeStatus"] == "absent_deleted"
    assert body_none["recoveryEnvelope"] == nil
    assert_record_resolvable!(body_none["recoveryCompletedRef"])
  end

  test "personal ledger-backed endpoints fail closed with 503 when evidence runtime is stopped" do
    c_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{"custodyMode" => "client-e2ee", "recoveryMode" => "r5e_assisted"},
        role: "owner",
        sub: "offline-parent"
      )

    %{"householdId" => hh_id} = JSON.decode!(c_hh.resp_body)

    # Stop the provenance runtime to prove zero fake refs are ever fabricated
    stop_supervised!(Runtime)
    :persistent_term.erase({Runtime, :info})

    c_erase =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "household",
          "targetId" => hh_id,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "offline-parent",
        hh_id: hh_id
      )

    assert c_erase.status == 503
    assert JSON.decode!(c_erase.resp_body)["error"] == "evidence_runtime_unavailable"

    c_dis =
      call_router(:post, "/v1/personal/recovery/disable-assisted", %{},
        role: "owner",
        sub: "offline-parent",
        hh_id: hh_id
      )

    assert c_dis.status == 503
    assert JSON.decode!(c_dis.resp_body)["error"] == "evidence_runtime_unavailable"
  end

  test "GET /v1/personal/digests strictly isolates SafetyIntervention records per household", %{
    deployment: deployment
  } do
    child_a = "mem_aaaaaaaaaaaa"
    child_b = "mem_bbbbbbbbbbbb"

    c_a =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "members" => [
            %{"memberId" => child_a, "role" => "child", "ageBand" => "8-12"}
          ]
        },
        role: "owner",
        sub: "digest-parent-a"
      )

    %{"householdId" => hh_a} = JSON.decode!(c_a.resp_body)

    c_b =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "members" => [
            %{"memberId" => child_b, "role" => "child", "ageBand" => "8-12"}
          ]
        },
        role: "owner",
        sub: "digest-parent-b"
      )

    %{"householdId" => hh_b} = JSON.decode!(c_b.resp_body)

    signer = Key.generate("ed25519")
    stream = "urn:r5e:stream:#{deployment}:personal"
    sess_a = "urn:r5e:session:#{hh_a}:child_a.s1"
    sess_b = "urn:r5e:session:#{hh_b}:child_b.s1"

    append_intervention = fn seq, prev, actor, session, category ->
      ev =
        Evidence.new(
          kind_path: "personal.r5e.io/v1/SafetyIntervention",
          schema_ref: Ref.bytes("schema:SafetyIntervention"),
          profile_ref: Ref.bytes("profile:test"),
          issuer: signer.key_id,
          actor: actor,
          session: session,
          stream: stream,
          seq: seq,
          previous: prev,
          captured_at: DateTime.utc_now(),
          body: %{"category" => category}
        )

      {:ok, signed} = Envelope.sign(ev, signer)

      :ok =
        PostgresEvidenceStore.append(Repo, %{
          ref: signed.ref,
          stream: stream,
          seq: seq,
          kind_path: "personal.r5e.io/v1/SafetyIntervention",
          envelope: signed.envelope,
          evidence: ev
        })

      signed.ref
    end

    ref1 = append_intervention.(1, nil, "urn:r5e:member:#{hh_a}:#{child_a}", sess_a, "age-gate")

    _ref2 =
      append_intervention.(2, ref1, "urn:r5e:member:#{hh_b}:#{child_b}", sess_b, "quiet-hours")

    c_dig_a =
      call_router(:get, "/v1/personal/digests", nil,
        role: "owner",
        sub: "digest-parent-a",
        hh_id: hh_a
      )

    assert c_dig_a.status == 200
    items_a = JSON.decode!(c_dig_a.resp_body)["items"]
    assert Enum.map(items_a, & &1["sessionScope"]) == [sess_a]

    c_dig_b =
      call_router(:get, "/v1/personal/digests", nil,
        role: "owner",
        sub: "digest-parent-b",
        hh_id: hh_b
      )

    assert c_dig_b.status == 200
    items_b = JSON.decode!(c_dig_b.resp_body)["items"]
    assert Enum.map(items_b, & &1["sessionScope"]) == [sess_b]

    c_cross_member =
      call_router(:get, "/v1/personal/digests?member_id=#{child_a}", nil,
        role: "owner",
        sub: "digest-parent-b",
        hh_id: hh_b
      )

    assert c_cross_member.status == 200
    assert JSON.decode!(c_cross_member.resp_body)["items"] == []
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp assert_record_resolvable!(ref) do
    assert is_binary(ref) and Ref.valid?(ref, :evidence),
           "expected valid evidence ref, got: #{inspect(ref)}"

    c =
      call_router(:get, "/v1/evidence/records/#{URI.encode_www_form(ref)}", nil,
        role: "platform_operator",
        sub: "auditor"
      )

    assert c.status == 200,
           "expected GET /v1/evidence/records/#{ref} to return 200, got #{c.status}: #{c.resp_body}"

    body = JSON.decode!(c.resp_body)
    assert body["ref"] == ref
    body
  end

  defp key_pub_map(key) do
    %{
      "algorithm" => key.algorithm,
      "bytes" => Base.encode64(key.public_key)
    }
  end

  defp wrap_payload(rk_id) do
    %{
      "recipientKeyId" => rk_id,
      "wrapAlg" => "x25519-hkdf-sha256-aes256gcm-v1",
      "ephemeralPubKey" => Base.encode64(:crypto.strong_rand_bytes(32)),
      "nonce" => Base.encode64(:crypto.strong_rand_bytes(12)),
      "wrappedDek" => Base.encode64(:crypto.strong_rand_bytes(48))
    }
  end

  defp valid_envelope_payload do
    pub = :crypto.strong_rand_bytes(32)
    key_id = "x25519:sha256:" <> Base.encode16(:crypto.hash(:sha256, pub), case: :lower)

    %{
      "recoveryX25519KeyId" => key_id,
      "recoveryX25519PublicKeyBase64" => Base.encode64(pub),
      "envelopeAlg" => "aes-256-gcm-v1",
      "kdfKind" => "webauthn_prf_v1",
      "kdfParams" => %{"prfSaltBase64" => Base.encode64(:crypto.strong_rand_bytes(32))},
      "envelopeNonceBase64" => Base.encode64(:crypto.strong_rand_bytes(12)),
      "envelopeCiphertextBase64" => Base.encode64(:crypto.strong_rand_bytes(64))
    }
  end

  defp call_router(method, path, body, opts) do
    raw_body = if is_map(body), do: JSON.encode!(body), else: ""

    c =
      conn(method, path, raw_body)
      |> then(fn c ->
        if is_map(body),
          do: Plug.Conn.put_req_header(c, "content-type", "application/json"),
          else: c
      end)
      |> then(fn c ->
        if Keyword.get(opts, :auth?, true) do
          token =
            JwtTestHelper.mint_test_jwt(
              subject: Keyword.fetch!(opts, :sub),
              recurse_role: Keyword.fetch!(opts, :role),
              audience: "recurse-gateway-test",
              issuer: "https://test-broker.example.invalid"
            )

          Plug.Conn.put_req_header(c, "authorization", "Bearer " <> token)
        else
          c
        end
      end)
      |> then(fn c ->
        case Keyword.get(opts, :hh_id) do
          id when is_binary(id) -> Plug.Conn.put_req_header(c, "x-r5e-household-id", id)
          _ -> c
        end
      end)
      |> then(fn c ->
        Enum.reduce(Keyword.get(opts, :headers, []), c, fn {k, v}, acc ->
          Plug.Conn.put_req_header(acc, k, v)
        end)
      end)

    Router.call(c, @router_opts)
  end

  defp put_env(key, val) do
    prev = Application.get_env(:recurse_gateway, key)
    Application.put_env(:recurse_gateway, key, val)
    {key, prev}
  end
end
