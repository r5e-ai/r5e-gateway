defmodule Recurse.Gateway.Personal.PersonalEndpointsTest do
  @moduledoc """
  End-to-end tests for opt-in `personal.r5e.io/v1` routes (`R5E_PERSONAL_ENABLED=true`):
    * 404 fail-closed when `R5E_PERSONAL_ENABLED=false`
    * Household creation, settings update, parent digests, cross-household 404 isolation
    * Bilateral QR child pairing + strict 5-kind child `Badge.kinds` admission guard
    * Phase-2 `client-e2ee` mutable key-wraps & blobs + 410 tombstone erasure
    * Two-parent (`threshold: 2`) co-sign erasure enforcement (self-approval & unilateral refusal)
    * D19 parent-locked recovery envelope + honest independent recovery completion flags
      (`authorityRotated`, `envelopeReleased`, `envelopeStatus`, `409 nothing_to_recover`)
  """

  use ExUnit.Case, async: false

  import Plug.Test

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Personal.Policy
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Router
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Provenance.{Key, Ref}
  alias Recurse.Providers.Repo

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @router_opts Router.init([])

  setup do
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

    restore = [
      put_env(:personal_enabled?, true),
      put_env(:personal_recovery_cooling_off_seconds, 0),
      put_env(:jwt_validator_opts,
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid",
        known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
      )
    ]

    on_exit(fn ->
      ProviderRegistry.uninstall()

      Enum.each(restore, fn
        {k, nil} -> Application.delete_env(:recurse_gateway, k)
        {k, v} -> Application.put_env(:recurse_gateway, k, v)
      end)
    end)

    :ok
  end

  test "all /v1/personal/* routes return 404 when R5E_PERSONAL_ENABLED is false" do
    Application.put_env(:recurse_gateway, :personal_enabled?, false)

    for {method, path, body} <- [
          {:post, "/v1/personal/households", %{}},
          {:get, "/v1/personal/digests", nil},
          {:patch, "/v1/personal/settings", %{}},
          {:get, "/v1/personal/key-wraps", nil},
          {:get, "/v1/personal/recovery-envelope", nil},
          {:post, "/v1/personal/pairings/pair_123/device-claim", %{}}
        ] do
      c = call_router(method, path, body, role: "owner", sub: "parent-a")
      assert c.status == 404
    end
  end

  test "child QR pairing enforces closed 5-kind Badge.kinds allowlist and blocks privilege escalation" do
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

    pub_map = %{
      "algorithm" => "ed25519",
      "bytes" => Base.encode64(child_key.public_key)
    }

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
    c_replay =
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

    assert c_replay.status == 409

    # 3. CRITICAL: Attempting to finalize with wildcard or parent-only kinds MUST fail with 422!
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

    # 4. Finalizing with exact 5-kind allowlist succeeds!
    c_fin =
      call_router(
        :post,
        "/v1/personal/pairings/#{cid}/finalize",
        %{"badgeKinds" => Policy.child_badge_kinds()},
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_fin.status == 201
    assert JSON.decode!(c_fin.resp_body)["deviceKeyId"] == child_key.key_id

    # 5. Defense-in-depth admission guard blocks child device submitting FamilyGuardrailSet / PersonalErasure
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

    # 6. Child role is forbidden from /v1/personal/digests and /v1/personal/settings
    c_child_digest =
      call_router(:get, "/v1/personal/digests", nil, role: "child", sub: child_id, hh_id: hh_id)

    assert c_child_digest.status == 403

    # Parent can read /v1/personal/digests and update /v1/personal/settings
    c_digest =
      call_router(:get, "/v1/personal/digests", nil, role: "owner", sub: "parent-a", hh_id: hh_id)

    assert c_digest.status == 200
    assert %{"items" => []} = JSON.decode!(c_digest.resp_body)

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

  test "client-e2ee mutable key-wraps & blobs support cross-household 404 isolation and 410 tombstone erasure" do
    # Household A and Household B
    c_a =
      call_router(:post, "/v1/personal/households", %{"custodyMode" => "client-e2ee"},
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

    # Register X25519 recipient key for A
    pub_b64 = Base.encode64(:crypto.strong_rand_bytes(32))

    c_rk =
      call_router(
        :post,
        "/v1/personal/recipient-keys",
        %{
          "recipientKind" => "parent_device",
          "algorithm" => "x25519",
          "publicKeyBase64" => pub_b64
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_rk.status == 201
    %{"recipientKeyId" => rk_id} = JSON.decode!(c_rk.resp_body)

    scope = "urn:r5e:session:#{hh_a}:abcdef0123456789.chat-1"
    ciphertext = "encrypted-e2ee-chat-bytes"
    bytes_ref = Ref.bytes("plaintext-for-ref")
    nonce_b64 = Base.encode64(:crypto.strong_rand_bytes(12))

    # Store key wrap + blob
    c_w =
      call_router(
        :put,
        "/v1/personal/key-wraps",
        %{
          "scope" => scope,
          "wraps" => [
            %{
              "recipientKeyId" => rk_id,
              "wrapAlg" => "x25519-hkdf-sha256-aes256gcm-v1",
              "ephemeralPubKey" => Base.encode64(:crypto.strong_rand_bytes(32)),
              "nonce" => Base.encode64(:crypto.strong_rand_bytes(12)),
              "wrappedDek" => Base.encode64(:crypto.strong_rand_bytes(48))
            }
          ]
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_w.status == 201

    c_bput =
      call_router(
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
      )

    assert c_bput.status == 201

    # Read blob as Parent A -> 200 raw bytes
    c_bget =
      call_router(
        :get,
        "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}",
        nil,
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_bget.status == 200
    assert c_bget.resp_body == ciphertext

    # Cross-household read as Parent B -> 404 (never leaks!)
    c_cross =
      call_router(
        :get,
        "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}",
        nil,
        role: "owner",
        sub: "parent-b",
        hh_id: hh_a
      )

    assert c_cross.status == 404

    # Direct DELETE without X-R5E-Erasure-Ref -> 409 erasure_record_required
    c_del_no_ref =
      call_router(
        :delete,
        "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}",
        nil,
        role: "owner",
        sub: "parent-a",
        hh_id: hh_a
      )

    assert c_del_no_ref.status == 409
    assert JSON.decode!(c_del_no_ref.resp_body)["error"] == "erasure_record_required"

    # Execute client-e2ee erasure -> 201, deletes wraps + tombstones blob (never 409 ERR_NOTHING_TO_DISPOSE!)
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
    assert erase_body["keyWrapsDeleted"] == 1
    assert erase_body["blobsTombstoned"] == 1

    # Subsequent GET blob & GET key-wraps return 410 ERR_CONTENT_DISPOSED for A, still 404 for B!
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

    c_cross_after =
      call_router(
        :get,
        "/v1/personal/blobs/#{bytes_ref}?scope=#{URI.encode_www_form(scope)}",
        nil,
        role: "owner",
        sub: "parent-b",
        hh_id: hh_b
      )

    assert c_cross_after.status == 404

    # Re-uploading to tombstoned scope -> 410 (anti-resurrection!)
    c_resurrect =
      call_router(
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
      )

    assert c_resurrect.status == 410
  end

  test "two-parent threshold: 2 household erasure rejects unilateral & self-approval and succeeds with distinct co-parent" do
    c_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{
          "custodyMode" => "client-e2ee",
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
            }
          ]
        },
        role: "owner",
        sub: "parent-a"
      )

    assert c_hh.status == 201
    %{"householdId" => hh_id} = JSON.decode!(c_hh.resp_body)

    # 1. Unilateral household erasure -> 409 co_sign_required
    c_unilateral =
      call_router(
        :post,
        "/v1/personal/erasures",
        %{
          "scope" => "household",
          "targetId" => hh_id,
          "erasureMethod" => "client-key-and-blob-deletion"
        },
        role: "owner",
        sub: "parent-a",
        hh_id: hh_id
      )

    assert c_unilateral.status == 409
    assert JSON.decode!(c_unilateral.resp_body)["error"] == "co_sign_required"

    # 2. Parent A creates erasure proposal
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

    # 3. Parent A tries to self-approve -> 409 self_approval_forbidden
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

    # 4. Parent B (distinct member, working key, and root key) approves -> 201 coSignRef
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

    # 5. Executing household erasure with coSignRef -> 201!
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
  end

  test "D19 parent-locked recovery envelope & honest independent recovery completion flags" do
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
               "newRootPublicKey" => %{"alg" => "ed25519"},
               "newWorkingPublicKey" => %{"alg" => "es256"}
             },
             role: "owner",
             sub: "self-parent",
             hh_id: self_hh
           ).status == 404

    # 2. r5e_assisted household: never-enrolled envelope -> authority rotated ONLY, envelopeStatus: absent_not_enrolled
    c_hh =
      call_router(
        :post,
        "/v1/personal/households",
        %{"custodyMode" => "client-e2ee", "recoveryMode" => "r5e_assisted"},
        role: "owner",
        sub: "assisted-parent"
      )

    %{"householdId" => hh_id} = JSON.decode!(c_hh.resp_body)

    c_req_no_env =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => %{"alg" => "ed25519"},
          "newWorkingPublicKey" => %{"alg" => "es256"},
          "coolingOffSeconds" => 0
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_req_no_env.status == 202
    %{"requestId" => req_no_env} = JSON.decode!(c_req_no_env.resp_body)

    c_comp_no_env =
      call_router(:post, "/v1/personal/recovery/requests/#{req_no_env}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_comp_no_env.status == 200
    body_no_env = JSON.decode!(c_comp_no_env.resp_body)
    assert body_no_env["authorityRotated"] == true
    assert is_binary(body_no_env["rootsChangedRef"])
    assert body_no_env["envelopeReleased"] == false
    assert body_no_env["envelopeStatus"] == "absent_not_enrolled"
    assert body_no_env["recoveryEnvelope"] == nil

    # 3. Upload parent-locked envelope -> intact completion releases envelope!
    assert call_router(:put, "/v1/personal/recovery-envelope", valid_envelope_payload(),
             role: "owner",
             sub: "assisted-parent",
             hh_id: hh_id
           ).status == 200

    # Cooling-off window active -> 409 waiting_window_active
    c_req_wait =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => %{"alg" => "ed25519"},
          "newWorkingPublicKey" => %{"alg" => "es256"},
          "coolingOffSeconds" => 3600
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_wait} = JSON.decode!(c_req_wait.resp_body)

    assert call_router(:post, "/v1/personal/recovery/requests/#{req_wait}/complete", %{},
             role: "owner",
             sub: "assisted-parent",
             hh_id: hh_id
           ).status == 409

    # Cancel pending request -> 200, subsequent complete -> 409 request_cancelled
    c_cancel =
      call_router(:post, "/v1/personal/recovery/requests/#{req_wait}/cancel", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_cancel.status == 200
    assert JSON.decode!(c_cancel.resp_body)["envelopeReleased"] == false

    assert call_router(:post, "/v1/personal/recovery/requests/#{req_wait}/complete", %{},
             role: "owner",
             sub: "assisted-parent",
             hh_id: hh_id
           ).status == 409

    # Envelope-only completion (rotateAuthority: false) ->
    # authorityRotated: false, rootsChangedRef: nil, envelopeReleased: true!
    c_req_env_only =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => %{"alg" => "ed25519"},
          "newWorkingPublicKey" => %{"alg" => "es256"},
          "rotateAuthority" => false,
          "coolingOffSeconds" => 0
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_env_only} = JSON.decode!(c_req_env_only.resp_body)

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
    assert is_map(body_env_only["recoveryEnvelope"])

    # 4. CRITICAL: Delete envelope DURING cooling-off window -> NEVER signs envelopeReleased: true!
    c_req_del =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => %{"alg" => "ed25519"},
          "newWorkingPublicKey" => %{"alg" => "es256"},
          "rotateAuthority" => true,
          "coolingOffSeconds" => 0
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_del} = JSON.decode!(c_req_del.resp_body)

    # Also start an envelope-only request before deletion to test 409 nothing_to_recover!
    c_req_del_none =
      call_router(
        :post,
        "/v1/personal/recovery/requests",
        %{
          "newRootPublicKey" => %{"alg" => "ed25519"},
          "newWorkingPublicKey" => %{"alg" => "es256"},
          "rotateAuthority" => false,
          "coolingOffSeconds" => 0
        },
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    %{"requestId" => req_del_none} = JSON.decode!(c_req_del_none.resp_body)

    # Parent deletes recovery envelope during cooling-off window
    c_del =
      call_router(:delete, "/v1/personal/recovery-envelope", nil,
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_del.status == 200
    assert JSON.decode!(c_del.resp_body)["envelopeStatus"] == "absent_deleted"

    # Authority-rotating request completes honestly:
    # authorityRotated: true, envelopeReleased: false, envelopeStatus: absent_deleted!
    c_comp_del =
      call_router(:post, "/v1/personal/recovery/requests/#{req_del}/complete", %{},
        role: "owner",
        sub: "assisted-parent",
        hh_id: hh_id
      )

    assert c_comp_del.status == 200
    body_del = JSON.decode!(c_comp_del.resp_body)
    assert body_del["authorityRotated"] == true
    assert is_binary(body_del["rootsChangedRef"])
    assert body_del["envelopeReleased"] == false
    assert body_del["envelopeStatus"] == "absent_deleted"
    assert body_del["recoveryEnvelope"] == nil

    # Envelope-only request after envelope deletion -> 409 nothing_to_recover!
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
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

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

    Router.call(c, @router_opts)
  end

  defp put_env(key, val) do
    prev = Application.get_env(:recurse_gateway, key)
    Application.put_env(:recurse_gateway, key, val)
    {key, prev}
  end
end
