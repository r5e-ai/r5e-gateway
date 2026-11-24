defmodule Recurse.Gateway.Personal.RecoveryHandler do
  @moduledoc """
  HTTP handlers for D19 parent-locked recovery envelopes
  (`PUT`/`GET`/`DELETE /v1/personal/recovery-envelope`) and cooling-off
  assisted recovery requests (`/v1/personal/recovery/requests*`,
  `/v1/personal/recovery/disable-assisted`).

  Security invariants:
    * All recovery routes require an authenticated `owner` or `parent` member.
    * `GET /v1/personal/recovery-envelope` returns enrollment metadata/status
      ONLY — never releasing the raw encrypted envelope before a recovery
      request completes after the cooling-off window.
    * `POST /v1/personal/recovery/requests/:request_id/complete` is strictly
      bound to the initiating parent's `member_id` / `authSubject`.
    * `POST /v1/personal/recovery/disable-assisted` requires a distinct
      two-parent co-sign (`coSignRef`) on `threshold >= 2` households.
    * Every returned `rootsChangedRef` and `recoveryCompletedRef` is a real
      admitted record in `evidence_records` (`503` if runtime is unavailable),
      and `authorityRotated: true` is returned ONLY after real member key
      rotation succeeds in the database and is recorded on the ledger.
  """

  alias Recurse.Gateway.Personal.{Common, Ledger}
  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Provenance.Key
  alias Recurse.Providers.Personal, as: Store

  @recover ~s(Recurse::Action::"RecoverHousehold")
  @default_cooling_off_seconds 86_400
  @max_cooling_off_seconds 604_800
  @common_errors [
    :not_found,
    :ambiguous_household,
    :parent_role_required,
    :evidence_runtime_unavailable
  ]

  @doc "`PUT /v1/personal/recovery-envelope`"
  @spec put_envelope(Plug.Conn.t()) :: Plug.Conn.t()
  def put_envelope(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate(conn, @recover, "/v1/personal/recovery-envelope", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_assisted_mode(household),
           {:ok, attrs} <- parse_envelope_attrs(body),
           {:ok, stored} <-
             Store.put_recovery_envelope(household.household_id, member.member_id, attrs) do
        Common.json(conn, 200, %{
          "recoveryX25519KeyId" => stored.recovery_x25519_key_id,
          "stored" => true,
          "updatedAt" => DateTime.to_iso8601(stored.updated_at)
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :recovery_mode_self_only} ->
          Common.json(conn, 409, %{"error" => "recovery_mode_self_only"})

        {:error, reason} ->
          Common.bad_request(conn, "invalid recovery envelope: #{inspect(reason)}")
      end
    end)
  end

  def put_envelope(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc """
  `GET /v1/personal/recovery-envelope`

  Returns enrollment metadata/status ONLY (never raw ciphertext/nonce/kdfParams)
  so callers cannot bypass the cooling-off window.
  """
  @spec get_envelope(Plug.Conn.t()) :: Plug.Conn.t()
  def get_envelope(conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery-envelope", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_assisted_mode(household),
           {:present, env} <- Store.envelope_state(household.household_id, member.member_id) do
        Common.json(conn, 200, render_envelope_metadata(env))
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :recovery_mode_self_only} ->
          Common.json(conn, 404, %{"error" => "recovery_envelope_not_found"})

        :absent_deleted ->
          Common.json(conn, 404, %{
            "error" => "recovery_envelope_not_found",
            "envelopeStatus" => "absent_deleted"
          })

        :absent_not_enrolled ->
          Common.json(conn, 404, %{
            "error" => "recovery_envelope_not_found",
            "envelopeStatus" => "absent_not_enrolled"
          })
      end
    end)
  end

  @doc "`DELETE /v1/personal/recovery-envelope`"
  @spec delete_envelope(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_envelope(conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery-envelope", fn conn, ctx ->
      case Common.resolve_parent_member(conn, ctx) do
        {:ok, household, member} ->
          {:ok, res} = Store.delete_recovery_envelope(household.household_id, member.member_id)

          Common.json(conn, 200, %{
            "envelopeDeleted" => res.deleted,
            "envelopeStatus" => res.envelope_status
          })

        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)
      end
    end)
  end

  @doc "`POST /v1/personal/recovery/requests`"
  @spec create_request(Plug.Conn.t()) :: Plug.Conn.t()
  def create_request(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate(conn, @recover, "/v1/personal/recovery/requests", fn conn, ctx ->
      rotate_authority = Map.get(body, "rotateAuthority", true) != false

      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_assisted_mode(household),
           :ok <- validate_recovery_keys(body, rotate_authority),
           {:ok, new_x25519} <- decode_optional_x25519(body["newX25519PublicKey"]),
           cooling_off = resolve_cooling_off_seconds(body),
           unlock_at = DateTime.add(now_utc(), cooling_off, :second),
           request_id = Common.random_id("rec_", 12),
           {:ok, req} <-
             Store.create_recovery_request(%{
               request_id: request_id,
               household_id: household.household_id,
               member_id: member.member_id,
               new_root_public_key: body["newRootPublicKey"],
               new_working_public_key: body["newWorkingPublicKey"],
               new_x25519_public_key: new_x25519,
               rotate_authority: rotate_authority,
               unlock_at: unlock_at
             }) do
        Common.json(conn, 202, %{
          "requestId" => req.request_id,
          "state" => req.state,
          "unlockAt" => DateTime.to_iso8601(req.unlock_at)
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :recovery_mode_self_only} ->
          Common.json(conn, 404, %{"error" => "recovery_not_enabled"})

        {:error, :invalid_public_key} ->
          Common.json(conn, 422, %{"error" => "invalid_public_key"})

        {:error, reason} ->
          Common.bad_request(conn, "invalid recovery request: #{inspect(reason)}")
      end
    end)
  end

  def create_request(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc "`POST /v1/personal/recovery/requests/:request_id/cancel`"
  @spec cancel_request(Plug.Conn.t()) :: Plug.Conn.t()
  def cancel_request(%Plug.Conn{path_params: %{"request_id" => request_id}} = conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery/requests/cancel", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_runtime_running(),
           {:ok, req} <- Store.get_recovery_request(household.household_id, request_id),
           true <- req.state == "pending_window" || {:error, :not_pending},
           {:ok, rec_ref} <-
             Ledger.record_observation(
               "personal.recovery.cancelled",
               Common.actor_urn(ctx, member),
               %{
                 "householdId" => household.household_id,
                 "requestId" => req.request_id,
                 "cancelledByMemberId" => member.member_id
               }
             ),
           {:ok, _cancelled} <-
             Store.cancel_recovery_request(
               household.household_id,
               req.request_id,
               member.member_id,
               rec_ref
             ) do
        Common.json(conn, 200, %{
          "requestId" => req.request_id,
          "state" => "cancelled",
          "authorityRotated" => false,
          "rootsChangedRef" => nil,
          "envelopeReleased" => false,
          "envelopeStatus" => cancelled_envelope_status(household.household_id, req.member_id),
          "recoveryCompletedRef" => rec_ref
        })
      else
        {:error, reason} when reason in @common_errors -> Common.send_common_error(conn, reason)
        :not_found -> Common.not_found(conn)
        {:error, :not_pending} -> Common.json(conn, 409, %{"error" => "request_not_pending"})
        {:error, reason} -> Common.json(conn, 503, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  @doc "`POST /v1/personal/recovery/requests/:request_id/complete`"
  @spec complete_request(Plug.Conn.t()) :: Plug.Conn.t()
  def complete_request(%Plug.Conn{path_params: %{"request_id" => request_id}} = conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery/requests/complete", fn conn, ctx ->
      now = now_utc()

      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_runtime_running(),
           {:ok, req} <- Store.get_recovery_request(household.household_id, request_id),
           :ok <- verify_recovery_initiator(req, member),
           :ok <- check_completable(req, now) do
        finalize_honest_completion(conn, household, member, req, ctx)
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        :not_found ->
          Common.not_found(conn)

        {:error, :recovery_initiator_mismatch} ->
          Common.json(conn, 403, %{"error" => "recovery_initiator_mismatch"})

        {:error, :request_cancelled} ->
          Common.json(conn, 409, %{"error" => "request_cancelled"})

        {:error, :request_already_completed} ->
          Common.json(conn, 409, %{"error" => "request_already_completed"})

        {:error, :waiting_window_active, unlock_at} ->
          Common.json(conn, 409, %{
            "error" => "waiting_window_active",
            "unlockAt" => DateTime.to_iso8601(unlock_at)
          })
      end
    end)
  end

  @doc "`POST /v1/personal/recovery/disable-assisted`"
  @spec disable_assisted(Plug.Conn.t()) :: Plug.Conn.t()
  def disable_assisted(conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery/disable-assisted", fn conn, ctx ->
      body = if is_map(conn.body_params), do: conn.body_params, else: %{}
      co_sign_ref = body["coSignRef"]

      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_runtime_running(),
           :ok <- check_disable_assisted_cosign(household, co_sign_ref),
           {:ok, rec_ref} <-
             Ledger.record_observation(
               "personal.recovery.assisted_disabled",
               Common.actor_urn(ctx, member),
               %{
                 "householdId" => household.household_id,
                 "memberId" => member.member_id
               }
             ),
           {:ok, res} <- Store.disable_assisted_recovery(household.household_id),
           :ok <- consume_disable_cosign(household, co_sign_ref, rec_ref) do
        Common.json(conn, 200, %{
          "recoveryMode" => "self_only",
          "envelopeDeleted" => res.envelopes_deleted > 0,
          "envelopeStatus" => disabled_envelope_status(res.envelopes_deleted),
          "recoveryWrapsDeleted" => res.wraps_deleted,
          "recoveryCompletedRef" => rec_ref
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :co_sign_required} ->
          Common.json(conn, 409, %{"error" => "co_sign_required"})

        {:error, reason} ->
          Common.json(conn, 503, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Honest independent completion evaluation
  # ---------------------------------------------------------------------------

  defp finalize_honest_completion(conn, household, member, req, ctx) do
    {envelope_released?, envelope_status, envelope_payload} =
      case Store.envelope_state(household.household_id, req.member_id) do
        {:present, env} -> {true, "released", render_envelope(env)}
        :absent_deleted -> {false, "absent_deleted", nil}
        :absent_not_enrolled -> {false, "absent_not_enrolled", nil}
      end

    actor = Common.actor_urn(ctx, member)

    if req.rotate_authority != true and not envelope_released? do
      complete_nothing_to_recover(conn, household, req, envelope_status, actor)
    else
      complete_real_recovery(
        conn,
        household,
        member,
        req,
        {envelope_released?, envelope_status, envelope_payload},
        actor
      )
    end
  end

  defp complete_nothing_to_recover(conn, household, req, envelope_status, actor) do
    case Ledger.record_observation("personal.recovery.completed", actor, %{
           "householdId" => household.household_id,
           "requestId" => req.request_id,
           "outcome" => "no-action-envelope-absent",
           "authorityRotated" => false,
           "envelopeReleased" => false,
           "envelopeStatus" => envelope_status
         }) do
      {:ok, rec_ref} ->
        _ = Store.mark_recovery_completed(household.household_id, req.request_id, nil, rec_ref)

        Common.json(conn, 409, %{
          "error" => "nothing_to_recover",
          "outcome" => "no-action-envelope-absent",
          "authorityRotated" => false,
          "rootsChangedRef" => nil,
          "envelopeReleased" => false,
          "envelopeStatus" => envelope_status,
          "recoveryEnvelope" => nil,
          "recoveryCompletedRef" => rec_ref
        })

      {:error, reason} ->
        Common.json(conn, 503, %{"error" => Atom.to_string(reason)})
    end
  end

  defp complete_real_recovery(
         conn,
         household,
         member,
         req,
         {envelope_released?, envelope_status, envelope_payload},
         actor
       ) do
    with {:ok, authority_rotated?, roots_changed_ref} <-
           perform_authority_rotation(household, member, req, actor),
         {:ok, rec_ref} <-
           Ledger.record_observation("personal.recovery.completed", actor, %{
             "householdId" => household.household_id,
             "requestId" => req.request_id,
             "outcome" => "completed",
             "authorityRotated" => authority_rotated?,
             "rootsChangedRef" => roots_changed_ref,
             "envelopeReleased" => envelope_released?,
             "envelopeStatus" => envelope_status
           }),
         {:ok, _} <-
           Store.mark_recovery_completed(
             household.household_id,
             req.request_id,
             roots_changed_ref,
             rec_ref
           ) do
      Common.json(conn, 200, %{
        "state" => "completed",
        "outcome" => "completed",
        "authorityRotated" => authority_rotated?,
        "rootsChangedRef" => roots_changed_ref,
        "envelopeReleased" => envelope_released?,
        "envelopeStatus" => envelope_status,
        "recoveryEnvelope" => envelope_payload,
        "recoveryCompletedRef" => rec_ref
      })
    else
      {:error, :invalid_public_key} ->
        Common.json(conn, 422, %{"error" => "invalid_public_key"})

      {:error, reason} when reason in @common_errors ->
        Common.send_common_error(conn, reason)

      {:error, reason} ->
        Common.json(conn, 503, %{"error" => Atom.to_string(reason)})
    end
  end

  defp perform_authority_rotation(_household, _member, %{rotate_authority: false}, _actor),
    do: {:ok, false, nil}

  defp perform_authority_rotation(household, member, req, actor) do
    with {:ok, new_root_id} <- extract_public_key_id(req.new_root_public_key),
         {:ok, new_working_id} <- extract_public_key_id(req.new_working_public_key),
         {:ok, _rotated} <-
           Store.rotate_member_keys(
             household.household_id,
             member.member_id,
             new_root_id,
             new_working_id
           ),
         {:ok, roots_ref} <-
           Ledger.record_observation("personal.recovery.authority_rotated", actor, %{
             "householdId" => household.household_id,
             "memberId" => member.member_id,
             "requestId" => req.request_id,
             "previousRootKeyId" => member.root_key_id,
             "newRootKeyId" => new_root_id,
             "newWorkingKeyId" => new_working_id
           }) do
      {:ok, true, roots_ref}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp require_runtime_running do
    if Runtime.running?(), do: :ok, else: {:error, :evidence_runtime_unavailable}
  end

  defp verify_recovery_initiator(%{member_id: req_member_id}, %{member_id: caller_member_id})
       when req_member_id == caller_member_id,
       do: :ok

  defp verify_recovery_initiator(_, _), do: {:error, :recovery_initiator_mismatch}

  defp check_disable_assisted_cosign(%{threshold: threshold, household_id: hh_id}, co_sign_ref)
       when threshold >= 2 do
    if Store.approved_cosign?(hh_id, "household", hh_id, co_sign_ref) do
      :ok
    else
      {:error, :co_sign_required}
    end
  end

  defp check_disable_assisted_cosign(_household, _co_sign_ref), do: :ok

  defp consume_disable_cosign(%{threshold: threshold, household_id: hh_id}, co_sign_ref, rec_ref)
       when threshold >= 2 and is_binary(co_sign_ref) do
    case Store.mark_proposal_executed(hh_id, co_sign_ref, rec_ref) do
      {:ok, :executed} -> :ok
      {:error, :proposal_not_approved} -> {:error, :co_sign_required}
    end
  end

  defp consume_disable_cosign(_household, _co_sign_ref, _rec_ref), do: :ok

  defp validate_recovery_keys(
         %{"newRootPublicKey" => root_key, "newWorkingPublicKey" => working_key},
         true
       )
       when is_map(root_key) and is_map(working_key) do
    with {:ok, _} <- extract_public_key_id(root_key),
         {:ok, _} <- extract_public_key_id(working_key) do
      :ok
    end
  end

  defp validate_recovery_keys(
         %{"newRootPublicKey" => root_key, "newWorkingPublicKey" => working_key},
         false
       )
       when is_map(root_key) and is_map(working_key),
       do: :ok

  defp validate_recovery_keys(_, _), do: {:error, :missing_keys}

  defp extract_public_key_id(%{"algorithm" => alg, "bytes" => b64})
       when alg in ["ed25519", "es256"] and is_binary(b64) do
    with {:ok, raw} <- Base.decode64(b64),
         {:ok, key_id} <- Key.id(alg, raw) do
      {:ok, key_id}
    else
      _ -> {:error, :invalid_public_key}
    end
  end

  defp extract_public_key_id(_), do: {:error, :invalid_public_key}

  defp cancelled_envelope_status(household_id, member_id) do
    case Store.envelope_state(household_id, member_id) do
      :absent_deleted -> "absent_deleted"
      _ -> "absent_not_enrolled"
    end
  end

  defp disabled_envelope_status(count) when count > 0, do: "absent_deleted"
  defp disabled_envelope_status(_count), do: "absent_not_enrolled"

  defp check_completable(%{state: "cancelled"}, _now), do: {:error, :request_cancelled}
  defp check_completable(%{state: "completed"}, _now), do: {:error, :request_already_completed}

  defp check_completable(%{state: "pending_window", unlock_at: unlock_at}, now) do
    if DateTime.compare(now, unlock_at) in [:gt, :eq] do
      :ok
    else
      {:error, :waiting_window_active, unlock_at}
    end
  end

  defp check_completable(_, _), do: {:error, :request_cancelled}

  defp require_assisted_mode(%{recovery_mode: "r5e_assisted"}), do: :ok
  defp require_assisted_mode(_), do: {:error, :recovery_mode_self_only}

  defp parse_envelope_attrs(%{
         "recoveryX25519KeyId" => key_id,
         "recoveryX25519PublicKeyBase64" => pub_b64,
         "envelopeAlg" => "aes-256-gcm-v1" = alg,
         "kdfKind" => kdf_kind,
         "kdfParams" => kdf_params,
         "envelopeNonceBase64" => nonce_b64,
         "envelopeCiphertextBase64" => ct_b64
       })
       when is_binary(key_id) and kdf_kind in ["webauthn_prf_v1", "signin_passphrase_argon2id_v1"] and
              is_map(kdf_params) do
    with true <- Regex.match?(~r/\Ax25519:sha256:[0-9a-f]{64}\z/, key_id) || {:error, :bad_key_id},
         {:ok, pub} <- decode_len(pub_b64, 32..32),
         {:ok, nonce} <- decode_len(nonce_b64, 12..12),
         {:ok, ct} <- decode_len(ct_b64, 32..4096) do
      {:ok,
       %{
         recovery_x25519_key_id: key_id,
         recovery_x25519_pub_key: pub,
         envelope_alg: alg,
         kdf_kind: kdf_kind,
         kdf_params: kdf_params,
         envelope_nonce: nonce,
         envelope_ciphertext: ct
       }}
    end
  end

  defp parse_envelope_attrs(_), do: {:error, :missing_or_invalid_fields}

  defp render_envelope_metadata(env) do
    %{
      "enrolled" => true,
      "envelopeStatus" => "enrolled",
      "recoveryX25519KeyId" => env.recovery_x25519_key_id,
      "recoveryX25519PublicKeyBase64" => Base.encode64(env.recovery_x25519_pub_key),
      "envelopeAlg" => env.envelope_alg,
      "kdfKind" => env.kdf_kind,
      "updatedAt" => DateTime.to_iso8601(env.updated_at)
    }
  end

  defp render_envelope(env) do
    %{
      "recoveryX25519KeyId" => env.recovery_x25519_key_id,
      "recoveryX25519PublicKeyBase64" => Base.encode64(env.recovery_x25519_pub_key),
      "envelopeAlg" => env.envelope_alg,
      "kdfKind" => env.kdf_kind,
      "kdfParams" => env.kdf_params,
      "envelopeNonceBase64" => Base.encode64(env.envelope_nonce),
      "envelopeCiphertextBase64" => Base.encode64(env.envelope_ciphertext),
      "updatedAt" => DateTime.to_iso8601(env.updated_at)
    }
  end

  defp decode_len(b64, min..max//1) when is_binary(b64) do
    case Base.decode64(b64) do
      {:ok, bytes} when byte_size(bytes) >= min and byte_size(bytes) <= max -> {:ok, bytes}
      _ -> {:error, :invalid_byte_length}
    end
  end

  defp decode_len(_, _), do: {:error, :invalid_base64}

  defp decode_optional_x25519(nil), do: {:ok, nil}
  defp decode_optional_x25519(b64), do: decode_len(b64, 32..32)

  defp now_utc do
    offset_s = Application.get_env(:recurse_gateway, :personal_recovery_clock_offset_seconds, 0)

    if is_integer(offset_s) and offset_s != 0 do
      DateTime.add(DateTime.utc_now(), offset_s, :second)
    else
      DateTime.utc_now()
    end
  end

  defp resolve_cooling_off_seconds(body) do
    floor_s =
      Application.get_env(
        :recurse_gateway,
        :personal_recovery_cooling_off_seconds,
        @default_cooling_off_seconds
      )

    # Server-configured floor is non-reducible: clients may extend the waiting
    # window up to 7 days, never shorten it below the server minimum.
    case body["coolingOffSeconds"] do
      n when is_integer(n) and n > floor_s -> min(n, @max_cooling_off_seconds)
      _ -> floor_s
    end
  end
end
