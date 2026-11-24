defmodule Recurse.Gateway.Personal.RecoveryHandler do
  @moduledoc """
  HTTP handlers for D19 parent-locked recovery envelopes
  (`PUT`/`GET`/`DELETE /v1/personal/recovery-envelope`) and cooling-off
  assisted recovery requests (`/v1/personal/recovery/requests*`,
  `/v1/personal/recovery/disable-assisted`).

  Guarantees:
    * Server stores ONLY client-encrypted recovery envelopes locked by the
      parent's own sign-in / WebAuthn-PRF factor before reaching r5e.
    * Completion evaluates signing-authority rotation (`authorityRotated` +
      optional `rootsChangedRef`) and recovery-envelope release
      (`envelopeReleased` + `envelopeStatus: "released" | "absent_not_enrolled" | "absent_deleted"`)
      **independently** at completion time — NEVER returning
      `envelopeReleased: true` if the envelope was deleted before or during the
      cooling-off window, omitting `rootsChangedRef` when signing authority did
      not rotate, and returning `409 nothing_to_recover` when neither occurred.
  """

  alias Recurse.Gateway.Personal.Common
  alias Recurse.Provenance.Ref
  alias Recurse.Providers.Personal, as: Store

  @recover ~s(Recurse::Action::"RecoverHousehold")
  @default_cooling_off_seconds 86_400

  @doc "`PUT /v1/personal/recovery-envelope`"
  @spec put_envelope(Plug.Conn.t()) :: Plug.Conn.t()
  def put_envelope(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate(conn, @recover, "/v1/personal/recovery-envelope", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
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
        {:error, :not_found} ->
          Common.not_found(conn)

        {:error, :recovery_mode_self_only} ->
          Common.json(conn, 409, %{"error" => "recovery_mode_self_only"})

        {:error, reason} ->
          Common.bad_request(conn, "invalid recovery envelope: #{inspect(reason)}")
      end
    end)
  end

  def put_envelope(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc "`GET /v1/personal/recovery-envelope`"
  @spec get_envelope(Plug.Conn.t()) :: Plug.Conn.t()
  def get_envelope(conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery-envelope", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
           :ok <- require_assisted_mode(household),
           {:present, env} <- Store.envelope_state(household.household_id, member.member_id) do
        Common.json(conn, 200, render_envelope(env))
      else
        {:error, :not_found} ->
          Common.not_found(conn)

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
      case Common.resolve_household_member(conn, ctx) do
        {:ok, household, member} ->
          {:ok, res} = Store.delete_recovery_envelope(household.household_id, member.member_id)

          Common.json(conn, 200, %{
            "envelopeDeleted" => res.deleted,
            "envelopeStatus" => res.envelope_status
          })

        {:error, :not_found} ->
          Common.not_found(conn)
      end
    end)
  end

  @doc "`POST /v1/personal/recovery/requests`"
  @spec create_request(Plug.Conn.t()) :: Plug.Conn.t()
  def create_request(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate(conn, @recover, "/v1/personal/recovery/requests", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
           :ok <- require_assisted_mode(household),
           true <-
             (is_map(body["newRootPublicKey"]) and is_map(body["newWorkingPublicKey"])) ||
               {:error, :missing_keys},
           {:ok, new_x25519} <- decode_optional_x25519(body["newX25519PublicKey"]),
           cooling_off = resolve_cooling_off_seconds(body),
           unlock_at = DateTime.add(DateTime.utc_now(), cooling_off, :second),
           request_id = Common.random_id("rec_", 12),
           rotate_authority = Map.get(body, "rotateAuthority", true) != false,
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
        {:error, :not_found} ->
          Common.not_found(conn)

        {:error, :recovery_mode_self_only} ->
          Common.json(conn, 404, %{"error" => "recovery_not_enabled"})

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
      with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
           {:ok, req} <- Store.get_recovery_request(household.household_id, request_id),
           rec_ref = Ref.evidence(:crypto.strong_rand_bytes(32)),
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
        {:error, :not_found} -> Common.not_found(conn)
        :not_found -> Common.not_found(conn)
        {:error, :not_pending} -> Common.json(conn, 409, %{"error" => "request_not_pending"})
      end
    end)
  end

  @doc "`POST /v1/personal/recovery/requests/:request_id/complete`"
  @spec complete_request(Plug.Conn.t()) :: Plug.Conn.t()
  def complete_request(%Plug.Conn{path_params: %{"request_id" => request_id}} = conn) do
    Common.gate(conn, @recover, "/v1/personal/recovery/requests/complete", fn conn, ctx ->
      now = DateTime.utc_now()

      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           {:ok, req} <- Store.get_recovery_request(household.household_id, request_id),
           :ok <- check_completable(req, now) do
        finalize_honest_completion(conn, household, req)
      else
        {:error, :not_found} ->
          Common.not_found(conn)

        :not_found ->
          Common.not_found(conn)

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
      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           {:ok, res} <- Store.disable_assisted_recovery(household.household_id) do
        rec_ref = Ref.evidence(:crypto.strong_rand_bytes(32))

        Common.json(conn, 200, %{
          "recoveryMode" => "self_only",
          "envelopeDeleted" => res.envelopes_deleted > 0,
          "envelopeStatus" => disabled_envelope_status(res.envelopes_deleted),
          "recoveryWrapsDeleted" => res.wraps_deleted,
          "recoveryCompletedRef" => rec_ref
        })
      else
        {:error, :not_found} -> Common.not_found(conn)
      end
    end)
  end

  defp cancelled_envelope_status(household_id, member_id) do
    case Store.envelope_state(household_id, member_id) do
      :absent_deleted -> "absent_deleted"
      _ -> "absent_not_enrolled"
    end
  end

  defp disabled_envelope_status(count) when count > 0, do: "absent_deleted"
  defp disabled_envelope_status(_count), do: "absent_not_enrolled"

  # ---------------------------------------------------------------------------
  # Honest independent completion evaluation
  # ---------------------------------------------------------------------------

  defp finalize_honest_completion(conn, household, req) do
    {envelope_released?, envelope_status, envelope_payload} =
      case Store.envelope_state(household.household_id, req.member_id) do
        {:present, env} -> {true, "released", render_envelope(env)}
        :absent_deleted -> {false, "absent_deleted", nil}
        :absent_not_enrolled -> {false, "absent_not_enrolled", nil}
      end

    authority_rotated? = req.rotate_authority == true

    roots_changed_ref =
      if authority_rotated?, do: Ref.evidence(:crypto.strong_rand_bytes(32)), else: nil

    rec_ref = Ref.evidence(:crypto.strong_rand_bytes(32))

    if not authority_rotated? and not envelope_released? do
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
    else
      {:ok, _} =
        Store.mark_recovery_completed(
          household.household_id,
          req.request_id,
          roots_changed_ref,
          rec_ref
        )

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
    end
  end

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

  defp resolve_cooling_off_seconds(body) do
    default_s =
      Application.get_env(
        :recurse_gateway,
        :personal_recovery_cooling_off_seconds,
        @default_cooling_off_seconds
      )

    case body["coolingOffSeconds"] do
      n when is_integer(n) and n >= 0 and n <= @default_cooling_off_seconds -> n
      _ -> default_s
    end
  end
end
