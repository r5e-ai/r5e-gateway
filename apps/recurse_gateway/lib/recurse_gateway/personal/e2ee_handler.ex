defmodule Recurse.Gateway.Personal.E2eeHandler do
  @moduledoc """
  HTTP handlers for Phase-2 `client-e2ee` mutable recipient keys, wrapped
  per-session DEKs (`/v1/personal/key-wraps`), and mutable ciphertext blobs
  with `410 ERR_CONTENT_DISPOSED` tombstones (`/v1/personal/blobs/:bytes_ref`).

  Security invariants:
    * Never touches immutable `evidence_blobs` or its append-only triggers.
    * Mutating operations require an authenticated `owner` or `parent` member
      (`child` principals receive `403 parent_role_required`).
    * `PUT /v1/personal/key-wraps` refuses overwriting another parent's
      existing wrap (`409 wrap_overwrite_forbidden`).
    * `PUT /v1/personal/blobs/:bytes_ref` verifies `Ref.bytes(ciphertext) == bytes_ref`
      before persisting (`422 digest_mismatch`).
    * `DELETE /v1/personal/key-wraps` and `DELETE /v1/personal/blobs/:bytes_ref`
      verify that `X-R5E-Erasure-Ref` is a real admitted erasure/disposition
      record in `evidence_records` belonging to this household & scope.
  """

  alias Recurse.Gateway.Personal.{Common, Ledger}
  alias Recurse.Provenance.Ref
  alias Recurse.Providers.Personal, as: Store

  @manage_e2ee ~s(Recurse::Action::"ManagePersonalE2EE")
  @read_household_payload ~s(Recurse::Action::"ReadHouseholdPayload")
  @read_own_payload ~s(Recurse::Action::"ReadOwnPayload")

  @max_blob_bytes 4_194_304
  @common_errors [
    :not_found,
    :ambiguous_household,
    :parent_role_required,
    :evidence_runtime_unavailable
  ]

  @doc "`POST /v1/personal/recipient-keys`"
  @spec register_recipient_key(Plug.Conn.t()) :: Plug.Conn.t()
  def register_recipient_key(
        %Plug.Conn{
          body_params: %{
            "recipientKind" => kind,
            "algorithm" => "x25519",
            "publicKeyBase64" => pub_b64
          }
        } = conn
      )
      when kind in ["parent_device", "parent_recovery_card", "parent_recovery_envelope"] and
             is_binary(pub_b64) do
    Common.gate(conn, @manage_e2ee, "/v1/personal/recipient-keys", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           :ok <- check_recovery_kind_allowed(household, kind),
           {:ok, pub_bytes} <- decode_exact(pub_b64, 32),
           key_id =
             "x25519:sha256:" <> Base.encode16(:crypto.hash(:sha256, pub_bytes), case: :lower),
           {:ok, _row} <-
             Store.upsert_recipient_key(household.household_id, %{
               recipient_key_id: key_id,
               member_id: member.member_id,
               recipient_kind: kind,
               public_key_bytes: pub_bytes
             }) do
        Common.json(conn, 201, %{"recipientKeyId" => key_id, "recipientKind" => kind})
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :recovery_mode_self_only} ->
          Common.json(conn, 409, %{"error" => "recovery_mode_self_only"})

        {:error, _} ->
          Common.bad_request(conn, "invalid x25519 public key (expected 32 bytes base64)")
      end
    end)
  end

  def register_recipient_key(conn),
    do:
      Common.bad_request(
        conn,
        ~s(expected {"recipientKind", "algorithm": "x25519", "publicKeyBase64"})
      )

  @doc "`PUT /v1/personal/key-wraps` (and `POST` alias)"
  @spec put_key_wraps(Plug.Conn.t()) :: Plug.Conn.t()
  def put_key_wraps(%Plug.Conn{body_params: %{"scope" => scope, "wraps" => wraps}} = conn)
      when is_binary(scope) and scope != "" and is_list(wraps) and wraps != [] do
    Common.gate(conn, @manage_e2ee, "/v1/personal/key-wraps", fn conn, ctx ->
      with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
           {:ok, decoded} <- decode_wraps(wraps),
           {:ok, count} <-
             Store.put_key_wraps(household.household_id, scope, decoded, member.member_id) do
        Common.json(conn, 201, %{"scope" => scope, "storedCount" => count})
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :recipient_not_found} ->
          Common.not_found(conn)

        {:error, :wrap_overwrite_forbidden} ->
          Common.json(conn, 409, %{"error" => "wrap_overwrite_forbidden"})

        {:gone, erasure_ref} ->
          Common.gone(conn, erasure_ref)

        {:error, _} ->
          Common.bad_request(conn, "invalid key wrap payload")
      end
    end)
  end

  def put_key_wraps(conn), do: Common.bad_request(conn, ~s(expected {"scope", "wraps": [...]}))

  @doc "`GET /v1/personal/key-wraps`"
  @spec get_key_wraps(Plug.Conn.t()) :: Plug.Conn.t()
  def get_key_wraps(conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate_any(
      conn,
      [@manage_e2ee, @read_household_payload, @read_own_payload],
      "/v1/personal/key-wraps",
      fn conn, ctx, _matched ->
        with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
             opts = key_wrap_list_opts(conn.query_params, member),
             {:ok, wraps} <- Store.list_key_wraps(household.household_id, opts) do
          Common.json(conn, 200, %{"wraps" => Enum.map(wraps, &render_wrap/1)})
        else
          {:error, reason} when reason in @common_errors -> Common.send_common_error(conn, reason)
          {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
        end
      end
    )
  end

  @doc "`DELETE /v1/personal/key-wraps?scope=...` (requires household-bound admitted `X-R5E-Erasure-Ref`)"
  @spec delete_key_wraps(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_key_wraps(conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate(conn, @manage_e2ee, "/v1/personal/key-wraps", fn conn, ctx ->
      scope = conn.query_params["scope"]
      erasure_ref = Common.header(conn, "x-r5e-erasure-ref")

      with {:ok, household, _member} <- Common.resolve_parent_member(conn, ctx),
           true <- (is_binary(scope) and scope != "") || {:error, :missing_scope},
           :ok <- Ledger.verify_household_erasure_ref(erasure_ref, household.household_id, scope),
           {:ok, deleted} <- Store.delete_key_wraps(household.household_id, scope) do
        Common.json(conn, 200, %{
          "scope" => scope,
          "erasureRef" => erasure_ref,
          "keyWrapsDeleted" => deleted
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, :missing_scope} ->
          Common.bad_request(conn, "scope query parameter required")

        {:error, :erasure_record_required} ->
          Common.json(conn, 409, %{"error" => "erasure_record_required"})
      end
    end)
  end

  @doc "`PUT /v1/personal/blobs/:bytes_ref`"
  @spec put_blob(Plug.Conn.t()) :: Plug.Conn.t()
  def put_blob(%Plug.Conn{path_params: %{"bytes_ref" => bytes_ref}} = conn) do
    Common.gate(conn, @manage_e2ee, "/v1/personal/blobs", fn conn, ctx ->
      with {:ok, household, _member} <- Common.resolve_parent_member(conn, ctx),
           {:ok, blob_attrs, conn} <- extract_blob_upload(conn, bytes_ref),
           {:ok, row} <- Store.put_blob(household.household_id, blob_attrs) do
        Common.json(conn, 201, %{
          "bytesRef" => row.bytes_ref,
          "scope" => row.scope,
          "size" => row.size
        })
      else
        {:error, reason} when reason in @common_errors -> Common.send_common_error(conn, reason)
        {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
        {:error, :payload_too_large} -> Common.json(conn, 413, %{"error" => "payload_too_large"})
        {:error, :digest_mismatch} -> Common.json(conn, 422, %{"error" => "digest_mismatch"})
        {:error, reason} -> Common.bad_request(conn, "invalid blob upload: #{inspect(reason)}")
      end
    end)
  end

  @doc "`GET /v1/personal/blobs/:bytes_ref?scope=...`"
  @spec get_blob(Plug.Conn.t()) :: Plug.Conn.t()
  def get_blob(%Plug.Conn{path_params: %{"bytes_ref" => bytes_ref}} = conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate_any(
      conn,
      [@read_household_payload, @read_own_payload, @manage_e2ee],
      "/v1/personal/blobs",
      fn conn, ctx, _matched ->
        scope = conn.query_params["scope"]

        with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
             true <- is_binary(scope) and scope != "",
             :ok <- authorize_blob_reader(member, scope),
             {:ok, blob} <- Store.get_blob(household.household_id, bytes_ref, scope) do
          conn
          |> Plug.Conn.put_resp_content_type("application/octet-stream", nil)
          |> Plug.Conn.put_resp_header("x-r5e-cipher-alg", blob.cipher_alg)
          |> Plug.Conn.put_resp_header("x-r5e-nonce", Base.encode64(blob.nonce))
          |> Plug.Conn.put_resp_header("content-disposition", "attachment")
          |> Plug.Conn.put_resp_header("x-content-type-options", "nosniff")
          |> Plug.Conn.put_resp_header("cache-control", "no-store, private")
          |> Plug.Conn.send_resp(200, blob.ciphertext)
        else
          {:error, reason} when reason in @common_errors -> Common.send_common_error(conn, reason)
          {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
          _ -> Common.not_found(conn)
        end
      end
    )
  end

  @doc "`DELETE /v1/personal/blobs/:bytes_ref?scope=...` (requires household-bound admitted `X-R5E-Erasure-Ref`)"
  @spec delete_blob(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_blob(%Plug.Conn{path_params: %{"bytes_ref" => bytes_ref}} = conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate(conn, @manage_e2ee, "/v1/personal/blobs", fn conn, ctx ->
      scope = conn.query_params["scope"]
      erasure_ref = Common.header(conn, "x-r5e-erasure-ref")

      with {:ok, household, _member} <- Common.resolve_parent_member(conn, ctx),
           true <- (is_binary(scope) and scope != "") || {:error, :missing_scope},
           :ok <- Ledger.verify_household_erasure_ref(erasure_ref, household.household_id, scope),
           :ok <- Store.tombstone_blob(household.household_id, bytes_ref, scope, erasure_ref) do
        Common.json(conn, 200, %{
          "bytesRef" => bytes_ref,
          "scope" => scope,
          "erasureRef" => erasure_ref,
          "status" => "tombstoned"
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        :not_found ->
          Common.not_found(conn)

        {:error, :missing_scope} ->
          Common.bad_request(conn, "scope query parameter required")

        {:error, :erasure_record_required} ->
          Common.json(conn, 409, %{"error" => "erasure_record_required"})
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp key_wrap_list_opts(query_params, %{role: role, member_id: member_id}) do
    base = [
      scope: query_params["scope"],
      recipient_key_id: query_params["recipientKeyId"]
    ]

    if role in ["owner", "parent"], do: base, else: Keyword.put(base, :member_id, member_id)
  end

  defp authorize_blob_reader(%{role: role}, _scope) when role in ["owner", "parent"], do: :ok

  defp authorize_blob_reader(%{member_id: member_id, auth_subject: sub}, scope) do
    matches_member? = is_binary(member_id) and String.contains?(scope, member_id)
    matches_sub? = is_binary(sub) and sub != "" and String.contains?(scope, sub)

    if matches_member? or matches_sub?, do: :ok, else: {:error, :parent_role_required}
  end

  defp extract_blob_upload(conn, bytes_ref) do
    with :ok <- validate_bytes_ref(bytes_ref),
         {:ok, scope} <- extract_blob_scope(conn),
         {:ok, cipher_alg} <- extract_cipher_alg(conn),
         {:ok, nonce} <- extract_blob_nonce(conn),
         {:ok, ciphertext, conn} <- read_blob_bytes(conn),
         :ok <- verify_ciphertext_digest(bytes_ref, ciphertext) do
      {:ok,
       %{
         bytes_ref: bytes_ref,
         scope: scope,
         cipher_alg: cipher_alg,
         nonce: nonce,
         ciphertext: ciphertext
       }, conn}
    end
  end

  defp validate_bytes_ref(bytes_ref) do
    if Ref.valid?(bytes_ref, :bytes), do: :ok, else: {:error, :invalid_bytes_ref}
  end

  defp verify_ciphertext_digest(bytes_ref, ciphertext) do
    if Ref.bytes(ciphertext) == bytes_ref, do: :ok, else: {:error, :digest_mismatch}
  end

  defp extract_blob_scope(conn) do
    case Common.header(conn, "x-r5e-scope") || Map.get(conn.body_params || %{}, "scope") do
      scope when is_binary(scope) and scope != "" -> {:ok, scope}
      _ -> {:error, :missing_scope}
    end
  end

  defp extract_cipher_alg(conn) do
    case Common.header(conn, "x-r5e-cipher-alg") || "aes-256-gcm-v1" do
      "aes-256-gcm-v1" = alg -> {:ok, alg}
      _ -> {:error, :invalid_cipher_alg}
    end
  end

  defp extract_blob_nonce(conn) do
    nonce_b64 = Common.header(conn, "x-r5e-nonce") || Map.get(conn.body_params || %{}, "nonce")
    decode_exact(nonce_b64, 12)
  end

  defp check_recovery_kind_allowed(%{recovery_mode: "self_only"}, "parent_recovery_envelope"),
    do: {:error, :recovery_mode_self_only}

  defp check_recovery_kind_allowed(_, _), do: :ok

  defp decode_wraps(wraps) do
    Enum.reduce_while(wraps, {:ok, []}, fn
      %{
        "recipientKeyId" => recipient_key_id,
        "wrapAlg" => "x25519-hkdf-sha256-aes256gcm-v1" = alg,
        "ephemeralPubKey" => eph_b64,
        "nonce" => nonce_b64,
        "wrappedDek" => dek_b64
      },
      {:ok, acc} ->
        with {:ok, eph} <- decode_exact(eph_b64, 32),
             {:ok, nonce} <- decode_exact(nonce_b64, 12),
             {:ok, dek} <- decode_exact(dek_b64, 48) do
          {:cont,
           {:ok,
            [
              %{
                recipient_key_id: recipient_key_id,
                wrap_alg: alg,
                ephemeral_pub_key: eph,
                nonce: nonce,
                wrapped_dek: dek
              }
              | acc
            ]}}
        else
          _ -> {:halt, {:error, :invalid_wrap}}
        end

      _, _ ->
        {:halt, {:error, :invalid_wrap}}
    end)
    |> case do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      error -> error
    end
  end

  defp render_wrap(wrap) do
    %{
      "scope" => wrap.scope,
      "recipientKeyId" => wrap.recipient_key_id,
      "recipientKind" => wrap.recipient_kind,
      "wrapAlg" => wrap.wrap_alg,
      "ephemeralPubKey" => Base.encode64(wrap.ephemeral_pub_key),
      "nonce" => Base.encode64(wrap.nonce),
      "wrappedDek" => Base.encode64(wrap.wrapped_dek)
    }
  end

  defp read_blob_bytes(%Plug.Conn{body_params: %{"ciphertextBase64" => b64}} = conn)
       when is_binary(b64) do
    case Base.decode64(b64) do
      {:ok, bytes} when byte_size(bytes) <= @max_blob_bytes -> {:ok, bytes, conn}
      {:ok, _} -> {:error, :payload_too_large}
      :error -> {:error, :invalid_base64}
    end
  end

  defp read_blob_bytes(conn) do
    case Plug.Conn.read_body(conn, length: @max_blob_bytes + 1) do
      {:ok, bytes, conn} when byte_size(bytes) <= @max_blob_bytes -> {:ok, bytes, conn}
      {:more, _, _} -> {:error, :payload_too_large}
      {:ok, _, _} -> {:error, :payload_too_large}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_exact(b64, expected_len) when is_binary(b64) do
    case Base.decode64(b64) do
      {:ok, bytes} when byte_size(bytes) == expected_len -> {:ok, bytes}
      _ -> {:error, :invalid_length}
    end
  end

  defp decode_exact(_, _), do: {:error, :invalid_base64}
end
