defmodule Recurse.Gateway.Personal.E2eeHandler do
  @moduledoc """
  HTTP handlers for Phase-2 `client-e2ee` mutable recipient keys, wrapped
  per-session DEKs (`/v1/personal/key-wraps`), and mutable ciphertext blobs
  with `410 ERR_CONTENT_DISPOSED` tombstones (`/v1/personal/blobs/:bytes_ref`).

  Never touches immutable `evidence_blobs` or its append-only Postgres triggers.
  """

  alias Recurse.Gateway.Personal.Common
  alias Recurse.Provenance.Ref
  alias Recurse.Providers.Personal, as: Store

  @manage_e2ee ~s(Recurse::Action::"ManagePersonalE2EE")
  @read_household_payload ~s(Recurse::Action::"ReadHouseholdPayload")
  @read_own_payload ~s(Recurse::Action::"ReadOwnPayload")

  @max_blob_bytes 4_194_304

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
      with {:ok, household, member} <- Common.resolve_household_member(conn, ctx),
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
        {:error, :not_found} ->
          Common.not_found(conn)

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
      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           {:ok, decoded} <- decode_wraps(wraps),
           {:ok, count} <- Store.put_key_wraps(household.household_id, scope, decoded) do
        Common.json(conn, 201, %{"scope" => scope, "storedCount" => count})
      else
        {:error, :not_found} -> Common.not_found(conn)
        {:error, :recipient_not_found} -> Common.not_found(conn)
        {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
        {:error, _} -> Common.bad_request(conn, "invalid key wrap payload")
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
        opts = [
          scope: conn.query_params["scope"],
          recipient_key_id: conn.query_params["recipientKeyId"]
        ]

        with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
             {:ok, wraps} <- Store.list_key_wraps(household.household_id, opts) do
          Common.json(conn, 200, %{"wraps" => Enum.map(wraps, &render_wrap/1)})
        else
          {:error, :not_found} -> Common.not_found(conn)
          {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
        end
      end
    )
  end

  @doc "`DELETE /v1/personal/key-wraps?scope=...` (requires `X-R5E-Erasure-Ref`)"
  @spec delete_key_wraps(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_key_wraps(conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate(conn, @manage_e2ee, "/v1/personal/key-wraps", fn conn, ctx ->
      scope = conn.query_params["scope"]
      erasure_ref = Common.header(conn, "x-r5e-erasure-ref")

      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           true <- (is_binary(scope) and scope != "") || {:error, :missing_scope},
           true <- valid_erasure_ref?(erasure_ref) || {:error, :erasure_record_required},
           {:ok, deleted} <- Store.delete_key_wraps(household.household_id, scope) do
        Common.json(conn, 200, %{
          "scope" => scope,
          "erasureRef" => erasure_ref,
          "keyWrapsDeleted" => deleted
        })
      else
        {:error, :not_found} ->
          Common.not_found(conn)

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
      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           {:ok, blob_attrs, conn} <- extract_blob_upload(conn, bytes_ref),
           {:ok, row} <- Store.put_blob(household.household_id, blob_attrs) do
        Common.json(conn, 201, %{
          "bytesRef" => row.bytes_ref,
          "scope" => row.scope,
          "size" => row.size
        })
      else
        {:error, :not_found} -> Common.not_found(conn)
        {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
        {:error, :payload_too_large} -> Common.json(conn, 413, %{"error" => "payload_too_large"})
        {:error, :digest_mismatch} -> Common.json(conn, 422, %{"error" => "digest_mismatch"})
        {:error, reason} -> Common.bad_request(conn, "invalid blob upload: #{inspect(reason)}")
      end
    end)
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

        with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
             true <- is_binary(scope) and scope != "",
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
          {:gone, erasure_ref} -> Common.gone(conn, erasure_ref)
          _ -> Common.not_found(conn)
        end
      end
    )
  end

  @doc "`DELETE /v1/personal/blobs/:bytes_ref?scope=...` (requires `X-R5E-Erasure-Ref`)"
  @spec delete_blob(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_blob(%Plug.Conn{path_params: %{"bytes_ref" => bytes_ref}} = conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate(conn, @manage_e2ee, "/v1/personal/blobs", fn conn, ctx ->
      scope = conn.query_params["scope"]
      erasure_ref = Common.header(conn, "x-r5e-erasure-ref")

      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           true <- (is_binary(scope) and scope != "") || {:error, :missing_scope},
           true <- valid_erasure_ref?(erasure_ref) || {:error, :erasure_record_required},
           :ok <- Store.tombstone_blob(household.household_id, bytes_ref, scope, erasure_ref) do
        Common.json(conn, 200, %{
          "bytesRef" => bytes_ref,
          "scope" => scope,
          "erasureRef" => erasure_ref,
          "status" => "tombstoned"
        })
      else
        {:error, :not_found} ->
          Common.not_found(conn)

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

  defp valid_erasure_ref?(ref) when is_binary(ref), do: Ref.valid?(ref, :evidence)
  defp valid_erasure_ref?(_), do: false
end
