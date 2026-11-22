defmodule Recurse.Providers.GcpKmsKeyServiceTest do
  @moduledoc """
  Contract, Cloud KMS REST v1 wire/AAD/CRC32C, key rotation, disabled/destroyed
  version classification, IAM/503/timeout outage handling, and bearer-secret
  redaction tests for `Recurse.Providers.Impls.GcpKmsKeyService`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.GcpKmsKeyService
  alias Recurse.Providers.Support.MockHttpUpstream

  @moduletag :tmp_dir

  @crypto_key "projects/acme-prod/locations/us-central1/keyRings/r5e-ring/cryptoKeys/content-master"
  @default_token "ya29.c.mock-cloudkms-bearer-token-01"

  use Recurse.Providers.KeyServiceContractSuite, impl: GcpKmsKeyService

  defmodule CloudKmsSim do
    @moduledoc false

    alias Plug.Conn
    alias Recurse.Providers.Impls.GcpKmsKeyService
    alias Recurse.Providers.Support.MockHttpUpstream

    @default_token_placeholder "ya29.c.mock-cloudkms-bearer-token-01"

    def start(crypto_key, valid_tokens \\ [@default_token_placeholder]) do
      {:ok, upstream} = MockHttpUpstream.start()

      {:ok, state_agent} =
        Agent.start_link(fn ->
          %{
            crypto_key: crypto_key,
            primary_version: 1,
            versions: %{
              1 => %{key: :crypto.strong_rand_bytes(32), state: :enabled}
            },
            valid_tokens: MapSet.new(valid_tokens),
            include_name_in_decrypt: false,
            requests: []
          }
        end)

      sim = %{upstream: upstream, state: state_agent, crypto_key: crypto_key}
      mount_default_handler(sim)
      sim
    end

    def stop(%{upstream: upstream, state: state_agent}) do
      MockHttpUpstream.stop(upstream)

      if Process.alive?(state_agent) do
        Agent.stop(state_agent)
      end

      :ok
    end

    def url(%{upstream: upstream}), do: MockHttpUpstream.url(upstream)

    def rotate(%{state: state_agent}) do
      Agent.get_and_update(state_agent, fn st ->
        next_v = st.primary_version + 1
        new_entry = %{key: :crypto.strong_rand_bytes(32), state: :enabled}

        updated = %{
          st
          | primary_version: next_v,
            versions: Map.put(st.versions, next_v, new_entry)
        }

        {next_v, updated}
      end)
    end

    def set_version_state(%{state: state_agent}, version, version_state)
        when version_state in [:enabled, :disabled, :destroyed] do
      Agent.update(state_agent, fn st ->
        put_in(st, [:versions, version, :state], version_state)
      end)
    end

    def allow_token(%{state: state_agent}, token) do
      Agent.update(state_agent, fn st ->
        %{st | valid_tokens: MapSet.put(st.valid_tokens, token)}
      end)
    end

    def set_include_name_in_decrypt(%{state: state_agent}, flag) when is_boolean(flag) do
      Agent.update(state_agent, fn st -> %{st | include_name_in_decrypt: flag} end)
    end

    def requests(%{state: state_agent}) do
      Agent.get(state_agent, fn st -> Enum.reverse(st.requests) end)
    end

    def mount_default_handler(%{upstream: upstream, state: state_agent}) do
      MockHttpUpstream.expect(upstream, fn conn ->
        handle_conn(conn, state_agent)
      end)
    end

    defp handle_conn(conn, state_agent) do
      {:ok, raw_body, conn} = Conn.read_body(conn)
      parsed_body = Jason.decode!(raw_body)
      auth_header = List.first(Conn.get_req_header(conn, "authorization"))
      quota_header = List.first(Conn.get_req_header(conn, "x-goog-user-project"))

      st =
        Agent.get_and_update(state_agent, fn st ->
          rec = %{
            method: conn.method,
            request_path: conn.request_path,
            auth_header: auth_header,
            quota_project: quota_header,
            body: parsed_body
          }

          updated = %{st | requests: [rec | st.requests]}
          {updated, updated}
        end)

      encrypt_path = "/v1/#{st.crypto_key}:encrypt"
      decrypt_path = "/v1/#{st.crypto_key}:decrypt"

      case check_bearer(auth_header, st.valid_tokens) do
        :ok ->
          route_kms_request(conn, st, parsed_body, encrypt_path, decrypt_path)

        {:error, {code, status, msg}} ->
          send_google_error(conn, code, status, msg)
      end
    end

    defp route_kms_request(conn, st, parsed_body, encrypt_path, decrypt_path) do
      case {conn.method, conn.request_path} do
        {"POST", ^encrypt_path} ->
          handle_encrypt(conn, st, parsed_body)

        {"POST", ^decrypt_path} ->
          handle_decrypt(conn, st, parsed_body)

        _ ->
          send_google_error(conn, 404, "NOT_FOUND", "Resource #{conn.request_path} not found.")
      end
    end

    defp check_bearer("Bearer " <> token, valid_tokens) do
      if MapSet.member?(valid_tokens, token) do
        :ok
      else
        {:error, {401, "UNAUTHENTICATED", "Request had invalid authentication credentials."}}
      end
    end

    defp check_bearer(_, _), do: {:error, {401, "UNAUTHENTICATED", "Missing bearer token."}}

    defp handle_encrypt(conn, st, body) do
      primary_v = st.primary_version
      %{key: v_key, state: v_state} = Map.fetch!(st.versions, primary_v)

      if v_state != :enabled do
        state_str = v_state |> Atom.to_string() |> String.upcase()

        send_google_error(
          conn,
          400,
          "FAILED_PRECONDITION",
          "CryptoKeyVersion #{st.crypto_key}/cryptoKeyVersions/#{primary_v} is #{state_str}."
        )
      else
        {:ok, pt} = Base.decode64(Map.fetch!(body, "plaintext"))
        {:ok, aad} = Base.decode64(Map.get(body, "additionalAuthenticatedData", ""))

        if crc_mismatch?(body, "plaintextCrc32c", pt) or
             crc_mismatch?(body, "additionalAuthenticatedDataCrc32c", aad) do
          send_google_error(conn, 400, "INVALID_ARGUMENT", "Request CRC32C check failed.")
        else
          iv = :crypto.strong_rand_bytes(12)
          {ct_body, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, v_key, iv, pt, aad, true)
          # 4-byte big-endian version header + 12-byte IV + 16-byte GCM tag + ciphertext
          kms_blob =
            <<primary_v::unsigned-big-32, iv::binary-size(12), tag::binary-size(16),
              ct_body::binary>>

          resp = %{
            "name" => "#{st.crypto_key}/cryptoKeyVersions/#{primary_v}",
            "ciphertext" => Base.encode64(kms_blob),
            "ciphertextCrc32c" => Integer.to_string(GcpKmsKeyService.crc32c(kms_blob)),
            "verifiedPlaintextCrc32c" => true,
            "verifiedAdditionalAuthenticatedDataCrc32c" => true,
            "protectionLevel" => "SOFTWARE"
          }

          send_json(conn, 200, resp)
        end
      end
    end

    defp handle_decrypt(conn, st, body) do
      with {:ok, kms_blob} <- Base.decode64(Map.get(body, "ciphertext", "")),
           {:ok, aad} <- Base.decode64(Map.get(body, "additionalAuthenticatedData", "")),
           false <- crc_mismatch?(body, "ciphertextCrc32c", kms_blob),
           false <- crc_mismatch?(body, "additionalAuthenticatedDataCrc32c", aad),
           <<version::unsigned-big-32, iv::binary-size(12), tag::binary-size(16),
             ct_body::binary>> <- kms_blob,
           {:ok, %{key: v_key, state: v_state}} <- Map.fetch(st.versions, version) do
        decrypt_for_version_state(conn, st, version, v_state, v_key, {iv, ct_body, aad, tag})
      else
        _ ->
          send_google_error(
            conn,
            400,
            "INVALID_ARGUMENT",
            "Decryption failed: malformed ciphertext."
          )
      end
    end

    defp decrypt_for_version_state(conn, st, version, :enabled, v_key, {iv, ct_body, aad, tag}) do
      case :crypto.crypto_one_time_aead(:aes_256_gcm, v_key, iv, ct_body, aad, tag, false) do
        pt when is_binary(pt) ->
          send_json(conn, 200, build_decrypt_response(st, version, pt))

        :error ->
          send_google_error(
            conn,
            400,
            "INVALID_ARGUMENT",
            "Decryption failed: the ciphertext is invalid."
          )
      end
    end

    defp decrypt_for_version_state(conn, _st, version, non_enabled, _v_key, _cipher_parts) do
      state_str = non_enabled |> Atom.to_string() |> String.upcase()

      send_google_error(
        conn,
        400,
        "FAILED_PRECONDITION",
        "Decryption failed: key version #{version} is #{state_str}."
      )
    end

    defp build_decrypt_response(st, version, pt) do
      base_resp = %{
        "plaintext" => Base.encode64(pt),
        "plaintextCrc32c" => Integer.to_string(GcpKmsKeyService.crc32c(pt)),
        "usedPrimary" => version == st.primary_version,
        "protectionLevel" => "SOFTWARE"
      }

      if st.include_name_in_decrypt do
        Map.put(base_resp, "name", "#{st.crypto_key}/cryptoKeyVersions/#{version}")
      else
        base_resp
      end
    end

    defp crc_mismatch?(body, field, bytes) do
      case Map.get(body, field) do
        nil -> false
        str -> str != Integer.to_string(GcpKmsKeyService.crc32c(bytes))
      end
    end

    defp send_google_error(conn, code, status, message) do
      send_json(conn, code, %{
        "error" => %{
          "code" => code,
          "status" => status,
          "message" => message
        }
      })
    end

    defp send_json(conn, status, map) do
      conn
      |> Conn.put_resp_header("content-type", "application/json")
      |> Conn.send_resp(status, Jason.encode!(map))
    end
  end

  defp build_service(_context) do
    sim = CloudKmsSim.start(@crypto_key, [@default_token])
    ExUnit.Callbacks.on_exit(fn -> CloudKmsSim.stop(sim) end)

    {:ok, state} =
      GcpKmsKeyService.new(
        url: CloudKmsSim.url(sim),
        crypto_key: @crypto_key,
        token: @default_token
      )

    state
  end

  describe "Cloud KMS REST v1 wire protocol, key rotation, and version disablement" do
    test "calls :encrypt and :decrypt with Base64 AAD, CRC32C, quota project, and versioned envelope" do
      sim = CloudKmsSim.start(@crypto_key, [@default_token])
      on_exit(fn -> CloudKmsSim.stop(sim) end)

      {:ok, state} =
        GcpKmsKeyService.new(
          endpoint: CloudKmsSim.url(sim),
          project_id: "acme-prod",
          location: "us-central1",
          key_ring: "r5e-ring",
          crypto_key_id: "content-master",
          token: @default_token,
          quota_project: "acme-billing"
        )

      assert GcpKmsKeyService.describe(state) ==
               "gcp cloudkms #{CloudKmsSim.url(sim)}/v1/#{@crypto_key}"

      dek = :crypto.strong_rand_bytes(32)
      scope = "deployment:acme-prod:epoch:0042"

      assert {:ok, "gcpkms:v1:" <> _ = wrapped} = GcpKmsKeyService.wrap(state, dek, scope)
      assert {:ok, ^dek} = GcpKmsKeyService.unwrap(state, wrapped, scope)

      [enc_req, dec_req] = CloudKmsSim.requests(sim)
      assert enc_req.method == "POST"
      assert enc_req.request_path == "/v1/#{@crypto_key}:encrypt"
      assert enc_req.auth_header == "Bearer #{@default_token}"
      assert enc_req.quota_project == "acme-billing"
      assert enc_req.body["additionalAuthenticatedData"] == Base.encode64(scope)
      assert enc_req.body["plaintext"] == Base.encode64(dek)

      assert dec_req.method == "POST"
      assert dec_req.request_path == "/v1/#{@crypto_key}:decrypt"
      assert dec_req.auth_header == "Bearer #{@default_token}"
      assert dec_req.quota_project == "acme-billing"
      assert dec_req.body["additionalAuthenticatedData"] == Base.encode64(scope)
    end

    test "supports cryptoKeyVersions/1 -> 2 rotation, min_decryption_version floor, and 400 FAILED_PRECONDITION disabled/destroyed versions" do
      sim = CloudKmsSim.start(@crypto_key, [@default_token])
      on_exit(fn -> CloudKmsSim.stop(sim) end)

      {:ok, state} =
        GcpKmsKeyService.new(
          url: CloudKmsSim.url(sim),
          crypto_key: @crypto_key,
          token: @default_token
        )

      dek_v1 = :crypto.strong_rand_bytes(32)
      dek_v2 = :crypto.strong_rand_bytes(32)

      assert {:ok, "gcpkms:v1:" <> ct_v1 = wrapped_v1} =
               GcpKmsKeyService.wrap(state, dek_v1, "session:v1")

      assert 2 == CloudKmsSim.rotate(sim)

      assert {:ok, "gcpkms:v2:" <> _ = wrapped_v2} =
               GcpKmsKeyService.wrap(state, dek_v2, "session:v2")

      # Both v1 and v2 unwrap while v1 is enabled and min_decryption_version == 1.
      assert {:ok, ^dek_v1} = GcpKmsKeyService.unwrap(state, wrapped_v1, "session:v1")
      assert {:ok, ^dek_v2} = GcpKmsKeyService.unwrap(state, wrapped_v2, "session:v2")

      # Client-side min_decryption_version = 2 blocks v1 without touching network.
      {:ok, floored_state} = GcpKmsKeyService.with_min_decryption_version(state, 2)
      req_count_before = length(CloudKmsSim.requests(sim))

      assert {:error, :not_unwrappable} =
               GcpKmsKeyService.unwrap(floored_state, wrapped_v1, "session:v1")

      assert length(CloudKmsSim.requests(sim)) == req_count_before
      assert {:ok, ^dek_v2} = GcpKmsKeyService.unwrap(floored_state, wrapped_v2, "session:v2")

      # Spoofing envelope prefix "gcpkms:v2:<ct_v1>" is caught if decrypt returns version name.
      CloudKmsSim.set_include_name_in_decrypt(sim, true)

      assert {:error, :not_unwrappable} =
               GcpKmsKeyService.unwrap(floored_state, "gcpkms:v2:" <> ct_v1, "session:v1")

      # Server-side Cloud KMS DISABLED / DESTROYED key version -> 400 FAILED_PRECONDITION -> :not_unwrappable.
      CloudKmsSim.set_version_state(sim, 1, :disabled)
      assert {:error, :not_unwrappable} = GcpKmsKeyService.unwrap(state, wrapped_v1, "session:v1")
      assert {:ok, ^dek_v2} = GcpKmsKeyService.unwrap(state, wrapped_v2, "session:v2")

      CloudKmsSim.set_version_state(sim, 1, :destroyed)
      assert {:error, :not_unwrappable} = GcpKmsKeyService.unwrap(state, wrapped_v1, "session:v1")

      # Disabling primary version 2 causes wrap/3 to return {:key_service_unavailable, {:http_status, 400, _}}.
      CloudKmsSim.set_version_state(sim, 2, :disabled)

      assert {:error,
              {:key_service_unavailable,
               {:http_status, 400, %{"error" => %{"status" => "FAILED_PRECONDITION"}}}}} =
               GcpKmsKeyService.wrap(state, dek_v2, "session:v2")
    end
  end

  describe "IAM, quota, 5xx, CRC32C, and transport outage classification" do
    test "classifies 401, 403, 404, 429, 503, CRC32C corruption, timeout, and closed TCP port as {:key_service_unavailable, _}" do
      {:ok, upstream} = MockHttpUpstream.start()
      on_exit(fn -> MockHttpUpstream.stop(upstream) end)

      {:ok, state} =
        GcpKmsKeyService.new(
          url: MockHttpUpstream.url(upstream),
          crypto_key: @crypto_key,
          token: @default_token,
          receive_timeout_ms: 150,
          connect_options: [timeout: 150]
        )

      sample_envelope = "gcpkms:v1:" <> Base.encode64(:crypto.strong_rand_bytes(48))
      dek = :crypto.strong_rand_bytes(32)

      for {code, gcp_status} <- [
            {401, "UNAUTHENTICATED"},
            {403, "PERMISSION_DENIED"},
            {404, "NOT_FOUND"},
            {429, "RESOURCE_EXHAUSTED"},
            {503, "UNAVAILABLE"}
          ] do
        MockHttpUpstream.expect(upstream, fn conn ->
          body =
            Jason.encode!(%{
              "error" => %{
                "code" => code,
                "status" => gcp_status,
                "message" => "Simulated #{gcp_status}"
              }
            })

          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(code, body)
        end)

        assert {:error, {:key_service_unavailable, {:http_status, ^code, _}}} =
                 GcpKmsKeyService.unwrap(state, sample_envelope, "session:err")

        assert {:error, {:key_service_unavailable, {:http_status, ^code, _}}} =
                 GcpKmsKeyService.wrap(state, dek, "session:err")
      end

      # Corrupted plaintextCrc32c on 200 OK fails closed as :key_service_unavailable.
      MockHttpUpstream.expect(upstream, fn conn ->
        resp =
          Jason.encode!(%{
            "plaintext" => Base.encode64(dek),
            "plaintextCrc32c" => "0"
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, resp)
      end)

      assert {:error, {:key_service_unavailable, {:crc32c_mismatch, "plaintextCrc32c"}}} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:crc")

      # Missing mandatory CRC32C / verified* fields on 200 OK fail closed as :key_service_unavailable (G3).
      MockHttpUpstream.expect(upstream, fn conn ->
        resp = Jason.encode!(%{"plaintext" => Base.encode64(dek)})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, resp)
      end)

      assert {:error,
              {:key_service_unavailable, {:missing_kms_integrity_field, "plaintextCrc32c"}}} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:no-crc")

      for {missing_or_false_override, expected_err} <- [
            {fn m -> Map.delete(m, "verifiedPlaintextCrc32c") end,
             {:missing_kms_integrity_field, "verifiedPlaintextCrc32c"}},
            {fn m -> Map.put(m, "verifiedPlaintextCrc32c", false) end,
             {:kms_integrity_check_failed, "verifiedPlaintextCrc32c"}},
            {fn m -> Map.delete(m, "verifiedAdditionalAuthenticatedDataCrc32c") end,
             {:missing_kms_integrity_field, "verifiedAdditionalAuthenticatedDataCrc32c"}},
            {fn m -> Map.delete(m, "ciphertextCrc32c") end,
             {:missing_kms_integrity_field, "ciphertextCrc32c"}}
          ] do
        MockHttpUpstream.expect(upstream, fn conn ->
          fake_ct = :crypto.strong_rand_bytes(48)

          base_map = %{
            "name" => "#{@crypto_key}/cryptoKeyVersions/1",
            "ciphertext" => Base.encode64(fake_ct),
            "ciphertextCrc32c" => Integer.to_string(GcpKmsKeyService.crc32c(fake_ct)),
            "verifiedPlaintextCrc32c" => true,
            "verifiedAdditionalAuthenticatedDataCrc32c" => true
          }

          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(200, Jason.encode!(missing_or_false_override.(base_map)))
        end)

        assert {:error, {:key_service_unavailable, ^expected_err}} =
                 GcpKmsKeyService.wrap(state, dek, "session:enc-crc")
      end

      # Decrypt HTTP 400 classification (G1):
      # - 400 INVALID_ARGUMENT due to server-side CRC32C / checksum corruption -> :key_service_unavailable
      # - 400 non-JSON proxy / L7 gateway error -> :key_service_unavailable
      # - 400 INVALID_ARGUMENT "Decryption failed: the ciphertext is invalid." -> :not_unwrappable
      # - 400 FAILED_PRECONDITION (disabled/destroyed key version) -> :not_unwrappable
      MockHttpUpstream.expect(upstream, fn conn ->
        body =
          Jason.encode!(%{
            "error" => %{
              "code" => 400,
              "status" => "INVALID_ARGUMENT",
              "message" => "Request ciphertextCrc32c checksum did not match."
            }
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(400, body)
      end)

      assert {:error, {:key_service_unavailable, {:http_status, 400, _}}} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:crc-400")

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "text/plain")
        |> Plug.Conn.send_resp(400, "400 Bad Request - upstream proxy")
      end)

      assert {:error, {:key_service_unavailable, {:http_status, 400, _}}} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:proxy-400")

      MockHttpUpstream.expect(upstream, fn conn ->
        body =
          Jason.encode!(%{
            "error" => %{
              "code" => 400,
              "status" => "INVALID_ARGUMENT",
              "message" => "Decryption failed: the ciphertext is invalid."
            }
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(400, body)
      end)

      assert {:error, :not_unwrappable} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:bad-ct")

      MockHttpUpstream.expect(upstream, fn conn ->
        body =
          Jason.encode!(%{
            "error" => %{
              "code" => 400,
              "status" => "FAILED_PRECONDITION",
              "message" => "CryptoKeyVersion is DISABLED."
            }
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(400, body)
      end)

      assert {:error, :not_unwrappable} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:disabled-400")

      # Receive timeout classifies as {:key_service_unavailable, :timeout}.
      MockHttpUpstream.expect(upstream, fn conn ->
        Process.sleep(350)
        Plug.Conn.send_resp(conn, 200, "{}")
      end)

      assert {:error, {:key_service_unavailable, :timeout}} =
               GcpKmsKeyService.unwrap(state, sample_envelope, "session:slow")

      # Unreachable closed TCP port classifies as {:key_service_unavailable, _}.
      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, closed_port} = :inet.port(listen_socket)
      :ok = :gen_tcp.close(listen_socket)

      {:ok, dead_state} =
        GcpKmsKeyService.new(
          url: "http://127.0.0.1:#{closed_port}",
          crypto_key: @crypto_key,
          token: @default_token,
          connect_options: [timeout: 200],
          receive_timeout_ms: 200
        )

      assert {:error, {:key_service_unavailable, _}} =
               GcpKmsKeyService.wrap(dead_state, dek, "session:dead")

      assert {:error, {:key_service_unavailable, _}} =
               GcpKmsKeyService.unwrap(dead_state, sample_envelope, "session:dead")
    end
  end

  describe "bearer token sources, Inspect redaction, and zero secret leaks" do
    test "supports rotating file and callback bearer tokens and redacts secrets across Inspect, structs: false, and error paths",
         %{tmp_dir: tmp_dir} do
      canary_static = "ya29.canary-static-secret-998877"
      canary_file_1 = "ya29.canary-file-secret-v1-112233"
      canary_file_2 = "ya29.canary-file-secret-v2-445566"
      canary_cb = "ya29.canary-callback-secret-776655"

      sim =
        CloudKmsSim.start(@crypto_key, [
          canary_static,
          canary_file_1,
          canary_file_2,
          canary_cb
        ])

      on_exit(fn -> CloudKmsSim.stop(sim) end)

      token_file = Path.join(tmp_dir, "wif-token")
      File.write!(token_file, canary_file_1 <> "\n")
      File.chmod!(token_file, 0o600)

      {:ok, static_state} =
        GcpKmsKeyService.new(
          url: CloudKmsSim.url(sim),
          crypto_key: @crypto_key,
          token: canary_static
        )

      {:ok, file_state} =
        GcpKmsKeyService.new(
          url: CloudKmsSim.url(sim),
          crypto_key: @crypto_key,
          token_path: token_file
        )

      {:ok, cb_state} =
        GcpKmsKeyService.new(
          url: CloudKmsSim.url(sim),
          crypto_key: @crypto_key,
          token_fetcher: fn -> {:ok, canary_cb} end
        )

      for {st, mode, secret} <- [
            {static_state, :static, canary_static},
            {file_state, :file, canary_file_1},
            {cb_state, :callback, canary_cb}
          ] do
        rendered = inspect(st)
        raw_rendered = inspect(st, structs: false)
        map_rendered = inspect(Map.from_struct(st))
        desc = GcpKmsKeyService.describe(st)

        assert rendered =~ "auth_mode: #{inspect(mode)}"
        assert rendered =~ ~s(token: "[REDACTED]")

        for text <- [rendered, raw_rendered, map_rendered, desc] do
          refute String.contains?(text, secret)
          refute String.contains?(text, token_file)
        end
      end

      dek = :crypto.strong_rand_bytes(32)
      assert {:ok, wrapped_f1} = GcpKmsKeyService.wrap(file_state, dek, "session:wif")

      # Rotate projected token file on disk; next call picks up canary_file_2 automatically.
      File.write!(token_file, canary_file_2)
      assert {:ok, ^dek} = GcpKmsKeyService.unwrap(file_state, wrapped_f1, "session:wif")
      assert {:ok, ^dek} = GcpKmsKeyService.unwrap(cb_state, wrapped_f1, "session:wif")

      # Deleting token file during runtime surfaces {:key_service_unavailable, _}
      # with zero path/token leak.
      File.rm!(token_file)

      assert {:error, {:key_service_unavailable, {:unreadable_token_file, :enoent}}} =
               GcpKmsKeyService.unwrap(file_state, wrapped_f1, "session:wif")

      # Raising inside token_fetcher never leaks exception message carrying a canary secret.
      {:ok, crashing_cb_state} =
        GcpKmsKeyService.new(
          url: CloudKmsSim.url(sim),
          crypto_key: @crypto_key,
          token_fetcher: fn -> raise "oauth refresh failed with #{canary_cb}" end
        )

      assert {:error, err} = GcpKmsKeyService.wrap(crashing_cb_state, dek, "session:crash")
      assert err == {:key_service_unavailable, {:token_fetcher_exception, RuntimeError}}
      refute String.contains?(inspect(err), canary_cb)

      # Upstream error echoing the bearer token back in JSON message is scrubbed!
      {:ok, echo_upstream} = MockHttpUpstream.start()
      on_exit(fn -> MockHttpUpstream.stop(echo_upstream) end)

      MockHttpUpstream.expect(echo_upstream, fn conn ->
        [auth] = Plug.Conn.get_req_header(conn, "authorization")

        body =
          Jason.encode!(%{
            "error" => %{
              "code" => 403,
              "status" => "PERMISSION_DENIED",
              "message" => "Rejected header #{auth}"
            }
          })

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(403, body)
      end)

      {:ok, echo_state} =
        GcpKmsKeyService.new(
          url: MockHttpUpstream.url(echo_upstream),
          crypto_key: @crypto_key,
          token: canary_static
        )

      assert {:error, echo_err} = GcpKmsKeyService.wrap(echo_state, dek, "session:echo")
      refute String.contains?(inspect(echo_err), canary_static)
      assert inspect(echo_err) =~ "[REDACTED]"
    end

    test "validates config strictly (path traversal, URL userinfo, CR/LF headers, missing/ambiguous auth, non-32B keys)" do
      assert {:error, {:invalid_config, :crypto_key}} =
               GcpKmsKeyService.new(
                 crypto_key: "projects/p/locations/../keyRings/r/cryptoKeys/k",
                 token: "tok"
               )

      assert {:error, {:invalid_config, :crypto_key}} =
               GcpKmsKeyService.new(
                 crypto_key: "#{@crypto_key}/cryptoKeyVersions/1",
                 token: "tok"
               )

      assert {:error, {:invalid_config, :url}} =
               GcpKmsKeyService.new(
                 url: "https://secret-token@cloudkms.googleapis.com",
                 crypto_key: @crypto_key,
                 token: "tok"
               )

      assert {:error, {:invalid_config, :url}} =
               GcpKmsKeyService.new(
                 url: "http://cloudkms.googleapis.com",
                 crypto_key: @crypto_key,
                 token: "tok"
               )

      assert {:error, {:invalid_config, :url}} =
               GcpKmsKeyService.new(
                 url: "http://10.0.0.5:8080",
                 crypto_key: @crypto_key,
                 token: "tok"
               )

      assert {:ok, _} =
               GcpKmsKeyService.new(
                 url: "http://127.0.0.1:8080",
                 crypto_key: @crypto_key,
                 token: "tok"
               )

      assert {:ok, _} =
               GcpKmsKeyService.new(
                 url: "http://[::1]:8080",
                 crypto_key: @crypto_key,
                 token: "tok"
               )

      assert {:error, {:invalid_config, :token}} =
               GcpKmsKeyService.new(
                 crypto_key: @crypto_key,
                 token: "bad\r\nheader: injected"
               )

      assert {:error, {:missing_config, :token}} =
               GcpKmsKeyService.new(crypto_key: @crypto_key)

      assert {:error, {:invalid_config, :ambiguous_auth}} =
               GcpKmsKeyService.new(
                 crypto_key: @crypto_key,
                 token: "a",
                 token_fetcher: fn -> "b" end
               )

      {:ok, valid} = GcpKmsKeyService.new(crypto_key: @crypto_key, token: "tok")
      assert {:error, {:invalid_key_length, 16}} = GcpKmsKeyService.wrap(valid, <<0::128>>, "ctx")
    end
  end
end
