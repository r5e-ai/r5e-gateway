defmodule Recurse.Providers.Impls.GcpKmsKeyService do
  @moduledoc """
  `Recurse.Providers.KeyService` backed by Google Cloud KMS REST v1
  (`POST /v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/*}:encrypt` and `:decrypt`).

  Per-session 32-byte content encryption keys are wrapped under a symmetric
  Cloud KMS `CryptoKey` with `additionalAuthenticatedData = Base.encode64(context)`
  and mandatory Castagnoli CRC32C integrity verification (`verifiedPlaintextCrc32c`,
  `verifiedAdditionalAuthenticatedDataCrc32c`, `ciphertextCrc32c`, and
  `plaintextCrc32c`).

  Wrapped envelopes record the issuing `CryptoKeyVersion` integer
  (`"gcpkms:v<version>:<ciphertext_b64>"`). Note that the client-side
  `min_decryption_version` check is an **advisory pre-flight filter only**: the
  envelope prefix is not bound into Cloud KMS AAD and Google's `DecryptResponse`
  omits the version `name`, so an attacker with database write access could
  rewrite the version prefix. The **authoritative cryptographic kill-switch** in
  Cloud KMS is disabling or destroying the `CryptoKeyVersion` server-side in GCP,
  which causes `:decrypt` to fail with `400 FAILED_PRECONDITION`.

  ## Error semantics

    * Malformed envelopes, key versions below the advisory `min_decryption_version`
      floor, and genuine decryption refusals on `:decrypt` (`400 FAILED_PRECONDITION`
      for `DISABLED` or `DESTROYED` key versions; `400 INVALID_ARGUMENT` for
      cipher/AAD decryption failure) return `{:error, :not_unwrappable}`.
    * `400 INVALID_ARGUMENT` mentioning `crc32c` or `checksum` (in-transit
      request corruption), unparseable/other `400` responses, IAM/auth failures
      (`401`/`403`), missing resources (`404`), quota/rate limits (`429`),
      server errors (`5xx`), missing/false CRC32C verification fields, transport
      timeouts/disconnects, and token-source failures return
      `{:error, {:key_service_unavailable, reason}}` with bearer credentials
      strictly scrubbed.
  """

  @behaviour Recurse.Providers.KeyService

  import Bitwise

  @default_url "https://cloudkms.googleapis.com"
  @default_receive_timeout_ms 5_000
  @default_connect_timeout_ms 2_000
  @envelope_prefix "gcpkms:v"
  @segment_regex ~r/\A[A-Za-z0-9._-]{1,128}\z/
  @crc32c_poly 0x82F63B78

  @type auth_mode :: :static | :file | :callback

  @enforce_keys [
    :url,
    :crypto_key,
    :auth_mode,
    :auth_fetcher,
    :min_decryption_version,
    :receive_timeout_ms,
    :connect_options
  ]
  defstruct [
    :url,
    :crypto_key,
    :auth_mode,
    :auth_fetcher,
    :quota_project,
    :finch_pool,
    :min_decryption_version,
    :receive_timeout_ms,
    :connect_options
  ]

  @opaque auth_fetcher_fun :: (-> {:ok, String.t()} | {:error, term()})

  @type t :: %__MODULE__{
          url: String.t(),
          crypto_key: String.t(),
          auth_mode: auth_mode(),
          auth_fetcher: auth_fetcher_fun(),
          quota_project: String.t() | nil,
          finch_pool: atom() | nil,
          min_decryption_version: pos_integer(),
          receive_timeout_ms: pos_integer(),
          connect_options: keyword()
        }

  defimpl Inspect do
    import Inspect.Algebra

    @spec inspect(Recurse.Providers.Impls.GcpKmsKeyService.t(), Inspect.Opts.t()) ::
            Inspect.Algebra.t()
    def inspect(state, opts) do
      concat([
        "#GcpKmsKeyService<url: ",
        to_doc(state.url, opts),
        ", crypto_key: ",
        to_doc(state.crypto_key, opts),
        ", auth_mode: ",
        to_doc(state.auth_mode, opts),
        ", min_decryption_version: ",
        to_doc(state.min_decryption_version, opts),
        ", token: \"[REDACTED]\">"
      ])
    end
  end

  @doc """
  Construct a validated `GcpKmsKeyService` state from a keyword list or map.

  ## Options

    * `:crypto_key` (or `:key_name`) — full Cloud KMS symmetric key resource
      name `"projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>"`, OR pass
      component options `:project_id` (or `:project`), `:location`, `:key_ring`,
      and `:crypto_key_id`.
    * `:token`, `:token_path`, or `:token_fetcher` (alias `:token_callback`) —
      exactly one OAuth2/WIF bearer token source.
    * `:url` (or `:endpoint`, `:base_url`) — Cloud KMS API base URL
      (default `"https://cloudkms.googleapis.com"`). Must use `https://`, except
      loopback (`127.0.0.1`, `localhost`, `::1`) where `http://` is permitted
      for local test upstreams.
    * `:min_decryption_version` — advisory client-side minimum `CryptoKeyVersion`
      integer pre-flight filter during `unwrap/3` (default `1`). Disable or
      destroy the `CryptoKeyVersion` in GCP KMS for authoritative enforcement.
    * `:quota_project` — optional `x-goog-user-project` header value.
    * `:finch_pool` — optional named Finch pool atom.
    * `:receive_timeout_ms` — per-call HTTP receive timeout (default `5_000`).
    * `:connect_options` — transport connect options (default `[timeout: 2_000]`).
  """
  @spec new(keyword() | map()) :: {:ok, t()} | {:error, term()}
  def new(opts) when is_list(opts), do: opts |> Map.new() |> new()

  def new(config) when is_map(config) do
    with {:ok, url} <- fetch_url(config),
         {:ok, crypto_key} <- fetch_crypto_key(config),
         {:ok, auth_mode, auth_fetcher} <- build_auth_fetcher(config),
         {:ok, min_decryption_version} <-
           fetch_pos_integer(config, :min_decryption_version, 1),
         {:ok, quota_project} <- fetch_optional_header_value(config, :quota_project),
         {:ok, finch_pool} <- fetch_optional_atom(config, :finch_pool),
         {:ok, receive_timeout_ms} <-
           fetch_pos_integer(config, :receive_timeout_ms, @default_receive_timeout_ms),
         {:ok, connect_options} <- fetch_connect_options(config) do
      {:ok,
       %__MODULE__{
         url: url,
         crypto_key: crypto_key,
         auth_mode: auth_mode,
         auth_fetcher: auth_fetcher,
         quota_project: quota_project,
         finch_pool: finch_pool,
         min_decryption_version: min_decryption_version,
         receive_timeout_ms: receive_timeout_ms,
         connect_options: connect_options
       }}
    end
  end

  def new(_other), do: {:error, {:invalid_config, :options}}

  @doc "Alias for `new/1`."
  @spec open(keyword() | map()) :: {:ok, t()} | {:error, term()}
  def open(opts), do: new(opts)

  @doc """
  Return an updated `GcpKmsKeyService` state enforcing `min_version` as an
  advisory client-side pre-flight floor on the `"gcpkms:v<version>:"` prefix.
  Authoritative key retirement requires disabling or destroying the version in
  Cloud KMS.
  """
  @spec with_min_decryption_version(t(), pos_integer()) :: {:ok, t()} | {:error, term()}
  def with_min_decryption_version(%__MODULE__{} = state, min_version)
      when is_integer(min_version) and min_version >= 1 do
    {:ok, %{state | min_decryption_version: min_version}}
  end

  def with_min_decryption_version(%__MODULE__{}, _min_version) do
    {:error, {:invalid_config, :min_decryption_version}}
  end

  @impl true
  @spec wrap(t(), <<_::256>>, String.t()) ::
          {:ok, binary()}
          | {:error, {:invalid_key_length, non_neg_integer()}}
          | {:error, :invalid_arguments}
          | {:error, {:key_service_unavailable, term()}}
  def wrap(%__MODULE__{} = state, <<_::256>> = key, context) when is_binary(context) do
    payload = %{
      "plaintext" => Base.encode64(key),
      "plaintextCrc32c" => Integer.to_string(crc32c(key)),
      "additionalAuthenticatedData" => Base.encode64(context),
      "additionalAuthenticatedDataCrc32c" => Integer.to_string(crc32c(context))
    }

    with {:ok, token} <- fetch_bearer_token(state),
         {:ok, status, body} <- post_json(state, encrypt_path(state), payload, token) do
      handle_encrypt_response(state, status, body, token)
    else
      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  def wrap(%__MODULE__{}, key, context) when is_binary(key) and is_binary(context) do
    {:error, {:invalid_key_length, byte_size(key)}}
  end

  def wrap(%__MODULE__{}, _key, _context), do: {:error, :invalid_arguments}

  @impl true
  @spec unwrap(t(), binary(), String.t()) ::
          {:ok, <<_::256>>}
          | {:error, :not_unwrappable}
          | {:error, {:key_service_unavailable, term()}}
  def unwrap(%__MODULE__{} = state, wrapped, context)
      when is_binary(wrapped) and is_binary(context) do
    with {:ok, version, ciphertext_b64, ciphertext_raw} <- parse_envelope(wrapped),
         true <- version >= state.min_decryption_version do
      do_unwrap(state, version, ciphertext_b64, ciphertext_raw, context)
    else
      _ -> {:error, :not_unwrappable}
    end
  end

  def unwrap(%__MODULE__{}, _wrapped, _context), do: {:error, :not_unwrappable}

  @impl true
  @spec describe(t()) :: String.t()
  def describe(%__MODULE__{url: url, crypto_key: crypto_key}) do
    "gcp cloudkms #{url}/v1/#{crypto_key}"
  end

  @doc false
  @spec crc32c(binary()) :: non_neg_integer()
  def crc32c(data) when is_binary(data) do
    data
    |> :binary.bin_to_list()
    |> Enum.reduce(0xFFFFFFFF, &crc32c_byte/2)
    |> bxor(0xFFFFFFFF)
    |> band(0xFFFFFFFF)
  end

  defp crc32c_byte(byte, crc) do
    Enum.reduce(0..7, bxor(crc, byte), fn _, acc -> crc32c_step(acc) end)
  end

  defp crc32c_step(acc) when (acc &&& 1) == 1, do: bxor(acc >>> 1, @crc32c_poly)
  defp crc32c_step(acc), do: acc >>> 1

  defp do_unwrap(state, expected_version, ciphertext_b64, ciphertext_raw, context) do
    payload = %{
      "ciphertext" => ciphertext_b64,
      "ciphertextCrc32c" => Integer.to_string(crc32c(ciphertext_raw)),
      "additionalAuthenticatedData" => Base.encode64(context),
      "additionalAuthenticatedDataCrc32c" => Integer.to_string(crc32c(context))
    }

    with {:ok, token} <- fetch_bearer_token(state),
         {:ok, status, body} <- post_json(state, decrypt_path(state), payload, token) do
      handle_decrypt_response(state, expected_version, status, body, token)
    else
      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  defp handle_encrypt_response(state, status, body, _token)
       when status in 200..299 and is_map(body) do
    with :ok <- require_verified_flag(body, "verifiedPlaintextCrc32c"),
         :ok <- require_verified_flag(body, "verifiedAdditionalAuthenticatedDataCrc32c"),
         {:ok, version} <- extract_encrypt_version(state.crypto_key, Map.get(body, "name")),
         {:ok, ciphertext_raw} <- decode_non_empty_base64(Map.get(body, "ciphertext")),
         :ok <- require_matching_crc32c(body, "ciphertextCrc32c", ciphertext_raw) do
      canonical_b64 = Base.encode64(ciphertext_raw)
      {:ok, "#{@envelope_prefix}#{version}:#{canonical_b64}"}
    else
      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  defp handle_encrypt_response(_state, status, body, token) do
    {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body, token)}}}
  end

  defp handle_decrypt_response(state, expected_version, status, body, _token)
       when status in 200..299 and is_map(body) do
    with :ok <- verify_optional_decrypt_name(state, expected_version, Map.get(body, "name")),
         {:ok, plaintext_raw} <- decode_decrypt_plaintext(Map.get(body, "plaintext")),
         :ok <- require_matching_crc32c(body, "plaintextCrc32c", plaintext_raw) do
      case plaintext_raw do
        <<_::256>> -> {:ok, plaintext_raw}
        _ -> {:error, :not_unwrappable}
      end
    else
      {:error, :not_unwrappable} ->
        {:error, :not_unwrappable}

      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  defp handle_decrypt_response(_state, _expected_version, 400, body, token) do
    if permanent_decrypt_400?(body) do
      {:error, :not_unwrappable}
    else
      {:error, {:key_service_unavailable, {:http_status, 400, sanitize_body(body, token)}}}
    end
  end

  defp handle_decrypt_response(_state, _expected_version, status, body, token) do
    {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body, token)}}}
  end

  defp permanent_decrypt_400?(%{"error" => %{"status" => "FAILED_PRECONDITION"}}), do: true

  defp permanent_decrypt_400?(%{
         "error" => %{"status" => "INVALID_ARGUMENT", "message" => msg}
       })
       when is_binary(msg) do
    downcased = String.downcase(msg)

    not integrity_checksum_failure?(downcased) and
      String.contains?(downcased, ["decryption failed", "ciphertext"])
  end

  defp permanent_decrypt_400?(_other), do: false

  defp integrity_checksum_failure?(downcased_msg) do
    String.contains?(downcased_msg, ["crc32c", "checksum"])
  end

  defp require_verified_flag(body, field) do
    case Map.get(body, field) do
      true -> :ok
      false -> {:error, {:kms_integrity_check_failed, field}}
      nil -> {:error, {:missing_kms_integrity_field, field}}
      _ -> {:error, {:malformed_kms_response, field}}
    end
  end

  defp extract_encrypt_version(crypto_key, name) when is_binary(name) do
    expected_prefix = crypto_key <> "/cryptoKeyVersions/"

    case String.split_at(name, byte_size(expected_prefix)) do
      {^expected_prefix, version_str} ->
        parse_canonical_pos_integer(version_str, :unexpected_key_version_name)

      _ ->
        {:error, :unexpected_key_version_name}
    end
  end

  defp extract_encrypt_version(_crypto_key, _other), do: {:error, :missing_key_version_name}

  defp verify_optional_decrypt_name(_state, _expected_version, nil), do: :ok

  defp verify_optional_decrypt_name(state, expected_version, name) when is_binary(name) do
    case extract_encrypt_version(state.crypto_key, name) do
      {:ok, ^expected_version} when expected_version >= state.min_decryption_version ->
        :ok

      _ ->
        {:error, :not_unwrappable}
    end
  end

  defp verify_optional_decrypt_name(_state, _expected_version, _other) do
    {:error, :malformed_decrypt_response}
  end

  defp decode_non_empty_base64(value) when is_binary(value) and byte_size(value) > 0 do
    case Base.decode64(value) do
      {:ok, raw} when byte_size(raw) > 0 -> {:ok, raw}
      _ -> {:error, :malformed_ciphertext}
    end
  end

  defp decode_non_empty_base64(_), do: {:error, :malformed_ciphertext}

  defp decode_decrypt_plaintext(value) when is_binary(value) and byte_size(value) > 0 do
    case Base.decode64(value) do
      {:ok, raw} -> {:ok, raw}
      :error -> {:error, :malformed_decrypt_response}
    end
  end

  defp decode_decrypt_plaintext(_), do: {:error, :malformed_decrypt_response}

  defp require_matching_crc32c(body, field, bytes) do
    case Map.get(body, field) do
      nil -> {:error, {:missing_kms_integrity_field, field}}
      val -> check_parsed_crc32c(parse_non_neg_integer(val), field, bytes)
    end
  end

  defp check_parsed_crc32c({:ok, expected}, field, bytes) do
    if expected == crc32c(bytes), do: :ok, else: {:error, {:crc32c_mismatch, field}}
  end

  defp check_parsed_crc32c(:error, field, _bytes), do: {:error, {:malformed_kms_response, field}}

  defp parse_non_neg_integer(val) when is_integer(val) and val >= 0, do: {:ok, val}

  defp parse_non_neg_integer(val) when is_binary(val) do
    case Integer.parse(val) do
      {num, ""} when num >= 0 -> {:ok, num}
      _ -> :error
    end
  end

  defp parse_non_neg_integer(_), do: :error

  defp parse_envelope(wrapped) do
    with true <- String.valid?(wrapped) and String.starts_with?(wrapped, @envelope_prefix),
         {:ok, version_str, ciphertext_b64} <- split_envelope_body(wrapped),
         {:ok, version} <- parse_canonical_pos_integer(version_str, :invalid_version),
         {:ok, ciphertext_raw} when byte_size(ciphertext_raw) > 0 <-
           Base.decode64(ciphertext_b64),
         true <- Base.encode64(ciphertext_raw) == ciphertext_b64 do
      {:ok, version, ciphertext_b64, ciphertext_raw}
    else
      _ -> :error
    end
  end

  defp split_envelope_body(wrapped) do
    rest = String.replace_prefix(wrapped, @envelope_prefix, "")

    case :binary.split(rest, ":") do
      [version_str, ciphertext_b64] when byte_size(ciphertext_b64) > 0 ->
        {:ok, version_str, ciphertext_b64}

      _ ->
        :error
    end
  end

  defp parse_canonical_pos_integer(str, err_reason) when is_binary(str) and byte_size(str) > 0 do
    case Integer.parse(str) do
      {num, ""} when num >= 1 ->
        if Integer.to_string(num) == str, do: {:ok, num}, else: {:error, err_reason}

      _ ->
        {:error, err_reason}
    end
  end

  defp parse_canonical_pos_integer(_, err_reason), do: {:error, err_reason}

  defp encrypt_path(%__MODULE__{crypto_key: crypto_key}), do: "/v1/#{crypto_key}:encrypt"
  defp decrypt_path(%__MODULE__{crypto_key: crypto_key}), do: "/v1/#{crypto_key}:decrypt"

  defp fetch_bearer_token(%__MODULE__{auth_fetcher: fetcher}) do
    fetcher.()
  end

  defp post_json(state, path, payload, token) do
    req_opts =
      maybe_put_finch(
        [
          url: state.url <> path,
          json: payload,
          headers: request_headers(state, token),
          retry: false,
          receive_timeout: state.receive_timeout_ms,
          connect_options: state.connect_options
        ],
        state.finch_pool
      )

    case Req.post(req_opts) do
      {:ok, %Req.Response{status: status, body: body}} ->
        {:ok, status, body}

      {:error, %Req.TransportError{reason: reason}} ->
        {:error, scrub_term(reason, token)}

      {:error, reason} ->
        {:error, scrub_term(reason, token)}
    end
  end

  defp maybe_put_finch(opts, nil), do: opts
  defp maybe_put_finch(opts, pool) when is_atom(pool), do: Keyword.put(opts, :finch, pool)

  defp request_headers(%__MODULE__{quota_project: nil}, token) do
    [{"authorization", "Bearer " <> token}]
  end

  defp request_headers(%__MODULE__{quota_project: quota_project}, token) do
    [{"authorization", "Bearer " <> token}, {"x-goog-user-project", quota_project}]
  end

  defp sanitize_body(%{"error" => %{} = err}, token) do
    sanitized =
      err
      |> Map.take(["code", "status", "message"])
      |> Enum.into(%{}, fn
        {"message", msg} when is_binary(msg) ->
          {"message", msg |> scrub_string(token) |> String.slice(0, 256)}

        {"status", st} when is_binary(st) ->
          {"status", st |> scrub_string(token) |> String.slice(0, 64)}

        {"code", code} when is_integer(code) ->
          {"code", code}

        {k, _v} ->
          {k, :redacted}
      end)

    %{"error" => sanitized}
  end

  defp sanitize_body(body, token) when is_binary(body) do
    body
    |> scrub_string(token)
    |> String.slice(0, 256)
  end

  defp sanitize_body(_other, _token), do: :unexpected_response_body

  defp scrub_term(term, _token) when is_atom(term) or is_number(term), do: term

  defp scrub_term(term, token) when is_binary(term), do: scrub_string(term, token)

  defp scrub_term({tag, detail}, token) when is_atom(tag) do
    {tag, scrub_term(detail, token)}
  end

  defp scrub_term(_other, _token), do: :transport_error

  defp scrub_string(str, token) when is_binary(str) and is_binary(token) and token != "" do
    String.replace(str, token, "[REDACTED]")
  end

  defp scrub_string(str, _token), do: str

  defp fetch_url(config) do
    raw =
      Map.get(config, :url) || Map.get(config, :endpoint) || Map.get(config, :base_url) ||
        @default_url

    with true <- is_binary(raw) and byte_size(String.trim(raw)) > 0,
         trimmed = String.trim_trailing(String.trim(raw), "/"),
         %URI{
           scheme: scheme,
           host: host,
           userinfo: nil,
           query: nil,
           fragment: nil
         }
         when is_binary(host) and host != "" <-
           URI.parse(trimmed),
         true <- allowed_url_scheme_and_host?(scheme, host) do
      {:ok, trimmed}
    else
      _ -> {:error, {:invalid_config, :url}}
    end
  end

  defp allowed_url_scheme_and_host?("https", _host), do: true

  defp allowed_url_scheme_and_host?("http", host) do
    String.downcase(host) in ["127.0.0.1", "localhost", "::1", "[::1]"]
  end

  defp allowed_url_scheme_and_host?(_scheme, _host), do: false

  defp fetch_crypto_key(config) do
    case Map.get(config, :crypto_key) || Map.get(config, :key_name) do
      raw when is_binary(raw) ->
        validate_crypto_key_path(String.trim(raw))

      nil ->
        project = Map.get(config, :project_id) || Map.get(config, :project)
        location = Map.get(config, :location)
        key_ring = Map.get(config, :key_ring)
        crypto_key_id = Map.get(config, :crypto_key_id)

        if Enum.all?([project, location, key_ring, crypto_key_id], &is_binary/1) do
          validate_crypto_key_segments(project, location, key_ring, crypto_key_id)
        else
          {:error, {:missing_config, :crypto_key}}
        end

      _ ->
        {:error, {:invalid_config, :crypto_key}}
    end
  end

  defp validate_crypto_key_path(path) do
    case String.split(path, "/") do
      [
        "projects",
        project,
        "locations",
        location,
        "keyRings",
        key_ring,
        "cryptoKeys",
        crypto_key_id
      ] ->
        validate_crypto_key_segments(project, location, key_ring, crypto_key_id)

      _ ->
        {:error, {:invalid_config, :crypto_key}}
    end
  end

  defp validate_crypto_key_segments(project, location, key_ring, crypto_key_id) do
    segments = [project, location, key_ring, crypto_key_id]

    if Enum.all?(segments, &valid_resource_segment?/1) do
      {:ok,
       "projects/#{project}/locations/#{location}/keyRings/#{key_ring}/cryptoKeys/#{crypto_key_id}"}
    else
      {:error, {:invalid_config, :crypto_key}}
    end
  end

  defp valid_resource_segment?(seg) when is_binary(seg) do
    seg not in [".", ".."] and Regex.match?(@segment_regex, seg)
  end

  defp build_auth_fetcher(config) do
    has_token = present_option?(config, :token)
    has_path = present_option?(config, :token_path)
    has_cb = present_option?(config, :token_fetcher) or present_option?(config, :token_callback)

    case {has_token, has_path, has_cb} do
      {false, false, false} ->
        {:error, {:missing_config, :token}}

      {true, false, false} ->
        build_static_auth_fetcher(Map.get(config, :token))

      {false, true, false} ->
        build_file_auth_fetcher(Map.get(config, :token_path))

      {false, false, true} ->
        build_callback_auth_fetcher(resolve_callback_option(config))

      _ ->
        {:error, {:invalid_config, :ambiguous_auth}}
    end
  end

  defp present_option?(config, key), do: Map.get(config, key) != nil

  defp resolve_callback_option(config) do
    Map.get(config, :token_fetcher) || Map.get(config, :token_callback)
  end

  defp build_static_auth_fetcher(raw_token) do
    case validate_bearer_token(raw_token, {:invalid_config, :token}) do
      {:ok, validated} -> {:ok, :static, fn -> {:ok, validated} end}
      {:error, _} = err -> err
    end
  end

  defp build_file_auth_fetcher(path) when is_binary(path) do
    case String.trim(path) do
      "" -> {:error, {:invalid_config, :token_path}}
      trimmed_path -> verify_and_wrap_token_file(trimmed_path)
    end
  end

  defp build_file_auth_fetcher(_other), do: {:error, {:invalid_config, :token_path}}

  defp verify_and_wrap_token_file(trimmed_path) do
    case read_token_file(trimmed_path) do
      {:ok, _initial_token} -> {:ok, :file, fn -> read_token_file(trimmed_path) end}
      {:error, _} = err -> err
    end
  end

  defp read_token_file(path) do
    case File.read(path) do
      {:ok, raw} ->
        validate_bearer_token(raw, {:unreadable_token_file, :invalid_token})

      {:error, posix} when is_atom(posix) ->
        {:error, {:unreadable_token_file, posix}}

      {:error, _} ->
        {:error, {:unreadable_token_file, :io_error}}
    end
  end

  defp build_callback_auth_fetcher(fun) when is_function(fun, 0) do
    {:ok, :callback, fn -> invoke_token_callback(fun) end}
  end

  defp build_callback_auth_fetcher(_other), do: {:error, {:invalid_config, :token_fetcher}}

  defp invoke_token_callback(fun) do
    result =
      try do
        fun.()
      rescue
        exc -> {:callback_exception, exc.__struct__}
      catch
        _kind, _value -> :callback_aborted
      end

    case result do
      {:ok, raw} ->
        validate_bearer_token(raw, :invalid_callback_token)

      raw when is_binary(raw) ->
        validate_bearer_token(raw, :invalid_callback_token)

      {:error, reason} when is_atom(reason) ->
        {:error, {:token_fetcher_error, reason}}

      {:error, _non_atom} ->
        {:error, {:token_fetcher_error, :redacted}}

      {:callback_exception, exc_mod} ->
        {:error, {:token_fetcher_exception, exc_mod}}

      :callback_aborted ->
        {:error, :token_fetcher_aborted}

      _other ->
        {:error, :invalid_callback_return}
    end
  end

  defp validate_bearer_token(raw, err_reason) when is_binary(raw) do
    trimmed = String.trim(raw)

    if trimmed != "" and not String.contains?(trimmed, ["\r", "\n"]) do
      {:ok, trimmed}
    else
      {:error, err_reason}
    end
  end

  defp validate_bearer_token(_other, err_reason), do: {:error, err_reason}

  defp fetch_optional_header_value(config, key) do
    case Map.get(config, key) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        trimmed = String.trim(value)

        cond do
          trimmed == "" -> {:ok, nil}
          String.contains?(trimmed, ["\r", "\n"]) -> {:error, {:invalid_config, key}}
          true -> {:ok, trimmed}
        end

      _ ->
        {:error, {:invalid_config, key}}
    end
  end

  defp fetch_optional_atom(config, key) do
    case Map.get(config, key) do
      nil -> {:ok, nil}
      value when is_atom(value) -> {:ok, value}
      _ -> {:error, {:invalid_config, key}}
    end
  end

  defp fetch_pos_integer(config, key, default) do
    case Map.get(config, key, default) do
      value when is_integer(value) and value > 0 -> {:ok, value}
      _ -> {:error, {:invalid_config, key}}
    end
  end

  defp fetch_connect_options(config) do
    case Map.get(config, :connect_options, timeout: @default_connect_timeout_ms) do
      opts when is_list(opts) ->
        if Keyword.keyword?(opts),
          do: {:ok, opts},
          else: {:error, {:invalid_config, :connect_options}}

      _ ->
        {:error, {:invalid_config, :connect_options}}
    end
  end
end
