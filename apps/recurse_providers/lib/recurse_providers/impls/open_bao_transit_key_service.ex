defmodule Recurse.Providers.Impls.OpenBaoTransitKeyService do
  @moduledoc """
  `Recurse.Providers.KeyService` backed by OpenBao or HashiCorp Vault Transit
  (`/v1/:mount/encrypt/:key_name` and `/v1/:mount/decrypt/:key_name`).

  Per-session 32-byte content encryption keys are wrapped under a derived
  `aes256-gcm96` Transit master key (`derived: true`) with `context` bound as
  base64 key-derivation/AAD context. The master key never leaves OpenBao/Vault,
  and every content read invokes `decrypt`, allowing the customer's KMS audit
  device to log every read and retire historical backups immediately via key
  rotation + `min_decryption_version`.

  ## Error semantics

    * HTTP `400` on `decrypt` (wrong `context`, corrupted ciphertext, or a key
      version below `min_decryption_version`) returns
      `{:error, :not_unwrappable}`.
    * Network failures, timeouts, TLS errors, auth errors (`401`/`403`),
      missing mounts (`404`), and server/seal outages (`5xx`) return
      `{:error, {:key_service_unavailable, reason}}` so a transient KMS outage
      is never misreported as a destroyed or corrupt session key.
  """

  @behaviour Recurse.Providers.KeyService

  @default_mount "transit"
  @default_receive_timeout_ms 5_000
  @default_connect_timeout_ms 2_000

  @enforce_keys [:url, :mount, :key_name, :token, :receive_timeout_ms, :connect_options]
  defstruct [
    :url,
    :mount,
    :key_name,
    :token,
    :namespace,
    :finch_pool,
    :receive_timeout_ms,
    :connect_options
  ]

  @type t :: %__MODULE__{
          url: String.t(),
          mount: String.t(),
          key_name: String.t(),
          token: String.t(),
          namespace: String.t() | nil,
          finch_pool: atom() | nil,
          receive_timeout_ms: pos_integer(),
          connect_options: keyword()
        }

  defimpl Inspect do
    import Inspect.Algebra

    @spec inspect(Recurse.Providers.Impls.OpenBaoTransitKeyService.t(), Inspect.Opts.t()) ::
            Inspect.Algebra.t()
    def inspect(state, opts) do
      concat([
        "#OpenBaoTransitKeyService<url: ",
        to_doc(state.url, opts),
        ", mount: ",
        to_doc(state.mount, opts),
        ", key: ",
        to_doc(state.key_name, opts),
        ", token: \"[REDACTED]\">"
      ])
    end
  end

  @doc """
  Construct a validated `OpenBaoTransitKeyService` state from a map or keyword list.

  ## Options

    * `:url` (required) — base OpenBao/Vault address, e.g. `"http://127.0.0.1:8200"`.
    * `:key_name` (or `:key`, required) — Transit key name, e.g. `"r5e-content-master"`.
    * `:token` or `:token_path` (required) — Vault/OpenBao client token or path
      to a `0600` token file on disk.
    * `:mount` — Transit secrets engine mount path (default `"transit"`).
    * `:namespace` — optional OpenBao/Vault namespace header value.
    * `:finch_pool` — optional named Finch pool atom; defaults to `Req`'s pool.
    * `:receive_timeout_ms` — per-call HTTP receive timeout (default `5_000`).
    * `:connect_options` — keyword list passed to `Req` transport connect options
      (default `[timeout: 2_000]`).
  """
  @spec new(keyword() | map()) :: {:ok, t()} | {:error, term()}
  def new(opts) when is_list(opts), do: opts |> Map.new() |> new()

  def new(config) when is_map(config) do
    with {:ok, url} <- fetch_url(config),
         {:ok, key_name} <- fetch_key_name(config),
         {:ok, mount} <- fetch_mount(config),
         {:ok, token} <- resolve_token(config),
         {:ok, namespace} <- fetch_optional_string(config, :namespace),
         {:ok, finch_pool} <- fetch_optional_atom(config, :finch_pool),
         {:ok, receive_timeout_ms} <-
           fetch_pos_integer(config, :receive_timeout_ms, @default_receive_timeout_ms),
         {:ok, connect_options} <- fetch_connect_options(config) do
      {:ok,
       %__MODULE__{
         url: url,
         mount: mount,
         key_name: key_name,
         token: token,
         namespace: namespace,
         finch_pool: finch_pool,
         receive_timeout_ms: receive_timeout_ms,
         connect_options: connect_options
       }}
    end
  end

  @doc "Alias for `new/1`."
  @spec open(keyword() | map()) :: {:ok, t()} | {:error, term()}
  def open(opts), do: new(opts)

  @impl true
  @spec wrap(t(), <<_::256>>, String.t()) ::
          {:ok, binary()} | {:error, {:key_service_unavailable, term()}}
  def wrap(%__MODULE__{} = state, <<_::256>> = key, context) when is_binary(context) do
    payload = %{
      "plaintext" => Base.encode64(key),
      "context" => Base.encode64(context)
    }

    case post_json(state, transit_path(state, ["encrypt", state.key_name]), payload) do
      {:ok, status, %{"data" => %{"ciphertext" => ciphertext}}}
      when status in 200..299 and is_binary(ciphertext) and byte_size(ciphertext) > 0 ->
        {:ok, ciphertext}

      {:ok, status, body} ->
        {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body)}}}

      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  @impl true
  @spec unwrap(t(), binary(), String.t()) ::
          {:ok, <<_::256>>}
          | {:error, :not_unwrappable}
          | {:error, {:key_service_unavailable, term()}}
  def unwrap(%__MODULE__{} = state, wrapped, context)
      when is_binary(wrapped) and is_binary(context) do
    if byte_size(wrapped) == 0 or not String.valid?(wrapped) do
      {:error, :not_unwrappable}
    else
      do_unwrap(state, wrapped, context)
    end
  end

  def unwrap(%__MODULE__{}, _wrapped, _context), do: {:error, :not_unwrappable}

  @impl true
  @spec describe(t()) :: String.t()
  def describe(%__MODULE__{url: url, mount: mount, key_name: key_name}) do
    "openbao transit #{url}/v1/#{mount}/keys/#{key_name}"
  end

  @doc """
  Provision or verify the Transit key (`type: "aes256-gcm96"`, `derived: true`).

  Intended for bootstrap ceremonies and isolated integration tests.
  """
  @spec ensure_key(t()) :: :ok | {:error, {:key_service_unavailable, term()}}
  def ensure_key(%__MODULE__{} = state) do
    payload = %{"type" => "aes256-gcm96", "derived" => true}

    case post_json(state, transit_path(state, ["keys", state.key_name]), payload) do
      {:ok, status, _body} when status in 200..299 ->
        :ok

      {:ok, status, body} ->
        {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body)}}}

      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  @doc """
  Rotate the Transit key to a new version (`POST /v1/:mount/keys/:key_name/rotate`).
  """
  @spec rotate(t()) :: :ok | {:error, {:key_service_unavailable, term()}}
  def rotate(%__MODULE__{} = state) do
    case post_json(state, transit_path(state, ["keys", state.key_name, "rotate"]), %{}) do
      {:ok, status, _body} when status in 200..299 ->
        :ok

      {:ok, status, body} ->
        {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body)}}}

      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  @doc """
  Update `min_decryption_version` on the Transit key
  (`POST /v1/:mount/keys/:key_name/config`).
  """
  @spec set_min_decryption_version(t(), pos_integer()) ::
          :ok | {:error, {:key_service_unavailable, term()}}
  def set_min_decryption_version(%__MODULE__{} = state, version)
      when is_integer(version) and version >= 1 do
    payload = %{"min_decryption_version" => version}

    case post_json(state, transit_path(state, ["keys", state.key_name, "config"]), payload) do
      {:ok, status, _body} when status in 200..299 ->
        :ok

      {:ok, status, body} ->
        {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body)}}}

      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  defp do_unwrap(state, wrapped, context) do
    payload = %{
      "ciphertext" => wrapped,
      "context" => Base.encode64(context)
    }

    case post_json(state, transit_path(state, ["decrypt", state.key_name]), payload) do
      {:ok, status, %{"data" => %{"plaintext" => plaintext_b64}}}
      when status in 200..299 and is_binary(plaintext_b64) ->
        case Base.decode64(plaintext_b64) do
          {:ok, <<_::256>> = key} -> {:ok, key}
          _ -> {:error, :not_unwrappable}
        end

      {:ok, 400, _body} ->
        {:error, :not_unwrappable}

      {:ok, status, body} ->
        {:error, {:key_service_unavailable, {:http_status, status, sanitize_body(body)}}}

      {:error, reason} ->
        {:error, {:key_service_unavailable, reason}}
    end
  end

  defp post_json(state, path, payload) do
    req_opts =
      maybe_put_finch(
        [
          url: state.url <> path,
          json: payload,
          headers: request_headers(state),
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
        {:error, reason}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_put_finch(opts, nil), do: opts
  defp maybe_put_finch(opts, pool) when is_atom(pool), do: Keyword.put(opts, :finch, pool)

  defp request_headers(%__MODULE__{token: token, namespace: nil}) do
    [{"x-vault-token", token}]
  end

  defp request_headers(%__MODULE__{token: token, namespace: namespace}) do
    [{"x-vault-token", token}, {"x-vault-namespace", namespace}]
  end

  defp transit_path(%__MODULE__{mount: mount}, segments) do
    encoded_segments =
      Enum.map_join(segments, "/", fn segment ->
        URI.encode(segment, &URI.char_unreserved?/1)
      end)

    "/v1/#{mount}/#{encoded_segments}"
  end

  defp sanitize_body(%{"errors" => errors}) when is_list(errors), do: %{"errors" => errors}
  defp sanitize_body(body) when is_binary(body), do: String.slice(body, 0, 256)
  defp sanitize_body(_), do: :unexpected_response_body

  defp fetch_url(config) do
    raw = Map.get(config, :url) || Map.get(config, :base_url)

    with true <- is_binary(raw) and byte_size(String.trim(raw)) > 0,
         trimmed = String.trim_trailing(String.trim(raw), "/"),
         %URI{scheme: scheme, host: host}
         when scheme in ["http", "https"] and is_binary(host) and host != "" <-
           URI.parse(trimmed) do
      {:ok, trimmed}
    else
      _ -> {:error, {:invalid_config, :url}}
    end
  end

  defp fetch_key_name(config) do
    case Map.get(config, :key_name) || Map.get(config, :key) do
      value when is_binary(value) ->
        trimmed = String.trim(value)
        if trimmed != "", do: {:ok, trimmed}, else: {:error, {:invalid_config, :key_name}}

      _ ->
        {:error, {:missing_config, :key_name}}
    end
  end

  defp fetch_mount(config) do
    case Map.get(config, :mount, @default_mount) do
      value when is_binary(value) ->
        trimmed = value |> String.trim() |> String.trim("/")
        if trimmed != "", do: {:ok, trimmed}, else: {:error, {:invalid_config, :mount}}

      _ ->
        {:error, {:invalid_config, :mount}}
    end
  end

  defp resolve_token(%{token: token}) when is_binary(token) do
    trimmed = String.trim(token)
    if trimmed != "", do: {:ok, trimmed}, else: {:error, {:invalid_config, :token}}
  end

  defp resolve_token(%{token_path: path}) when is_binary(path) do
    case File.read(path) do
      {:ok, raw} ->
        trimmed = String.trim(raw)
        if trimmed != "", do: {:ok, trimmed}, else: {:error, {:unreadable_token_file, :empty}}

      {:error, reason} ->
        {:error, {:unreadable_token_file, reason}}
    end
  end

  defp resolve_token(_), do: {:error, {:missing_config, :token}}

  defp fetch_optional_string(config, key) do
    case Map.get(config, key) do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        trimmed = String.trim(value)
        {:ok, if(trimmed == "", do: nil, else: trimmed)}

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
