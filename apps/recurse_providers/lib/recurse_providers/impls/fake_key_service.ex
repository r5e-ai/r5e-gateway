defmodule Recurse.Providers.Impls.FakeKeyService do
  @moduledoc """
  In-process stateful fake KMS implementing `Recurse.Providers.KeyService`.

  Designed for fast, async-safe gateway and store tests that need real
  context-bound AES-256-GCM key wrapping, versioned key rotation
  (`v1`, `v2`, ...), `min_decryption_version` kill-switch enforcement,
  availability simulation, and exact KMS read/write audit assertions with
  zero external dependencies.

  Raw version keys stay inside the backing `Agent` process and never sit in
  the handle struct, so `inspect/1` or crash logs on caller state cannot
  leak key material.
  """

  @behaviour Recurse.Providers.KeyService

  @enforce_keys [:agent, :key_name]
  defstruct [:agent, :key_name]

  @type key_version :: pos_integer() | :unknown
  @type audit_outcome :: :ok | {:error, term()}
  @type audit_entry :: {:wrap | :unwrap, key_version(), String.t(), audit_outcome()}

  @type t :: %__MODULE__{
          agent: pid(),
          key_name: String.t()
        }

  defimpl Inspect do
    import Inspect.Algebra

    @spec inspect(Recurse.Providers.Impls.FakeKeyService.t(), Inspect.Opts.t()) ::
            Inspect.Algebra.t()
    def inspect(state, opts) do
      concat([
        "#FakeKeyService<key: ",
        to_doc(state.key_name, opts),
        ", agent: ",
        to_doc(state.agent, opts),
        ">"
      ])
    end
  end

  @doc """
  Start an isolated `FakeKeyService` instance initialized at key version `1`.

  ## Options

    * `:key_name` — logical key identifier returned in `describe/1`
      (default `"r5e-content-master"`).
    * `:initial_key` — optional 32-byte binary for deterministic test setups;
      defaults to 32 random bytes.
  """
  @spec start_link(keyword()) :: {:ok, t()} | {:error, term()}
  def start_link(opts \\ []) when is_list(opts) do
    key_name = Keyword.get(opts, :key_name, "r5e-content-master")
    initial_key = Keyword.get_lazy(opts, :initial_key, fn -> :crypto.strong_rand_bytes(32) end)

    with :ok <- validate_key_name(key_name),
         :ok <- validate_key_bytes(initial_key),
         {:ok, agent} <-
           Agent.start_link(fn ->
             %{
               keys: %{1 => initial_key},
               latest_version: 1,
               min_decryption_version: 1,
               available?: true,
               audit_log: []
             }
           end) do
      {:ok, %__MODULE__{agent: agent, key_name: key_name}}
    end
  end

  @doc "Stop the backing `Agent` process."
  @spec stop(t()) :: :ok
  def stop(%__MODULE__{agent: agent}) do
    if Process.alive?(agent) do
      Agent.stop(agent)
    end

    :ok
  end

  @doc """
  Rotate to a fresh 32-byte key version (`v1 -> v2`, etc.).

  Existing ciphertexts remain decryptable until retired via
  `set_min_decryption_version/2`.
  """
  @spec rotate(t()) :: :ok
  def rotate(%__MODULE__{agent: agent}) do
    fresh_key = :crypto.strong_rand_bytes(32)

    Agent.update(agent, fn data ->
      next_version = data.latest_version + 1

      %{
        data
        | keys: Map.put(data.keys, next_version, fresh_key),
          latest_version: next_version
      }
    end)
  end

  @doc """
  Set the minimum key version allowed for `unwrap/3`.

  Any ciphertext wrapped under an older version fails with
  `{:error, :not_unwrappable}`, matching OpenBao/Vault Transit's backup
  kill-switch (`min_decryption_version`).
  """
  @spec set_min_decryption_version(t(), pos_integer()) ::
          :ok | {:error, :invalid_min_decryption_version}
  def set_min_decryption_version(%__MODULE__{agent: agent}, version)
      when is_integer(version) and version >= 1 do
    Agent.get_and_update(agent, fn data ->
      if version <= data.latest_version do
        {:ok, %{data | min_decryption_version: version}}
      else
        {{:error, :invalid_min_decryption_version}, data}
      end
    end)
  end

  @doc "Toggle simulated KMS availability for transient-outage tests."
  @spec set_available(t(), boolean()) :: :ok
  def set_available(%__MODULE__{agent: agent}, available?) when is_boolean(available?) do
    Agent.update(agent, &%{&1 | available?: available?})
  end

  @doc "Return the current active wrapping key version (`1`, `2`, ...)."
  @spec latest_version(t()) :: pos_integer()
  def latest_version(%__MODULE__{agent: agent}) do
    Agent.get(agent, & &1.latest_version)
  end

  @doc "Return the configured `min_decryption_version`."
  @spec min_decryption_version(t()) :: pos_integer()
  def min_decryption_version(%__MODULE__{agent: agent}) do
    Agent.get(agent, & &1.min_decryption_version)
  end

  @doc """
  Return recorded KMS operations in chronological order.

  Each entry has the shape `{:wrap | :unwrap, key_version, context, outcome}`.
  """
  @spec audit_log(t()) :: [audit_entry()]
  def audit_log(%__MODULE__{agent: agent}) do
    Agent.get(agent, fn data -> Enum.reverse(data.audit_log) end)
  end

  @doc "Clear all recorded entries in `audit_log/1`."
  @spec clear_audit_log(t()) :: :ok
  def clear_audit_log(%__MODULE__{agent: agent}) do
    Agent.update(agent, &%{&1 | audit_log: []})
  end

  @impl true
  @spec wrap(t(), <<_::256>>, String.t()) :: {:ok, binary()} | {:error, term()}
  def wrap(%__MODULE__{agent: agent}, <<_::256>> = key, context) when is_binary(context) do
    nonce = :crypto.strong_rand_bytes(12)

    Agent.get_and_update(agent, fn data ->
      if data.available? do
        version = data.latest_version
        master = Map.fetch!(data.keys, version)

        {text, tag} =
          :crypto.crypto_one_time_aead(
            :aes_256_gcm,
            derive_context_key(master, version, context),
            nonce,
            key,
            context,
            16,
            true
          )

        wrapped = "fakekms:v#{version}:" <> Base.encode64(nonce <> text <> tag)
        entry = {:wrap, version, context, :ok}
        {{:ok, wrapped}, %{data | audit_log: [entry | data.audit_log]}}
      else
        reason = {:key_service_unavailable, :simulated_outage}
        entry = {:wrap, data.latest_version, context, {:error, reason}}
        {{:error, reason}, %{data | audit_log: [entry | data.audit_log]}}
      end
    end)
  end

  @impl true
  @spec unwrap(t(), binary(), String.t()) :: {:ok, <<_::256>>} | {:error, term()}
  def unwrap(%__MODULE__{agent: agent}, wrapped, context)
      when is_binary(wrapped) and is_binary(context) do
    Agent.get_and_update(agent, fn data ->
      do_unwrap(data, wrapped, context)
    end)
  end

  def unwrap(%__MODULE__{}, _wrapped, _context), do: {:error, :not_unwrappable}

  @impl true
  @spec describe(t()) :: String.t()
  def describe(%__MODULE__{key_name: key_name}), do: "fake kms " <> key_name

  defp do_unwrap(%{available?: false} = data, wrapped, context) do
    version =
      case parse_envelope(wrapped) do
        {:ok, v, _nonce, _text, _tag} -> v
        :error -> :unknown
      end

    reason = {:key_service_unavailable, :simulated_outage}
    entry = {:unwrap, version, context, {:error, reason}}
    {{:error, reason}, %{data | audit_log: [entry | data.audit_log]}}
  end

  defp do_unwrap(data, wrapped, context) do
    case parse_envelope(wrapped) do
      {:ok, version, nonce, text, tag} ->
        unwrap_versioned(data, version, nonce, text, tag, context)

      :error ->
        fail_unwrap(data, :unknown, context)
    end
  end

  defp unwrap_versioned(data, version, _nonce, _text, _tag, context)
       when version < data.min_decryption_version do
    fail_unwrap(data, version, context)
  end

  defp unwrap_versioned(data, version, nonce, text, tag, context) do
    with {:ok, master} <- Map.fetch(data.keys, version),
         <<_::256>> = key <-
           :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             derive_context_key(master, version, context),
             nonce,
             text,
             context,
             tag,
             false
           ) do
      entry = {:unwrap, version, context, :ok}
      {{:ok, key}, %{data | audit_log: [entry | data.audit_log]}}
    else
      _ -> fail_unwrap(data, version, context)
    end
  end

  defp fail_unwrap(data, version, context) do
    outcome = {:error, :not_unwrappable}
    entry = {:unwrap, version, context, outcome}
    {outcome, %{data | audit_log: [entry | data.audit_log]}}
  end

  defp parse_envelope("fakekms:v" <> rest) do
    with [version_str, payload_b64] <- String.split(rest, ":", parts: 2),
         {version, ""} when version >= 1 <- Integer.parse(version_str),
         {:ok, <<nonce::binary-12, text::binary-32, tag::binary-16>>} <-
           Base.decode64(payload_b64) do
      {:ok, version, nonce, text, tag}
    else
      _ -> :error
    end
  end

  defp parse_envelope(_), do: :error

  defp derive_context_key(master, version, context) do
    :crypto.mac(
      :hmac,
      :sha256,
      master,
      ["r5e fake key service v1 ", Integer.to_string(version), ":", context]
    )
  end

  defp validate_key_name(name) when is_binary(name) and byte_size(name) > 0, do: :ok
  defp validate_key_name(_), do: {:error, {:invalid_config, :key_name}}

  defp validate_key_bytes(<<_::256>>), do: :ok
  defp validate_key_bytes(_), do: {:error, {:invalid_config, :initial_key}}
end
