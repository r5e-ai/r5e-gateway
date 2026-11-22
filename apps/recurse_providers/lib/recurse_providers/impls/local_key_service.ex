defmodule Recurse.Providers.Impls.LocalKeyService do
  @moduledoc """
  A key service that keeps the customer's key in a local file.

  For a single machine, a trial, or a site with no key service to call.
  The file holds 32 random bytes, base64-encoded, and must be readable
  only by the gateway's user. Whoever can read that file can read all
  recorded content, so this gives none of the separation a real key
  service gives; it exists so that content is never stored unencrypted
  even on the smallest installation, and so that erasing a session's key
  works the same way everywhere.
  """

  @behaviour Recurse.Providers.KeyService

  @enforce_keys [:key, :name]
  defstruct [:key, :name]

  @type t :: %__MODULE__{
          key: <<_::256>>,
          name: String.t()
        }

  defimpl Inspect do
    import Inspect.Algebra

    @spec inspect(Recurse.Providers.Impls.LocalKeyService.t(), Inspect.Opts.t()) ::
            Inspect.Algebra.t()
    def inspect(state, opts) do
      concat([
        "#LocalKeyService<name: ",
        to_doc(state.name, opts),
        ", key: \"[REDACTED]\">"
      ])
    end
  end

  @doc "Open the key file. Refuses a file that is not 32 bytes of base64."
  @spec open(Path.t()) :: {:ok, t()} | {:error, :unreadable_content_key}
  def open(path) do
    with {:ok, text} <- File.read(path),
         {:ok, <<_::256>> = key} <- Base.decode64(String.trim(text)) do
      {:ok, %__MODULE__{key: key, name: "local file " <> Path.basename(path)}}
    else
      _ -> {:error, :unreadable_content_key}
    end
  end

  @doc """
  Write a new key file, readable only by its owner. Fails if the file
  exists. The key is written to a private temporary file first, so the
  key file is never present with wider permissions or half written.
  """
  @spec generate(Path.t()) :: :ok | {:error, term()}
  def generate(path) do
    temporary = path <> ".new-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    with false <- File.exists?(path),
         {:ok, device} <- :file.open(temporary, [:raw, :write, :exclusive]) do
      try do
        :ok = :file.change_mode(temporary, 0o600)
        :ok = :file.write(device, Base.encode64(:crypto.strong_rand_bytes(32)))
        :ok = :file.close(device)
        # A hard link fails if the name is taken, which a rename would not.
        :file.make_link(temporary, path)
      after
        File.rm(temporary)
      end
    else
      true -> {:error, :eexist}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  @spec wrap(map(), <<_::256>>, String.t()) :: {:ok, binary()}
  def wrap(%{key: master}, <<_::256>> = key, context) when is_binary(context) do
    nonce = :crypto.strong_rand_bytes(12)

    {text, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        for_context(master, context),
        nonce,
        key,
        context,
        16,
        true
      )

    {:ok, nonce <> text <> tag}
  end

  @impl true
  @spec unwrap(map(), binary(), String.t()) :: {:ok, <<_::256>>} | {:error, :not_unwrappable}
  def unwrap(%{key: master}, <<nonce::binary-12, text::binary-32, tag::binary-16>>, context)
      when is_binary(context) do
    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           for_context(master, context),
           nonce,
           text,
           context,
           tag,
           false
         ) do
      <<_::256>> = key -> {:ok, key}
      _ -> {:error, :not_unwrappable}
    end
  end

  def unwrap(_state, _wrapped, _context), do: {:error, :not_unwrappable}

  # Each context is locked under a key of its own derived from the file's
  # key, so the file's key itself encrypts nothing and the number of
  # contexts is not limited by how many random nonces one key can bear.
  defp for_context(master, context),
    do: :crypto.mac(:hmac, :sha256, master, ["r5e local key service v1 ", context])

  @impl true
  @spec describe(map()) :: String.t()
  def describe(%{name: name}), do: name
end
