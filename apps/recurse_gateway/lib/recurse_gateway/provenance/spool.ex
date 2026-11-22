defmodule Recurse.Gateway.Provenance.Spool do
  @moduledoc """
  The format recorded content is kept in while it waits on this
  gateway's own disk, and the sealing of the keys it is kept under.

  Recorded content waits on the gateway's disk in two places before the
  content store has it: a temporary file while a large request or
  response is still streaming, and the evidence pipeline's content
  directory until the shipper has stored it. Both are written in this
  format, so nothing recorded is ever on the gateway's disk in the
  clear, and once the key a file was written under is retired, the
  file, and whatever of it is left in freed disk blocks, cannot be read.

  Pure functions only; the keys are held by
  `Recurse.Gateway.Provenance.SpoolKeys`. No function here matches keys
  in its head or hands a key of the wrong size to `:crypto`: either
  would put the key's bytes into a crash report's arguments. Sizes are
  checked first and a wrong one is an error that names no bytes.

  ## File format (`R5ES1`)

      header  = "R5ES1" ‖ epoch_id (16 bytes) ‖ file_id (16 bytes)      37 bytes
      chunk_i = AES-256-GCM(file_key, nonce_i, plain_i, aad_i) ‖ tag (16 bytes)

    * `file_key = HKDF-SHA256(ikm = epoch DEK, salt = file_id,
      info = "r5e spool file v1" ‖ epoch_id)`; `file_id` is random per
      file, so no two files share a key and the counter nonces below never
      repeat under one key, however long an epoch lives.
    * `nonce_i = i (8 bytes, big-endian) ‖ last (1 byte, 0 or 1) ‖ 0 (3 bytes)`
    * `aad_i = header ‖ i (8 bytes) ‖ last (1 byte)`
    * every chunk but the last holds exactly 65 536 plain bytes; the last
      holds 0 to 65 536 and is the only one sealed with `last = 1`. An
      empty file is one empty last chunk.

  Chunks are therefore located by the file's size alone. A chunk moved,
  dropped, repeated, cut short or taken from another file fails its tag;
  a file cut at a chunk boundary ends on a chunk not sealed as last and
  fails; bytes after the last chunk make the true last chunk be read as
  not-last and fail.

  ## Sealed epoch keys

  An epoch's 32-byte key (DEK) is kept on disk only sealed to the spool
  identity, an X25519 key pair whose private half is kept on disk only
  locked by the customer's key service:

      (e, E)  = fresh X25519 key pair
      shared  = X25519(e, identity_pub)          (all-zero refused)
      kek     = HKDF-SHA256(ikm = shared, salt = E ‖ identity_pub,
                            info = "r5e spool epoch v1|" ‖ deployment ‖ "|" ‖ epoch_hex)
      sealed  = AES-256-GCM(kek, nonce = 0^12, dek,
                            aad = "r5e-spool-epoch-v1|" ‖ deployment ‖ "|" ‖ epoch_hex) ‖ tag

  `kek` is used once, so the fixed nonce never repeats under it. Making a
  new epoch needs no key service at all; opening an old one needs the
  identity's private key, and so the key service.
  """

  @magic "R5ES1"
  @header_bytes 37
  @chunk 65_536
  @tag 16
  @framed @chunk + @tag
  @file_info "r5e spool file v1"
  @epoch_info "r5e spool epoch v1|"
  @epoch_aad "r5e-spool-epoch-v1|"

  @type epoch_id :: <<_::128>>
  @type key :: <<_::256>>

  @doc "Bytes in a file's header."
  @spec header_bytes() :: pos_integer()
  def header_bytes, do: @header_bytes

  @doc "Plain bytes in every chunk but the last."
  @spec chunk_bytes() :: pos_integer()
  def chunk_bytes, do: @chunk

  # -- whole files in memory -------------------------------------------------

  @doc """
  Seal `plain` as a whole file. `file_id` is random unless given, which
  only a test vector does.
  """
  @spec seal(binary(), epoch_id(), key(), <<_::128>> | nil) :: iodata()
  def seal(plain, epoch_id, dek, file_id \\ nil) do
    file_id = file_id || :crypto.strong_rand_bytes(16)

    unless sizes_ok?(epoch_id, dek) and is_binary(file_id) and byte_size(file_id) == 16 and
             is_binary(plain),
           do: raise(ArgumentError, "a spool key, epoch id or file id of the wrong size")

    {header, key} = start(epoch_id, dek, file_id)
    {chunks, index, rest} = full_chunks(plain, header, key, 0, [])
    [header, Enum.reverse(chunks), seal_chunk(rest, header, key, index, true)]
  end

  defp full_chunks(<<piece::binary-size(@chunk), rest::binary>>, header, key, index, acc)
       when byte_size(rest) > 0,
       do:
         full_chunks(rest, header, key, index + 1, [
           seal_chunk(piece, header, key, index, false) | acc
         ])

  defp full_chunks(rest, _header, _key, index, acc), do: {acc, index, rest}

  @doc """
  Open a whole sealed file held in memory. For tests and small files;
  shipping reads with `open_reader/3`.
  """
  @spec open(binary(), (epoch_id() -> {:ok, key()} | {:error, term()})) ::
          {:ok, binary()} | {:error, term()}
  def open(<<@magic, epoch_id::binary-16, file_id::binary-16, body::binary>> = whole, key_for) do
    with {:ok, dek} <- key_for.(epoch_id),
         true <- sizes_ok?(epoch_id, dek) || {:error, :bad_key},
         {:ok, count} <- chunk_count(byte_size(body)) do
      header = binary_part(whole, 0, @header_bytes)
      key = file_key(dek, epoch_id, file_id)

      Enum.reduce_while(0..(count - 1)//1, {:ok, []}, fn index, {:ok, acc} ->
        last? = index == count - 1
        length = if last?, do: byte_size(body) - index * @framed, else: @framed

        case open_chunk(binary_part(body, index * @framed, length), header, key, index, last?) do
          {:ok, plain} -> {:cont, {:ok, [acc, plain]}}
          error -> {:halt, error}
        end
      end)
      |> case do
        {:ok, plain} -> {:ok, IO.iodata_to_binary(plain)}
        error -> error
      end
    end
  end

  def open(_other, _key_for), do: {:error, {:staged_content_unreadable, :malformed_header}}

  # -- streaming writes --------------------------------------------------------

  defmodule Writer do
    @moduledoc false
    @derive {Inspect, only: [:path, :index, :size]}
    defstruct [:path, :device, :header, :key, :hash, index: 0, size: 0, buffer: <<>>]

    @type t :: %__MODULE__{}
  end

  @doc """
  Create a sealed file at `path` and write its header. Fails if the file
  exists. The file is readable by its owner only.
  """
  @spec create(Path.t(), epoch_id(), key()) :: {:ok, Writer.t()} | {:error, term()}
  def create(path, epoch_id, dek) do
    with true <- sizes_ok?(epoch_id, dek) || {:error, :bad_key},
         {header, key} = start(epoch_id, dek, :crypto.strong_rand_bytes(16)),
         {:ok, device} <- :file.open(path, [:raw, :binary, :write, :exclusive]),
         :ok <- :file.change_mode(path, 0o600),
         :ok <- :file.write(device, header) do
      {:ok,
       %Writer{
         path: path,
         device: device,
         header: header,
         key: key,
         hash: :crypto.hash_init(:sha256)
       }}
    end
  end

  @doc """
  Add plain bytes. Whole chunks are sealed and written as they fill; at
  most one chunk's worth is held in memory.
  """
  @spec append(Writer.t(), binary()) :: {:ok, Writer.t()} | {:error, term()}
  def append(%Writer{} = w, bytes) when is_binary(bytes) do
    w = %{w | hash: :crypto.hash_update(w.hash, bytes), size: w.size + byte_size(bytes)}
    drain(%{w | buffer: w.buffer <> bytes})
  end

  # A full chunk is written only once more bytes follow it, so the last
  # chunk is always the one left in hand at `finish/1`.
  defp drain(%Writer{buffer: <<piece::binary-size(@chunk), rest::binary>>} = w)
       when byte_size(rest) > 0 do
    case :file.write(w.device, seal_chunk(piece, w.header, w.key, w.index, false)) do
      :ok -> drain(%{w | buffer: rest, index: w.index + 1})
      {:error, reason} -> {:error, reason}
    end
  end

  defp drain(w), do: {:ok, w}

  @doc """
  Seal the last chunk and close the file. Answers the SHA-256 and size
  of the plain bytes written.
  """
  @spec finish(Writer.t()) ::
          {:ok, %{sha256: <<_::256>>, size: non_neg_integer()}} | {:error, term()}
  def finish(%Writer{} = w) do
    result =
      with :ok <- :file.write(w.device, seal_chunk(w.buffer, w.header, w.key, w.index, true)) do
        {:ok, %{sha256: :crypto.hash_final(w.hash), size: w.size}}
      end

    case {result, :file.close(w.device)} do
      {{:ok, _} = ok, :ok} -> ok
      {{:ok, _}, {:error, reason}} -> {:error, reason}
      {error, _} -> error
    end
  end

  @doc "Close and remove a file that will not be finished."
  @spec abort(Writer.t()) :: :ok
  def abort(%Writer{device: device, path: path}) do
    _ = :file.close(device)
    _ = File.rm(path)
    :ok
  end

  # -- streaming reads ---------------------------------------------------------

  @doc """
  The epoch a file was written under, `:plain` for a file not in this
  format, or an error when it cannot be read.
  """
  @spec epoch_of(Path.t()) :: {:ok, epoch_id()} | :plain | {:error, term()}
  def epoch_of(path) do
    with {:ok, device} <- :file.open(path, [:raw, :binary, :read]) do
      try do
        case :file.read(device, @header_bytes) do
          {:ok, <<@magic, epoch_id::binary-16, _file_id::binary-16>>} ->
            {:ok, epoch_id}

          {:ok, <<@magic, _::binary>>} ->
            {:error, {:staged_content_unreadable, :malformed_header}}

          {:ok, _other} ->
            :plain

          :eof ->
            :plain

          {:error, reason} ->
            {:error, reason}
        end
      after
        :file.close(device)
      end
    end
  end

  @doc """
  Open a sealed file for reading as a content-store reader (see
  `Recurse.Provenance.Store`): `{:ok, source, read, close}`.

  `read` answers one chunk's plain bytes at a time and `:eof` only after
  the last chunk, when the SHA-256 of everything it answered equals
  `expected`. Any failure is `{:staged_content_unreadable, why}`, apart
  from the key lookup's own errors, which are passed on as they are.
  """
  @spec open_reader(Path.t(), <<_::256>>, (epoch_id() -> {:ok, key()} | {:error, term()})) ::
          {:ok, term(), (term() -> {:ok, binary(), term()} | :eof | {:error, term()}), (-> :ok)}
          | {:error, term()}
  def open_reader(path, <<_::256>> = expected, key_for),
    do: open_stream(path, expected, key_for)

  @doc """
  Stream a sealed file chunk by chunk and answer the SHA-256 of its plain
  bytes without holding more than one chunk in memory.
  """
  @spec digest_file(Path.t(), (epoch_id() -> {:ok, key()} | {:error, term()})) ::
          {:ok, <<_::256>>} | {:error, term()}
  def digest_file(path, key_for) do
    with {:ok, source, _read, close} <- open_stream(path, :none, key_for) do
      try do
        digest_chunks(source)
      after
        close.()
      end
    end
  end

  defp open_stream(path, expected, key_for) do
    with {:ok, %{size: size}} <- File.stat(path),
         {:ok, count} <- chunk_count(size - @header_bytes),
         {:ok, device} <- :file.open(path, [:raw, :binary, :read, :read_ahead]) do
      with {:ok, <<@magic, epoch_id::binary-16, file_id::binary-16>> = header} <-
             read_exact(device, @header_bytes),
           {:ok, dek} <- key_for.(epoch_id),
           true <- sizes_ok?(epoch_id, dek) || {:error, :bad_key} do
        source = %{
          device: device,
          header: header,
          key: file_key(dek, epoch_id, file_id),
          index: 0,
          count: count,
          last_length: size - @header_bytes - (count - 1) * @framed,
          hash: :crypto.hash_init(:sha256),
          expected: expected
        }

        {:ok, source, &read/1, fn -> :file.close(device) end}
      else
        {:ok, _not_a_header} ->
          :file.close(device)
          {:error, {:staged_content_unreadable, :malformed_header}}

        error ->
          :file.close(device)
          error
      end
    end
  end

  defp digest_chunks(%{index: index, count: count, hash: hash}) when index == count,
    do: {:ok, :crypto.hash_final(hash)}

  defp digest_chunks(s) do
    with {:ok, _plain, next} <- read(s), do: digest_chunks(next)
  end

  defp read(%{index: index, count: count} = s) when index == count do
    if :crypto.hash_final(s.hash) == s.expected,
      do: :eof,
      else: {:error, {:staged_content_unreadable, :does_not_match_ref}}
  end

  defp read(%{index: index, count: count} = s) do
    last? = index == count - 1
    length = if last?, do: s.last_length, else: @framed

    with {:ok, framed} <- read_exact(s.device, length),
         {:ok, plain} <- open_chunk(framed, s.header, s.key, index, last?) do
      {:ok, plain, %{s | index: index + 1, hash: :crypto.hash_update(s.hash, plain)}}
    end
  end

  defp read_exact(device, length) do
    case :file.read(device, length) do
      {:ok, bytes} when byte_size(bytes) == length -> {:ok, bytes}
      {:ok, _short} -> {:error, {:staged_content_unreadable, :truncated}}
      :eof -> {:error, {:staged_content_unreadable, :truncated}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  How many plain bytes a sealed file of `file_size` bytes holds, or nil
  when no well-formed file has that size.
  """
  @spec plain_size(non_neg_integer()) :: non_neg_integer() | nil
  def plain_size(file_size) do
    case chunk_count(file_size - @header_bytes) do
      {:ok, count} -> file_size - @header_bytes - count * @tag
      _ -> nil
    end
  end

  # Every chunk but the last is exactly `@framed` bytes and the last is at
  # least a tag, so the count follows from the size.
  defp chunk_count(body) when is_integer(body) and body >= @tag,
    do: {:ok, div(body - @tag, @framed) + 1}

  defp chunk_count(_body), do: {:error, {:staged_content_unreadable, :truncated}}

  # -- chunks ------------------------------------------------------------------

  defp sizes_ok?(epoch_id, dek),
    do:
      is_binary(epoch_id) and byte_size(epoch_id) == 16 and is_binary(dek) and
        byte_size(dek) == 32

  defp start(epoch_id, dek, file_id) do
    header = <<@magic, epoch_id::binary, file_id::binary>>
    {header, file_key(dek, epoch_id, file_id)}
  end

  @doc false
  # Exposed for test vectors.
  def file_key(dek, epoch_id, file_id), do: hkdf(dek, file_id, [@file_info, epoch_id])

  defp seal_chunk(plain, header, key, index, last?) do
    flag = if last?, do: 1, else: 0

    {text, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        key,
        nonce(index, flag),
        plain,
        [header, <<index::64, flag::8>>],
        @tag,
        true
      )

    [text, tag]
  end

  defp open_chunk(framed, header, key, index, last?) when byte_size(framed) >= @tag do
    flag = if last?, do: 1, else: 0
    text_size = byte_size(framed) - @tag
    <<text::binary-size(text_size), tag::binary-size(@tag)>> = framed

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           nonce(index, flag),
           text,
           [header, <<index::64, flag::8>>],
           tag,
           false
         ) do
      plain when is_binary(plain) -> {:ok, plain}
      :error -> {:error, {:staged_content_unreadable, :tag_mismatch}}
    end
  end

  defp open_chunk(_short, _header, _key, _index, _last?),
    do: {:error, {:staged_content_unreadable, :truncated}}

  defp nonce(index, flag), do: <<index::64, flag::8, 0::24>>

  # -- sealed epoch keys ---------------------------------------------------------

  @doc "A fresh X25519 key pair: `{public, private}`."
  @spec identity_keypair() :: {<<_::256>>, <<_::256>>}
  def identity_keypair do
    {public, private} = :crypto.generate_key(:ecdh, :x25519)
    {public, private}
  end

  @doc "The public half of an X25519 private key."
  @spec public_of(<<_::256>>) :: <<_::256>>
  def public_of(private) when is_binary(private) and byte_size(private) == 32 do
    {public, _} = :crypto.generate_key(:ecdh, :x25519, private)
    public
  end

  @doc """
  Seal an epoch's key to the spool identity. `ephemeral` is a fresh key
  pair unless given, which only a test vector does.
  """
  @spec seal_epoch(key(), epoch_id(), String.t(), <<_::256>>, {binary(), binary()} | nil) ::
          {:ok, %{ephemeral: <<_::256>>, sealed: binary()}} | {:error, :weak_identity_key}
  def seal_epoch(dek, epoch_id, deployment, identity_pub, ephemeral \\ nil) do
    {e_pub, e_priv} = ephemeral || :crypto.generate_key(:ecdh, :x25519)

    with true <- (sizes_ok?(epoch_id, dek) and is_binary(deployment)) || {:error, :bad_key},
         true <- all_32?([identity_pub, e_pub, e_priv]) || {:error, :weak_identity_key},
         {:ok, kek} <- epoch_kek(e_priv, e_pub, identity_pub, deployment, epoch_id) do
      {text, tag} =
        :crypto.crypto_one_time_aead(
          :aes_256_gcm,
          kek,
          <<0::96>>,
          dek,
          epoch_aad(deployment, epoch_id),
          @tag,
          true
        )

      {:ok, %{ephemeral: e_pub, sealed: text <> tag}}
    end
  end

  @doc "Open an epoch key sealed by `seal_epoch/5`."
  @spec open_epoch(binary(), binary(), epoch_id(), String.t(), <<_::256>>) ::
          {:ok, key()} | {:error, :not_decryptable | :weak_identity_key}
  def open_epoch(e_pub, sealed, epoch_id, deployment, identity_priv) do
    with true <- (all_32?([e_pub, identity_priv]) and is_binary(deployment)) || :bad,
         true <- (is_binary(epoch_id) and byte_size(epoch_id) == 16) || :bad,
         <<text::binary-32, tag::binary-16>> <- sealed,
         {:ok, kek} <-
           epoch_kek(identity_priv, e_pub, public_of(identity_priv), deployment, epoch_id) do
      case :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             kek,
             <<0::96>>,
             text,
             epoch_aad(deployment, epoch_id),
             tag,
             false
           ) do
        <<_::256>> = dek -> {:ok, dek}
        _ -> {:error, :not_decryptable}
      end
    else
      {:error, :weak_identity_key} = error -> error
      _ -> {:error, :not_decryptable}
    end
  end

  defp all_32?(keys), do: Enum.all?(keys, &(is_binary(&1) and byte_size(&1) == 32))

  @doc false
  # The key-encryption key of a sealed epoch, for test vectors only.
  def kek_for_vector(e_priv, e_pub, identity_pub, deployment, epoch_id),
    do: epoch_kek(e_priv, e_pub, identity_pub, deployment, epoch_id)

  # Either side's private key with the other's public key gives the same
  # shared secret. An all-zero result means a low-order public key was
  # supplied, and is refused.
  defp epoch_kek(private, e_pub, identity_pub, deployment, epoch_id) do
    peer = if public_of(private) == identity_pub, do: e_pub, else: identity_pub
    shared = :crypto.compute_key(:ecdh, peer, private, :x25519)

    if shared == <<0::256>> do
      {:error, :weak_identity_key}
    else
      {:ok,
       hkdf(shared, e_pub <> identity_pub, [
         @epoch_info,
         deployment,
         "|",
         Base.encode16(epoch_id, case: :lower)
       ])}
    end
  rescue
    # Sizes are checked before this is reached; what is left is the
    # library refusing a public key that is not a usable point.
    ErlangError -> {:error, :weak_identity_key}
  end

  defp epoch_aad(deployment, epoch_id),
    do: [@epoch_aad, deployment, "|", Base.encode16(epoch_id, case: :lower)]

  # HKDF-SHA256 (RFC 5869), one 32-byte output block.
  defp hkdf(ikm, salt, info) do
    prk = :crypto.mac(:hmac, :sha256, salt, ikm)
    :crypto.mac(:hmac, :sha256, prk, [info, <<1>>])
  end
end
