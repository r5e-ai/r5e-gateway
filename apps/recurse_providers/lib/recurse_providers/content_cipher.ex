defmodule Recurse.Providers.ContentCipher do
  @moduledoc """
  Encrypts recorded content before it is stored, and decrypts it on read.

  Content (prompts, responses, tool arguments) is the sensitive part of
  the record. Each stored piece of content is encrypted once, under a
  random key of its own. That key is then locked separately for every
  scope (in practice every session) that refers to the content, under
  that scope's key. Identical content in many sessions is stored once.
  Destroying a scope's key removes that scope's way in; when no scope
  with a living key refers to a piece of content, nothing can open it,
  wherever copies of the stored bytes are.

  The working key is derived from the content's key and its reference,
  so the counter below never repeats under one key. Content is processed in
  fixed-size chunks, so a large body is never held in memory whole
  while it is being stored (reading it back does hold it whole). Every
  chunk is bound to its position, to whether it is the last, and to the
  content's reference, so chunks cannot be reordered, dropped from the
  end, or moved to another piece of content without the read failing.

  Content is compressed before it is encrypted, because recorded
  content is mostly text and encrypted bytes do not compress. The
  reference a record carries is the hash of the original bytes, so what
  comes back out is checked against it like any other content.

  Format: the five bytes `R5EC2`, then the zstd-compressed content cut
  into chunks, each a four-byte big-endian length followed by
  AES-256-GCM ciphertext and its 16-byte tag. The last chunk is marked
  in its nonce. `R5EC1` is the same without compression and is still
  read.
  """

  @plain_magic "R5EC1"
  @magic "R5EC2"
  @chunk 65_536
  @tag 16
  @level 3

  @type key :: <<_::256>>

  @doc "Whether stored bytes are in this module's format."
  @spec encrypted?(binary()) :: boolean()
  def encrypted?(<<@magic, _::binary>>), do: true
  def encrypted?(<<@plain_magic, _::binary>>), do: true
  def encrypted?(_other), do: false

  @doc "Compress and encrypt bytes held in memory."
  @spec encrypt(binary(), key(), String.t()) :: binary()
  def encrypt(plain, <<_::256>> = content_key, ref) when is_binary(plain) do
    pieces = for <<piece::binary-size(@chunk) <- plain>>, do: piece
    rest = binary_part(plain, length(pieces) * @chunk, rem(byte_size(plain), @chunk))

    {:ok, sealed} =
      run(
        fn
          [] -> :eof
          [piece | more] -> {:ok, piece, more}
        end,
        if(rest == <<>>, do: pieces, else: pieces ++ [rest]),
        fn out, acc -> {:ok, [acc, out]} end,
        [],
        working_key(content_key, ref, @magic),
        aad(@magic, ref)
      )

    IO.iodata_to_binary(sealed)
  end

  @doc """
  Compress and encrypt the file at `source` into a new file at `target`,
  a piece at a time, to the same bytes `encrypt/3` would give.
  """
  @spec encrypt_file(Path.t(), Path.t(), key(), String.t()) :: :ok | {:error, term()}
  def encrypt_file(source, target, <<_::256>> = content_key, ref) do
    with {:ok, input} <- :file.open(source, [:raw, :binary, :read]),
         {:ok, output} <- :file.open(target, [:raw, :binary, :write]) do
      try do
        result =
          run(
            fn input ->
              case :file.read(input, @chunk) do
                {:ok, piece} -> {:ok, piece, input}
                :eof -> :eof
                {:error, reason} -> {:error, reason}
              end
            end,
            input,
            fn out, :ok -> with(:ok <- :file.write(output, out), do: {:ok, :ok}) end,
            :ok,
            working_key(content_key, ref, @magic),
            aad(@magic, ref)
          )

        with {:ok, :ok} <- result, do: :ok
      after
        :file.close(input)
        :file.close(output)
      end
    end
  end

  @doc """
  Compress and encrypt content read from a reader (see
  `Recurse.Provenance.Store`) into a new file at `target`, a piece at a
  time, to the same bytes `encrypt/3` would give. Answers how many plain
  bytes were read. The reader is opened and closed here; whatever error
  it gives is returned as it is, and then `target` must not be used.
  """
  @spec encrypt_reader(
          (-> {:ok, term(), (term() -> term()), (-> any())} | {:error, term()}),
          Path.t(),
          key(),
          String.t()
        ) :: {:ok, non_neg_integer()} | {:error, term()}
  def encrypt_reader(open, target, <<_::256>> = content_key, ref) when is_function(open, 0) do
    with {:ok, source, read, close} <- open.() do
      counted = :counters.new(1, [])

      counting = fn source ->
        case read.(source) do
          {:ok, piece, source} ->
            :counters.add(counted, 1, byte_size(piece))
            {:ok, piece, source}

          other ->
            other
        end
      end

      try do
        with {:ok, output} <- :file.open(target, [:raw, :binary, :write]) do
          try do
            result =
              run(
                counting,
                source,
                fn out, :ok -> with(:ok <- :file.write(output, out), do: {:ok, :ok}) end,
                :ok,
                working_key(content_key, ref, @magic),
                aad(@magic, ref)
              )

            with {:ok, :ok} <- result, do: {:ok, :counters.get(counted, 1)}
          after
            :file.close(output)
          end
        end
      after
        close.()
      end
    end
  end

  # Read pieces of plain content, compress them as one stream, and write
  # the compressed stream out in sealed chunks. Compressed bytes are held
  # back until a full chunk is ready, and one chunk is always kept in
  # hand so the final one can be marked as last.
  defp run(read, source, write, sink, key, ref) do
    {:ok, zstd} = :zstd.context(:compress, %{compressionLevel: @level})

    try do
      with {:ok, sink} <- write.(@magic, sink) do
        pump(read, source, write, sink, zstd, key, ref, <<>>, 0)
      end
    after
      :zstd.close(zstd)
    end
  end

  defp pump(read, source, write, sink, zstd, key, ref, held, index) do
    case read.(source) do
      {:ok, piece, source} ->
        out = feed(zstd, piece)

        with {:ok, held, sink, index} <-
               emit(held <> IO.iodata_to_binary(out), write, sink, key, ref, index) do
          pump(read, source, write, sink, zstd, key, ref, held, index)
        end

      :eof ->
        {:done, out} = :zstd.finish(zstd, <<>>)

        with {:ok, held, sink, index} <-
               emit(held <> IO.iodata_to_binary(out), write, sink, key, ref, index) do
          write.(seal(held, key, ref, index, true), sink)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # The compressor may take only part of what it is given and hand the
  # rest back; keep feeding until it has taken all of it.
  defp feed(zstd, piece) do
    case :zstd.stream(zstd, piece) do
      {:continue, out} -> out
      {:continue, remainder, out} -> [out | feed(zstd, remainder)]
    end
  end

  # Seal and write every full chunk but the one that might be the last.
  defp emit(held, write, sink, key, ref, index) when byte_size(held) > @chunk do
    <<chunk::binary-size(@chunk), rest::binary>> = held

    with {:ok, sink} <- write.(seal(chunk, key, ref, index, false), sink) do
      emit(rest, write, sink, key, ref, index + 1)
    end
  end

  defp emit(held, _write, sink, _key, _ref, index), do: {:ok, held, sink, index}

  @doc """
  Decrypt stored bytes. Fails when the key is not the one the content was
  encrypted under, when the bytes were altered, cut short or rearranged,
  or when they belong to a different reference.
  """
  @spec decrypt(binary(), key(), String.t()) :: {:ok, binary()} | {:error, :not_decryptable}
  def decrypt(<<@magic, rest::binary>>, <<_::256>> = content_key, ref) do
    with {:ok, compressed} <-
           open(rest, working_key(content_key, ref, @magic), aad(@magic, ref), 0, []) do
      {:ok, IO.iodata_to_binary(:zstd.decompress(compressed))}
    end
  rescue
    _ -> {:error, :not_decryptable}
  end

  # Content stored before compression was added.
  def decrypt(<<@plain_magic, rest::binary>>, <<_::256>> = content_key, ref),
    do: open(rest, working_key(content_key, ref, @plain_magic), ref, 0, [])

  def decrypt(_other, _key, _ref), do: {:error, :not_decryptable}

  defp open(<<size::32, body::binary-size(size), rest::binary>>, key, ref, index, acc)
       when size >= @tag do
    text_size = size - @tag
    <<text::binary-size(text_size), tag::binary-size(@tag)>> = body
    last? = rest == <<>>

    case :crypto.crypto_one_time_aead(
           :aes_256_gcm,
           key,
           nonce(index, last?),
           text,
           ref,
           tag,
           false
         ) do
      plain when is_binary(plain) and last? ->
        {:ok, IO.iodata_to_binary(Enum.reverse([plain | acc]))}

      plain when is_binary(plain) ->
        open(rest, key, ref, index + 1, [plain | acc])

      :error ->
        {:error, :not_decryptable}
    end
  end

  defp open(_other, _key, _ref, _index, _acc), do: {:error, :not_decryptable}

  defp seal(chunk, key, ref, index, last?) do
    {text, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce(index, last?), chunk, ref, @tag, true)

    [<<byte_size(text) + @tag::32>>, text, tag]
  end

  defp nonce(index, last?), do: <<index::64, if(last?, do: 1, else: 0)::8, 0::24>>

  @doc """
  Lock a content key under a scope's key, so that scope can open the
  content. The lock is bound to the content's reference.
  """
  @spec lock(key(), key(), String.t()) :: binary()
  def lock(<<_::256>> = content_key, <<_::256>> = scope_key, ref) do
    nonce = :crypto.strong_rand_bytes(12)

    {text, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, scope_key, nonce, content_key, ref, @tag, true)

    nonce <> text <> tag
  end

  @doc "Open a lock made by `lock/3` with the same scope key and reference."
  @spec unlock(binary(), key(), String.t()) :: {:ok, key()} | {:error, :not_decryptable}
  def unlock(<<nonce::binary-12, text::binary-32, tag::binary-@tag>>, <<_::256>> = scope_key, ref) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, scope_key, nonce, text, ref, tag, false) do
      <<_::256>> = content_key -> {:ok, content_key}
      _ -> {:error, :not_decryptable}
    end
  end

  def unlock(_other, _scope_key, _ref), do: {:error, :not_decryptable}

  # HKDF-SHA256 with an empty salt and one output block.
  # The format marker is part of what every chunk is bound to, and each
  # format has its own working key, so stored bytes cannot be relabelled
  # from one format to the other and still open. The first format bound
  # only the reference; it is read as it was written.
  defp aad(@magic, ref), do: [@magic, " ", ref]

  defp working_key(content_key, ref, magic) do
    label = if magic == @magic, do: "r5e content v2 ", else: "r5e content v1 "
    extracted = :crypto.mac(:hmac, :sha256, <<0::256>>, content_key)
    :crypto.mac(:hmac, :sha256, extracted, [label, ref, <<1>>])
  end
end
