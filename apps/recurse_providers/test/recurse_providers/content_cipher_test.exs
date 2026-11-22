defmodule Recurse.Providers.ContentCipherTest do
  use ExUnit.Case, async: true

  alias Recurse.Providers.ContentCipher
  alias Recurse.Providers.Impls.LocalKeyService

  @moduletag :tmp_dir
  @ref "bytes:sha256:" <> String.duplicate("ab", 32)

  defp key, do: :crypto.strong_rand_bytes(32)

  test "bytes of every awkward size come back as they went in" do
    k = key()

    for size <- [0, 1, 65_535, 65_536, 65_537, 131_072, 200_001] do
      plain = :crypto.strong_rand_bytes(size)
      sealed = ContentCipher.encrypt(plain, k, @ref)
      assert ContentCipher.encrypted?(sealed)
      assert {:ok, ^plain} = ContentCipher.decrypt(sealed, k, @ref)
      if size > 32, do: refute(:binary.match(sealed, binary_part(plain, 0, 32)) != :nomatch)
    end
  end

  test "text is compressed before it is encrypted, and comes back exactly" do
    k = key()
    # A model request is mostly repeated structure; this stands in for one.
    plain =
      :binary.copy(~s({"role":"user","content":"list the files in the routing service"},), 4000)

    sealed = ContentCipher.encrypt(plain, k, @ref)

    assert byte_size(sealed) * 20 < byte_size(plain)
    assert {:ok, ^plain} = ContentCipher.decrypt(sealed, k, @ref)
  end

  test "a file is encrypted a chunk at a time to the same bytes as in memory", %{tmp_dir: dir} do
    k = key()

    for size <- [0, 10, 65_536, 300_000] do
      plain = :crypto.strong_rand_bytes(size)
      source = Path.join(dir, "plain-#{size}")
      target = Path.join(dir, "sealed-#{size}")
      File.write!(source, plain)

      assert :ok = ContentCipher.encrypt_file(source, target, k, @ref)
      assert File.read!(target) == ContentCipher.encrypt(plain, k, @ref)
      assert {:ok, ^plain} = ContentCipher.decrypt(File.read!(target), k, @ref)
    end
  end

  test "the wrong key, another reference, or any change to the bytes is refused" do
    k = key()
    plain = :crypto.strong_rand_bytes(150_000)
    sealed = ContentCipher.encrypt(plain, k, @ref)
    refused = {:error, :not_decryptable}

    assert refused == ContentCipher.decrypt(sealed, key(), @ref)

    assert refused ==
             ContentCipher.decrypt(sealed, k, "bytes:sha256:" <> String.duplicate("cd", 32))

    assert refused == ContentCipher.decrypt(plain, k, @ref)

    # Relabelled as the uncompressed format: the marker is bound into
    # every chunk, so this must not come back as raw compressed bytes.
    <<"R5EC2", body::binary>> = sealed
    assert refused == ContentCipher.decrypt(<<"R5EC1", body::binary>>, k, @ref)

    # One bit flipped in the middle.
    <<head::binary-70_000, byte, tail::binary>> = sealed

    assert refused ==
             ContentCipher.decrypt(<<head::binary, Bitwise.bxor(byte, 1), tail::binary>>, k, @ref)

    # The last chunk dropped: what is left ends on a chunk not marked last.
    <<"R5EC2", size::32, first::binary-size(size), _rest::binary>> = sealed
    assert refused == ContentCipher.decrypt(<<"R5EC2", size::32, first::binary>>, k, @ref)

    # The first two chunks swapped.
    <<"R5EC2", a::32, one::binary-size(a), b::32, two::binary-size(b), rest::binary>> = sealed

    assert refused ==
             ContentCipher.decrypt(
               <<"R5EC2", b::32, two::binary, a::32, one::binary, rest::binary>>,
               k,
               @ref
             )
  end

  test "content stored in the first format, before compression, still opens" do
    # Built by hand from the first format's description: one last chunk,
    # bound to the reference only, under the first format's working key.
    k = key()
    plain = "stored before compression existed"
    extracted = :crypto.mac(:hmac, :sha256, <<0::256>>, k)
    working = :crypto.mac(:hmac, :sha256, extracted, ["r5e content v1 ", @ref, <<1>>])
    nonce = <<0::64, 1::8, 0::24>>

    {text, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, working, nonce, plain, @ref, 16, true)

    stored = <<"R5EC1", byte_size(text) + 16::32, text::binary, tag::binary>>

    assert {:ok, ^plain} = ContentCipher.decrypt(stored, k, @ref)

    # And cannot be relabelled as the compressed format.
    <<"R5EC1", body::binary>> = stored
    assert {:error, :not_decryptable} = ContentCipher.decrypt(<<"R5EC2", body::binary>>, k, @ref)
  end

  test "a content key locked for a session opens only with that session's key and that reference" do
    content_key = key()
    session_key = key()
    locked = ContentCipher.lock(content_key, session_key, @ref)

    refute :binary.match(locked, content_key) != :nomatch
    assert {:ok, ^content_key} = ContentCipher.unlock(locked, session_key, @ref)
    assert {:error, :not_decryptable} = ContentCipher.unlock(locked, key(), @ref)

    assert {:error, :not_decryptable} =
             ContentCipher.unlock(locked, session_key, "bytes:sha256:00")

    assert {:error, :not_decryptable} = ContentCipher.unlock("short", session_key, @ref)
  end

  test "a local key file locks and unlocks a key, for its own context only", %{tmp_dir: dir} do
    path = Path.join(dir, "content.key")
    assert :ok = LocalKeyService.generate(path)
    assert {:error, _} = LocalKeyService.generate(path)
    assert Bitwise.band(File.stat!(path).mode, 0o077) == 0

    {:ok, service} = LocalKeyService.open(path)
    k = key()
    {:ok, wrapped} = LocalKeyService.wrap(service, k, "urn:r5e:session:one")

    refute :binary.match(wrapped, k) != :nomatch
    assert {:ok, ^k} = LocalKeyService.unwrap(service, wrapped, "urn:r5e:session:one")

    assert {:error, :not_unwrappable} =
             LocalKeyService.unwrap(service, wrapped, "urn:r5e:session:two")

    assert {:error, :not_unwrappable} =
             LocalKeyService.unwrap(service, "short", "urn:r5e:session:one")

    other = Path.join(dir, "other.key")
    :ok = LocalKeyService.generate(other)
    {:ok, stranger} = LocalKeyService.open(other)

    assert {:error, :not_unwrappable} =
             LocalKeyService.unwrap(stranger, wrapped, "urn:r5e:session:one")

    File.write!(other, "not a key")
    assert {:error, :unreadable_content_key} = LocalKeyService.open(other)
  end
end
