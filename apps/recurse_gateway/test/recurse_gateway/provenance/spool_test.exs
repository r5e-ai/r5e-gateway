defmodule Recurse.Gateway.Provenance.SpoolTest do
  use ExUnit.Case, async: true

  alias Recurse.Gateway.Provenance.Spool

  @moduletag :tmp_dir

  @epoch :binary.list_to_bin(Enum.to_list(0..15))
  @dek :binary.list_to_bin(Enum.to_list(32..63))
  @file_id :binary.list_to_bin(Enum.to_list(64..79))
  @chunk 65_536

  defp key_for(epoch \\ @epoch, dek \\ @dek), do: fn ^epoch -> {:ok, dek} end

  defp vectors,
    do: "test/fixtures/spool/vectors.json" |> File.read!() |> Jason.decode!()

  defp pattern(n, k), do: :binary.list_to_bin(for i <- 0..(n - 1)//1, do: rem(i * k, 251))

  defp write_sealed(dir, plain, pieces \\ 4096) do
    path = Path.join(dir, "f-#{System.unique_integer([:positive])}")
    {:ok, w} = Spool.create(path, @epoch, @dek)

    w =
      plain
      |> chunks(pieces)
      |> Enum.reduce(w, fn piece, w ->
        {:ok, w} = Spool.append(w, piece)
        w
      end)

    {:ok, %{sha256: sha, size: size}} = Spool.finish(w)
    assert sha == :crypto.hash(:sha256, plain)
    assert size == byte_size(plain)
    path
  end

  defp chunks(<<>>, _n), do: []
  defp chunks(bin, n) when byte_size(bin) <= n, do: [bin]

  defp chunks(bin, n) do
    <<piece::binary-size(n), rest::binary>> = bin
    [piece | chunks(rest, n)]
  end

  defp read_all(path, expected) do
    with {:ok, source, read, close} <- Spool.open_reader(path, expected, key_for()) do
      try do
        drain(read, source, [])
      after
        close.()
      end
    end
  end

  defp drain(read, source, acc) do
    case read.(source) do
      {:ok, piece, source} -> drain(read, source, [acc, piece])
      :eof -> {:ok, IO.iodata_to_binary(acc)}
      {:error, _} = error -> error
    end
  end

  describe "fixed vectors (checked by an independent implementation, test/support/spool_vectors_check.py)" do
    test "file format" do
      plain = %{
        "empty" => "",
        "short" => "hello spool",
        "chunk_plus_5" => pattern(@chunk + 5, 7),
        "exact_chunk" => pattern(@chunk, 3),
        "two_full_chunks" => pattern(2 * @chunk, 5)
      }

      for {name, want} <- vectors()["files"] do
        sealed = IO.iodata_to_binary(Spool.seal(plain[name], @epoch, @dek, @file_id))
        assert Base.encode16(:crypto.hash(:sha256, sealed), case: :lower) == want, name
        assert {:ok, plain[name]} == Spool.open(sealed, key_for())
      end
    end

    test "sealed epoch key" do
      %{"identity_pub" => id_pub, "ephemeral_pub" => e_pub, "sealed" => sealed, "kek" => kek} =
        vectors()["epoch"]

      identity = :binary.list_to_bin(Enum.to_list(80..111))
      ephemeral = :binary.list_to_bin(Enum.to_list(112..143))

      assert Base.encode16(Spool.public_of(identity), case: :lower) == id_pub
      assert Base.encode16(Spool.public_of(ephemeral), case: :lower) == e_pub

      assert {:ok, %{ephemeral: e, sealed: s}} =
               Spool.seal_epoch(
                 @dek,
                 @epoch,
                 "dep-vector",
                 Spool.public_of(identity),
                 {Spool.public_of(ephemeral), ephemeral}
               )

      assert Base.encode16(s, case: :lower) == sealed

      assert {:ok, k} =
               Spool.kek_for_vector(
                 ephemeral,
                 Spool.public_of(ephemeral),
                 Spool.public_of(identity),
                 "dep-vector",
                 @epoch
               )

      assert Base.encode16(k, case: :lower) == kek
      assert {:ok, @dek} == Spool.open_epoch(e, s, @epoch, "dep-vector", identity)
    end
  end

  describe "streaming writer and reader" do
    test "round-trips every size around the chunk edges, in odd pieces", %{tmp_dir: dir} do
      for n <- [0, 1, 4095, @chunk - 1, @chunk, @chunk + 1, 3 * @chunk, 350_000],
          pieces <- [1_000, 4096, 70_000] do
        plain = :crypto.strong_rand_bytes(n)
        path = write_sealed(dir, plain, pieces)
        assert {:ok, ^plain} = read_all(path, :crypto.hash(:sha256, plain))
        assert Spool.plain_size(File.stat!(path).size) == n
        assert {:ok, @epoch} = Spool.epoch_of(path)
        assert {:ok, ^plain} = Spool.open(File.read!(path), key_for())
      end
    end

    test "no plaintext reaches the disk", %{tmp_dir: dir} do
      canary = String.duplicate("STAGE_DISK_CANARY_7f3a", 20_000)
      path = write_sealed(dir, canary)
      refute File.read!(path) =~ "STAGE_DISK_CANARY"
    end

    test "files are created for their owner only, and never over an existing file", %{
      tmp_dir: dir
    } do
      path = write_sealed(dir, "x")
      assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
      assert {:error, :eexist} = Spool.create(path, @epoch, @dek)
    end

    test "two files under one epoch never share a key", %{tmp_dir: dir} do
      a = File.read!(write_sealed(dir, String.duplicate("a", 100)))
      b = File.read!(write_sealed(dir, String.duplicate("a", 100)))
      assert binary_part(a, 37, 100) != binary_part(b, 37, 100)
    end

    test "a plain file is told apart", %{tmp_dir: dir} do
      path = Path.join(dir, "plain")
      File.write!(path, "just some bytes")
      assert :plain = Spool.epoch_of(path)
    end
  end

  describe "the reader refuses" do
    setup %{tmp_dir: dir} do
      plain = :crypto.strong_rand_bytes(3 * @chunk + 10)
      path = write_sealed(dir, plain)
      %{plain: plain, path: path, sha: :crypto.hash(:sha256, plain), bytes: File.read!(path)}
    end

    defp rewrite(path, bytes) do
      File.write!(path, bytes)
      path
    end

    test "an altered byte in any chunk", %{path: path, sha: sha, bytes: bytes} do
      for offset <- [40, 37 + 65_552 + 3, byte_size(bytes) - 1] do
        <<head::binary-size(offset), b, tail::binary>> = bytes
        rewrite(path, <<head::binary, Bitwise.bxor(b, 1), tail::binary>>)
        assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
      end
    end

    test "a file cut at a chunk boundary (missing final chunk)", %{
      path: path,
      sha: sha,
      bytes: bytes
    } do
      rewrite(path, binary_part(bytes, 0, 37 + 3 * 65_552))
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
    end

    test "a file cut inside a chunk", %{path: path, sha: sha, bytes: bytes} do
      rewrite(path, binary_part(bytes, 0, byte_size(bytes) - 5))
      assert {:error, {:staged_content_unreadable, _}} = read_all(path, sha)
    end

    test "bytes after the final chunk", %{path: path, sha: sha, bytes: bytes} do
      rewrite(path, bytes <> "trailing")
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
    end

    test "chunks swapped or repeated", %{path: path, sha: sha, bytes: bytes} do
      <<header::binary-37, c0::binary-65_552, c1::binary-65_552, rest::binary>> = bytes
      rewrite(path, header <> c1 <> c0 <> rest)
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
      rewrite(path, header <> c0 <> c0 <> rest)
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
    end

    test "a chunk spliced from another file of the same epoch", %{
      path: path,
      sha: sha,
      bytes: bytes,
      tmp_dir: dir
    } do
      other = File.read!(write_sealed(dir, :crypto.strong_rand_bytes(3 * @chunk + 10)))
      <<header::binary-37, _c0::binary-65_552, rest::binary>> = bytes
      <<_::binary-37, o0::binary-65_552, _::binary>> = other
      rewrite(path, header <> o0 <> rest)
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
    end

    test "a header naming another file id", %{path: path, sha: sha, bytes: bytes} do
      <<magic::binary-5, epoch::binary-16, _id::binary-16, rest::binary>> = bytes
      rewrite(path, magic <> epoch <> :crypto.strong_rand_bytes(16) <> rest)
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read_all(path, sha)
    end

    test "a short header or no chunk at all", %{path: path, sha: sha, bytes: bytes} do
      rewrite(path, binary_part(bytes, 0, 20))
      assert {:error, {:staged_content_unreadable, :truncated}} = read_all(path, sha)
      rewrite(path, binary_part(bytes, 0, 37))
      assert {:error, {:staged_content_unreadable, :truncated}} = read_all(path, sha)
    end

    test "content that is not what the reference names", %{path: path} do
      assert {:error, {:staged_content_unreadable, :does_not_match_ref}} =
               read_all(path, :crypto.hash(:sha256, "something else"))
    end

    test "the wrong key, and passes on the key lookup's own error", %{path: path, sha: sha} do
      wrong = fn _ -> {:ok, :crypto.strong_rand_bytes(32)} end
      {:ok, s, read, close} = Spool.open_reader(path, sha, wrong)
      assert {:error, {:staged_content_unreadable, :tag_mismatch}} = read.(s)
      close.()

      outage = fn _ -> {:error, {:key_service_unavailable, :timeout}} end
      assert {:error, {:key_service_unavailable, :timeout}} = Spool.open_reader(path, sha, outage)
    end
  end

  test "keys of the wrong size are refused without reaching :crypto", %{tmp_dir: dir} do
    assert {:error, :bad_key} = Spool.create(Path.join(dir, "k"), @epoch, "short")

    assert {:error, :bad_key} =
             Spool.seal_epoch("short", @epoch, "dep", :crypto.strong_rand_bytes(32))

    assert {:error, :not_decryptable} = Spool.open_epoch("x", "y", @epoch, "dep", "z")
    assert_raise ArgumentError, ~r/wrong size/, fn -> Spool.seal("p", @epoch, "short") end
  end

  describe "sealed epoch keys" do
    test "bind the deployment, the epoch and the identity" do
      {id_pub, id_priv} = Spool.identity_keypair()
      {:ok, %{ephemeral: e, sealed: s}} = Spool.seal_epoch(@dek, @epoch, "dep-a", id_pub)

      assert {:ok, @dek} = Spool.open_epoch(e, s, @epoch, "dep-a", id_priv)
      assert {:error, :not_decryptable} = Spool.open_epoch(e, s, @epoch, "dep-b", id_priv)

      assert {:error, :not_decryptable} =
               Spool.open_epoch(e, s, :crypto.strong_rand_bytes(16), "dep-a", id_priv)

      {_other_pub, other_priv} = Spool.identity_keypair()
      assert {:error, :not_decryptable} = Spool.open_epoch(e, s, @epoch, "dep-a", other_priv)
    end

    test "each sealing uses a fresh ephemeral key" do
      {id_pub, _} = Spool.identity_keypair()
      {:ok, a} = Spool.seal_epoch(@dek, @epoch, "dep", id_pub)
      {:ok, b} = Spool.seal_epoch(@dek, @epoch, "dep", id_pub)
      assert a.ephemeral != b.ephemeral and a.sealed != b.sealed
    end

    test "a low-order identity public key is refused" do
      assert {:error, :weak_identity_key} = Spool.seal_epoch(@dek, @epoch, "dep", <<0::256>>)

      assert {:error, :weak_identity_key} =
               Spool.seal_epoch(@dek, @epoch, "dep", <<1::256-little>>)
    end
  end
end
