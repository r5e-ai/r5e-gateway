defmodule RecurseVerify.Merkle do
  @moduledoc """
  RFC 9162 Merkle tree math: root (MTH), inclusion proofs (audit paths),
  and consistency proofs. Pure functions over an ordered list of leaf data
  blobs; no storage coupling.

  Hash definitions (RFC 9162 §2):

      hash_leaf(d)        = SHA-256(0x00 || d)
      hash_interior(l, r) = SHA-256(0x01 || l || r)

  MTH (§2.1), for D[n] a list of n entries, with k the largest power of 2
  strictly less than n:

      MTH({})     = SHA-256()
      MTH({d0})   = hash_leaf(d0)
      MTH(D[n>1]) = hash_interior(MTH(D[0:k]), MTH(D[k:n]))

  Provenance: leaf/interior hashing, MTH, and the inclusion audit path +
  iterative inclusion verifier are ported from the r5e-enterprise
  Postgres-Merkle ledger (Feature 002, `MerkleTree` module), minus the
  Postgres coupling. Consistency proofs (SUBPROOF, §2.1.2) and their
  iterative verifier (§2.1.4.2) are implemented here from the RFC — the
  enterprise ledger did not need them (its checkpoints were per-epoch).

  Proofs are ordered deepest-to-root: the first element is the sibling
  nearest the leaf. Complexity is honest-but-lazy (list splits recompute
  lengths); r5e logs at kernel scale are small, and the verifier's job is
  to be readable.
  """

  import Bitwise, only: [<<<: 2, >>>: 2]

  @type hash32 :: <<_::256>>

  @doc "RFC 9162 §2: `hash_leaf(d) = SHA-256(0x00 || d)`."
  @spec leaf_hash(binary()) :: hash32()
  def leaf_hash(data) when is_binary(data), do: :crypto.hash(:sha256, <<0x00>> <> data)

  @doc "RFC 9162 §2: `hash_interior(l, r) = SHA-256(0x01 || l || r)`."
  @spec node_hash(hash32(), hash32()) :: hash32()
  def node_hash(<<_::256>> = left, <<_::256>> = right) do
    :crypto.hash(:sha256, <<0x01>> <> left <> right)
  end

  @doc "Merkle Tree Hash over an ordered list of leaf data blobs."
  @spec root([binary()]) :: hash32()
  def root([]), do: :crypto.hash(:sha256, <<>>)
  def root([single]) when is_binary(single), do: leaf_hash(single)

  def root([_ | _] = leaves) do
    {left, right} = Enum.split(leaves, split_point(length(leaves)))
    node_hash(root(left), root(right))
  end

  @doc """
  RFC 9162 §2.1.1 audit path (inclusion proof) for the 0-based `index`
  within `leaves`. Deepest-to-root sibling hashes; `[]` for a single-leaf
  tree.
  """
  @spec inclusion_proof([binary()], non_neg_integer()) ::
          {:ok, [hash32()]} | {:error, :index_out_of_range}
  def inclusion_proof(leaves, index)
      when is_list(leaves) and is_integer(index) and index >= 0 do
    if leaves != [] and index < length(leaves) do
      {:ok, audit_path(leaves, index)}
    else
      {:error, :index_out_of_range}
    end
  end

  def inclusion_proof(_, _), do: {:error, :index_out_of_range}

  defp audit_path([_one], 0), do: []

  defp audit_path(leaves, index) do
    k = split_point(length(leaves))
    {left, right} = Enum.split(leaves, k)

    if index < k do
      audit_path(left, index) ++ [root(right)]
    else
      audit_path(right, index - k) ++ [root(left)]
    end
  end

  @doc """
  RFC 9162 §2.1.3.2 iterative inclusion verification: `true` iff `proof`
  reconstructs `expected_root` from `leaf_data` at `index` in a tree of
  `tree_size` leaves.
  """
  @spec verify_inclusion(binary(), non_neg_integer(), pos_integer(), [hash32()], hash32()) ::
          boolean()
  def verify_inclusion(leaf_data, index, tree_size, proof, <<_::256>> = expected_root)
      when is_binary(leaf_data) and is_integer(index) and index >= 0 and
             is_integer(tree_size) and tree_size > 0 and is_list(proof) do
    with true <- index < tree_size,
         true <- Enum.all?(proof, &match?(<<_::256>>, &1)),
         {:ok, hash} <- fold_inclusion(leaf_hash(leaf_data), index, tree_size - 1, proof) do
      hash == expected_root
    else
      _ -> false
    end
  end

  def verify_inclusion(_, _, _, _, _), do: false

  defp fold_inclusion(hash, 0, 0, []), do: {:ok, hash}
  defp fold_inclusion(_hash, _fn_, 0, [_ | _]), do: :error
  defp fold_inclusion(_hash, _fn_, _sn, []), do: :error

  defp fold_inclusion(hash, fn_, sn, [sibling | rest]) do
    cond do
      # Stray last node at this level: no sibling here; halve without
      # consuming the proof element.
      fn_ == sn and rem(fn_, 2) == 0 ->
        fold_inclusion(hash, fn_ >>> 1, sn >>> 1, [sibling | rest])

      # Right child: sibling on the left.
      rem(fn_, 2) == 1 ->
        continue_inclusion(node_hash(sibling, hash), fn_ >>> 1, sn >>> 1, rest)

      # Left child with a right sibling.
      true ->
        continue_inclusion(node_hash(hash, sibling), fn_ >>> 1, sn >>> 1, rest)
    end
  end

  defp continue_inclusion(hash, 0, 0, []), do: {:ok, hash}
  defp continue_inclusion(_hash, _fn_, _sn, []), do: :error
  defp continue_inclusion(hash, fn_, sn, rest), do: fold_inclusion(hash, fn_, sn, rest)

  @doc """
  RFC 9162 §2.1.2 consistency proof `PROOF(m, D[n])` between the tree over
  the first `m` leaves and the tree over the first `n` (`0 < m <= n`,
  `n <= length(leaves)`). `[]` when `m == n`.
  """
  @spec consistency_proof([binary()], pos_integer(), pos_integer()) ::
          {:ok, [hash32()]} | {:error, :bad_sizes}
  def consistency_proof(leaves, m, n)
      when is_list(leaves) and is_integer(m) and is_integer(n) and
             0 < m and m <= n do
    if n <= length(leaves) do
      {:ok, subproof(m, Enum.take(leaves, n), true)}
    else
      {:error, :bad_sizes}
    end
  end

  def consistency_proof(_, _, _), do: {:error, :bad_sizes}

  # SUBPROOF(m, D[n], b) per §2.1.2.
  defp subproof(m, leaves, true) when length(leaves) == m, do: []
  defp subproof(m, leaves, false) when length(leaves) == m, do: [root(leaves)]

  defp subproof(m, leaves, b) do
    k = split_point(length(leaves))
    {left, right} = Enum.split(leaves, k)

    if m <= k do
      subproof(m, left, b) ++ [root(right)]
    else
      subproof(m - k, right, false) ++ [root(left)]
    end
  end

  @doc """
  RFC 9162 §2.1.4.2 iterative consistency verification: `true` iff `proof`
  proves the tree of size `n` with root `root_n` is an append-only
  extension of the tree of size `m` with root `root_m`.
  """
  @spec verify_consistency(pos_integer(), pos_integer(), hash32(), hash32(), [hash32()]) ::
          boolean()
  def verify_consistency(m, m, root_m, root_n, []), do: root_m == root_n
  def verify_consistency(m, m, _root_m, _root_n, _proof), do: false

  def verify_consistency(m, n, <<_::256>> = root_m, <<_::256>> = root_n, proof)
      when is_integer(m) and is_integer(n) and 0 < m and m < n and is_list(proof) do
    proof = if power_of_two?(m), do: [root_m | proof], else: proof

    case proof do
      [] ->
        false

      [seed | rest] ->
        {fn_, sn} = shift_while_odd(m - 1, n - 1)
        fold_consistency(rest, fn_, sn, seed, seed, root_m, root_n)
    end
  end

  def verify_consistency(_, _, _, _, _), do: false

  defp fold_consistency([], _fn_, sn, fr, sr, root_m, root_n) do
    sn == 0 and fr == root_m and sr == root_n
  end

  defp fold_consistency([c | rest], fn_, sn, fr, sr, root_m, root_n) do
    cond do
      sn == 0 ->
        false

      rem(fn_, 2) == 1 or fn_ == sn ->
        fr = node_hash(c, fr)
        sr = node_hash(c, sr)
        {fn_, sn} = if rem(fn_, 2) == 1, do: {fn_, sn}, else: shift_until_odd_or_zero(fn_, sn)
        fold_consistency(rest, fn_ >>> 1, sn >>> 1, fr, sr, root_m, root_n)

      true ->
        fold_consistency(rest, fn_ >>> 1, sn >>> 1, fr, node_hash(sr, c), root_m, root_n)
    end
  end

  defp shift_while_odd(fn_, sn) when rem(fn_, 2) == 1, do: shift_while_odd(fn_ >>> 1, sn >>> 1)
  defp shift_while_odd(fn_, sn), do: {fn_, sn}

  defp shift_until_odd_or_zero(0, sn), do: {0, sn}
  defp shift_until_odd_or_zero(fn_, sn) when rem(fn_, 2) == 1, do: {fn_, sn}
  defp shift_until_odd_or_zero(fn_, sn), do: shift_until_odd_or_zero(fn_ >>> 1, sn >>> 1)

  defp power_of_two?(n) when n >= 1, do: Bitwise.band(n, n - 1) == 0

  # Largest power of 2 strictly less than n (n > 1).
  defp split_point(n) when n > 1, do: 1 <<< (bit_length(n - 1) - 1)

  defp bit_length(n), do: do_bit_length(n, 0)
  defp do_bit_length(0, acc), do: acc
  defp do_bit_length(n, acc), do: do_bit_length(n >>> 1, acc + 1)

  @doc "Lowercase hex of a 32-byte hash (JSON representation of roots/proofs)."
  @spec hex(hash32()) :: String.t()
  def hex(<<_::256>> = h), do: Base.encode16(h, case: :lower)

  @doc "Decode lowercase/uppercase hex to 32 bytes; `:error` otherwise."
  @spec unhex(term()) :: {:ok, hash32()} | :error
  def unhex(hex) when is_binary(hex) and byte_size(hex) == 64 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, <<_::256>> = h} -> {:ok, h}
      _ -> :error
    end
  end

  def unhex(_), do: :error
end
