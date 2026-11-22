defmodule Recurse.Provenance.Epoch do
  @moduledoc """
  Epoch seals: a commitment to a contiguous run of one stream (contract §6).

  A seal's manifest lists the covered records' references in stream
  order. Its root is a Merkle tree over the 32-byte digests inside those
  references: `leaf(d) = H(0x00 || d)`, `node(l, r) = H(0x01 || l || r)`,
  split at the largest power of two strictly below the size, with no
  padding and no duplicated last leaf. That is the RFC 9162 tree, taken
  from the Core verifier. An empty epoch does not exist.

  Each covered record keeps its own signature; a seal adds a commitment
  over records already signed and never stands in for them.
  """

  alias Recurse.Provenance.{Definitions, Ref}
  alias RecurseVerify.{Canonical, Merkle}

  @format "r5e.provenance-epoch/v2"

  @doc "The manifest value for an ordered, non-empty list of evidence references."
  @spec manifest([Ref.t(), ...]) :: map()
  def manifest([_ | _] = refs), do: %{"format" => @format, "events" => refs}

  @doc "Canonical bytes of a manifest and their `bytes:` reference."
  @spec manifest_bytes(map()) :: {binary(), Ref.t()}
  def manifest_bytes(manifest) do
    bytes = Canonical.encode(manifest)
    {bytes, Ref.bytes(bytes)}
  end

  @doc "The Merkle root over the references, as `sha256:<hex>`."
  @spec root([Ref.t(), ...]) :: String.t()
  def root([_ | _] = refs), do: "sha256:" <> Merkle.hex(Merkle.root(leaves(refs)))

  @doc """
  The body of an `EpochSeal` covering `refs`, which occupy positions
  `first_seq..first_seq + length - 1` of `stream`. `previous_seal` is nil
  only when `first_seq` is 1, and is then left out of the body.
  """
  @spec seal_body(String.t(), pos_integer(), [Ref.t(), ...], Ref.t() | nil) ::
          {body :: map(), manifest_bytes :: binary()}
  def seal_body(stream, first_seq, [_ | _] = refs, previous_seal) do
    {bytes, manifest_ref} = refs |> manifest() |> manifest_bytes()

    body = %{
      "stream" => stream,
      "firstSeq" => first_seq,
      "lastSeq" => first_seq + length(refs) - 1,
      "root" => root(refs),
      "manifestRef" => manifest_ref
    }

    # A stream's first seal has no predecessor, and says so by leaving
    # the field out: a definition has no place for a null.
    body = if previous_seal, do: Map.put(body, "previousSeal", previous_seal), else: body

    {body, bytes}
  end

  @doc "The kind path and definition reference of an `EpochSeal`."
  @spec seal_kind() :: {String.t(), Ref.t()}
  def seal_kind do
    path = Definitions.api_version() <> "/EpochSeal"
    {:ok, %{ref: ref}} = Definitions.fetch(path)
    {path, ref}
  end

  @doc "Bottom-up sibling hashes proving the record at `index` is in the tree."
  @spec proof([Ref.t(), ...], non_neg_integer()) ::
          {:ok, [String.t()]} | {:error, :index_out_of_range}
  def proof(refs, index) do
    with {:ok, path} <- Merkle.inclusion_proof(leaves(refs), index) do
      {:ok, Enum.map(path, &("sha256:" <> Merkle.hex(&1)))}
    end
  end

  @doc """
  Check a membership proof: `record` sits at zero-based `index` in a tree
  of `size` leaves with root `root`. Every sibling is used; none may be
  left over.
  """
  @spec verify_proof(Ref.t(), non_neg_integer(), pos_integer(), [String.t()], String.t()) ::
          boolean()
  def verify_proof(record, index, size, siblings, "sha256:" <> root_hex) do
    with {:ok, :evidence, digest} <- Ref.parse(record),
         {:ok, root} <- Merkle.unhex(root_hex),
         {:ok, path} <- unhex_all(siblings) do
      Merkle.verify_inclusion(digest, index, size, path, root)
    else
      _ -> false
    end
  end

  def verify_proof(_record, _index, _size, _siblings, _root), do: false

  @doc """
  Check a complete seal against its manifest and the opened records it
  covers, in order: length, stream, contiguous positions, each record's
  `previous`, and the root. `prior_last` is the reference of the record
  before `firstSeq`, or nil when the seal starts the stream.
  """
  @spec check_complete(map(), map(), [%{ref: Ref.t(), evidence: map()}], Ref.t() | nil) ::
          :ok | {:error, atom()}
  def check_complete(seal_body, manifest, records, prior_last) do
    refs = manifest["events"]
    first = seal_body["firstSeq"]

    cond do
      manifest["format"] != @format -> {:error, :manifest_format}
      elem(manifest_bytes(manifest), 1) != seal_body["manifestRef"] -> {:error, :manifest_ref}
      seal_body["lastSeq"] - first + 1 != length(refs) -> {:error, :range_length}
      Enum.map(records, & &1.ref) != refs -> {:error, :records_do_not_match_manifest}
      root(refs) != seal_body["root"] -> {:error, :root}
      true -> chain(records, seal_body["stream"], first, prior_last)
    end
  end

  defp chain(records, stream, first, prior_last) do
    records
    |> Enum.with_index(first)
    |> Enum.reduce_while({:ok, prior_last}, fn {%{ref: ref, evidence: e}, seq}, {:ok, previous} ->
      cond do
        e["stream"] != stream -> {:halt, {:error, :stream}}
        e["seq"] != seq -> {:halt, {:error, :sequence}}
        e["previous"] != previous -> {:halt, {:error, :previous}}
        true -> {:cont, {:ok, ref}}
      end
    end)
    |> case do
      {:ok, _last} -> :ok
      error -> error
    end
  end

  defp leaves(refs), do: Enum.map(refs, &Ref.digest!(&1, :evidence))

  defp unhex_all(siblings) do
    Enum.reduce_while(siblings, {:ok, []}, fn
      "sha256:" <> hex, {:ok, acc} ->
        case Merkle.unhex(hex) do
          {:ok, hash} -> {:cont, {:ok, acc ++ [hash]}}
          :error -> {:halt, :error}
        end

      _other, _acc ->
        {:halt, :error}
    end)
  end
end
