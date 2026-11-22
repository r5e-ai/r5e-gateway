defmodule RecurseVerify.CAS do
  @moduledoc """
  Read-side helpers for r5e content-addressed storage: address validation,
  the on-disk sharding layout (`<root>/<aa>/<rest-of-hex>`), and reads
  from an explicit CAS root (a bundle's `cas/` directory). Writing lives
  in the kernel; addressing truth lives here.
  """

  @doc """
  Is this string a well-formed r5e address? The three forms of spec/05 §6:

    * `sha256:<hex>` — an admitted spec or an event payload (kernel-written)
    * `bytes:sha256:<hex>` — raw bytes admitted as a `CasObject`
    * `event:sha256:<hex>` — an event hash

  Two of the three name **objects** and share one tree; `event:` names a
  position on the log and nothing in the CAS. Use `object_address?/1`
  wherever the question is "can this be read from a CAS root", because
  asking `valid_address?/1` there would send an event hash looking for a
  file that was never meant to exist.
  """
  @spec valid_address?(term()) :: boolean()
  def valid_address?("sha256:" <> hex), do: hash?(hex)
  def valid_address?("bytes:sha256:" <> hex), do: hash?(hex)
  def valid_address?("event:sha256:" <> hex), do: hash?(hex)
  def valid_address?(_), do: false

  @doc """
  Is this an address of an object stored in a CAS tree? `sha256:` and
  `bytes:sha256:` both are, and both live at the same path — the
  partition between them is the *act* that put them there (§4), which is
  a fact about the log, not about the bytes.
  """
  @spec object_address?(term()) :: boolean()
  def object_address?("sha256:" <> hex), do: hash?(hex)
  def object_address?("bytes:sha256:" <> hex), do: hash?(hex)
  def object_address?(_), do: false

  @doc "Is this an event hash in address form (`event:sha256:<hex>`)?"
  @spec event_address?(term()) :: boolean()
  def event_address?("event:sha256:" <> hex), do: hash?(hex)
  def event_address?(_), do: false

  @doc "Strip the class prefix: the `sha256:<hex>` an object address carries."
  @spec object_hash(String.t()) :: String.t()
  def object_hash("bytes:" <> rest), do: rest
  def object_hash("event:" <> rest), do: rest
  def object_hash(addr), do: addr

  defp hash?(hex), do: byte_size(hex) == 64 and String.match?(hex, ~r/^[a-f0-9]{64}$/)

  @doc "Relative object path within a CAS root, e.g. `ab/cdef...`."
  @spec relative_path(String.t()) :: Path.t()
  def relative_path("bytes:sha256:" <> hex), do: shard(hex)
  def relative_path("sha256:" <> hex), do: shard(hex)

  defp shard(hex) do
    {shard, rest} = String.split_at(hex, 2)
    Path.join(shard, rest)
  end

  @doc "Fetch bytes by address from an explicit CAS root."
  @spec get(Path.t(), String.t()) :: {:ok, binary()} | {:error, :not_found | :bad_address}
  def get(cas_root, addr) do
    if object_address?(addr) do
      case File.read(Path.join(cas_root, relative_path(addr))) do
        {:ok, bytes} -> {:ok, bytes}
        {:error, _} -> {:error, :not_found}
      end
    else
      {:error, :bad_address}
    end
  end

  @doc "Exists-and-hashes-to-its-address check from an explicit CAS root."
  @spec intact?(Path.t(), String.t()) :: boolean()
  def intact?(cas_root, addr) do
    case get(cas_root, addr) do
      # A `bytes:` address hashes to the same object as the bare form it
      # wraps: same tree, same layout, different act (§6).
      {:ok, bytes} -> RecurseVerify.Canonical.hash_bytes(bytes) == object_hash(addr)
      _ -> false
    end
  end
end
