defmodule Recurse.Provenance.Ref do
  @moduledoc """
  The reference strings of Provenance v2 (contract §2).

  A reference is a plain string. The field it sits in declares the
  relationship; the prefix declares what kind of thing is addressed:

    * `evidence:sha256:<hex>` — the exact signed payload of one record
    * `bytes:sha256:<hex>` — exact raw content bytes, wherever they are held
    * `event:sha256:<hex>` — a Core admission event, read under its own version

  The hash names content, never a location, so a reference stays valid
  when the thing it names is held on another recorder or is not held
  locally at all.
  """

  @hex ~r/\A[0-9a-f]{64}\z/

  @type kind :: :evidence | :bytes | :event
  @type t :: String.t()

  @doc "The `bytes:` address of raw content."
  @spec bytes(binary()) :: t()
  def bytes(content) when is_binary(content), do: "bytes:sha256:" <> digest_hex(content)

  @doc "The `evidence:` address of a canonical Evidence payload."
  @spec evidence(binary()) :: t()
  def evidence(payload) when is_binary(payload), do: "evidence:sha256:" <> digest_hex(payload)

  @doc "Split a reference into its kind and 32-byte digest."
  @spec parse(term()) :: {:ok, kind(), <<_::256>>} | :error
  def parse("evidence:sha256:" <> hex), do: decode(:evidence, hex)
  def parse("bytes:sha256:" <> hex), do: decode(:bytes, hex)
  def parse("event:sha256:" <> hex), do: decode(:event, hex)
  def parse(_other), do: :error

  @doc "Whether `value` is a well-formed reference of the given kind."
  @spec valid?(term(), kind()) :: boolean()
  def valid?(value, kind), do: match?({:ok, ^kind, _}, parse(value))

  @doc "The 32-byte digest inside a reference of the given kind."
  @spec digest!(t(), kind()) :: <<_::256>>
  def digest!(ref, kind) do
    case parse(ref) do
      {:ok, ^kind, digest} -> digest
      _ -> raise ArgumentError, "not a #{kind}: reference: #{inspect(ref)}"
    end
  end

  @doc "Whether raw content matches a `bytes:` reference."
  @spec matches?(t(), binary()) :: boolean()
  def matches?(ref, content) when is_binary(content), do: ref == bytes(content)

  defp decode(kind, hex) do
    if Regex.match?(@hex, hex),
      do: {:ok, kind, Base.decode16!(hex, case: :lower)},
      else: :error
  end

  defp digest_hex(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
end
