defmodule RecurseVerify.DSSE do
  @moduledoc """
  Verification side of DSSE (Dead Simple Signing Envelope, ITE-5) with
  PAE, ed25519 via `:crypto` only, plus spec 011 contract §0's algorithm
  registry and key-id derivation and §7's ed25519 profile. The kernel
  signs with the same PAE assembly (path dependency); this module is the
  single source of envelope-verification truth.

  PAE: `"DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload` — the
  signature covers the raw PAE bytes (never a JWS signing input).

  ## §0 — the algorithm registry and the key id

  v1 of the registry holds one algorithm: `ed25519`, tag `"ed25519"`,
  32-byte public key, 64-byte signature, the profile below. A key id is

      key:<alg>:sha256:<64 lowercase hex>

  over `uvarint(len(tag)) || tag || publicKeyBytes` — the tag is inside
  the hash, so the same 32 bytes under a future algorithm are a different
  key id and no two registry entries can ever collide.

  `fingerprint/1` is the *older*, unprefixed convention (`sha256(pubkey)`)
  and is still what a checkpoint's `keyid` is: the signed tree head is not
  an admission and this slice does not restate it.

  ## §7 — the ed25519 profile

  RFC 8032 verification behind explicit pre-checks, because
  `:crypto.verify/5` accepts inputs the profile refuses:

    * lengths ≠ 32 (public key) / 64 (signature);
    * a non-canonical public-key encoding — y ≥ p, with p = 2^255 − 19;
    * a small-order public key, by libsodium's blacklist (below);
    * `S ≥ L`, the signature's scalar half against the group order.

  The blacklist is copied verbatim from libsodium
  (`crypto_sign/ed25519/ref10/open.c`, `has_small_order`) and compared the
  way libsodium compares it: the first 31 bytes exactly, byte 31 with the
  sign bit masked off. Seven rows plus that masking cover the eight
  small-order points — the identity, the point of order 2, both of order
  4 and all four of order 8 — and the two non-canonical encodings p and
  p+1 besides. The same table is copied into
  `r5e-kernel/test/vectors/identity/ed25519/small-order-points.json` with
  this citation.
  """

  import Bitwise

  # §0, registry v1. Every `keyBytes.algorithm` enum must be a subset of
  # these keys; a new algorithm arrives by a new Kind version, never by
  # widening this map in place.
  @registry %{
    "ed25519" => %{tag: "ed25519", public_key_bytes: 32, signature_bytes: 64}
  }

  # libsodium's ed25519 blacklist (crypto_sign/ed25519/ref10/open.c).
  @small_order [
    # 0 (order 4)
    "0000000000000000000000000000000000000000000000000000000000000000",
    # 1 (order 1)
    "0100000000000000000000000000000000000000000000000000000000000000",
    # 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8)
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    # 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8)
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    # p-1 (order 2)
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    # p (order 4)
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    # p+1 (order 1)
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  ]

  @p 57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_949
  @l 7_237_005_577_332_262_213_973_186_563_042_994_240_857_116_359_379_907_606_001_950_938_285_454_250_989

  @doc "The algorithm registry (§0), v1."
  @spec registry() :: map()
  def registry, do: @registry

  @doc "The registry entry for `algorithm`, or `:error`."
  @spec algorithm(String.t()) :: {:ok, map()} | :error
  def algorithm(name) when is_binary(name), do: Map.fetch(@registry, name)
  def algorithm(_name), do: :error

  @doc "unsigned LEB128 (§0's `uvarint`)."
  @spec uvarint(non_neg_integer()) :: binary()
  def uvarint(n) when is_integer(n) and n >= 0 and n < 128, do: <<n>>

  def uvarint(n) when is_integer(n) and n >= 128 do
    <<1::1, band(n, 0x7F)::7>> <> uvarint(bsr(n, 7))
  end

  @doc """
  §0's key id: `key:<alg>:sha256:<hex>` over
  `uvarint(len(tag)) || tag || publicKeyBytes`. `{:error, reason}` when
  the algorithm is not in the registry or the key is the wrong length.
  """
  @spec key_id(String.t(), binary()) :: {:ok, String.t()} | {:error, String.t()}
  def key_id(algorithm, public_key_bytes) when is_binary(public_key_bytes) do
    case algorithm(algorithm) do
      {:ok, %{tag: tag, public_key_bytes: size}} when byte_size(public_key_bytes) == size ->
        digest = :crypto.hash(:sha256, uvarint(byte_size(tag)) <> tag <> public_key_bytes)
        {:ok, "key:#{algorithm}:sha256:" <> Base.encode16(digest, case: :lower)}

      {:ok, %{public_key_bytes: size}} ->
        {:error,
         "an #{algorithm} public key is #{size} bytes, got #{byte_size(public_key_bytes)}"}

      :error ->
        {:error, "unknown algorithm #{inspect(algorithm)} (§0 registry v1: ed25519)"}
    end
  end

  @doc "`key_id/2`, raising. For code that already knows the key is well formed."
  @spec key_id!(String.t(), binary()) :: String.t()
  def key_id!(algorithm, public_key_bytes) do
    {:ok, id} = key_id(algorithm, public_key_bytes)
    id
  end

  @doc "Whether `id` has the shape of a §0 key id."
  @spec key_id?(term()) :: boolean()
  def key_id?(id) when is_binary(id) do
    case String.split(id, ":") do
      ["key", alg, "sha256", hex] -> Map.has_key?(@registry, alg) and hex64?(hex)
      _ -> false
    end
  end

  def key_id?(_id), do: false

  defp hex64?(hex),
    do: byte_size(hex) == 64 and String.match?(hex, ~r/\A[0-9a-f]{64}\z/)

  @doc """
  §0's base64: standard alphabet, padded, and **canonical** — zero
  trailing bits, length a multiple of 4. Decode-then-re-encode is the
  check, because `Base.decode64/1` accepts non-zero trailing bits.
  """
  @spec decode64(term()) :: {:ok, binary()} | :error
  def decode64(value) when is_binary(value) do
    with true <- rem(byte_size(value), 4) == 0,
         {:ok, bytes} <- Base.decode64(value),
         true <- Base.encode64(bytes) == value do
      {:ok, bytes}
    else
      _ -> :error
    end
  end

  def decode64(_value), do: :error

  @doc "DSSE Pre-Authentication Encoding."
  @spec pae(String.t(), binary()) :: binary()
  def pae(type, payload) when is_binary(type) and is_binary(payload) do
    IO.iodata_to_binary([
      "DSSEv1 ",
      Integer.to_string(byte_size(type)),
      " ",
      type,
      " ",
      Integer.to_string(byte_size(payload)),
      " ",
      payload
    ])
  end

  @doc """
  Verify raw ed25519 under §7's profile: signature over message under a
  32-byte public key, with the pre-checks in this module's doc. `false`
  whenever the profile refuses the input, so a caller cannot tell a
  refused encoding from a bad signature — neither is a valid signature.
  """
  @spec verify_ed25519(binary(), binary(), binary()) :: boolean()
  def verify_ed25519(message, signature, public_key_bytes)
      when is_binary(message) and is_binary(signature) and is_binary(public_key_bytes) do
    ed25519_admissible?(signature, public_key_bytes) and
      :crypto.verify(:eddsa, :none, message, signature, [public_key_bytes, :ed25519])
  end

  def verify_ed25519(_message, _signature, _public_key_bytes), do: false

  @doc "§7's pre-checks alone: whether this key and signature are admissible encodings."
  @spec ed25519_admissible?(binary(), binary()) :: boolean()
  def ed25519_admissible?(signature, public_key_bytes) do
    byte_size(public_key_bytes) == 32 and byte_size(signature) == 64 and
      canonical_point?(public_key_bytes) and not small_order?(public_key_bytes) and
      scalar_below_order?(binary_part(signature, 32, 32))
  end

  # y is the low 255 bits, little-endian; the top bit is the sign of x.
  defp canonical_point?(<<head::binary-size(31), last>>) do
    <<y::little-integer-size(256)>> = head <> <<band(last, 0x7F)>>
    y < @p
  end

  defp small_order?(<<head::binary-size(31), last>>) do
    masked = head <> <<band(last, 0x7F)>>
    Enum.any?(@small_order, &(Base.decode16!(&1, case: :lower) == masked))
  end

  defp scalar_below_order?(<<s::little-integer-size(256)>>), do: s < @l

  @doc "sha256 fingerprint of raw public key bytes — the *checkpoint* key id convention."
  @spec fingerprint(binary()) :: String.t()
  def fingerprint(public_key_bytes), do: RecurseVerify.Canonical.hash_bytes(public_key_bytes)

  @doc """
  Verify an envelope's first signature against raw ed25519 public key
  bytes. `{:ok, payload_bytes, key_id}` when the signature covers the PAE
  of the envelope's own type and payload; `{:error, reason}` otherwise.
  """
  @spec verify(map(), binary()) :: {:ok, binary(), String.t() | nil} | {:error, atom()}
  def verify(
        %{"payloadType" => type, "payload" => payload_b64, "signatures" => [first | _]},
        public_key_bytes
      )
      when is_binary(type) and is_binary(payload_b64) do
    with {:ok, payload} <- b64(payload_b64, :invalid_payload_base64),
         {:ok, sig} <- b64(first["sig"], :invalid_signature_base64) do
      if verify_ed25519(pae(type, payload), sig, public_key_bytes) do
        {:ok, payload, first["keyid"]}
      else
        {:error, :signature_mismatch}
      end
    end
  end

  def verify(_envelope, _public_key_bytes), do: {:error, :malformed_envelope}

  defp b64(value, error_tag) do
    case is_binary(value) && Base.decode64(value) do
      {:ok, bytes} -> {:ok, bytes}
      _ -> {:error, error_tag}
    end
  end
end
