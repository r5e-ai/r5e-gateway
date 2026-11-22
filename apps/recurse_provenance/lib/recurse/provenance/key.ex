defmodule Recurse.Provenance.Key do
  @moduledoc """
  Signing keys and signature checks for evidence (contract §3).

  Three algorithms are registered: `ed25519`, `es256` and `es384`.

  A key id is `key:<alg>:sha256:<hex>`, the hash of
  `uvarint(len(tag)) || tag || public key bytes` (Core §0). The algorithm
  tag is inside the hash, so the same bytes under another algorithm are a
  different key. A key id is derived from the key itself and is never
  granted by a platform.

  Wire forms:

    * `ed25519` — 32-byte public key, 64-byte signature, Core's profile
      (canonical point, not small order, `S` below the group order).
    * `es256` — 65-byte uncompressed SEC1 P-256 public key; signature is
      the 64 bytes `r || s` with both in range and `s` in the low half,
      over SHA-256 of the message taken once. DER is never the wire form;
      `es256_raw_from_der/1` converts what a KMS returns.
    * `es384` — the same on P-384: 97-byte uncompressed public key,
      96-byte `r || s` signature in the low half, over SHA-384 of the
      message. It is here for hardware keys and regimes that require it.
  """

  alias RecurseVerify.DSSE, as: Core

  @p256_p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @p256_b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  @p256_n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  @p384_p Integer.pow(2, 384) - Integer.pow(2, 128) - Integer.pow(2, 96) + Integer.pow(2, 32) - 1
  @p384_b 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
  @p384_n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

  @algorithms %{
    "ed25519" => %{public_key_bytes: 32, signature_bytes: 64},
    "es256" => %{public_key_bytes: 65, signature_bytes: 64},
    "es384" => %{public_key_bytes: 97, signature_bytes: 96}
  }

  @type algorithm :: String.t()
  @type signer :: %{
          algorithm: algorithm(),
          key_id: String.t(),
          public_key: binary(),
          sign: (binary() -> {:ok, binary()} | {:error, term()})
        }

  @doc "The registered algorithm names."
  @spec algorithms() :: [algorithm()]
  def algorithms, do: Map.keys(@algorithms)

  @doc "The key id for a public key under an algorithm."
  @spec id(algorithm(), binary()) :: {:ok, String.t()} | {:error, String.t()}
  def id(algorithm, public_key) when is_binary(public_key) do
    with {:ok, %{public_key_bytes: size}} <- Map.fetch(@algorithms, algorithm),
         true <- byte_size(public_key) == size,
         true <- admissible_public_key?(algorithm, public_key) do
      digest =
        :crypto.hash(:sha256, Core.uvarint(byte_size(algorithm)) <> algorithm <> public_key)

      {:ok, "key:#{algorithm}:sha256:" <> Base.encode16(digest, case: :lower)}
    else
      :error -> {:error, "unknown algorithm #{inspect(algorithm)}"}
      false -> {:error, "not an admissible #{algorithm} public key"}
    end
  end

  @doc "The algorithm named in a key id, when it is registered."
  @spec algorithm_of(term()) :: {:ok, algorithm()} | :error
  def algorithm_of("key:" <> rest) do
    case String.split(rest, ":") do
      [alg, "sha256", hex] when is_map_key(@algorithms, alg) and byte_size(hex) == 64 ->
        {:ok, alg}

      _ ->
        :error
    end
  end

  def algorithm_of(_other), do: :error

  @doc """
  Check a raw signature over `message` under a public key.

  `false` for a bad signature and for any encoding the profile refuses;
  neither is a valid signature.
  """
  @spec verify(algorithm(), binary(), binary(), binary()) :: boolean()
  def verify("ed25519", message, signature, public_key),
    do: Core.verify_ed25519(message, signature, public_key)

  def verify("es256", message, <<r::unsigned-256, s::unsigned-256>>, public_key)
      when is_binary(message) and byte_size(public_key) == 65 do
    r >= 1 and r < @p256_n and s >= 1 and s <= div(@p256_n, 2) and
      admissible_public_key?("es256", public_key) and
      :crypto.verify(:ecdsa, :sha256, message, der(r, s), [public_key, :secp256r1])
  end

  def verify("es384", message, <<r::unsigned-384, s::unsigned-384>>, public_key)
      when is_binary(message) and byte_size(public_key) == 97 do
    r >= 1 and r < @p384_n and s >= 1 and s <= div(@p384_n, 2) and
      admissible_public_key?("es384", public_key) and
      :crypto.verify(:ecdsa, :sha384, message, der(r, s), [public_key, :secp384r1])
  end

  def verify(_algorithm, _message, _signature, _public_key), do: false

  @doc """
  Convert a DER ECDSA signature to the 96-byte low-S `r || s` wire form of
  `es384`.
  """
  @spec es384_raw_from_der(binary()) :: {:ok, <<_::768>>} | {:error, :invalid_der}
  def es384_raw_from_der(der) when is_binary(der) do
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)

    if r >= 1 and r < @p384_n and s >= 1 and s < @p384_n do
      s = if s > div(@p384_n, 2), do: @p384_n - s, else: s
      {:ok, <<r::unsigned-384, s::unsigned-384>>}
    else
      {:error, :invalid_der}
    end
  rescue
    _ -> {:error, :invalid_der}
  end

  @doc """
  Convert a DER ECDSA signature to the 64-byte low-S `r || s` wire form.
  """
  @spec es256_raw_from_der(binary()) :: {:ok, <<_::512>>} | {:error, :invalid_der}
  def es256_raw_from_der(der) when is_binary(der) do
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der)

    if r >= 1 and r < @p256_n and s >= 1 and s < @p256_n do
      s = if s > div(@p256_n, 2), do: @p256_n - s, else: s
      {:ok, <<r::unsigned-256, s::unsigned-256>>}
    else
      {:error, :invalid_der}
    end
  rescue
    _ -> {:error, :invalid_der}
  end

  @doc "Generate a local key pair. For tests and local-appliance signing."
  @spec generate(algorithm()) :: signer()
  def generate("ed25519") do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    local_signer("ed25519", public, private)
  end

  def generate("es256") do
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    local_signer("es256", public, private)
  end

  def generate("es384") do
    {public, private} = :crypto.generate_key(:ecdh, :secp384r1)
    local_signer("es384", public, private)
  end

  @doc """
  A signer over a private key held in a PEM file (PKCS#8 or SEC1), for
  the few keys used by hand and kept offline, such as a publisher's.
  A serving machine reaches its key through its secrets provider
  instead.
  """
  @spec signer_from_pem(binary()) :: {:ok, signer()} | {:error, :unreadable_private_key}
  def signer_from_pem(pem) when is_binary(pem) do
    with [entry] <- :public_key.pem_decode(pem),
         {:ECPrivateKey, _version, private, {:namedCurve, curve}, _public, _} <-
           :public_key.pem_entry_decode(entry),
         {:ok, algorithm, type, name} <- curve(curve) do
      {public, _} = :crypto.generate_key(type, name, private)
      {:ok, local_signer(algorithm, public, private)}
    else
      _ -> {:error, :unreadable_private_key}
    end
  rescue
    _ -> {:error, :unreadable_private_key}
  end

  defp curve({1, 3, 101, 112}), do: {:ok, "ed25519", :eddsa, :ed25519}
  defp curve({1, 2, 840, 10_045, 3, 1, 7}), do: {:ok, "es256", :ecdh, :secp256r1}
  defp curve({1, 3, 132, 0, 34}), do: {:ok, "es384", :ecdh, :secp384r1}
  defp curve(_other), do: :error

  @doc "A signer over locally held private key bytes."
  @spec local_signer(algorithm(), binary(), binary()) :: signer()
  def local_signer("ed25519" = algorithm, public, private) do
    {:ok, key_id} = id(algorithm, public)

    %{
      algorithm: algorithm,
      key_id: key_id,
      public_key: public,
      sign: fn message ->
        {:ok, :crypto.sign(:eddsa, :none, message, [private, :ed25519])}
      end
    }
  end

  def local_signer("es256" = algorithm, public, private) do
    {:ok, key_id} = id(algorithm, public)

    %{
      algorithm: algorithm,
      key_id: key_id,
      public_key: public,
      sign: fn message ->
        :ecdsa
        |> :crypto.sign(:sha256, message, [private, :secp256r1])
        |> es256_raw_from_der()
      end
    }
  end

  def local_signer("es384" = algorithm, public, private) do
    {:ok, key_id} = id(algorithm, public)

    %{
      algorithm: algorithm,
      key_id: key_id,
      public_key: public,
      sign: fn message ->
        :ecdsa
        |> :crypto.sign(:sha384, message, [private, :secp384r1])
        |> es384_raw_from_der()
      end
    }
  end

  @doc """
  A signer backed by an external service that returns DER ECDSA
  signatures over SHA-256 of the message (a KMS `ECDSA_SHA_256` key).
  """
  @spec es256_der_signer(binary(), (binary() -> {:ok, binary()} | {:error, term()})) ::
          {:ok, signer()} | {:error, String.t()}
  def es256_der_signer(public_key, sign_der) when is_function(sign_der, 1) do
    with {:ok, key_id} <- id("es256", public_key) do
      {:ok,
       %{
         algorithm: "es256",
         key_id: key_id,
         public_key: public_key,
         sign: fn message ->
           with {:ok, der} <- sign_der.(message), do: es256_raw_from_der(der)
         end
       }}
    end
  end

  # -- admissibility -----------------------------------------------------

  defp admissible_public_key?("ed25519", public_key) do
    # Core's pre-checks need a signature too; an all-zero scalar half is
    # below the group order, so this isolates the public-key checks.
    Core.ed25519_admissible?(<<0::512>>, public_key) and ed25519_on_curve?(public_key)
  end

  defp admissible_public_key?("es256", <<4, x::unsigned-256, y::unsigned-256>>) do
    x < @p256_p and y < @p256_p and
      rem(y * y, @p256_p) == rem(x * x * x + (@p256_p - 3) * x + @p256_b, @p256_p)
  end

  defp admissible_public_key?("es384", <<4, x::unsigned-384, y::unsigned-384>>) do
    x < @p384_p and y < @p384_p and
      rem(y * y, @p384_p) == rem(x * x * x + (@p384_p - 3) * x + @p384_b, @p384_p)
  end

  defp admissible_public_key?(_algorithm, _public_key), do: false

  @ed_p Integer.pow(2, 255) - 19
  # d = -121665 / 121666 mod p
  @ed_d 37_095_705_934_669_439_343_138_083_508_754_565_189_542_113_879_843_219_016_388_785_533_085_940_283_555

  # Whether the encoded y has an x on the curve: x^2 = (y^2 - 1) / (d y^2 + 1)
  # must be a square. Libraries disagree on when they notice an encoding
  # with no point behind it (some when loading the key, some only when
  # verifying), so the check is made here, the same for all of them.
  defp ed25519_on_curve?(<<head::binary-31, last>>) do
    <<y::little-unsigned-256>> = head <> <<Bitwise.band(last, 0x7F)>>
    u = Integer.mod(y * y - 1, @ed_p)
    v = Integer.mod(@ed_d * y * y + 1, @ed_p)
    x2 = Integer.mod(u * mod_pow(v, @ed_p - 2, @ed_p), @ed_p)
    x2 == 0 or mod_pow(x2, div(@ed_p - 1, 2), @ed_p) == 1
  end

  defp mod_pow(base, exponent, modulus),
    do: :binary.decode_unsigned(:crypto.mod_pow(base, exponent, modulus))

  defp der(r, s), do: :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s})
end
