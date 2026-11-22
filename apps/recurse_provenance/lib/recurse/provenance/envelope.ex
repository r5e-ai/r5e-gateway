defmodule Recurse.Provenance.Envelope do
  @moduledoc """
  The signed form of one evidence record: a DSSE envelope (contract §3).

  The wrapper has exactly `payloadType`, `payload` and `signatures`. Every
  signature is over the same message, the DSSE pre-authentication encoding
  of the payload. The first signature is the issuer's; a kind whose
  definition asks for more than one signature has the others after it, in
  the positions the definition's `matchesSigner` rules name. No key signs
  twice. The payload is the base64 of the record's Core canonical bytes,
  and the record's reference is the hash of those bytes alone, so it does
  not depend on who signed. Public keys travel separately; holding a key
  that verifies a signature says nothing about whether that signer was
  authorized.
  """

  alias Recurse.Provenance.{Definitions, Evidence, Key, Ref, Schema}
  alias RecurseVerify.{Canonical, DSSE}

  @payload_type "application/vnd.r5e.provenance-evidence+json;v=2"

  @type t :: %{String.t() => term()}
  @type opened :: %{
          evidence: Evidence.t(),
          payload: binary(),
          ref: Ref.t(),
          signatures: [%{keyid: String.t(), signature: binary()}]
        }
  @type keys :: %{String.t() => %{algorithm: String.t(), bytes: binary()}}

  @doc "The DSSE payload type of a v2 evidence record."
  @spec payload_type() :: String.t()
  def payload_type, do: @payload_type

  @doc """
  Sign an evidence value. Pass one signer, or a list in signer order. The
  first signer's key id must be the record's `issuer`, and no key may
  appear twice. Returns the envelope, the canonical payload and its
  reference.
  """
  @spec sign(Evidence.t(), Key.signer() | [Key.signer(), ...]) ::
          {:ok, %{envelope: t(), payload: binary(), ref: Ref.t()}} | {:error, term()}
  def sign(evidence, %{key_id: _} = signer), do: sign(evidence, [signer])

  def sign(%{"issuer" => issuer} = evidence, [%{key_id: first} | _] = signers) do
    with true <- issuer == first || {:error, :issuer_is_not_signer},
         :ok <- distinct(Enum.map(signers, & &1.key_id)),
         {:ok, payload} <- Evidence.encode(evidence),
         {:ok, signatures} <- sign_each(signers, DSSE.pae(@payload_type, payload)) do
      envelope = %{
        "payloadType" => @payload_type,
        "payload" => Base.encode64(payload),
        "signatures" => signatures
      }

      {:ok, %{envelope: envelope, payload: payload, ref: Evidence.ref(payload)}}
    end
  end

  defp sign_each(signers, message) do
    Enum.reduce_while(signers, {:ok, []}, fn %{key_id: key_id, sign: sign}, {:ok, acc} ->
      case sign.(message) do
        {:ok, signature} ->
          {:cont, {:ok, acc ++ [%{"keyid" => key_id, "sig" => Base.encode64(signature)}]}}

        {:error, _} = error ->
          {:halt, error}
      end
    end)
  end

  @doc """
  Put an envelope together from canonical payload bytes and signatures
  made elsewhere, in signer order. Nothing is checked here; `open/1` and
  `verify_each/2` are how the result is read.

  This is how a record that two parties sign comes to exist: each signs
  the same message (`message/1`) on its own machine, and whoever holds
  both signatures assembles them.
  """
  @spec assemble(binary(), [{String.t(), binary()}, ...]) :: t()
  def assemble(payload, [_ | _] = signatures) when is_binary(payload) do
    %{
      "payloadType" => @payload_type,
      "payload" => Base.encode64(payload),
      "signatures" =>
        for(
          {key_id, signature} <- signatures,
          do: %{"keyid" => key_id, "sig" => Base.encode64(signature)}
        )
    }
  end

  @doc "The bytes every signer of a record with this payload signs."
  @spec message(binary()) :: binary()
  def message(payload) when is_binary(payload), do: DSSE.pae(@payload_type, payload)

  @doc """
  Read an envelope without checking its signatures.

  Checks the wrapper shape, that every base64 value is canonically
  spelled, that the payload bytes are exactly the Core canonical encoding
  of the value they decode to, that the first signature's key id is the
  record's issuer, and that no key id appears twice. A differently encoded
  payload is refused, never re-canonicalized into the same record.
  """
  @spec open(term()) :: {:ok, opened()} | {:error, term()}
  def open(envelope) do
    with :ok <- shape(envelope),
         %{"payload" => payload64, "signatures" => entries} = envelope,
         {:ok, payload} <- canonical_base64(payload64, :payload),
         {:ok, signatures} <- decode_signatures(entries),
         {:ok, evidence} <- decode(payload),
         :ok <- issuer(evidence, hd(signatures).keyid),
         :ok <- distinct(Enum.map(signatures, & &1.keyid)) do
      {:ok,
       %{
         evidence: evidence,
         payload: payload,
         ref: Evidence.ref(payload),
         signatures: signatures
       }}
    end
  end

  defp decode_signatures(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn %{"keyid" => keyid, "sig" => sig64}, {:ok, acc} ->
      case canonical_base64(sig64, :signature) do
        {:ok, signature} -> {:cont, {:ok, acc ++ [%{keyid: keyid, signature: signature}]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp distinct(keyids) do
    if Enum.uniq(keyids) == keyids, do: :ok, else: {:error, :duplicate_signer}
  end

  @doc "The key ids that signed an opened envelope, in signer order."
  @spec signers(opened()) :: [String.t()]
  def signers(%{signatures: signatures}), do: Enum.map(signatures, & &1.keyid)

  @doc """
  Check every signature of an opened envelope against supplied public keys.

  `keys` maps a key id to `%{algorithm: _, bytes: _}`; the key bytes must
  hash to the key id they are filed under. Returns one result per
  signature, in signer order.
  """
  @spec verify_each(opened(), keys()) ::
          [{String.t(), :ok | {:error, :missing_key | :key_mismatch | :bad_signature}}]
  def verify_each(%{payload: payload, signatures: signatures}, keys) when is_map(keys) do
    message = DSSE.pae(@payload_type, payload)
    Enum.map(signatures, fn s -> {s.keyid, verify_one(s, message, keys)} end)
  end

  @doc """
  `:ok` when every signature verifies; otherwise the first signature's
  problem, in signer order.
  """
  @spec verify(opened(), keys()) ::
          :ok | {:error, :missing_key | :key_mismatch | :bad_signature}
  def verify(opened, keys) when is_map(keys) do
    Enum.find_value(verify_each(opened, keys), :ok, fn
      {_keyid, :ok} -> nil
      {_keyid, error} -> error
    end)
  end

  defp verify_one(%{keyid: keyid, signature: signature}, message, keys) do
    with {:ok, %{algorithm: algorithm, bytes: bytes}} <- fetch_key(keys, keyid),
         {:ok, id} <- key_id(algorithm, bytes),
         true <- id == keyid || {:error, :key_mismatch},
         true <- Key.verify(algorithm, message, signature, bytes) || {:error, :bad_signature} do
      :ok
    end
  end

  defp fetch_key(keys, keyid) do
    case Map.fetch(keys, keyid) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, :missing_key}
    end
  end

  defp key_id(algorithm, bytes) do
    case Key.id(algorithm, bytes) do
      {:ok, id} -> {:ok, id}
      {:error, _} -> {:error, :key_mismatch}
    end
  end

  defp shape(envelope) do
    case is_map(envelope) and Schema.validate(Definitions.signed_schema(), envelope) do
      :ok -> :ok
      false -> {:error, :malformed_envelope}
      {:error, problems} -> {:error, {:malformed_envelope, problems}}
    end
  end

  defp canonical_base64(text, what) do
    case Base.decode64(text) do
      {:ok, raw} when raw != "" ->
        if Base.encode64(raw) == text,
          do: {:ok, raw},
          else: {:error, {:noncanonical_base64, what}}

      _ ->
        {:error, {:invalid_base64, what}}
    end
  end

  defp decode(payload) do
    with {:ok, term} when is_map(term) <- Canonical.decode_json(payload),
         true <- Canonical.encode(term) == payload do
      {:ok, term}
    else
      false -> {:error, :payload_not_canonical}
      {:ok, _not_object} -> {:error, :payload_not_an_object}
      {:error, reason} -> {:error, {:payload_not_canonical, reason}}
    end
  end

  defp issuer(%{"issuer" => keyid}, keyid), do: :ok
  defp issuer(_evidence, _keyid), do: {:error, :issuer_is_not_signer}
end
