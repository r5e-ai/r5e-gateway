defmodule Recurse.Gateway.Provenance.Signer do
  @moduledoc """
  A `Recurse.Provenance.Key` signer over the deployment's SecretsProvider.

  The provider keeps the private key (local PEM, KMS, Vault); this adapts
  its document-signing key to the evidence wire forms. The key id is
  derived from the public key bytes, so it does not change when the same
  key is reached through another provider, and it is not a provider's
  name for the key.
  """

  alias Recurse.Provenance.Key

  @doc "Build a signer from a SecretsProvider module and its state."
  @spec from_secrets(module(), term()) :: {:ok, Key.signer()} | {:error, term()}
  def from_secrets(module, state) do
    with {:ok, handle} <- module.active_signing_key(state),
         {:ok, pem} <- module.public_key(state, handle),
         {:ok, algorithm, public_key} <- public_key_bytes(pem),
         {:ok, key_id} <- key_id(algorithm, public_key) do
      {:ok,
       %{
         algorithm: algorithm,
         key_id: key_id,
         public_key: public_key,
         sign: fn message ->
           with {:ok, signature} <- module.sign(state, handle, message),
                do: wire_signature(algorithm, signature)
         end
       }}
    end
  end

  @doc "The algorithm and raw public key bytes inside a SubjectPublicKeyInfo PEM."
  @spec public_key_bytes(binary()) :: {:ok, Key.algorithm(), binary()} | {:error, term()}
  def public_key_bytes(pem) when is_binary(pem) do
    with [{:SubjectPublicKeyInfo, der, _} | _] <- :public_key.pem_decode(pem),
         {:SubjectPublicKeyInfo, _algorithm, bytes} <-
           :public_key.der_decode(:SubjectPublicKeyInfo, der) do
      case byte_size(bytes) do
        65 -> {:ok, "es256", bytes}
        32 -> {:ok, "ed25519", bytes}
        _ -> {:error, :unsupported_public_key}
      end
    else
      _ -> {:error, :unreadable_public_key}
    end
  rescue
    _ -> {:error, :unreadable_public_key}
  end

  defp key_id(algorithm, public_key) do
    case Key.id(algorithm, public_key) do
      {:ok, id} -> {:ok, id}
      {:error, reason} -> {:error, {:public_key_refused, reason}}
    end
  end

  # ES256 providers answer in DER; the wire form is the 64-byte low-S pair.
  defp wire_signature("es256", signature) do
    case Key.es256_raw_from_der(signature) do
      {:ok, raw} -> {:ok, raw}
      {:error, _} when byte_size(signature) == 64 -> normalise_raw(signature)
      {:error, reason} -> {:error, reason}
    end
  end

  defp wire_signature("ed25519", signature) when byte_size(signature) == 64, do: {:ok, signature}
  defp wire_signature(_algorithm, _signature), do: {:error, :unexpected_signature_form}

  defp normalise_raw(<<r::unsigned-256, s::unsigned-256>>) do
    {:"ECDSA-Sig-Value", r, s}
    |> then(&:public_key.der_encode(:"ECDSA-Sig-Value", &1))
    |> Key.es256_raw_from_der()
  end
end
