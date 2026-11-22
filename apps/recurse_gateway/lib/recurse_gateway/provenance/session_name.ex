defmodule Recurse.Gateway.Provenance.SessionName do
  @moduledoc """
  The name a session is recorded under.

  A client chooses its own session id, and nothing about that id says
  whose session it is. If the recorded name were only the tenant and
  that id, anyone naming another person's id would have their records
  filed in that person's session. So the recorded name also carries a
  short fingerprint of who the session belongs to:

      urn:r5e:session:<tenant>:<fingerprint>.<id>

  The fingerprint is worked out from the caller's own identity, which
  the gateway already has in hand on every call, so nothing is looked
  up. The same id from two people names two different sessions, and
  neither can reach the other's.

  The fingerprint is the first sixteen hex characters of the SHA-256 of
  the principal's name. It is there to keep sessions apart, not to hide
  who the principal is: every record in the session names its actor.
  """

  @prefix "urn:r5e:session:"
  # `\A` and `\z`, not `^` and `$`: `$` also matches before a final
  # newline. The id is the client's, percent-encoded, and a client's id
  # of up to 128 bytes can grow to three times that.
  @name ~r/\Aurn:r5e:session:([A-Za-z0-9._~%-]+):([0-9a-f]{16})\.([A-Za-z0-9._~%-]{1,384})\z/

  @doc "The fingerprint of a principal, as it appears in a session's name."
  @spec fingerprint(String.t()) :: String.t()
  def fingerprint(principal) when is_binary(principal) do
    :crypto.hash(:sha256, principal) |> Base.encode16(case: :lower) |> binary_part(0, 16)
  end

  @doc """
  The recorded name of `principal`'s session `id` in `tenant`. Tenant
  and id are written as the client gave them, percent-encoded.
  """
  @spec for(term(), String.t(), term()) :: String.t()
  def for(tenant, principal, id) do
    @prefix <> encode(tenant) <> ":" <> fingerprint(principal) <> "." <> encode(id)
  end

  @doc "Tenant, fingerprint and id of a recorded name, or `:error` if it is not one."
  @spec parts(term()) ::
          {:ok, %{tenant: String.t(), fingerprint: String.t(), id: String.t()}} | :error
  def parts(session) when is_binary(session) do
    case Regex.run(@name, session) do
      [_, tenant, fingerprint, id] -> {:ok, %{tenant: tenant, fingerprint: fingerprint, id: id}}
      _ -> :error
    end
  end

  def parts(_other), do: :error

  @doc "Whether a recorded name is one of `principal`'s sessions."
  @spec owned_by?(term(), String.t()) :: boolean()
  def owned_by?(session, principal) do
    case parts(session) do
      {:ok, %{fingerprint: fingerprint}} -> fingerprint == fingerprint(principal)
      :error -> false
    end
  end

  @doc "Percent-encode a tenant or an id the way a recorded name carries it."
  @spec encode(term()) :: String.t()
  def encode(value), do: URI.encode(to_string(value), &URI.char_unreserved?/1)
end
