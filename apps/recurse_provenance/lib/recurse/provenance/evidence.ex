defmodule Recurse.Provenance.Evidence do
  @moduledoc """
  The Evidence payload: one attributed, signed fact (contract §3).

  An evidence value here is the wire map itself, with string keys, so
  what is validated is what is encoded and signed. Its identity is the
  hash of its Core canonical bytes; the signature is not part of it.
  """

  alias Recurse.Provenance.{Definitions, Ref, Schema}
  alias RecurseVerify.Canonical

  @type t :: %{String.t() => term()}
  @type problem :: Schema.problem()

  @doc """
  Assemble the wire map from named fields.

  Required: `:kind_path`, `:schema_ref`, `:profile_ref`, `:issuer`,
  `:actor`, `:stream`, `:seq`, `:previous`, `:captured_at`, `:body`.
  Optional: `:occurred_at`, `:session`, `:subject`, `:identity_ref`,
  `:on_behalf_of`, `:context_refs`, `:causes`. Causes are sorted and
  de-duplicated; empty optional lists are left out.
  """
  @spec new(keyword() | map()) :: t()
  def new(fields) do
    f = Map.new(fields)
    {api_version, kind} = split_kind_path!(Map.fetch!(f, :kind_path))

    %{
      "apiVersion" => api_version,
      "kind" => kind,
      "schemaRef" => Map.fetch!(f, :schema_ref),
      "profileRef" => Map.fetch!(f, :profile_ref),
      "issuer" => Map.fetch!(f, :issuer),
      "actor" => Map.fetch!(f, :actor),
      "stream" => Map.fetch!(f, :stream),
      "seq" => Map.fetch!(f, :seq),
      "previous" => Map.fetch!(f, :previous),
      "capturedAt" => timestamp(Map.fetch!(f, :captured_at)),
      "body" => Map.fetch!(f, :body)
    }
    |> put_optional("occurredAt", f[:occurred_at] && timestamp(f[:occurred_at]))
    |> put_optional("session", f[:session])
    |> put_optional("subject", f[:subject])
    |> put_optional("identityRef", f[:identity_ref])
    |> put_optional("onBehalfOf", f[:on_behalf_of])
    |> put_optional("contextRefs", nonempty(f[:context_refs]))
    |> put_optional("causes", nonempty(f[:causes] && f[:causes] |> Enum.uniq() |> Enum.sort()))
  end

  @doc "`<apiVersion>/<kind>` of an evidence value."
  @spec kind_path(t()) :: String.t()
  def kind_path(%{"apiVersion" => api_version, "kind" => kind}),
    do: Definitions.kind_path(api_version, kind)

  @doc "Core canonical bytes of an evidence value. These are what is signed."
  @spec encode(t()) :: {:ok, binary()} | {:error, String.t()}
  def encode(evidence) when is_map(evidence) do
    {:ok, Canonical.encode(evidence)}
  rescue
    e in ArgumentError -> {:error, Exception.message(e)}
  end

  @doc "The `evidence:` reference of canonical payload bytes."
  @spec ref(binary()) :: Ref.t()
  def ref(payload) when is_binary(payload), do: Ref.evidence(payload)

  @doc """
  Check an evidence value: the common envelope, the ordering of `causes`,
  and its body against the definition its `schemaRef` names.

  `:definitions` is a function from a `schemaRef` to `{:ok, schema}` for
  installed extension definitions; base definitions are always known.
  `:signers` is the key ids that signed the record, in order; with it the
  number of signatures and any field a definition binds to a signer are
  checked too.

  Returns `{:ok, :validated}` when the body was checked against its
  definition, or `{:ok, :body_unsupported}` when the envelope is sound but
  the definition is not installed here. A reader must not report the
  latter as an understood body.
  """
  @spec validate(t(), keyword()) :: {:ok, :validated | :body_unsupported} | {:error, [problem()]}
  def validate(evidence, opts \\ []) do
    with :ok <- Schema.validate(Definitions.envelope_schema(), evidence),
         :ok <- causes_ordered(evidence),
         {:ok, status} <- body(evidence, opts),
         :ok <- session_agrees(evidence) do
      {:ok, status}
    end
  end

  defp body(evidence, opts) do
    fetch_bytes = Keyword.get(opts, :definitions, fn _ref -> :error end)

    case Definitions.check(
           kind_path(evidence),
           evidence["schemaRef"],
           evidence["body"],
           fetch_bytes,
           Keyword.get(opts, :signers)
         ) do
      :ok ->
        {:ok, :validated}

      # The definition is not one this reader holds or was given.
      :unavailable ->
        {:ok, :body_unsupported}

      {:error, :definition_is_for_another_kind} ->
        {:error, [{"/schemaRef", "definition_is_for_another_kind"}]}

      {:error, :signature_count_differs} ->
        {:error, [{"/signatures", "signature_count_differs_from_definition"}]}

      {:error, violations} ->
        {:error, Enum.map(violations, &{"/body" <> String.trim_leading(&1.path, "$"), &1.code})}
    end
  end

  defp causes_ordered(%{"causes" => causes}) do
    if causes == Enum.sort(causes) and causes == Enum.uniq(causes),
      do: :ok,
      else: {:error, [{"/causes", "must be sorted and unique"}]}
  end

  defp causes_ordered(_evidence), do: :ok

  # When a session record also carries the common `session`, they agree.
  defp session_agrees(%{"session" => common, "body" => %{"session" => body}, "kind" => kind})
       when kind in ["SessionOpened", "SessionClosed"] and common != body,
       do: {:error, [{"/session", "differs from body.session"}]}

  defp session_agrees(_evidence), do: :ok

  defp split_kind_path!(path) do
    case path |> String.split("/") |> Enum.split(-1) do
      {[_ | _] = group, [kind]} -> {Enum.join(group, "/"), kind}
      _ -> raise ArgumentError, "not a kind path: #{inspect(path)}"
    end
  end

  @doc "A UTC instant in the wire form (RFC 3339, `Z`)."
  @spec timestamp(DateTime.t() | String.t()) :: String.t()
  def timestamp(%DateTime{} = at),
    do: at |> DateTime.shift_zone!("Etc/UTC") |> DateTime.to_iso8601()

  def timestamp(text) when is_binary(text), do: text

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)

  defp nonempty([]), do: nil
  defp nonempty(other), do: other

  @doc """
  What a record's content is kept, read and disposed of together with:
  its session, or its stream when it has none. `nil` for a seal or a
  checkpoint, whose manifest is structure every reader needs, and for a
  hold, a release or a disposal, which are the records that keep and
  dispose of other records' content and have none of their own.
  """
  @spec content_scope(t()) :: String.t() | nil
  def content_scope(evidence) do
    cond do
      evidence["kind"] in ~w[EpochSeal Checkpoint RetentionHold RetentionHoldRelease
                              PayloadDisposition] ->
        nil

      is_binary(evidence["session"]) ->
        evidence["session"]

      true ->
        "stream:" <> evidence["stream"]
    end
  end

  @doc """
  A record's content scope together with who the session belongs to:
  the person the record says it was made for. A store that encrypts can
  lock a session's key under its owner's, so that one person's content
  across all their sessions is disposed of together. Only a session has
  an owner; any other scope is given as it is.

  Only `onBehalfOf` names an owner. Whoever captures a record sets it
  from an identity it has verified and from nothing else: an `actor`
  can be a name a client merely claimed, and an owner chosen by a claim
  would let one person put content under, or keep it out from under,
  another's key.
  """
  @spec content_owner(t()) :: String.t() | {String.t(), String.t()} | nil
  def content_owner(evidence) do
    scope = content_scope(evidence)
    subject = evidence["onBehalfOf"]

    if is_binary(scope) and scope == evidence["session"] and is_binary(subject),
      do: {scope, subject},
      else: scope
  end
end
