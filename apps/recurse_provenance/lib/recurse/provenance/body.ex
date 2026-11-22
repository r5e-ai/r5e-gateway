defmodule Recurse.Provenance.Body do
  @moduledoc """
  Constructors for the bodies a gateway records (contract §4).

  Each returns the wire map for one kind's `body`. Optional fields that
  are nil are left out, since a closed body schema has no place for a
  null. Shapes are checked against the kind's definition when the record
  is validated, not here.

  A call records the actual request. `policy` is the inline evaluation
  the recorder itself performed, so an ordinary allowed or denied call
  needs no separate decision record. `result` is set only by a recorder
  that observed the whole interaction; a recorder that captures the
  request first records the outcome later as a response or result that
  points back with `call`. A stored record is never changed to add one.
  """

  alias Recurse.Provenance.Evidence

  @doc """
  A `ModelCall` body. Its content is the exact request body; see
  `artifact/1` for `:content_ref`, `:media_type` and `:size`.
  """
  def model_call(fields) do
    f = Map.new(fields)

    put_all(
      Map.merge(artifact(f), %{"provider" => fetch!(f, :provider), "model" => fetch!(f, :model)}),
      policy: f[:policy],
      result: f[:result],
      retryOf: f[:retry_of],
      details: f[:details]
    )
  end

  @doc """
  A `ToolCall` body. Its content is the exact arguments; `:call_id` is
  the identifier the model gave the call, when it gave one.
  """
  def tool_call(fields) do
    f = Map.new(fields)

    put_all(Map.merge(artifact(f), %{"tool" => fetch!(f, :tool)}),
      callId: f[:call_id],
      policy: f[:policy],
      result: f[:result],
      retryOf: f[:retry_of],
      details: f[:details]
    )
  end

  @doc """
  A `ModelResponse` or `ToolResult` body. Its content is the exact
  response or output. `:call` points at the call; a `ToolResult` must
  have it, and may carry the `:call_id` it was returned under.
  """
  def response(fields) do
    f = Map.new(fields)

    put_all(Map.merge(artifact(f), %{"outcome" => fetch!(f, :outcome)}),
      call: f[:call],
      callId: f[:call_id],
      reason: f[:reason],
      details: f[:details]
    )
  end

  @doc """
  The fields every content-carrying kind has, as an Artifact:

    * `:content_ref` — the `bytes:` reference of the exact content, or
      an `attachment:<name>` token for content submitted with the request
    * `:media_type` — what the bytes are
    * `:size` — how many bytes
    * `:derived_from` — references to what the content was made from
  """
  def artifact(fields) do
    f = Map.new(fields)

    put_all(
      %{
        "contentRef" => fetch!(f, :content_ref),
        "mediaType" => fetch!(f, :media_type),
        "size" => fetch!(f, :size)
      },
      derivedFrom: f[:derived_from]
    )
  end

  @doc """
  An inline `PolicyEvaluation`: the policy actually evaluated, the
  outcome (`"allow"`, `"deny"` or `"error"`), and the exact inputs.
  """
  def policy_evaluation(fields) do
    f = Map.new(fields)

    put_all(
      %{
        "policyRef" => fetch!(f, :policy_ref),
        "outcome" => fetch!(f, :outcome),
        "inputRefs" => Map.get(f, :input_refs, [])
      },
      evaluatorRef: f[:evaluator_ref],
      decisionRef: f[:decision_ref],
      activationRef: f[:activation_ref],
      reason: f[:reason]
    )
  end

  @doc "A completed-call `result` for a recorder that saw the whole interaction."
  def call_result(fields) do
    f = Map.new(fields)

    put_all(%{"outcome" => fetch!(f, :outcome), "outputRefs" => Map.get(f, :output_refs, [])},
      reason: f[:reason],
      completedAt: f[:completed_at] && Evidence.timestamp(f[:completed_at])
    )
  end

  @doc "A `SessionOpened` body."
  def session_opened(fields) do
    f = Map.new(fields)

    put_all(%{"session" => fetch!(f, :session)},
      continues: f[:continues],
      contextRefs: f[:context_refs],
      details: f[:details]
    )
  end

  @doc "A `SessionClosed` body; `:through` is the frontier the session reached."
  def session_closed(fields) do
    f = Map.new(fields)

    put_all(
      %{
        "session" => fetch!(f, :session),
        "outcome" => fetch!(f, :outcome),
        "through" => fetch!(f, :through)
      },
      reason: f[:reason],
      details: f[:details]
    )
  end

  @doc "An `Observation` body: a topic and the content that records it."
  def observation(fields) do
    f = Map.new(fields)

    put_all(%{"topic" => fetch!(f, :topic), "contentRefs" => Map.get(f, :content_refs, [])},
      about: f[:about],
      details: f[:details]
    )
  end

  @doc """
  A `Disclosure` body. Give `:scope` (a session) with `:excluding` (the
  content references withheld, possibly none) for a whole session, or
  `:requested_refs` and `:provided_refs` for named pieces. `:recipient`
  is who it was provided to and `:outcome` is `"provided"`, `"partial"`
  or `"denied"`.
  """
  def disclosure(fields) do
    f = Map.new(fields)

    put_all(%{"recipient" => fetch!(f, :recipient), "outcome" => fetch!(f, :outcome)},
      scope: f[:scope],
      excluding: f[:excluding],
      requestedRefs: f[:requested_refs],
      providedRefs: f[:provided_refs],
      policy: f[:policy],
      reason: f[:reason],
      details: f[:details]
    )
  end

  @doc """
  A `DefinitionPublished` body: `:definitions` maps each kind path to the
  reference of the definition document the publisher issues for it.
  `:proposal` names the record the definitions were proposed in, which
  may be on another chain.
  """
  def definition_published(fields) do
    f = Map.new(fields)

    definitions =
      for {kind, ref} <- Enum.sort(fetch!(f, :definitions)),
          do: %{"kind" => kind, "definition" => ref}

    put_all(%{"definitions" => definitions},
      package: f[:package],
      manifestRef: f[:manifest_ref],
      previous: f[:previous],
      proposal: f[:proposal],
      details: f[:details]
    )
  end

  defp fetch!(map, key), do: Map.fetch!(map, key)

  defp put_all(map, optional) do
    Enum.reduce(optional, map, fn
      {_key, nil}, acc -> acc
      {key, value}, acc -> Map.put(acc, Atom.to_string(key), value)
    end)
  end
end
