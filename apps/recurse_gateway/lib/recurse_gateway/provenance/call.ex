defmodule Recurse.Gateway.Provenance.Call do
  @moduledoc """
  One proxied model call, as Provenance v2 evidence.

  A call becomes a short run of records on the gateway's stream:

    1. `ModelCall` — the request as sent: provider, model, the hash of
       the exact request body.
    2. `ToolResult` — one per tool output the request carried back to
       the model, pointing at the `ToolCall` recorded when the model
       proposed that call (see `ToolResults`). The gateway did not see
       the tool run; the record says what the client told the model.
    3. `ToolCall` — one per tool the model proposed, each with the inline
       policy evaluation the gate performed for it: the exact policy
       bytes, the outcome, the reason on a denial. A denied call carries
       `result.outcome = "denied"`; nothing was released for it. Each
       names the model call as its cause.
    4. `ModelResponse` — what came back, pointing at the model call:
       outcome, the hash of the exact response bytes, and how the bytes
       were read (parser, completeness, tokens, status, latency).

  The actor on every record is the caller the gateway identified. The
  issuer is the gateway. How the caller was identified travels in
  `details`, so a reader can tell a verified identity from one the client
  merely stated.

  All records of one call share a session, so they land in one stream in
  order. They are captured together when the call closes, which is what
  the proxy observes today. The shapes are the request-first ones,
  so moving a capture earlier in the stream changes when a record is
  written and nothing about what it says.
  """

  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Provenance.{Runtime, ToolResults}
  alias Recurse.Provenance.{Body, Definitions, Pipeline}
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @base Definitions.api_version()

  @doc """
  Record a closed call. Returns the `evidence:` reference of its
  `ModelCall`, which stands for the call wherever one id is needed.
  """
  @spec record(map()) :: {:ok, String.t()} | {:error, term()}
  def record(call_state) do
    pipeline = Runtime.pipeline()
    common = common(call_state)

    result =
      with {:ok, call} <- Pipeline.capture(pipeline, model_call(call_state, common)),
           :ok <- tool_results(pipeline, call_state, common, call.ref),
           :ok <- tool_calls(pipeline, call_state, common, call.ref),
           {:ok, _response} <-
             Pipeline.capture(pipeline, model_response(call_state, common, call.ref)) do
        {:ok, call.ref}
      end

    # Spooled bodies were moved into the content directory when their
    # record was prepared, or the capture failed; either way the
    # temporary files are done with.
    PayloadCapture.discard(Map.get(call_state, :request_payload))
    PayloadCapture.discard(Map.get(call_state, :response_payload))
    result
  end

  defp tool_calls(pipeline, call_state, common, call_ref) do
    Enum.reduce_while(call_state.intents, :ok, fn {intent, decision}, :ok ->
      case Pipeline.capture(pipeline, tool_call(call_state, common, call_ref, intent, decision)) do
        {:ok, receipt} ->
          # So the result, when the client sends it back, can name this
          # record. A call the gate denied was never run and has none.
          if decision == {:allow} and answered?(call_state),
            do: ToolResults.remember(owner(call_state), intent.call_id, receipt.ref)

          {:cont, :ok}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end

  # A result is recorded only when the call it answers was recorded here
  # for the same caller presenting the same credential, and only from a
  # request the provider accepted: a request it turned away proves
  # nothing about who sent it. One that cannot be recorded does not stop
  # the call being recorded: the output is in the request either way.
  defp tool_results(pipeline, call_state, common, call_ref) do
    for result <- Map.get(call_state, :tool_results, []),
        answered?(call_state),
        {:ok, tool_call} <- [ToolResults.take(owner(call_state), result.call_id)] do
      case Pipeline.capture(pipeline, tool_result(common, call_ref, tool_call, result)) do
        {:ok, _receipt} ->
          :ok

        {:error, reason} ->
          :telemetry.execute([:recurse, :provenance, :tool_result_not_recorded], %{count: 1}, %{
            reason: reason
          })
      end
    end

    :ok
  end

  defp answered?(%{upstream_status_code: status}), do: status in 200..299
  defp answered?(_call_state), do: false

  defp owner(call_state) do
    case Map.get(call_state, :credential) do
      <<_::256>> = credential -> {actor(call_state), credential}
      _ -> nil
    end
  end

  defp tool_result(common, call_ref, tool_call, result) do
    Map.merge(common, %{
      kind_path: @base <> "/ToolResult",
      causes: [call_ref],
      attachments: [%{name: "output", bytes: result.content}],
      body:
        Body.response(
          outcome: if(result.error?, do: "failed", else: "completed"),
          content_ref: "attachment:output",
          media_type: result.media_type,
          size: byte_size(result.content),
          call: tool_call,
          call_id: result.call_id
        )
    })
  end

  defp common(call_state) do
    %{
      actor: actor(call_state),
      session: session(call_state),
      occurred_at: call_state.started_at
    }
  end

  defp model_call(call_state, common) do
    payload = Map.get(call_state, :request_payload)
    {input_ref, attachments, held?} = content("request", call_state.prompt_hash, payload)
    {size, size_known?} = size(payload, Map.get(call_state, :request_size))

    Map.merge(common, %{
      kind_path: @base <> "/ModelCall",
      attachments: attachments,
      body:
        Body.model_call(
          provider: call_state.provider,
          model: call_state.model,
          content_ref: input_ref,
          media_type: "application/json",
          size: size,
          details:
            compact(%{
              "upstreamHost" => call_state.upstream_host,
              "transport" => Atom.to_string(call_state.transport),
              "apiFormat" => to_string(call_state.api_format),
              "requestPath" => call_state.request_path,
              "tenant" => call_state.tenant_id,
              "principalSource" => AttestationEmitter.principal_source(call_state),
              "requestKind" => stringify(Map.get(call_state, :kind)),
              "contentHeld" => held_flag(held?),
              "sizeKnown" => held_flag(size_known?)
            })
        )
    })
  end

  defp tool_call(call_state, common, call_ref, %ToolUseIntent{} = intent, decision) do
    {args_ref, attachments, held?} = arguments(intent)
    {policy, blobs} = policy(Map.get(call_state, :policy_bundle), decision, args_ref)

    Map.merge(common, %{
      kind_path: @base <> "/ToolCall",
      occurred_at: intent.extracted_at || call_state.started_at,
      causes: [call_ref],
      attachments: attachments,
      blobs: blobs,
      body:
        Body.tool_call(
          tool: intent.tool_name,
          content_ref: args_ref,
          media_type: "application/json",
          size: intent.tool_args_size_bytes,
          policy: policy,
          result: denied_result(decision),
          call_id: call_id(intent.call_id),
          details:
            compact(%{
              "ruleId" => rule_id(decision),
              "contentHeld" => held_flag(held?)
            })
        )
    })
  end

  # The exact argument bytes the gate hashed and evaluated. They are
  # rebuilt the same way the parser hashed them and checked against that
  # hash, so what is held is what the reference names. Arguments too
  # large to have been decoded are recorded by hash and marked not held.
  defp arguments(%ToolUseIntent{tool_args: args, tool_args_hash: hash}) when is_map(args) do
    bytes = Jason.encode!(args)

    if :crypto.hash(:sha256, bytes) == hash,
      do: {"attachment:args", [%{name: "args", bytes: bytes}], true},
      else: not_held("tool_args", hash, :arguments_do_not_match_hash)
  end

  defp arguments(%ToolUseIntent{tool_args_hash: hash}),
    do: not_held("tool_args", hash, :too_large)

  defp model_response(call_state, common, call_ref) do
    payload = Map.get(call_state, :response_payload)
    {output_ref, attachments, held?} = content("response", call_state.response_hash, payload)
    {size, size_known?} = size(payload, Map.get(call_state, :response_size))

    Map.merge(common, %{
      kind_path: @base <> "/ModelResponse",
      occurred_at: call_state.completed_at,
      attachments: attachments,
      body:
        Body.response(
          outcome: outcome(call_state),
          content_ref: output_ref,
          media_type: Map.get(call_state, :response_media_type, "application/octet-stream"),
          size: size,
          call: call_ref,
          reason: Map.get(call_state, :error_kind),
          details:
            compact(%{
              "upstreamStatus" => call_state.upstream_status_code,
              "promptTokens" => call_state.prompt_token_count,
              "completionTokens" => call_state.completion_token_count,
              "reasoningTokens" => Map.get(call_state, :reasoning_token_count),
              "latencyMs" => call_state.latency_ms,
              "addedLatencyMs" => call_state.added_latency_ms,
              "parser" => string_keys(Map.get(call_state, :parser)),
              "parse" => string_keys(Map.get(call_state, :parse)),
              "parserFailed" => Map.get(call_state, :parser_failed?, false),
              "toolCalls" => length(call_state.intents),
              "contentHeld" => held_flag(held?),
              "sizeKnown" => held_flag(size_known?)
            })
        )
    })
  end

  # The inline evaluation the gate performed. With no policy loaded there
  # was no evaluation, and the record says nothing rather than inventing one.
  defp policy(%PolicyBundleRef{bundle_bytes: bytes}, decision, args_ref) when is_binary(bytes) do
    {Body.policy_evaluation(
       policy_ref: Recurse.Provenance.Ref.bytes(bytes),
       outcome: policy_outcome(decision),
       input_refs: [args_ref],
       reason: reason(decision)
     ), [bytes]}
  end

  defp policy(_no_bundle, _decision, _args_ref), do: {nil, []}

  defp policy_outcome({:allow}), do: "allow"
  defp policy_outcome({:deny, %{rule_id: "policy_evaluation_error"}}), do: "error"
  defp policy_outcome({:deny, _}), do: "deny"
  defp policy_outcome(_error), do: "error"

  defp reason({:deny, %{reason: reason}}) when is_binary(reason) and reason != "", do: reason
  defp reason({:error, reason}), do: inspect(reason)
  defp reason(_), do: nil

  defp rule_id({:deny, %{rule_id: id}}) when is_binary(id), do: id
  defp rule_id(_), do: nil

  # Anything but an allow was withheld from the client.
  defp denied_result({:allow}), do: nil
  defp denied_result(_), do: Body.call_result(outcome: "denied")

  defp outcome(%{error_kind: kind}) when kind in ["upstream_connection_failed"], do: "failed"
  defp outcome(%{parser_failed?: true}), do: "partial"

  defp outcome(%{upstream_status_code: status}) when is_integer(status) and status >= 400,
    do: "failed"

  defp outcome(%{upstream_status_code: status}) when is_integer(status) and status >= 200,
    do: "completed"

  defp outcome(_), do: "unknown"

  # A content reference with the bytes behind it. The proxy captures
  # every body while evidence capture is running, so the bytes are
  # normally here and are retained with the record.
  #
  # They are missing only when a capture failed (the spool could not be
  # written) or does not hash to what was sent. The call still happened and is
  # still recorded, but the record says in plain words that the content
  # behind this reference is not held, and the gap is counted.
  defp content(name, <<_::256>> = hash, {:ok, bytes}) when is_binary(bytes) do
    if :crypto.hash(:sha256, bytes) == hash,
      do: {"attachment:" <> name, [%{name: name, bytes: bytes}], true},
      else: not_held(name, hash, :capture_does_not_match_hash)
  end

  # An encrypted spooled body: its plain bytes were hashed as they were
  # written, and that hash is checked against the one taken on the wire
  # here. The recorder then renames the file into place without reading
  # it; shipping checks every byte against the reference again.
  defp content(name, <<_::256>> = hash, {:sealed_file, path, sha256, _size}) do
    if sha256 == hash,
      do: {"attachment:" <> name, [%{name: name, path: path, sha256: hash}], true},
      else: not_held(name, hash, :capture_does_not_match_hash)
  end

  # A spooled body: the recorder hashes the file as a stream, checks it
  # against the hash taken on the wire, and moves it into storage.
  defp content(name, <<_::256>> = hash, {:file, path}) do
    {"attachment:" <> name, [%{name: name, path: path, sha256: hash}], true}
  end

  defp content(name, <<_::256>> = hash, absent), do: not_held(name, hash, absent)

  # How many bytes the content is: from the bytes when they are here,
  # otherwise from the count the proxy kept as they passed. A size of
  # zero with `sizeKnown: false` means neither was available.
  defp size({:ok, bytes}, _counted) when is_binary(bytes), do: {byte_size(bytes), true}
  defp size({:sealed_file, _path, _sha256, size}, _counted), do: {size, true}

  defp size({:file, path}, counted) do
    case File.stat(path) do
      {:ok, %{size: size}} -> {size, true}
      {:error, _} -> size(nil, counted)
    end
  end

  defp size(_absent, counted) when is_integer(counted), do: {counted, true}
  defp size(_absent, _unknown), do: {0, false}

  defp not_held(name, hash, why) do
    :telemetry.execute([:recurse, :provenance, :content_not_held], %{count: 1}, %{
      direction: name,
      reason: why
    })

    {"bytes:sha256:" <> hex(hash), [], false}
  end

  # Present only when false, so an ordinary record carries no extra field.
  defp held_flag(true), do: nil
  defp held_flag(false), do: false

  # The caller by the name the authenticated routes would give them, so
  # that a proxied call and a helper's record are about the same person.
  defp actor(call_state) do
    case Map.get(call_state, :principal_name) || call_state.principal_id do
      "spiffe://" <> _ = spiffe ->
        spiffe

      id ->
        "urn:r5e:principal:" <>
          URI.encode(to_string(call_state.tenant_id), &URI.char_unreserved?/1) <>
          ":" <> URI.encode(to_string(id), &URI.char_unreserved?/1)
    end
  end

  defp session(call_state) do
    id = Map.get(call_state, :client_session_id) || call_state.session_id

    # Named for whoever is calling, so the id a client chooses can only
    # ever name one of that caller's own sessions.
    Recurse.Gateway.Provenance.SessionName.for(call_state.tenant_id, actor(call_state), id)
  end

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  defp stringify(nil), do: nil
  defp stringify(value), do: to_string(value)

  # Evidence admits strings, integers, booleans, lists and maps. Atoms
  # become strings; nils and floats are dropped rather than coerced.
  defp string_keys(map) when is_map(map) and not is_struct(map) do
    for {k, v} <- map, cleaned = {:ok, clean(v)}, elem(cleaned, 1) != nil, into: %{} do
      {to_string(k), elem(cleaned, 1)}
    end
  end

  defp string_keys(_), do: nil

  defp clean(v) when is_binary(v) or is_integer(v) or is_boolean(v), do: v
  defp clean(v) when is_atom(v) and not is_nil(v), do: Atom.to_string(v)
  defp clean(v) when is_list(v), do: v |> Enum.map(&clean/1) |> Enum.reject(&is_nil/1)
  defp clean(v) when is_map(v), do: string_keys(v)
  defp clean(_), do: nil

  # `details` is a flat set of named scalars, bounded by its definition.
  # A nested map becomes dotted names and a list of scalars one
  # comma-separated string. Anything that still would not fit (a name
  # outside the pattern, a string over the limit) is left out instead of
  # failing the record: details describe a call, they are not the call.
  @detail_key ~r/\A[A-Za-z][A-Za-z0-9_.-]{0,63}\z/
  @detail_bytes 2048
  @detail_entries 64

  defp compact(map) do
    map
    |> flatten(nil)
    |> Enum.filter(fn {k, v} ->
      Regex.match?(@detail_key, k) and (not is_binary(v) or byte_size(v) <= @detail_bytes)
    end)
    |> Enum.sort()
    |> Enum.take(@detail_entries)
    |> Map.new()
  end

  defp flatten(map, prefix) do
    Enum.flat_map(map, fn {k, v} ->
      name = if prefix, do: prefix <> "." <> to_string(k), else: to_string(k)
      detail(name, v)
    end)
  end

  defp detail(name, v) when is_binary(v) or is_integer(v) or is_boolean(v), do: [{name, v}]
  defp detail(name, v) when is_map(v) and not is_struct(v), do: flatten(v, name)
  defp detail(name, [_ | _] = v), do: [{name, Enum.map_join(v, ",", &scalar/1)}]
  defp detail(_name, _nil_float_or_empty), do: []

  defp scalar(v) when is_binary(v), do: v
  defp scalar(v) when is_integer(v) or is_boolean(v), do: to_string(v)
  defp scalar(_), do: ""

  # A call id is recorded only when the model gave one that fits.
  defp call_id(id) when is_binary(id) and id != "" and byte_size(id) <= 256, do: id
  defp call_id(_), do: nil
end
