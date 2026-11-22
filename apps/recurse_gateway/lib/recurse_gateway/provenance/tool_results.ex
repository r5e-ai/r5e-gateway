defmodule Recurse.Gateway.Provenance.ToolResults do
  @moduledoc """
  What tools returned, as a model call's request states it.

  A client that ran a tool sends its output back to the model in the next
  request. The gateway never sees the tool run; it sees that request. So a
  `ToolResult` is recorded from the request that carried it, and points at
  the `ToolCall` the gateway recorded when the model proposed the call.

  Two things are needed for that, and this module is both:

    * `extract/2` reads the tool results out of a request the proxy has
      already decoded. Only the results at the end of the conversation are
      taken: a client resends the whole history on every turn, and the
      earlier results were recorded when they were new.

    * A table from `{owner, call id}` to the reference of the recorded
      `ToolCall`. `remember/3` is called when a tool call is recorded and
      `take/2` when its result arrives. An entry is removed when taken, so
      a request sent twice records its results once.

  The owner is who made the call and a fingerprint of the credential they
  presented. On the proxy a caller's name is what the client states, not
  something the gateway has verified, so the name alone would let anyone
  who knows it claim another caller's tool call. The credential is what
  the provider accepted; a call is only remembered, and a result only
  matched, when the provider answered that request with success. The
  table is not keyed by session: a client that sends no session id gets
  a new one on every request, and its results would never be matched.

  The table is ETS, owned by the evidence runtime's supervisor and read
  and written directly by the process recording a call. No process stands
  between a call and the table. It is memory only: after a restart, or
  when the result reaches a different node than the call did, `take/2`
  finds nothing and no `ToolResult` is recorded. Nothing is lost by that:
  the output is still in the recorded request, byte for byte. Entries
  that are never taken (a call whose result never came back) are dropped
  after an hour, when the table next grows past its limit; if that is
  not enough, the oldest go first.
  """

  @table __MODULE__
  @limit 50_000
  @keep_ms 3_600_000
  @most 64
  @call_id_bytes 256
  @outputs ["function_call_output", "custom_tool_call_output"]
  @calls ["function_call", "custom_tool_call", "reasoning"]

  @type result :: %{
          call_id: String.t(),
          content: binary(),
          media_type: String.t(),
          error?: boolean()
        }

  @doc """
  Create the table. Called once by the evidence runtime as it starts; the
  table lives as long as the calling process.
  """
  @spec init() :: :ok
  def init do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, write_concurrency: true])
    end

    :ok
  end

  @typedoc "Who made a call: their name and a fingerprint of the credential they presented."
  @type owner :: {actor :: String.t(), credential :: binary()}

  @doc "Note that `owner`'s call `call_id` was recorded as the `ToolCall` at `ref`."
  @spec remember(owner() | nil, String.t(), String.t()) :: :ok
  def remember({_actor, _credential} = owner, call_id, ref)
      when is_binary(call_id) and is_binary(ref) do
    if :ets.whereis(@table) != :undefined do
      now = System.monotonic_time(:millisecond)
      if :ets.info(@table, :size) >= @limit, do: make_room(now, @keep_ms)
      :ets.insert(@table, {{owner, call_id}, ref, now})
    end

    :ok
  end

  def remember(_owner, _call_id, _ref), do: :ok

  @doc """
  The reference of the `ToolCall` recorded for `owner`'s call `call_id`,
  removing the entry. `:error` when there is none.
  """
  @spec take(owner() | nil, String.t()) :: {:ok, String.t()} | :error
  def take({_actor, _credential} = owner, call_id) when is_binary(call_id) do
    with true <- :ets.whereis(@table) != :undefined,
         [{_key, ref, _at}] <- :ets.take(@table, {owner, call_id}) do
      {:ok, ref}
    else
      _ -> :error
    end
  end

  def take(_owner, _call_id), do: :error

  # Entries past their hour go first. If the table is still full, the
  # age kept is halved until a tenth of the table is free, so the oldest
  # calls are forgotten and the ones just made are not.
  defp make_room(now, keep_ms) do
    :ets.select_delete(@table, [{{:_, :_, :"$1"}, [{:<, :"$1", now - keep_ms}], [true]}])

    if :ets.info(@table, :size) > @limit * 9 / 10 and keep_ms > 1,
      do: make_room(now, div(keep_ms, 2))
  end

  @doc """
  The tool results a decoded request ends with, in order, at most
  #{@most}.

  For Anthropic Messages these are the `tool_result` blocks of the last
  message when it is the user's. For OpenAI Responses they are the
  `function_call_output` and `custom_tool_call_output` items that come
  after the last thing the model produced (a call, reasoning, or an
  assistant message); a client may add a message of its own after them. A result with
  no usable call id is left out. Output that is text is kept as that
  text; structured output is kept as its JSON.
  """
  @spec extract(atom(), term()) :: [result()]
  def extract(:anthropic_messages, %{"messages" => [_ | _] = messages}) do
    case List.last(messages) do
      %{"role" => "user", "content" => blocks} when is_list(blocks) ->
        blocks
        |> Enum.filter(&match?(%{"type" => "tool_result"}, &1))
        |> Enum.flat_map(fn block ->
          result(block["tool_use_id"], Map.get(block, "content", ""), block["is_error"] == true)
        end)
        |> Enum.take(@most)

      _ ->
        []
    end
  end

  def extract(:openai_responses, %{"input" => [_ | _] = input}) do
    input
    |> Enum.reverse()
    |> Enum.take_while(&(not from_the_model?(&1)))
    |> Enum.reverse()
    |> Enum.filter(&match?(%{"type" => type} when type in @outputs, &1))
    |> Enum.flat_map(fn item -> result(item["call_id"], Map.get(item, "output", ""), false) end)
    |> Enum.take(@most)
  end

  def extract(_format, _params), do: []

  defp from_the_model?(%{"type" => type}) when type in @calls, do: true
  defp from_the_model?(%{"role" => "assistant"}), do: true
  defp from_the_model?(_item), do: false

  defp result(call_id, content, error?)
       when is_binary(call_id) and call_id != "" and byte_size(call_id) <= @call_id_bytes do
    {bytes, media_type} = content(content)
    [%{call_id: call_id, content: bytes, media_type: media_type, error?: error?}]
  end

  defp result(_call_id, _content, _error?), do: []

  defp content(text) when is_binary(text), do: {text, "text/plain"}
  defp content(other), do: {Jason.encode!(other), "application/json"}
end
