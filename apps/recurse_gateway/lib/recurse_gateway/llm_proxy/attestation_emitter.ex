defmodule Recurse.Gateway.LlmProxy.AttestationEmitter do
  @moduledoc """
  Records a finished model call as evidence.

  The proxy calls `emit_call_attestation/1` once per call, as its last
  step before it closes the client's connection, with everything it
  learned about the call: who made it, what was sent and returned (as
  hashes, with the content held separately), which tool uses the model
  asked for and what policy decided about each. The call is recorded as
  Provenance v2 evidence by `Recurse.Gateway.Provenance.Call`.

  This module exists so that the two proxies (streamed HTTP and
  WebSocket) describe a call in one shape, `t:call_state/0`, and so that
  a call that could not be recorded is reported to the client as a
  failure instead of being closed as if nothing were wrong.

  It holds no state and starts no process: recording is a function of
  the call it is given.
  """

  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.LlmProxy.PrincipalExtractor
  alias Recurse.Gateway.LlmProxy.RequestKind
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @typedoc """
  Per-intent tuple shape used by the emitter. The first element is the
  canonical `ToolUseIntent` struct produced by the per-provider parser
  (`Recurse.Shared.LlmProxy.ToolUseIntent`); the second is the gate
  decision tuple emitted by `Recurse.Gateway.LlmProxy.CedarToolUseGate`.

  Mirrors the `intents_seen` accumulator on `StreamingProxy` /
  `WebSocketBridge` state.
  """
  @type intent_decision :: {ToolUseIntent.t(), gate_decision()}

  @typedoc """
  Cedar gate decisions per `Recurse.Gateway.LlmProxy.CedarToolUseGate`.

  `{:error, _}` means policy could not be evaluated. The proxy holds
  the tool use back exactly as it does for a deny, and the record says
  that it was an error and not a decision to deny.
  """
  @type gate_decision ::
          {:allow}
          | {:deny, %{rule_id: String.t(), reason: String.t()}}
          | {:error, term()}

  @typedoc """
  Per-call emitter input. Field documentation:

    * `:tenant_id` — tenant ULID.
    * `:principal_id` — operator-meaningful identity string.
    * `:principal_kind` — `"obo_human" | "service_account" | "autonomous"`.
    * `:session_id` — agent session id (mirror of `gate_context_base.session_id`).
    * `:started_at` / `:completed_at` — RFC 3339 / `DateTime.t()`.
    * `:model` / `:provider` / `:upstream_host` / `:transport` /
      `:api_format` / `:request_path` — provider metadata captured at
      proxy open.
    * `:prompt_hash` / `:response_hash` — 32 raw bytes (SHA-256 over
      the canonical prompt + response bytes; computed upstream).
    * `:prompt_token_count` / `:completion_token_count` /
      `:reasoning_token_count` — non-negative integers.
    * `:cedar_bundle_hash` — 32 raw bytes (the snapshot bundle's
      canonical hash).
    * `:upstream_status_code` — provider response code (200 success;
      4xx/5xx maps via `:error_kind`).
    * `:error_kind` — nullable; a short name for what went wrong upstream.
    * `:intents` — list of `intent_decision()` tuples: each tool use the
      model asked for, with what policy decided about it.
    * `:latency_ms` / `:added_latency_ms` — non-negative integers.
    * `:correlation_id` — optional ULID; defaults to a freshly minted
      one.
    * `:chatgpt_account_id` — optional.
    * `:kind` — optional `RequestKind.kind()`:
      `:agent_turn | :session_title | :side_query`. nil when the
      transport does not classify (the WebSocket bridge).
    * `:client_session_id` — optional; the client's own session id
      (`X-Claude-Code-Session-Id` / `metadata.user_id.session_id`).
    * `:parser` — `%{module, version, format}` —
      the recognizer that read the response bytes (`version` is the
      SHA-256 prefix of its source, `format` the wire format + version
      it is exhaustive for). Build it with `parser_identity/3`.
    * `:parse` — `%{events_total, events_unhandled, unhandled_types,
      status}` — recognition completeness. With `events_unhandled == 0`
      an empty list of intents claims the response carried no tool
      call in the format's encoding; with `> 0` the listed types are the
      events the parser could not classify. `status` is `"ok"` or
      `"failed"` (the proxy stopped calling the parser after it raised;
      the rest of the stream was forwarded unread). Build it with
      `parse_completeness/2`. Both default (`parser_identity(nil, …)`,
      `{0, 0, [], "ok"}`) so a call that never produced bytes still
      carries them.
    * `:parser_failed?` — optional boolean (the proxy's call-state flag);
      when the `:parse` map carries no `status` this decides it.
    * `:principal_source` — optional `"jwt" | "client_metadata" |
      "mtls_svid" | "anonymous"` (or the atom); how the principal id was
      obtained. When absent it is derived from the id (`"anonymous"`,
      `claude-code:` → `"client_metadata"`, else `"jwt"`).
    * `:upstream_org_id` — optional; the upstream's
      `anthropic-organization-id` response header, the one identity
      signal the upstream itself attests. Also derived from
      `:upstream_response_headers` (a `[{name, value}]` list) when given.
    * `:request_payload` / `:response_payload` — optional
      `PayloadCapture.result()`: the bytes `prompt_hash` /
      `response_hash` cover, or why they were not kept.
  """
  @type call_state :: %{
          required(:tenant_id) => String.t(),
          required(:principal_id) => String.t(),
          required(:principal_kind) => String.t(),
          required(:session_id) => String.t(),
          required(:started_at) => DateTime.t(),
          required(:completed_at) => DateTime.t(),
          required(:model) => String.t(),
          required(:provider) => String.t(),
          required(:upstream_host) => String.t(),
          required(:transport) => :wss | :https_sse,
          required(:api_format) => atom() | String.t(),
          required(:request_path) => String.t(),
          required(:prompt_hash) => binary(),
          required(:response_hash) => binary(),
          required(:prompt_token_count) => non_neg_integer(),
          required(:completion_token_count) => non_neg_integer(),
          optional(:reasoning_token_count) => non_neg_integer() | nil,
          required(:cedar_bundle_hash) => binary(),
          required(:upstream_status_code) => integer(),
          optional(:error_kind) => String.t() | nil,
          required(:intents) => [intent_decision()],
          required(:latency_ms) => non_neg_integer(),
          required(:added_latency_ms) => non_neg_integer(),
          optional(:correlation_id) => String.t() | nil,
          optional(:chatgpt_account_id) => String.t() | nil,
          optional(:kind) => RequestKind.kind() | nil,
          optional(:client_session_id) => String.t() | nil,
          optional(:parser) => parser_identity() | nil,
          optional(:parse) => parse_completeness() | nil,
          optional(:parser_failed?) => boolean(),
          optional(:principal_source) => String.t() | atom() | nil,
          optional(:upstream_org_id) => String.t() | nil,
          optional(:upstream_response_headers) => [{String.t(), String.t()}] | nil,
          optional(:request_payload) => PayloadCapture.result() | nil,
          optional(:response_payload) => PayloadCapture.result() | nil
        }

  @typedoc "Which parser read the response, at which version, for which wire format."
  @type parser_identity :: %{
          module: String.t(),
          version: String.t(),
          format: String.t()
        }

  @typedoc "How much of the response the parser could classify."
  @type parse_completeness :: %{
          required(:events_total) => non_neg_integer(),
          required(:events_unhandled) => non_neg_integer(),
          required(:unhandled_types) => [String.t()],
          optional(:status) => String.t(),
          optional(:betas_requested) => [String.t()]
        }

  @typedoc """
  Why a call was not recorded:

    * `{:error, {:invariant, field}}`: the call state is malformed in
      that field;
    * `{:error, {:evidence_capture, reason}}`: the record could not be
      made or handed to the evidence log.
  """
  @type emit_error ::
          {:error, {:invariant, atom()}}
          | {:error, {:evidence_capture, term()}}

  @doc """
  Build the `:parser` field for a call state: the parser module's name,
  its compile-time source hash (`version/0`, `"unknown"` when the module
  does not export one) and the wire format it is exhaustive for (the
  parser summary's `:format`, else the config's `api_format`).
  """
  @spec parser_identity(module() | nil, map(), atom() | String.t()) :: parser_identity()
  def parser_identity(module, summary, api_format) do
    version =
      if is_atom(module) and module != nil and Code.ensure_loaded?(module) and
           function_exported?(module, :version, 0),
         do: module.version(),
         else: "unknown"

    %{
      module: if(is_atom(module) and module != nil, do: inspect(module), else: "unknown"),
      version: version,
      format:
        nonempty_string(Map.get(summary || %{}, :format)) || api_format_to_string(api_format)
    }
  end

  @doc """
  Build the `:parse` field from a parser summary (`events_total`,
  `events_unhandled`, `unhandled_types`, `betas_requested`); `{0, 0, []}`
  when the parser produced no summary (no response bytes). `opts` may
  carry `parser_failed?: true` (the proxy's call-state flag) which sets
  `status: "failed"`; the default is `"ok"`.
  """
  @spec parse_completeness(map() | nil, keyword()) :: parse_completeness()
  def parse_completeness(summary, opts \\ []) do
    summary = summary || %{}

    base = %{
      events_total: non_neg(Map.get(summary, :events_total) || Map.get(summary, :event_count)),
      events_unhandled: non_neg(Map.get(summary, :events_unhandled)),
      unhandled_types:
        string_list(Map.get(summary, :unhandled_types)) |> Enum.uniq() |> Enum.sort(),
      status: if(Keyword.get(opts, :parser_failed?, false) == true, do: "failed", else: "ok")
    }

    case string_list(Map.get(summary, :betas_requested)) do
      [] -> base
      betas -> Map.put(base, :betas_requested, betas)
    end
  end

  defp string_list(v), do: v |> List.wrap() |> Enum.filter(&is_binary/1)

  @doc """
  Wire form of the principal's provenance for a call state:
  `call_state.principal_source` when given, else derived from the
  principal id (see `t:call_state/0`).
  """
  @spec principal_source(map()) :: String.t()
  def principal_source(call_state) do
    case Map.get(call_state, :principal_source) do
      nil ->
        case Map.get(call_state, :principal_id) do
          "anonymous" -> "anonymous"
          "claude-code:" <> _ -> "client_metadata"
          id when is_binary(id) and id != "" -> "jwt"
          _ -> "anonymous"
        end

      source ->
        PrincipalExtractor.principal_source_to_string(source)
    end
  end

  @doc """
  The upstream's `anthropic-organization-id` response header, from
  `call_state.upstream_org_id` or `call_state.upstream_response_headers`;
  nil when the upstream sent none.
  """
  @spec upstream_org_id(map()) :: String.t() | nil
  def upstream_org_id(call_state) do
    nonempty_string(Map.get(call_state, :upstream_org_id)) ||
      header_value(Map.get(call_state, :upstream_response_headers), "anthropic-organization-id")
  end

  defp header_value(headers, name) when is_list(headers) do
    Enum.find_value(headers, fn
      {k, v} when is_binary(k) and is_binary(v) ->
        if String.downcase(k, :ascii) == name, do: nonempty_string(v), else: nil

      _ ->
        nil
    end)
  end

  defp header_value(_, _), do: nil

  @doc """
  Record one finished call.

  Returns `{:ok, ref}`, where `ref` is the reference of the call's
  `ModelCall` record. On `{:error, reason}` the caller reports the
  failure to the client (HTTP 500, or WebSocket close 1011) instead of
  closing cleanly, so that an unrecorded call is never mistaken for a
  recorded one.
  """
  @spec emit_call_attestation(call_state()) :: {:ok, ref :: String.t()} | emit_error()
  def emit_call_attestation(call_state) when is_map(call_state) do
    with :ok <- validate_invariants(call_state) do
      case Recurse.Gateway.Provenance.Call.record(call_state) do
        {:ok, ref} -> {:ok, ref}
        {:error, reason} -> {:error, {:evidence_capture, reason}}
      end
    end
  end

  # A call state the proxy could not have built correctly is refused
  # before anything is signed.
  defp validate_invariants(call_state) do
    cond do
      not is_binary(call_state[:tenant_id]) or call_state[:tenant_id] == "" ->
        {:error, {:invariant, :tenant_id}}

      not is_binary(call_state[:principal_id]) or call_state[:principal_id] == "" ->
        {:error, {:invariant, :principal_id}}

      not is_binary(call_state[:session_id]) or call_state[:session_id] == "" ->
        {:error, {:invariant, :session_id}}

      not match?(<<_::binary-size(32)>>, call_state[:prompt_hash]) ->
        {:error, {:invariant, :prompt_hash}}

      not match?(<<_::binary-size(32)>>, call_state[:response_hash]) ->
        {:error, {:invariant, :response_hash}}

      not match?(<<_::binary-size(32)>>, call_state[:cedar_bundle_hash]) ->
        {:error, {:invariant, :cedar_bundle_hash}}

      not is_list(call_state[:intents]) ->
        {:error, {:invariant, :intents}}

      true ->
        :ok
    end
  end

  defp non_neg(n) when is_integer(n) and n >= 0, do: n
  defp non_neg(_), do: 0

  defp nonempty_string(s) when is_binary(s) and s != "", do: s
  defp nonempty_string(_), do: nil

  defp api_format_to_string(format) when is_atom(format), do: Atom.to_string(format)
  defp api_format_to_string(format) when is_binary(format), do: format
end
