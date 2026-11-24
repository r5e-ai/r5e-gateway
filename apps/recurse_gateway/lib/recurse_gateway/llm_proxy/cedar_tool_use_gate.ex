defmodule Recurse.Gateway.LlmProxy.CedarToolUseGate do
  @moduledoc """
  Per-`ToolUseIntent` Cedar policy gate (Spec 009 Phase 3 Sub-3.4 / T039-T044).

  Spec source of truth:
  `specs/009-llm-api-proxy/contracts/cedar_tool_use_gate.md` (typespec +
  Cedar context shape + bundle-snapshot semantic + decision-cache spec).

  ## Role

  The streaming proxy (HTTPS+SSE: `Recurse.Gateway.LlmProxy.StreamingProxy`;
  WebSocket: `Recurse.Gateway.LlmProxy.WebSocketBridge`) extracts a stream
  of `Recurse.Shared.LlmProxy.ToolUseIntent` values from the upstream
  response. For each intent, this module:

    1. Builds a Cedar context from the intent + per-call gate context
       (principal, model, tenant, session id, prompt hash, etc.). Per
       R-004, `tool_args` is inlined as JSON when under the
       configured size threshold; otherwise only `tool_args_hash`
       is exposed and policies must rely on hash allowlists.
    2. Looks up the cached decision (key:
       `{principal_id, tool_name, tool_args_hash, cedar_bundle_hash}`)
       to skip the Cedar NIF on parallel/repeat tool calls.
    3. On miss: invokes the Cedar Rustler NIF
       (`Recurse.Cedar.evaluate_with_entities/3`) against the
       call-start bundle snapshot.
    4. Returns `{:allow}`, `{:deny, %{rule_id, reason, suggested_alternative}}`,
       or `{:error, reason_atom}` per the contract.

  ## Bundle-snapshot semantic (T041)

  The bundle active at call-START is captured by the proxy via
  `Recurse.Gateway.Policy.Active.current/0` (a `:persistent_term`
  lookup) and threaded into every per-intent evaluation as the
  `:bundle` field of `gate_context`. Even if a new bundle activates
  mid-stream, in-flight calls keep their captured snapshot. This
  avoids a race where bundle activation flips a deny into an allow
  (or vice versa) for a single in-flight call.

  ## Iron-Law check (`elixir:elixir-thinking`, `otp-thinking`)

  This module is PURE — no GenServer, no process state. It calls into
  `Recurse.Cedar.evaluate_with_entities/3` (NIF; stateless) and into
  the `DecisionCache` (whose state is owned by a sibling GenServer).

  ## Wiring into the proxy

  `StreamingProxy.proxy/2` and `WebSocketBridge.upgrade/2` capture
  `:cedar_bundle_ref` and a `:gate_context_base` at call-open. For
  each parser-emitted intent they call `evaluate/2` with that base
  plus the intent's `parallel_index`. The proxy records `{intent,
  decision}` tuples into `state.intents_seen` for denial injection and
  attestation emission. Both `:deny` and `:error` decisions fail-CLOSED:
  `StreamingProxy` suppresses denied tool calls and injects a synthetic
  denial via `suppress_and_inject/4`.

  ## Failure modes

    * Cedar NIF returns `{:error, reason}` → return `{:error, :cedar_eval_error}`.
      Caller (proxy) MUST fail-CLOSED (suppress the intent; the S4
      review made the proxy treat a gate error as a deny).
    * Bundle ref missing → return `{:error, :no_bundle}`.
    * `tool_args` encode failure (extreme edge: non-encodable map values)
      → return `{:error, :args_encode_error}`.

  `{:error, _}` decisions are never cached: a transient NIF failure
  must not pin a fail-closed answer for the cache TTL.

  ## Untrusted identifiers (spec 012 S4 review)

  Both entity ids the gate builds come from the wire: the principal id
  is client-asserted (`metadata.user_id` for Claude Code, the peeked JWT
  `sub` for Codex) and the tool name is whatever the model emitted. A
  `"`, `\\` or newline in either used to break the Cedar request parse
  and surface as `{:error, _}`. Two layers now stop that:

    * the tool name must match `#{inspect(~r/\A[A-Za-z0-9_.:-]{1,128}\z/)}`;
      anything else is DENIED with `reason: "invalid_tool_name"` before
      Cedar runs (the intent is still recorded, as a deny);
    * every id is Cedar-string-escaped (`\\` → `\\\\`, `"` → `\\"`,
      control bytes → `\\u{XXXX}`) when the request is built, so no input
      can make the request unparseable. Principal ids are validated at
      the source (`PrincipalExtractor.valid_account_uuid?/1`); the
      escaping here is the belt to that brace.

  Constitution Principle III (Fail-Closed on Policy): every error path
  is fail-CLOSED.
  """

  alias Recurse.Cedar
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate.DecisionCache
  alias Recurse.Gateway.LlmProxy.TokenEstimator
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  require Logger

  @typedoc """
  Per-call gate context. Built once at call-open by the proxy and
  threaded into every per-intent evaluation. Per the contract:

    * `:principal` — actor identity + claims for the Cedar User entity.
    * `:model` — the LLM model id (used both as Cedar context and as the
      per-model selector for the TokenEstimator).
    * `:tenant`, `:session_id` — call-scoping for Cedar policies.
    * `:prompt_hash` / `:response_so_far_hash` — content-derived audit
      anchors so policies can key on "this exact prompt".
    * `:estimated_completion_tokens` — populated from `TokenEstimator`
      (FR-011); Cedar policies enforce per-principal token budgets.
    * `:parallel_tool_call_index` — `nil` for sequential calls;
      otherwise the position in the upstream parallel-tool-calls array
      (per `ToolUseIntent.parallel_index`).
    * `:cedar_bundle_hash` — hex-encoded SHA-256 of the call-start
      bundle (matches `PolicyBundleRef.bundle_id`); included in the
      Cedar context so policies can audit-trail-key on bundle versions
      AND used as the cache key fourth component.
    * `:upstream_domain`, `:transport` — provider/transport
      identification for policies that want to allow/deny per upstream.
    * `:started_at` — call-start `DateTime.t()`; lets time-of-day
      policies exist.
    * `:bundle` — the `%PolicyBundleRef{}` snapshot from call-start.
      The cedar_bundle_hash MUST match this bundle's canonical_hash.
    * `:cache` — keyword opts threaded into `DecisionCache.get/2` +
      `put/3`. Tests use this to swap in an isolated cache.
  """
  @type gate_context :: %{
          required(:principal) => principal_context(),
          required(:model) => String.t(),
          required(:tenant) => String.t(),
          required(:session_id) => String.t(),
          required(:prompt_hash) => binary(),
          required(:response_so_far_hash) => binary(),
          required(:estimated_completion_tokens) => non_neg_integer(),
          required(:cedar_bundle_hash) => binary(),
          required(:upstream_domain) => String.t(),
          required(:transport) => :wss | :https_sse,
          required(:started_at) => DateTime.t(),
          required(:bundle) => PolicyBundleRef.t(),
          optional(:parallel_tool_call_index) => non_neg_integer() | nil,
          optional(:upstream_route_id) => String.t(),
          optional(:upstream_zdr_pinned) => boolean(),
          optional(:args_inline_threshold_bytes) => pos_integer(),
          optional(:cache) => keyword()
        }

  @type principal_context :: %{
          required(:id) => String.t(),
          required(:kind) => :obo_human | :service_account | :autonomous,
          optional(:chatgpt_account_id) => String.t() | nil,
          optional(:claims) => map()
        }

  @type deny_reason :: %{
          rule_id: String.t(),
          reason: String.t(),
          suggested_alternative: String.t() | nil
        }

  @type decision :: {:allow} | {:deny, deny_reason()} | {:error, atom()}

  @default_args_inline_threshold_bytes 10_000

  # `\A`/`\z`, not `^`/`$`: `$` also matches before a trailing newline.
  @tool_name_re ~r/\A[A-Za-z0-9_.:-]{1,128}\z/
  @invalid_tool_name_rule "gateway.invalid_tool_name"

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Evaluate a single `ToolUseIntent` against the current Cedar bundle in
  `context.bundle`. Returns `{:allow}`, `{:deny, reason_map}`, or
  `{:error, reason_atom}`.

  Callers should be ready for any of the three; `:error` is fail-CLOSED
  per Constitution Principle III — the proxy must close the call.
  """
  @spec evaluate(ToolUseIntent.t(), gate_context()) :: decision()
  def evaluate(%ToolUseIntent{} = intent, %{bundle: %PolicyBundleRef{} = bundle} = context) do
    if valid_tool_name?(intent.tool_name) do
      evaluate_cached(intent, context, bundle)
    else
      Logger.info(fn ->
        "cedar_tool_use_gate: tool name outside the safe charset " <>
          "(#{describe_shape(intent.tool_name)}); denied without evaluation"
      end)

      {:deny,
       %{
         rule_id: @invalid_tool_name_rule,
         reason: "invalid_tool_name",
         suggested_alternative: nil
       }}
    end
  end

  def evaluate(_intent, _context), do: {:error, :no_bundle}

  @doc """
  `true` when `name` matches `#{inspect(@tool_name_re)}` — the charset the
  gate will put inside `ToolUse::"…"`. Everything else is denied with
  `reason: "invalid_tool_name"` (see the module doc).
  """
  @spec valid_tool_name?(term()) :: boolean()
  def valid_tool_name?(name) when is_binary(name), do: Regex.match?(@tool_name_re, name)
  def valid_tool_name?(_), do: false

  @doc """
  Escape a string for use inside a Cedar string literal / entity id:
  `\\`, `"` and `'` are backslash-escaped, `\\n` `\\r` `\\t` use their
  short forms, other control bytes become `\\u{h+}` (minimal lowercase
  hex, Cedar's normalized form). Bytes ≥ 0x80 (UTF-8 continuation + lead
  bytes) pass through unchanged. Total over any binary; never raises.
  Non-printable Unicode above U+007F (zero-width characters and the
  like) is not escaped; Cedar rejects such an id as un-normalized, which
  surfaces as `{:error, :cedar_eval_error}` — still fail-closed, and
  unreachable for the validated `claude-code:` principals and tool names.
  """
  @spec cedar_escape(binary()) :: binary()
  def cedar_escape(s) when is_binary(s) do
    s
    |> :binary.bin_to_list()
    |> Enum.map(&escape_byte/1)
    |> IO.iodata_to_binary()
  end

  # Cedar accepts an entity id only in its NORMALIZED form (the string
  # must round-trip through its own printer, Rust's `str::escape_debug`):
  # short escapes for `\t \r \n \\ \' \"`, control bytes as `\u{h+}` with
  # minimal lowercase hex, printable text untouched.
  defp escape_byte(?\\), do: "\\\\"
  defp escape_byte(?"), do: "\\\""
  defp escape_byte(?'), do: "\\'"
  defp escape_byte(?\n), do: "\\n"
  defp escape_byte(?\r), do: "\\r"
  defp escape_byte(?\t), do: "\\t"

  defp escape_byte(b) when b < 0x20 or b == 0x7F,
    do: "\\u{" <> String.downcase(Integer.to_string(b, 16)) <> "}"

  defp escape_byte(b), do: <<b>>

  defp describe_shape(v) when is_binary(v), do: "binary of #{byte_size(v)} bytes"
  defp describe_shape(_), do: "non-binary"

  defp evaluate_cached(intent, context, bundle) do
    cache_opts = Map.get(context, :cache, [])

    cache_key =
      {context.principal.id, intent.tool_name, intent.tool_args_hash, bundle.canonical_hash}

    case DecisionCache.get(cache_key, cache_opts) do
      {:hit, value} ->
        value

      :miss ->
        decision = evaluate_uncached(intent, context, bundle)
        # Errors are transient (NIF / encode failures); caching one would
        # pin a fail-closed answer for the TTL after the cause is gone.
        unless match?({:error, _}, decision),
          do: DecisionCache.put(cache_key, decision, cache_opts)

        decision
    end
  end

  @doc """
  Build the Cedar context map a Cedar policy sees as `context`. Extracted
  per Principle VII so `StreamingProxy` and `WebSocketBridge` share the
  same construction (and tests can introspect it without invoking
  Cedar). Threshold logic + hash inlining live here.
  """
  @spec build_cedar_context(ToolUseIntent.t(), gate_context()) :: map()
  def build_cedar_context(%ToolUseIntent{} = intent, %{} = context) do
    threshold =
      Map.get(context, :args_inline_threshold_bytes, @default_args_inline_threshold_bytes)

    inline? = should_inline_args?(intent, threshold)

    base = %{
      "tool_args_hash" => Base.encode16(intent.tool_args_hash, case: :lower),
      "tool_args_size_bytes" => intent.tool_args_size_bytes,
      "model" => context.model,
      "tenant" => context.tenant,
      "session_id" => context.session_id,
      "prompt_hash" => Base.encode16(context.prompt_hash, case: :lower),
      "response_so_far_hash" => Base.encode16(context.response_so_far_hash, case: :lower),
      "estimated_completion_tokens" => context.estimated_completion_tokens,
      "cedar_bundle_hash" => Base.encode16(context.cedar_bundle_hash, case: :lower),
      "upstream_domain" => context.upstream_domain,
      "upstream_route_id" => Map.get(context, :upstream_route_id, ""),
      "upstream_zdr_pinned" => Map.get(context, :upstream_zdr_pinned, false) == true,
      "transport" => Atom.to_string(context.transport),
      "started_at" => DateTime.to_iso8601(context.started_at),
      "principal_kind" => Atom.to_string(context.principal.kind),
      "chatgpt_account_id" => Map.get(context.principal, :chatgpt_account_id) || "",
      "principal_groups" => extract_groups(context.principal),
      "parallel_tool_call_index" => parallel_index_or(-1, context, intent)
    }

    if inline? do
      Map.put(base, "tool_args", intent.tool_args)
    else
      base
    end
  end

  @doc """
  Capture the current Cedar bundle snapshot. Returns
  `{:ok, %PolicyBundleRef{}}` or `{:error, :not_loaded}`. Called by the
  proxy at call-open; the returned ref is threaded into every per-intent
  `evaluate/2` for the lifetime of the call.

  Thin wrapper over `Recurse.Gateway.Policy.Active.current/0` that
  unwraps the `%Active{}` envelope to return the inner
  `%PolicyBundleRef{}` (the gate context only needs bundle bytes +
  canonical_hash, not provenance). Tests can inject a fake via the
  `:active_module` opt to simulate alternate bundle states.
  """
  @spec snapshot_bundle(keyword()) :: {:ok, PolicyBundleRef.t()} | {:error, :not_loaded}
  def snapshot_bundle(opts \\ []) do
    active_mod = Keyword.get(opts, :active_module, Recurse.Gateway.Policy.Active)

    case active_mod.current() do
      {:ok, %Recurse.Gateway.Policy.Active{bundle: %PolicyBundleRef{} = ref}} -> {:ok, ref}
      {:error, :not_loaded} -> {:error, :not_loaded}
    end
  end

  @doc """
  Resolve the per-tenant args-inline threshold. Defaults to 10KB; tenants
  override via `LlmProviderConfig.metadata["cedar_args_inline_threshold_bytes"]`.
  """
  @spec resolve_args_inline_threshold(map() | nil) :: pos_integer()
  def resolve_args_inline_threshold(metadata) when is_map(metadata) do
    case Map.get(metadata, "cedar_args_inline_threshold_bytes") do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_args_inline_threshold_bytes
    end
  end

  def resolve_args_inline_threshold(_), do: @default_args_inline_threshold_bytes

  @doc """
  Default args-inline threshold. Documented for tests + callers that
  want to hard-code it.
  """
  @spec default_args_inline_threshold_bytes() :: pos_integer()
  def default_args_inline_threshold_bytes, do: @default_args_inline_threshold_bytes

  @doc """
  Convenience builder used by `StreamingProxy` + `WebSocketBridge` at
  call-open to assemble the gate-context base (everything except the
  per-intent `:parallel_tool_call_index`). Returns a map shaped per
  `gate_context()` minus that one field.
  """
  @spec build_gate_context_base(map()) :: map()
  def build_gate_context_base(%{} = inputs) do
    Map.merge(
      %{
        estimated_completion_tokens: 0,
        prompt_hash: <<>>,
        response_so_far_hash: <<>>,
        parallel_tool_call_index: nil
      },
      inputs
    )
  end

  @doc """
  Wire-friendly: assemble the per-intent `gate_context` from a base and
  the intent's `parallel_index`. Used by the proxy dispatch loop.
  """
  @spec gate_context_for_intent(map(), ToolUseIntent.t()) :: gate_context()
  def gate_context_for_intent(base, %ToolUseIntent{parallel_index: idx}) do
    Map.put(base, :parallel_tool_call_index, idx)
  end

  @doc """
  Estimator wiring helper — populates `:estimated_completion_tokens` on
  the gate-context base from a prompt body + request params at
  call-open. Wraps `TokenEstimator.estimate_completion_tokens/3`.
  """
  @spec populate_estimated_tokens(map(), %{
          prompt_byte_size: non_neg_integer(),
          request_params: map()
        }) ::
          map()
  def populate_estimated_tokens(%{model: model} = base, %{
        prompt_byte_size: pbs,
        request_params: rp
      }) do
    estimate = TokenEstimator.estimate_completion_tokens(pbs, rp, model: model)
    Map.put(base, :estimated_completion_tokens, estimate)
  end

  # ---------------------------------------------------------------------------
  # Internal — uncached evaluate
  # ---------------------------------------------------------------------------

  defp evaluate_uncached(intent, context, bundle) do
    cedar_context = build_cedar_context(intent, context)
    principal_uid = principal_uid(context.principal)
    resource_uid = ~s[ToolUse::"#{cedar_escape(intent.tool_name)}"]
    action_uid = ~s[Action::"invoke_tool"]

    with {:ok, request_json} <-
           encode_request(principal_uid, action_uid, resource_uid, cedar_context),
         {:ok, entities_json} <- encode_entities(context.principal, intent),
         {:ok, %{decision: decision, matched_policies: matched}} <-
           Cedar.evaluate_with_entities(bundle.bundle_bytes, request_json, entities_json) do
      finalize_decision(decision, matched)
    else
      {:error, reason} ->
        Logger.warning(fn ->
          "cedar_tool_use_gate: evaluation failed reason=#{inspect(reason)} " <>
            "tool=#{inspect(intent.tool_name)} principal=#{inspect(context.principal.id)}"
        end)

        {:error, :cedar_eval_error}
    end
  end

  # Cedar request shape — mirrors Recurse.Cedar.evaluate_with_entities/3
  # documented JSON.
  defp encode_request(principal_uid, action_uid, resource_uid, context) do
    {:ok,
     JSON.encode!(%{
       "principal" => principal_uid,
       "action" => action_uid,
       "resource" => resource_uid,
       "context" => context
     })}
  rescue
    e -> {:error, {:request_encode_error, Exception.message(e)}}
  end

  # Cedar entities — minimal: the User principal entity (with claims +
  # groups + chatgpt_account_id) and the ToolUse resource entity. The
  # NIF accepts an array; bundles that don't reference these entities
  # ignore them.
  defp encode_entities(principal, intent) do
    user_entity = %{
      "uid" => %{"type" => "User", "id" => principal.id},
      "attrs" => %{
        "kind" => Atom.to_string(principal.kind),
        "chatgpt_account_id" => Map.get(principal, :chatgpt_account_id) || "",
        "groups" => extract_groups(principal)
      },
      "parents" => []
    }

    tool_entity = %{
      "uid" => %{"type" => "ToolUse", "id" => intent.tool_name},
      "attrs" => %{},
      "parents" => []
    }

    {:ok, JSON.encode!([user_entity, tool_entity])}
  rescue
    e -> {:error, {:entities_encode_error, Exception.message(e)}}
  end

  defp finalize_decision(:allow, _matched), do: {:allow}

  defp finalize_decision(:deny, matched) do
    rule_id =
      matched
      |> Enum.reject(&(&1 in [:cedar_error, "cedar_error"]))
      |> Enum.find(&is_binary/1)
      |> Kernel.||("unknown")

    {:deny,
     %{
       rule_id: rule_id,
       reason: "denied_by_cedar_policy",
       suggested_alternative: nil
     }}
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # The entity-store side (`encode_entities/2`) carries the raw id in
  # JSON, where the NIF decodes it structurally; only the request's
  # textual `Type::"id"` form needs Cedar escaping.
  defp principal_uid(%{id: id}) when is_binary(id), do: ~s[User::"#{cedar_escape(id)}"]
  defp principal_uid(%{id: id}), do: ~s[User::"#{cedar_escape(to_string(id))}"]

  defp extract_groups(%{claims: %{"groups" => groups}}) when is_list(groups),
    do: Enum.map(groups, &to_string/1)

  defp extract_groups(%{claims: %{groups: groups}}) when is_list(groups),
    do: Enum.map(groups, &to_string/1)

  defp extract_groups(_), do: []

  # `:too_large` sentinel intents NEVER inline (regardless of threshold).
  defp should_inline_args?(%ToolUseIntent{tool_args: :too_large}, _threshold), do: false

  defp should_inline_args?(%ToolUseIntent{tool_args_size_bytes: size}, threshold)
       when is_integer(size),
       do: size <= threshold

  defp should_inline_args?(_intent, _threshold), do: false

  # Per-intent override beats per-context default when both present.
  defp parallel_index_or(default, context, intent) do
    case Map.get(context, :parallel_tool_call_index) do
      nil ->
        case intent.parallel_index do
          nil -> default
          n when is_integer(n) -> n
        end

      n when is_integer(n) ->
        n
    end
  end
end
