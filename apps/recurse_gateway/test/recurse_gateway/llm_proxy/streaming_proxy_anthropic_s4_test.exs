defmodule Recurse.Gateway.LlmProxy.StreamingProxyAnthropicS4Test do
  @moduledoc """
  The Anthropic Messages parser and the denial rewriting in the proxy,
  against a mock upstream that serves captured responses as chunked SSE,
  with a real Cedar policy deciding and evidence capture running:

    * allow: bytes out equal bytes in, and the Bash tool use is recorded
      with the policy that allowed it;
    * deny: the tool-use frames never reach the client, a text block at
      the same index carries the denial, `stop_reason` becomes
      `end_turn`, and the tool use is recorded as denied;
    * non-streaming JSON with a denied tool use is rewritten as JSON;
    * an event type the parser does not know is forwarded, counted in
      the record, and kept for inspection.
  """

  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  import ExUnit.CaptureLog, only: [with_log: 1]

  alias Recurse.Gateway.LlmProxy.ParserDrift
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.EvidenceCapture
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.ParserDrift, as: DriftStore
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @tenant_id "01TEN_S4_ANTHROPIC_PROXY"
  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)
  @bash_call_id "toolu_01LZV8Ni38xTJKZoqdQM8Pdk"
  @account "00000000-0000-0000-0000-000000000000"

  @bundle """
  permit (principal, action == Action::"invoke_tool", resource);

  forbid (
    principal,
    action == Action::"invoke_tool",
    resource == ToolUse::"Bash"
  ) when {
    context has tool_args && context.tool_args has command &&
    context.tool_args.command like "*rm -rf*"
  };
  """

  setup %{tmp_dir: tmp_dir} do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    capture = EvidenceCapture.start(tmp_dir)

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "S4 anthropic proxy test tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/s4-anthropic-test"
    })

    canonical_hash = Recurse.Cedar.canonical_hash(@bundle)

    bundle = %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: @bundle,
      bundle_bytes: @bundle
    }

    previous_active = Active.current()

    Active.update(%Active{
      source: :filesystem,
      source_ref: "s4-test",
      loaded_at: DateTime.utc_now(),
      bundle: bundle
    })

    ParserDrift.reset_counter()
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()

      case previous_active do
        {:ok, active} -> Active.update(active)
        _ -> Active.erase()
      end
    end)

    {:ok, upstream: upstream, capture: capture}
  end

  defp config(upstream) do
    %LlmProviderConfig{
      tenant_id: @tenant_id,
      provider: "anthropic",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{
        "scheme" => "http",
        "appeal_uri" => "https://appeal.example/r5e",
        "appeal_contact" => "#sec-ops"
      }
    }
  end

  defp fixture(name), do: File.read!(Path.join(@fixtures, name))

  defp proxy(conn, upstream) do
    StreamingProxy.proxy(conn, %{llm_provider_config: config(upstream), tenant_id: @tenant_id})
  end

  defp request_conn(body) do
    Plug.Test.conn(:post, "/v1/messages?beta=true", body)
    |> Map.update!(:req_headers, &[{"host", "localhost:4443"} | &1])
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header(
      "authorization",
      "Bearer sk-ant-oat01-" <> String.duplicate("x", 100)
    )
    |> Plug.Conn.put_req_header("anthropic-version", "2023-06-01")
    |> Plug.Conn.put_req_header("anthropic-beta", "oauth-2025-04-20,claude-code-20250219")
    |> Plug.Conn.put_req_header(
      "x-claude-code-session-id",
      "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"
    )
  end

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_list(chunks),
    do: IO.iodata_to_binary(chunks)

  defp resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks), do: chunks
  defp resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  # Parse an SSE body into decoded event maps (in order).
  defp events(sse) do
    sse
    |> String.split("\n\n", trim: true)
    |> Enum.map(fn block ->
      block
      |> String.split("\n")
      |> Enum.find_value(fn
        "data:" <> rest -> Jason.decode!(String.trim(rest))
        _ -> nil
      end)
    end)
    |> Enum.reject(&is_nil/1)
  end

  # What was recorded for the one call a test made: the call, the answer,
  # and each tool use as `{tool, policy outcome, record}`.
  defp recorded(capture) do
    records = EvidenceCapture.records(capture)

    %{
      call: EvidenceCapture.one(records, "ModelCall"),
      answer: EvidenceCapture.one(records, "ModelResponse"),
      tools:
        for tool <- EvidenceCapture.of_kind(records, "ToolCall") do
          body = EvidenceCapture.body(tool)
          {body["tool"], body["policy"]["outcome"], tool}
        end
    }
  end

  defp policy_ref, do: Recurse.Provenance.Ref.bytes(@bundle)

  # The captured `ls -la` turn with the command rewritten to `rm -rf /tmp/x`
  # across the same two fragments (`": \"l"` + `"s -la\""`).
  defp deny_sse do
    fixture("single_tool_use_bash.sse")
    |> String.replace(~s|"partial_json":": \\"l"|, ~s|"partial_json":": \\"rm -rf /tmp/x"|)
    |> String.replace(~s|"partial_json":"s -la\\""|, ~s|"partial_json":"\\""|)
  end

  test "allow: bytes out equal bytes in; the Bash tool use, the parser and its completeness are recorded",
       %{upstream: upstream, capture: capture} do
    request = fixture("single_tool_use_bash.request.json")
    sse = fixture("single_tool_use_bash.sse")
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 53)

    result = proxy(request_conn(request), upstream)

    assert result.status == 200
    assert resp_body(result) == sse
    assert {"content-type", "text/event-stream; charset=utf-8"} in result.resp_headers

    %{call: call, answer: answer, tools: [{"Bash", "allow", tool}]} = recorded(capture)

    assert EvidenceCapture.body(call)["model"] == "claude-haiku-4-5-20251001"
    assert call.evidence["actor"] =~ "claude-code%3A" <> @account

    assert %{"requestKind" => "agent_turn", "principalSource" => "client_metadata"} =
             EvidenceCapture.details(call)

    # The tool use: which call the model made, with which arguments, and
    # the policy that allowed it.
    tool_body = EvidenceCapture.body(tool)
    assert tool_body["callId"] == @bash_call_id
    assert tool_body["policy"]["policyRef"] == policy_ref()
    refute Map.has_key?(tool_body, "result")

    {:ok, arguments} =
      Recurse.Providers.Impls.PostgresEvidenceStore.get_blob(Repo, tool_body["contentRef"])

    assert JSON.decode!(arguments) == %{
             "command" => "ls -la",
             "description" => "List files in the current directory"
           }

    details = EvidenceCapture.details(answer)

    assert %{
             "promptTokens" => 10,
             "completionTokens" => 181,
             "reasoningTokens" => 102,
             "toolCalls" => 1,
             "parser.module" => "Recurse.Shared.LlmProxy.Parsers.AnthropicMessages",
             "parser.format" => "anthropic_messages/2023-06-01",
             "parse.events_total" => 23,
             "parse.events_unhandled" => 0,
             "parse.status" => "ok",
             "parse.betas_requested" => "oauth-2025-04-20,claude-code-20250219"
           } = details

    assert details["parser.version"] ==
             Recurse.Shared.LlmProxy.Parsers.AnthropicMessages.version()
  end

  test "deny: tool_use frames are replaced by a text block at the same index, stop_reason becomes end_turn, and the denial is recorded",
       %{upstream: upstream, capture: capture} do
    request = fixture("single_tool_use_bash.request.json")
    sse = deny_sse()
    assert sse =~ "rm -rf /tmp/x"
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 61)

    result = proxy(request_conn(request), upstream)
    assert result.status == 200
    body = resp_body(result)

    # The original tool_use never reaches the client; no HTTP error status.
    refute body =~ ~s|"name":"Bash"|
    refute body =~ "input_json_delta"
    refute body =~ ~s|"id":"#{@bash_call_id}"|

    evs = events(body)
    types = Enum.map(evs, & &1["type"])

    assert types == [
             "message_start",
             "content_block_start",
             "ping",
             "content_block_delta",
             "content_block_delta",
             "content_block_delta",
             "content_block_stop",
             "content_block_start",
             "content_block_delta",
             "content_block_stop",
             "message_delta",
             "message_stop"
           ]

    # Every injected frame carries its `event:` line (the SDK dispatches on it).
    assert body =~ "event: content_block_start\ndata: {"
    assert body =~ "event: content_block_delta\ndata: {"

    [thinking_start | _] = Enum.filter(evs, &(&1["type"] == "content_block_start"))
    assert thinking_start["index"] == 0
    assert thinking_start["content_block"]["type"] == "thinking"

    replacement_start = Enum.at(evs, 7)
    assert replacement_start["index"] == 1
    assert replacement_start["content_block"] == %{"type" => "text", "text" => ""}
    refute Map.has_key?(replacement_start["content_block"], "signature")

    replacement_delta = Enum.at(evs, 8)
    assert replacement_delta["index"] == 1
    assert replacement_delta["delta"]["type"] == "text_delta"
    text = replacement_delta["delta"]["text"]
    assert text =~ "Tool call 'Bash' (call_id: #{@bash_call_id}) was blocked by org policy."
    assert text =~ "- Rule: policy1"
    assert text =~ "- Reason: denied_by_cedar_policy"
    assert text =~ "- Tenant: #{@tenant_id}"
    assert text =~ "- Principal: claude-code:#{@account} (obo_human)"
    assert text =~ "- To appeal: ping #sec-ops (https://appeal.example/r5e)"
    assert Enum.at(evs, 9) == %{"type" => "content_block_stop", "index" => 1}

    message_delta = Enum.at(evs, 10)
    assert message_delta["delta"]["stop_reason"] == "end_turn"
    assert message_delta["usage"]["output_tokens"] == 181

    # The tool use is recorded as denied by this policy, under the call.
    %{call: call, answer: answer, tools: [{"Bash", "deny", tool}]} = recorded(capture)
    tool_body = EvidenceCapture.body(tool)
    assert tool_body["callId"] == @bash_call_id
    assert tool_body["policy"]["policyRef"] == policy_ref()
    assert tool_body["result"]["outcome"] == "denied"
    assert tool_body["details"]["ruleId"] == "policy1"
    assert tool.evidence["causes"] == [call.ref]
    assert EvidenceCapture.details(answer)["parse.events_unhandled"] == 0
  end

  defmodule ErrorGate do
    @moduledoc false
    # Stands in for CedarToolUseGate.evaluate/2 via the
    # `:llm_proxy_cedar_gate_module` seam.
    def evaluate(_intent, _context), do: {:error, "bad principal"}
  end

  test "gate error: the held tool_use is suppressed, a denial names the evaluation error, the stream ends cleanly",
       %{upstream: upstream, capture: capture} do
    Application.put_env(:recurse_gateway, :llm_proxy_cedar_gate_module, ErrorGate)
    on_exit(fn -> Application.delete_env(:recurse_gateway, :llm_proxy_cedar_gate_module) end)

    request = fixture("single_tool_use_bash.request.json")
    MockHttpUpstream.serve_sse(upstream, fixture("single_tool_use_bash.sse"), chunk_size: 61)

    {result, log} = with_log(fn -> proxy(request_conn(request), upstream) end)
    assert result.status == 200
    assert log =~ "cedar gate ERROR"
    body = resp_body(result)

    # Spec 012 S4 review — an unevaluated block must never reach the
    # client (the parser's EOF path would have released it).
    refute body =~ ~s|"name":"Bash"|
    refute body =~ "input_json_delta"
    refute body =~ ~s|"id":"#{@bash_call_id}"|

    evs = events(body)
    types = Enum.map(evs, & &1["type"])

    assert List.last(types) == "message_stop"
    assert Enum.count(types, &(&1 == "content_block_start")) == 2
    assert Enum.count(types, &(&1 == "content_block_stop")) == 2

    replacement_delta = Enum.find(evs, &(&1["delta"]["type"] == "text_delta"))
    assert replacement_delta["index"] == 1
    text = replacement_delta["delta"]["text"]
    assert text =~ "Tool call 'Bash' (call_id: #{@bash_call_id}) was blocked by org policy."
    assert text =~ "- Rule: policy_evaluation_error"
    assert text =~ ~s|- Reason: policy evaluation error: "bad principal"|

    message_delta = Enum.find(evs, &(&1["type"] == "message_delta"))
    assert message_delta["delta"]["stop_reason"] == "end_turn"

    # The call is recorded as one where policy could not be evaluated,
    # and the tool use as held back for that reason.
    refute log =~ "attestation emit"
    %{answer: answer, tools: [{"Bash", _outcome, tool}]} = recorded(capture)
    assert EvidenceCapture.body(answer)["reason"] == "policy_evaluation_failure"
    tool_body = EvidenceCapture.body(tool)
    assert tool_body["callId"] == @bash_call_id
    assert tool_body["result"]["outcome"] == "denied"
  end

  test "parallel: deny the Read (index 1), allow the Bash (index 2) — indices stay contiguous",
       %{upstream: upstream, capture: capture} do
    # Make the Read block deniable by forbidding it in a bundle variant.
    bundle =
      @bundle <>
        ~s|\nforbid (principal, action == Action::"invoke_tool", resource == ToolUse::"Read");\n|

    hash = Recurse.Cedar.canonical_hash(bundle)

    Active.update(%Active{
      source: :filesystem,
      source_ref: "s4-parallel",
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: bundle,
        bundle_bytes: bundle
      }
    })

    request = fixture("parallel_tool_use.request.json")
    sse = fixture("parallel_tool_use.sse")
    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 41)

    result = proxy(request_conn(request), upstream)
    body = resp_body(result)
    evs = events(body)

    refute body =~ ~s|"name":"Read"|
    assert body =~ ~s|"name":"Bash"|

    starts = Enum.filter(evs, &(&1["type"] == "content_block_start"))
    assert Enum.map(starts, & &1["index"]) == [0, 1, 2]
    assert Enum.map(starts, & &1["content_block"]["type"]) == ["thinking", "text", "tool_use"]

    # The allowed Bash block is byte-identical to upstream and comes after the replacement.
    bash_frames = sse |> String.split("\n\n", trim: true) |> Enum.filter(&(&1 =~ ~s|"index":2|))
    assert Enum.all?(bash_frames, &String.contains?(body, &1))
    [before, after_] = String.split(body, ~s|"name":"Bash"|)
    assert before =~ ~s|"text_delta"|
    assert after_ =~ ~s|"stop_reason":"tool_use"|

    %{tools: tools} = recorded(capture)

    assert Enum.sort(Enum.map(tools, fn {tool, outcome, _record} -> {tool, outcome} end)) == [
             {"Bash", "allow"},
             {"Read", "deny"}
           ]
  end

  test "non-streaming JSON with a denied tool_use is rewritten as JSON (no SSE frames)",
       %{upstream: upstream, capture: capture} do
    request = fixture("non_streaming_state_summary.request.json")

    message = %{
      "id" => "msg_json",
      "type" => "message",
      "role" => "assistant",
      "model" => "claude-haiku-4-5-20251001",
      "content" => [
        %{"type" => "text", "text" => "Cleaning up."},
        %{
          "type" => "tool_use",
          "id" => "toolu_JSON1",
          "name" => "Bash",
          "input" => %{"command" => "rm -rf /tmp/x"}
        }
      ],
      "stop_reason" => "tool_use",
      "usage" => %{"input_tokens" => 3, "output_tokens" => 4}
    }

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, Jason.encode!(message))
    end)

    result = proxy(request_conn(request), upstream)
    assert result.status == 200
    body = resp_body(result)
    refute body =~ "data: "
    decoded = Jason.decode!(body)

    assert [%{"type" => "text", "text" => "Cleaning up."}, %{"type" => "text", "text" => text}] =
             decoded["content"]

    assert text =~ "Tool call 'Bash' (call_id: toolu_JSON1) was blocked by org policy."
    assert decoded["stop_reason"] == "end_turn"

    %{call: call, answer: answer, tools: [{"Bash", "deny", _tool}]} = recorded(capture)
    assert EvidenceCapture.details(call)["requestKind"] == "side_query"

    assert %{"completionTokens" => 4, "parse.events_total" => 3} =
             EvidenceCapture.details(answer)
  end

  test "non-streaming JSON without tool_use passes through byte-for-byte", %{
    upstream: upstream,
    capture: capture
  } do
    request = fixture("non_streaming_state_summary.request.json")
    response = fixture("non_streaming_state_summary.response.json")

    MockHttpUpstream.expect(upstream, fn conn ->
      conn
      |> Plug.Conn.put_resp_header("content-type", "application/json")
      |> Plug.Conn.send_resp(200, response)
    end)

    result = proxy(request_conn(request), upstream)
    assert resp_body(result) == response
    %{call: call, answer: answer, tools: []} = recorded(capture)
    assert EvidenceCapture.body(call)["model"] == "claude-haiku-4-5-20251001"
    assert %{"completionTokens" => 74, "toolCalls" => 0} = EvidenceCapture.details(answer)
  end

  test "an unknown event type is forwarded, counted in the record, and kept", %{
    upstream: upstream,
    capture: capture
  } do
    request = fixture("text_only.request.json")

    sse =
      fixture("text_only.sse")
      |> String.replace(
        "event: message_stop",
        "event: telemetry\ndata: {\"type\":\"telemetry\",\"latency_ms\":1,\"secret\":\"S\"}\n\nevent: message_stop"
      )

    MockHttpUpstream.serve_sse(upstream, sse, chunk_size: 29)

    assert ParserDrift.new_since_boot() == 0
    result = proxy(request_conn(request), upstream)
    assert resp_body(result) == sse

    %{answer: answer, tools: []} = recorded(capture)

    assert %{"parse.events_unhandled" => 1, "parse.unhandled_types" => "event:telemetry"} =
             EvidenceCapture.details(answer)

    assert [row] = DriftStore.list(@tenant_id)
    assert row.api_format == "anthropic_messages"
    assert row.event_type == "event:telemetry"
    assert row.sample_redacted == "keys=latency_ms,secret,type"
    refute row.sample_redacted =~ "S\""
    assert ParserDrift.new_since_boot() == 1
  end
end
