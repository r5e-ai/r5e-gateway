defmodule Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest do
  @moduledoc """
  Failure-mode contract tests for `Recurse.Gateway.LlmProxy.StreamingProxy`
  (T033).

  Spec source:
  `specs/009-llm-api-proxy/contracts/streaming_proxy.md` §"Failure modes"
  + spec.md FR-016.

  | Failure | Behavior |
  |---|---|
  | Upstream connection fails | 503 to client |
  | Upstream 401 | forward unmodified |
  | Upstream 429 | forward unmodified, Retry-After preserved |
  | Parser failure mid-stream | fail-OPEN, forward subsequent chunks unchanged |
  | Cedar eval failure | fail-CLOSED (Sub-3.4 hook; not exercised here) |

  Cedar wiring is Sub-3.4; this MR ships the structure but no
  evaluator. The fail-CLOSED behavior on Cedar failure is verified in
  Sub-3.4's tests; here we document the behavior expected of the
  current `dispatch_directive/3` hook point: in absence of Cedar, all
  forward directives pass through unchanged.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Providers.Schemas.LlmProviderConfig

  setup do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)
    {:ok, upstream: upstream}
  end

  defp build_config(upstream) do
    %LlmProviderConfig{
      tenant_id: "01TEN_FAIL",
      provider: "test_fail_provider",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :bearer,
      api_format: :openai_responses,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }
  end

  defp build_conn(method, path, body, headers \\ []) do
    Plug.Test.conn(method, path, body)
    |> Map.update!(:req_headers, &(&1 ++ headers))
  end

  defp sent_resp_body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  defp sent_resp_body(%Plug.Conn{adapter: {Plug.Adapters.Test.Conn, %{chunks: chunks}}})
       when is_list(chunks) do
    IO.iodata_to_binary(chunks)
  end

  defp sent_resp_body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks) do
    chunks
  end

  defp sent_resp_body(_), do: ""

  describe "upstream connection failures → 503" do
    test "connect-refused returns 503 with structured error", %{upstream: _upstream} do
      cfg = %LlmProviderConfig{
        tenant_id: "01TEN_FAIL",
        provider: "test",
        upstream_host: "127.0.0.1",
        upstream_port: 1,
        transport_modes: ["https-sse"],
        auth_mode: :bearer,
        api_format: :openai_responses,
        enabled: true,
        metadata: %{"scheme" => "http"}
      }

      conn = build_conn(:post, "/v1/responses", "{}")

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.NoopParser
        })

      assert result.status == 503
      body = sent_resp_body(result)
      assert body =~ "ERR_UPSTREAM_UNAVAILABLE"
      assert body =~ "upstream_connection_failed"
    end
  end

  describe "upstream 401 / 429 — forward unmodified (FR-016)" do
    test "401 forwarded with body intact", %{upstream: upstream} do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(401, ~s|{"error":"invalid_token"}|)
      end)

      conn = build_conn(:post, "/v1/responses", "{}")
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.NoopParser
        })

      assert result.status == 401
      assert sent_resp_body(result) =~ "invalid_token"
    end

    test "429 forwarded with Retry-After preserved", %{upstream: upstream} do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("retry-after", "120")
        |> Plug.Conn.send_resp(429, ~s|{"error":"rate_limit"}|)
      end)

      conn = build_conn(:post, "/v1/responses", "{}")
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.NoopParser
        })

      assert result.status == 429

      headers =
        Enum.into(result.resp_headers, %{}, fn {k, v} -> {String.downcase(k), v} end)

      assert headers["retry-after"] == "120"
      assert sent_resp_body(result) =~ "rate_limit"
    end
  end

  describe "parser failure mid-stream → fail-OPEN" do
    test "parser raise on chunk forwards subsequent chunks unchanged", %{upstream: upstream} do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_content_type("text/event-stream")
          |> Plug.Conn.send_chunked(200)

        # Three chunks; the parser will raise on the second.
        Enum.reduce(["data: chunk-1\n\n", "data: chunk-2\n\n", "data: chunk-3\n\n"], conn, fn p,
                                                                                              c ->
          {:ok, c} = Plug.Conn.chunk(c, p)
          c
        end)
      end)

      conn = build_conn(:post, "/v1/responses", "{}")
      cfg = build_config(upstream)

      result =
        StreamingProxy.proxy(conn, %{
          llm_provider_config: cfg,
          tenant_id: "01TEN_FAIL",
          parser_module: Recurse.Gateway.LlmProxy.StreamingProxyFailureModesTest.RaisingParser
        })

      assert result.status == 200

      body = sent_resp_body(result)

      # All three chunks must reach the client even though the parser
      # raised on chunk 2 — fail-OPEN per contract.
      assert body =~ "chunk-1"
      assert body =~ "chunk-2"
      assert body =~ "chunk-3"

      # Spec 012 S4 review — after the raise the parser is never called
      # again (the proxy runs in this process, so the parser's
      # notifications land in our mailbox).
      assert_received {:parse_chunk_called, 1}
      assert_received {:parse_chunk_called, 2}
      refute_received {:parse_chunk_called, 3}
    end
  end

  defmodule NoopParser do
    @moduledoc false
    @behaviour Recurse.Shared.LlmProxy.Parsers.Parser

    @impl true
    def init(_opts), do: %{count: 0}

    @impl true
    def parse_chunk(state, chunk) do
      {%{state | count: state.count + 1}, [], [{:forward, chunk}]}
    end

    @impl true
    def finalize(state) do
      {%{event_count: state.count, intent_count: 0}, []}
    end
  end

  defmodule RaisingParser do
    @moduledoc false
    @behaviour Recurse.Shared.LlmProxy.Parsers.Parser

    @impl true
    def init(_opts), do: %{count: 0}

    @impl true
    def parse_chunk(state, chunk) do
      new_count = state.count + 1
      send(self(), {:parse_chunk_called, new_count})

      if new_count >= 2 do
        # Per Invariant I-001 parsers MUST NOT raise; we deliberately
        # violate to verify the proxy's fail-OPEN handling.
        raise "synthetic parser bug — should be caught by proxy"
      end

      {%{state | count: new_count}, [], [{:forward, chunk}]}
    end

    @impl true
    def finalize(state) do
      {%{event_count: state.count, intent_count: 0}, []}
    end
  end
end
