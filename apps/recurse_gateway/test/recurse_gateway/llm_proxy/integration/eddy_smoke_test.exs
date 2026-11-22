defmodule Recurse.Gateway.LlmProxy.Integration.EddySmokeTest do
  @moduledoc """
  A Codex CLI session through the WebSocket bridge, end to end, against
  a mock upstream on a local node.

  A client (driven here with Mint.WebSocket) connects to a Bandit
  endpoint hosting `Recurse.Gateway.LlmProxy.WebSocketBridge`; the
  bridge opens its own connection to the mock upstream, which streams an
  OpenAI Responses event sequence containing a `function_call` for the
  `shell` tool. The parser reads the tool use, the Cedar policy in the
  fixture decides, and when the session closes the bridge records the
  call as evidence.

  Three cases:

    * **deny `rm -rf`**: the client receives a synthetic message in
      place of the function call, the command never reaches it, and the
      tool use is recorded as denied;
    * **allow `ls`**: the function call is forwarded unchanged and
      recorded as allowed;
    * **OAuth passthrough**: `auth.openai.com` is recognised as a host
      whose traffic is not parsed or gated.

  Not async: the active policy, the provider registry and evidence
  capture are each one per node, and the database sandbox is shared so
  the Bandit worker can use it.
  """

  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag :tmp_dir

  alias Mint.HTTP, as: MintHttp
  alias Mint.WebSocket, as: MintWs
  alias Recurse.Gateway.LlmProxy.AuthPassthrough
  alias Recurse.Gateway.LlmProxy.WebSocketBridge
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.EvidenceCapture
  alias Recurse.Gateway.Test.MockWebsocketUpstream
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @tenant_id "01TEN_SMOKE_009_T075"

  # Sub-3.7-followon (US1 plumbing) — Codex-Enterprise-shaped JWT
  # injected on the WS upgrade headers. PrincipalExtractor decodes
  # WITHOUT signature verification, so the signature segment is
  # arbitrary bytes — only the header + payload need to be valid
  # base64url-JSON.
  @test_subject "user-eddy-corp-007"
  @test_chatgpt_account_id "acct_eddy_corp_42"
  @test_model "gpt-5-codex"
  @test_input_tokens 50
  @test_output_tokens 30

  defp build_test_jwt do
    header = %{"alg" => "RS256", "typ" => "JWT"}

    payload = %{
      "iss" => "https://auth.openai.com",
      "sub" => @test_subject,
      "chatgpt_account_id" => @test_chatgpt_account_id,
      "aud" => "chatgpt.com",
      "exp" => 9_999_999_999,
      "iat" => 1_700_000_000
    }

    encoded_header = Base.url_encode64(Jason.encode!(header), padding: false)
    encoded_payload = Base.url_encode64(Jason.encode!(payload), padding: false)

    encoded_header <> "." <> encoded_payload <> ".synthetic_signature_bytes"
  end

  @cedar_bundle_path Path.expand(
                       "../../../../../../specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/bundle.cedar",
                       __DIR__
                     )

  defmodule BridgeEndpoint do
    @moduledoc false
    @behaviour Plug

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts) do
      cfg = Keyword.fetch!(opts, :llm_provider_config)
      tenant_id = Keyword.fetch!(opts, :tenant_id)

      WebSocketBridge.upgrade(conn,
        llm_provider_config: cfg,
        tenant_id: tenant_id
      )
    end
  end

  setup %{tmp_dir: tmp_dir} do
    # 1. SQL Sandbox + shared mode — the WebSock callback runs in a
    # Bandit-spawned process that needs Repo access.
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
    capture = EvidenceCapture.start(tmp_dir)

    # 2. Tenant row (LlmCallRecord FK).
    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: @tenant_id,
        display_name: "Eddy smoke test tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

    # 3. ProviderRegistry — same shape as the AttestationEmitter
    # contract test: real Postgres-Merkle ledger + stub LLM/storage/
    # secrets. The real ledger is what writes the `attestations` rows
    # we assert against.
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant_id,
      signer: "observed://gateway/integration-eddy-smoke"
    })

    # 4. Cedar bundle → canonical `Active` store so the bridge's
    # `CedarToolUseGate.snapshot_bundle/0` finds it.
    original =
      case Active.current() do
        {:ok, envelope} -> envelope
        {:error, :not_loaded} -> :not_loaded
      end

    bundle_source = File.read!(@cedar_bundle_path)
    canonical_hash = Recurse.Cedar.canonical_hash(bundle_source)
    loaded_at = DateTime.utc_now()

    bundle_ref = %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: loaded_at,
      evaluator_handle: bundle_source,
      bundle_bytes: bundle_source
    }

    envelope = %Active{
      source: :filesystem,
      source_ref: @cedar_bundle_path,
      loaded_at: loaded_at,
      metadata: %{file_path: @cedar_bundle_path, fixture: :eddy_smoke},
      bundle: bundle_ref
    }

    :ok = Active.update(envelope)

    on_exit(fn ->
      ProviderRegistry.uninstall()

      case original do
        :not_loaded -> Active.erase()
        prior -> Active.update(prior)
      end
    end)

    {:ok, bundle_ref: bundle_ref, capture: capture}
  end

  # =========================================================================
  # Helpers — Bridge endpoint + mock upstream wiring
  # =========================================================================

  defp boot_bridge(upstream, opts \\ []) do
    cfg = %LlmProviderConfig{
      tenant_id: @tenant_id,
      provider: Keyword.get(opts, :provider, "openai_chatgpt"),
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["wss"],
      auth_mode: :bearer_plus_chatgpt_account_id,
      api_format: :openai_responses,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }

    {:ok, bridge_pid} =
      Bandit.start_link(
        plug: {BridgeEndpoint, llm_provider_config: cfg, tenant_id: @tenant_id},
        port: 0
      )

    {:ok, {_addr, bridge_port}} = ThousandIsland.listener_info(bridge_pid)

    on_exit(fn ->
      try do
        Process.exit(bridge_pid, :shutdown)
      catch
        _, _ -> :ok
      end
    end)

    {bridge_pid, bridge_port, cfg}
  end

  # Drive a single test client from "Codex's side" through the bridge.
  # Returns frames received until `response.completed` (or 1 of the
  # synthetic message events forces deny dispatch). The test then
  # closes the WS to trigger `terminate/2` in the bridge, which fires
  # the AttestationEmitter.
  defp drive_client_session(bridge_port, prompt_frame_payload, terminal_event_type) do
    # Sub-3.7-followon — pass a real Codex-shape JWT in the upgrade
    # request so PrincipalExtractor lands a real principal_id +
    # chatgpt_account_id on the LlmCallRecord.
    headers = [
      {"authorization", "Bearer " <> build_test_jwt()},
      {"chatgpt-account-id", @test_chatgpt_account_id}
    ]

    {:ok, ws_state} = open_client_ws(bridge_port, headers)

    ws_state = send_frame(ws_state, {:text, prompt_frame_payload})

    {:ok, ws_state, frames} =
      recv_until_terminal(ws_state, terminal_event_type, 8_000)

    close_ws(ws_state)
    # Give the bridge time to terminate and record the call.
    wait_for_recorded_calls(1, 5_000)
    frames
  end

  # =========================================================================
  # Helpers — Synthetic Codex / OpenAI Responses event stream
  # =========================================================================

  # The mock upstream is a fresh handler per test. It receives the client's
  # prompt frame (whatever bytes Codex would have sent) and pushes back a
  # canonical Responses-API stream that includes:
  #
  #   1. response.created
  #   2. response.output_item.added (function_call)
  #   3. response.function_call.arguments.delta (chunked)
  #   4. response.function_call.completed
  #   5. response.completed
  #
  # The arguments JSON is configurable so we can exercise allow vs deny.
  defp configure_upstream_for_shell_call(upstream, command_string) do
    args_json = Jason.encode!(%{"command" => command_string})
    chunks = chunk_string(args_json, 16)
    call_id = "call_test_#{:erlang.unique_integer([:positive])}"

    MockWebsocketUpstream.expect(upstream, fn
      {:text, _client_payload}, state ->
        events =
          [
            Jason.encode!(%{
              "type" => "response.created",
              "response" => %{
                "id" => "resp_test_#{call_id}",
                # Sub-3.7-followon — inject a model so the
                # parser's summary populates the LlmCallRecord.model
                # column (no longer "unknown").
                "model" => @test_model
              }
            }),
            Jason.encode!(%{
              "type" => "response.output_item.added",
              "output_index" => 0,
              "item" => %{
                "type" => "function_call",
                "call_id" => call_id,
                "name" => "shell",
                "arguments" => ""
              }
            })
          ] ++
            Enum.map(chunks, fn delta ->
              Jason.encode!(%{
                "type" => "response.function_call.arguments.delta",
                "call_id" => call_id,
                "item_id" => call_id,
                "delta" => delta
              })
            end) ++
            [
              Jason.encode!(%{
                "type" => "response.function_call.completed",
                "call_id" => call_id,
                "item_id" => call_id,
                "arguments" => args_json
              }),
              Jason.encode!(%{
                "type" => "response.completed",
                "response" => %{
                  "id" => "resp_test_#{call_id}",
                  "usage" => %{
                    "input_tokens" => @test_input_tokens,
                    "output_tokens" => @test_output_tokens
                  }
                }
              })
            ]

        push_frames = Enum.map(events, fn ev -> {:text, ev} end)
        {:push, push_frames, state}

      _other_frame, state ->
        {:ok, state}
    end)

    %{call_id: call_id, args_json: args_json}
  end

  defp chunk_string(s, chunk_size) when is_binary(s) and chunk_size > 0 do
    do_chunk(s, chunk_size, [])
  end

  defp do_chunk(<<>>, _, acc), do: Enum.reverse(acc)

  defp do_chunk(s, n, acc) do
    case s do
      <<head::binary-size(n), rest::binary>> -> do_chunk(rest, n, [head | acc])
      _ -> Enum.reverse([s | acc])
    end
  end

  # =========================================================================
  # Helpers — what was recorded
  # =========================================================================

  # The bridge records a call when its session ends, in its own process.
  defp wait_for_recorded_calls(expected, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    do_wait_for_recorded_calls(expected, deadline)
  end

  defp do_wait_for_recorded_calls(expected, deadline) do
    cond do
      length(answers()) >= expected ->
        :ok

      System.monotonic_time(:millisecond) > deadline ->
        :timeout

      true ->
        Process.sleep(50)
        do_wait_for_recorded_calls(expected, deadline)
    end
  end

  defp records, do: EvidenceCapture.records(Recurse.Gateway.Provenance.Runtime.info())
  defp answers, do: EvidenceCapture.of_kind(records(), "ModelResponse")

  # What every recorded call must carry, whatever policy decided: who
  # made it, which model answered, how much was used, and references to
  # the bytes that crossed the wire.
  defp assert_call_recorded(records, bundle_ref) do
    call = EvidenceCapture.one(records, "ModelCall")
    answer = EvidenceCapture.one(records, "ModelResponse")
    tool = EvidenceCapture.one(records, "ToolCall")

    assert call.evidence["actor"] =~ @test_subject
    assert EvidenceCapture.body(call)["model"] == @test_model
    assert EvidenceCapture.details(call)["transport"] == "wss"

    assert %{
             "promptTokens" => @test_input_tokens,
             "completionTokens" => @test_output_tokens,
             "toolCalls" => 1
           } = EvidenceCapture.details(answer)

    assert "bytes:sha256:" <> _ = EvidenceCapture.body(call)["contentRef"]
    assert "bytes:sha256:" <> _ = EvidenceCapture.body(answer)["contentRef"]
    assert EvidenceCapture.body(call)["contentRef"] != EvidenceCapture.body(answer)["contentRef"]

    # The tool use names the exact policy that decided it.
    assert EvidenceCapture.body(tool)["policy"]["policyRef"] ==
             Recurse.Provenance.Ref.bytes(bundle_ref.bundle_bytes)

    assert tool.evidence["causes"] == [call.ref]
    {call, answer, tool}
  end

  # =========================================================================
  # Tests
  # =========================================================================

  describe "Eddy uses Codex CLI under enforcement: deny rm -rf" do
    test "a synthetic denial replaces the function call, and the denial is recorded",
         %{bundle_ref: bundle_ref} do
      {:ok, upstream} = MockWebsocketUpstream.start()
      on_exit(fn -> MockWebsocketUpstream.stop(upstream) end)

      _meta = configure_upstream_for_shell_call(upstream, "rm -rf /tmp/test-dir")

      {_pid, bridge_port, _cfg} = boot_bridge(upstream)

      frames =
        drive_client_session(bridge_port, "{\"prompt\":\"delete temp\"}", "response.completed")

      texts =
        for {:text, payload} <- frames, do: payload

      # Recover the parsed events the client received. response.completed
      # MUST appear (the upstream's terminal event was forwarded).
      parsed =
        for t <- texts,
            match?({:ok, _}, Jason.decode(t)),
            {:ok, ev} = Jason.decode(t),
            do: ev

      assert Enum.any?(parsed, fn ev -> ev["type"] == "response.created" end),
             "client never received response.created; texts=#{inspect(texts)}"

      # Synthetic denial path: the injector emits 3 events
      #   response.output_item.added (item.type=message,  status=in_progress)
      #   response.output_text.delta (with denial text body)
      #   response.output_item.completed (item.type=message, status=completed)
      synthetic_added =
        Enum.filter(parsed, fn ev ->
          ev["type"] == "response.output_item.added" &&
            get_in(ev, ["item", "type"]) == "message" &&
            get_in(ev, ["item", "status"]) == "in_progress"
        end)

      synthetic_completed =
        Enum.filter(parsed, fn ev ->
          ev["type"] == "response.output_item.completed" &&
            get_in(ev, ["item", "type"]) == "message" &&
            get_in(ev, ["item", "status"]) == "completed"
        end)

      synthetic_deltas =
        Enum.filter(parsed, fn ev -> ev["type"] == "response.output_text.delta" end)

      assert length(synthetic_added) >= 1,
             "expected at least one synthetic message added event; got #{inspect(parsed)}"

      assert length(synthetic_completed) >= 1,
             "expected at least one synthetic message completed event"

      assert length(synthetic_deltas) >= 1,
             "expected at least one synthetic output_text.delta with denial text"

      # The denial text body MUST mention the rule_id and template tokens.
      denial_delta = hd(synthetic_deltas)
      delta_text = denial_delta["delta"] || ""

      assert delta_text =~ "blocked",
             "denial text missing blocked-by-policy phrasing; got: #{inspect(delta_text)}"

      assert delta_text =~ "shell",
             "denial text should name the denied tool; got: #{inspect(delta_text)}"

      # Radical-transparency-by-default. The agent (and the human
      # appealing the denial) MUST see every load-bearing identifier
      # in the synthetic message text — no obfuscation, no "contact
      # your administrator." If any of these regress out, file an
      # exception goes back to being archeology.
      assert delta_text =~ "Rule:",
             "denial text missing rule_id label; got: #{inspect(delta_text)}"

      assert delta_text =~ "policy1",
             "denial text missing rule_id value; got: #{inspect(delta_text)}"

      assert delta_text =~ "Tenant:",
             "denial text missing tenant_id label; got: #{inspect(delta_text)}"

      assert delta_text =~ "Principal:",
             "denial text missing principal_id label; got: #{inspect(delta_text)}"

      assert delta_text =~ "user-eddy-corp-007",
             "denial text should include the principal_id (user-eddy-corp-007); got: #{inspect(delta_text)}"

      assert delta_text =~ "obo_human",
             "denial text should include principal_kind; got: #{inspect(delta_text)}"

      assert delta_text =~ "Policy bundle:",
             "denial text missing cedar_bundle_hash_short label; got: #{inspect(delta_text)}"

      # Spec 012 S7: the appeal line exists only when the tenant configured
      # `appeal_uri` / `appeal_contact` (this fixture sets neither), so no
      # generic "contact your administrator" filler is rendered.
      refute delta_text =~ "appeal",
             "denial text rendered an appeal line with no appeal pointer configured; got: #{inspect(delta_text)}"

      # ---------------------------------------------------------------------
      # R5E-102 — Phase 6 byte-precise suppression. The deny path MUST
      # drop the original function_call frames entirely. If any of these
      # frames reaches the client, codex (or any agent harness) WILL
      # execute the tool locally before noticing the denial — that's the
      # exact bug Phase 6 fixes. This is the load-bearing assertion for
      # "the policy enforcement tool actually enforces policy."
      # ---------------------------------------------------------------------
      original_fcall_added =
        Enum.filter(parsed, fn ev ->
          ev["type"] == "response.output_item.added" &&
            get_in(ev, ["item", "type"]) == "function_call"
        end)

      original_fcall_args_delta =
        Enum.filter(parsed, fn ev ->
          ev["type"] in [
            "response.function_call.arguments.delta",
            "response.function_call_arguments.delta"
          ]
        end)

      original_fcall_completed =
        Enum.filter(parsed, fn ev ->
          ev["type"] in [
            "response.function_call.completed",
            "response.function_call_arguments.done"
          ]
        end)

      original_fcall_output_done =
        Enum.filter(parsed, fn ev ->
          ev["type"] in ["response.output_item.done", "response.output_item.completed"] &&
            get_in(ev, ["item", "type"]) == "function_call"
        end)

      assert original_fcall_added == [],
             "DENY path leaked function_call output_item.added to client — codex would have executed the tool locally before seeing the denial. R5E-102 NOT FIXED. Frames: #{inspect(original_fcall_added)}"

      assert original_fcall_args_delta == [],
             "DENY path leaked function_call argument deltas — codex would have reconstructed and executed the tool. R5E-102 NOT FIXED. Frames: #{inspect(original_fcall_args_delta)}"

      assert original_fcall_completed == [],
             "DENY path leaked function_call.completed — codex would have executed. R5E-102 NOT FIXED. Frames: #{inspect(original_fcall_completed)}"

      assert original_fcall_output_done == [],
             "DENY path leaked output_item.done for function_call — codex would have at minimum logged the call as observed. R5E-102 NOT FIXED. Frames: #{inspect(original_fcall_output_done)}"

      # And the destructive shell command MUST NOT appear in any frame
      # the client received (defense in depth: even if the agent harness
      # reconstructs from raw text instead of structured events, the
      # command bytes never crossed the wire).
      all_text = Enum.join(texts, "\n")

      refute all_text =~ "rm -rf /tmp/test-dir",
             "DENY path leaked the rm -rf command in some text frame. The command bytes MUST NOT reach the client on a deny verdict. Texts: #{inspect(texts)}"

      # What was recorded: one call, its one tool use denied.
      {_call, _answer, tool} = assert_call_recorded(records(), bundle_ref)
      assert EvidenceCapture.body(tool)["policy"]["outcome"] == "deny"
      assert EvidenceCapture.body(tool)["result"]["outcome"] == "denied"
    end
  end

  describe "Eddy uses Codex CLI under enforcement: allow ls" do
    test "the function call is forwarded unchanged and recorded as allowed",
         %{bundle_ref: bundle_ref} do
      {:ok, upstream} = MockWebsocketUpstream.start()
      on_exit(fn -> MockWebsocketUpstream.stop(upstream) end)

      _meta = configure_upstream_for_shell_call(upstream, "ls -la")

      {_pid, bridge_port, _cfg} = boot_bridge(upstream)

      frames =
        drive_client_session(bridge_port, "{\"prompt\":\"list files\"}", "response.completed")

      texts =
        for {:text, payload} <- frames, do: payload

      parsed =
        for t <- texts,
            match?({:ok, _}, Jason.decode(t)),
            {:ok, ev} = Jason.decode(t),
            do: ev

      # Allow path: function_call.completed MUST be forwarded; no
      # synthetic message frames replace it.
      assert Enum.any?(parsed, fn ev -> ev["type"] == "response.function_call.completed" end),
             "function_call.completed should have forwarded on allow path; texts=#{inspect(texts)}"

      synthetic_added =
        Enum.filter(parsed, fn ev ->
          ev["type"] == "response.output_item.added" &&
            get_in(ev, ["item", "type"]) == "message" &&
            get_in(ev, ["item", "status"]) == "in_progress"
        end)

      assert synthetic_added == [],
             "should not have emitted synthetic message frames on allow; got #{inspect(synthetic_added)}"

      # What was recorded: one call, its one tool use allowed.
      {_call, _answer, tool} = assert_call_recorded(records(), bundle_ref)
      assert EvidenceCapture.body(tool)["policy"]["outcome"] == "allow"
      refute Map.has_key?(EvidenceCapture.body(tool), "result")
    end
  end

  describe "two sessions" do
    test "are recorded with references to their own bytes", %{bundle_ref: _bundle_ref} do
      {:ok, upstream1} = MockWebsocketUpstream.start()
      on_exit(fn -> MockWebsocketUpstream.stop(upstream1) end)
      _ = configure_upstream_for_shell_call(upstream1, "ls -la")
      {_pid1, port1, _cfg1} = boot_bridge(upstream1)

      _ = drive_client_session(port1, "{\"prompt\":\"first session\"}", "response.completed")

      # A different prompt, and an upstream stream that differs because
      # each carries its own call id.
      {:ok, upstream2} = MockWebsocketUpstream.start()
      on_exit(fn -> MockWebsocketUpstream.stop(upstream2) end)
      _ = configure_upstream_for_shell_call(upstream2, "ls -la")
      {_pid2, port2, _cfg2} = boot_bridge(upstream2)

      _ =
        drive_client_session(
          port2,
          "{\"prompt\":\"second session different bytes\"}",
          "response.completed"
        )

      assert :ok = wait_for_recorded_calls(2, 5_000)
      recorded = records()

      assert [p1, p2] =
               recorded
               |> EvidenceCapture.of_kind("ModelCall")
               |> Enum.map(&EvidenceCapture.body(&1)["contentRef"])

      assert [r1, r2] =
               recorded
               |> EvidenceCapture.of_kind("ModelResponse")
               |> Enum.map(&EvidenceCapture.body(&1)["contentRef"])

      refute p1 == p2
      refute r1 == r2
    end
  end

  describe "OAuth flow passthrough host detection" do
    # Full OAuth replay through Mint is doable but adds substantial
    # surface for marginal value: AuthPassthrough's behavior is
    # already covered structurally by `auth_passthrough_test.exs` +
    # `proxy_router_test.exs` ("auth.openai.com special case (T032)").
    # The integration concern at THIS layer is "the dispatcher
    # routes auth.openai.com away from the WS-bridge + Cedar-gate
    # path entirely". We exercise that structural property here.
    test "auth.openai.com is recognized as passthrough; chatgpt.com is NOT" do
      assert AuthPassthrough.passthrough_host?("auth.openai.com")
      assert AuthPassthrough.passthrough_host?("AUTH.OPENAI.COM")
      refute AuthPassthrough.passthrough_host?("chatgpt.com")
      refute AuthPassthrough.passthrough_host?("api.openai.com")
    end
  end

  # =========================================================================
  # Mint.WebSocket client driver — borrowed from web_socket_bridge_test.exs
  # =========================================================================

  defmodule WsState do
    @moduledoc false
    defstruct [:conn, :ref, :ws, :open?]
  end

  defp open_client_ws(port, extra_headers) do
    {:ok, conn} =
      MintHttp.connect(:http, "127.0.0.1", port, protocols: [:http1])

    {:ok, conn, ref} = MintWs.upgrade(:ws, conn, "/", extra_headers)

    state = %WsState{conn: conn, ref: ref, open?: false}
    drain_until_open(state, 3_000)
  end

  defp drain_until_open(state, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_drain_until_open(state, deadline)
  end

  defp do_drain_until_open(state, deadline) do
    if System.monotonic_time(:millisecond) > deadline do
      {:error, :timeout}
    else
      receive do
        msg ->
          case MintHttp.stream(state.conn, msg) do
            {:ok, conn, responses} ->
              state = %{state | conn: conn}

              {state, opened?} =
                Enum.reduce(responses, {state, false}, fn
                  {:status, ref, 101}, {st, _} when ref == st.ref ->
                    {Map.put(st, :_pending_status, 101), false}

                  {:headers, ref, headers}, {st, _} when ref == st.ref ->
                    {Map.put(st, :_pending_headers, headers), false}

                  {:done, ref}, {st, _} when ref == st.ref ->
                    case MintWs.new(st.conn, st.ref, 101, st._pending_headers) do
                      {:ok, conn, ws} ->
                        st =
                          %{st | conn: conn, ws: ws, open?: true}
                          |> Map.delete(:_pending_status)
                          |> Map.delete(:_pending_headers)

                        {st, true}

                      _ ->
                        {st, false}
                    end

                  _, acc ->
                    acc
                end)

              if opened? do
                {:ok, state}
              else
                do_drain_until_open(state, deadline)
              end

            {:error, _conn, reason, _} ->
              {:error, reason}

            :unknown ->
              do_drain_until_open(state, deadline)
          end
      after
        100 ->
          do_drain_until_open(state, deadline)
      end
    end
  end

  defp send_frame(state, frame) do
    {:ok, ws, data} = MintWs.encode(state.ws, frame)
    {:ok, conn} = MintWs.stream_request_body(state.conn, state.ref, data)
    %{state | conn: conn, ws: ws}
  end

  defp recv_until_terminal(state, terminal_event_type, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_recv_until_terminal(state, terminal_event_type, deadline, [])
  end

  defp do_recv_until_terminal(state, terminal_type, deadline, acc) do
    if System.monotonic_time(:millisecond) > deadline do
      if Enum.empty?(acc) do
        {:error, :timeout}
      else
        {:ok, state, acc}
      end
    else
      receive do
        msg ->
          case MintWs.stream(state.conn, msg) do
            {:ok, conn, mint_messages} ->
              state = %{state | conn: conn}

              {state, frames} =
                Enum.reduce(mint_messages, {state, acc}, fn
                  {:data, ref, payload}, {st, fr} when ref == st.ref ->
                    case MintWs.decode(st.ws, payload) do
                      {:ok, ws, decoded} -> {%{st | ws: ws}, fr ++ decoded}
                      _ -> {st, fr}
                    end

                  _, acc2 ->
                    acc2
                end)

              if terminal_seen?(frames, terminal_type) do
                {:ok, state, frames}
              else
                do_recv_until_terminal(state, terminal_type, deadline, frames)
              end

            {:error, _conn, _reason, _} ->
              if Enum.empty?(acc) do
                {:error, :stream_error}
              else
                {:ok, state, acc}
              end

            :unknown ->
              do_recv_until_terminal(state, terminal_type, deadline, acc)
          end
      after
        100 ->
          do_recv_until_terminal(state, terminal_type, deadline, acc)
      end
    end
  end

  defp terminal_seen?(frames, terminal_type) do
    Enum.any?(frames, fn
      {:text, payload} ->
        case Jason.decode(payload) do
          {:ok, %{"type" => ^terminal_type}} -> true
          _ -> false
        end

      _ ->
        false
    end)
  end

  defp close_ws(state) do
    case MintWs.encode(state.ws, :close) do
      {:ok, _ws, data} -> _ = MintWs.stream_request_body(state.conn, state.ref, data)
      _ -> :ok
    end

    _ = MintHttp.close(state.conn)
    :ok
  end
end
