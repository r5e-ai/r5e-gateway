defmodule Recurse.Gateway.LlmProxy.ZdrRoutesTest do
  @moduledoc """
  Unit and integration tests for structured route-bound ZDR upstream selection
  (`R5E_UPSTREAM_ZDR_ROUTES`): primary ZDR, fallback-to-ZDR, fallback-to-non-ZDR
  fail-closed, bare hostname refusal, CedarToolUseGate context propagation, and
  ChatCompletionsHandler end-to-end enforcement.
  """

  use ExUnit.Case, async: false

  import Mox
  import Plug.Conn
  import Plug.Test

  alias Recurse.Cedar
  alias Recurse.Gateway.DataPlane.ChatCompletionsHandler
  alias Recurse.Gateway.LlmProxy.{CedarToolUseGate, ZdrRoutes}
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.{PolicyBundleRef, ProviderRegistry}
  alias Recurse.Gateway.Test.Mocks.LLMProvider, as: LLMMock
  alias Recurse.Gateway.Test.Mocks.StorageProvider, as: StorageMock
  alias Recurse.Providers.Schemas.LlmProviderConfig
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.LlmProxy.ToolUseIntent
  alias Recurse.Shared.Principal

  setup :verify_on_exit!

  @valid_evidence "bytes:sha256:" <> String.duplicate("a", 64)
  @fallback_evidence "bytes:sha256:" <> String.duplicate("b", 64)

  @routes_json JSON.encode!(%{
                 "failClosedOnNonZdrFallback" => true,
                 "routes" => [
                   %{
                     "routeId" => "anthropic-zdr-primary",
                     "endpointUrl" => "https://api.anthropic.com/v1/messages",
                     "providerCredentialRef" => "secret://district/anthropic-zdr-key",
                     "projectRef" => "proj_zdr_001",
                     "zdrContracted" => true,
                     "zdrEvidenceRef" => @valid_evidence,
                     "fallbackRouteId" => "openai-zdr-fallback"
                   },
                   %{
                     "routeId" => "openai-zdr-fallback",
                     "endpointUrl" => "https://api.openai.com/v1/chat/completions",
                     "providerCredentialRef" => "secret://district/openai-zdr-key",
                     "projectRef" => "proj_zdr_002",
                     "zdrContracted" => true,
                     "zdrEvidenceRef" => @fallback_evidence
                   },
                   %{
                     "routeId" => "anthropic-zdr-bad-fallback",
                     "endpointUrl" => "https://api.anthropic.com/v1/messages",
                     "providerCredentialRef" => "secret://district/anthropic-zdr-key",
                     "projectRef" => "proj_zdr_001",
                     "zdrContracted" => true,
                     "zdrEvidenceRef" => @valid_evidence,
                     "fallbackRouteId" => "consumer-non-zdr"
                   },
                   %{
                     "routeId" => "consumer-non-zdr",
                     "endpointUrl" => "https://api.openai.com/v1/chat/completions",
                     "providerCredentialRef" => "secret://dev/consumer-key",
                     "zdrContracted" => false
                   },
                   %{
                     "routeId" => "missing-evidence-route",
                     "endpointUrl" => "https://api.anthropic.com/v1/messages",
                     "providerCredentialRef" => "secret://district/anthropic-key",
                     "zdrContracted" => true,
                     "zdrEvidenceRef" => "not-a-sha256-ref"
                   },
                   %{
                     "routeId" => "missing-cred-route",
                     "endpointUrl" => "https://api.anthropic.com/v1/messages",
                     "zdrContracted" => true,
                     "zdrEvidenceRef" => @valid_evidence
                   }
                 ]
               })

  describe "parse_env!/1 and zdr_pinned?/1" do
    test "parses structured JSON route definitions and fails on malformed JSON" do
      routes = ZdrRoutes.parse_env!(@routes_json)
      assert length(routes) == 6
      assert ZdrRoutes.parse_env!(nil) == []
      assert ZdrRoutes.parse_env!("   ") == []

      assert_raise ArgumentError, ~r/invalid R5E_UPSTREAM_ZDR_ROUTES JSON/, fn ->
        ZdrRoutes.parse_env!("{not-json")
      end

      assert_raise ArgumentError, ~r/invalid R5E_UPSTREAM_ZDR_ROUTES configuration/, fn ->
        ZdrRoutes.parse_env!(~s([{"endpointUrl": "https://api.anthropic.com"}]))
      end
    end

    test "zdr_pinned?/1 requires zdrContracted, non-empty providerCredentialRef, and valid bytes:sha256 zdrEvidenceRef" do
      routes = ZdrRoutes.parse_env!(@routes_json)
      by_id = Map.new(routes, &{&1.route_id, &1})

      assert ZdrRoutes.zdr_pinned?(by_id["anthropic-zdr-primary"])
      assert ZdrRoutes.zdr_pinned?(by_id["openai-zdr-fallback"])
      refute ZdrRoutes.zdr_pinned?(by_id["consumer-non-zdr"])
      refute ZdrRoutes.zdr_pinned?(by_id["missing-evidence-route"])
      refute ZdrRoutes.zdr_pinned?(by_id["missing-cred-route"])
      refute ZdrRoutes.zdr_pinned?(nil)
    end
  end

  describe "select_route/2 — primary ZDR, fallback-to-ZDR, and fallback-to-non-ZDR fail-closed" do
    setup do
      {:ok, routes: ZdrRoutes.parse_env!(@routes_json)}
    end

    test "primary contracted ZDR route evaluates upstream_zdr_pinned: true", %{routes: routes} do
      assert {:ok, sel} =
               ZdrRoutes.select_route("anthropic-zdr-primary",
                 routes: routes,
                 primary_available?: true
               )

      assert sel.upstream_route_id == "anthropic-zdr-primary"
      assert sel.upstream_zdr_pinned == true
      assert sel.via_fallback? == false
    end

    test "fallback to contracted ZDR route evaluates upstream_zdr_pinned: true", %{routes: routes} do
      assert {:ok, sel} =
               ZdrRoutes.select_route("anthropic-zdr-primary",
                 routes: routes,
                 primary_available?: false
               )

      assert sel.upstream_route_id == "openai-zdr-fallback"
      assert sel.upstream_zdr_pinned == true
      assert sel.via_fallback? == true
    end

    test "fallback to non-ZDR route fails closed with non_zdr_fallback_refused", %{routes: routes} do
      assert {:error, :non_zdr_fallback_refused, details} =
               ZdrRoutes.select_route("anthropic-zdr-bad-fallback",
                 routes: routes,
                 primary_available?: false
               )

      assert details.primary_route_id == "anthropic-zdr-bad-fallback"
      assert details.fallback_route_id == "consumer-non-zdr"
      assert details.upstream_zdr_pinned == false
    end

    test "bare hostname without a structured route never sets upstream_zdr_pinned: true", %{
      routes: routes
    } do
      cfg = %LlmProviderConfig{upstream_host: "api.anthropic.com", metadata: %{}}
      assert {:ok, ctx} = ZdrRoutes.cedar_context_for_config(cfg, routes: routes)
      assert ctx == %{upstream_route_id: "", upstream_zdr_pinned: false}
    end
  end

  describe "CedarToolUseGate & ChatCompletionsHandler integration" do
    @zdr_tool_bundle ~S"""
    permit (
      principal,
      action == Action::"invoke_tool",
      resource
    ) when {
      context.upstream_zdr_pinned == true
    };
    """

    @zdr_chat_bundle ~S"""
    permit (
      principal,
      action == Recurse::Action::"ChatCompletion",
      resource
    ) when {
      principal has recurse_role &&
      principal.recurse_role == "caller" &&
      context.upstream_zdr_pinned == true
    };
    """

    test "CedarToolUseGate enforces context.upstream_zdr_pinned from selected route" do
      routes = ZdrRoutes.parse_env!(@routes_json)
      bundle_hash = Cedar.canonical_hash(@zdr_tool_bundle)

      bundle = %PolicyBundleRef{
        bundle_id: Base.encode16(bundle_hash, case: :lower),
        canonical_hash: bundle_hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: @zdr_tool_bundle,
        bundle_bytes: @zdr_tool_bundle
      }

      {:ok, intent} =
        ToolUseIntent.new(%{
          call_id: "call_zdr",
          tool_name: "read_file",
          tool_args: %{"path" => "notes.md"},
          provider_event_span: %{start_byte_offset: 0, end_byte_offset: 10, event_indices: [0]}
        })

      {:ok, zdr_sel} = ZdrRoutes.select_route("anthropic-zdr-primary", routes: routes)

      base_ctx = %{
        principal: %{id: "student-1", kind: :obo_human, chatgpt_account_id: nil, claims: %{}},
        model: "claude-sonnet",
        tenant: "district-1",
        session_id: "sess-1",
        prompt_hash: <<0::256>>,
        response_so_far_hash: <<0::256>>,
        estimated_completion_tokens: 10,
        cedar_bundle_hash: bundle_hash,
        upstream_domain: "api.anthropic.com",
        transport: :https_sse,
        started_at: DateTime.utc_now(),
        bundle: bundle,
        cache: [table_name: :zdr_gate_test_nonexistent]
      }

      # Selected contracted ZDR route -> allowed
      assert {:allow} =
               CedarToolUseGate.evaluate(
                 intent,
                 Map.merge(base_ctx, %{
                   upstream_route_id: zdr_sel.upstream_route_id,
                   upstream_zdr_pinned: zdr_sel.upstream_zdr_pinned
                 })
               )

      # Bare hostname with no ZDR route -> upstream_zdr_pinned defaults false -> denied
      assert {:deny, _} = CedarToolUseGate.evaluate(intent, base_ctx)
    end

    test "ChatCompletionsHandler allows primary ZDR & fallback-to-ZDR, denies non-ZDR via Cedar, and fails closed on fallback-to-non-ZDR" do
      prev_routes = Application.get_env(:recurse_gateway, :upstream_zdr_routes)

      Application.put_env(
        :recurse_gateway,
        :upstream_zdr_routes,
        ZdrRoutes.parse_env!(@routes_json)
      )

      on_exit(fn ->
        ProviderRegistry.uninstall()

        if is_nil(prev_routes),
          do: Application.delete_env(:recurse_gateway, :upstream_zdr_routes),
          else: Application.put_env(:recurse_gateway, :upstream_zdr_routes, prev_routes)
      end)

      ProviderRegistry.install_raw!(%{
        llm: {LLMMock, %{}},
        ledger: {Recurse.Gateway.LlmProxy.ZdrRoutesTest.StubLedger, %{}},
        storage: {StorageMock, %{}},
        secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{backend: :stub}},
        tenant_id: "district-test",
        signer: "observed://gateway/test"
      })

      hash = Cedar.canonical_hash(@zdr_chat_bundle)

      :ok =
        Active.update(%Active{
          bundle: %PolicyBundleRef{
            bundle_id: Base.encode16(hash, case: :lower),
            canonical_hash: hash,
            loaded_at: DateTime.utc_now(),
            evaluator_handle: @zdr_chat_bundle,
            bundle_bytes: @zdr_chat_bundle
          },
          source: :filesystem,
          source_ref: "test-zdr",
          loaded_at: DateTime.utc_now()
        })

      ctx =
        IdentityContext.new(%{
          machine_identity: "spiffe://recurse.test/workload/test",
          principal:
            Principal.obo_human(%{
              subject: "student-1",
              issuer: "https://idp.example",
              groups: [],
              recurse_role: "caller"
            }),
          tenant_id: "district-test",
          correlation_id: "01TESTCORR"
        })

      body = %{"model" => "gpt-4o-mini", "messages" => [%{"role" => "user", "content" => "hi"}]}

      upstream_ok =
        JSON.encode!(%{
          "id" => "chatcmpl-zdr",
          "object" => "chat.completion",
          "model" => "gpt-4o-mini",
          "choices" => [%{"index" => 0, "message" => %{"role" => "assistant", "content" => "ok"}}]
        })

      expect(LLMMock, :chat_complete, 2, fn _state, _req, _ctx ->
        {:ok, %{status: 200, headers: [], body: upstream_ok}}
      end)

      expect(StorageMock, :put_payload, 3, fn _state, _bytes, _ctx ->
        {:ok, %{uri: "s3://test/zdr-run.json", hash: <<0::256>>}}
      end)

      # 1. Primary ZDR route -> 200 non-refusal
      conn_ok =
        conn(:post, "/v1/chat/completions")
        |> put_req_header("x-r5e-upstream-route", "anthropic-zdr-primary")
        |> Map.put(:body_params, body)
        |> Plug.Conn.assign(:identity_ctx, ctx)
        |> ChatCompletionsHandler.handle()

      assert conn_ok.status == 200
      resp_ok = JSON.decode!(conn_ok.resp_body)
      assert get_in(resp_ok, ["choices", Access.at(0), "message", "refusal"]) == nil

      # 2. Fallback to ZDR route -> 200 non-refusal
      conn_fb_ok =
        conn(:post, "/v1/chat/completions")
        |> put_req_header("x-r5e-upstream-route", "anthropic-zdr-primary")
        |> put_req_header("x-r5e-upstream-fallback", "true")
        |> Map.put(:body_params, body)
        |> Plug.Conn.assign(:identity_ctx, ctx)
        |> ChatCompletionsHandler.handle()

      assert conn_fb_ok.status == 200
      resp_fb_ok = JSON.decode!(conn_fb_ok.resp_body)
      assert get_in(resp_fb_ok, ["choices", Access.at(0), "message", "refusal"]) == nil

      # 3. Non-ZDR route -> Cedar denies (context.upstream_zdr_pinned == false), LLM never called
      conn_non_zdr =
        conn(:post, "/v1/chat/completions")
        |> put_req_header("x-r5e-upstream-route", "consumer-non-zdr")
        |> Map.put(:body_params, body)
        |> Plug.Conn.assign(:identity_ctx, ctx)
        |> ChatCompletionsHandler.handle()

      assert conn_non_zdr.status == 200
      resp_non_zdr = JSON.decode!(conn_non_zdr.resp_body)
      assert is_binary(get_in(resp_non_zdr, ["choices", Access.at(0), "message", "refusal"]))

      # 4. Fallback to non-ZDR route -> fails closed with 503 non_zdr_fallback_refused
      conn_fb_fail =
        conn(:post, "/v1/chat/completions")
        |> put_req_header("x-r5e-upstream-route", "anthropic-zdr-bad-fallback")
        |> put_req_header("x-r5e-upstream-fallback", "true")
        |> Map.put(:body_params, body)
        |> Plug.Conn.assign(:identity_ctx, ctx)
        |> ChatCompletionsHandler.handle()

      assert conn_fb_fail.status == 503
      assert conn_fb_fail.resp_body =~ "non_zdr_fallback_refused"
    end
  end
end

defmodule Recurse.Gateway.LlmProxy.ZdrRoutesTest.StubLedger do
  @moduledoc false
  @behaviour Recurse.Providers.LedgerProvider

  def commit_attestation(_envelope, _opts) do
    {:ok,
     %{
       run_id: "01HQZN5K7J8M9N0P1Q2R3S4T5X",
       verification_level: :local_inclusion_verified,
       session_chain_root: <<0::256>>,
       global_inclusion_proof: <<>>
     }}
  end

  @impl true
  def init(_), do: {:ok, %{}}
  @impl true
  def commit_epoch(_state, _session_id, _epoch, _leaves), do: {:error, :not_implemented}
  @impl true
  def inclusion_proof(_state, _session_id, _index), do: {:error, :not_implemented}
  @impl true
  def consistency_proof(_state, _session_id, _from), do: {:error, :not_implemented}
  @impl true
  def current_root(_state), do: {:error, :not_implemented}
  @impl true
  def capabilities(_state), do: []
  @impl true
  def healthcheck(_state), do: :ok
  @impl true
  def terminate(_state, _reason), do: :ok
end
