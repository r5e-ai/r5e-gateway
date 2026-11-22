# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Local demo scaffolding: dev provider impls (software Ed25519 signer,
# filesystem CAS, echo LLM) + setup/driver helpers for the demo flow.
#
# Usage (from an `iex -S mix` session booted per scripts/fable_demo/boot.sh):
#
#     Code.require_file("scripts/fable_demo/demo.exs")
#     FableDemo.setup!()
#     FableDemo.print_curl()          # step (b): allowed chat completion
#     FableDemo.mint_cookie()         # step (c): browser login cookie
#     FableDemo.ToolDemo.run("ls -la /tmp")            # allowed tool call
#     FableDemo.ToolDemo.run("rm -rf /tmp/test-dir")   # DENIED tool call
#     FableDemo.use_deny_bundle!()    # step (d): activate deny bundle for chat plane
#
defmodule FableDemo.DevSecretsProvider do
  @moduledoc """
  Local software SecretsProvider: real ECDSA P-256 / SHA-256 signatures
  (same algorithm family as the production AWS KMS ECDSA_SHA_256 signer,
  so docs/auditor/recurse-verify's openssl path verifies them offline).
  Key material persisted under _build/dev/fable-demo/ so receipts stay
  verifiable across BEAM restarts. Dev-only — never a production path.
  """
  @behaviour Recurse.Providers.SecretsProvider

  @key_id "fable-demo-es256"

  @impl true
  def init(config) do
    dir = Map.get(config, :key_dir, Path.join(File.cwd!(), "_build/dev/fable-demo"))
    File.mkdir_p!(dir)
    priv_path = Path.join(dir, "signing-es256.pem")

    jwk =
      if File.exists?(priv_path) do
        JOSE.JWK.from_pem_file(priv_path)
      else
        jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
        {_meta, priv_pem} = JOSE.JWK.to_pem(jwk)
        File.write!(priv_path, priv_pem)
        File.chmod!(priv_path, 0o600)
        jwk
      end

    {%{kty: _}, ec_private_key} = JOSE.JWK.to_key(jwk)
    {_meta, pub_pem} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_pem()
    {:ok, %{ec_key: ec_private_key, pub_pem: pub_pem}}
  end

  @impl true
  def active_signing_key(_state) do
    {:ok, %{key_id: @key_id, key_version: 1, algorithm: :ecdsa_sha256}}
  end

  @impl true
  def sign(state, _handle, payload) when is_binary(payload) do
    # DER-encoded ECDSA-SHA256 signature — verifiable with
    # `openssl dgst -sha256 -verify <pub.pem> -signature <sig> <payload>`.
    {:ok, :public_key.sign(payload, :sha256, state.ec_key)}
  end

  @impl true
  def public_key(state, _handle) do
    {:ok, state.pub_pem}
  end

  @impl true
  def store_user_token(_state, _ctx, _tok, _ttl), do: :ok

  @impl true
  def exchange_for_downstream_token(_s, _c, _id, _scope), do: {:error, :not_supported_in_dev}

  @impl true
  def capabilities(_state), do: [:sign, :public_key_export]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule FableDemo.DevFsStorage do
  @moduledoc """
  Local filesystem CAS StorageProvider. Payloads stored content-addressed
  (SHA-256 hex) under _build/dev/fable-demo/cas/. Dev-only.
  """
  @behaviour Recurse.Providers.StorageProvider

  @impl true
  def init(config) do
    root = Map.get(config, :root, Path.join(File.cwd!(), "_build/dev/fable-demo/cas"))
    File.mkdir_p!(root)
    {:ok, %{root: root}}
  end

  @impl true
  def put_payload(state, payload, _ctx) when is_binary(payload) do
    hash = :crypto.hash(:sha256, payload)
    hex = Base.encode16(hash, case: :lower)
    path = Path.join(state.root, hex)
    File.write!(path, payload)
    {:ok, %{uri: "file://" <> path, hash: hash}}
  end

  @impl true
  def get_payload(_state, "file://" <> path, _ctx) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, reason} -> {:error, reason}
    end
  end

  def get_payload(_state, _uri, _ctx), do: {:error, :unknown_uri_scheme}

  @impl true
  def delete_payload(_state, "file://" <> path, _ctx) do
    case File.rm(path) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def delete_payload(_state, _uri, _ctx), do: {:error, :unknown_uri_scheme}

  @impl true
  def capabilities(_state), do: []

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule FableDemo.DevEchoLlm do
  @moduledoc """
  LLMProvider that answers locally (no network). Response echoes the last
  user message so the demo produces deterministic receipts without an
  OpenAI key. Dev-only.
  """
  @behaviour Recurse.Providers.LLMProvider

  @impl true
  def init(config), do: {:ok, config}

  @impl true
  def chat_complete(_state, request, _ctx) do
    model = Map.get(request, "model", "fable-echo-1")

    last_user =
      request
      |> Map.get("messages", [])
      |> Enum.reverse()
      |> Enum.find_value("(no user message)", fn
        %{"role" => "user", "content" => c} when is_binary(c) -> c
        _ -> nil
      end)

    {:ok,
     %{
       "id" => "chatcmpl-fable-#{System.unique_integer([:positive])}",
       "object" => "chat.completion",
       "created" => System.system_time(:second),
       "model" => model,
       "choices" => [
         %{
           "index" => 0,
           "message" => %{
             "role" => "assistant",
             "content" => "echo (local dev provider): " <> last_user
           },
           "finish_reason" => "stop"
         }
       ],
       "usage" => %{"prompt_tokens" => 7, "completion_tokens" => 11, "total_tokens" => 18}
     }}
  end

  @impl true
  def chat_complete_stream(_state, _request, _ctx), do: {:error, :streaming_not_supported_in_dev}

  @impl true
  def capabilities(_state), do: []

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok
end

defmodule FableDemo do
  @moduledoc """
  Demo orchestration helpers. See file header for the flow.
  """

  alias Recurse.Gateway.Admin.BrowserSessionPlug
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Identity.JwtMinter

  @tenant_id "01TEN_FABLE_DEMO_LOCAL"
  @subject "operator@local.dev"

  def tenant_id, do: @tenant_id

  def setup! do
    seed_tenant!()

    {:ok, secrets_state} = FableDemo.DevSecretsProvider.init(%{})
    {:ok, storage_state} = FableDemo.DevFsStorage.init(%{})
    {:ok, llm_state} = FableDemo.DevEchoLlm.init(%{})

    ProviderRegistry.install_raw!(%{
      llm: {FableDemo.DevEchoLlm, llm_state},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {FableDemo.DevFsStorage, storage_state},
      secrets: {FableDemo.DevSecretsProvider, secrets_state},
      tenant_id: @tenant_id,
      signer: "observed://gateway/fable-demo-local"
    })

    case Active.current() do
      {:ok, %Active{bundle: ref}} ->
        IO.puts("[fable-demo] providers installed; active bundle #{short_hash(ref)}")

      {:error, :not_loaded} ->
        IO.puts("[fable-demo] providers installed; NO bundle loaded — call FableDemo.use_permissive_bundle!()")
    end

    :ok
  end

  defp seed_tenant! do
    case Repo.get(Tenant, @tenant_id) do
      nil ->
        Repo.insert!(
          Tenant.changeset(%Tenant{}, %{
            tenant_id: @tenant_id,
            display_name: "Fable demo local tenant",
            tier: :standalone_gateway,
            created_at: DateTime.utc_now()
          }),
          on_conflict: :nothing,
          conflict_target: :tenant_id
        )

      %Tenant{} ->
        :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Policy bundle switching. Preferred path: overwrite the file the
  # BundleLoader watches (RECURSE_POLICY_BUNDLE_PATH) and cast :reload —
  # the same code path a SIGHUP takes. Fallback (loader not running):
  # write the parsed bundle straight into the canonical Active store the
  # way the integration tests do.
  # ---------------------------------------------------------------------------

  def use_permissive_bundle! do
    activate_file!(Path.join(File.cwd!(), "apps/recurse_gateway/priv/reference_policies/permissive_all.cedar"))
  end

  def use_deny_bundle! do
    activate_file!(Path.join(File.cwd!(), "scripts/fable_demo/deny_destructive.cedar"))
  end

  def activate_file!(source_path) do
    target = System.get_env("RECURSE_POLICY_BUNDLE_PATH", "")
    loader_alive? = is_pid(Process.whereis(Recurse.Gateway.Policy.BundleLoader))

    expected_hash = Recurse.Cedar.canonical_hash(File.read!(source_path))

    if target != "" and loader_alive? do
      File.cp!(source_path, target)
      :ok = Recurse.Gateway.Policy.BundleLoader.reload()
      Process.sleep(400)

      case Active.current() do
        {:ok, %Active{bundle: %PolicyBundleRef{canonical_hash: ^expected_hash}}} ->
          report_active("bundle-loader reload (SIGHUP path)")

        _ ->
          IO.puts("[fable-demo] loader reload did not activate the expected bundle; falling back to direct Active.update")
          direct_activate!(source_path)
          report_active("direct Active.update (loader reload fallback)")
      end
    else
      direct_activate!(source_path)
      report_active("direct Active.update (loader not running)")
    end
  end

  defp direct_activate!(source_path) do
    bundle_source = File.read!(source_path)
    canonical_hash = Recurse.Cedar.canonical_hash(bundle_source)
    loaded_at = DateTime.utc_now()

    bundle_ref = %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: loaded_at,
      evaluator_handle: bundle_source,
      bundle_bytes: bundle_source
    }

    :ok =
      Active.update(%Active{
        source: :filesystem,
        source_ref: source_path,
        loaded_at: loaded_at,
        metadata: %{file_path: source_path, fable_demo: true},
        bundle: bundle_ref
      })
  end

  @doc """
  Print the active bundle without changing it. Read-only counterpart to
  `use_deny_bundle!/0` / `use_permissive_bundle!/0`, so a demo operator
  (or `scripts/fable_demo/swap-bundle.sh status`) can confirm which
  bundle is live before a take.
  """
  def report_active_bundle, do: report_active("query")

  defp report_active(via) do
    case Active.current() do
      {:ok, %Active{bundle: ref}} ->
        IO.puts("[fable-demo] active bundle now #{short_hash(ref)} via #{via}")

      other ->
        IO.puts("[fable-demo] WARNING: Active.current() -> #{inspect(other)}")
    end
  end

  defp short_hash(%PolicyBundleRef{canonical_hash: h}),
    do: h |> Base.encode16(case: :lower) |> binary_part(0, 12)

  # ---------------------------------------------------------------------------
  # Auth: mint an internal broker-shaped JWT + the r5e_session cookie.
  # ---------------------------------------------------------------------------

  def mint_jwt(role \\ "platform_operator") do
    cfg = Application.get_env(:recurse_gateway, :internal_jwt, [])
    path = Keyword.fetch!(cfg, :signing_key_path)
    audience = Keyword.fetch!(cfg, :audience)
    issuer = Keyword.fetch!(cfg, :issuer)
    jwk = JOSE.JWK.from_pem_file(path)
    kid = path |> Path.basename() |> Path.rootname()

    principal = %{
      "kind" => "obo_human",
      "issuer" => "https://local-dev.invalid",
      "subject" => @subject,
      "display_name" => "Thomas (local dev)",
      "groups" => [],
      "recurse_role" => role,
      "tenant_id" => @tenant_id
    }

    {:ok, jwt} =
      JwtMinter.mint(
        subject: @subject,
        issuer: issuer,
        audience: audience,
        principal: principal,
        jwk: jwk,
        kid: kid,
        ttl_seconds: 28_800
      )

    jwt
  end

  def mint_cookie(role \\ "platform_operator") do
    jwt = mint_jwt(role)
    now = System.system_time(:second)

    payload = %{
      jwt: jwt,
      issued_at: now,
      last_activity_at: now,
      browser_session_id: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
      principal_subject: @subject,
      recurse_role: role,
      tenant_id: @tenant_id
    }

    cookie = BrowserSessionPlug.encrypt_payload(payload)

    IO.puts("""

    [fable-demo] r5e_session cookie minted (role=#{role}, ttl 8h).

    Browser (devtools console on the UI origin):
      document.cookie = "r5e_session=#{cookie}; path=/";

    curl:
      curl -s http://localhost:4000/v1/auth/me -H 'Cookie: r5e_session=#{cookie}' | head -c 400
    """)

    cookie
  end

  def print_curl do
    jwt = mint_jwt()

    IO.puts("""

    [fable-demo] allowed chat completion (step b):

    curl -s http://localhost:4000/v1/chat/completions \\
      -H "Authorization: Bearer #{jwt}" \\
      -H "Content-Type: application/json" \\
      -d '{"model":"fable-echo-1","messages":[{"role":"user","content":"say hello for the receipt ledger"}]}'

    then:

    curl -s "http://localhost:4000/v1/audit/receipts?limit=3" -H "Authorization: Bearer #{jwt}"
    """)

    :ok
  end
end

# =============================================================================
# Tool-use demo: in-BEAM WebSocketBridge + mock Responses-API upstream,
# driven by a Mint.WebSocket client — the same vertical the eddy smoke
# test (T075) exercises, but against the live dev BEAM so receipts land
# in the real recurse_dev ledger.
# =============================================================================

defmodule FableDemo.MockUpstream do
  @moduledoc false

  defmodule UpPlug do
    @moduledoc false
    @behaviour Plug
    import Plug.Conn

    @impl true
    def init(ref), do: ref

    @impl true
    def call(conn, ref) do
      upgrade? =
        conn
        |> get_req_header("upgrade")
        |> List.first()
        |> case do
          nil -> false
          v -> String.downcase(v, :ascii) == "websocket"
        end

      if upgrade? do
        WebSockAdapter.upgrade(conn, FableDemo.MockUpstream.Handler, %{ref: ref}, [])
      else
        send_resp(conn, 426, "upgrade required")
      end
    end
  end

  defmodule Handler do
    @moduledoc false
    @behaviour WebSock

    @impl true
    def init(state), do: {:ok, state}

    @impl true
    def handle_in({_payload, opcode: :text}, state) do
      command = :persistent_term.get({FableDemo.MockUpstream, state.ref})
      args_json = JSON.encode!(%{"command" => command})
      call_id = "call_fable_#{System.unique_integer([:positive])}"

      events =
        [
          %{"type" => "response.created", "response" => %{"id" => "resp_#{call_id}", "model" => "gpt-5-codex"}},
          %{
            "type" => "response.output_item.added",
            "output_index" => 0,
            "item" => %{"type" => "function_call", "call_id" => call_id, "name" => "shell", "arguments" => ""}
          },
          %{"type" => "response.function_call.arguments.delta", "call_id" => call_id, "item_id" => call_id, "delta" => args_json},
          %{"type" => "response.function_call.completed", "call_id" => call_id, "item_id" => call_id, "arguments" => args_json},
          %{
            "type" => "response.completed",
            "response" => %{"id" => "resp_#{call_id}", "usage" => %{"input_tokens" => 50, "output_tokens" => 30}}
          }
        ]

      {:push, Enum.map(events, fn ev -> {:text, JSON.encode!(ev)} end), state}
    end

    def handle_in(_frame, state), do: {:ok, state}

    @impl true
    def handle_info(_msg, state), do: {:ok, state}

    @impl true
    def terminate(_reason, _state), do: :ok
  end

  def start(command) do
    ref = make_ref()
    :persistent_term.put({__MODULE__, ref}, command)

    {:ok, pid} = Bandit.start_link(plug: {UpPlug, ref}, port: 0, startup_log: false)
    {:ok, {_addr, port}} = ThousandIsland.listener_info(pid)
    %{pid: pid, port: port, ref: ref}
  end

  def stop(%{pid: pid, ref: ref}) do
    Process.unlink(pid)

    try do
      Process.exit(pid, :shutdown)
    catch
      _, _ -> :ok
    end

    :persistent_term.erase({__MODULE__, ref})
    :ok
  end
end

defmodule FableDemo.ToolDemo do
  @moduledoc false

  alias Mint.HTTP, as: MintHttp
  alias Mint.WebSocket, as: MintWs
  alias Recurse.Gateway.LlmProxy.WebSocketBridge
  alias Recurse.Providers.Schemas.LlmProviderConfig

  defmodule BridgeEndpoint do
    @moduledoc false
    @behaviour Plug

    @impl true
    def init(opts), do: opts

    @impl true
    def call(conn, opts) do
      WebSocketBridge.upgrade(conn,
        llm_provider_config: Keyword.fetch!(opts, :llm_provider_config),
        tenant_id: Keyword.fetch!(opts, :tenant_id)
      )
    end
  end

  @doc """
  Run one simulated Codex tool-call session through the live bridge.
  `command` is the shell command the (mock) model asks to run — under the
  deny bundle, anything matching `*rm -rf*` (or `*DROP DATABASE*` in the
  fable deny bundle) is stripped + replaced with a synthetic denial, and a
  :tool_use_denied receipt is committed alongside the :llm_call_attested.
  """
  def run(command) do
    tenant_id = FableDemo.tenant_id()
    upstream = FableDemo.MockUpstream.start(command)

    cfg = %LlmProviderConfig{
      tenant_id: tenant_id,
      provider: "openai_chatgpt",
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
        plug: {BridgeEndpoint, llm_provider_config: cfg, tenant_id: tenant_id},
        port: 0,
        startup_log: false
      )

    {:ok, {_addr, bridge_port}} = ThousandIsland.listener_info(bridge_pid)

    headers = [
      {"authorization", "Bearer " <> codex_shaped_jwt()},
      {"chatgpt-account-id", "acct_fable_demo"}
    ]

    result =
      with {:ok, ws} <- open_ws(bridge_port, headers) do
        ws = send_frame(ws, {:text, JSON.encode!(%{"prompt" => "run: " <> command})})
        {:ok, ws, frames} = recv_until(ws, "response.completed", 8_000)
        close_ws(ws)
        {:ok, frames}
      end

    Process.sleep(500)

    Process.unlink(bridge_pid)

    try do
      Process.exit(bridge_pid, :shutdown)
    catch
      _, _ -> :ok
    end

    FableDemo.MockUpstream.stop(upstream)

    case result do
      {:ok, frames} ->
        texts = for {:text, t} <- frames, do: t
        denied? = Enum.any?(texts, &String.contains?(&1, "blocked"))
        fcall? = Enum.any?(texts, &String.contains?(&1, "function_call"))

        IO.puts("""
        [fable-demo] tool session done. command=#{inspect(command)}
          frames received: #{length(texts)}
          function_call forwarded to client: #{fcall?}
          synthetic denial injected:         #{denied?}
        """)

        {:ok, %{denied: denied?, forwarded: fcall?, frames: texts}}

      other ->
        IO.puts("[fable-demo] tool session FAILED: #{inspect(other)}")
        other
    end
  end

  # Codex-Enterprise-shaped JWT — PrincipalExtractor decodes without
  # signature verification, so only header+payload need valid b64url JSON.
  defp codex_shaped_jwt do
    header = %{"alg" => "RS256", "typ" => "JWT"}

    payload = %{
      "iss" => "https://auth.openai.com",
      "sub" => "user-fable-demo-001",
      "chatgpt_account_id" => "acct_fable_demo",
      "aud" => "chatgpt.com",
      "exp" => 9_999_999_999,
      "iat" => 1_700_000_000
    }

    Base.url_encode64(JSON.encode!(header), padding: false) <>
      "." <> Base.url_encode64(JSON.encode!(payload), padding: false) <> ".sig"
  end

  # --- minimal Mint.WebSocket client (adapted from eddy_smoke_test.exs) ---

  defp open_ws(port, extra_headers) do
    {:ok, conn} = MintHttp.connect(:http, "127.0.0.1", port, protocols: [:http1])
    {:ok, conn, ref} = MintWs.upgrade(:ws, conn, "/", extra_headers)
    drain_until_open(%{conn: conn, ref: ref, ws: nil, headers: nil}, System.monotonic_time(:millisecond) + 3_000)
  end

  defp drain_until_open(state, deadline) do
    if System.monotonic_time(:millisecond) > deadline do
      {:error, :ws_open_timeout}
    else
      receive do
        msg ->
          case MintHttp.stream(state.conn, msg) do
            {:ok, conn, responses} ->
              state = %{state | conn: conn}

              {state, opened?} =
                Enum.reduce(responses, {state, false}, fn
                  {:status, ref, 101}, {st, o} when ref == st.ref -> {st, o}
                  {:headers, ref, headers}, {st, o} when ref == st.ref -> {%{st | headers: headers}, o}
                  {:done, ref}, {st, _} when ref == st.ref ->
                    case MintWs.new(st.conn, st.ref, 101, st.headers || []) do
                      {:ok, conn, ws} -> {%{st | conn: conn, ws: ws}, true}
                      _ -> {st, false}
                    end

                  _, acc -> acc
                end)

              if opened?, do: {:ok, state}, else: drain_until_open(state, deadline)

            {:error, _conn, reason, _} -> {:error, reason}
            :unknown -> drain_until_open(state, deadline)
          end
      after
        100 -> drain_until_open(state, deadline)
      end
    end
  end

  defp send_frame(state, frame) do
    {:ok, ws, data} = MintWs.encode(state.ws, frame)
    {:ok, conn} = MintWs.stream_request_body(state.conn, state.ref, data)
    %{state | conn: conn, ws: ws}
  end

  defp recv_until(state, terminal_type, timeout) do
    do_recv(state, terminal_type, System.monotonic_time(:millisecond) + timeout, [])
  end

  defp do_recv(state, terminal, deadline, acc) do
    if System.monotonic_time(:millisecond) > deadline do
      {:ok, state, acc}
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

                  _, acc2 -> acc2
                end)

              terminal? =
                Enum.any?(frames, fn
                  {:text, t} -> String.contains?(t, terminal)
                  _ -> false
                end)

              if terminal?, do: {:ok, state, frames}, else: do_recv(state, terminal, deadline, frames)

            {:error, _conn, _reason, _} -> {:ok, state, acc}
            :unknown -> do_recv(state, terminal, deadline, acc)
          end
      after
        100 -> do_recv(state, terminal, deadline, acc)
      end
    end
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

IO.puts("[fable-demo] demo.exs loaded. Next: FableDemo.setup!()")
