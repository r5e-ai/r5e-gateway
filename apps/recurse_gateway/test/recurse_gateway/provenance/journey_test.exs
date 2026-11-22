defmodule Recurse.Gateway.Provenance.JourneyTest do
  @moduledoc """
  The product journey on Provenance v2 evidence, through the real proxy:

    1. a Claude Code agent turn that proposes a Bash tool call is allowed;
    2. the operator activates a stricter policy;
    3. the same turn is sent again and the tool call is withheld;
    4. the session is sealed and exported;
    5. the export verifies offline, and shows each decision under the
       exact policy that was in force when it was made.

  The upstream is a mock serving a captured Anthropic response. Policy
  evaluation, signing, the local log, shipping to Postgres, sealing,
  export and verification are the real ones.
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.LlmProxy.StreamingProxy
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.MockHttpUpstream
  alias Recurse.Provenance.{Envelope, Export, Exporter, Key, Ref}
  alias Recurse.Providers.Impls.PostgresEvidenceStore, as: Store
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo
  alias Recurse.Providers.Schemas.LlmProviderConfig

  @moduletag :tmp_dir

  @tenant "01TEN_JOURNEY"
  @client_session "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"

  # A session is recorded under a name that carries a fingerprint of the
  # caller; a reader who knows only the client's id looks the name up.
  defp recorded(id) do
    [session] =
      Recurse.Providers.Impls.PostgresEvidenceStore.sessions_named(
        Recurse.Providers.Repo,
        "urn:r5e:session:#{@tenant}:",
        id
      )

    session
  end

  @fixtures Path.expand("../../../../recurse_shared/test/fixtures/anthropic_messages", __DIR__)
  @base "provenance.r5e.io/v2"

  @permit "permit (principal, action == Action::\"invoke_tool\", resource);\n"
  @no_shell @permit <>
              "forbid (principal, action == Action::\"invoke_tool\", resource == ToolUse::\"Bash\");\n"

  setup %{tmp_dir: tmp_dir} do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    # The proxy only records a call when a provider registry is installed.
    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant,
      signer: "observed://gateway/journey-test"
    })

    signer = Key.generate("es256")

    start_supervised!(
      {Runtime,
       deployment: "journey-#{System.unique_integer([:positive])}",
       signer: signer,
       store: {Store, Repo},
       dir: tmp_dir,
       partitions: 2,
       flush_interval_ms: 20}
    )

    previous = Active.current()
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn ->
      MockHttpUpstream.stop(upstream)
      ProviderRegistry.uninstall()
      :persistent_term.erase({Runtime, :info})

      case previous do
        {:ok, active} -> Active.update(active)
        _ -> Active.erase()
      end
    end)

    %{upstream: upstream, info: Runtime.info()}
  end

  defp activate(policy, label) do
    hash = Recurse.Cedar.canonical_hash(policy)

    Active.update(%Active{
      source: :filesystem,
      source_ref: label,
      loaded_at: DateTime.utc_now(),
      bundle: %PolicyBundleRef{
        bundle_id: Base.encode16(hash, case: :lower),
        canonical_hash: hash,
        loaded_at: DateTime.utc_now(),
        evaluator_handle: policy,
        bundle_bytes: policy
      }
    })
  end

  defp agent_turn(upstream) do
    request = File.read!(Path.join(@fixtures, "single_tool_use_bash.request.json"))

    MockHttpUpstream.serve_sse(
      upstream,
      File.read!(Path.join(@fixtures, "single_tool_use_bash.sse"))
    )

    config = %LlmProviderConfig{
      tenant_id: @tenant,
      provider: "anthropic",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :anthropic_messages,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }

    conn =
      Plug.Test.conn(:post, "/v1/messages?beta=true", request)
      |> Map.update!(:req_headers, &[{"host", "127.0.0.1:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer sk-ant-oat01-TEST")
      |> Plug.Conn.put_req_header("x-claude-code-session-id", @client_session)

    result = StreamingProxy.proxy(conn, %{llm_provider_config: config, tenant_id: @tenant})
    {result.status, body(result), request}
  end

  defp body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_list(chunks),
    do: IO.iodata_to_binary(chunks)

  defp body(%Plug.Conn{adapter: {_, %{chunks: chunks}}}) when is_binary(chunks), do: chunks
  defp body(%Plug.Conn{resp_body: body}) when is_binary(body), do: body

  test "allow, change policy, deny, seal, export, verify offline", %{
    upstream: upstream,
    info: info
  } do
    # 1. Allowed under the first policy: the tool call reaches the client.
    activate(@permit, "journey-p1")
    assert {200, allowed_body, request} = agent_turn(upstream)
    assert allowed_body =~ ~s|"name":"Bash"|

    # 2. The operator activates a stricter policy.
    activate(@no_shell, "journey-p2")

    # 3. The same turn again: the tool call is withheld from the client.
    assert {200, denied_body, ^request} = agent_turn(upstream)
    refute denied_body =~ ~s|"name":"Bash"|
    assert denied_body =~ "event: message_stop"

    # 4. Seal what was recorded and export the session.
    assert {:ok, [_ | _]} = Runtime.seal()
    assert {:ok, bundle} = Exporter.session(info.store, recorded(@client_session))

    # 5. A reader holding only the bundle, and told which profile to
    #    trust, checks it without calling anyone.
    offline = bundle |> Jason.encode!() |> Jason.decode!()
    report = Export.verify(offline, trusted_profiles: [info.profile_ref])

    assert report.summary.failed == 0
    assert Enum.all?(report.findings, &(&1.check != :signature or &1.result == :ok))
    assert Enum.all?(report.findings, &(&1.check != :authority or &1.result == :ok))
    assert Enum.any?(report.findings, &(&1.check in [:epoch, :membership] and &1.result == :ok))

    # What the bundle says happened, read from the signed records alone.
    records =
      for %{"envelope" => envelope} <- offline["records"],
          {:ok, %{evidence: evidence}} = Envelope.open(envelope),
          evidence["session"] == recorded(@client_session),
          do: evidence

    by_kind = Enum.group_by(records, & &1["kind"])
    assert [_, _] = by_kind["ModelCall"]
    assert [_, _] = by_kind["ModelResponse"]

    assert [first, second] = Enum.sort_by(by_kind["ToolCall"], & &1["seq"])

    assert %{"tool" => "Bash", "policy" => %{"outcome" => "allow", "policyRef" => p1}} =
             first["body"]

    refute Map.has_key?(first["body"], "result")

    assert %{
             "tool" => "Bash",
             "policy" => %{"outcome" => "deny", "policyRef" => p2},
             "result" => %{"outcome" => "denied"}
           } = second["body"]

    # Each decision names the exact policy bytes in force when it was made,
    # and those bytes travel in the bundle.
    assert p1 == Ref.bytes(@permit)
    assert p2 == Ref.bytes(@no_shell)
    carried = MapSet.new(offline["blobs"], & &1["ref"])
    assert MapSet.subset?(MapSet.new([p1, p2]), carried)

    # The request and response bodies are held and carried too.
    assert MapSet.member?(carried, Ref.bytes(request))

    assert [%{"body" => %{"contentRef" => request_ref, "size" => size}} | _] =
             by_kind["ModelCall"]

    assert size == byte_size(request)
    assert request_ref == Ref.bytes(request)

    # The same records form one chain in one stream.
    seqs = records |> Enum.map(& &1["seq"]) |> Enum.sort()
    assert seqs == Enum.to_list(1..length(records))
    assert [_one] = records |> Enum.map(& &1["stream"]) |> Enum.uniq()
  end

  # The same journey for Codex, which speaks the OpenAI Responses API
  # and names its session in a `session_id` header.
  @codex_session "0199c0de-7a11-7000-8000-00000000c0de"
  @codex_fixture Path.expand(
                   "../../../../recurse_shared/test/fixtures/openai_responses/single_function_call.jsonl",
                   __DIR__
                 )
  @no_codex_shell @permit <>
                    "forbid (principal, action == Action::\"invoke_tool\", resource == ToolUse::\"shell\");\n"

  defp codex_turn(upstream) do
    request =
      ~s({"model":"gpt-5-codex","stream":true,"input":[{"role":"user","content":"list /tmp"}]})

    sse =
      @codex_fixture
      |> File.stream!()
      |> Enum.map_join(fn line ->
        line = String.trim(line)
        "event: #{Jason.decode!(line)["type"]}\ndata: #{line}\n\n"
      end)

    MockHttpUpstream.serve_sse(upstream, sse)

    config = %LlmProviderConfig{
      tenant_id: @tenant,
      provider: "openai_api",
      upstream_host: "127.0.0.1",
      upstream_port: upstream.port,
      transport_modes: ["https-sse"],
      auth_mode: :passthrough,
      api_format: :openai_responses,
      enabled: true,
      metadata: %{"scheme" => "http"}
    }

    conn =
      Plug.Test.conn(:post, "/v1/responses", request)
      |> Map.update!(:req_headers, &[{"host", "127.0.0.1:4443"} | &1])
      |> Plug.Conn.put_req_header("content-type", "application/json")
      |> Plug.Conn.put_req_header("authorization", "Bearer sk-TEST")
      |> Plug.Conn.put_req_header("session_id", @codex_session)

    result = StreamingProxy.proxy(conn, %{llm_provider_config: config, tenant_id: @tenant})
    {result.status, body(result), request}
  end

  test "a Codex turn over the Responses API: allow, change policy, deny, export, verify", %{
    upstream: upstream,
    info: info
  } do
    activate(@permit, "codex-p1")
    assert {200, allowed_body, request} = codex_turn(upstream)
    assert allowed_body =~ "call_ls_42"

    activate(@no_codex_shell, "codex-p2")
    assert {200, denied_body, ^request} = codex_turn(upstream)
    refute denied_body =~ ~s|"name":"shell"|

    assert {:ok, [_ | _]} = Runtime.seal()
    assert {:ok, bundle} = Exporter.session(info.store, recorded(@codex_session))

    offline = bundle |> Jason.encode!() |> Jason.decode!()
    report = Export.verify(offline, trusted_profiles: [info.profile_ref])
    assert report.summary.failed == 0
    assert Enum.any?(report.findings, &(&1.check in [:epoch, :membership] and &1.result == :ok))

    records =
      for %{"envelope" => envelope} <- offline["records"],
          {:ok, %{evidence: evidence}} = Envelope.open(envelope),
          evidence["session"] == recorded(@codex_session),
          do: evidence

    by_kind = Enum.group_by(records, & &1["kind"])
    assert [_, _] = by_kind["ModelCall"]
    assert [_, _] = by_kind["ModelResponse"]

    assert [
             %{
               "body" => %{
                 "tool" => "shell",
                 "policy" => %{"outcome" => "allow", "policyRef" => p1}
               }
             },
             %{
               "body" => %{
                 "tool" => "shell",
                 "policy" => %{"outcome" => "deny", "policyRef" => p2}
               }
             }
           ] = Enum.sort_by(by_kind["ToolCall"], & &1["seq"])

    assert p1 == Ref.bytes(@permit)
    assert p2 == Ref.bytes(@no_codex_shell)

    carried = MapSet.new(offline["blobs"], & &1["ref"])
    assert MapSet.subset?(MapSet.new([p1, p2, Ref.bytes(request)]), carried)
  end

  test "an export without content names what was withheld and still verifies", %{
    upstream: upstream,
    info: info
  } do
    activate(@permit, "journey-p1")
    assert {200, _body, request} = agent_turn(upstream)
    assert {:ok, [_ | _]} = Runtime.seal()

    assert {:ok, bundle} = Exporter.session(info.store, recorded(@client_session), content: false)
    report = Export.verify(bundle, trusted_profiles: [info.profile_ref])

    assert report.summary.failed == 0
    refute Enum.any?(bundle["blobs"], &(&1["ref"] == Ref.bytes(request)))

    assert Enum.any?(
             bundle["omissions"],
             &(&1 == %{"ref" => Ref.bytes(request), "reason" => "withheld"})
           )

    assert Enum.any?(report.findings, &(&1.check == :content and &1.result == :incomplete))
    assert (@base <> "/ModelCall") in Enum.map(report.findings, & &1.about)
  end
end
