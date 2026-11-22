defmodule Recurse.Gateway.Evidence.ApiHandlerTest do
  @moduledoc """
  The evidence API against real records in Postgres: who may call, what
  comes back, and that an exported bundle verifies.

  `async: false` because the policy bundle loader, the provider registry
  and evidence capture are node-wide.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Evidence.{ApiHandler, TailSocket}
  alias Recurse.Gateway.Policy.BundleLoader
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Provenance.{Runtime, SessionName}
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Provenance.{Body, Export, Key, Pipeline, Ref}
  alias Recurse.Providers.Impls.PostgresEvidenceStore
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @alice "urn:r5e:principal:test:alice"
  @args ~s({"command":"ls"})
  @policy "permit(principal, action, resource);"

  setup %{tmp_dir: tmp_dir} do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    start_supervised!(
      Supervisor.child_spec(
        {BundleLoader,
         bundle_path: write_bundle(),
         entity_schema_path:
           Path.join([
             Application.app_dir(:recurse_gateway, "priv"),
             "cedar",
             "schema.cedarschema.json"
           ]),
         trap_sighup: false,
         name: nil},
        id: make_ref()
      )
    )

    ProviderRegistry.install_raw!(%{
      llm: {Recurse.Gateway.Test.StubLLM, %{}},
      ledger: {PostgresMerkleLedger, %{repo: Repo, pubsub: Recurse.PubSub, config: %{}}},
      storage: {Recurse.Gateway.Test.StubStorage, %{}},
      secrets: {Recurse.Gateway.Test.StubSecretsProvider, %{}},
      tenant_id: @tenant,
      signer: "observed://gateway/test"
    })

    restore = [
      put_env(:jwt_validator_opts,
        audience: "recurse-gateway-test",
        issuer: "https://test-broker.example.invalid",
        known_kids: [{"test-key-rs256", JwtTestHelper.public_jwk(:rs256)}]
      ),
      put_env(:browser_session,
        cookie_name: "r5e_session",
        secret_key_base: :crypto.strong_rand_bytes(64),
        secure_cookie?: false,
        absent_cookie_redirect: :always_401
      )
    ]

    deployment = "api-#{System.unique_integer([:positive])}"

    start_supervised!(
      {Runtime,
       deployment: deployment,
       signer: Key.generate("ed25519"),
       store: {PostgresEvidenceStore, Repo},
       retention: {:keep_for_seconds, 0},
       dir: tmp_dir,
       partitions: 1,
       flush_interval_ms: 20}
    )

    on_exit(fn ->
      :persistent_term.erase({Runtime, :info})
      ProviderRegistry.uninstall()
      Enum.each(restore, & &1.())
    end)

    session = "s-#{System.unique_integer([:positive])}"
    receipts = for _ <- 1..2, do: capture(recorded(session))

    [foreign] = [
      capture(SessionName.for("01OTHER000000000000000000", @alice, session <> "-x"))
    ]

    {:ok, [_seal]} = Runtime.seal()

    %{
      session: session,
      receipts: receipts,
      foreign: foreign,
      profile_ref: Runtime.info().profile_ref
    }
  end

  defp recorded(id), do: SessionName.for(@tenant, @alice, id)

  defp put_env(key, value) do
    previous = Application.get_env(:recurse_gateway, key)
    Application.put_env(:recurse_gateway, key, value)

    fn ->
      if previous,
        do: Application.put_env(:recurse_gateway, key, previous),
        else: Application.delete_env(:recurse_gateway, key)
    end
  end

  defp capture(session) do
    {:ok, receipt} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: "provenance.r5e.io/v2/ToolCall",
        actor: "urn:r5e:principal:test:alice",
        session: session,
        attachments: [%{name: "args", bytes: @args}],
        blobs: [@policy],
        body:
          Body.tool_call(
            tool: "Bash",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: byte_size(@args),
            policy:
              Body.policy_evaluation(
                policy_ref: Ref.bytes(@policy),
                outcome: "allow",
                input_refs: ["attachment:args"]
              )
          )
      })

    receipt
  end

  defp write_bundle do
    source =
      [
        Application.app_dir(:recurse_gateway, "priv"),
        "reference_policies",
        "platform_roles.cedar"
      ]
      |> Path.join()
      |> File.read!()

    path = Path.join(System.tmp_dir!(), "evidence_api_bundle_#{System.unique_integer()}.cedar")
    File.write!(path, source)
    on_exit(fn -> File.rm(path) end)
    path
  end

  defp request(method, path, opts \\ []) do
    conn = Plug.Test.conn(method, path)

    conn =
      case Keyword.get(opts, :role, "tenant_auditor") do
        nil ->
          conn

        role ->
          token =
            JwtTestHelper.mint_test_jwt(
              recurse_role: role,
              audience: "recurse-gateway-test",
              issuer: "https://test-broker.example.invalid"
            )

          Plug.Conn.put_req_header(conn, "authorization", "Bearer " <> token)
      end

    conn
    |> Map.put(:path_params, Keyword.get(opts, :params, %{}))
    |> Map.put(:body_params, Keyword.get(opts, :body, %{}))
  end

  defp record(ref, opts \\ []),
    do:
      ApiHandler.record(
        request(:get, "/v1/evidence/records/x", [params: %{"ref" => ref}] ++ opts)
      )

  defp records(query, opts \\ []),
    do:
      ApiHandler.records(request(:get, "/v1/evidence/records?" <> URI.encode_query(query), opts))

  defp tail(query, opts \\ []) do
    conn = request(:get, "/v1/evidence/tail?" <> URI.encode_query(query), opts)

    handshake =
      if opts[:handshake],
        do: [
          {"host", "gateway.test"},
          {"connection", "Upgrade"},
          {"upgrade", "websocket"},
          {"sec-websocket-key", Base.encode64(:crypto.strong_rand_bytes(16))},
          {"sec-websocket-version", "13"}
        ],
        else: []

    # Set directly: Plug refuses a host header through its own setters.
    ApiHandler.tail(%{conn | req_headers: conn.req_headers ++ handshake})
  end

  defp opening(filter) do
    info = Runtime.info()

    %{
      store: Runtime.store(info.deployment),
      signals: Pipeline.signals(Runtime.pipeline()),
      stream_prefix: "urn:r5e:stream:#{info.deployment}:",
      filter: filter
    }
  end

  defp content(ref, bytes_ref, opts \\ []),
    do:
      ApiHandler.content(
        request(
          :get,
          "/v1/evidence/records/x/content/y",
          [params: %{"ref" => ref, "bytes_ref" => bytes_ref}] ++ opts
        )
      )

  defp session(id, opts \\ []),
    do:
      ApiHandler.session(
        request(:get, "/v1/evidence/sessions/x", [params: %{"session_id" => id}] ++ opts)
      )

  defp export(body, opts \\ []),
    do: ApiHandler.export(request(:post, "/v1/evidence/export", [body: body] ++ opts))

  defp verify(body, opts \\ []),
    do: ApiHandler.verify(request(:post, "/v1/evidence/verify", [body: body] ++ opts))

  defp body(conn), do: JSON.decode!(conn.resp_body)

  describe "who may call" do
    test "no credentials is 401 on every route", ctx do
      [%{ref: ref} | _] = ctx.receipts
      assert record(ref, role: nil).status == 401
      assert session(ctx.session, role: nil).status == 401
      assert export(%{"session" => ctx.session}, role: nil).status == 401
      assert verify(%{"bundle" => %{}}, role: nil).status == 401
    end

    test "the data-plane caller role is refused", ctx do
      [%{ref: ref} | _] = ctx.receipts
      assert record(ref, role: "caller").status == 403
      assert session(ctx.session, role: "caller").status == 403
      assert export(%{"session" => ctx.session}, role: "caller").status == 403
    end
  end

  describe "listing records" do
    @tool_call "provenance.r5e.io/v2/ToolCall"

    test "needs the same right as reading one record" do
      assert records(%{}, role: nil).status == 401
      assert records(%{}, role: "caller").status == 403
    end

    test "newest first, a page at a time, each row with its actor and session", ctx do
      first = records(%{"kind" => @tool_call, "limit" => "2"})
      assert first.status == 200

      assert %{
               "records" => [
                 %{"ref" => newest, "kind" => @tool_call, "actor" => @alice, "envelope" => %{}},
                 %{"ref" => next, "session" => "urn:r5e:session:" <> _}
               ],
               "cursor" => cursor
             } = body(first)

      assert is_binary(cursor)

      assert %{"records" => [%{"ref" => oldest}], "cursor" => nil} =
               body(records(%{"kind" => @tool_call, "limit" => "2", "cursor" => cursor}))

      # The setup captured two of the session's calls, then one elsewhere.
      assert [oldest, next, newest] == Enum.map(ctx.receipts, & &1.ref) ++ [ctx.foreign.ref]

      assert %{"records" => [_, _, _, _ | _], "cursor" => nil} = body(records(%{}))
    end

    test "narrowed by session, actor, kind and time", ctx do
      refs = ctx.receipts |> Enum.map(& &1.ref) |> Enum.reverse()

      listed = fn query ->
        conn = records(query)
        assert conn.status == 200
        Enum.map(body(conn)["records"], & &1["ref"])
      end

      assert listed.(%{"session" => ctx.session}) == refs
      assert listed.(%{"session" => recorded(ctx.session)}) == refs
      assert listed.(%{"session" => "no-such-session"}) == []

      assert listed.(%{"actor" => @alice, "kind" => @tool_call}) == [ctx.foreign.ref | refs]
      assert listed.(%{"actor" => "urn:r5e:principal:test:nobody"}) == []
      assert listed.(%{"kind" => "example.test/v1/Unheard"}) == []

      assert listed.(%{"kind" => @tool_call, "until" => "2000-01-01T00:00:00Z"}) == []

      assert listed.(%{"kind" => @tool_call, "since" => "2000-01-01T00:00:00Z"}) ==
               [ctx.foreign.ref | refs]
    end

    test "a session id from another tenant matches nothing", ctx do
      other = SessionName.for("01OTHER000000000000000000", @alice, ctx.session <> "-x")
      assert %{"records" => [], "cursor" => nil} = body(records(%{"session" => other}))
    end

    test "a question it cannot answer as asked is refused, not answered loosely" do
      for query <- [
            %{"policyOutcome" => "deny"},
            %{"q" => "shell"},
            %{"limit" => "0"},
            %{"limit" => "201"},
            %{"limit" => "ten"},
            %{"since" => "yesterday"},
            %{"cursor" => "not-a-cursor"},
            %{"kind" => ""}
          ] do
        conn = records(query)
        assert conn.status == 400, "expected 400 for #{inspect(query)}, got #{conn.status}"
        assert %{"error" => "ERR_BAD_REQUEST"} = body(conn)
      end
    end
  end

  describe "GET /v1/evidence/tail" do
    test "needs credentials and the right to read records" do
      assert tail(%{}, role: nil).status == 401
      assert tail(%{}, role: "tenant_app").status == 403
    end

    test "opens a connection for a reader, and refuses a filter it does not have" do
      assert %Plug.Conn{state: :upgraded} = tail(%{}, handshake: true)
      assert tail(%{}).status == 426
      assert tail(%{"policyOutcome" => "deny"}).status == 400
      assert tail(%{"session" => "nobody-opened-this"}).status == 404
    end

    test "is refused where nothing is being captured" do
      info = Runtime.info()
      :persistent_term.erase({Runtime, :info})
      on_exit(fn -> :persistent_term.put({Runtime, :info}, info) end)

      assert %{status: 503, resp_body: body} = tail(%{})
      assert JSON.decode!(body) == %{"error" => "ERR_NOT_CAPTURING"}
    end

    test "a record that arrives is sent once, as a list row", ctx do
      {:ok, state} = TailSocket.init(opening(%{}))

      receipt = capture(recorded(ctx.session))
      :ok = Runtime.flush()
      assert_receive {:provenance, :shipped, stream, seq} = signal when seq == receipt.seq

      assert {:push, frames, state} = TailSocket.handle_info(signal, state)
      rows = for {:text, frame} <- frames, do: JSON.decode!(frame)
      assert %{"type" => "record", "record" => row} = List.last(rows)

      assert %{"records" => [^row | _]} = body(records(%{}))
      assert row["ref"] == receipt.ref

      assert {:ok, _} = TailSocket.handle_info({:provenance, :shipped, stream, seq}, state)
    end

    test "only what the reader asked for is sent", ctx do
      {:ok, mine} = TailSocket.init(opening(%{session: recorded(ctx.session)}))
      {:ok, other} = TailSocket.init(opening(%{actor: "urn:r5e:principal:test:bob"}))

      receipt = capture(recorded(ctx.session))
      :ok = Runtime.flush()
      assert_receive {:provenance, :shipped, _, seq} = signal when seq == receipt.seq

      assert {:push, [_ | _], _} = TailSocket.handle_info(signal, mine)
      assert {:ok, _} = TailSocket.handle_info(signal, other)
    end

    test "another deployment's streams are not read", ctx do
      {:ok, state} = TailSocket.init(opening(%{}))

      assert {:ok, ^state} =
               TailSocket.handle_info({:provenance, :shipped, "urn:r5e:stream:else:1", 1}, state)

      assert ctx.session
    end

    test "a ping is answered and a tick sends one" do
      {:ok, state} = TailSocket.init(opening(%{}))

      assert {:push, [{:text, ~s({"type":"pong"})}], ^state} =
               TailSocket.handle_in({~s({"type":"ping"}), opcode: :text}, state)

      assert {:ok, ^state} = TailSocket.handle_in({"not json", opcode: :text}, state)

      assert {:push, [{:text, ~s({"type":"ping"})}], ^state} =
               TailSocket.handle_info(:ping, state)
    end
  end

  describe "reading content through a record" do
    test "the bytes come as a download of unstated type", ctx do
      [%{ref: ref} | _] = ctx.receipts
      args_ref = Ref.bytes(@args)

      conn = content(ref, args_ref)
      assert conn.status == 200
      assert conn.resp_body == @args
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/octet-stream"]
      assert Plug.Conn.get_resp_header(conn, "content-disposition") == ["attachment"]
      assert Plug.Conn.get_resp_header(conn, "x-content-type-options") == ["nosniff"]
      assert Plug.Conn.get_resp_header(conn, "cache-control") == ["no-store, private"]
      assert Plug.Conn.get_resp_header(conn, "x-r5e-content-ref") == [args_ref]
    end

    test "only content the record names, and only for someone who may read content", ctx do
      [%{ref: ref} | _] = ctx.receipts
      args_ref = Ref.bytes(@args)

      assert content(ref, args_ref, role: nil).status == 401
      assert content(ref, args_ref, role: "caller").status == 403

      # Held by the deployment, but this record does not name it.
      assert content(ref, ctx.profile_ref).status == 404
      assert content(ref, Ref.bytes("never recorded")).status == 404
      assert content(Ref.evidence("no such record"), args_ref).status == 404
      assert content("not-a-ref", args_ref).status == 404
    end

    test "a disposal that could destroy nothing leaves the content readable", ctx do
      [%{ref: ref} | _] = ctx.receipts

      # This deployment has no key service, so content is held as it is
      # and there is no key to destroy. The disposal says so in its answer.
      disposed =
        ApiHandler.dispose(
          request(:post, "/v1/evidence/retention/disposals",
            body: %{"scope" => recorded(ctx.session), "reason" => "erasure request"},
            role: "platform_operator"
          )
        )

      assert disposed.status == 201
      assert %{"outcome" => "nothing_encrypted_under_scope"} = body(disposed)

      # What is still held is still served: 410 is only for content that
      # can no longer be read.
      assert content(ref, Ref.bytes(@args)).status == 200
    end
  end

  describe "the active policy" do
    alias Recurse.Gateway.Policy.ActiveHandler

    test "its source, the reference records name it by, and where it came from" do
      conn = ActiveHandler.show(request(:get, "/v1/policies/active"))
      assert conn.status == 200

      assert %{
               "bundleRef" => "bytes:sha256:" <> _ = bundle_ref,
               "source" => source,
               "sourceMode" => "filesystem",
               "activatedAt" => activated_at
             } = body(conn)

      assert bundle_ref == Ref.bytes(source)
      assert source =~ "permit"
      assert {:ok, _, 0} = DateTime.from_iso8601(activated_at)
    end

    test "needs credentials and a role that may replay decisions" do
      assert ActiveHandler.show(request(:get, "/v1/policies/active", role: nil)).status == 401

      assert ActiveHandler.show(request(:get, "/v1/policies/active", role: "caller")).status ==
               403
    end
  end

  describe "retention" do
    test "only an operator places a hold or disposes; an auditor may look", ctx do
      scope = recorded(ctx.session)
      hold = %{"scope" => scope, "reason" => "litigation"}
      post = fn path, body, opts -> request(:post, path, [body: body] ++ opts) end

      assert ApiHandler.hold(post.("/v1/evidence/retention/holds", hold, role: nil)).status == 401
      assert ApiHandler.hold(post.("/v1/evidence/retention/holds", hold, [])).status == 403

      assert ApiHandler.dispose(
               post.("/v1/evidence/retention/disposals", %{"scope" => scope, "reason" => "x"}, [])
             ).status == 403

      placed =
        ApiHandler.hold(post.("/v1/evidence/retention/holds", hold, role: "platform_operator"))

      assert placed.status == 201
      assert %{"hold" => "evidence:sha256:" <> _ = ref, "seq" => 1} = body(placed)

      # The hold stands in the way of a disposal, and the answer says which.
      refused =
        ApiHandler.dispose(
          post.("/v1/evidence/retention/disposals", %{"scope" => scope, "reason" => "x"},
            role: "platform_operator"
          )
        )

      assert refused.status == 409
      assert %{"error" => "under_hold", "about" => ^ref} = body(refused)

      listed = ApiHandler.retention(request(:get, "/v1/evidence/retention"))
      assert listed.status == 200
      assert %{"holds" => [%{"ref" => ^ref, "scope" => ^scope}], "disposals" => []} = body(listed)

      assert ApiHandler.hold(
               post.("/v1/evidence/retention/holds", %{"reason" => "no scope"},
                 role: "platform_operator"
               )
             ).status == 400
    end
  end

  describe "records" do
    test "a record is returned with its signed envelope", ctx do
      [%{ref: ref, stream: stream} | _] = ctx.receipts
      conn = record(ref)

      assert conn.status == 200

      assert %{
               "ref" => ^ref,
               "stream" => ^stream,
               "seq" => 1,
               "kind" => "provenance.r5e.io/v2/ToolCall",
               "envelope" => %{"payload" => _, "signatures" => [_]}
             } = body(conn)
    end

    test "an unknown or malformed reference is 404" do
      assert record(Ref.evidence("nothing")).status == 404
      assert record("not-a-reference").status == 404
    end
  end

  describe "sessions" do
    test "a session's records come back in order", ctx do
      refs = Enum.map(ctx.receipts, & &1.ref)
      conn = session(ctx.session)

      assert conn.status == 200

      assert %{"session" => urn, "records" => [%{"seq" => 1}, %{"seq" => 2}] = records} =
               body(conn)

      assert urn == recorded(ctx.session)
      assert Enum.map(records, & &1["ref"]) == refs
    end

    test "an id two people used is not guessed at; the reader is given the names", ctx do
      # Someone else's client happens to use the same id. It is another
      # session, and a reader asking by the id alone is told there are two.
      other = SessionName.for(@tenant, "urn:r5e:principal:test:bob", ctx.session)
      capture(other)
      :ok = Runtime.flush()

      conn = session(ctx.session)
      assert conn.status == 409
      mine = recorded(ctx.session)

      assert %{"error" => "more_than_one_session_has_this_id", "sessions" => sessions} =
               body(conn)

      assert Enum.sort(sessions) == Enum.sort([mine, other])

      # By its recorded name, or the part after the tenant, each is read alone.
      assert %{"session" => ^other, "records" => [_]} = body(session(other))
      "urn:r5e:session:" <> rest = mine
      [_tenant, tail] = String.split(rest, ":", parts: 2)
      assert %{"session" => ^mine, "records" => [_, _]} = body(session(tail))
      assert export(%{"session" => other}).status == 200
    end

    test "a session recorded under another tenant cannot be reached by its id", ctx do
      assert session(ctx.session <> "-x").status == 404
      assert export(%{"session" => ctx.session <> "-x"}).status == 404
    end

    test "a session with no records is 404" do
      assert session("never-happened").status == 404
    end
  end

  describe "export" do
    test "content is withheld unless asked for, and the bundle verifies", ctx do
      conn = export(%{"session" => ctx.session})
      assert conn.status == 200
      bundle = body(conn)

      assert Enum.any?(
               bundle["omissions"],
               &(&1 == %{"ref" => Ref.bytes(@args), "reason" => "withheld"})
             )

      refute Enum.any?(bundle["blobs"], &(&1["ref"] == Ref.bytes(@args)))

      report = Export.verify(bundle, trusted_profiles: [ctx.profile_ref])
      assert %{failed: 0} = report.summary

      # The seal also covers the other tenant's record, which is not in
      # this bundle, so each record is proved a member instead.
      assert Enum.count(report.findings, &match?(%{check: :membership, result: :ok}, &1)) == 2
    end

    test "with content, everything the records refer to is carried",
         ctx do
      conn = export(%{"session" => ctx.session, "content" => true})
      assert conn.status == 200
      bundle = body(conn)

      assert Enum.any?(bundle["blobs"], &(&1["ref"] == Ref.bytes(@args)))

      report = Export.verify(bundle, trusted_profiles: [ctx.profile_ref])
      assert %{failed: 0} = report.summary

      # Everything the two records refer to is carried. The only content
      # not carried is the seal's manifest, which is named as not selected.
      assert [%{code: "omitted_not_selected"}] =
               Enum.filter(report.findings, &(&1.check == :content and &1.result != :ok))
    end

    test "a body without a session is 400" do
      assert export(%{}).status == 400
    end
  end

  describe "verify" do
    test "a submitted bundle is checked and the report returned", ctx do
      bundle = body(export(%{"session" => ctx.session, "content" => true}))

      conn = verify(%{"bundle" => bundle, "trustedProfiles" => [ctx.profile_ref]})
      assert conn.status == 200

      assert %{"format" => "r5e.provenance-verify-report/v2", "summary" => %{"failed" => 0}} =
               body(conn)
    end

    test "a tampered bundle is reported, not refused", ctx do
      bundle = body(export(%{"session" => ctx.session}))

      tampered =
        update_in(
          bundle,
          ["records", Access.at(0), "envelope", "signatures", Access.at(0), "sig"],
          fn sig ->
            <<first, rest::binary>> = Base.decode64!(sig)
            Base.encode64(<<Bitwise.bxor(first, 1), rest::binary>>)
          end
        )

      conn = verify(%{"bundle" => tampered})
      assert conn.status == 200
      assert %{"summary" => %{"failed" => failed}} = body(conn)
      assert failed > 0
    end

    test "trusted profiles that are not references are 400", ctx do
      bundle = body(export(%{"session" => ctx.session}))
      assert verify(%{"bundle" => bundle, "trustedProfiles" => ["mine"]}).status == 400
      assert verify(%{}).status == 400
    end
  end
end
