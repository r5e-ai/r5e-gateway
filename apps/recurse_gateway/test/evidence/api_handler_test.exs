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
  alias Recurse.Gateway.Provenance.{Runtime, SessionName}
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Provenance.{Body, Export, Key, Pipeline, Ref}
  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore}
  alias Recurse.Providers.Impls.PostgresMerkleLedger
  alias Recurse.Providers.Repo

  @tenant "01HQZN5K7J8M9N0P1Q2R3S4T5V"
  @alice "urn:r5e:principal:test:alice"
  @args ~s({"command":"ls"})
  @policy "permit(principal, action, resource);"

  setup %{tmp_dir: tmp_dir} = ctx do
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

    # Content is encrypted only where a test asks: the handler opens the
    # store from the node's settings, so the key file is named there too.
    {store, restore} =
      if ctx[:encrypted] do
        key_file = Path.join(tmp_dir, "content.key")
        :ok = LocalKeyService.generate(key_file)
        {:ok, keys} = LocalKeyService.open(key_file)

        {{PostgresEvidenceStore, %{repo: Repo, keys: {LocalKeyService, keys}}},
         [put_env(:evidence_content_key_file, key_file) | restore]}
      else
        {{PostgresEvidenceStore, Repo}, restore}
      end

    start_supervised!(
      {Runtime,
       deployment: deployment,
       signer: Key.generate("ed25519"),
       store: store,
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
              subject: Keyword.get(opts, :subject, "user-0001"),
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

  defp facets(query, opts \\ []),
    do: ApiHandler.facets(request(:get, "/v1/evidence/facets?" <> URI.encode_query(query), opts))

  defp histogram(query, opts \\ []),
    do:
      ApiHandler.histogram(
        request(:get, "/v1/evidence/histogram?" <> URI.encode_query(query), opts)
      )

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

  defp dispose(scope),
    do:
      ApiHandler.dispose(
        request(:post, "/v1/evidence/retention/disposals",
          body: %{"scope" => scope, "reason" => "erasure request"},
          role: "platform_operator"
        )
      )

  defp dispose_owner(owner),
    do:
      ApiHandler.dispose(
        request(:post, "/v1/evidence/retention/disposals",
          body: %{"owner" => owner, "reason" => "erasure request"},
          role: "platform_operator"
        )
      )

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

    test "an unauthorized role is refused on every route", ctx do
      [%{ref: ref} | _] = ctx.receipts
      assert record(ref, role: "tenant_app").status == 403
      assert session(ctx.session, role: "tenant_app").status == 403
      assert export(%{"session" => ctx.session}, role: "tenant_app").status == 403
      assert verify(%{"bundle" => %{}}, role: "caller").status == 403
    end
  end

  describe "listing records" do
    @tool_call "provenance.r5e.io/v2/ToolCall"

    test "needs credentials and either ReadReceipts or ReadOwnEvidence" do
      assert records(%{}, role: nil).status == 401
      assert records(%{}, role: "tenant_app").status == 403
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
            %{"outcome" => "deny"},
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
      assert content(ref, args_ref, role: "tenant_app").status == 403

      # Held by the deployment, but this record does not name it.
      assert content(ref, ctx.profile_ref).status == 404
      assert content(ref, Ref.bytes("never recorded")).status == 404
      assert content(Ref.evidence("no such record"), args_ref).status == 404
      assert content("not-a-ref", args_ref).status == 404
    end

    test "where content is not encrypted a disposal is refused and nothing is recorded", ctx do
      [%{ref: ref} | _] = ctx.receipts

      refused = dispose(recorded(ctx.session))

      assert refused.status == 409
      assert %{"error" => "ERR_NOTHING_TO_DISPOSE"} = body(refused)

      assert %{"records" => []} =
               body(records(%{"kind" => "provenance.r5e.io/v2/PayloadDisposition"}))

      assert content(ref, Ref.bytes(@args)).status == 200
    end

    @tag :encrypted
    test "disposed content answers 410, and cannot be disposed of twice", ctx do
      [%{ref: ref} | _] = ctx.receipts
      assert content(ref, Ref.bytes(@args)).resp_body == @args

      disposed = dispose(recorded(ctx.session))
      assert disposed.status == 201
      assert %{"outcome" => "disposed"} = body(disposed)

      gone = content(ref, Ref.bytes(@args))
      assert gone.status == 410
      assert %{"error" => "ERR_CONTENT_DISPOSED"} = body(gone)

      assert dispose(recorded(ctx.session)).status == 409
    end

    @tag :encrypted
    test "disposing of a person disposes of each session of theirs, by a record of its own",
         ctx do
      [%{ref: ref} | _] = ctx.receipts
      later = capture(recorded(ctx.session <> "-later"))
      {:ok, _} = Runtime.seal()

      answer = dispose_owner(@alice)
      assert answer.status == 201

      assert %{"owner" => @alice, "complete" => true, "refused" => [], "disposed" => disposed} =
               body(answer)

      # Alice's two sessions in this tenant, and not her session in another.
      assert Enum.sort([recorded(ctx.session), recorded(ctx.session <> "-later")]) ==
               disposed |> Enum.map(& &1["session"]) |> Enum.sort()

      assert Enum.all?(
               disposed,
               &match?(%{"disposal" => "evidence:" <> _, "outcome" => "disposed"}, &1)
             )

      for gone <- [ref, later.ref] do
        assert content(gone, Ref.bytes(@args)).status == 410
      end

      again = dispose_owner(@alice)
      assert again.status == 409
      assert %{"error" => "ERR_NOTHING_TO_DISPOSE"} = body(again)
    end

    @tag :encrypted
    test "a session under a hold is refused and named, and the person's others still go", ctx do
      [%{ref: ref} | _] = ctx.receipts
      kept = recorded(ctx.session <> "-kept")
      held = capture(kept)
      {:ok, _} = Runtime.seal()

      hold =
        ApiHandler.hold(
          request(:post, "/v1/evidence/retention/holds",
            body: %{"scope" => kept, "reason" => "litigation"},
            role: "platform_operator"
          )
        )

      assert hold.status == 201

      answer = dispose_owner(@alice)
      assert answer.status == 201

      assert %{
               "complete" => false,
               "disposed" => [%{"session" => session}],
               "refused" => [%{"session" => ^kept, "error" => %{"reason" => "under_hold"}}]
             } = body(answer)

      assert session == recorded(ctx.session)
      assert content(ref, Ref.bytes(@args)).status == 410
      assert content(held.ref, Ref.bytes(@args)).resp_body == @args
    end

    test "a person is asked for by owner alone, and someone with no sessions has nothing", _ctx do
      both =
        ApiHandler.dispose(
          request(:post, "/v1/evidence/retention/disposals",
            body: %{"owner" => @alice, "scope" => "urn:r5e:session:x", "reason" => "r"},
            role: "platform_operator"
          )
        )

      assert both.status == 400
      assert dispose_owner("urn:r5e:principal:test:nobody").status == 409
    end
  end

  describe "narrowing and counting records" do
    @tool_call "provenance.r5e.io/v2/ToolCall"

    defp count_of(facet, value),
      do: Enum.find_value(facet, 0, &(&1["value"] == value && &1["count"]))

    test "a list row says how policy decided and what was called, and both narrow the list" do
      allowed = records(%{"policyOutcome" => "allow"})
      assert allowed.status == 200
      assert %{"records" => [_ | _] = rows} = body(allowed)
      assert Enum.all?(rows, &match?(%{"policyOutcome" => "allow", "target" => "Bash"}, &1))

      assert %{"records" => []} = body(records(%{"policyOutcome" => "deny"}))
      assert %{"records" => ^rows} = body(records(%{"target" => "Bash"}))
      assert %{"records" => []} = body(records(%{"target" => "bash"}))
      # Free text finds it whatever the case, and is never read as a pattern.
      assert %{"records" => ^rows} = body(records(%{"q" => "bAsH"}))
      assert %{"records" => []} = body(records(%{"q" => "b%h"}))
    end

    test "the counts are of every matching record, not of a page" do
      %{"records" => all} = body(records(%{"kind" => @tool_call, "limit" => "200"}))
      %{"records" => [_one]} = body(records(%{"kind" => @tool_call, "limit" => "1"}))

      counted = facets(%{"kind" => @tool_call})
      assert counted.status == 200

      assert %{
               "total" => total,
               "facets" => %{"kind" => kinds, "policyOutcome" => outcomes, "target" => targets}
             } =
               body(counted)

      assert total == length(all)
      assert count_of(outcomes, "allow") == total
      assert count_of(targets, "Bash") == total
      # Other kinds are still offered beside the one chosen.
      assert count_of(kinds, @tool_call) == total
      assert length(kinds) > 1
    end

    test "a division is counted without the reader's own choice in it" do
      assert %{"total" => 0, "facets" => %{"policyOutcome" => outcomes, "target" => []}} =
               body(facets(%{"policyOutcome" => "deny"}))

      assert count_of(outcomes, "allow") > 0
    end

    test "records over time, with empty spans given" do
      since = DateTime.add(DateTime.utc_now(), -3600, :second)
      until = DateTime.add(DateTime.utc_now(), 3600, :second)
      span = %{"since" => DateTime.to_iso8601(since), "until" => DateTime.to_iso8601(until)}

      drawn = histogram(Map.merge(span, %{"buckets" => "4", "kind" => @tool_call}))
      assert drawn.status == 200
      assert %{"bucketSeconds" => seconds, "buckets" => [_, _, _, _] = buckets} = body(drawn)
      assert_in_delta seconds, 1800, 1

      %{"total" => total} = body(facets(Map.put(span, "kind", @tool_call)))
      assert total > 0
      assert total == buckets |> Enum.map(& &1["count"]) |> Enum.sum()
      assert total == buckets |> Enum.map(&Map.get(&1["byOutcome"], "allow", 0)) |> Enum.sum()
      assert Enum.any?(buckets, &(&1["count"] == 0 and &1["byOutcome"] == %{}))
      assert {:ok, _, 0} = DateTime.from_iso8601(hd(buckets)["start"])
    end

    test "several kinds are asked for together, and counted as one view" do
      %{"records" => calls} = body(records(%{"kind" => @tool_call, "limit" => "200"}))
      opened = "provenance.r5e.io/v2/EpochSeal"
      %{"records" => openings} = body(records(%{"kind" => opened, "limit" => "200"}))
      assert openings != []

      both = @tool_call <> "," <> opened
      %{"records" => together} = body(records(%{"kind" => both, "limit" => "200"}))
      assert length(together) == length(calls) + length(openings)

      assert %{"total" => total, "facets" => %{"kind" => kinds}} = body(facets(%{"kind" => both}))
      assert total == length(together)
      assert count_of(kinds, @tool_call) == length(calls)
      assert count_of(kinds, opened) == length(openings)
    end

    test "a decision's reason is on the row, narrows the list and is counted" do
      {:ok, _} =
        Pipeline.capture(Runtime.pipeline(), %{
          kind_path: "provenance.r5e.io/v2/ToolCall",
          actor: @alice,
          session: recorded("reasoned"),
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
                  outcome: "deny",
                  reason: "not_allowed_here",
                  input_refs: ["attachment:args"]
                )
            )
        })

      {:ok, _} = Runtime.seal()

      assert %{"records" => [%{"reason" => "not_allowed_here", "policyOutcome" => "deny"}]} =
               body(records(%{"reason" => "not_allowed_here"}))

      assert %{"facets" => %{"reason" => reasons}} = body(facets(%{}))
      assert count_of(reasons, "not_allowed_here") == 1
    end

    test "what is asked for is checked" do
      assert histogram(%{}).status == 400

      assert histogram(%{"since" => "2026-01-02T00:00:00Z", "until" => "2026-01-01T00:00:00Z"}).status ==
               400

      assert histogram(%{
               "since" => "2026-01-01T00:00:00Z",
               "until" => "2026-01-02T00:00:00Z",
               "buckets" => "0"
             }).status == 400

      assert facets(%{"limit" => "5"}).status == 400
      assert facets(%{"nope" => "x"}).status == 400
      assert records(%{"q" => String.duplicate("a", 201)}).status == 400
      assert facets(%{}, role: nil).status == 401
      assert histogram(%{}, role: nil).status == 401
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

  describe "self-scoped user evidence (ReadOwnEvidence)" do
    defp principal_urn(subject),
      do: "urn:r5e:principal:#{SessionName.encode(@tenant)}:#{SessionName.encode(subject)}"

    defp capture_for(actor, session, args) do
      {:ok, receipt} =
        Pipeline.capture(Runtime.pipeline(), %{
          kind_path: "provenance.r5e.io/v2/ToolCall",
          actor: actor,
          session: session,
          attachments: [%{name: "args", bytes: args}],
          blobs: [@policy],
          body:
            Body.tool_call(
              tool: "Bash",
              content_ref: "attachment:args",
              media_type: "application/json",
              size: byte_size(args),
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

    @tag :encrypted
    test "non-admin users read and export strictly their own records and content, never another user's",
         ctx do
      alice_sub = "alice.self@example.test"
      bob_sub = "bob.self@example.test"
      alice_urn = principal_urn(alice_sub)
      bob_urn = principal_urn(bob_sub)

      # Both users reuse the exact same bare client session id to prove
      # self-scoped resolution never collides or leaks the other user's name.
      shared_id = "shared-chat-#{System.unique_integer([:positive])}"
      alice_session = SessionName.for(@tenant, alice_urn, shared_id)
      alice_only_id = "alice-only-#{System.unique_integer([:positive])}"
      alice_only_session = SessionName.for(@tenant, alice_urn, alice_only_id)
      bob_session = SessionName.for(@tenant, bob_urn, shared_id)
      bob_private_id = "bob-private-#{System.unique_integer([:positive])}"
      bob_private_session = SessionName.for(@tenant, bob_urn, bob_private_id)

      alice_args = ~s({"command":"echo alice-secret"})
      bob_args = ~s({"command":"echo bob-secret"})

      # 1. Alice record matched by actor AND session
      alice_rec = capture_for(alice_urn, alice_session, alice_args)
      # 2. Alice record matched by session principal even when actor is a workload
      alice_workload_rec = capture_for("urn:r5e:workload:helper-1", alice_session, alice_args)
      # 3. Alice sessionless record matched strictly by actor
      alice_actor_only = capture_for(alice_urn, nil, alice_args)
      # 4. Alice private session
      alice_private_rec = capture_for(alice_urn, alice_only_session, alice_args)

      # Bob's records
      bob_rec = capture_for(bob_urn, bob_session, bob_args)
      bob_private_rec = capture_for(bob_urn, bob_private_session, bob_args)

      {:ok, _} = Runtime.seal()

      # Place a retention hold on Bob's private session so we can assert
      # Alice's self-scoped export never carries org-wide retention holds.
      hold_conn =
        ApiHandler.hold(
          request(:post, "/v1/evidence/retention/holds",
            body: %{"scope" => bob_private_session, "reason" => "bob_case"},
            role: "platform_operator"
          )
        )

      assert hold_conn.status == 201
      %{"hold" => bob_hold_ref} = body(hold_conn)

      alice_expected_refs =
        Enum.sort([
          alice_rec.ref,
          alice_workload_rec.ref,
          alice_actor_only.ref,
          alice_private_rec.ref
        ])

      # Positive: listing records works for caller, employee, parent, and student
      for role <- ~w(caller employee parent student) do
        listed = records(%{"limit" => "200"}, role: role, subject: alice_sub)
        assert listed.status == 200

        got_refs =
          listed |> body() |> Map.fetch!("records") |> Enum.map(& &1["ref"]) |> Enum.sort()

        assert got_refs == alice_expected_refs
      end

      # Positive: fetching own record by ref (actor-matched & workload-in-own-session)
      assert record(alice_rec.ref, role: "caller", subject: alice_sub).status == 200
      assert record(alice_workload_rec.ref, role: "caller", subject: alice_sub).status == 200
      assert record(alice_actor_only.ref, role: "caller", subject: alice_sub).status == 200

      # Positive: fetching own content bytes (encrypted store!)
      alice_content =
        content(alice_rec.ref, Ref.bytes(alice_args), role: "caller", subject: alice_sub)

      assert alice_content.status == 200
      assert alice_content.resp_body == alice_args

      # Positive: fetching own session by bare id (no 409 collision with Bob!),
      # by <fingerprint>.<id> tail, and by full URN
      bare_session = session(shared_id, role: "caller", subject: alice_sub)
      assert bare_session.status == 200

      assert %{"session" => ^alice_session, "records" => alice_session_rows} =
               body(bare_session)

      assert Enum.map(alice_session_rows, & &1["ref"]) == [alice_rec.ref, alice_workload_rec.ref]

      "urn:r5e:session:" <> alice_rest = alice_session
      [_tenant_part, alice_tail] = String.split(alice_rest, ":", parts: 2)
      assert session(alice_tail, role: "caller", subject: alice_sub).status == 200
      assert session(alice_session, role: "caller", subject: alice_sub).status == 200

      # Positive: exporting own session (with & without content) verifies offline
      # and omits org-wide retention holds belonging to other users.
      exported =
        export(%{"session" => shared_id, "content" => true}, role: "caller", subject: alice_sub)

      assert exported.status == 200
      bundle = body(exported)
      exported_refs = Enum.map(bundle["records"], & &1["ref"])
      assert alice_rec.ref in exported_refs
      assert alice_workload_rec.ref in exported_refs
      refute bob_rec.ref in exported_refs
      refute bob_private_rec.ref in exported_refs
      refute bob_hold_ref in exported_refs
      assert Enum.any?(bundle["blobs"], &(&1["ref"] == Ref.bytes(alice_args)))
      report = Export.verify(bundle, trusted_profiles: [ctx.profile_ref])
      assert %{failed: 0} = report.summary

      # Negative cross-user isolation: Bob can NEVER see Alice's records,
      # content, or sessions through any route or filter.
      bob_list = records(%{"limit" => "200"}, role: "caller", subject: bob_sub)
      assert bob_list.status == 200

      bob_refs =
        bob_list |> body() |> Map.fetch!("records") |> Enum.map(& &1["ref"]) |> Enum.sort()

      assert bob_refs == Enum.sort([bob_rec.ref, bob_private_rec.ref])

      # Bob passing ?actor=<alice> or ?session=<alice_session> gets zero records
      assert %{"records" => []} =
               body(records(%{"actor" => alice_urn}, role: "caller", subject: bob_sub))

      assert %{"records" => []} =
               body(records(%{"session" => alice_session}, role: "caller", subject: bob_sub))

      assert %{"records" => []} =
               body(records(%{"session" => alice_tail}, role: "caller", subject: bob_sub))

      # Bob probing Alice's refs, content, sessions, and export all get 404
      assert record(alice_rec.ref, role: "caller", subject: bob_sub).status == 404
      assert record(alice_workload_rec.ref, role: "caller", subject: bob_sub).status == 404
      assert record(alice_actor_only.ref, role: "caller", subject: bob_sub).status == 404

      assert content(alice_rec.ref, Ref.bytes(alice_args), role: "caller", subject: bob_sub).status ==
               404

      assert session(alice_session, role: "caller", subject: bob_sub).status == 404
      assert session(alice_tail, role: "caller", subject: bob_sub).status == 404
      assert session(alice_only_id, role: "caller", subject: bob_sub).status == 404

      assert export(%{"session" => alice_session, "content" => true},
               role: "caller",
               subject: bob_sub
             ).status == 404

      assert export(%{"session" => alice_tail}, role: "caller", subject: bob_sub).status == 404
      assert export(%{"session" => alice_only_id}, role: "caller", subject: bob_sub).status == 404

      # Even after Alice's session is disposed, Bob still gets 404 (never 410 leak)
      # while Alice gets 410 for her own disposed content.
      assert dispose(alice_session).status == 201

      assert content(alice_rec.ref, Ref.bytes(alice_args), role: "caller", subject: bob_sub).status ==
               404

      assert content(alice_rec.ref, Ref.bytes(alice_args), role: "caller", subject: alice_sub).status ==
               410

      # Direct SQL-layer verification on PostgresEvidenceStore
      handle = elem(Runtime.info().store, 1)
      bob_prefix = SessionName.for(@tenant, bob_urn, "")

      assert :error =
               PostgresEvidenceStore.fetch_owned(handle, alice_rec.ref, bob_urn, bob_prefix)

      assert {:ok, []} =
               PostgresEvidenceStore.by_session_owned(handle, alice_session, bob_urn, bob_prefix)

      # Non-self-scoped endpoints remain forbidden for caller role
      assert facets(%{}, role: "caller", subject: alice_sub).status == 403
      assert tail(%{}, role: "caller", subject: alice_sub).status == 403

      assert ApiHandler.retention(request(:get, "/v1/evidence/retention", role: "caller")).status ==
               403
    end

    test "caller is denied with 403 when active Cedar bundle does not grant ReadOwnEvidence" do
      no_own_bundle =
        Path.join(System.tmp_dir!(), "no_own_bundle_#{System.unique_integer()}.cedar")

      File.write!(
        no_own_bundle,
        ~s[permit(principal, action == Recurse::Action::"ReadReceipts", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };]
      )

      on_exit(fn -> File.rm(no_own_bundle) end)

      start_supervised!(
        Supervisor.child_spec(
          {BundleLoader,
           bundle_path: no_own_bundle,
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

      assert records(%{}, role: "caller", subject: "alice.denied@example.test").status == 403

      assert export(%{"session" => "any"}, role: "caller", subject: "alice.denied@example.test").status ==
               403
    end
  end
end
