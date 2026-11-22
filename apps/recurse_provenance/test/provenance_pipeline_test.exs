defmodule Recurse.Provenance.PipelineTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.{
    Body,
    Envelope,
    Export,
    Key,
    Log,
    Pipeline,
    Profile,
    Ref,
    Shipper,
    Signals
  }

  alias Recurse.Provenance.Store.Memory

  @moduletag :tmp_dir

  @base "provenance.r5e.io/v2"
  @actor "spiffe://example.test/workload/gateway"
  @args ~s({"command":"ls"})

  setup %{tmp_dir: dir} = ctx do
    signer = Key.generate("ed25519")
    {:ok, store} = Memory.start_link()

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: "urn:r5e:stream:test:",
            actor_prefixes: ["spiffe://example.test/workload/"],
            issuer_keys: [signer.key_id],
            sealer_keys: [signer.key_id]
          }
        ],
        failure_domain: "local disk (test)",
        deployment_policy_ref: Ref.bytes("deployment")
      )

    name = Module.concat(__MODULE__, "P#{System.unique_integer([:positive])}")

    ctx =
      Map.merge(ctx, %{pipeline: name, store: store, signer: signer, profile: profile, dir: dir})

    restart_pipeline(ctx)
    Map.take(ctx, [:pipeline, :store, :signer, :profile, :dir])
  end

  defp restart_pipeline(ctx) do
    start_supervised!(
      {Pipeline,
       name: ctx.pipeline,
       dir: ctx.dir,
       stream_prefix: "urn:r5e:stream:test:",
       signer: ctx.signer,
       profile: ctx.profile,
       index: {Memory, ctx.store},
       actor: @actor,
       partitions: Map.get(ctx, :partitions, 2),
       flush_interval_ms: Map.get(ctx, :flush_interval_ms, 20)}
    )
  end

  defp restart(ctx) do
    :ok = stop_supervised!(Pipeline)
    name = Module.concat(__MODULE__, "P#{System.unique_integer([:positive])}")

    start_supervised!(
      {Pipeline,
       name: name,
       dir: ctx.dir,
       stream_prefix: "urn:r5e:stream:test:",
       signer: ctx.signer,
       profile: ctx.profile,
       index: {Memory, ctx.store},
       actor: @actor,
       partitions: 1,
       flush_interval_ms: 20}
    )

    name
  end

  defp tool_call(overrides \\ %{}) do
    Map.merge(
      %{
        kind_path: @base <> "/ToolCall",
        actor: @actor,
        session: "urn:r5e:session:test:one",
        attachments: [%{name: "args", bytes: @args}],
        body:
          Body.tool_call(
            tool: "shell",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: byte_size(@args),
            policy:
              Body.policy_evaluation(
                policy_ref: Ref.bytes("permit(principal, action, resource);"),
                outcome: "allow",
                input_refs: ["attachment:args"]
              )
          )
      },
      overrides
    )
  end

  test "records are listed newest first, a page at a time, and narrowed by what is asked", ctx do
    {store, handle} = {Memory, ctx.store}
    pipeline = ctx.pipeline
    other_actor = "spiffe://example.test/workload/other"

    for overrides <- [
          %{session: "urn:r5e:session:test:list-a"},
          %{session: "urn:r5e:session:test:list-a", actor: other_actor},
          %{session: "urn:r5e:session:test:list-b"},
          %{session: "urn:r5e:session:test:list-b", actor: other_actor},
          %{session: "urn:r5e:session:test:list-b"}
        ] do
      {:ok, _} = Pipeline.capture(pipeline, tool_call(overrides))
    end

    :ok = Pipeline.flush(pipeline)

    asked = %{stream_prefix: "urn:r5e:stream:test:", limit: 100}
    assert {:ok, [_, _, _, _, _] = all} = store.list(handle, asked)

    position = fn entry ->
      {:ok, at, 0} = DateTime.from_iso8601(entry.evidence["capturedAt"])
      {at, entry.ref}
    end

    newest_first =
      Enum.sort(all, fn a, b ->
        {at, ref} = position.(a)
        {other_at, other_ref} = position.(b)
        DateTime.compare(at, other_at) == :gt or (at == other_at and ref >= other_ref)
      end)

    refs = Enum.map(newest_first, & &1.ref)
    assert Enum.map(all, & &1.ref) == refs

    # Three pages of two: nothing repeated, nothing missed.
    assert {:ok, [first, second]} = store.list(handle, %{asked | limit: 2})

    assert {:ok, [third, fourth]} =
             store.list(handle, Map.merge(asked, %{limit: 2, before: position.(second)}))

    assert {:ok, [fifth]} =
             store.list(handle, Map.merge(asked, %{limit: 2, before: position.(fourth)}))

    assert Enum.map([first, second, third, fourth, fifth], & &1.ref) == refs
    assert {:ok, []} = store.list(handle, Map.put(asked, :before, position.(fifth)))

    assert {:ok, [_, _, _] = of_session} =
             store.list(handle, Map.put(asked, :session, "urn:r5e:session:test:list-b"))

    assert Enum.all?(of_session, &(&1.evidence["session"] == "urn:r5e:session:test:list-b"))

    assert {:ok,
            [%{evidence: %{"actor" => ^other_actor}}, %{evidence: %{"actor" => ^other_actor}}]} =
             store.list(handle, Map.put(asked, :actor, other_actor))

    assert {:ok, [_, _, _, _, _]} =
             store.list(handle, Map.put(asked, :kind_path, @base <> "/ToolCall"))

    assert {:ok, []} = store.list(handle, Map.put(asked, :kind_path, @base <> "/ToolResult"))

    # `since` includes its moment and `until` excludes its own.
    {middle, _} = position.(third)
    assert {:ok, since} = store.list(handle, Map.put(asked, :since, middle))
    assert {:ok, until} = store.list(handle, Map.put(asked, :until, middle))
    assert third.ref in Enum.map(since, & &1.ref)
    refute third.ref in Enum.map(until, & &1.ref)
    assert Enum.sort(Enum.map(since ++ until, & &1.ref)) == Enum.sort(refs)

    assert {:ok, []} =
             store.list(handle, %{asked | stream_prefix: "urn:r5e:stream:test:" <> "elsewhere:"})
  end

  @tag flush_interval_ms: 60_000
  test "capture answers when the record is signed, before anything reaches disk or the index",
       ctx do
    assert {:ok, %{ref: "evidence:sha256:" <> _ = ref, seq: 1, stream: stream}} =
             Pipeline.capture(ctx.pipeline, tool_call())

    assert String.starts_with?(stream, "urn:r5e:stream:test:gateway:")
    assert :error = Memory.fetch(ctx.store, ref)

    assert :ok = Pipeline.flush(ctx.pipeline)
    assert {:ok, %{seq: 1, evidence: %{"issuer" => issuer}}} = Memory.fetch(ctx.store, ref)
    assert issuer == ctx.signer.key_id
  end

  test "durable and shipped are announced as signals, in that order, without being asked", ctx do
    signals = Pipeline.signals(ctx.pipeline)
    Signals.subscribe(signals, :durable)
    Signals.subscribe(signals, :shipped)

    {:ok, %{stream: stream, seq: seq, ref: ref}} = Pipeline.capture(ctx.pipeline, tool_call())

    assert :ok = Signals.await(:durable, stream, seq, 2_000)
    assert :ok = Signals.await(:shipped, stream, seq, 2_000)
    assert {:ok, _} = Memory.fetch(ctx.store, ref)
  end

  test "one session's records form one chain; signatures verify", ctx do
    receipts = for _ <- 1..5, do: elem(Pipeline.capture(ctx.pipeline, tool_call()), 1)
    :ok = Pipeline.flush(ctx.pipeline)

    assert [1, 2, 3, 4, 5] = Enum.map(receipts, & &1.seq)
    assert [_one_stream] = receipts |> Enum.map(& &1.stream) |> Enum.uniq()

    entries = for r <- receipts, do: elem(Memory.fetch(ctx.store, r.ref), 1)
    previous = [nil | Enum.map(Enum.drop(receipts, -1), & &1.ref)]
    assert previous == Enum.map(entries, & &1.evidence["previous"])

    keys = %{ctx.signer.key_id => %{algorithm: "ed25519", bytes: ctx.signer.public_key}}

    for entry <- entries do
      {:ok, opened} = Envelope.open(entry.envelope)
      assert :ok = Envelope.verify(opened, keys)
    end
  end

  @tag partitions: 4
  test "different sessions are spread over writers and do not share a chain", ctx do
    streams =
      for n <- 1..40, into: MapSet.new() do
        {:ok, %{stream: stream}} =
          Pipeline.capture(ctx.pipeline, tool_call(%{session: "urn:r5e:session:test:#{n}"}))

        stream
      end

    assert MapSet.size(streams) > 1
    assert MapSet.subset?(streams, MapSet.new(Pipeline.streams(ctx.pipeline)))
  end

  test "attachments become content references; the bytes end up in the content store", ctx do
    {:ok, %{ref: ref}} = Pipeline.capture(ctx.pipeline, tool_call())
    :ok = Pipeline.flush(ctx.pipeline)

    {:ok, entry} = Memory.fetch(ctx.store, ref)
    args_ref = Ref.bytes(@args)
    assert entry.evidence["body"]["contentRef"] == args_ref
    refute Jason.encode!(entry.evidence) =~ "attachment:"
    assert {:ok, @args} = Memory.get_blob(ctx.store, args_ref)

    # Nothing is left waiting locally once it has been shipped.
    assert [] = File.ls!(Path.join(ctx.dir, "content"))
  end

  describe "content that waits on disk through a host's own staging" do
    defmodule Staging do
      @moduledoc false
      # Plain files, except that reading one back answers whatever the
      # test has said it should.
      @behaviour Recurse.Provenance.Staging
      alias Recurse.Provenance.Staging.Plain

      @impl true
      defdelegate write_bytes(state, target, bytes), to: Plain
      @impl true
      defdelegate hash_file(state, path, expected), to: Plain
      @impl true
      defdelegate place_file(state, source, target), to: Plain

      @impl true
      def content(answers, path) do
        case Agent.get(answers, & &1) do
          :as_it_is -> Plain.content(nil, path)
          answer -> answer
        end
      end
    end

    setup ctx do
      {:ok, answers} = Agent.start_link(fn -> :as_it_is end)
      name = Module.concat(__MODULE__, "S#{System.unique_integer([:positive])}")

      start_supervised!(
        {Pipeline,
         name: name,
         dir: Path.join(ctx.dir, "staged"),
         stream_prefix: "urn:r5e:stream:test:",
         signer: ctx.signer,
         profile: ctx.profile,
         index: {Memory, ctx.store},
         actor: @actor,
         partitions: 1,
         flush_interval_ms: 20,
         staging: {Staging, answers}},
        id: name
      )

      %{staged: name, answers: answers}
    end

    defp with_args(text),
      do:
        tool_call(%{
          attachments: [%{name: "args", bytes: text}],
          session: "urn:r5e:session:staged"
        })

    test "a waiting file that can never be read again does not hold up its records or the ones after",
         %{staged: pipeline, answers: answers, store: store} do
      for gone <- [{:error, :staged_content_lost}] do
        Agent.update(answers, fn _ -> gone end)
        {:ok, lost} = Pipeline.capture(pipeline, with_args("content whose key is gone"))
        assert :ok = Pipeline.flush(pipeline)

        # The record is in the index; its content is not, and nothing waits.
        assert {:ok, %{ref: ref}} = Memory.fetch(store, lost.ref)
        assert ref == lost.ref
        assert :error = Memory.get_blob(store, Ref.bytes("content whose key is gone"))
      end

      Agent.update(answers, fn _ -> :as_it_is end)
      {:ok, after_it} = Pipeline.capture(pipeline, with_args("content recorded afterwards"))
      assert :ok = Pipeline.flush(pipeline)
      assert {:ok, _} = Memory.fetch(store, after_it.ref)

      assert {:ok, "content recorded afterwards"} =
               Memory.get_blob(store, Ref.bytes("content recorded afterwards"))
    end

    test "a waiting file that cannot be read for now is kept and shipped when it can be",
         %{staged: pipeline, answers: answers, store: store} do
      Agent.update(answers, fn _ -> {:error, {:key_service_unavailable, :timeout}} end)
      {:ok, receipt} = Pipeline.capture(pipeline, with_args("content that has to wait"))

      assert {:error, :not_shipped} = Pipeline.flush(pipeline)
      assert :error = Memory.fetch(store, receipt.ref)

      Agent.update(answers, fn _ -> :as_it_is end)
      assert :ok = Pipeline.flush(pipeline)
      assert {:ok, _} = Memory.fetch(store, receipt.ref)

      assert {:ok, "content that has to wait"} =
               Memory.get_blob(store, Ref.bytes("content that has to wait"))
    end

    defmodule NotHeldStore do
      @moduledoc false
      @behaviour Recurse.Provenance.Store

      @impl true
      def head({mem, _state}, stream), do: Memory.head(mem, stream)
      @impl true
      def append({mem, _state}, entry), do: Memory.append(mem, entry)

      @impl true
      def append_many({mem, state}, entries) do
        case Agent.get(state, & &1.append) do
          :ok -> Memory.append_many(mem, entries)
          {:error, _} = error -> error
        end
      end

      @impl true
      def fetch({mem, _state}, ref), do: Memory.fetch(mem, ref)
      @impl true
      def by_submission({mem, _state}, stream, id), do: Memory.by_submission(mem, stream, id)
      @impl true
      def range({mem, _state}, s, a, b), do: Memory.range(mem, s, a, b)
      @impl true
      def last_seal({mem, _state}, stream), do: Memory.last_seal(mem, stream)
      @impl true
      def unsealed_firsts({mem, _state}, prefix), do: Memory.unsealed_firsts(mem, prefix)
      @impl true
      def by_session({mem, _state}, session), do: Memory.by_session(mem, session)
      @impl true
      def by_kind({mem, _state}, kind, prefix), do: Memory.by_kind(mem, kind, prefix)
      @impl true
      def list({mem, _state}, asked), do: Memory.list(mem, asked)
      @impl true
      def seal_covering({mem, _state}, stream, seq), do: Memory.seal_covering(mem, stream, seq)
      @impl true
      def put_key({mem, _state}, key), do: Memory.put_key(mem, key)
      @impl true
      def get_key({mem, _state}, key_id), do: Memory.get_key(mem, key_id)
      @impl true
      def put_blob({mem, _state}, ref, content), do: Memory.put_blob(mem, ref, content)

      @impl true
      def put_content({_mem, state}, ref, :held, scope) do
        Agent.update(state, fn s -> %{s | not_held_calls: [{ref, scope} | s.not_held_calls]} end)
        {:error, :not_held}
      end

      def put_content({mem, _state}, ref, content, scope),
        do: Memory.put_content(mem, ref, content, scope)

      @impl true
      def get_content({mem, _state}, ref, scope), do: Memory.get_content(mem, ref, scope)
      @impl true
      def get_blob({mem, _state}, ref), do: Memory.get_blob(mem, ref)
    end

    defmodule QuarantiningStaging do
      @moduledoc false
      @behaviour Recurse.Provenance.Staging
      alias Recurse.Provenance.Staging.Plain

      @impl true
      defdelegate write_bytes(s, target, bytes), to: Plain
      @impl true
      defdelegate hash_file(s, path, expected), to: Plain
      @impl true
      defdelegate place_file(s, source, target), to: Plain

      @impl true
      def content(quarantine_hex, path) do
        if String.ends_with?(path, quarantine_hex) do
          File.rm!(path)
          {:error, {:staged_content_unreadable, :tampered}}
        else
          Plain.content(nil, path)
        end
      end
    end

    test "content that is neither waiting nor held ships its records without content rather than wedging",
         ctx do
      {:ok, mem} = Memory.start_link()

      {:ok, state} =
        Agent.start_link(fn -> %{append: {:error, :index_down}, not_held_calls: []} end)

      dir = Path.join(ctx.dir, "not-held")
      quarantine_hex = Base.encode16(:crypto.hash(:sha256, "moved aside"), case: :lower)
      name = Module.concat(__MODULE__, "NH#{System.unique_integer([:positive])}")

      start_supervised!(
        {Pipeline,
         name: name,
         dir: dir,
         stream_prefix: "urn:r5e:stream:test:",
         signer: ctx.signer,
         profile: ctx.profile,
         index: {NotHeldStore, {mem, state}},
         actor: @actor,
         partitions: 1,
         flush_interval_ms: 20,
         staging: {QuarantiningStaging, quarantine_hex}},
        id: name
      )

      {:ok, gone} = Pipeline.capture(name, with_args("moved aside"))
      assert {:error, :not_shipped} = Pipeline.flush(name)

      # The waiting file was moved aside on the first attempt (`not waiting?`),
      # and the index had failed before saving the cursor. When the index comes
      # back, the store answers `{:error, :not_held}` for `:held` under the
      # session's scope, and the shipper ships the record without its content
      # rather than wedging behind it.
      Agent.update(state, fn s -> %{s | append: :ok} end)
      {:ok, after_it} = Pipeline.capture(name, with_args("intact afterwards"))
      assert :ok = Pipeline.flush(name)

      missing_ref = Ref.bytes("moved aside")

      assert [{^missing_ref, {"urn:r5e:session:staged", _owner}}] =
               Agent.get(state, &Enum.uniq(&1.not_held_calls))

      assert {:ok, _} = Memory.fetch(mem, gone.ref)
      assert :error = Memory.get_blob(mem, missing_ref)
      assert {:ok, _} = Memory.fetch(mem, after_it.ref)
      assert {:ok, "intact afterwards"} = Memory.get_blob(mem, Ref.bytes("intact afterwards"))
    end
  end

  test "content in a file is hashed as a stream, checked, and shipped", ctx do
    body = :binary.copy("0123456789abcdef", 200_000)
    path = Path.join(ctx.dir, "spooled-body")
    File.write!(path, body)

    request =
      tool_call(%{
        attachments: [%{name: "args", path: path, sha256: :crypto.hash(:sha256, body)}]
      })
      |> put_in([:body, "size"], byte_size(body))

    assert {:ok, %{ref: ref}} = Pipeline.capture(ctx.pipeline, request)
    :ok = Pipeline.flush(ctx.pipeline)

    {:ok, entry} = Memory.fetch(ctx.store, ref)
    assert entry.evidence["body"]["contentRef"] == Ref.bytes(body)
    assert {:ok, ^body} = Memory.get_blob(ctx.store, Ref.bytes(body))

    File.write!(path, body)

    wrong =
      tool_call(%{attachments: [%{name: "args", path: path, sha256: :crypto.hash(:sha256, "x")}]})

    assert {:error, {:attachment, "args", :does_not_match_expected_hash}} =
             Pipeline.capture(ctx.pipeline, wrong)
  end

  test "a retried submission gets the same answer and no second record", ctx do
    request = tool_call(%{submission_id: "sub-1"})

    assert {:ok, first} = Pipeline.capture(ctx.pipeline, request)
    assert {:ok, ^first} = Pipeline.capture(ctx.pipeline, request)

    changed = put_in(request, [:body, "tool"], "other")

    assert {:error, :submission_reused_with_different_content} =
             Pipeline.capture(ctx.pipeline, changed)

    assert {:ok, %{seq: 2}} = Pipeline.capture(ctx.pipeline, tool_call(%{submission_id: "sub-2"}))
  end

  test "requests outside the profile, or that fail their definition, are refused", ctx do
    capture = &Pipeline.capture(ctx.pipeline, &1)

    assert {:error, :issuer_not_bound} =
             capture.(tool_call(%{actor: "spiffe://elsewhere.test/x"}))

    assert {:error, :kind_not_in_profile} =
             capture.(tool_call(%{kind_path: "acme.example/v1/Unknown"}))

    assert {:error, {:invalid_evidence, [{"/body.surprise", "unexpected_property"}]}} =
             capture.(put_in(tool_call(), [:body, "surprise"], 1))

    assert {:error, :policy_required} =
             capture.(update_in(tool_call(), [:body], &Map.delete(&1, "policy")))

    assert {:error, {:missing_attachment, "args"}} =
             capture.(Map.delete(tool_call(), :attachments))

    assert {:error, :recorder_only_kind} =
             capture.(tool_call(%{kind_path: @base <> "/EpochSeal"}))

    # A refused request takes no position in the stream.
    assert {:ok, %{seq: 1}} = capture.(tool_call())
  end

  test "sealed and exported, the records verify offline", ctx do
    receipts = for _ <- 1..4, do: elem(Pipeline.capture(ctx.pipeline, tool_call()), 1)
    control = "spiffe://example.test/workload/control"

    assert {:ok, [seal]} = Pipeline.seal_all(ctx.pipeline, control)
    assert {:ok, []} = Pipeline.seal_all(ctx.pipeline, control)

    {:ok, seal_entry} = Memory.fetch(ctx.store, seal.ref)
    assert %{"firstSeq" => 1, "lastSeq" => 4} = first_body = seal_entry.evidence["body"]
    refute Map.has_key?(first_body, "previousSeal")

    {:ok, _} = Pipeline.capture(ctx.pipeline, tool_call())
    assert {:ok, [second]} = Pipeline.seal_all(ctx.pipeline, control)
    {:ok, second_entry} = Memory.fetch(ctx.store, second.ref)
    assert %{"firstSeq" => 5, "lastSeq" => 5} = second_entry.evidence["body"]
    assert second_entry.evidence["body"]["previousSeal"] == seal.ref

    entries = for r <- receipts, do: elem(Memory.fetch(ctx.store, r.ref), 1)

    blob_refs = [
      Pipeline.profile_ref(ctx.pipeline),
      seal_entry.evidence["body"]["manifestRef"],
      Ref.bytes(@args)
    ]

    blobs = for ref <- blob_refs, do: {elem(Memory.get_blob(ctx.store, ref), 1), nil}

    {:ok, bundle} =
      Export.build(
        records: Enum.map(entries ++ [seal_entry], & &1.envelope),
        blobs: blobs,
        keys: [
          %{key_id: ctx.signer.key_id, algorithm: "ed25519", public_key: ctx.signer.public_key}
        ],
        seals: [seal.ref],
        omissions: [
          %{ref: Ref.bytes("permit(principal, action, resource);"), reason: "unavailable"}
        ]
      )

    report =
      Export.verify(bundle |> Jason.encode!() |> Jason.decode!(),
        trusted_profiles: [Pipeline.profile_ref(ctx.pipeline)]
      )

    assert report.summary.failed == 0
    assert Enum.any?(report.findings, &(&1.check == :epoch and &1.result == :ok))
    assert Enum.count(report.findings, &(&1.check == :signature and &1.result == :ok)) == 5
  end

  test "a shipper finishes a segment an earlier run left unshipped", %{
    dir: dir,
    signer: signer,
    profile: profile
  } do
    {:ok, store} = Memory.start_link()
    segments = Path.join(dir, "leftover")
    name = Module.concat(__MODULE__, "S#{System.unique_integer([:positive])}")
    start_supervised!(Signals.child_spec(name))

    # A log with nobody shipping it: records are durable and go no further.
    {:ok, log} = Log.start_link(dir: segments, signals: name, flush_interval_ms: 60_000)

    {:ok, %{ref: schema_ref}} = Recurse.Provenance.Definitions.fetch(@base <> "/Observation")

    evidence =
      Recurse.Provenance.Evidence.new(
        kind_path: @base <> "/Observation",
        schema_ref: schema_ref,
        profile_ref: Profile.ref(profile),
        issuer: signer.key_id,
        actor: @actor,
        stream: "urn:r5e:stream:test:gateway:9:abc",
        seq: 1,
        previous: nil,
        captured_at: ~U[2026-11-09 12:00:00Z],
        body: Body.observation(topic: "test")
      )

    {:ok, %{envelope: envelope, ref: ref}} = Envelope.sign(evidence, signer)

    Log.append(log, %{
      stream: evidence["stream"],
      seq: 1,
      ref: ref,
      kind_path: @base <> "/Observation",
      envelope: envelope,
      content: []
    })

    :ok = Log.flush(log)
    GenServer.stop(log)
    assert :error = Memory.fetch(store, ref)

    {:ok, shipper} =
      Shipper.start_link(
        dir: segments,
        content_dir: Path.join(dir, "c"),
        index: {Memory, store},
        signals: name
      )

    assert :ok = Shipper.sync(shipper)
    assert {:ok, %{seq: 1}} = Memory.fetch(store, ref)
  end

  @tag partitions: 1
  test "a stream whose log died is reported by the stream that replaces it", ctx do
    {:ok, %{stream: old, ref: durable}} = Pipeline.capture(ctx.pipeline, tool_call())
    :ok = Pipeline.flush(ctx.pipeline)

    [{log, _}] = Registry.lookup(Module.concat(ctx.pipeline, Names), {:log, 0})
    monitor = Process.monitor(log)
    Process.exit(log, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^log, :killed}

    new = await_new_stream(ctx.pipeline, old)
    :ok = Pipeline.flush(ctx.pipeline)

    assert {:ok, [%{evidence: evidence}]} = Memory.range(ctx.store, new, 1, 1)

    assert %{
             "kind" => "Observation",
             "body" => %{
               "topic" => "recorder.unclean-stop",
               "about" => ^durable,
               "details" => %{"stream" => ^old, "lastDurableSeq" => 1}
             }
           } = evidence

    # Reported once: the stream after that one opens with an ordinary record.
    after_restart = restart(ctx)
    {:ok, %{seq: 1, ref: first}} = Pipeline.capture(after_restart, tool_call())
    :ok = Pipeline.flush(after_restart)
    assert {:ok, %{evidence: %{"kind" => "ToolCall"}}} = Memory.fetch(ctx.store, first)
  end

  @tag partitions: 1
  test "a pipeline that is shut down in order leaves nothing to report", ctx do
    {:ok, _} = Pipeline.capture(ctx.pipeline, tool_call())

    # Not flushed by the test: an orderly stop flushes on its own.
    restarted = restart(ctx)
    {:ok, %{seq: 1, ref: first}} = Pipeline.capture(restarted, tool_call())
    :ok = Pipeline.flush(restarted)

    assert {:ok, %{evidence: %{"kind" => "ToolCall"}}} = Memory.fetch(ctx.store, first)
    assert [_ | _] = Path.wildcard(Path.join(ctx.dir, "segments/0/*.seg.closed"))
  end

  defp await_new_stream(pipeline, old, tries \\ 100) do
    case safe_streams(pipeline) do
      [stream] when stream != old -> stream
      _ when tries > 0 -> Process.sleep(10) && await_new_stream(pipeline, old, tries - 1)
    end
  end

  # The writer's name is briefly unregistered while its trio restarts.
  defp safe_streams(pipeline) do
    Pipeline.streams(pipeline)
  catch
    :exit, _ -> []
  end

  test "a torn final frame is ignored when a segment is read back" do
    entry = %{stream: "s", seq: 1, ref: "r", kind_path: "k", envelope: %{}, content: []}
    whole = IO.iodata_to_binary(Log.frame(entry))
    torn = binary_part(whole, 0, byte_size(whole) - 3)

    assert {[%{"seq" => 1}], size} = Log.decode(whole <> torn)
    assert size == byte_size(whole)
    assert {[], 0} = Log.decode(torn)
  end

  describe "accept/5: records another key issued, under that key's own profile" do
    defp start_profile(bootstrap) do
      {:ok, profile} =
        Profile.new(
          bindings: [
            %{
              stream_prefix: "urn:r5e:stream:test:start",
              actor_prefixes: ["urn:r5e:node:"],
              issuer_keys: [bootstrap.key_id],
              sealer_keys: []
            }
          ],
          failure_domain: "the node's own disk",
          deployment_policy_ref: Ref.bytes("bootstrap")
        )

      profile
    end

    defp start_record(bootstrap, profile, seq, previous, kind, body) do
      path = @base <> "/" <> kind

      Recurse.Provenance.Evidence.new(
        kind_path: path,
        schema_ref: elem(Recurse.Provenance.Definitions.fetch(path), 1).ref,
        profile_ref: Profile.ref(profile),
        issuer: bootstrap.key_id,
        actor: "urn:r5e:node:test",
        stream: "urn:r5e:stream:test:start",
        seq: seq,
        previous: previous,
        captured_at: ~U[2026-11-12 08:00:00Z],
        body: body
      )
    end

    defp wire(signer),
      do: %{"algorithm" => signer.algorithm, "bytes" => Base.encode64(signer.public_key)}

    test "a start record and the deployment record after it are recorded, sealed together, and a rival is refused",
         ctx do
      %{pipeline: pipeline, store: store} = ctx
      bootstrap = Key.generate("ed25519")
      root = Key.generate("ed25519")
      profile = start_profile(bootstrap)
      keys = Map.merge(keys_of(bootstrap), keys_of(root))

      started =
        start_record(bootstrap, profile, 1, nil, "ChainStarted", %{
          "deployment" => "test",
          "bootstrap" => bootstrap.key_id,
          "bootstrapKey" => wire(bootstrap),
          "publication" => Ref.evidence("the publication"),
          "publisher" => root.key_id,
          "definitions" => [%{"kind" => @base <> "/ToolCall", "definition" => Ref.bytes("d")}]
        })

      {:ok, first} = Envelope.sign(started, bootstrap)

      deployment = fn claimed_by ->
        evidence =
          start_record(bootstrap, profile, 2, first.ref, "Deployment", %{
            "accepts" => first.ref,
            "bootstrap" => bootstrap.key_id,
            "claimedBy" => claimed_by.key_id,
            "roots" => [%{"key" => claimed_by.key_id, "publicKey" => wire(claimed_by)}],
            "threshold" => 1
          })

        countersigned(evidence, bootstrap, claimed_by)
      end

      # The second record cannot go in before the first.
      assert {:error, :not_next_in_stream} =
               Pipeline.accept(pipeline, deployment.(root), keys, profile, "start")

      assert {:ok, %{seq: 1, stream: stream}} =
               Pipeline.accept(pipeline, first.envelope, keys, profile, "start")

      assert {:ok, %{seq: 2, ref: accepted}} =
               Pipeline.accept(pipeline, deployment.(root), keys, profile, "start")

      # Offered again: the same answer. A different record at that position: refused.
      assert {:ok, %{ref: ^accepted}} =
               Pipeline.accept(pipeline, deployment.(root), keys, profile, "start")

      thief = Key.generate("ed25519")

      assert {:error, :stream_fork_refused} =
               Pipeline.accept(
                 pipeline,
                 deployment.(thief),
                 Map.merge(keys, keys_of(thief)),
                 profile,
                 "start"
               )

      # Not somewhere it was not allowed, and not without every signature.
      {:ok, another} = Envelope.sign(put_in(started, ["body", "details"], %{"n" => 2}), bootstrap)

      assert {:error, :stream_not_admissible} =
               Pipeline.accept(pipeline, another.envelope, keys, profile, "authority:root:")

      assert {:error, _} =
               Pipeline.accept(pipeline, deployment.(root), keys_of(bootstrap), profile, "start")

      # Both positions are covered by one seal, and the issuer's profile and
      # keys are kept for an export to carry.
      assert {:ok, [_seal]} = Pipeline.seal_all(pipeline, @actor)
      assert {:ok, {_ref, 2}} = Memory.last_seal(store, stream)
      assert {:ok, []} = Pipeline.seal_all(pipeline, @actor)
      assert {:ok, _} = Memory.get_blob(store, Profile.ref(profile))
      assert {:ok, %{algorithm: "ed25519"}} = Memory.get_key(store, root.key_id)
    end
  end

  describe "admit/3: a record signed by two parties" do
    defp badge(signer, subject, profile, overrides \\ %{}) do
      Recurse.Provenance.Evidence.new(
        kind_path: @base <> "/Badge",
        schema_ref: elem(Recurse.Provenance.Definitions.fetch(@base <> "/Badge"), 1).ref,
        profile_ref: Profile.ref(profile),
        issuer: signer.key_id,
        actor: @actor,
        stream: "urn:r5e:stream:test:authority:badge:one",
        seq: 1,
        previous: nil,
        captured_at: ~U[2026-11-10 12:00:00Z],
        body: %{
          "subject" => subject.key_id,
          "subjectKey" => %{
            "algorithm" => subject.algorithm,
            "bytes" => Base.encode64(subject.public_key)
          },
          "holder" => "workload",
          "kinds" => [@base <> "/ToolCall"],
          "notBefore" => "2026-11-10T00:00:00Z",
          "notAfter" => "2026-11-11T00:00:00Z",
          "parent" => Ref.evidence("the endorsement above")
        }
      )
      |> Map.merge(overrides)
    end

    # Each party signs the same message on its own; whoever holds both
    # signatures puts the envelope together.
    defp countersigned(evidence, first, second) do
      {:ok, payload} = Recurse.Provenance.Evidence.encode(evidence)
      message = Envelope.message(payload)
      {:ok, theirs} = second.sign.(message)
      {:ok, ours} = first.sign.(message)
      Envelope.assemble(payload, [{first.key_id, ours}, {second.key_id, theirs}])
    end

    defp keys_of(signer),
      do: %{signer.key_id => %{algorithm: signer.algorithm, bytes: signer.public_key}}

    test "is recorded on a stream of its own, shipped, sealed, and verifies", ctx do
      %{pipeline: pipeline, store: store, signer: signer, profile: profile} = ctx
      subject = Key.generate("es256")
      envelope = countersigned(badge(signer, subject, profile), signer, subject)

      assert {:ok, %{ref: ref, stream: stream, seq: 1}} =
               Pipeline.admit(pipeline, envelope, keys_of(subject))

      assert {:ok, [_seal]} = Pipeline.seal_all(pipeline, @actor)
      assert {:ok, %{envelope: ^envelope}} = Memory.fetch(store, ref)
      assert {:ok, {_seal_ref, 1}} = Memory.last_seal(store, stream)

      # Sealed once: a second pass finds nothing left to seal.
      assert {:ok, []} = Pipeline.seal_all(pipeline, @actor)
    end

    test "offered again, answers the same and records nothing more", ctx do
      %{pipeline: pipeline, store: store, signer: signer, profile: profile} = ctx
      subject = Key.generate("ed25519")
      envelope = countersigned(badge(signer, subject, profile), signer, subject)

      assert {:ok, first} = Pipeline.admit(pipeline, envelope, keys_of(subject))
      # Before it has been shipped, and after.
      assert {:ok, ^first} = Pipeline.admit(pipeline, envelope, keys_of(subject))
      :ok = Pipeline.flush(pipeline)
      assert {:ok, ^first} = Pipeline.admit(pipeline, envelope, keys_of(subject))

      assert {:ok, [_one_seal]} = Pipeline.seal_all(pipeline, @actor)
      assert {:ok, ^first} = Pipeline.admit(pipeline, envelope, keys_of(subject))
      assert {:ok, []} = Pipeline.seal_all(pipeline, @actor)
      assert {:ok, [_only]} = Memory.range(store, first.stream, 1, 1)
    end

    test "admitted before a restart, is sealed after it", ctx do
      %{pipeline: pipeline, store: store, signer: signer, profile: profile} = ctx
      subject = Key.generate("ed25519")
      envelope = countersigned(badge(signer, subject, profile), signer, subject)

      assert {:ok, %{stream: stream}} = Pipeline.admit(pipeline, envelope, keys_of(subject))
      :ok = Pipeline.flush(pipeline)

      # The pipeline stops with the record shipped and unsealed, and a new
      # one starts over the same index with nothing in memory.
      :ok = stop_supervised(Pipeline)
      restart_pipeline(ctx)

      assert {:ok, nil} = Memory.last_seal(store, stream)
      assert {:ok, [_seal]} = Pipeline.seal_all(pipeline, @actor)
      assert {:ok, {_seal_ref, 1}} = Memory.last_seal(store, stream)
    end

    test "is refused unless this pipeline issued it and both signatures hold", ctx do
      %{pipeline: pipeline, signer: signer, profile: profile} = ctx
      subject = Key.generate("ed25519")
      other = Key.generate("ed25519")
      good = badge(signer, subject, profile)

      # The subject's key was not supplied.
      assert {:error, :missing_key} =
               Pipeline.admit(pipeline, countersigned(good, signer, subject))

      # Someone else in the first position.
      theirs = badge(other, subject, profile)

      assert {:error, :not_issued_here} =
               Pipeline.admit(
                 pipeline,
                 countersigned(theirs, other, subject),
                 Map.merge(keys_of(subject), keys_of(other))
               )

      # The second signer is not the subject the body names.
      assert {:error, [{"/body.subject", "signer_mismatch"}]} =
               Pipeline.admit(
                 pipeline,
                 countersigned(good, signer, other),
                 keys_of(other)
               )

      # Only one signature.
      {:ok, %{envelope: alone}} = Envelope.sign(good, signer)

      assert {:error, [{"/signatures", "signature_count_differs_from_definition"}]} =
               Pipeline.admit(pipeline, alone, keys_of(subject))

      # Not on an authority stream, or not first in it.
      elsewhere = Map.put(good, "stream", "urn:r5e:stream:test:gateway:0:abc")

      assert {:error, :stream_not_admissible} =
               Pipeline.admit(
                 pipeline,
                 countersigned(elsewhere, signer, subject),
                 keys_of(subject)
               )

      second = Map.merge(good, %{"seq" => 2, "previous" => Ref.evidence("x")})

      assert {:error, :not_first_in_stream} =
               Pipeline.admit(pipeline, countersigned(second, signer, subject), keys_of(subject))
    end
  end
end
