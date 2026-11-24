defmodule Recurse.Providers.Impls.PostgresEvidenceStoreTest do
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Provenance.{Body, Envelope, Export, Key, Pipeline, Profile, Ref}
  alias Recurse.Providers.Impls.FilesystemStorageProvider, as: Filesystem
  alias Recurse.Providers.Impls.LocalKeyService
  alias Recurse.Providers.Impls.PostgresEvidenceStore, as: Store
  alias Recurse.Providers.Repo

  @moduletag :tmp_dir

  @base "provenance.r5e.io/v2"
  @actor "spiffe://example.test/workload/gateway"
  @args ~s({"command":"ls"})

  setup %{tmp_dir: dir} = ctx do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    signer = Key.generate("es256")
    unique = System.unique_integer([:positive])
    prefix = "urn:r5e:stream:test#{unique}:"

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: prefix,
            actor_prefixes: ["spiffe://example.test/workload/"],
            issuer_keys: [signer.key_id],
            sealer_keys: [signer.key_id]
          }
        ],
        failure_domain: "local disk, then postgres (test)",
        deployment_policy_ref: Ref.bytes("deployment"),
        retention: Map.get(ctx, :retention)
      )

    start = fn index ->
      name = Module.concat(__MODULE__, "P#{System.unique_integer([:positive])}")

      start_supervised!(
        {Pipeline,
         name: name,
         dir: Path.join(dir, Atom.to_string(name)),
         stream_prefix: prefix,
         signer: signer,
         profile: profile,
         index: index,
         partitions: 2,
         flush_interval_ms: 20},
        id: name
      )

      name
    end

    %{signer: signer, profile: profile, start: start, dir: dir, prefix: prefix}
  end

  defp tool_call(overrides \\ %{}) do
    Map.merge(
      %{
        kind_path: @base <> "/ToolCall",
        actor: @actor,
        session: "urn:r5e:session:test:pg",
        attachments: [%{name: "args", bytes: @args}],
        body:
          Body.tool_call(
            tool: "shell",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: 16,
            policy:
              Body.policy_evaluation(
                policy_ref: Ref.bytes("policy"),
                outcome: "allow",
                input_refs: ["attachment:args"]
              )
          )
      },
      overrides
    )
  end

  test "captured records are shipped to Postgres in order, with their content", ctx do
    pipeline = ctx.start.({Store, Repo})

    receipts = for _ <- 1..3, do: elem(Pipeline.capture(pipeline, tool_call()), 1)
    :ok = Pipeline.flush(pipeline)

    [%{stream: stream} | _] = receipts
    assert {:ok, {3, last_ref}} = Store.head(Repo, stream)
    assert last_ref == List.last(receipts).ref

    assert {:ok, [%{seq: 1}, %{seq: 2, evidence: second}, %{seq: 3}]} =
             Store.range(Repo, stream, 1, 3)

    assert second["previous"] == hd(receipts).ref
    assert {:ok, @args} = Store.get_blob(Repo, Ref.bytes(@args))
  end

  test "a different payload at an occupied position is a conflict; a replayed batch changes nothing",
       ctx do
    pipeline = ctx.start.({Store, Repo})
    {:ok, %{ref: ref, stream: stream}} = Pipeline.capture(pipeline, tool_call())
    :ok = Pipeline.flush(pipeline)

    {:ok, entry} = Store.fetch(Repo, ref)
    assert :ok = Store.append(Repo, entry)
    assert :ok = Store.append_many(Repo, [entry, entry])
    assert {:ok, {1, ^ref}} = Store.head(Repo, stream)

    {:ok, opened} = Envelope.open(entry.envelope)
    rival = put_in(opened.evidence, ["body", "tool"], "other")
    {:ok, signed} = Envelope.sign(rival, ctx.signer)

    assert {:error, :conflict} =
             Store.append(Repo, %{
               entry
               | ref: signed.ref,
                 envelope: signed.envelope,
                 evidence: rival
             })
  end

  test "streams whose first record no seal covers are found by prefix, until sealed", ctx do
    pipeline = ctx.start.({Store, Repo})
    {:ok, %{stream: stream}} = Pipeline.capture(pipeline, tool_call())
    :ok = Pipeline.flush(pipeline)

    prefix = String.replace(stream, ~r/[^:]+$/, "")
    assert prefix != stream and String.starts_with?(stream, prefix)
    assert {:ok, [^stream]} = Store.unsealed_firsts(Repo, prefix)
    assert {:ok, [^stream]} = Store.unsealed_firsts(Repo, stream)
    assert {:ok, []} = Store.unsealed_firsts(Repo, stream <> "x")

    # A prefix is matched as written: these are not wildcards.
    assert {:ok, []} = Store.unsealed_firsts(Repo, String.replace(prefix, "test", "t%"))
    assert {:ok, []} = Store.unsealed_firsts(Repo, String.replace(prefix, "test", "tes_"))

    {:ok, _} = Pipeline.seal(pipeline, stream, "spiffe://example.test/workload/sealer")
    :ok = Pipeline.flush(pipeline)
    assert {:ok, []} = Store.unsealed_firsts(Repo, stream)
  end

  test "records are listed newest first, a page at a time, and narrowed by what is asked", ctx do
    {store, handle} = {Store, Repo}
    pipeline = ctx.start.({Store, Repo})
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

    asked = %{stream_prefix: ctx.prefix, limit: 100}
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

    assert {:ok, []} = store.list(handle, %{asked | stream_prefix: ctx.prefix <> "elsewhere:"})
  end

  test "records and content rows cannot be changed or removed", ctx do
    pipeline = ctx.start.({Store, Repo})
    {:ok, %{ref: ref}} = Pipeline.capture(pipeline, tool_call())
    :ok = Pipeline.flush(pipeline)

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.query!("UPDATE evidence_records SET actor = 'x' WHERE ref = $1", [ref])
    end

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.query!("DELETE FROM evidence_blobs")
    end
  end

  defmodule NamedByCaller do
    @moduledoc """
    A storage provider that, like the S3 one, names what `put_payload/3`
    writes after the caller, and offers `put_content/3` to name by the
    bytes instead. It keeps what it is given in an Agent.
    """

    def put_payload(agent, bytes, _ctx) do
      Agent.update(agent, &Map.put(&1, "mem://the-caller", bytes))
      {:ok, %{uri: "mem://the-caller", hash: :crypto.hash(:sha256, bytes)}}
    end

    def put_content(agent, bytes, _ctx) do
      hash = :crypto.hash(:sha256, bytes)
      uri = "mem://" <> Base.encode16(hash, case: :lower)
      Agent.update(agent, &Map.put(&1, uri, bytes))
      {:ok, %{uri: uri, hash: hash}}
    end

    def get_payload(agent, uri, _ctx) do
      case Agent.get(agent, &Map.fetch(&1, uri)) do
        {:ok, bytes} -> {:ok, bytes}
        :error -> {:error, :permanent, :not_found}
      end
    end
  end

  test "content goes to a provider under a name of its own, so one piece does not replace another",
       ctx do
    {:ok, agent} = Agent.start_link(fn -> %{} end)
    handle = %{repo: Repo, content: {NamedByCaller, agent, nil}}
    pipeline = ctx.start.({Store, handle})

    for text <- ["the first piece", "the second piece"] do
      {:ok, _} =
        Pipeline.capture(pipeline, tool_call(%{attachments: [%{name: "args", bytes: text}]}))
    end

    :ok = Pipeline.flush(pipeline)

    assert {:ok, "the first piece"} = Store.get_blob(handle, Ref.bytes("the first piece"))
    assert {:ok, "the second piece"} = Store.get_blob(handle, Ref.bytes("the second piece"))
    refute Agent.get(agent, &Map.has_key?(&1, "mem://the-caller"))
  end

  test "with a storage provider, Postgres holds references and the provider holds the bytes",
       ctx do
    root = Path.join(ctx.dir, "cas")
    {:ok, storage} = Filesystem.init(%{root: root})
    handle = %{repo: Repo, content: {Filesystem, storage, nil}}
    pipeline = ctx.start.({Store, handle})

    big = :binary.copy("x", 3_000_000)
    path = Path.join(ctx.dir, "spooled")
    File.write!(path, big)

    {:ok, %{ref: record}} =
      Pipeline.capture(pipeline, tool_call(%{attachments: [%{name: "args", path: path}]}))

    :ok = Pipeline.flush(pipeline)

    ref = Ref.bytes(big)
    assert {:ok, %{evidence: %{"body" => %{"contentRef" => ^ref}}}} = Store.fetch(handle, record)

    # The row carries where the bytes are and how many, not the bytes.
    assert %{rows: [[uri, nil, 3_000_000]]} =
             Repo.query!("SELECT uri, bytes, size FROM evidence_blobs WHERE ref = $1", [ref])

    assert String.starts_with?(uri, "file://" <> root)
    assert {:ok, ^big} = Store.get_blob(handle, ref)

    # The profile and definitions went to storage as well.
    assert %{rows: [[nil]]} =
             Repo.query!("SELECT bytes FROM evidence_blobs WHERE ref = $1", [
               Profile.ref(ctx.profile)
             ])
  end

  describe "with a key service" do
    # These records are made under a profile that lets content be
    # disposed of as soon as it is recorded, so disposal can be shown.
    @describetag retention: {:keep_for_seconds, 0}

    defp disposal(n \\ 1),
      do: %{ref: Ref.evidence("disposal #{n}"), at: DateTime.add(DateTime.utc_now(), 5, :second)}

    setup ctx do
      root = Path.join(ctx.dir, "cas")
      {:ok, storage} = Filesystem.init(%{root: root})
      key_file = Path.join(ctx.dir, "content.key")
      :ok = LocalKeyService.generate(key_file)
      {:ok, keys} = LocalKeyService.open(key_file)
      handle = %{repo: Repo, content: {Filesystem, storage, nil}, keys: {LocalKeyService, keys}}
      %{handle: handle, root: root, pipeline: ctx.start.({Store, handle})}
    end

    defp everything_stored(root) do
      root |> Path.join("**") |> Path.wildcard() |> Enum.filter(&File.regular?/1)
    end

    test "content is unreadable where it is stored, reads back through the store, and exports whole",
         %{handle: handle, root: root, pipeline: pipeline} = ctx do
      secret = ~s({"command":"cat /home/dana/notes-about-the-merger.txt"})
      session = "urn:r5e:session:test:enc-#{System.unique_integer([:positive])}"

      {:ok, %{stream: stream}} =
        Pipeline.capture(
          pipeline,
          tool_call(%{session: session, attachments: [%{name: "args", bytes: secret}]})
        )

      {:ok, _} = Pipeline.seal(pipeline, stream, @actor)
      :ok = Pipeline.flush(pipeline)
      ref = Ref.bytes(secret)

      # One encrypted copy with the true size, and this session's lock on it.
      assert %{rows: [[copy, uri, nil, size]]} =
               Repo.query!("SELECT copy, uri, bytes, size FROM evidence_blobs WHERE ref = $1", [
                 ref
               ])

      assert copy != ""
      assert size == byte_size(secret)
      assert is_binary(uri)

      assert %{rows: [[^session, ^copy]]} =
               Repo.query!("SELECT scope, copy FROM evidence_content_locks WHERE ref = $1", [ref])

      for path <- everything_stored(root) do
        refute File.read!(path) =~ "merger"
      end

      assert %{rows: [[wrapped]]} =
               Repo.query!("SELECT wrapped FROM evidence_content_keys WHERE scope = $1", [session])

      assert byte_size(wrapped) == 60

      # The profile, the definitions and the seal's manifest are structure and are not encrypted.
      assert %{rows: [[""]]} =
               Repo.query!("SELECT copy FROM evidence_blobs WHERE ref = $1", [
                 Profile.ref(ctx.profile)
               ])

      assert {:ok, ^secret} = Store.get_content(handle, ref, session)
      assert :held == Store.content_state(handle, ref)

      # Not through another session, and not as if it were structure.
      assert :error = Store.get_content(handle, ref, "urn:r5e:session:someone-else")
      assert :error = Store.get_blob(handle, ref)

      {:ok, bundle} = Recurse.Provenance.Exporter.session({Store, handle}, session)
      report = Export.verify(bundle, trusted_profiles: [Profile.ref(ctx.profile)])
      assert [] == Enum.filter(report.findings, &(&1.result == :failed))
      assert Enum.any?(bundle["blobs"], &(&1["ref"] == ref))

      # Without the key service, the same database and storage give nothing.
      assert :error = Store.get_content(Map.delete(handle, :keys), ref, session)
    end

    test "destroying a session's key removes that session's way in; content goes when no session has one",
         %{handle: handle, pipeline: pipeline} do
      shared = ~s({"command":"the same command in two sessions"})

      [one, two] =
        for n <- 1..2, do: "urn:r5e:session:test:erase-#{n}-#{System.unique_integer([:positive])}"

      for session <- [one, two] do
        {:ok, _} =
          Pipeline.capture(
            pipeline,
            tool_call(%{session: session, attachments: [%{name: "args", bytes: shared}]})
          )

        :ok = Pipeline.flush(pipeline)
      end

      ref = Ref.bytes(shared)

      # Stored once; each session has its own lock on that one copy.
      assert %{rows: [[_one_copy]]} =
               Repo.query!("SELECT uri FROM evidence_blobs WHERE ref = $1", [ref])

      assert %{rows: [[2]]} =
               Repo.query!("SELECT count(*) FROM evidence_content_locks WHERE ref = $1", [ref])

      assert :ok = Store.dispose_content(handle, one, disposal(42))
      assert :already = Store.dispose_content(handle, one, disposal(1))
      assert :none = Store.dispose_content(handle, "urn:r5e:session:never", disposal(1))

      # Still readable by the other session, and no longer by this one,
      # even though the same bytes are still held.
      assert {:ok, ^shared} = Store.get_content(handle, ref, two)
      assert :error = Store.get_content(handle, ref, one)
      assert :held == Store.content_state(handle, ref)

      {:ok, disposed} = Recurse.Provenance.Exporter.session({Store, handle}, one)
      refute Enum.any?(disposed["blobs"], &(&1["ref"] == ref))
      assert Enum.any?(disposed["omissions"], &(&1["ref"] == ref))

      {:ok, live} = Recurse.Provenance.Exporter.session({Store, handle}, two)
      assert Enum.any?(live["blobs"], &(&1["ref"] == ref))

      assert :ok = Store.dispose_content(handle, two, disposal(43))
      assert :error = Store.get_content(handle, ref, two)
      assert :erased == Store.content_state(handle, ref)
      assert :absent == Store.content_state(handle, Ref.bytes("never recorded"))

      # The key's row remains and says when and why; the record is untouched.
      by = Ref.evidence("disposal 42")

      assert %{rows: [[nil, ^by]]} =
               Repo.query!(
                 "SELECT wrapped, destroyed_reason FROM evidence_content_keys WHERE scope = $1",
                 [one]
               )

      {:ok, bundle} = Recurse.Provenance.Exporter.session({Store, handle}, one)
      assert [%{"ref" => _, "envelope" => _} | _] = bundle["records"]
      assert Enum.any?(bundle["omissions"], &(&1["ref"] == ref))

      # What the session records afterwards is kept, under a new key.
      assert :ok = Store.put_content(handle, Ref.bytes("x"), "x", one)
      assert {:ok, "x"} = Store.get_content(handle, Ref.bytes("x"), one)
    end

    test "a session that refers to content already shipped for another gets its own lock, and content recorded again after disposal is stored again",
         %{handle: handle} do
      content = "held for the first session"
      ref = Ref.bytes(content)
      assert :ok = Store.put_content(handle, ref, content, "urn:r5e:session:first")
      assert :ok = Store.put_content(handle, ref, :held, "urn:r5e:session:second")
      assert :ok = Store.put_content(handle, ref, :held, "urn:r5e:session:second")

      assert :ok = Store.dispose_content(handle, "urn:r5e:session:first", disposal(1))
      assert {:ok, ^content} = Store.get_content(handle, ref, "urn:r5e:session:second")

      assert {:error, :not_held} =
               Store.put_content(handle, Ref.bytes("gone"), :held, "urn:r5e:session:second")

      # Every way in is destroyed; the same content arrives again in a third
      # session and is readable again, as a second stored copy.
      assert :ok = Store.dispose_content(handle, "urn:r5e:session:second", disposal(2))
      assert :error = Store.get_content(handle, ref, "urn:r5e:session:second")
      assert {:error, :not_held} = Store.put_content(handle, ref, :held, "urn:r5e:session:third")
      assert :ok = Store.put_content(handle, ref, content, "urn:r5e:session:third")
      assert {:ok, ^content} = Store.get_content(handle, ref, "urn:r5e:session:third")

      assert %{rows: [[2]]} =
               Repo.query!("SELECT count(*) FROM evidence_blobs WHERE ref = $1", [ref])
    end

    defp recorded(pipeline, session, text) do
      {:ok, _} =
        Pipeline.capture(
          pipeline,
          tool_call(%{session: session, attachments: [%{name: "args", bytes: text}]})
        )

      :ok = Pipeline.flush(pipeline)
      Ref.bytes(text)
    end

    test "a session that records again after its content was disposed of keeps what arrives, under a new key",
         %{handle: handle, pipeline: pipeline} do
      session = "urn:r5e:session:test:resumed"
      before = recorded(pipeline, session, "recorded before the disposal")
      assert :ok = Store.dispose_content(handle, session, disposal(1))
      assert :error = Store.get_content(handle, before, session)

      # The late record ships like any other, and nothing waits behind it.
      later = recorded(pipeline, session, "recorded after the disposal")
      assert {:ok, "recorded after the disposal"} = Store.get_content(handle, later, session)
      assert :error = Store.get_content(handle, before, session)

      # A hold on the session reaches what arrived later, and a second
      # disposal destroys the later key as well.
      hold = Ref.evidence("a hold after the fact")

      assert {:ok, %{held: 1, lost: [^before]}} =
               Store.hold_content(handle, hold, {:scope, session})

      assert :ok = Store.dispose_content(handle, session, disposal(2))
      assert :error = Store.get_content(handle, later, session)
      assert {:ok, _} = Store.get_content(handle, later, "urn:r5e:hold:" <> hold)
      assert :already = Store.dispose_content(handle, session, disposal(3))
    end

    test "a key service that cannot be reached is an outage, never content lost",
         %{dir: dir, start: start} do
      alias Recurse.Providers.Impls.FakeKeyService

      {:ok, keys} = FakeKeyService.start_link()
      {:ok, storage} = Filesystem.init(%{root: Path.join(dir, "cas-fake")})
      handle = %{repo: Repo, content: {Filesystem, storage, nil}, keys: {FakeKeyService, keys}}
      pipeline = start.({Store, handle})

      session = "urn:r5e:session:test:outage-#{System.unique_integer([:positive])}"
      ref = recorded(pipeline, session, "recorded while the key service was up")
      assert {:ok, _} = Store.get_content(handle, ref, session)

      # Every read of content asked the key service, which is what lets a
      # customer see each read in the key service's own log.
      assert Enum.any?(FakeKeyService.audit_log(keys), &match?({:unwrap, _, _, :ok}, &1))

      FakeKeyService.set_available(keys, false)
      hold = Ref.evidence("a hold placed during an outage")

      # The content cannot be read, and the answer says it is the key
      # service that did not answer, not that the content is gone. A hold
      # is refused whole, not recorded as holding nothing.
      assert {:error, :key_service_unavailable} = Store.get_content(handle, ref, session)

      assert {:error, {:key_service_unavailable, _}} =
               Store.hold_content(handle, hold, {:scope, session})

      assert :held == Store.content_state(handle, ref)

      # Nor is content said to be not held, stored a second time, or taken
      # without its hold's lock, while the question cannot be asked.
      other = "urn:r5e:session:test:outage-other-#{System.unique_integer([:positive])}"

      assert {:error, {:key_service_unavailable, _}} =
               Store.put_content(handle, ref, :held, other)

      assert {:error, {:key_service_unavailable, _}} =
               Store.put_content(handle, ref, "recorded while the key service was up", other)

      assert %{rows: [[1]]} =
               Repo.query!("SELECT count(*) FROM evidence_blobs WHERE ref = $1", [ref])

      FakeKeyService.set_available(keys, true)
      assert {:ok, %{held: 1, lost: []}} = Store.hold_content(handle, hold, {:scope, session})

      # The customer retires the key version everything so far was locked
      # under. What was written is unreadable. The session goes on
      # recording under a new key, and what it records then reads back.
      :ok = FakeKeyService.rotate(keys)
      :ok = FakeKeyService.set_min_decryption_version(keys, 2)
      assert :error = Store.get_content(handle, ref, session)
      later = recorded(pipeline, session, "recorded after the old version was retired")

      assert {:ok, "recorded after the old version was retired"} =
               Store.get_content(handle, later, session)

      FakeKeyService.set_min_decryption_version(keys, 1)

      assert {:ok, "recorded while the key service was up"} =
               Store.get_content(handle, ref, session)
    end

    @tag retention: {:keep_for_seconds, 3600}
    test "content is not disposed of before the period its own profile gives has run",
         %{handle: handle, pipeline: pipeline} do
      session = "urn:r5e:session:test:keep-#{System.unique_integer([:positive])}"
      ref = recorded(pipeline, session, "kept for an hour")
      now = DateTime.utc_now()

      assert {:error, {:kept_until, _record}} =
               Store.dispose_content(handle, session, %{ref: Ref.evidence("d"), at: now})

      assert {:ok, "kept for an hour"} = Store.get_content(handle, ref, session)

      # A disposal made after the hour is allowed.
      later = DateTime.add(now, 3700, :second)
      assert :ok = Store.dispose_content(handle, session, %{ref: Ref.evidence("d"), at: later})
      assert :error = Store.get_content(handle, ref, session)
    end

    @tag retention: nil
    test "under a profile that says nothing about retention, content is never disposed of",
         %{handle: handle, pipeline: pipeline} do
      session = "urn:r5e:session:test:never-#{System.unique_integer([:positive])}"
      ref = recorded(pipeline, session, "kept for good")
      far = DateTime.add(DateTime.utc_now(), 86_400 * 365 * 50, :second)

      assert {:error, {:never_disposed_of, _record}} =
               Store.dispose_content(handle, session, %{ref: Ref.evidence("d"), at: far})

      assert {:ok, "kept for good"} = Store.get_content(handle, ref, session)
    end

    test "content under a hold survives its session's disposal, until the hold is released",
         %{handle: handle, pipeline: pipeline} do
      session = "urn:r5e:session:test:held-#{System.unique_integer([:positive])}"
      hold = Ref.evidence("hold #{System.unique_integer([:positive])}")
      before = recorded(pipeline, session, "recorded before the hold")
      assert {:ok, %{held: 1, lost: []}} = Store.hold_content(handle, hold, {:scope, session})

      # What is recorded under the scope afterwards is held as it arrives.
      afterwards = recorded(pipeline, session, "recorded after the hold")

      assert :ok = Store.dispose_content(handle, session, disposal())

      # The session can no longer read it; someone reading under the hold can.
      for {ref, text} <- [
            {before, "recorded before the hold"},
            {afterwards, "recorded after the hold"}
          ] do
        assert :error = Store.get_content(handle, ref, session)
        assert {:ok, ^text} = Store.get_content(handle, ref, "urn:r5e:hold:" <> hold)
        assert :held == Store.content_state(handle, ref)
      end

      # A hold is released, never disposed of.
      assert {:error, :a_hold_is_released_not_disposed_of} =
               Store.dispose_content(handle, "urn:r5e:hold:" <> hold, disposal())

      assert :ok = Store.release_hold(handle, hold, Ref.evidence("release"))
      assert :already = Store.release_hold(handle, hold, Ref.evidence("release"))
      assert :error = Store.get_content(handle, before, "urn:r5e:hold:" <> hold)
      assert :erased == Store.content_state(handle, before)
    end

    test "a hold on named content holds only that, and says what it could not hold",
         %{handle: handle, pipeline: pipeline} do
      session = "urn:r5e:session:test:named-#{System.unique_integer([:positive])}"
      wanted = recorded(pipeline, session, "the one that matters")
      other = recorded(pipeline, session, "the one that does not")
      hold = Ref.evidence("hold #{System.unique_integer([:positive])}")
      gone = Ref.bytes("never recorded")

      assert {:ok, %{held: 1, lost: [^gone]}} =
               Store.hold_content(handle, hold, {:content, [wanted, gone]})

      assert :ok = Store.dispose_content(handle, session, disposal())

      assert {:ok, "the one that matters"} =
               Store.get_content(handle, wanted, "urn:r5e:hold:" <> hold)

      assert :erased == Store.content_state(handle, other)
    end
  end

  test "sealed and exported from Postgres, the records verify offline", ctx do
    pipeline = ctx.start.({Store, Repo})

    receipts = for _ <- 1..3, do: elem(Pipeline.capture(pipeline, tool_call()), 1)
    {:ok, [seal]} = Pipeline.seal_all(pipeline, "spiffe://example.test/workload/control")

    stream = hd(receipts).stream
    assert {:ok, {seal_ref, 3}} = Store.last_seal(Repo, stream)
    assert seal_ref == seal.ref

    entries = for r <- receipts ++ [seal], do: elem(Store.fetch(Repo, r.ref), 1)
    seal_entry = List.last(entries)

    blobs =
      for ref <- [
            Profile.ref(ctx.profile),
            seal_entry.evidence["body"]["manifestRef"],
            Ref.bytes(@args)
          ],
          do: {elem(Store.get_blob(Repo, ref), 1), nil}

    {:ok, bundle} =
      Export.build(
        records: Enum.map(entries, & &1.envelope),
        blobs: blobs,
        keys: [
          %{key_id: ctx.signer.key_id, algorithm: "es256", public_key: ctx.signer.public_key}
        ],
        seals: [seal.ref]
      )

    report = Export.verify(bundle, trusted_profiles: [Profile.ref(ctx.profile)])
    assert report.summary.failed == 0
    assert Enum.any?(report.findings, &(&1.check == :epoch and &1.result == :ok))
    assert Enum.count(report.findings, &(&1.check == :signature and &1.result == :ok)) == 4
  end

  test "by_session_and_kinds scopes queries to one session or stream without scanning other sessions",
       ctx do
    deployment = "scoped-#{System.unique_integer([:positive])}"
    prefix = "urn:r5e:stream:#{deployment}:"
    stream = prefix <> "endpoint:det"
    target_session = "urn:r5e:session:tenant:abc1234567890def.s1"
    other_session = "urn:r5e:session:tenant:abc1234567890def.s2"
    flag_kind = "education.r5e.io/v1/SafeguardingFlag"
    other_kind = "provenance.r5e.io/v2/ToolCall"

    append_record = fn seq, prev, kind_path, env_session, body ->
      evidence =
        Recurse.Provenance.Evidence.new(
          kind_path: kind_path,
          schema_ref: Ref.bytes("schema:" <> kind_path),
          profile_ref: Profile.ref(ctx.profile),
          issuer: ctx.signer.key_id,
          actor: "urn:r5e:workload:detector",
          session: env_session,
          stream: stream,
          seq: seq,
          previous: prev,
          captured_at: DateTime.utc_now(),
          body: body
        )

      {:ok, signed} = Recurse.Provenance.Envelope.sign(evidence, ctx.signer)

      :ok =
        Store.append(Repo, %{
          ref: signed.ref,
          stream: stream,
          seq: seq,
          kind_path: kind_path,
          envelope: signed.envelope,
          evidence: evidence
        })

      signed.ref
    end

    # 1. Matching envelope session + matching kind -> included
    ref1 = append_record.(1, nil, flag_kind, target_session, %{"session" => target_session})
    # 2. Matching envelope session + non-matching kind -> excluded
    ref2 = append_record.(2, ref1, other_kind, target_session, %{"tool" => "echo"})
    # 3. Other envelope session + matching kind -> excluded
    ref3 = append_record.(3, ref2, flag_kind, other_session, %{"session" => other_session})
    # 4. Sessionless record whose body.session matches target_session + matching kind -> included
    ref4 = append_record.(4, ref3, flag_kind, nil, %{"session" => target_session})
    # 5. Sessionless record whose body.session is other_session + matching kind -> excluded
    _ref5 = append_record.(5, ref4, flag_kind, nil, %{"session" => other_session})

    assert {:ok, entries} = Store.by_session_and_kinds(Repo, target_session, [flag_kind], prefix)
    assert Enum.map(entries, & &1.ref) == [ref1, ref4]

    assert {:ok, []} = Store.by_session_and_kinds(Repo, target_session, [], prefix)

    # Stream scope matches only sessionless records on that stream with matching kind
    assert {:ok, stream_entries} =
             Store.by_session_and_kinds(Repo, "stream:" <> stream, [flag_kind], prefix)

    assert length(stream_entries) == 2
    assert ref4 in Enum.map(stream_entries, & &1.ref)
  end

  test "session_anchor/3 returns the earliest record signed by the given issuer with LIMIT 1",
       ctx do
    deployment = "anchor-#{System.unique_integer([:positive])}"
    gw_stream = "urn:r5e:stream:#{deployment}:sessions"
    wk_stream = "urn:r5e:stream:#{deployment}:workload"
    session = "urn:r5e:session:tenant:abc1234567890def.anchor1"
    workload_signer = Key.generate("es256")
    t0 = ~U[2026-11-24 00:00:01.000000Z]
    t1 = ~U[2026-11-24 00:00:02.000000Z]
    t2 = ~U[2026-11-24 00:00:03.000000Z]

    put_row = fn signer, stream, seq, prev, captured_at ->
      evidence =
        Recurse.Provenance.Evidence.new(
          kind_path: "provenance.r5e.io/v2/ToolCall",
          schema_ref: Ref.bytes("schema:ToolCall"),
          profile_ref: Profile.ref(ctx.profile),
          issuer: signer.key_id,
          actor: "urn:r5e:principal:tenant:alice",
          session: session,
          stream: stream,
          seq: seq,
          previous: prev,
          captured_at: captured_at,
          body: %{"tool" => "echo"}
        )

      {:ok, signed} = Recurse.Provenance.Envelope.sign(evidence, signer)

      :ok =
        Store.append(Repo, %{
          ref: signed.ref,
          stream: stream,
          seq: seq,
          kind_path: "provenance.r5e.io/v2/ToolCall",
          envelope: signed.envelope,
          evidence: evidence
        })

      signed.ref
    end

    # Earlier workload-signed record must be skipped for gateway issuer
    _wk_ref = put_row.(workload_signer, wk_stream, 1, nil, t0)
    # Earliest gateway-signed record is the anchor
    gw_anchor = put_row.(ctx.signer, gw_stream, 1, nil, t1)
    # Later gateway-signed record must not win over gw_anchor
    _gw_later = put_row.(ctx.signer, gw_stream, 2, gw_anchor, t2)

    assert {:ok, %{ref: ^gw_anchor}} = Store.session_anchor(Repo, session, ctx.signer.key_id)
    assert :error = Store.session_anchor(Repo, session, "key:es256:nonexistent")

    assert :error =
             Store.session_anchor(Repo, "urn:r5e:session:tenant:missing", ctx.signer.key_id)
  end
end
