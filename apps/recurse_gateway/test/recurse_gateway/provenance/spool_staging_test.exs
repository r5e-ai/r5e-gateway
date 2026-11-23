defmodule Recurse.Gateway.Provenance.SpoolStagingTest do
  @moduledoc """
  Content waiting on the gateway's own disk is encrypted end to end: a
  streamed body, the pipeline's content directory, a restart, the key
  service down at start, files that fail their check, retiring keys, and
  files no record waits for. Everything runs through the real
  `PostgresEvidenceStore`.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.Provenance.{Call, Runtime, SessionName, Spool, SpoolKeys, SpoolStaging}
  alias Recurse.Provenance.{Key, Ref}
  alias Recurse.Providers.Impls.{FakeKeyService, PostgresEvidenceStore}
  alias Recurse.Providers.Repo

  @canary "STAGE_DISK_CANARY_9c41e0"
  @actor "urn:r5e:principal:01TENANT:alice%40example.test"

  setup %{tmp_dir: tmp_dir} do
    owner = Sandbox.start_owner!(Repo, shared: true)

    on_exit(fn -> Sandbox.stop_owner(owner) end)

    {:ok, fake} = FakeKeyService.start_link()
    handle = %{repo: Repo, keys: {FakeKeyService, fake}}

    on_exit(fn -> :persistent_term.erase({Runtime, :info}) end)

    %{
      fake: fake,
      handle: handle,
      dir: Path.join(tmp_dir, "evidence"),
      signer: Key.generate("es256"),
      deployment: "spool-#{System.unique_integer([:positive])}"
    }
  end

  defp start_runtime(ctx, spool_opts \\ []) do
    start_supervised!(
      {Runtime,
       deployment: ctx.deployment,
       signer: ctx.signer,
       dir: ctx.dir,
       store: {PostgresEvidenceStore, ctx.handle},
       partitions: 2,
       flush_interval_ms: 20,
       spool_opts: [retry_ms: 50, sweep_ms: 0, gc_ms: 0] ++ spool_opts},
      id: Runtime
    )

    # Wait for the one-shot startup retention reconciler task to complete its
    # initial Repo query before returning so a subsequent `stop_runtime/0`
    # never kills a sandbox borrower mid-query and tears down shared ownership.
    await_reconciler()

    Runtime.info()
  end

  defp stop_runtime do
    await_reconciler()
    :ok = stop_supervised(Runtime)
    :persistent_term.erase({Runtime, :info})
  end

  defp await_reconciler do
    case Process.whereis(Runtime) do
      nil ->
        :ok

      pid ->
        for {:reconcile_retention, child, _, _} <- Supervisor.which_children(pid),
            is_pid(child) do
          ref = Process.monitor(child)

          receive do
            {:DOWN, ^ref, :process, ^child, _} -> :ok
          after
            5_000 -> flunk("retention reconciler did not finish within 5s")
          end
        end

        :ok
    end
  end

  defp spooled(text, piece \\ 4096) do
    capture = PayloadCapture.init(spool?: true)
    assert {:sealed, _, _} = capture.spool

    text
    |> chunks(piece)
    |> Enum.reduce(capture, &PayloadCapture.append(&2, &1))
    |> PayloadCapture.result()
  end

  defp chunks(<<>>, _n), do: []
  defp chunks(bin, n) when byte_size(bin) <= n, do: [bin]

  defp chunks(bin, n) do
    <<piece::binary-size(n), rest::binary>> = bin
    [piece | chunks(rest, n)]
  end

  defp body(bytes),
    do: binary_part(:binary.copy(@canary <> " lorem ipsum ", div(bytes, 30) + 1), 0, bytes)

  defp call_state(request, response, overrides \\ %{}) do
    Map.merge(
      %{
        tenant_id: "01TENANT",
        principal_id: "alice@example.test",
        principal_kind: "obo_human",
        principal_source: :jwt,
        session_id: "session-1",
        client_session_id: "client-session-1",
        started_at: ~U[2026-11-09 12:00:00.000000Z],
        completed_at: ~U[2026-11-09 12:00:01.500000Z],
        model: "claude-haiku-4-5",
        provider: "anthropic",
        upstream_host: "api.anthropic.com",
        transport: :https_sse,
        api_format: :anthropic_messages,
        request_path: "/v1/messages",
        prompt_hash: :crypto.hash(:sha256, request),
        response_hash: :crypto.hash(:sha256, response),
        request_payload: spooled(request),
        response_payload: spooled(response),
        prompt_token_count: 100,
        completion_token_count: 20,
        reasoning_token_count: nil,
        cedar_bundle_hash: nil,
        policy_bundle: nil,
        upstream_status_code: 200,
        error_kind: nil,
        intents: [],
        latency_ms: 1500,
        added_latency_ms: 12,
        correlation_id: nil,
        parser_failed?: false
      },
      overrides
    )
  end

  defp session(id \\ "client-session-1"), do: SessionName.for("01TENANT", @actor, id)

  defp stored(handle, bytes, scope \\ session()),
    do: PostgresEvidenceStore.get_content(handle, Ref.bytes(bytes), scope)

  defp files(dir) do
    for path <- Path.wildcard(Path.join(dir, "**/*"), match_dot: true),
        File.regular?(path),
        do: path
  end

  defp plaintext_anywhere?(dir),
    do: Enum.any?(files(dir), &(File.read!(&1) =~ @canary))

  defp content_files(dir), do: files(Path.join(dir, "content"))

  defp record_count(deployment) do
    prefix = "urn:r5e:stream:#{deployment}:gateway:%"
    Repo.one(from(r in "evidence_records", where: like(r.stream, ^prefix), select: count()))
  end

  test "a streamed call's bodies are never on disk in the clear, and ship once the store can take them",
       ctx do
    start_runtime(ctx)
    request = body(350_000)
    response = body(120_000) <> "response"

    # The store cannot encrypt for now, so the content waits.
    FakeKeyService.set_available(ctx.fake, false)
    assert {:ok, _ref} = Call.record(call_state(request, response))
    assert {:error, :not_shipped} = Runtime.flush()

    waiting = content_files(ctx.dir)
    assert length(waiting) == 2
    assert Enum.all?(waiting, &match?({:ok, _}, Spool.epoch_of(&1)))
    assert Enum.all?(waiting, &(File.stat!(&1).mode |> Bitwise.band(0o777) == 0o600))
    refute plaintext_anywhere?(ctx.dir)
    assert File.ls!(Path.join(ctx.dir, "spool")) == []

    FakeKeyService.set_available(ctx.fake, true)
    assert :ok = Runtime.flush()
    assert {:ok, ^request} = stored(ctx.handle, request)
    assert {:ok, ^response} = stored(ctx.handle, response)
    assert content_files(ctx.dir) == []
  end

  test "the record states the plain size of an encrypted spooled body", ctx do
    start_runtime(ctx)
    request = body(200_001)
    sha = :crypto.hash(:sha256, request)
    {:sealed_file, path, ^sha, 200_001} = spooled(request)
    assert {:ok, 200_001} = SpoolStaging.plain_size(path)
    assert File.stat!(path).size > 200_001
  end

  test "spooled bytes that do not match the hash taken on the wire are recorded as not held",
       ctx do
    info = start_runtime(ctx)
    request = body(80_000)
    state = call_state(request, "r", %{prompt_hash: :crypto.hash(:sha256, "what the wire saw")})
    {:sealed_file, spool_path, _, _} = state.request_payload

    assert {:ok, call_ref} = Call.record(state)
    assert :ok = Runtime.flush()
    refute File.exists?(spool_path)

    {:ok, %{evidence: evidence}} = PostgresEvidenceStore.fetch(ctx.handle, call_ref)
    assert evidence["body"]["details"]["contentHeld"] == false
    assert :error = stored(ctx.handle, request)
    assert info.spool?
  end

  test "while the spool's keys are not ready a configured spool captures in memory, never a plain file",
       ctx do
    start_runtime(ctx)
    plain_dir = Path.join(System.tmp_dir!(), "r5e-capture")
    before = if File.dir?(plain_dir), do: File.ls!(plain_dir), else: []
    spool_before = File.ls!(Path.join(ctx.dir, "spool"))

    :ok = Supervisor.terminate_child(Runtime, SpoolKeys)
    refute SpoolKeys.running?()

    capture = PayloadCapture.init(spool?: true) |> PayloadCapture.append(body(50_000))
    assert capture.spool == nil
    assert {:ok, bytes} = PayloadCapture.result(capture)
    assert bytes == body(50_000)

    after_ = if File.dir?(plain_dir), do: File.ls!(plain_dir), else: []
    assert after_ -- before == []
    assert File.ls!(Path.join(ctx.dir, "spool")) == spool_before
    {:ok, _} = Supervisor.restart_child(Runtime, SpoolKeys)
  end

  test "a restart unlocks the spool identity and ships everything that waited", ctx do
    start_runtime(ctx)
    request = body(350_000)
    response = "a short response " <> @canary

    FakeKeyService.set_available(ctx.fake, false)
    assert {:ok, _} = Call.record(call_state(request, response))
    assert {:error, :not_shipped} = Runtime.flush()
    stop_runtime()

    refute plaintext_anywhere?(ctx.dir)
    assert [_identity] = Path.wildcard(Path.join(ctx.dir, "spool-keys/identity-*.json"))

    FakeKeyService.set_available(ctx.fake, true)
    start_runtime(ctx)
    assert :ok = Runtime.flush()

    assert {:ok, ^request} = stored(ctx.handle, request)
    assert {:ok, ^response} = stored(ctx.handle, response)
    assert content_files(ctx.dir) == []
  end

  test "with the key service down at start the gateway records, and ships once it returns", ctx do
    start_runtime(ctx)
    stop_runtime()

    FakeKeyService.set_available(ctx.fake, false)
    start_runtime(ctx)
    request = body(70_000)
    response = body(66_000)

    # Encrypting needs no key service; the new epoch is sealed to the
    # identity's public key and written before it is used.
    assert {:ok, _} = Call.record(call_state(request, response))
    refute plaintext_anywhere?(ctx.dir)
    assert length(Path.wildcard(Path.join(ctx.dir, "spool-keys/epoch-*.json"))) >= 2

    FakeKeyService.set_available(ctx.fake, true)
    assert :ok = Runtime.flush()
    assert {:ok, ^request} = stored(ctx.handle, request)
    assert {:ok, ^response} = stored(ctx.handle, response)
  end

  test "first start with the key service down: memory-only key until an identity can be written",
       ctx do
    FakeKeyService.set_available(ctx.fake, false)
    start_runtime(ctx)
    assert Path.wildcard(Path.join(ctx.dir, "spool-keys/*.json")) == []

    request = body(10_000)
    assert {:ok, _} = Call.record(call_state(request, "r"))
    refute plaintext_anywhere?(ctx.dir)

    FakeKeyService.set_available(ctx.fake, true)

    wait_until(fn ->
      Path.wildcard(Path.join(ctx.dir, "spool-keys/identity-*.json")) != [] and
        Path.wildcard(Path.join(ctx.dir, "spool-keys/epoch-*.json")) != []
    end)

    assert :ok = Runtime.flush()
    assert {:ok, ^request} = stored(ctx.handle, request)
  end

  test "an altered waiting file is set aside and its records still ship (real store)", ctx do
    start_runtime(ctx)
    request = body(150_000)
    response = "fine response"

    FakeKeyService.set_available(ctx.fake, false)
    assert {:ok, _} = Call.record(call_state(request, response))
    assert {:error, :not_shipped} = Runtime.flush()

    target =
      Path.join([ctx.dir, "content", Base.encode16(:crypto.hash(:sha256, request), case: :lower)])

    bytes = File.read!(target)
    <<head::binary-size(100), b, tail::binary>> = bytes
    File.write!(target, <<head::binary, Bitwise.bxor(b, 0xFF), tail::binary>>)

    FakeKeyService.set_available(ctx.fake, true)
    assert :ok = Runtime.flush()

    assert record_count(ctx.deployment) >= 2
    assert :error = stored(ctx.handle, request)
    assert {:ok, ^response} = stored(ctx.handle, response)
    assert [aside] = files(Path.join(ctx.dir, "quarantine"))
    assert File.read!(aside) == <<head::binary, Bitwise.bxor(b, 0xFF), tail::binary>>
    assert content_files(ctx.dir) == []
  end

  test "a reader that fails its check stores nothing, and says exactly why", ctx do
    %{handle: handle, tmp_dir: tmp_dir} = ctx
    epoch = :crypto.strong_rand_bytes(16)
    dek = :crypto.strong_rand_bytes(32)
    plain = :crypto.strong_rand_bytes(200_000)
    ref = Ref.bytes(plain)
    path = Path.join(tmp_dir, Base.encode16(:crypto.hash(:sha256, plain), case: :lower))
    key_for = fn ^epoch -> {:ok, dek} end
    open = fn -> Spool.open_reader(path, :crypto.hash(:sha256, plain), key_for) end
    held? = fn -> Repo.exists?(from(b in "evidence_blobs", where: b.ref == ^ref)) end

    sealed = IO.iodata_to_binary(Spool.seal(plain, epoch, dek))

    # Cut short: the first chunks decrypt, the end does not.
    File.write!(path, binary_part(sealed, 0, byte_size(sealed) - 30))

    assert {:error, {:staged_content_unreadable, _}} =
             PostgresEvidenceStore.put_content(handle, ref, {:reader, path, open}, "urn:scope:a")

    refute held?.()

    # Whole, but not the content the reference names.
    other = IO.iodata_to_binary(Spool.seal(:crypto.strong_rand_bytes(200_000), epoch, dek))
    File.write!(path, other)

    assert {:error, {:staged_content_unreadable, :does_not_match_ref}} =
             PostgresEvidenceStore.put_content(handle, ref, {:reader, path, open}, "urn:scope:a")

    refute held?.()

    File.write!(path, sealed)

    assert :ok =
             PostgresEvidenceStore.put_content(handle, ref, {:reader, path, open}, "urn:scope:a")

    assert {:ok, ^plain} = PostgresEvidenceStore.get_content(handle, ref, "urn:scope:a")
    assert Path.wildcard(path <> ".sealed-*") == []

    assert {:error, :reader_requires_key_service} =
             PostgresEvidenceStore.put_content(Repo, ref, {:reader, path, open}, "urn:scope:a")
  end

  test "a second record naming content the first record's shipping removed still ships", ctx do
    start_runtime(ctx)
    shared = body(90_000)

    FakeKeyService.set_available(ctx.fake, false)
    assert {:ok, _} = Call.record(call_state(shared, "first", %{client_session_id: "s-one"}))
    assert {:ok, _} = Call.record(call_state(shared, "second", %{client_session_id: "s-two"}))
    assert {:error, :not_shipped} = Runtime.flush()

    FakeKeyService.set_available(ctx.fake, true)
    assert :ok = Runtime.flush()

    assert {:ok, ^shared} = stored(ctx.handle, shared, session("s-one"))
    assert {:ok, ^shared} = stored(ctx.handle, shared, session("s-two"))
    assert content_files(ctx.dir) == []
  end

  test "an epoch retires once nothing waits under it; a waiting file holds it", ctx do
    start_runtime(ctx, grace_seconds: 0)
    {:ok, first, _} = SpoolKeys.current()

    FakeKeyService.set_available(ctx.fake, false)
    request = body(5_000)
    assert {:ok, _} = Call.record(call_state(request, "r"))
    :ok = SpoolKeys.rotate()
    {:ok, second, _} = SpoolKeys.current()
    assert first != second

    first_file =
      Path.join([ctx.dir, "spool-keys", "epoch-#{Base.encode16(first, case: :lower)}.json"])

    assert %{held: held} = SpoolKeys.sweep()
    assert first in held
    assert File.exists?(first_file)

    FakeKeyService.set_available(ctx.fake, true)
    assert :ok = Runtime.flush()
    assert %{held: held} = SpoolKeys.sweep()
    refute first in held
    refute File.exists?(first_file)
    assert {:error, :staged_content_lost} = SpoolKeys.fetch(first)
    assert {:ok, ^request} = stored(ctx.handle, request)
  end

  test "the temporary file of a call whose process died is removed", ctx do
    start_runtime(ctx, orphan_grace_ms: 10)
    parent = self()

    {pid, monitor} =
      spawn_monitor(fn ->
        capture = PayloadCapture.init(spool?: true) |> PayloadCapture.append(body(1000))
        {:sealed, path, _} = capture.spool
        send(parent, {:path, path})
        exit(:killed_mid_stream)
      end)

    assert_receive {:path, path}
    assert_receive {:DOWN, ^monitor, :process, ^pid, _}
    wait_until(fn -> not File.exists?(path) end)
  end

  test "content files no record waits for are collected after a full flush; wanted ones are not",
       ctx do
    start_runtime(ctx)
    content = Path.join(ctx.dir, "content")
    orphan = Path.join(content, String.duplicate("ab", 32))
    File.write!(orphan, "left by a capture whose record never reached the log")
    old = System.os_time(:second) - 3_600
    File.touch!(orphan, old)

    FakeKeyService.set_available(ctx.fake, false)
    request = body(3_000)
    assert {:ok, _} = Call.record(call_state(request, "r"))

    # An outage longer than the margin: the waiting file is as old as the
    # orphan. Not everything is shipped, so nothing is collected.
    waiting = Path.join(content, Base.encode16(:crypto.hash(:sha256, request), case: :lower))
    File.touch!(waiting, old)
    assert {:error, _} = SpoolKeys.collect()
    assert File.exists?(orphan)
    assert File.exists?(waiting)

    FakeKeyService.set_available(ctx.fake, true)
    assert {:ok, 1} = SpoolKeys.collect()
    refute File.exists?(orphan)
    assert {:ok, ^request} = stored(ctx.handle, request)
  end

  test "a body that waited a long time for its call to end is not taken for a file nobody wants",
       ctx do
    start_runtime(ctx)
    {:ok, epoch, dek} = SpoolKeys.current()

    # A request body is written when the call begins. The call may then
    # run for a long time before its record is made and the file is put in
    # the content directory. The collector judges a file by its age, so a
    # file's age must count from when it was put there.
    source = Path.join(SpoolKeys.spool_dir(), "a-long-call")
    {:ok, writer} = Spool.create(source, epoch, dek)
    {:ok, writer} = Spool.append(writer, "sent twenty minutes before the answer finished")
    {:ok, %{sha256: sha}} = Spool.finish(writer)
    File.touch!(source, System.os_time(:second) - 1200)

    target = Path.join([ctx.dir, "content", Base.encode16(sha, case: :lower)])
    assert :ok = Recurse.Provenance.Staging.place_file(SpoolStaging.new(ctx.dir), source, target)

    assert File.stat!(target, time: :posix).mtime >= System.os_time(:second) - 5
    assert {:ok, 0} = SpoolKeys.collect()
    assert File.exists?(target)
  end

  test "hashing a sealed file without an expected digest streams it chunk by chunk", ctx do
    start_runtime(ctx)
    {:ok, epoch, dek} = SpoolKeys.current()

    plain = :crypto.strong_rand_bytes(Spool.chunk_bytes() * 3 + 17)
    source = Path.join(SpoolKeys.spool_dir(), "streamed-digest")
    {:ok, writer} = Spool.create(source, epoch, dek)
    {:ok, writer} = Spool.append(writer, plain)
    {:ok, %{sha256: expected}} = Spool.finish(writer)

    assert {:ok, ^expected} =
             Recurse.Provenance.Staging.hash_file(SpoolStaging.new(ctx.dir), source, nil)

    # A tampered byte in the last chunk is refused rather than hashed.
    bytes = File.read!(source)
    last = byte_size(bytes) - 1
    <<prefix::binary-size(last), b>> = bytes
    File.write!(source, <<prefix::binary, Bitwise.bxor(b, 1)>>)

    assert {:error, {:staged_content_unreadable, :tag_mismatch}} =
             Recurse.Provenance.Staging.hash_file(SpoolStaging.new(ctx.dir), source, nil)
  end

  test "without a key service the spool stays as it was" do
    capture = PayloadCapture.init(spool?: true)
    refute match?({:sealed, _, _}, capture.spool)
    PayloadCapture.discard(capture)
  end

  defp wait_until(fun, tries \\ 100) do
    cond do
      fun.() -> :ok
      tries == 0 -> flunk("condition not met")
      true -> Process.sleep(50) && wait_until(fun, tries - 1)
    end
  end
end
