defmodule Recurse.Gateway.Identity.JwksCacheTest do
  @moduledoc """
  Contract tests for `Recurse.Gateway.Identity.JwksCache` (F002 T042).

  Covers:

    * TTL-hot path — cached kid returns without a new HTTP fetch.
    * `kid`-miss refresh — unknown kid triggers a JWKS fetch + populates
      the cache.
    * Coalescing — N concurrent `fetch_jwk/2` calls on an unknown kid
      trigger EXACTLY ONE upstream fetch. This is Surface P's core
      invariant.
    * HTTP failure — 5xx / connect errors surface as
      `{:error, :jwks_fetch_failed}` and do NOT poison the cache.
    * Unknown issuer — config boundary check.

  `async: false` because `Recurse.Providers.Support.MockHttpUpstream`
  binds a port per test. Two tests starting upstreams in parallel could
  race on ephemeral port allocation; serialization is the cheap fix.
  """

  use ExUnit.Case, async: false

  alias Recurse.Gateway.Identity.JwksCache
  alias Recurse.Gateway.Test.JwtTestHelper
  alias Recurse.Providers.Support.MockHttpUpstream

  @test_issuer "https://test-broker.example.invalid"

  setup do
    {:ok, upstream} = MockHttpUpstream.start()

    on_exit(fn -> MockHttpUpstream.stop(upstream) end)

    # Each test gets its own Task.Supervisor so concurrent fetches in
    # this test are isolated from the Gateway's app-level supervisor.
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    task_sup_name = :"jwks_cache_task_sup_#{System.unique_integer([:positive])}"
    {:ok, _pid} = start_supervised({Task.Supervisor, name: task_sup_name})

    %{upstream: upstream, task_supervisor: task_sup_name}
  end

  describe "start_link/1 + fetch_jwk/2 happy-path" do
    test "refreshes on cache-miss and caches for subsequent reads", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      # Second call — cache is warm, NO new upstream hit.
      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert counter_value(call_counter) == 1
    end

    test "unknown kid after successful refresh returns :unknown_kid", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:error, :unknown_kid} =
               JwksCache.fetch_jwk(cache, @test_issuer, "not-in-jwks")
    end

    test "unknown issuer returns :unknown_issuer without touching the network", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)
        Plug.Conn.send_resp(conn, 200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:error, :unknown_issuer} =
               JwksCache.fetch_jwk(cache, "https://unknown-broker.example", "test-key-rs256")

      assert counter_value(call_counter) == 0
    end
  end

  describe "coalesced kid-miss refresh (Surface P)" do
    test "N concurrent fetch_jwk calls coalesce behind one upstream fetch", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()
      gate = start_gate()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)

        # Block until the test releases the gate — ensures all N callers
        # enqueue BEFORE the refresh completes.
        wait_for_release(gate)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      n = 20

      tasks =
        for _ <- 1..n do
          Task.async(fn ->
            JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
          end)
        end

      # Give the GenServer time to enqueue all N waiters before we let
      # the upstream respond. 100 ms is comfortably above the call
      # dispatch cost while keeping the test fast.
      Process.sleep(100)
      release_gate(gate)

      results = Task.await_many(tasks, 5_000)

      assert Enum.all?(results, &match?({:ok, %{"kid" => "test-key-rs256"}}, &1))
      assert counter_value(call_counter) == 1
    end
  end

  describe "HTTP failure handling" do
    test "upstream 5xx returns :jwks_fetch_failed to all coalesced waiters", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        Plug.Conn.send_resp(conn, 503, "service down")
      end)

      cache = start_cache!(upstream, task_sup)

      # Single caller is enough to exercise the error path — coalescing
      # is already covered above.
      assert {:error, :jwks_fetch_failed} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
    end

    test "subsequent call after failure re-attempts the fetch", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        count = increment(call_counter)

        if count == 1 do
          Plug.Conn.send_resp(conn, 503, "down")
        else
          conn
          |> Plug.Conn.put_resp_header("content-type", "application/json")
          |> Plug.Conn.send_resp(200, rs256_jwks_body())
        end
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:error, :jwks_fetch_failed} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert counter_value(call_counter) == 2
    end
  end

  describe "refresh/1" do
    test "forces a JWKS fetch even when cache has entries", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      MockHttpUpstream.expect(upstream, fn conn ->
        increment(call_counter)

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, rs256_jwks_body())
      end)

      cache = start_cache!(upstream, task_sup)

      assert {:ok, _} = JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
      assert :ok = JwksCache.refresh(cache, @test_issuer)
      assert counter_value(call_counter) == 2
    end

    test "returns :unknown_issuer when issuer not configured", %{
      upstream: upstream,
      task_supervisor: task_sup
    } do
      cache = start_cache!(upstream, task_sup)

      assert {:error, :unknown_issuer} = JwksCache.refresh(cache, "https://nope.example")
    end
  end

  # Refresh deadline, task death and caller timeout (enterprise #41).
  # These tests drive the refresh task through `req_opts: [plug: ...]`:
  # Req runs the plug inside the refresh task process, so the plug can
  # report the task's pid, trap exits, or hang.
  describe "refresh deadline and task failure" do
    test "an exit-trapping hung task: waiters fail at the deadline and the cache stays free", %{
      task_supervisor: task_sup
    } do
      test_pid = self()

      plug = fn conn ->
        case conn.host do
          "hung.example.invalid" ->
            Process.flag(:trap_exit, true)
            send(test_pid, {:refresh_task, self()})
            # Hang, swallowing any trappable exit signal.
            hang()

          "other.example.invalid" ->
            jwks_response(conn)
        end
      end

      cache =
        start_plug_cache!(task_sup, plug,
          refresh_timeout_ms: 300,
          issuers: [
            %{issuer_url: "https://hung", jwks_url: "https://hung.example.invalid/jwks"},
            %{issuer_url: "https://other", jwks_url: "https://other.example.invalid/jwks"}
          ]
        )

      started = System.monotonic_time(:millisecond)

      waiters =
        for _ <- 1..3 do
          Task.async(fn -> JwksCache.fetch_jwk(cache, "https://hung", "test-key-rs256") end)
        end

      assert_receive {:refresh_task, task_pid}, 1_000
      task_mon = Process.monitor(task_pid)

      # While the hung fetch is in flight, another issuer is served.
      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, "https://other", "test-key-rs256")

      assert Enum.all?(Task.await_many(waiters, 2_000), &(&1 == {:error, :jwks_fetch_failed}))
      elapsed = System.monotonic_time(:millisecond) - started

      # The deadline answered the waiters: not before 300 ms, and far
      # below the 5 s a waiting `Task.Supervisor.terminate_child/2`
      # would spend on an exit-trapping task.
      assert elapsed >= 300
      assert elapsed < 1_500

      assert_receive {:DOWN, ^task_mon, :process, ^task_pid, :killed}, 1_000

      # The cache is free right after the deadline: the in-flight entry
      # is gone and a call returns at once.
      assert %{refresh_coalescing: coalescing} = :sys.get_state(cache)
      assert coalescing == %{}

      {micros, result} =
        :timer.tc(fn -> JwksCache.fetch_jwk(cache, "https://other", "test-key-rs256") end)

      assert {:ok, _} = result
      assert micros < 100_000
    end

    test "after a deadline the next miss starts a fresh refresh that succeeds", %{
      task_supervisor: task_sup
    } do
      call_counter = start_counter()

      plug = fn conn ->
        if increment(call_counter) == 1, do: hang(), else: jwks_response(conn)
      end

      cache = start_plug_cache!(task_sup, plug, refresh_timeout_ms: 200)

      assert {:error, :jwks_fetch_failed} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      assert counter_value(call_counter) == 2
    end

    test "a killed refresh task fails its waiters at once and the next miss retries", %{
      task_supervisor: task_sup
    } do
      test_pid = self()
      call_counter = start_counter()

      plug = fn conn ->
        if increment(call_counter) == 1 do
          send(test_pid, {:refresh_task, self()})
          hang()
        else
          jwks_response(conn)
        end
      end

      # A deadline far beyond the test, so only the :DOWN path can answer.
      cache = start_plug_cache!(task_sup, plug, refresh_timeout_ms: 60_000)

      waiters =
        for _ <- 1..3 do
          Task.async(fn -> JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256") end)
        end

      assert_receive {:refresh_task, task_pid}, 1_000
      Process.exit(task_pid, :kill)

      assert Enum.all?(Task.await_many(waiters, 1_000), &(&1 == {:error, :jwks_fetch_failed}))
      assert %{refresh_coalescing: coalescing} = :sys.get_state(cache)
      assert coalescing == %{}

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")
    end

    test "a stale deadline or :DOWN for an old task does not touch its replacement", %{
      task_supervisor: task_sup
    } do
      test_pid = self()
      call_counter = start_counter()
      gate = start_gate()

      plug = fn conn ->
        n = increment(call_counter)
        send(test_pid, {:refresh_task, n, self()})

        case n do
          1 -> hang()
          _ -> wait_for_release(gate) && jwks_response(conn)
        end
      end

      cache = start_plug_cache!(task_sup, plug, refresh_timeout_ms: 60_000)

      first = Task.async(fn -> JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256") end)
      assert_receive {:refresh_task, 1, first_pid}, 1_000
      %{refresh_coalescing: %{@test_issuer => %{task_ref: old_ref}}} = :sys.get_state(cache)
      Process.exit(first_pid, :kill)
      assert {:error, :jwks_fetch_failed} = Task.await(first, 1_000)

      second = Task.async(fn -> JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256") end)
      assert_receive {:refresh_task, 2, second_pid}, 1_000

      send(cache, {:refresh_timeout, @test_issuer, old_ref})
      send(cache, {:DOWN, old_ref, :process, first_pid, :killed})

      # The replacement is still in flight and alive.
      assert %{refresh_coalescing: %{@test_issuer => %{task_pid: ^second_pid}}} =
               :sys.get_state(cache)

      assert Process.alive?(second_pid)

      release_gate(gate)
      assert {:ok, %{"kid" => "test-key-rs256"}} = Task.await(second, 1_000)
    end

    test "a caller timeout returns :jwks_fetch_failed and the cache recovers", %{
      task_supervisor: task_sup
    } do
      Application.put_env(:recurse_gateway, :jwks_cache_call_timeout_ms, 100)
      on_exit(fn -> Application.delete_env(:recurse_gateway, :jwks_cache_call_timeout_ms) end)

      gate = start_gate()

      plug = fn conn ->
        wait_for_release(gate)
        jwks_response(conn)
      end

      cache = start_plug_cache!(task_sup, plug, refresh_timeout_ms: 60_000)

      assert {:error, :jwks_fetch_failed} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      # The timed-out caller is still a waiter; the refresh completes,
      # its reply is dropped, and nothing lands in this mailbox.
      release_gate(gate)

      Application.delete_env(:recurse_gateway, :jwks_cache_call_timeout_ms)

      assert {:ok, %{"kid" => "test-key-rs256"}} =
               JwksCache.fetch_jwk(cache, @test_issuer, "test-key-rs256")

      refute_received {_ref, {:ok, _}}
      refute_received {_ref, {:error, _}}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp start_cache!(upstream, task_supervisor) do
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    name = :"jwks_cache_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      start_supervised(
        {JwksCache,
         [
           issuers: [
             %{
               issuer_url: @test_issuer,
               jwks_url: MockHttpUpstream.url(upstream) <> "/oidc/jwks",
               ttl_seconds: 300
             }
           ],
           finch_pool: :jwks_pool,
           task_supervisor: task_supervisor,
           name: name
         ]}
      )

    _ = pid
    name
  end

  defp start_plug_cache!(task_supervisor, plug, opts) do
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    name = :"jwks_cache_#{System.unique_integer([:positive])}"

    issuers =
      Keyword.get(opts, :issuers, [
        %{issuer_url: @test_issuer, jwks_url: "https://jwks.example.invalid/oidc/jwks"}
      ])

    {:ok, _pid} =
      start_supervised(
        {JwksCache,
         [
           issuers: issuers,
           task_supervisor: task_supervisor,
           req_opts: [plug: plug],
           refresh_timeout_ms: Keyword.fetch!(opts, :refresh_timeout_ms),
           name: name
         ]}
      )

    name
  end

  defp jwks_response(conn) do
    conn
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.send_resp(200, rs256_jwks_body())
  end

  # Block the refresh task until it is killed. With `trap_exit` set, a
  # trappable exit signal arrives as a message and is swallowed here.
  defp hang do
    receive do
      {:EXIT, _from, _reason} -> hang()
    end
  end

  # Real RS256 JWKS body using the JwtTestHelper's per-BEAM keypair so
  # callers that round-trip through the validator work against the same
  # keys.
  defp rs256_jwks_body do
    %{"keys" => [JwtTestHelper.public_jwk(:rs256)]}
    |> JSON.encode!()
  end

  # Tiny atomic counter via an Agent. We use Agent here instead of
  # `:counters.new/2` so the increment ops are ordered + readable; these
  # are tests, not a hot path.
  defp start_counter do
    {:ok, pid} = Agent.start_link(fn -> 0 end)
    pid
  end

  defp increment(counter) do
    Agent.get_and_update(counter, fn n -> {n + 1, n + 1} end)
  end

  defp counter_value(counter), do: Agent.get(counter, & &1)

  # A "gate" is a process the upstream handler blocks on until the test
  # explicitly releases it — used to enforce "all N waiters have
  # enqueued" in the coalescing test.
  defp start_gate do
    {:ok, pid} = Agent.start_link(fn -> :closed end)
    pid
  end

  defp wait_for_release(gate) do
    if Agent.get(gate, & &1) == :open do
      :ok
    else
      Process.sleep(10)
      wait_for_release(gate)
    end
  end

  defp release_gate(gate), do: Agent.update(gate, fn _ -> :open end)
end
