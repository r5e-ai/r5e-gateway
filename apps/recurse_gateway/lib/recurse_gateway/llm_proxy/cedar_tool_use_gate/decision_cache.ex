defmodule Recurse.Gateway.LlmProxy.CedarToolUseGate.DecisionCache do
  @moduledoc """
  ETS-backed decision cache for `Recurse.Gateway.LlmProxy.CedarToolUseGate`
  (Spec 009 Phase 3 Sub-3.4 / T042).

  ## Cache shape

    * **Key**: `{principal_id, tool_name, tool_args_hash, cedar_bundle_hash}`
    * **Value**: the `evaluate/2` return value — `{:allow}` |
      `{:deny, %{...}}` | `{:error, atom()}`

  ## Iron-Law check (`elixir:otp-thinking`)

  This is the canonical "GenServer owns ETS table; reads bypass entirely
  via `:read_concurrency`" pattern. The GenServer answers exactly two
  cast messages — `{:put, key, value, ttl}` and `:purge` — neither of
  which can become a serialization bottleneck because we only enter
  the GenServer on a cache miss + hot reads do not enter it. We're
  not creating a process to organize stateless code; we're creating
  one to own a write-side resource (the ETS table) so it can be
  cleaned up when the owning process dies.

  Reads use `:ets.lookup/2` directly from the calling process; the
  cache hit path is a single ETS lookup + a TTL check + a microsecond
  return. This satisfies P-001 (sub-ms cache hits).

  ## TTL + size bounds

    * **TTL**: 10 seconds. Set in the value tuple:
      `{key, value, expires_at_monotonic}`.
    * **Size**: bounded at 1000 entries. We use simple FIFO purge —
      on `put/3`, if size > 1000, we sweep entries with stale TTLs
      and (if still over) drop the oldest 10% of remaining entries.
      LRU would require touch-on-read, which would re-introduce a
      hot-path write the read-bypass design rules out. Per the
      contract docs, this trade-off is accepted.

  ## Lifecycle

  Started under the `:recurse_gateway` supervisor (alongside other
  hot-path caches). Survives across requests; dies with the BEAM.
  Tests can use `start_link/1` with a `:name` opt to spawn an
  isolated cache for async test bodies.

  ## Telemetry

  Emits `[:recurse, :llm_proxy, :cedar_gate_cache, :hit | :miss | :evict]`
  events. The hit-rate is observable via the Audit Console.
  """

  use GenServer

  @typedoc """
  Cache key. Matches the `:ets` lookup tuple shape.
  """
  @type key ::
          {principal_id :: String.t(), tool_name :: String.t(), tool_args_hash :: binary(),
           cedar_bundle_hash :: binary()}

  @typedoc """
  Cached value — opaque to the cache; the gate consumes its own union.
  """
  @type value :: term()

  @default_ttl_ms 10_000
  @default_max_size 1_000

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Start the cache.

  ## Options

    * `:name` — process registration name (default `__MODULE__`).
    * `:table_name` — ETS table name (default `:"#{__MODULE__}.table"`,
      derived from `:name` when overridden in tests).
    * `:ttl_ms` — entry TTL in milliseconds (default #{@default_ttl_ms}).
    * `:max_size` — bound on entry count (default #{@default_max_size}).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Look up a cache entry. Returns `{:hit, value}` if present-and-fresh,
  `:miss` otherwise. Reads bypass the GenServer entirely.
  """
  @spec get(key(), keyword()) :: {:hit, value()} | :miss
  def get(key, opts \\ []) do
    table = Keyword.get(opts, :table_name, default_table_name(__MODULE__))

    case :ets.lookup(table, key) do
      [{^key, value, expires_at_mono}] ->
        if System.monotonic_time(:millisecond) < expires_at_mono do
          :telemetry.execute(
            [:recurse, :llm_proxy, :cedar_gate_cache, :hit],
            %{count: 1},
            %{}
          )

          {:hit, value}
        else
          # Stale; treat as miss. The next `put/3` (on the cache miss
          # path) will overwrite this entry.
          :telemetry.execute(
            [:recurse, :llm_proxy, :cedar_gate_cache, :miss],
            %{count: 1},
            %{reason: :expired}
          )

          :miss
        end

      [] ->
        :telemetry.execute(
          [:recurse, :llm_proxy, :cedar_gate_cache, :miss],
          %{count: 1},
          %{reason: :not_found}
        )

        :miss
    end
  rescue
    # If the ETS table does not exist (e.g. cache not started in this
    # test), behave as a permanent cache miss. The gate caller will
    # fall through to a fresh evaluation.
    ArgumentError -> :miss
  end

  @doc """
  Put an entry into the cache. Fires-and-forgets through the GenServer
  to ensure size bounds are enforced. Returns `:ok` immediately.
  """
  @spec put(key(), value(), keyword()) :: :ok
  def put(key, value, opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)

    case Process.whereis(name) do
      nil -> :ok
      _pid -> GenServer.cast(name, {:put, key, value, opts})
    end
  end

  @doc """
  Remove all entries from the cache. Synchronous (waits for sweep).
  Used in test setups; not on hot path.
  """
  @spec clear(keyword()) :: :ok
  def clear(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)

    case Process.whereis(name) do
      nil -> :ok
      _pid -> GenServer.call(name, :clear)
    end
  end

  @doc """
  Default ETS table name for a given GenServer name.
  """
  @spec default_table_name(atom()) :: atom()
  def default_table_name(name) when is_atom(name) do
    String.to_atom("#{name}.table")
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    table_name = Keyword.get(opts, :table_name, default_table_name(name))
    ttl_ms = Keyword.get(opts, :ttl_ms, @default_ttl_ms)
    max_size = Keyword.get(opts, :max_size, @default_max_size)

    table =
      :ets.new(table_name, [
        :named_table,
        :public,
        :set,
        read_concurrency: true,
        write_concurrency: false
      ])

    {:ok,
     %{
       table: table,
       ttl_ms: ttl_ms,
       max_size: max_size,
       inserts_since_purge: 0
     }}
  end

  @impl true
  def handle_cast({:put, key, value, opts}, state) do
    ttl_ms = Keyword.get(opts, :ttl_ms, state.ttl_ms)
    expires_at_mono = System.monotonic_time(:millisecond) + ttl_ms

    :ets.insert(state.table, {key, value, expires_at_mono})

    state = %{state | inserts_since_purge: state.inserts_since_purge + 1}

    state =
      if :ets.info(state.table, :size) > state.max_size do
        purge_until_under_bound(state)
      else
        state
      end

    {:noreply, state}
  end

  @impl true
  def handle_call(:clear, _from, state) do
    :ets.delete_all_objects(state.table)
    {:reply, :ok, %{state | inserts_since_purge: 0}}
  end

  # ---------------------------------------------------------------------------
  # Internal — bounded purge
  # ---------------------------------------------------------------------------

  # Two-pass: drop expired entries first; if still over `max_size`,
  # drop the oldest 10% of remaining entries by `expires_at_mono`.
  defp purge_until_under_bound(state) do
    now = System.monotonic_time(:millisecond)

    # Pass 1: drop expired.
    :ets.select_delete(state.table, [
      {{:_, :_, :"$1"}, [{:<, :"$1", now}], [true]}
    ])

    size = :ets.info(state.table, :size)

    if size > state.max_size do
      # Pass 2: keep the youngest entries by sorting on expires_at_mono;
      # delete the oldest 10% of the table to keep amortized cost low
      # (each insert pays O(table_size) only once per ~max_size/10 inserts).
      to_drop = max(div(state.max_size, 10), 1)

      state.table
      |> :ets.tab2list()
      |> Enum.sort_by(fn {_k, _v, exp} -> exp end)
      |> Enum.take(to_drop)
      |> Enum.each(fn {k, _v, _exp} ->
        :ets.delete(state.table, k)

        :telemetry.execute(
          [:recurse, :llm_proxy, :cedar_gate_cache, :evict],
          %{count: 1},
          %{}
        )
      end)
    end

    %{state | inserts_since_purge: 0}
  end
end
