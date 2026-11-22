defmodule Recurse.Gateway.Identity.JwksCache do
  @moduledoc """
  Per-issuer JWKS cache for Gateway-side JWT verification (F002 T042).

  ## Iron Law check (otp-thinking)

  This IS a legitimate GenServer. All three criteria met:

    1. Mutable state persisting across calls? YES — fetched JWKS
       mapped `{issuer_url => %{keys: %{kid => JWK}, last_fetch,
       ttl_seconds}}` plus the coalescing `from`-queue.
    2. Fault isolation? YES — a crashed refresh must not drag down the
       Gateway; supervisor restarts a clean cache state.
    3. Serialized access? YES — on `kid`-miss we MUST refresh exactly
       once across N concurrent callers (coalescing property, Surface P).

  ## Coalescing pattern (Surface P)

  When a `fetch_jwk(issuer, kid)` call misses, the GenServer checks
  whether a refresh is already in flight:

    - If NOT, kick off an async `Task` for that issuer's refresh and
      stash the caller's `from` under `refresh_coalescing[issuer]`.
    - If YES, append the caller's `from` to the same list.

  When the refresh completes (`handle_info/2` on a `Task` ref), EVERY
  stashed `from` is replied to with the result derived from the refreshed
  keys. Exactly one upstream HTTP request covers N concurrent callers.

  ## Deadlines

  Two independent bounds, for two different things:

    * **Refresh deadline** (`:refresh_timeout_ms`, default 10 s) bounds
      the refresh task. It is an intentional end-to-end cap on one JWKS
      fetch, not a sum of the HTTP client's timeouts (those bound single
      phases; a slow-dripping response or a wedged handshake can outlast
      all of them). When it expires the cache replies
      `{:error, :jwks_fetch_failed}` to every coalesced waiter, clears the
      issuer's in-flight entry, and only then kills the task with
      `Process.exit(pid, :kill)`, which does not wait on the task (an
      exit-trapping task cannot delay it). The next miss starts a fresh
      fetch. Tradeoff: a fetch that would have succeeded after the cap is
      abandoned; in exchange no caller ever coalesces onto a wedged fetch,
      and the cache stays responsive to other issuers throughout.
    * **Caller timeout** (`:jwks_cache_call_timeout_ms` app env, read on
      each call, default 12 s) bounds one caller's `GenServer.call`. On
      expiry that caller gets `{:error, :jwks_fetch_failed}`.

  The two are configured separately and nothing enforces an order
  between them. With the defaults the refresh deadline fires first, so
  waiters are answered by the cache. If a caller times out first, its
  entry stays in the issuer's waiters until the refresh completes or hits
  its deadline; the reply sent then is dropped by the runtime (the
  caller's call alias is gone), so a late reply never lands in a
  caller's mailbox.

  A refresh task that dies without replying (`:DOWN` for an in-flight
  ref) is cleaned up the same way as a deadline: waiters get
  `{:error, :jwks_fetch_failed}` and the in-flight entry is cleared.
  Completion, crash and deadline share one cleanup path; late messages
  for a ref that is no longer in flight are ignored.

  Why async `Task` + `handle_info` instead of blocking inside
  `handle_call`: a blocking `handle_call` with `GenServer.reply/2` from
  a spawned helper works, but we want to keep the GenServer responsive
  to OTHER issuers' requests during a slow JWKS fetch. Task supervision
  under `Task.Supervisor` gives us both.

  ## State shape

      %{
        issuers: %{
          issuer_url => %{
            jwks_url: String.t(),
            keys: %{kid => %JOSE.JWK{} | map()},
            last_fetch: DateTime.t() | nil,
            ttl_seconds: pos_integer()
          }
        },
        refresh_coalescing: %{
          issuer_url => %{
            task_ref: reference() | nil,
            task_pid: pid() | nil,
            timer_ref: reference() | nil,
            waiters: [from]
          }
        },
        task_supervisor: Task.Supervisor | atom(),
        finch_pool: atom(),
        refresh_timeout_ms: pos_integer()
      }

  ## Boot config

      JwksCache.start_link(
        issuers: [
          %{
            issuer_url: "https://recurse-broker.corp.example",
            jwks_url: "https://recurse-broker.corp.example/oidc/jwks",
            ttl_seconds: 300
          }
        ],
        finch_pool: :jwks_pool,
        task_supervisor: Recurse.Gateway.Identity.JwksCache.TaskSupervisor
      )

  The `:jwks_pool` named Finch pool must already be started by
  `RecurseGateway.Application` (F002 T016). The Task supervisor is
  expected to live adjacent to the cache in the Gateway supervision tree
  (started by the same application).

  ## Cross-references

    * `specs/002-standalone-gateway-vertical-slice/research.md` D2
    * `specs/002-standalone-gateway-vertical-slice/contracts/property_test_surface_catalog_f002.md` §Surface P
    * `contracts/recurse_broker_api.md` GET /oidc/jwks response shape
    * F002 FR-007 (alg allowlist — enforced at JwtValidator, not here)

  ## See also

  `RecurseBroker.OIDC.DiscoveryCache` is a structurally similar JWKS-
  caching GenServer but differs in three ways: (1) it discovers issuers
  dynamically via OIDC well-known endpoints; (2) it uses a public ETS
  fast-path read that bypasses the GenServer; (3) it runs without a
  configured Finch pool (DI via `:req_opts`). A shared abstraction was
  considered during Phase-10 refactor review and declined — the
  divergent cache-population models would force one cache into the
  other's shape.
  """

  use GenServer

  require Logger

  @default_ttl_seconds 300
  @default_finch_pool :jwks_pool
  # 3s HTTP timeout matches :jwks_pool's configured transport timeout
  # (RecurseGateway.Application T016).
  @http_timeout_ms 3_000
  # End-to-end cap on one refresh task (see "Deadlines" in the moduledoc).
  @default_refresh_timeout_ms 10_000
  # Per-call bound on `GenServer.call`; overridable through the
  # `:jwks_cache_call_timeout_ms` app env (see "Deadlines").
  @default_call_timeout_ms 12_000

  @type issuer_config :: %{
          required(:issuer_url) => String.t(),
          required(:jwks_url) => String.t(),
          optional(:ttl_seconds) => pos_integer()
        }

  @type init_opts :: [
          issuers: [issuer_config()],
          finch_pool: atom(),
          task_supervisor: module() | atom(),
          name: GenServer.name(),
          req_opts: keyword(),
          refresh_timeout_ms: pos_integer()
        ]

  # `:req_opts` is a keyword list merged into every `Req.new/1` call made
  # by the refresh task. Production leaves it `[]`; tests can pass
  # `[plug: fn conn, _opts -> ... end]` to redirect the upstream JWKS
  # fetch at an in-process stub without binding a real port. Matches the
  # shape exposed by `RecurseBroker.OIDC.DiscoveryCache` (sibling broker-
  # side cache) so the two caches share one DI convention. See F002 T096
  # (`jwks_cache_property_test.exs`) for the coalescing property that
  # exercises this seam under 2–50 concurrent callers.

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  @doc """
  Start the cache. See moduledoc for `opts` schema.
  """
  @spec start_link(init_opts()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Resolve a `(issuer_url, kid)` to a JWK.

  Returns `{:ok, jwk}` if present in cache, `{:error, :unknown_issuer}`
  if the issuer was not configured at boot, or `{:error, :unknown_kid}`
  after a forced refresh still does not contain the kid, or
  `{:error, :jwks_fetch_failed}` if the refresh itself failed.

  Concurrent callers on the same `(issuer_url, unknown_kid)` coalesce
  behind a single refresh — Surface P invariant.

  The call is bounded by the caller timeout, and an in-flight refresh by
  the refresh deadline (see "Deadlines" in the moduledoc). Either one
  expiring returns `{:error, :jwks_fetch_failed}`.
  """
  @spec fetch_jwk(GenServer.server(), String.t(), String.t()) ::
          {:ok, map() | JOSE.JWK.t()}
          | {:error, :unknown_issuer | :unknown_kid | :jwks_fetch_failed}
  def fetch_jwk(server, issuer_url, kid)
      when is_binary(issuer_url) and is_binary(kid) do
    GenServer.call(server, {:fetch_jwk, issuer_url, kid}, call_timeout_ms())
  catch
    :exit, {:timeout, _} -> {:error, :jwks_fetch_failed}
  end

  @doc """
  Arity-2 convenience used by `JwtValidator.validate/2` when configured
  with `{:cache, __MODULE__}` — delegates to `fetch_jwk/3` on the
  default-named process.
  """
  @spec fetch_jwk(String.t(), String.t()) ::
          {:ok, map() | JOSE.JWK.t()}
          | {:error, :unknown_issuer | :unknown_kid | :jwks_fetch_failed}
  def fetch_jwk(issuer_url, kid) when is_binary(issuer_url) and is_binary(kid) do
    fetch_jwk(__MODULE__, issuer_url, kid)
  end

  @doc """
  Force-refresh the cache for a specific issuer. Blocks until the
  upstream JWKS fetch completes (or fails), bounded by the same two
  deadlines as `fetch_jwk/3`.
  """
  @spec refresh(GenServer.server(), String.t()) ::
          :ok | {:error, :unknown_issuer | :jwks_fetch_failed}
  def refresh(server \\ __MODULE__, issuer_url) do
    GenServer.call(server, {:refresh, issuer_url}, call_timeout_ms())
  catch
    :exit, {:timeout, _} -> {:error, :jwks_fetch_failed}
  end

  defp call_timeout_ms do
    Application.get_env(:recurse_gateway, :jwks_cache_call_timeout_ms, @default_call_timeout_ms)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl GenServer
  def init(opts) do
    issuers = Keyword.get(opts, :issuers, [])
    finch_pool = Keyword.get(opts, :finch_pool, @default_finch_pool)
    task_supervisor = Keyword.get(opts, :task_supervisor, Task.Supervisor)
    req_opts = Keyword.get(opts, :req_opts, [])
    refresh_timeout_ms = Keyword.get(opts, :refresh_timeout_ms, @default_refresh_timeout_ms)

    issuers_state =
      Map.new(issuers, fn cfg ->
        {cfg.issuer_url,
         %{
           jwks_url: cfg.jwks_url,
           keys: %{},
           last_fetch: nil,
           ttl_seconds: Map.get(cfg, :ttl_seconds, @default_ttl_seconds)
         }}
      end)

    state = %{
      issuers: issuers_state,
      refresh_coalescing: %{},
      task_supervisor: task_supervisor,
      finch_pool: finch_pool,
      req_opts: req_opts,
      refresh_timeout_ms: refresh_timeout_ms
    }

    {:ok, state}
  end

  @impl GenServer
  def handle_call({:fetch_jwk, issuer_url, kid}, from, state) do
    case Map.fetch(state.issuers, issuer_url) do
      :error ->
        {:reply, {:error, :unknown_issuer}, state}

      {:ok, issuer_state} ->
        handle_fetch_attempt(issuer_url, issuer_state, kid, from, state)
    end
  end

  @impl GenServer
  def handle_call({:refresh, issuer_url}, from, state) do
    case Map.fetch(state.issuers, issuer_url) do
      :error ->
        {:reply, {:error, :unknown_issuer}, state}

      {:ok, _issuer_state} ->
        {:noreply, enqueue_refresh(issuer_url, {:refresh, from}, state)}
    end
  end

  # Messages about a refresh task from `Task.Supervisor.async_nolink/2`
  # and this module's own deadline timer:
  #
  #   - `{ref, result}` — the actual refresh result.
  #   - `{:DOWN, ref, :process, _pid, reason}` — for a ref still in
  #     flight, the task died without replying (crash or kill). A normal
  #     completion demonitors with `:flush`, so its `:DOWN` never
  #     arrives here.
  #   - `{:refresh_timeout, issuer_url, ref}` — the refresh deadline.
  #
  # Each one is acted on only while `ref` is the issuer's in-flight task
  # ref; anything else is a late message for a finished refresh and is
  # ignored.
  @impl GenServer
  def handle_info({ref, result}, state) when is_reference(ref) do
    case find_by_task_ref(state, ref) do
      {:ok, issuer_url} -> {:noreply, finish_refresh(issuer_url, result, state)}
      :error -> {:noreply, state}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    case find_by_task_ref(state, ref) do
      {:ok, issuer_url} ->
        {:noreply, finish_refresh(issuer_url, {:error, {:refresh_task_down, reason}}, state)}

      :error ->
        {:noreply, state}
    end
  end

  def handle_info({:refresh_timeout, issuer_url, ref}, state) do
    case state.refresh_coalescing do
      %{^issuer_url => %{task_ref: ^ref, task_pid: task_pid}} ->
        state = finish_refresh(issuer_url, {:error, :refresh_timeout}, state)
        # Waiters are answered and the entry cleared above; the kill is
        # last and never blocks (`:kill` cannot be trapped).
        Process.exit(task_pid, :kill)
        {:noreply, state}

      _not_in_flight ->
        {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Refresh orchestration.
  # ---------------------------------------------------------------------------

  # `{fetch, from, kid}` keeps us from replying `:unknown_kid` prematurely
  # when a caller hits a cache-miss and a refresh is already in flight —
  # we need to re-check the kid against the POST-refresh keys. The
  # `{:refresh, from}` shape is for explicit `refresh/1` callers who just
  # want :ok / {:error, _}.

  defp handle_fetch_attempt(issuer_url, issuer_state, kid, from, state) do
    if Map.has_key?(issuer_state.keys, kid) do
      {:reply, {:ok, issuer_state.keys[kid]}, state}
    else
      {:noreply, enqueue_refresh(issuer_url, {:fetch, from, kid}, state)}
    end
  end

  defp enqueue_refresh(issuer_url, waiter, state) do
    entry =
      Map.get(state.refresh_coalescing, issuer_url, %{
        task_ref: nil,
        task_pid: nil,
        timer_ref: nil,
        waiters: []
      })

    entry = %{entry | waiters: [waiter | entry.waiters]}

    entry =
      if entry.task_ref == nil do
        start_refresh_task(issuer_url, entry, state)
      else
        entry
      end

    %{state | refresh_coalescing: Map.put(state.refresh_coalescing, issuer_url, entry)}
  end

  defp start_refresh_task(issuer_url, entry, state) do
    %{jwks_url: jwks_url} = state.issuers[issuer_url]
    finch_pool = state.finch_pool
    req_opts = state.req_opts

    task =
      Task.Supervisor.async_nolink(
        state.task_supervisor,
        fn -> do_http_fetch(jwks_url, finch_pool, req_opts) end
      )

    timer_ref =
      Process.send_after(
        self(),
        {:refresh_timeout, issuer_url, task.ref},
        state.refresh_timeout_ms
      )

    %{entry | task_ref: task.ref, task_pid: task.pid, timer_ref: timer_ref}
  end

  defp find_by_task_ref(state, ref) do
    Enum.find_value(state.refresh_coalescing, :error, fn
      {issuer_url, %{task_ref: ^ref}} -> {:ok, issuer_url}
      # Expected non-match: a different in-flight refresh's task_ref. Keep
      # iterating by returning nil. Any other shape is a programmer bug —
      # let it crash.
      {_issuer_url, %{task_ref: _other_ref}} -> nil
    end) || :error
  end

  # The one cleanup path for an in-flight refresh, whichever way it ends:
  # stop the deadline timer, drop the task monitor (flushing a queued
  # `:DOWN`), then answer every waiter and clear the entry.
  defp finish_refresh(issuer_url, result, state) do
    %{task_ref: task_ref, timer_ref: timer_ref} = state.refresh_coalescing[issuer_url]
    _ = Process.cancel_timer(timer_ref, async: false, info: false)
    Process.demonitor(task_ref, [:flush])
    complete_refresh(issuer_url, result, state)
  end

  defp complete_refresh(issuer_url, result, state) do
    %{waiters: waiters} = state.refresh_coalescing[issuer_url]
    now = DateTime.utc_now()

    {reply_state, reply_keys} =
      case result do
        {:ok, keys_map} ->
          issuers =
            Map.update!(state.issuers, issuer_url, fn entry ->
              %{entry | keys: keys_map, last_fetch: now}
            end)

          {%{state | issuers: issuers}, {:ok, keys_map}}

        {:error, reason} ->
          Logger.warning(fn ->
            "JWKS refresh failed for #{inspect(issuer_url)}: #{inspect(reason)}"
          end)

          {state, {:error, :jwks_fetch_failed}}
      end

    Enum.each(waiters, fn waiter -> reply_waiter(waiter, reply_keys) end)

    %{
      reply_state
      | refresh_coalescing: Map.delete(reply_state.refresh_coalescing, issuer_url)
    }
  end

  # Reply to a fetch waiter with the resolved kid (post-refresh lookup),
  # or `:unknown_kid` if the refreshed JWKS still doesn't carry it, or
  # `:jwks_fetch_failed` if refresh errored.
  defp reply_waiter({:fetch, from, kid}, {:ok, keys_map}) do
    case Map.fetch(keys_map, kid) do
      {:ok, jwk} -> GenServer.reply(from, {:ok, jwk})
      :error -> GenServer.reply(from, {:error, :unknown_kid})
    end
  end

  defp reply_waiter({:fetch, from, _kid}, {:error, :jwks_fetch_failed}) do
    GenServer.reply(from, {:error, :jwks_fetch_failed})
  end

  defp reply_waiter({:refresh, from}, {:ok, _keys_map}) do
    GenServer.reply(from, :ok)
  end

  defp reply_waiter({:refresh, from}, {:error, :jwks_fetch_failed}) do
    GenServer.reply(from, {:error, :jwks_fetch_failed})
  end

  # ---------------------------------------------------------------------------
  # HTTP fetch — runs under Task.Supervisor, NOT on the GenServer process.
  # Returns `{:ok, keys_map}` or `{:error, reason}`. No GenServer state is
  # touched here — we're a leaf in the supervision tree for the duration
  # of the fetch.
  # ---------------------------------------------------------------------------

  defp do_http_fetch(jwks_url, finch_pool, req_opts) do
    # Req disallows mixing `:finch` (named pool) with `:connect_options`
    # because connection options belong to the owning Finch pool's config,
    # not to the per-request call. Timeouts for :jwks_pool are set at the
    # pool level in RecurseGateway.Application (T016); we keep the
    # per-request receive_timeout as an upper bound.
    #
    # `req_opts` is caller-supplied DI (empty in production). When tests
    # pass `plug: fn conn, _ -> ... end`, Req short-circuits the entire
    # HTTP layer — we MUST drop `:finch` when a `:plug` is provided
    # because Req raises on the combination. That drop is pure test
    # seam; production `req_opts` is `[]` and the `:finch` pool remains.
    base =
      [
        url: jwks_url,
        receive_timeout: @http_timeout_ms,
        # JWKS endpoints respond with JSON; Req decodes automatically.
        decode_body: true,
        # We handle retry policy at the JwksCache / OIDC layer; Req's
        # default retries are too aggressive for a cache-miss hot path.
        retry: false
      ]

    base =
      if Keyword.has_key?(req_opts, :plug) do
        base
      else
        Keyword.put(base, :finch, finch_pool)
      end

    req = Req.new(Keyword.merge(base, req_opts))

    case Req.get(req) do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        parse_jwks_body(body)

      {:ok, %Req.Response{status: status}} ->
        {:error, {:http_status, status}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  rescue
    # Req can raise on malformed URLs / TLS handshake failures; collapse
    # to {:error, _} rather than crash the Task (async_nolink isolates
    # the cache from the crash, but we want cleaner telemetry).
    exception -> {:error, {:exception, Exception.message(exception)}}
  end

  # JWKS body per RFC 7517: `{"keys": [JWK, JWK, ...]}`. Each JWK has a
  # `"kid"` field; we index by it. Req decodes JSON for us when
  # `decode_body: true` (default), so `body` is already a map.
  defp parse_jwks_body(%{"keys" => keys}) when is_list(keys) do
    indexed =
      Map.new(keys, fn
        %{"kid" => kid} = jwk when is_binary(kid) -> {kid, jwk}
        _jwk -> {nil, nil}
      end)
      |> Map.delete(nil)

    {:ok, indexed}
  end

  defp parse_jwks_body(_other), do: {:error, :malformed_jwks}
end
