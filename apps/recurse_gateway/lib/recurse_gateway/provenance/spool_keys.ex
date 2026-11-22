defmodule Recurse.Gateway.Provenance.SpoolKeys do
  @moduledoc """
  Holds the keys recorded content is encrypted under while it waits on
  this gateway's disk (`Recurse.Gateway.Provenance.Spool`), and retires
  them once nothing waits under them.

  ## The keys

    * **Spool identity.** An X25519 key pair per deployment. Its public
      half is on disk; its private half is on disk only locked by the
      customer's key service (`Recurse.Providers.KeyService.wrap/3`, with
      context `urn:r5e:spool-identity:<deployment>:<id>:<sha256(public)>`,
      so a locked key moved to another identity, or a public key swapped
      on disk, does not unlock). It is written once, wrapped private key
      and public key together in one file, fsynced and renamed into place
      and its directory fsynced, before anything is sealed to it.
    * **Epoch keys.** A random 32-byte key per epoch. Every new file is
      written under the current epoch. A new epoch begins at start, every
      `epoch_seconds`, and whenever a disposal is recorded. An epoch's key
      is sealed to the identity's public key (no key service call) and
      written to disk, fsynced, before it is used for a single byte.

  So encrypting needs nothing but memory: no key service call and no
  public-key operation on any request. Reading back what an earlier run
  left behind needs the identity's private key, and so the key service.
  It is unlocked at start (and retried in the background while the key
  service cannot be reached), used to open the earlier epochs' keys, and
  dropped again.

  If the key service cannot be reached the very first time a deployment
  starts, no identity can be written. The gateway still records: the
  current epoch's key is then held in memory only, and sealed to disk as
  soon as an identity can be made. Content written in that window and
  not yet shipped is lost if the gateway stops before then; this is
  logged. It is the only window in which a stop loses waiting content.

  ## Retiring

  An epoch that is no longer current, has been so for `grace_seconds`,
  and under which no file waits (in the spool or the content directory)
  is retired: its key is dropped from memory and its sealed key file
  overwritten with zeros, synced and removed. From then on nothing
  written under it can be read, including whatever is left of shipped
  and removed files in freed disk blocks. Overwriting in place is
  best-effort on copy-on-write file systems and SSDs (APFS among them):
  old blocks of the sealed key file may survive, but they open only with
  the identity's private key, that is with the customer's key service,
  whose administrator can end even that by retiring the key version.
  Operators should drain waiting spool content before disabling a KMS key
  version or raising OpenBao Transit's `min_decryption_version`: when the
  key service reports `:key_not_available` at startup, this process treats
  that spool identity as permanently gone (`lose_identity`), wipes its
  wrapped identity and waiting epoch keys so the stream does not wedge,
  and will not recover those epochs even if the key version is later
  re-enabled.

  ## What is in memory

  Epoch keys live in a `:protected` ETS table owned by this process, so
  that capture reads them without a message round trip. Like any memory
  of this node they are readable by code running in the node and are
  included in crash dumps; `format_status/1` keeps them out of crash
  reports of this process. The identity's private key is held only while
  earlier epochs are being opened.

  ## Files that are not waiting for anything

  A temporary file of a call whose process died is removed a little
  after the process went (`orphan_grace_seconds`); at start, any left by
  an earlier run of the node are removed. A file placed in the content
  directory whose record never reached the log (the gateway stopped in
  between) is removed after the pipeline has been flushed and shipped
  completely, when it is older than `gc_margin_seconds` before the flush
  began. `Recurse.Provenance.Pipeline.flush/1` answers `:ok` only when
  every shipper has put every record captured before it into the index
  and the content they name into the content store; during an outage of
  either it answers an error and nothing is removed, however long the
  outage lasts. After an `:ok`, a file that old is named by no record
  still waiting, and shipped content is no longer needed on disk. Placing
  content that already waits touches the file, so a file still wanted by
  a newer record is never that old.
  """

  use GenServer

  require Logger

  alias Recurse.Gateway.Provenance.Spool

  @table __MODULE__
  @default_epoch_seconds 900
  @default_grace_seconds 60
  @default_sweep_ms 30_000
  @default_gc_ms 300_000
  @default_gc_margin_seconds 600
  @default_orphan_grace_seconds 120
  @retry_ms 5_000
  @verify_timeout_ms 5_000

  # -- reading keys (any process) -------------------------------------------

  @doc "Whether encrypted staging is running on this node."
  @spec running?() :: boolean()
  def running?, do: :ets.whereis(@table) != :undefined

  @doc "The current epoch and its key, for writing."
  @spec current() :: {:ok, Spool.epoch_id(), Spool.key()} | :error
  def current do
    case :ets.lookup(@table, :current) do
      [{:current, epoch, dek}] -> {:ok, epoch, dek}
      [] -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @doc """
  The key of an epoch, for reading. `{:error, {:key_service_unavailable,
  _}}` while the identity that opens it cannot be unlocked yet;
  `{:error, :staged_content_lost}` when it never will be.
  """
  @spec fetch(Spool.epoch_id()) :: {:ok, Spool.key()} | {:error, term()}
  def fetch(<<_::128>> = epoch) do
    case :ets.lookup(@table, {:epoch, epoch}) do
      [{_, :ready, dek}] -> {:ok, dek}
      [{_, :pending}] -> {:error, {:key_service_unavailable, :spool_identity_locked}}
      [{_, :lost}] -> {:error, :staged_content_lost}
      [] -> {:error, :staged_content_lost}
    end
  rescue
    ArgumentError -> {:error, {:key_service_unavailable, :spool_keys_not_running}}
  end

  def fetch(_other), do: {:error, :staged_content_lost}

  @doc "Where streaming calls keep their temporary files."
  @spec spool_dir() :: Path.t() | nil
  def spool_dir do
    case :ets.lookup(@table, :spool_dir) do
      [{:spool_dir, dir}] -> dir
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @doc """
  Note a temporary file owned by the calling process, so it is removed
  if that process dies without finishing with it. Never waits.
  """
  @spec watch(Path.t()) :: :ok
  def watch(path), do: GenServer.cast(__MODULE__, {:watch, self(), path})

  @doc """
  A temporary file noted with `watch/1` has been finished with or
  removed by its owner. A process that serves many calls would otherwise
  be watched once more for each of them until it ends. Never waits.
  """
  @spec unwatch(Path.t()) :: :ok
  def unwatch(path) do
    if running?(), do: GenServer.cast(__MODULE__, {:unwatch, path})
    :ok
  end

  @doc "Begin a new epoch now, as after a disposal. Never waits."
  @spec rotate_async() :: :ok
  def rotate_async do
    if running?(), do: GenServer.cast(__MODULE__, :rotate)
    :ok
  end

  @doc "Begin a new epoch and answer when it is in use. For tests."
  @spec rotate() :: :ok
  def rotate, do: GenServer.call(__MODULE__, :rotate_now, 30_000)

  @doc "Retire what can be retired now and answer which epochs remain. For tests."
  @spec sweep() :: %{current: Spool.epoch_id(), held: [Spool.epoch_id()]}
  def sweep, do: GenServer.call(__MODULE__, :sweep_now, 60_000)

  @doc "Remove content files no record waits for, now. For tests."
  @spec collect() :: {:ok, non_neg_integer()} | {:error, term()}
  def collect, do: GenServer.call(__MODULE__, :collect_now, 120_000)

  # -- process -----------------------------------------------------------------

  @doc """
  Start the key holder.

    * `:dir` — the deployment's evidence directory (required)
    * `:deployment` — the deployment id (required)
    * `:keys` — `{module, state}` of a `Recurse.Providers.KeyService` (required)
    * `:pipeline` — the pipeline whose content directory is swept
    * `:epoch_seconds`, `:grace_seconds`, `:sweep_ms`, `:gc_ms`,
      `:gc_margin_seconds`, `:orphan_grace_seconds` — see the moduledoc
    * `:retry_ms` — how often an identity that cannot be unlocked or
      written yet is tried again (default #{@retry_ms})
  """
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    dir = Keyword.fetch!(opts, :dir)
    keys_dir = Path.join(dir, "spool-keys")
    spool = Path.join(dir, "spool")
    content = Path.join(dir, "content")

    for d <- [dir, keys_dir, spool, content, Path.join(dir, "quarantine")] do
      File.mkdir_p!(d)
      File.chmod!(d, 0o700)
    end

    table = :ets.new(@table, [:named_table, :protected, :set, read_concurrency: true])
    :ets.insert(table, {:spool_dir, spool})

    state = %{
      deployment: Keyword.fetch!(opts, :deployment),
      keys: Keyword.fetch!(opts, :keys),
      keys_dir: keys_dir,
      spool_dir: spool,
      content_dir: content,
      pipeline: Keyword.get(opts, :pipeline),
      epoch_seconds: Keyword.get(opts, :epoch_seconds, @default_epoch_seconds),
      grace_seconds: Keyword.get(opts, :grace_seconds, @default_grace_seconds),
      gc_margin_seconds: Keyword.get(opts, :gc_margin_seconds, @default_gc_margin_seconds),
      orphan_grace_ms:
        Keyword.get_lazy(opts, :orphan_grace_ms, fn ->
          Keyword.get(opts, :orphan_grace_seconds, @default_orphan_grace_seconds) * 1000
        end),
      identity: nil,
      identities: %{},
      # epoch => %{since: monotonic seconds it stopped being current | nil,
      #            identity: id | nil (memory-only), file: path | nil}
      epochs: %{},
      current: nil,
      watched: %{},
      retry: nil,
      retry_ms: Keyword.get(opts, :retry_ms, @retry_ms)
    }

    sweep_orphans_from_earlier_runs(spool)

    state =
      state
      |> load_identities()
      |> load_epochs()
      |> open_or_make_identity()
      |> new_epoch()

    schedule(:rotate, state.epoch_seconds * 1000)
    schedule(:sweep, Keyword.get(opts, :sweep_ms, @default_sweep_ms))
    schedule(:collect, Keyword.get(opts, :gc_ms, @default_gc_ms))

    {:ok,
     Map.merge(state, %{
       sweep_ms: Keyword.get(opts, :sweep_ms, @default_sweep_ms),
       gc_ms: Keyword.get(opts, :gc_ms, @default_gc_ms)
     })}
  end

  # Nothing secret in a crash report of this process.
  @impl true
  def format_status(status) do
    Map.update(status, :state, nil, fn
      %{} = state -> Map.drop(state, [:identities, :epochs, :keys]) |> Map.put(:keys, :redacted)
      other -> other
    end)
  end

  @impl true
  def handle_cast(:rotate, state), do: {:noreply, rotate_now(state)}

  def handle_cast({:watch, pid, path}, state) do
    ref = Process.monitor(pid)
    {:noreply, %{state | watched: Map.put(state.watched, ref, path)}}
  end

  def handle_cast({:unwatch, path}, state) do
    case Enum.find(state.watched, fn {_ref, watched} -> watched == path end) do
      {ref, _path} ->
        Process.demonitor(ref, [:flush])
        {:noreply, %{state | watched: Map.delete(state.watched, ref)}}

      nil ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:rotate_now, _from, state), do: {:reply, :ok, rotate_now(state)}

  def handle_call(:sweep_now, _from, state) do
    state = retire(state, in_use(state), System.monotonic_time(:second))
    {:reply, %{current: state.current, held: Map.keys(state.epochs) -- [state.current]}, state}
  end

  def handle_call(:collect_now, _from, state), do: {:reply, collect_now(state), state}

  @impl true
  def handle_info(:rotate, state) do
    schedule(:rotate, state.epoch_seconds * 1000)
    {:noreply, rotate_now(state)}
  end

  def handle_info(:sweep, state) do
    schedule(:sweep, state.sweep_ms)
    me = self()
    started = System.monotonic_time(:second)
    dirs = {state.spool_dir, state.content_dir}
    Task.start(fn -> send(me, {:in_use, scan(dirs), started}) end)
    {:noreply, state}
  end

  def handle_info({:in_use, used, started}, state), do: {:noreply, retire(state, used, started)}

  def handle_info(:collect, state) do
    schedule(:collect, state.gc_ms)
    snapshot = Map.take(state, [:pipeline, :content_dir, :gc_margin_seconds])
    Task.start(fn -> collect_now(snapshot) end)
    {:noreply, state}
  end

  def handle_info(:retry_identity, state),
    do: {:noreply, open_or_make_identity(%{state | retry: nil})}

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    {path, watched} = Map.pop(state.watched, ref)
    if path, do: Process.send_after(self(), {:reap, path}, state.orphan_grace_ms)
    {:noreply, %{state | watched: watched}}
  end

  # A call that ended normally removed or moved its file long ago.
  def handle_info({:reap, path}, state) do
    case File.rm(path) do
      :ok -> Logger.info("evidence: removed the temporary file of a call that did not finish")
      _ -> :ok
    end

    {:noreply, state}
  end

  def handle_info(_other, state), do: {:noreply, state}

  # -- identity ----------------------------------------------------------------

  defp load_identities(state) do
    identities =
      for path <- Path.wildcard(Path.join(state.keys_dir, "identity-*.json")),
          {:ok, text} <- [File.read(path)],
          {:ok, %{"identity" => id, "public" => pub64, "wrapped" => wrapped64} = doc} <-
            [Jason.decode(text)],
          doc["deployment"] == state.deployment,
          id =~ ~r/\A[0-9a-f]{32}\z/,
          {:ok, <<_::256>> = public} <- [Base.decode64(pub64)],
          {:ok, wrapped} <- [Base.decode64(wrapped64)],
          into: %{} do
        {id,
         %{
           public: public,
           wrapped: wrapped,
           created: doc["createdAt"],
           private: nil,
           verified?: false
         }}
      end

    newest =
      identities
      |> Enum.max_by(fn {_id, i} -> i.created end, fn -> nil end)
      |> case do
        nil -> nil
        {id, _} -> id
      end

    %{state | identities: identities, identity: newest}
  end

  # Unlock the identities (to check each public key and to open what earlier
  # runs left), or make one if there is none.
  defp open_or_make_identity(state) do
    state = Enum.reduce(Map.keys(state.identities), state, &unlock_identity/2)
    state = if is_nil(state.identity), do: make_identity(state), else: state
    state = reseal_epochs(state) |> drop_private_keys()

    waiting? =
      is_nil(state.identity) or
        Enum.any?(state.identities, fn {_, i} -> not i.verified? and not lost?(i) end)

    if waiting? and is_nil(state.retry),
      do: %{state | retry: Process.send_after(self(), :retry_identity, state.retry_ms)},
      else: state
  end

  defp unlock_identity(id, state) do
    identity = state.identities[id]

    cond do
      identity.verified? or lost?(identity) ->
        state

      true ->
        case bounded(fn -> unwrap(state, id, identity) end) do
          {:ok, private} ->
            if Spool.public_of(private) == identity.public do
              identity = %{identity | private: private, verified?: true}
              state = put_in(state.identities[id], identity)
              open_epochs_of(state, id, private)
            else
              # Unlocking binds the public key, so this means the file was
              # altered after the unlock check was made. Never seal to it.
              Logger.error(
                "evidence: spool identity #{id} does not match its public key; it is not used"
              )

              lose_identity(state, id)
            end

          {:error, :not_unwrappable} ->
            Logger.error(
              "evidence: the key service can no longer unlock spool identity #{id} " <>
                "(its key was retired); content waiting under it cannot be read"
            )

            lose_identity(state, id)

          {:error, reason} ->
            Logger.warning(
              "evidence: spool identity #{id} cannot be unlocked yet (#{inspect(reason)}); " <>
                "content an earlier run left waiting is shipped once it can"
            )

            state
        end
    end
  end

  defp lost?(identity), do: Map.get(identity, :lost?, false)

  # Epochs whose keys are only on disk under this identity can no longer
  # be opened. Those begun in this run still have their keys in memory
  # and are sealed again to another identity by `reseal_epochs/1`.
  defp lose_identity(state, id) do
    state = put_in(state.identities[id], Map.put(state.identities[id], :lost?, true))

    for {epoch, %{identity: ^id}} <- state.epochs,
        not match?([{_, :ready, _}], :ets.lookup(@table, {:epoch, epoch})) do
      :ets.insert(@table, {{:epoch, epoch}, :lost})
    end

    if state.identity == id, do: %{state | identity: nil}, else: state
  end

  defp make_identity(state) do
    {public, private} = Spool.identity_keypair()
    id = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

    with {:ok, wrapped} <- bounded(fn -> wrap(state, id, public, private) end),
         :ok <-
           write_durably(Path.join(state.keys_dir, "identity-#{id}.json"), %{
             "v" => 1,
             "deployment" => state.deployment,
             "identity" => id,
             "public" => Base.encode64(public),
             "wrapped" => Base.encode64(wrapped),
             "keyService" => describe(state),
             "createdAt" => DateTime.utc_now() |> DateTime.to_iso8601()
           }) do
      Logger.info(
        "evidence: content waiting on this gateway's disk is encrypted (spool identity #{id})"
      )

      identity = %{public: public, wrapped: wrapped, created: nil, private: nil, verified?: true}
      %{state | identity: id, identities: Map.put(state.identities, id, identity)}
    else
      {:error, reason} ->
        Logger.error(
          "evidence: no spool identity could be written (#{inspect(reason)}); content waiting " <>
            "on this gateway's disk is encrypted under a key held in memory only, and is lost if " <>
            "the gateway stops before the key service can be reached"
        )

        state
    end
  end

  defp context(state, id, public),
    do:
      "urn:r5e:spool-identity:#{state.deployment}:#{id}:" <>
        Base.encode16(:crypto.hash(:sha256, public), case: :lower)

  defp wrap(%{keys: {module, keys}} = state, id, public, private),
    do: module.wrap(keys, private, context(state, id, public))

  defp unwrap(%{keys: {module, keys}} = state, id, identity),
    do: module.unwrap(keys, identity.wrapped, context(state, id, identity.public))

  defp describe(%{keys: {module, keys}}), do: module.describe(keys)

  # A key service that does not answer must not hold up the gateway's start.
  defp bounded(fun) do
    task = Task.async(fn -> safely(fun) end)

    case Task.yield(task, @verify_timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> result
      _ -> {:error, {:key_service_unavailable, :timeout}}
    end
  end

  defp safely(fun) do
    fun.()
  rescue
    error -> {:error, {:key_service_unavailable, Exception.message(error)}}
  end

  defp drop_private_keys(state) do
    identities = Map.new(state.identities, fn {id, i} -> {id, %{i | private: nil}} end)
    %{state | identities: identities}
  end

  # -- epochs ------------------------------------------------------------------

  defp load_epochs(state) do
    now = System.monotonic_time(:second)

    epochs =
      for path <- Path.wildcard(Path.join(state.keys_dir, "epoch-*.json")),
          {:ok, text} <- [File.read(path)],
          {:ok, %{"epoch" => hex, "identity" => id} = doc} <- [Jason.decode(text)],
          doc["deployment"] == state.deployment,
          hex =~ ~r/\A[0-9a-f]{32}\z/,
          into: %{} do
        epoch = Base.decode16!(hex, case: :lower)
        :ets.insert(@table, {{:epoch, epoch}, :pending})
        {epoch, %{since: now, identity: id, file: path, doc: doc}}
      end

    %{state | epochs: epochs}
  end

  defp open_epochs_of(state, id, private) do
    Enum.reduce(state.epochs, state, fn
      {epoch, %{identity: ^id, doc: doc}}, state ->
        with {:ok, e} <- Base.decode64(doc["ephemeral"] || ""),
             {:ok, sealed} <- Base.decode64(doc["sealed"] || ""),
             {:ok, dek} <- Spool.open_epoch(e, sealed, epoch, state.deployment, private) do
          :ets.insert(@table, {{:epoch, epoch}, :ready, dek})
        else
          _ ->
            Logger.error(
              "evidence: spool epoch #{Base.encode16(epoch, case: :lower)} cannot be opened"
            )

            :ets.insert(@table, {{:epoch, epoch}, :lost})
        end

        state

      _other, state ->
        state
    end)
  end

  defp new_epoch(state) do
    epoch = :crypto.strong_rand_bytes(16)
    dek = :crypto.strong_rand_bytes(32)

    state =
      case seal_to_identity(state, epoch, dek) do
        {:ok, file} ->
          put_in(state.epochs[epoch], %{
            since: nil,
            identity: state.identity,
            file: file,
            doc: nil
          })

        :memory_only ->
          put_in(state.epochs[epoch], %{since: nil, identity: nil, file: nil, doc: nil})
      end

    # Written and synced before a single byte is encrypted under it.
    :ets.insert(@table, {{:epoch, epoch}, :ready, dek})
    :ets.insert(@table, {:current, epoch, dek})

    now = System.monotonic_time(:second)

    epochs =
      Map.new(state.epochs, fn
        {^epoch, e} -> {epoch, e}
        {other, %{since: nil} = e} -> {other, %{e | since: now}}
        pair -> pair
      end)

    %{state | epochs: epochs, current: epoch}
  end

  defp seal_to_identity(%{identity: nil}, _epoch, _dek), do: :memory_only

  defp seal_to_identity(state, epoch, dek) do
    identity = state.identities[state.identity]
    hex = Base.encode16(epoch, case: :lower)

    with {:ok, %{ephemeral: e, sealed: sealed}} <-
           Spool.seal_epoch(dek, epoch, state.deployment, identity.public),
         path = Path.join(state.keys_dir, "epoch-#{hex}.json"),
         :ok <-
           write_durably(path, %{
             "v" => 1,
             "deployment" => state.deployment,
             "epoch" => hex,
             "identity" => state.identity,
             "ephemeral" => Base.encode64(e),
             "sealed" => Base.encode64(sealed),
             "createdAt" => DateTime.utc_now() |> DateTime.to_iso8601()
           }) do
      {:ok, path}
    else
      error ->
        Logger.error(
          "evidence: a spool epoch key could not be written (#{inspect(error)}); held in memory only"
        )

        :memory_only
    end
  end

  # An epoch whose key is in memory but sealed to no usable identity (one
  # begun while there was none, or sealed to an identity found not to be
  # what it claimed) is sealed to the current identity as soon as there
  # is one, and the old sealed file is removed.
  defp reseal_epochs(%{identity: nil} = state), do: state

  defp reseal_epochs(state) do
    Enum.reduce(state.epochs, state, fn {epoch, e}, state ->
      usable? = e.identity != nil and not lost?(Map.get(state.identities, e.identity, %{}))

      case {usable?, :ets.lookup(@table, {:epoch, epoch})} do
        {false, [{_, :ready, dek}]} ->
          case seal_to_identity(state, epoch, dek) do
            {:ok, file} ->
              if e.file && e.file != file, do: shred(e.file)
              put_in(state.epochs[epoch], %{e | identity: state.identity, file: file})

            :memory_only ->
              state
          end

        _ ->
          state
      end
    end)
  end

  defp rotate_now(state), do: new_epoch(state)

  # -- retiring -----------------------------------------------------------------

  defp scan({spool, content}) do
    for dir <- [spool, content],
        name <- ls(dir),
        path = Path.join(dir, name),
        {:ok, epoch} <- [Spool.epoch_of(path)],
        into: MapSet.new(),
        do: epoch
  end

  defp in_use(state), do: scan({state.spool_dir, state.content_dir})

  defp ls(dir) do
    case File.ls(dir) do
      {:ok, names} -> names
      _ -> []
    end
  end

  # Only epochs that were already past their grace when the scan began are
  # retired, so a file begun under an epoch just before it stopped being
  # current is always seen.
  defp retire(state, used, scan_started) do
    Enum.reduce(state.epochs, state, fn
      {epoch, %{since: since} = e}, state
      when epoch != state.current and is_integer(since) ->
        if since + state.grace_seconds <= scan_started and not MapSet.member?(used, epoch) do
          :ets.delete(@table, {:epoch, epoch})
          if e.file, do: shred(e.file)
          %{state | epochs: Map.delete(state.epochs, epoch)}
        else
          state
        end

      _other, state ->
        state
    end)
  end

  defp shred(path) do
    with {:ok, %{size: size}} <- File.stat(path),
         {:ok, device} <- :file.open(path, [:raw, :binary, :write, :read]) do
      _ = :file.pwrite(device, 0, :binary.copy(<<0>>, size))
      _ = :file.datasync(device)
      :file.close(device)
    end

    _ = File.rm(path)
    sync_dir(Path.dirname(path))
  end

  # -- files no record waits for --------------------------------------------------

  defp collect_now(%{pipeline: nil}), do: {:ok, 0}

  defp collect_now(%{pipeline: pipeline, content_dir: dir, gc_margin_seconds: margin}) do
    started = System.os_time(:second)

    case Recurse.Provenance.Pipeline.flush(pipeline) do
      :ok ->
        limit = started - margin

        removed =
          for name <- ls(dir),
              path = Path.join(dir, name),
              {:ok, %{mtime: mtime, type: :regular}} <- [File.stat(path, time: :posix)],
              mtime < limit,
              File.rm(path) == :ok,
              reduce: 0,
              do: (n -> n + 1)

        if removed > 0,
          do:
            Logger.info(
              "evidence: removed #{removed} waiting content file(s) no record refers to"
            )

        {:ok, removed}

      error ->
        error
    end
  catch
    :exit, reason -> {:error, {:not_flushed, reason}}
  end

  # A file left by an earlier run of this node belonged to a call that can
  # no longer finish: no record refers to it.
  defp sweep_orphans_from_earlier_runs(spool) do
    {uptime_ms, _} = :erlang.statistics(:wall_clock)
    started = System.os_time(:second) - div(uptime_ms, 1000) - 1

    for name <- ls(spool),
        path = Path.join(spool, name),
        {:ok, %{mtime: mtime}} <- [File.stat(path, time: :posix)],
        mtime < started,
        do: File.rm(path)
  end

  # -- files ----------------------------------------------------------------------

  # Written beside, synced, renamed into place, and the directory synced,
  # so the file is either absent or whole, and is on disk when this returns.
  defp write_durably(path, doc) do
    partial = path <> ".partial-" <> Integer.to_string(System.unique_integer([:positive]))

    with {:ok, device} <- :file.open(partial, [:raw, :binary, :write, :exclusive]),
         :ok <- :file.change_mode(partial, 0o600),
         :ok <- :file.write(device, Jason.encode!(doc)),
         :ok <- :file.sync(device),
         :ok <- :file.close(device),
         :ok <- :file.rename(partial, path) do
      sync_dir(Path.dirname(path))
    else
      error ->
        _ = File.rm(partial)
        error
    end
  end

  defp sync_dir(dir) do
    with {:ok, device} <- :file.open(dir, [:raw, :read, :directory]) do
      _ = :file.sync(device)
      :file.close(device)
    end

    :ok
  rescue
    _ -> :ok
  end

  defp schedule(message, ms) when is_integer(ms) and ms > 0,
    do: Process.send_after(self(), message, ms)

  defp schedule(_message, _ms), do: nil
end
