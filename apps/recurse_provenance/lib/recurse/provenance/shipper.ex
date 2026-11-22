defmodule Recurse.Provenance.Shipper do
  @moduledoc """
  Moves durable records from a local log into the index and the content
  store.

  It follows one log by a byte cursor. When the log announces a sync, the
  shipper reads the new frames, puts any content they name into the
  content store, inserts the records into the index in one batch, saves
  its cursor, and announces the stream as shipped.

  Every step can be repeated safely: content is addressed by its hash,
  the index ignores a record it already holds, and the cursor is saved
  only after both succeeded. So a crash at any point is handled by doing
  the batch again, and a failure of the index or the content store is
  handled by trying again later. Capture is never held up by either.

  On start it also finishes any segment an earlier incarnation left
  partly shipped.
  """

  use GenServer

  require Logger

  alias Recurse.Provenance.{Capture, Envelope, Evidence, Log, Signals, Staging}

  @retry_ms 2_000
  @read_chunk 8 * 1024 * 1024

  @doc """
  Start a shipper.

    * `:dir` — the log's segment directory
    * `:content_dir` — where content waits under its hash
    * `:staging` — how those files are read (`Recurse.Provenance.Staging`)
    * `:index` — `{module, handle}` implementing `Recurse.Provenance.Store`
    * `:signals` — the signals registry
  """
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "Ship everything durable so far and answer when done. For shutdown and tests."
  @spec sync(GenServer.server()) :: :ok | {:error, term()}
  def sync(shipper), do: GenServer.call(shipper, :sync, 60_000)

  @impl true
  def init(opts) do
    state = %{
      dir: Keyword.fetch!(opts, :dir),
      content_dir: Keyword.fetch!(opts, :content_dir),
      staging: Keyword.get(opts, :staging) || Staging.plain(),
      index: Keyword.fetch!(opts, :index),
      signals: Keyword.fetch!(opts, :signals),
      targets: %{},
      retry: nil
    }

    {:ok, state, {:continue, :recover}}
  end

  # Segments left by an earlier incarnation are shipped to their end.
  @impl true
  def handle_continue(:recover, state) do
    targets =
      for path <- Path.wildcard(Path.join(state.dir, "*.seg")),
          size = File.stat!(path).size,
          size > cursor(path),
          into: %{},
          do: {path, size}

    {:noreply, ship_all(%{state | targets: targets})}
  end

  @impl true
  def handle_info({:durable, path, bytes, _stream, _seq}, state) do
    targets = Map.update(state.targets, path, bytes, &max(&1, bytes))
    {:noreply, ship_all(%{state | targets: targets})}
  end

  def handle_info(:retry, state), do: {:noreply, ship_all(%{state | retry: nil})}

  @impl true
  def handle_call(:sync, _from, state) do
    state = ship_all(state)
    reply = if map_size(state.targets) == 0, do: :ok, else: {:error, :not_shipped}
    {:reply, reply, state}
  end

  defp ship_all(state) do
    remaining =
      Enum.reduce(state.targets, %{}, fn {path, target}, acc ->
        case ship(path, target, state) do
          :ok ->
            acc

          {:error, reason} ->
            Logger.warning(
              "provenance shipper: #{Path.basename(path)} not shipped: #{inspect(reason)}"
            )

            Map.put(acc, path, target)
        end
      end)

    retry =
      cond do
        map_size(remaining) == 0 -> state.retry
        state.retry -> state.retry
        true -> Process.send_after(self(), :retry, @retry_ms)
      end

    %{state | targets: remaining, retry: retry}
  end

  # Ship a segment from its cursor up to `target` bytes, a chunk at a time.
  defp ship(path, target, state) do
    from = cursor(path)

    if from >= target do
      :ok
    else
      with {:ok, bytes} <- read(path, from, min(target - from, @read_chunk)),
           {entries, used} when used > 0 <- Log.decode(bytes),
           :ok <- hold_content(entries, state),
           :ok <- index(entries, state) do
        save_cursor(path, from + used)

        for {stream, seq} <- last_per_stream(entries),
            do: Signals.publish(state.signals, :shipped, stream, seq)

        ship(path, target, state)
      else
        {[], 0} -> {:error, :no_complete_frame}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp read(path, from, length) do
    with {:ok, device} <- :file.open(path, [:raw, :binary, :read]) do
      result = :file.pread(device, from, length)
      :file.close(device)

      case result do
        {:ok, bytes} -> {:ok, bytes}
        :eof -> {:ok, <<>>}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # Content goes to the content store before any record that names it
  # reaches the index, once for each session that refers to it, so that
  # each session's copy can be erased by itself. A file that is no longer
  # waiting was shipped with an earlier record; a session that refers to
  # it now is given its own copy from what is already held.
  #
  # A waiting file that can never be read again (its key no longer
  # exists, or it is not what its name says and has been moved aside) is
  # shipped without: its records go on, and their content is reported as
  # missing, rather than every later record of the stream waiting for
  # ever behind it. The same holds for content that is neither waiting
  # nor held, as when a batch is tried again after such a file was moved
  # aside: nothing will ever bring it back, so waiting for it is no use.
  defp hold_content(entries, %{index: {module, handle}, content_dir: dir, staging: staging}) do
    wanted =
      for %{"content" => [_ | _] = refs} = entry <- entries,
          {:ok, %{evidence: evidence}} <- [Envelope.open(entry["envelope"])],
          ref <- refs,
          uniq: true,
          do: {ref, Evidence.content_scope(evidence)}

    result =
      Enum.reduce_while(wanted, :ok, fn {ref, scope}, :ok ->
        path = Capture.content_path(dir, ref)

        waiting? = File.exists?(path)
        content = if waiting?, do: Staging.content(staging, path), else: {:ok, :held}

        case content do
          {:ok, content} ->
            case module.put_content(handle, ref, content, scope) do
              :ok ->
                {:cont, :ok}

              # Shipped before scopes existed, or by a store that keeps one copy.
              {:error, :not_held} when is_nil(scope) ->
                {:cont, :ok}

              {:error, :not_held} when not waiting? ->
                Logger.error(
                  "provenance shipper: the content #{ref} is neither waiting nor held; " <>
                    "its records are shipped without it"
                )

                {:cont, :ok}

              {:error, {:staged_content_unreadable, why}} ->
                Logger.error(
                  "provenance shipper: the waiting content #{ref} is unreadable " <>
                    "(#{inspect(why)}); it was moved aside and its records are shipped without it"
                )

                {:cont, :ok}

              {:error, reason} ->
                {:halt, {:error, {:content_not_held, ref, reason}}}
            end

          {:error, {:staged_content_unreadable, why}} ->
            Logger.error(
              "provenance shipper: the waiting content #{ref} is unreadable " <>
                "(#{inspect(why)}); its records are shipped without it"
            )

            {:cont, :ok}

          {:error, :staged_content_lost} ->
            Logger.error(
              "provenance shipper: the waiting content #{ref} can no longer be read " <>
                "(its staging key is gone); its records are shipped without it"
            )

            {:cont, :ok}

          {:error, reason} ->
            {:halt, {:error, {:content_not_held, ref, reason}}}
        end
      end)

    with :ok <- result do
      wanted
      |> Enum.map(&elem(&1, 0))
      |> Enum.uniq()
      |> Enum.each(&File.rm(Capture.content_path(dir, &1)))

      :ok
    end
  end

  defp index(entries, %{index: {module, handle}}) do
    rows =
      for entry <- entries do
        {:ok, %{evidence: evidence}} = Envelope.open(entry["envelope"])

        %{
          ref: entry["ref"],
          stream: entry["stream"],
          seq: entry["seq"],
          kind_path: entry["kind"],
          envelope: entry["envelope"],
          evidence: evidence
        }
      end

    module.append_many(handle, rows)
  end

  defp last_per_stream(entries),
    do: Enum.reduce(entries, %{}, fn e, acc -> Map.put(acc, e["stream"], e["seq"]) end)

  defp cursor(path) do
    case File.read(path <> ".cursor") do
      {:ok, text} -> String.to_integer(String.trim(text))
      {:error, _} -> 0
    end
  end

  # Written beside the segment and renamed into place, so a crash leaves
  # either the old cursor or the new one.
  defp save_cursor(path, offset) do
    partial = path <> ".cursor.partial"
    File.write!(partial, Integer.to_string(offset))
    File.rename!(partial, path <> ".cursor")
  end
end
