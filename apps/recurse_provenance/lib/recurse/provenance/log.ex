defmodule Recurse.Provenance.Log do
  @moduledoc """
  The local, append-only file behind one stream.

  This process owns one open file, which is why it exists: a file has
  one writer. Signed records arrive as messages and are held briefly.
  On a size or time threshold the whole batch is written with a single
  write and a single sync, and only then is the stream announced as
  durable through the last position in the batch.

  Batching is where the speed comes from. Syncing once for a hundred
  records costs about the same as syncing once for one.

  A record that has been signed and not yet synced is lost if the node
  dies. That window is `:flush_interval_ms`, and it is the one number an
  operator chooses here.

  ## File format

  A segment is a sequence of frames: a four-byte big-endian length, then
  that many bytes of JSON holding `seq`, `ref`, `kind`, `envelope` and
  the references of any `content` the record submitted. Each envelope is
  independently signed, so the file needs no integrity structure of its
  own. A torn final frame after a crash is detected by its length and
  ignored.

  ## Clean and unclean stops

  Records signed in the last moments before a node dies never reach the
  file, and nothing in the stream points at them, so the loss cannot be
  seen from the records alone. The log therefore leaves a mark of its
  own. A log that is shut down in order flushes and writes a `.closed`
  file beside its segment. A segment found without one belonged to a
  log that died, and `begin/2` reports it to the next writer with the
  last position that did reach the disk, so the writer can open its new
  stream by saying so.
  """

  use GenServer

  alias Recurse.Provenance.Signals

  @default_interval_ms 1_000
  @default_max_batch 500

  @type entry :: %{
          stream: String.t(),
          seq: pos_integer(),
          ref: String.t(),
          kind_path: String.t(),
          envelope: map(),
          content: [String.t()]
        }

  @doc """
  Start a log.

    * `:dir` — directory for segment files
    * `:signals` — the signals registry
    * `:notify` — the name of a process told
      `{:durable, path, bytes, stream, seq}` after every sync (the shipper
      for this log)
    * `:flush_interval_ms` — longest a record waits before being synced
      (default #{@default_interval_ms})
    * `:max_batch` — records that force a sync early (default #{@default_max_batch})
  """
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "Queue a signed record for the next batch. Never blocks the caller."
  @spec append(GenServer.server(), entry()) :: :ok
  def append(log, entry), do: GenServer.cast(log, {:append, entry})

  @doc "Write and sync whatever is queued now. For shutdown and tests."
  @spec flush(GenServer.server()) :: :ok
  def flush(log), do: GenServer.call(log, :flush, 30_000)

  @typedoc "A stream whose log stopped without closing, and how far it got."
  @type unclean :: %{
          stream: String.t(),
          last_seq: non_neg_integer(),
          last_ref: String.t() | nil
        }

  @doc """
  Name the stream this log now holds, and learn which earlier streams in
  the same directory stopped uncleanly. Called once by the writer before
  its first record. Each unclean stream is reported until a batch that
  follows this call has been synced, so the writer's record of it is on
  disk before the log stops reporting it.
  """
  @spec begin(GenServer.server(), String.t()) :: [unclean()]
  def begin(log, stream), do: GenServer.call(log, {:begin, stream}, 30_000)

  @doc "Encode one entry as a frame."
  @spec frame(entry()) :: iodata()
  def frame(entry) do
    json =
      Jason.encode_to_iodata!(%{
        "stream" => entry.stream,
        "seq" => entry.seq,
        "ref" => entry.ref,
        "kind" => entry.kind_path,
        "envelope" => entry.envelope,
        "content" => entry.content
      })

    [<<IO.iodata_length(json)::unsigned-big-32>>, json]
  end

  @doc """
  Decode the complete frames at the start of `bytes`. Returns the entries
  and how many bytes they occupied; a partial final frame is left alone.
  """
  @spec decode(binary()) :: {[map()], non_neg_integer()}
  def decode(bytes), do: decode(bytes, [], 0)

  defp decode(<<size::unsigned-big-32, json::binary-size(size), rest::binary>>, acc, used) do
    case Jason.decode(json) do
      {:ok, entry} -> decode(rest, [entry | acc], used + 4 + size)
      {:error, _} -> {Enum.reverse(acc), used}
    end
  end

  defp decode(_partial, acc, used), do: {Enum.reverse(acc), used}

  @impl true
  def init(opts) do
    # Trapping exits is what lets `terminate/2` flush and mark the
    # segment closed when the supervisor shuts this process down.
    Process.flag(:trap_exit, true)

    dir = Keyword.fetch!(opts, :dir)
    File.mkdir_p!(dir)
    unclean = find_unclean(dir)

    path =
      Path.join(dir, "#{System.os_time(:microsecond)}-#{System.unique_integer([:positive])}.seg")

    {:ok, device} = :file.open(path, [:raw, :binary, :append])

    {:ok,
     %{
       path: path,
       device: device,
       bytes: 0,
       unclean: unclean,
       pending: [],
       pending_count: 0,
       timer: nil,
       signals: Keyword.fetch!(opts, :signals),
       notify: Keyword.get(opts, :notify),
       interval: Keyword.get(opts, :flush_interval_ms, @default_interval_ms),
       max_batch: Keyword.get(opts, :max_batch, @default_max_batch)
     }}
  end

  @impl true
  def handle_cast({:append, entry}, state) do
    state = %{state | pending: [entry | state.pending], pending_count: state.pending_count + 1}

    cond do
      state.pending_count >= state.max_batch ->
        {:noreply, write(state)}

      is_nil(state.timer) ->
        {:noreply, %{state | timer: Process.send_after(self(), :flush, state.interval)}}

      true ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:flush, _from, state), do: {:reply, :ok, write(state)}

  def handle_call({:begin, stream}, _from, state) do
    File.write!(state.path <> ".stream", stream)
    {:reply, Enum.map(state.unclean, &elem(&1, 1)), state}
  end

  @impl true
  def handle_info(:flush, state), do: {:noreply, write(%{state | timer: nil})}

  # A linked process exiting is not a message this log acts on.
  def handle_info({:EXIT, _from, _reason}, state), do: {:noreply, state}

  # Only an orderly stop is marked closed. After a crash the writer may
  # have signed records this process never received, so the segment is
  # left unmarked for the next log to report.
  @impl true
  def terminate(reason, state) do
    write(state)
    :file.close(state.device)

    if reason in [:normal, :shutdown] or match?({:shutdown, _}, reason),
      do: File.write(state.path <> ".closed", "clean\n")

    :ok
  end

  defp write(%{pending: []} = state), do: cancel(state)

  defp write(state) do
    entries = Enum.reverse(state.pending)
    frames = Enum.map(entries, &frame/1)

    # One write and one sync for the whole batch. A failure here crashes
    # the log on purpose: its supervisor restarts it together with the
    # writer, which opens a new stream instead of continuing a chain whose
    # tail may not be on disk.
    :ok = :file.write(state.device, frames)
    :ok = :file.datasync(state.device)

    bytes = state.bytes + IO.iodata_length(frames)

    for {stream, last} <- last_per_stream(entries) do
      Signals.publish(state.signals, :durable, stream, last)
      notify(state.notify, {:durable, state.path, bytes, stream, last})
    end

    cancel(%{acknowledge_unclean(state) | pending: [], pending_count: 0, bytes: bytes})
  end

  # The writer's records about earlier unclean stops were in a batch that
  # is now on disk, so those segments need not be reported again.
  defp acknowledge_unclean(%{unclean: []} = state), do: state

  defp acknowledge_unclean(state) do
    for {path, _report} <- state.unclean, do: File.write(path <> ".closed", "unclean\n")
    %{state | unclean: []}
  end

  # Segments in `dir` with no `.closed` mark, with the last record each
  # holds. A segment whose stream was never named held nothing and is
  # closed here.
  defp find_unclean(dir) do
    for path <- Path.wildcard(Path.join(dir, "*.seg")),
        not File.exists?(path <> ".closed"),
        report = last_record(path),
        do: {path, report}
  end

  defp last_record(path) do
    case last_frame(path) do
      %{"stream" => stream, "seq" => seq, "ref" => ref} ->
        %{stream: stream, last_seq: seq, last_ref: ref}

      nil ->
        case File.read(path <> ".stream") do
          {:ok, stream} ->
            %{stream: stream, last_seq: 0, last_ref: nil}

          {:error, _} ->
            File.write(path <> ".closed", "empty\n")
            nil
        end
    end
  end

  # Walk the frame lengths to the last complete frame and decode only it.
  defp last_frame(path) do
    with {:ok, device} <- :file.open(path, [:raw, :binary, :read]) do
      size = File.stat!(path).size
      last = walk(device, 0, size, nil)

      frame =
        with {offset, length} <- last,
             {:ok, json} <- :file.pread(device, offset + 4, length),
             {:ok, entry} <- Jason.decode(json) do
          entry
        else
          _ -> nil
        end

      :file.close(device)
      frame
    else
      _ -> nil
    end
  end

  defp walk(device, offset, size, last) do
    with true <- offset + 4 <= size,
         {:ok, <<length::unsigned-big-32>>} <- :file.pread(device, offset, 4),
         true <- offset + 4 + length <= size do
      walk(device, offset + 4 + length, size, {offset, length})
    else
      _ -> last
    end
  end

  # The shipper is named, not held by pid, so a message reaches whichever
  # process currently has that name.
  defp notify(nil, _message), do: :ok

  defp notify(name, message) do
    case GenServer.whereis(name) do
      nil -> :ok
      pid -> send(pid, message)
    end
  end

  defp last_per_stream(entries) do
    Enum.reduce(entries, %{}, fn e, acc -> Map.put(acc, e.stream, e.seq) end)
  end

  defp cancel(%{timer: nil} = state), do: state

  defp cancel(%{timer: timer} = state) do
    Process.cancel_timer(timer)
    %{state | timer: nil}
  end
end
