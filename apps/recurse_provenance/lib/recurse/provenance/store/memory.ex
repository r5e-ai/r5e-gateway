defmodule Recurse.Provenance.Store.Memory do
  @moduledoc """
  An in-memory `Recurse.Provenance.Store`, for tests and local trials.
  Nothing here survives the process, so a receipt it backs is durable
  only in the sense the profile's `failureDomain` says.
  """
  @behaviour Recurse.Provenance.Store

  use Agent

  @doc "Start an empty store; the pid is the handle."
  def start_link(opts \\ []) do
    Agent.start_link(
      fn -> %{records: %{}, positions: %{}, submissions: %{}, blobs: %{}, keys: %{}} end,
      opts
    )
  end

  @impl true
  def head(store, stream) do
    Agent.get(store, fn s ->
      s.positions
      |> Enum.filter(fn {{st, _seq}, _ref} -> st == stream end)
      |> Enum.max_by(fn {{_st, seq}, _ref} -> seq end, fn -> nil end)
      |> case do
        nil -> {:ok, nil}
        {{_st, seq}, ref} -> {:ok, {seq, ref}}
      end
    end)
  end

  @impl true
  def append(store, %{ref: ref, stream: stream, seq: seq} = entry) do
    Agent.get_and_update(store, fn s ->
      case Map.get(s.positions, {stream, seq}) do
        nil ->
          blobs =
            Enum.reduce(Map.get(entry, :blobs, []), s.blobs, fn {r, b}, acc ->
              Map.put(acc, r, bytes(b))
            end)

          submissions =
            case entry[:submission_id] do
              nil -> s.submissions
              id -> Map.put(s.submissions, {stream, id}, ref)
            end

          {:ok,
           %{
             s
             | records: Map.put(s.records, ref, Map.delete(entry, :blobs)),
               positions: Map.put(s.positions, {stream, seq}, ref),
               submissions: submissions,
               blobs: blobs
           }}

        ^ref ->
          {:ok, s}

        _other ->
          {{:error, :conflict}, s}
      end
    end)
  end

  @impl true
  def append_many(store, entries) do
    Enum.reduce_while(entries, :ok, fn entry, :ok ->
      case append(store, entry) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  @impl true
  def fetch(store, ref), do: Agent.get(store, &Map.fetch(&1.records, ref))

  @impl true
  def by_submission(store, stream, submission_id) do
    Agent.get(store, fn s ->
      with {:ok, ref} <- Map.fetch(s.submissions, {stream, submission_id}),
           do: Map.fetch(s.records, ref)
    end)
  end

  @impl true
  def range(store, stream, first, last) do
    Agent.get(store, fn s ->
      refs = for seq <- first..last//1, do: Map.get(s.positions, {stream, seq})

      if Enum.any?(refs, &is_nil/1),
        do: {:error, :gap},
        else: {:ok, Enum.map(refs, &Map.fetch!(s.records, &1))}
    end)
  end

  @impl true
  def last_seal(store, stream) do
    Agent.get(store, fn s ->
      s.records
      |> Map.values()
      |> Enum.filter(
        &(&1.kind_path == "provenance.r5e.io/v2/EpochSeal" and
            &1.evidence["body"]["stream"] == stream)
      )
      |> Enum.max_by(& &1.evidence["body"]["lastSeq"], fn -> nil end)
      |> case do
        nil -> {:ok, nil}
        entry -> {:ok, {entry.ref, entry.evidence["body"]["lastSeq"]}}
      end
    end)
  end

  @impl true
  def unsealed_firsts(store, prefix) do
    Agent.get(store, fn s ->
      records = Map.values(s.records)

      sealed =
        for %{kind_path: "provenance.r5e.io/v2/EpochSeal", evidence: %{"body" => body}} <- records,
            reduce: %{} do
          acc -> Map.update(acc, body["stream"], body["lastSeq"], &max(&1, body["lastSeq"]))
        end

      streams =
        records
        |> Enum.filter(&String.starts_with?(&1.stream, prefix))
        |> Enum.group_by(& &1.stream, & &1.seq)
        |> Enum.filter(fn {stream, seqs} -> Enum.max(seqs) > Map.get(sealed, stream, 0) end)
        |> Enum.map(&elem(&1, 0))

      {:ok, Enum.sort(streams)}
    end)
  end

  @impl true
  def by_session(store, session) do
    Agent.get(store, fn s ->
      {:ok,
       s.records
       |> Map.values()
       |> Enum.filter(&(&1.evidence["session"] == session))
       |> Enum.sort_by(&{&1.stream, &1.seq})}
    end)
  end

  @impl true
  def list(store, %{stream_prefix: prefix, limit: limit} = asked) do
    Agent.get(store, fn s ->
      {:ok,
       s.records
       |> Map.values()
       |> Enum.filter(&(String.starts_with?(&1.stream, prefix) and listed?(&1, asked)))
       |> Enum.sort_by(&{captured_at(&1), &1.ref}, &later?/2)
       |> Enum.take(limit)}
    end)
  end

  defp listed?(entry, asked) do
    at = captured_at(entry)

    Enum.all?(asked, fn
      {:kind_path, kind} ->
        entry.kind_path == kind

      {:session, session} ->
        entry.evidence["session"] == session

      {:actor, actor} ->
        entry.evidence["actor"] == actor

      {:own_principal, {principal, session_prefix}} ->
        entry.evidence["actor"] == principal or
          (is_binary(entry.evidence["session"]) and
             String.starts_with?(entry.evidence["session"], session_prefix))

      {:since, since} ->
        DateTime.compare(at, since) != :lt

      {:until, until} ->
        DateTime.compare(at, until) == :lt

      {:before, position} ->
        later?(position, {at, entry.ref}) and position != {at, entry.ref}

      {_, _} ->
        true
    end)
  end

  defp captured_at(%{evidence: %{"capturedAt" => stated}}) do
    {:ok, at, 0} = DateTime.from_iso8601(stated)
    at
  end

  # Whether the first position comes at or after the second: later
  # capture time, then the greater reference.
  defp later?({at, ref}, {other_at, other_ref}) do
    case DateTime.compare(at, other_at) do
      :gt -> true
      :lt -> false
      :eq -> ref >= other_ref
    end
  end

  @impl true
  def by_kind(store, kind_path, stream_prefix) do
    Agent.get(store, fn s ->
      {:ok,
       s.records
       |> Map.values()
       |> Enum.filter(
         &(&1.kind_path == kind_path and String.starts_with?(&1.stream, stream_prefix))
       )
       |> Enum.sort_by(&{&1.stream, &1.seq})}
    end)
  end

  @impl true
  def seal_covering(store, stream, seq) do
    Agent.get(store, fn s ->
      s.records
      |> Map.values()
      |> Enum.filter(fn e ->
        e.kind_path == "provenance.r5e.io/v2/EpochSeal" and e.evidence["body"]["stream"] == stream and
          e.evidence["body"]["firstSeq"] <= seq and e.evidence["body"]["lastSeq"] >= seq
      end)
      |> Enum.min_by(& &1.evidence["body"]["lastSeq"], fn -> nil end)
      |> case do
        nil -> :error
        entry -> {:ok, entry}
      end
    end)
  end

  @impl true
  def put_key(store, key), do: Agent.update(store, &put_in(&1.keys[key.key_id], key))

  @impl true
  def get_key(store, key_id), do: Agent.get(store, &Map.fetch(&1.keys, key_id))

  @impl true
  def put_blob(store, ref, content),
    do: Agent.update(store, &put_in(&1.blobs[ref], bytes(content)))

  defp bytes({:file, path}), do: File.read!(path)
  defp bytes(binary) when is_binary(binary), do: binary

  # Nothing is encrypted in memory, so a scope makes no difference here.
  @impl true
  def put_content(_store, _ref, :own, _scope), do: {:error, :not_held}

  def put_content(store, ref, :held, _scope),
    do: if(match?({:ok, _}, get_blob(store, ref)), do: :ok, else: {:error, :not_held})

  # A reader is read to its end before anything is kept, so content that
  # fails its check on the way is never held.
  def put_content(store, ref, {:reader, _path, open}, _scope) do
    with {:ok, bytes} <- drain(open), do: put_blob(store, ref, bytes)
  end

  def put_content(store, ref, content, _scope), do: put_blob(store, ref, content)

  defp drain(open) do
    with {:ok, source, read, close} <- open.() do
      try do
        drain(read, source, [])
      after
        close.()
      end
    end
  end

  defp drain(read, source, acc) do
    case read.(source) do
      {:ok, piece, source} -> drain(read, source, [acc, piece])
      :eof -> {:ok, IO.iodata_to_binary(acc)}
      {:error, _} = error -> error
    end
  end

  @impl true
  def get_content(store, ref, _scope), do: get_blob(store, ref)

  @impl true
  def get_blob(store, ref), do: Agent.get(store, &Map.fetch(&1.blobs, ref))
end
