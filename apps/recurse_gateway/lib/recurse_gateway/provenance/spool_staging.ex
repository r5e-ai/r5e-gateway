defmodule Recurse.Gateway.Provenance.SpoolStaging do
  @moduledoc """
  The gateway's `Recurse.Provenance.Staging`: content waits in the
  evidence pipeline's content directory in the encrypted spool format
  (`Recurse.Gateway.Provenance.Spool`), under the keys
  `Recurse.Gateway.Provenance.SpoolKeys` holds.

  Used only while evidence capture runs with a key service; otherwise
  the pipeline keeps plain files, as before.

    * Bytes in hand (tool arguments, the policy evaluated, a seal's
      manifest) are sealed in memory and written beside their target,
      then renamed into place.
    * A streamed body already sealed by `PayloadCapture` is renamed into
      place and never read again here: its hash was taken as it streamed
      and compared with the hash taken on the wire by the recorder
      (`Recurse.Gateway.Provenance.Call`), which records the content as not
      held when they differ; the shipping reader checks every byte against
      the reference again. A plain file handed in by another caller is
      sealed into place and the plain file removed.
    * Shipping reads a waiting file through a reader that decrypts one
      chunk at a time in memory and answers its end only once the content
      matches its reference. A file that fails is moved to `quarantine/`
      beside the content directory, not deleted, and its records ship
      without it. A quarantined file is kept as a sign that something
      altered the disk, not as content: it no longer pins its epoch, so
      once that epoch retires it can no longer be decrypted at all.

  Waiting files are not synced to disk one by one, as plain files were
  not: the log syncs the records that name them, and a file cut short by
  a power failure is reported unreadable and its content missing, never
  taken for the content.

  A plain file in the content directory while the spool is running (left
  from before the spool, or with its marker damaged) is read through the
  same checking reader, and is logged.
  """

  @behaviour Recurse.Provenance.Staging

  require Logger

  alias Recurse.Gateway.Provenance.{Spool, SpoolKeys}

  @doc "The staging for a deployment's evidence directory."
  @spec new(Path.t()) :: Recurse.Provenance.Staging.t()
  def new(dir), do: {__MODULE__, %{quarantine: Path.join(dir, "quarantine")}}

  @impl true
  def write_bytes(_state, target, bytes) do
    if File.exists?(target) do
      touch(target)
    else
      with {:ok, epoch, dek} <- current() do
        partial = partial(target)

        with :ok <- write_new(partial, Spool.seal(bytes, epoch, dek)),
             :ok <- File.rename(partial, target) do
          :ok
        else
          error ->
            _ = File.rm(partial)
            error
        end
      end
    end
  end

  @impl true
  def hash_file(_state, path, expected) do
    case Spool.epoch_of(path) do
      # Sealed as it streamed, hashed as it streamed; checked again, byte
      # for byte, when it is shipped.
      {:ok, _epoch} when is_binary(expected) and byte_size(expected) == 32 ->
        {:ok, expected}

      {:ok, _epoch} ->
        digest_sealed(path)

      :plain ->
        Recurse.Provenance.Staging.Plain.hash_file(nil, path, expected)

      {:error, _} = error ->
        error
    end
  end

  @impl true
  def place_file(_state, source, target) do
    cond do
      File.exists?(target) ->
        touch(target)

      # A file's age counts from when it was put here, not from when its
      # last byte was written. A request body is written when its call
      # begins and put here when the call ends, which can be a long time
      # later; a rename keeps the old time, and the collector, which
      # judges a file by its age, would take a file whose record has only
      # just been made.
      match?({:ok, _}, Spool.epoch_of(source)) ->
        with :ok <- move(source, target), do: touch(target)

      true ->
        with :ok <- seal_plain_file(source, target), do: touch(target)
    end
  end

  @impl true
  def content(state, path) do
    with {:ok, expected} <- expected(path) do
      case Spool.epoch_of(path) do
        {:ok, epoch} ->
          case SpoolKeys.fetch(epoch) do
            {:ok, _dek} -> {:ok, {:reader, path, opener(state, path, expected)}}
            {:error, _} = error -> error
          end

        :plain ->
          Logger.warning(
            "evidence: #{Path.basename(path)} waits unencrypted although the spool is " <>
              "encrypted (left from before, or its marker is damaged); it is checked as it ships"
          )

          {:ok, {:reader, path, plain_opener(state, path, expected)}}

        {:error, {:staged_content_unreadable, _} = why} ->
          set_aside(state, path, why)
          {:error, why}

        {:error, _} = error ->
          error
      end
    end
  end

  @doc """
  How many plain bytes the file at `path` holds: computed from its size
  for a sealed file, its size for a plain one.
  """
  @spec plain_size(Path.t()) :: {:ok, non_neg_integer()} | :error
  def plain_size(path) do
    with {:ok, %{size: size}} <- File.stat(path) do
      case Spool.epoch_of(path) do
        {:ok, _} ->
          case Spool.plain_size(size) do
            nil -> :error
            n -> {:ok, n}
          end

        :plain ->
          {:ok, size}

        _ ->
          :error
      end
    else
      _ -> :error
    end
  end

  # -- readers -----------------------------------------------------------------

  defp opener(state, path, expected) do
    fn ->
      case Spool.open_reader(path, expected, &SpoolKeys.fetch/1) do
        {:ok, source, read, close} -> {:ok, source, guarded(state, path, read), close}
        {:error, {:staged_content_unreadable, _} = why} -> set_aside(state, path, why)
        {:error, _} = error -> error
      end
    end
  end

  defp plain_opener(state, path, expected) do
    fn ->
      with {:ok, device} <- :file.open(path, [:raw, :binary, :read, :read_ahead]) do
        read = fn {device, hash} ->
          case :file.read(device, Spool.chunk_bytes()) do
            {:ok, piece} ->
              {:ok, piece, {device, :crypto.hash_update(hash, piece)}}

            :eof ->
              if :crypto.hash_final(hash) == expected,
                do: :eof,
                else: {:error, {:staged_content_unreadable, :does_not_match_ref}}

            {:error, reason} ->
              {:error, reason}
          end
        end

        {:ok, {device, :crypto.hash_init(:sha256)}, guarded(state, path, read),
         fn -> :file.close(device) end}
      end
    end
  end

  # A read that finds the file unreadable moves it aside before saying so,
  # so the shipper never meets it again.
  defp guarded(state, path, read) do
    fn source ->
      case read.(source) do
        {:error, {:staged_content_unreadable, _} = why} -> set_aside(state, path, why)
        other -> other
      end
    end
  end

  defp set_aside(%{quarantine: dir}, path, {_, reason} = why) do
    target =
      Path.join(dir, Path.basename(path) <> "." <> Integer.to_string(System.os_time(:second)))

    case File.rename(path, target) do
      :ok ->
        Logger.error(
          "evidence: waiting content #{Path.basename(path)} is unreadable (#{inspect(reason)}); " <>
            "moved to #{target}"
        )

      {:error, _} ->
        :ok
    end

    {:error, why}
  end

  defp expected(path) do
    case Base.decode16(Path.basename(path), case: :lower) do
      {:ok, <<_::256>> = sha} -> {:ok, sha}
      _ -> {:error, {:staged_content_unreadable, :not_named_by_reference}}
    end
  end

  defp digest_sealed(path), do: Spool.digest_file(path, &SpoolKeys.fetch/1)

  # -- files -----------------------------------------------------------------

  defp current do
    case SpoolKeys.current() do
      {:ok, epoch, dek} -> {:ok, epoch, dek}
      :error -> {:error, :spool_keys_not_running}
    end
  end

  # Content already waiting is wanted again; see SpoolKeys on collecting
  # files no record waits for.
  defp touch(path) do
    _ = File.touch(path)
    :ok
  end

  defp move(source, target) do
    case File.rename(source, target) do
      :ok ->
        :ok

      {:error, _} ->
        partial = partial(target)

        with :ok <- File.cp(source, partial),
             :ok <- File.chmod(partial, 0o600),
             :ok <- File.rename(partial, target) do
          :ok
        else
          error ->
            _ = File.rm(partial)
            error
        end
    end
  end

  defp seal_plain_file(source, target) do
    with {:ok, epoch, dek} <- current() do
      partial = partial(target)

      result =
        with {:ok, writer} <- Spool.create(partial, epoch, dek),
             {:ok, writer} <- copy_in(source, writer),
             {:ok, _} <- Spool.finish(writer),
             :ok <- File.rename(partial, target) do
          File.rm(source)
          :ok
        end

      with {:error, _} <- result, do: File.rm(partial)
      result
    end
  end

  defp copy_in(source, writer) do
    with {:ok, device} <- :file.open(source, [:raw, :binary, :read, :read_ahead]) do
      try do
        pump(device, writer)
      after
        :file.close(device)
      end
    end
  end

  defp pump(device, writer) do
    case :file.read(device, Spool.chunk_bytes()) do
      {:ok, piece} ->
        with {:ok, writer} <- Spool.append(writer, piece), do: pump(device, writer)

      :eof ->
        {:ok, writer}

      {:error, reason} ->
        Spool.abort(writer)
        {:error, reason}
    end
  end

  defp write_new(path, iodata) do
    with {:ok, device} <- :file.open(path, [:raw, :binary, :write, :exclusive]) do
      try do
        with :ok <- :file.change_mode(path, 0o600), do: :file.write(device, iodata)
      after
        :file.close(device)
      end
    end
  end

  defp partial(target),
    do: target <> ".partial-" <> Integer.to_string(System.unique_integer([:positive]))
end
