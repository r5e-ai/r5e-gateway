defmodule Recurse.Gateway.LlmProxy.PayloadCapture do
  @moduledoc """
  Bounded byte capture for the LLM proxy's request + response bodies
  (spec 012 S6b; spec 009 `streaming_proxy.md` "detached payloads").

  `BodyHasher` computes `prompt_hash` / `response_hash` while the bytes
  flow past and never keeps them. That leaves the signed hash pointing
  at bytes nobody retained (plan §16). This module sits next to the
  hasher: fed the same chunks in the same order, it keeps them so the
  emitter can put them in the StorageProvider under the hash the
  predicate commits to.

  ## Bounds (`R5E_RETAIN_PAYLOADS_MAX_BYTES`, default 8 MiB per direction)

  A capture that would exceed `max_bytes` drops what it holds and marks
  itself `:truncated`. A partial payload can never be checked against
  the hash, so storing a prefix would be evidence-shaped noise; the
  receipt instead records `payload_truncated: true` and no URI for that
  direction. Memory stays bounded at `max_bytes` per direction per
  in-flight call. Write-through to a temp file was considered and not
  chosen: the request body is already fully in memory (Plug reads it),
  and a response over the cap is the case where an operator raises the
  cap deliberately rather than one the proxy should absorb silently.

  ## Off switch (`R5E_RETAIN_PAYLOADS`, default false; compose sets true)

  `init/1` with `enabled?: false` yields a capture that ignores every
  `append/2` and reports `:disabled`. Payloads carry prompt content —
  the StorageProvider is the operator's own store — so production
  defaults to off and the quickstart opts in.

  ## Spooling (Provenance v2 evidence)

  When evidence capture is running, the switch and the in-memory cap do
  not apply. An evidence record refers to content by hash, and a
  reference is a promise that the bytes are held, so bodies are kept.
  Chunks are appended to a temporary file as they pass, memory stays
  flat, and `result/1` returns `{:file, path}` for the recorder to move
  into storage. The caller removes the file with `discard/1` once the
  record is written.

  A spooled body has its own bound (`R5E_EVIDENCE_MAX_BODY_BYTES`,
  default 256 MiB per direction), so one call cannot fill the disk. A
  body that passes it is dropped and reported `:truncated`; the record
  still carries its hash and says the content is not held.

  When evidence capture is configured with a key service (the runtime's
  `spool?`), the spool file is written encrypted as the chunks arrive
  (`Recurse.Gateway.Provenance.Spool`), in the deployment's own `spool/`
  directory, readable by the gateway's user only; at most one 64 KiB chunk
  is held in memory. Nothing of the body is on disk in the clear at any
  moment: if the spool's keys are not ready (their holder is restarting),
  the body is captured in bounded memory instead, never to a plain file.
  `result/1` answers `{:sealed_file, path, sha256, size}`, the hash and
  size of the plain bytes taken as they streamed; the recorder compares
  the hash with the one taken on the wire and renames the file into the
  content directory unread. Without a key service, and whenever evidence
  capture is off (the older retain-payloads path), capture behaves exactly
  as before.

  ## Iron Law

  Plain functions over an immutable struct threaded through the proxy
  state, exactly like `BodyHasher`.
  """

  @default_max_bytes 8 * 1024 * 1024
  @default_spool_max_bytes 256 * 1024 * 1024

  @type t :: %__MODULE__{
          enabled?: boolean(),
          max_bytes: non_neg_integer(),
          size: non_neg_integer(),
          seen: non_neg_integer(),
          chunks: [binary()],
          truncated?: boolean(),
          spool:
            nil
            | {Path.t(), :file.io_device()}
            | {:sealed, Path.t(), Recurse.Gateway.Provenance.Spool.Writer.t()},
          spool_max_bytes: non_neg_integer()
        }

  @typedoc """
  What the capture holds at close: the bytes, `:truncated` (cap
  exceeded — nothing kept), or `:disabled` (retention off).
  """
  @type result ::
          {:ok, binary()}
          | {:file, Path.t()}
          | {:sealed_file, Path.t(), <<_::256>>, non_neg_integer()}
          | :truncated
          | :disabled

  defstruct enabled?: false,
            max_bytes: @default_max_bytes,
            size: 0,
            seen: 0,
            chunks: [],
            truncated?: false,
            spool: nil,
            spool_max_bytes: @default_spool_max_bytes

  @doc """
  Start a capture. `opts`:

    * `:enabled?` — default `Application.get_env(:recurse_gateway, :retain_payloads?, false)`.
    * `:max_bytes` — default `Application.get_env(:recurse_gateway, :retain_payloads_max_bytes, 8 MiB)`.
    * `:spool?` — spool to a file; default is whether evidence capture is running.
    * `:spool_max_bytes` — default `Application.get_env(:recurse_gateway, :evidence_max_body_bytes, 256 MiB)`.
  """
  @spec init(keyword()) :: t()
  def init(opts \\ []) do
    enabled? =
      Keyword.get_lazy(opts, :enabled?, fn ->
        Application.get_env(:recurse_gateway, :retain_payloads?, false) == true or
          Recurse.Gateway.Provenance.Runtime.running?()
      end)

    max_bytes =
      Keyword.get_lazy(opts, :max_bytes, fn ->
        Application.get_env(:recurse_gateway, :retain_payloads_max_bytes, @default_max_bytes)
      end)

    spool? =
      Keyword.get_lazy(opts, :spool?, &Recurse.Gateway.Provenance.Runtime.running?/0)

    spool_max =
      Keyword.get_lazy(opts, :spool_max_bytes, fn ->
        Application.get_env(:recurse_gateway, :evidence_max_body_bytes, @default_spool_max_bytes)
      end)

    capture = %__MODULE__{
      enabled?: enabled? == true,
      max_bytes: normalize_max(max_bytes),
      spool_max_bytes:
        if(is_integer(spool_max) and spool_max > 0, do: spool_max, else: @default_spool_max_bytes)
    }

    if spool?, do: open_spool(capture), else: capture
  end

  # A spool that cannot be opened falls back to bounded memory capture
  # rather than failing the call.
  defp open_spool(capture) do
    alias Recurse.Gateway.Provenance.{Spool, SpoolKeys}

    if encrypted_spool?() do
      # Configured to encrypt: a sealed file, or memory, never a plain file.
      with dir when is_binary(dir) <- SpoolKeys.spool_dir(),
           {:ok, epoch, dek} <- SpoolKeys.current(),
           path = Path.join(dir, spool_name()),
           {:ok, writer} <- Spool.create(path, epoch, dek) do
        SpoolKeys.watch(path)
        %{capture | enabled?: true, spool: {:sealed, path, writer}}
      else
        _not_ready -> %{capture | enabled?: true}
      end
    else
      open_plain_spool(capture)
    end
  end

  # Read from the runtime's configuration, not from whether the spool's
  # keys happen to be up at this moment.
  defp encrypted_spool? do
    case Recurse.Gateway.Provenance.Runtime.info() do
      %{spool?: true} -> true
      _ -> false
    end
  end

  defp spool_name,
    do:
      "#{System.unique_integer([:positive])}-#{:erlang.unique_integer([:positive])}.#{System.os_time(:nanosecond)}"

  defp open_plain_spool(capture) do
    dir = Path.join(System.tmp_dir!(), "r5e-capture")

    path =
      Path.join(
        dir,
        "#{System.unique_integer([:positive])}-#{:erlang.unique_integer([:positive])}.#{System.os_time(:nanosecond)}"
      )

    with :ok <- File.mkdir_p(dir),
         {:ok, device} <- :file.open(path, [:raw, :binary, :write, :delayed_write]) do
      %{capture | enabled?: true, spool: {path, device}}
    else
      _ -> %{capture | enabled?: true}
    end
  end

  @doc """
  Append a chunk. Nothing is kept when disabled or already truncated,
  but every byte is still counted; see `seen/1`.
  """
  @spec append(t(), binary()) :: t()
  def append(%__MODULE__{} = capture, bytes) when is_binary(bytes),
    do: keep(%{capture | seen: capture.seen + byte_size(bytes)}, bytes)

  @doc """
  How many bytes passed through this capture, kept or not. A record
  states the size of a body even when the body itself was too large to
  hold.
  """
  @spec seen(t()) :: non_neg_integer()
  def seen(%__MODULE__{seen: seen}), do: seen

  defp keep(%__MODULE__{spool: {:sealed, path, writer}} = capture, bytes) do
    with true <- capture.size + byte_size(bytes) <= capture.spool_max_bytes,
         {:ok, writer} <- Recurse.Gateway.Provenance.Spool.append(writer, bytes) do
      %{capture | size: capture.size + byte_size(bytes), spool: {:sealed, path, writer}}
    else
      _over_bound_or_write_error -> close_spool(%{capture | truncated?: true})
    end
  end

  defp keep(%__MODULE__{spool: {_path, device}} = capture, bytes) do
    with true <- capture.size + byte_size(bytes) <= capture.spool_max_bytes,
         :ok <- :file.write(device, bytes) do
      %{capture | size: capture.size + byte_size(bytes)}
    else
      _over_bound_or_write_error -> close_spool(%{capture | truncated?: true})
    end
  end

  defp keep(%__MODULE__{enabled?: false} = capture, _bytes), do: capture
  defp keep(%__MODULE__{truncated?: true} = capture, _bytes), do: capture
  defp keep(capture, ""), do: capture

  defp keep(%__MODULE__{size: size, max_bytes: max} = capture, bytes) do
    if size + byte_size(bytes) > max do
      %{capture | chunks: [], size: 0, truncated?: true}
    else
      %{capture | chunks: [bytes | capture.chunks], size: size + byte_size(bytes)}
    end
  end

  @doc "Finish the capture."
  @spec result(t()) :: result()
  def result(%__MODULE__{spool: {:sealed, path, writer}}) do
    # The file is now the recorder's to place or discard.
    Recurse.Gateway.Provenance.SpoolKeys.unwatch(path)

    case Recurse.Gateway.Provenance.Spool.finish(writer) do
      {:ok, %{sha256: sha256, size: size}} ->
        {:sealed_file, path, sha256, size}

      {:error, _reason} ->
        _ = File.rm(path)
        :truncated
    end
  end

  def result(%__MODULE__{spool: {path, device}}) do
    case :file.close(device) do
      :ok -> {:file, path}
      # A second close of an already-closed device still leaves the file.
      {:error, :einval} -> {:file, path}
      {:error, _reason} -> :truncated
    end
  end

  def result(%__MODULE__{enabled?: false}), do: :disabled
  def result(%__MODULE__{truncated?: true}), do: :truncated

  def result(%__MODULE__{chunks: chunks}),
    do: {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

  @doc "Remove a spooled capture's file. Safe on any result."
  @spec discard(result() | t()) :: :ok
  def discard({:sealed_file, path, _sha256, _size}) do
    _ = File.rm(path)
    :ok
  end

  def discard({:file, path}) do
    _ = File.rm(path)
    :ok
  end

  def discard(%__MODULE__{spool: {:sealed, path, writer}}) do
    Recurse.Gateway.Provenance.SpoolKeys.unwatch(path)
    Recurse.Gateway.Provenance.Spool.abort(writer)
  end

  def discard(%__MODULE__{spool: {path, device}}) do
    _ = :file.close(device)
    _ = File.rm(path)
    :ok
  end

  def discard(_other), do: :ok

  defp close_spool(%__MODULE__{spool: {:sealed, path, writer}} = capture) do
    Recurse.Gateway.Provenance.SpoolKeys.unwatch(path)
    Recurse.Gateway.Provenance.Spool.abort(writer)
    %{capture | spool: nil}
  end

  defp close_spool(%__MODULE__{spool: {path, device}} = capture) do
    _ = :file.close(device)
    _ = File.rm(path)
    %{capture | spool: nil}
  end

  @doc "Default per-direction cap in bytes."
  @spec default_max_bytes() :: pos_integer()
  def default_max_bytes, do: @default_max_bytes

  defp normalize_max(n) when is_integer(n) and n >= 0, do: n
  defp normalize_max(_), do: @default_max_bytes
end
