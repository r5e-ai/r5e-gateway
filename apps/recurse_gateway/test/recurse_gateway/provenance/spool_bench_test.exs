defmodule Recurse.Gateway.Provenance.SpoolBenchTest do
  @moduledoc """
  What encrypting the spool costs a streamed call: time added inside
  `PayloadCapture.append/2` per chunk (p50/p99), throughput for a 350 KB
  body, a 100 MB body and concurrent streams, plain spool against
  encrypted spool, and what shipping costs to read an encrypted file back.

  Excluded by default. Run with:

      MIX_ENV=test mix test --include perf \\
        test/recurse_gateway/provenance/spool_bench_test.exs

  Numbers are printed, not asserted, apart from a loose ceiling so a
  pathological regression fails.
  """
  use ExUnit.Case, async: false

  @moduletag :perf
  @moduletag :tmp_dir
  @moduletag timeout: 600_000

  alias Recurse.Gateway.LlmProxy.PayloadCapture
  alias Recurse.Gateway.Provenance.{Spool, SpoolKeys}
  alias Recurse.Providers.Impls.FakeKeyService

  @piece 4_096

  setup %{tmp_dir: dir} do
    {:ok, fake} = FakeKeyService.start_link()
    %{dir: dir, keys: {FakeKeyService, fake}}
  end

  defp with_spool(:sealed, ctx, fun) do
    pid =
      start_supervised!(
        {SpoolKeys,
         dir: Path.join(ctx.dir, "ev"), deployment: "bench", keys: ctx.keys, sweep_ms: 0, gc_ms: 0}
      )

    # PayloadCapture writes an encrypted spool when the runtime says the
    # deployment has one, not merely when the keys happen to be up.
    info = {Recurse.Gateway.Provenance.Runtime, :info}
    :persistent_term.put(info, %{spool?: true})

    try do
      fun.()
    after
      :persistent_term.erase(info)
      stop_supervised(SpoolKeys)
      refute Process.alive?(pid)
    end
  end

  defp with_spool(:plain, _ctx, fun), do: fun.()

  # One stream: every append timed on its own, in nanoseconds.
  defp stream(bytes, piece \\ @piece) do
    chunk = :crypto.strong_rand_bytes(piece)
    count = div(bytes, piece)
    capture = PayloadCapture.init(spool?: true)

    {capture, times} =
      Enum.reduce(1..count, {capture, []}, fn _, {capture, times} ->
        t0 = System.monotonic_time(:nanosecond)
        capture = PayloadCapture.append(capture, chunk)
        {capture, [System.monotonic_time(:nanosecond) - t0 | times]}
      end)

    t0 = System.monotonic_time(:nanosecond)
    result = PayloadCapture.result(capture)
    close = System.monotonic_time(:nanosecond) - t0

    path =
      case result do
        {:file, path} -> path
        {:sealed_file, path, _sha256, _size} -> path
      end

    {path, times, close, count * piece}
  end

  defp pct(sorted, p), do: Enum.at(sorted, min(length(sorted) - 1, trunc(p * length(sorted))))

  defp summary(label, times, bytes, close_ns) do
    sorted = Enum.sort(times)
    total = Enum.sum(times) + close_ns
    mbps = bytes / 1_048_576 / (total / 1.0e9)

    IO.puts(
      :io_lib.format(
        "  ~-34s p50 ~7.2f us  p99 ~7.2f us  close ~8.1f us  total ~9.2f ms  ~8.1f MB/s",
        [
          label,
          pct(sorted, 0.5) / 1000,
          pct(sorted, 0.99) / 1000,
          close_ns / 1000,
          total / 1.0e6,
          mbps
        ]
      )
    )

    %{p50: pct(sorted, 0.5), p99: pct(sorted, 0.99), total: total, mbps: mbps}
  end

  defp machine do
    cpu = System.cmd("sysctl", ["-n", "machdep.cpu.brand_string"]) |> elem(0) |> String.trim()
    mem = System.cmd("sysctl", ["-n", "hw.memsize"]) |> elem(0) |> String.trim()
    cores = System.schedulers_online()

    "#{cpu}, #{div(String.to_integer(mem), 1_073_741_824)} GiB, #{cores} schedulers, " <>
      "OTP #{System.otp_release()}, Elixir #{System.version()}, #{:crypto.info_lib() |> inspect()}"
  rescue
    _ -> "unknown"
  end

  test "spool overhead", ctx do
    IO.puts("\nmachine: #{machine()}")

    IO.puts(
      "\n350 KB body, #{@piece}-byte appends, 200 runs each (per-append p50/p99 over all runs):"
    )

    for mode <- [:plain, :sealed] do
      with_spool(mode, ctx, fn ->
        # Warm up.
        for _ <- 1..20, do: stream(350_000) |> elem(0) |> File.rm()

        runs = for _ <- 1..200, do: stream(350_000)
        for {path, _, _, _} <- runs, do: File.rm(path)
        times = Enum.flat_map(runs, &elem(&1, 1))
        close = runs |> Enum.map(&elem(&1, 2)) |> Enum.sort() |> pct(0.5)
        per_body = runs |> Enum.map(fn {_, t, c, _} -> Enum.sum(t) + c end) |> Enum.sort()

        summary("#{mode} (per append)", times, 350_000 * 200, close * 200)

        IO.puts(
          "  #{mode}: whole 350 KB body p50 #{Float.round(pct(per_body, 0.5) / 1000, 1)} us, " <>
            "p99 #{Float.round(pct(per_body, 0.99) / 1000, 1)} us"
        )
      end)
    end

    IO.puts("\n100 MB body, 16 KiB appends:")

    for mode <- [:plain, :sealed] do
      with_spool(mode, ctx, fn ->
        {path, times, close, bytes} = stream(100 * 1_048_576, 16_384)
        result = summary("#{mode} 100 MB", times, bytes, close)

        if mode == :sealed do
          sha = sha_of(path)
          t0 = System.monotonic_time(:nanosecond)
          {:ok, source, read, done} = Spool.open_reader(path, sha, &SpoolKeys.fetch/1)
          :eof = drain(read, source)
          done.()
          ns = System.monotonic_time(:nanosecond) - t0

          IO.puts(
            "  ship-side reader (decrypt + SHA-256 check), 100 MB: " <>
              "#{Float.round(ns / 1.0e6, 1)} ms, #{Float.round(100 / (ns / 1.0e9), 1)} MB/s"
          )
        end

        File.rm(path)
        assert result.mbps > 20
      end)
    end

    IO.puts("\n16 concurrent streams x 10 MB, 4 KiB appends (aggregate):")

    for mode <- [:plain, :sealed] do
      with_spool(mode, ctx, fn ->
        t0 = System.monotonic_time(:nanosecond)

        results =
          1..16
          |> Task.async_stream(fn _ -> stream(10 * 1_048_576) end,
            max_concurrency: 16,
            timeout: :infinity
          )
          |> Enum.map(fn {:ok, r} -> r end)

        wall = System.monotonic_time(:nanosecond) - t0
        for {path, _, _, _} <- results, do: File.rm(path)
        times = Enum.flat_map(results, &elem(&1, 1)) |> Enum.sort()

        IO.puts(
          :io_lib.format(
            "  ~-10s per-append p50 ~6.2f us  p99 ~7.2f us   wall ~8.1f ms   aggregate ~7.1f MB/s",
            [
              Atom.to_string(mode),
              pct(times, 0.5) / 1000,
              pct(times, 0.99) / 1000,
              wall / 1.0e6,
              160 / (wall / 1.0e9)
            ]
          )
        )
      end)
    end
  end

  # The bench's own streams are random bytes; the reader needs their hash.
  defp sha_of(path) do
    {:ok, epoch} = Spool.epoch_of(path)
    {:ok, dek} = SpoolKeys.fetch(epoch)
    {:ok, plain} = Spool.open(File.read!(path), fn ^epoch -> {:ok, dek} end)
    :crypto.hash(:sha256, plain)
  end

  defp drain(read, source) do
    case read.(source) do
      {:ok, _piece, source} -> drain(read, source)
      other -> other
    end
  end
end
