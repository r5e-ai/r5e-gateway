defmodule Recurse.Gateway.Provenance.Sealer do
  @moduledoc """
  Seals this gateway's evidence on a schedule and once more at shutdown.

  A seal commits to a run of records with one Merkle root. Until a
  record is sealed it is individually signed but not yet part of a
  roll-up that can be anchored or witnessed. This process is the clock
  that decides when: every `:interval_ms`, and when the node stops.

  It owns nothing but a timer. Sealing itself is done by the pipeline,
  from records already shipped, and never touches the request path.
  """

  use GenServer

  require Logger

  alias Recurse.Gateway.Provenance.Runtime

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @impl true
  def init(opts) do
    # Trap exits so a normal shutdown reaches terminate/2 and seals.
    Process.flag(:trap_exit, true)
    interval = Keyword.fetch!(opts, :interval_ms)
    {:ok, %{interval: interval, timer: Process.send_after(self(), :seal, interval)}}
  end

  @impl true
  def handle_info(:seal, state) do
    seal()
    {:noreply, %{state | timer: Process.send_after(self(), :seal, state.interval)}}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, _state), do: seal()

  defp seal do
    case Runtime.seal() do
      {:ok, []} -> :ok
      {:ok, seals} -> Logger.debug("provenance sealer: sealed #{length(seals)} stream(s)")
      {:error, reason} -> Logger.warning("provenance sealer: seal failed: #{inspect(reason)}")
    end
  rescue
    error -> Logger.warning("provenance sealer: seal raised: #{inspect(error)}")
  end
end
