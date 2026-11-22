defmodule Recurse.Provenance.Signals do
  @moduledoc """
  Watermark signals for evidence streams.

  Capture never waits for anything downstream. Each later stage instead
  announces how far a stream has progressed, and whoever cares
  subscribes:

    * `:captured` — signed and placed in its stream, in memory
    * `:durable` — on this node's disk
    * `:shipped` — in the index and the content store
    * `:sealed` — covered by a signed roll-up

  A signal is `{:provenance, level, stream, through_seq}` and means every
  position of that stream up to and including `through_seq` has reached
  that level. Signals are hints to wake a subscriber, not a delivery
  guarantee: a subscriber that was down reads the durable state when it
  returns.

  Built on a duplicate-key `Registry`, so there is no process that
  signals pass through.
  """

  @type level :: :captured | :durable | :shipped | :sealed
  @type signal :: {:provenance, level(), stream :: String.t(), through_seq :: pos_integer()}

  @doc "Child spec for the registry that carries signals."
  @spec child_spec(atom()) :: Supervisor.child_spec()
  def child_spec(name),
    do: Registry.child_spec(keys: :duplicate, name: name, partitions: System.schedulers_online())

  @doc "Receive every signal of `level` in the calling process's mailbox."
  @spec subscribe(atom(), level()) :: :ok
  def subscribe(registry, level) do
    {:ok, _} = Registry.register(registry, level, nil)
    :ok
  end

  @doc "Announce that `stream` has reached `level` through `seq`."
  @spec publish(atom(), level(), String.t(), pos_integer()) :: :ok
  def publish(registry, level, stream, seq) do
    Registry.dispatch(registry, level, fn subscribers ->
      for {pid, _} <- subscribers, do: send(pid, {:provenance, level, stream, seq})
    end)

    :telemetry.execute([:recurse, :provenance, level], %{seq: seq}, %{stream: stream})
  end

  @doc """
  Wait until `stream` reaches `level` through `seq`. For tests and for a
  caller that has chosen to wait; the request path never calls this.
  The caller must already be subscribed to `level`.
  """
  @spec await(level(), String.t(), pos_integer(), timeout()) :: :ok | {:error, :timeout}
  def await(level, stream, seq, timeout \\ 5_000) do
    receive do
      {:provenance, ^level, ^stream, through} when through >= seq -> :ok
    after
      timeout -> {:error, :timeout}
    end
  end
end
