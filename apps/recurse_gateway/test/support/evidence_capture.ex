defmodule Recurse.Gateway.Test.EvidenceCapture do
  @moduledoc """
  Evidence capture for a test that sends a call through the proxy and
  then looks at what was recorded.

  The test suite starts without capture, because each test wants its own
  deployment name and its own directory. `start/1` gives a test both;
  `records/1` returns what the gateway recorded for that deployment, in
  order, once it has been shipped to the index.
  """

  import Ecto.Query, only: [from: 2]
  import ExUnit.Callbacks, only: [start_supervised!: 1, on_exit: 1]

  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Provenance.Key
  alias Recurse.Providers.Impls.PostgresEvidenceStore, as: Store
  alias Recurse.Providers.Repo

  @base "provenance.r5e.io/v2/"

  @doc """
  Start capture under a deployment name of the test's own, logging into
  `dir`. Call it from `setup`, after the database sandbox is checked out
  in shared mode. Returns the running capture's description.
  """
  @spec start(Path.t()) :: map()
  def start(dir) do
    start_supervised!(
      {Runtime,
       deployment: "test-#{System.unique_integer([:positive])}",
       signer: Key.generate("es256"),
       dir: dir,
       partitions: 2,
       flush_interval_ms: 20}
    )

    on_exit(fn -> :persistent_term.erase({Runtime, :info}) end)
    Runtime.info()
  end

  @doc "Every record on the gateway's own streams, oldest first within a stream."
  @spec records(map()) :: [map()]
  def records(info) do
    :ok = Runtime.flush()
    prefix = "urn:r5e:stream:#{info.deployment}:gateway:%"

    from(r in "evidence_records",
      where: like(r.stream, ^prefix),
      order_by: [r.stream, r.seq],
      select: r.ref
    )
    |> Repo.all()
    |> Enum.map(fn ref -> elem(Store.fetch(Repo, ref), 1) end)
  end

  @doc "The records of one kind, by its short name (`\"ModelCall\"`)."
  @spec of_kind([map()], String.t()) :: [map()]
  def of_kind(records, kind), do: Enum.filter(records, &(&1.kind_path == @base <> kind))

  @doc "The one record of a kind; the test fails if there is not exactly one."
  @spec one([map()], String.t()) :: map()
  def one(records, kind) do
    [record] = of_kind(records, kind)
    record
  end

  @doc "A record's body."
  @spec body(map()) :: map()
  def body(record), do: record.evidence["body"]

  @doc "A record's details, or an empty map."
  @spec details(map()) :: map()
  def details(record), do: Map.get(body(record), "details", %{})
end
