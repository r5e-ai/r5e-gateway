defmodule Recurse.Gateway.Evidence.TailSocket do
  @moduledoc """
  Records as they arrive, over a WebSocket: `GET /v1/evidence/tail`.

  A reader watching a deployment wants each new record without asking
  again. Each connection is one process. It subscribes to the
  `:shipped` signal of `Recurse.Provenance.Signals`, which says a stream
  has reached the index through some position, reads the positions it
  has not sent yet from the index, and sends the ones the reader asked
  for. Nothing on the capture path knows a reader exists.

  ## Frames

  Server to client, as JSON text:

    * `{"type": "record", "record": {…}}` — one record, in the same
      shape as a row of `GET /v1/evidence/records`.
    * `{"type": "ping"}` — every 30 seconds.

  Client to server: `{"type": "pong"}` in answer to a ping, or
  `{"type": "ping"}`, which is answered with a pong. A connection that
  sends nothing for 90 seconds is closed.

  What to send is fixed when the connection opens, by the query string:
  `kind`, `session` and `actor`, with the same meaning as on the list
  route. To change it, open another connection.

  ## What a reader can rely on

  Signals wake a subscriber; they are not a delivery guarantee. To miss
  nothing, open the connection first and then read the list. A record
  that reached the index in the minute before the connection opened may
  be sent as well, so drop any `ref` already held. When a stream moves
  more than 200 positions between two signals only the newest are sent;
  the list has the rest.
  """

  @behaviour WebSock

  alias Recurse.Provenance.Signals

  @ping_ms 30_000
  @idle_ms 90_000
  @most 200
  @overlap_seconds 60

  @typedoc "What a connection is opened with."
  @type opening :: %{
          store: {module(), term()},
          signals: atom(),
          stream_prefix: String.t(),
          filter: %{optional(:kind_path | :session | :actor) => String.t()}
        }

  @doc """
  Hand an already authorised request over to a connection. A request
  that is not a WebSocket handshake is answered 426.
  """
  @spec upgrade(Plug.Conn.t(), opening()) :: Plug.Conn.t()
  def upgrade(conn, opening) do
    WebSockAdapter.upgrade(conn, __MODULE__, opening, compress: false, timeout: @idle_ms)
  rescue
    WebSockAdapter.UpgradeError ->
      conn
      |> Plug.Conn.put_resp_header("upgrade", "websocket")
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(426, ~s({"error":"ERR_WEBSOCKET_REQUIRED"}))
  end

  @doc "The frame that carries one record's row."
  @spec frame(map()) :: String.t()
  def frame(row), do: JSON.encode!(%{"type" => "record", "record" => row})

  @impl WebSock
  def init(opening) do
    :ok = Signals.subscribe(opening.signals, :shipped)
    Process.send_after(self(), :ping, @ping_ms)

    since = DateTime.add(DateTime.utc_now(), -@overlap_seconds, :second)
    {:ok, Map.merge(opening, %{seen: %{}, since: since})}
  end

  @impl WebSock
  def handle_in({text, opcode: :text}, state) do
    case JSON.decode(text) do
      {:ok, %{"type" => "ping"}} -> {:push, [{:text, ~s({"type":"pong"})}], state}
      _ -> {:ok, state}
    end
  end

  def handle_in(_frame, state), do: {:ok, state}

  @impl WebSock
  def handle_info({:provenance, :shipped, stream, through}, state) do
    if String.starts_with?(stream, state.stream_prefix),
      do: arrived(stream, through, state),
      else: {:ok, state}
  end

  def handle_info(:ping, state) do
    Process.send_after(self(), :ping, @ping_ms)
    {:push, [{:text, ~s({"type":"ping"})}], state}
  end

  def handle_info(_other, state), do: {:ok, state}

  # Send what the stream gained since this connection last looked. A
  # read that fails leaves the position where it was, so the next signal
  # for the stream covers the same records again.
  defp arrived(stream, through, %{store: {module, handle}} = state) do
    known = Map.get(state.seen, stream)
    first = max((known || 0) + 1, through - @most + 1)

    with true <- first <= through,
         {:ok, entries} <- module.range(handle, stream, first, through) do
      frames = for entry <- entries, wanted?(entry, known, state), do: {:text, frame(row(entry))}
      state = %{state | seen: Map.put(state.seen, stream, through)}
      if frames == [], do: {:ok, state}, else: {:push, frames, state}
    else
      _ -> {:ok, state}
    end
  end

  # The first time a stream is heard of, its earlier records are not
  # news: only those captured since just before the connection opened.
  defp wanted?(entry, known, state),
    do: matches?(entry, state.filter) and (known != nil or recent?(entry, state.since))

  defp matches?(entry, filter) do
    Enum.all?(filter, fn
      {:kind_path, kind} -> entry.kind_path == kind
      {:session, session} -> entry.evidence["session"] == session
      {:actor, actor} -> entry.evidence["actor"] == actor
    end)
  end

  defp recent?(entry, since) do
    case DateTime.from_iso8601(entry.evidence["capturedAt"] || "") do
      {:ok, at, _offset} -> DateTime.compare(at, since) != :lt
      _ -> false
    end
  end

  @doc "A record as the list route and the tail give it."
  @spec row(Recurse.Provenance.Store.entry()) :: map()
  def row(entry) do
    labels = Recurse.Provenance.Evidence.labels(entry.evidence)

    %{
      "ref" => entry.ref,
      "policyOutcome" => labels["policyOutcome"],
      "target" => labels["target"],
      "stream" => entry.stream,
      "seq" => entry.seq,
      "kind" => entry.kind_path,
      "capturedAt" => entry.evidence["capturedAt"],
      "actor" => entry.evidence["actor"],
      "session" => entry.evidence["session"],
      "envelope" => entry.envelope
    }
  end
end
