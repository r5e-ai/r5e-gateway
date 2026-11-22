defmodule Recurse.Provenance.Writer do
  @moduledoc """
  The owner of one evidence stream.

  A stream is an ordered chain: every record names its position and the
  record before it. Something has to own "what is the next position and
  what came last", and that is this process. It is the only state here,
  and it is why writes to one stream are serialised.

  The work done under that serialisation is small and touches no disk
  or network: give a prepared request its position, sign it, hand the
  signed bytes to the log, and answer with the record's reference. A
  node runs several writers and spreads sessions across them, so no
  single process sees every request.

  A writer's stream id carries a fresh incarnation. If the writer or its
  log restarts, it opens a new stream instead of guessing where an old
  one ended.

  When the log reports that an earlier stream stopped uncleanly, the
  first records of the new stream say so: one `Observation` per stream,
  with topic `#{inspect("recorder.unclean-stop")}` and the last position
  that reached the disk. Records signed after that position were lost,
  and this is the only place that loss is stated.
  """

  use GenServer

  require Logger

  alias Recurse.Provenance.{Body, Capture, Definitions, Envelope, Log, Profile, Signals}

  @unclean_stop "recorder.unclean-stop"

  @submissions_kept 4096

  @type receipt :: %{ref: String.t(), stream: String.t(), seq: pos_integer()}

  @doc """
  Start a writer.

    * `:stream_base` — the stream id up to its incarnation
    * `:signer` — a `Recurse.Provenance.Key` signer; its key is the issuer
    * `:profile` — the capture profile every record cites
    * `:log` — the `Recurse.Provenance.Log` that persists this stream
    * `:signals` — the signals registry
    * `:clock` — `(-> DateTime.t())`, default `DateTime.utc_now/0`
    * `:actor` — the identity under which the writer records its own
      observations. Without one, an unclean stop is logged and not recorded.
    * `:content_dir` — where content waits; needed with `:actor`
  """
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc """
  Place a prepared request in the stream. Answers as soon as the record
  is signed; persistence follows and is announced as a signal.
  """
  @spec append(GenServer.server(), Capture.prepared()) :: {:ok, receipt()} | {:error, term()}
  def append(writer, prepared), do: GenServer.call(writer, {:append, prepared})

  @doc "The topic of the observation that opens a stream after an unclean stop."
  @spec unclean_stop_topic() :: String.t()
  def unclean_stop_topic, do: @unclean_stop

  @doc "The stream this writer owns."
  @spec stream(GenServer.server()) :: String.t()
  def stream(writer), do: GenServer.call(writer, :stream)

  @impl true
  def init(opts) do
    profile = Keyword.fetch!(opts, :profile)
    incarnation = Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    {:ok,
     %{
       stream: Keyword.fetch!(opts, :stream_base) <> ":" <> incarnation,
       head: nil,
       signer: Keyword.fetch!(opts, :signer),
       profile: profile,
       profile_ref: Profile.ref(profile),
       log: Keyword.fetch!(opts, :log),
       signals: Keyword.fetch!(opts, :signals),
       clock: Keyword.get(opts, :clock, &DateTime.utc_now/0),
       actor: Keyword.get(opts, :actor),
       content_dir: Keyword.get(opts, :content_dir),
       submissions: %{},
       submission_order: :queue.new()
     }, {:continue, :begin}}
  end

  # Runs before any append, so these are the stream's first records.
  @impl true
  def handle_continue(:begin, state) do
    state =
      state.log
      |> Log.begin(state.stream)
      |> Enum.reduce(state, &record_unclean_stop/2)

    {:noreply, state}
  end

  defp record_unclean_stop(unclean, %{actor: nil} = state) do
    Logger.warning(
      "provenance writer: stream #{unclean.stream} stopped uncleanly after position " <>
        "#{unclean.last_seq}; no actor is configured, so this is not recorded"
    )

    state
  end

  defp record_unclean_stop(unclean, state) do
    request = %{
      kind_path: Definitions.api_version() <> "/Observation",
      actor: state.actor,
      body:
        Body.observation(
          topic: @unclean_stop,
          about: unclean.last_ref,
          details: %{"stream" => unclean.stream, "lastDurableSeq" => unclean.last_seq}
        )
    }

    with {:ok, prepared} <- Capture.prepare(request, state.profile, state.content_dir),
         {:ok, _receipt, state} <- record(prepared, state) do
      state
    else
      {:error, reason} ->
        Logger.error(
          "provenance writer: could not record the unclean stop of #{unclean.stream}: " <>
            inspect(reason)
        )

        state
    end
  end

  @impl true
  def handle_call(:stream, _from, state), do: {:reply, state.stream, state}

  def handle_call({:append, prepared}, _from, state) do
    case prior_submission(prepared, state) do
      {:replay, receipt} -> {:reply, {:ok, receipt}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
      :new -> sign_and_hand_off(prepared, state)
    end
  end

  defp sign_and_hand_off(prepared, state) do
    case record(prepared, state) do
      {:ok, receipt, state} -> {:reply, {:ok, receipt}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  defp record(prepared, state) do
    {seq, previous} =
      case state.head do
        nil -> {1, nil}
        {last, ref} -> {last + 1, ref}
      end

    evidence =
      Capture.evidence(prepared, %{
        profile_ref: state.profile_ref,
        issuer: state.signer.key_id,
        stream: state.stream,
        seq: seq,
        previous: previous,
        captured_at: state.clock.()
      })

    with :ok <- Profile.check(state.profile, evidence),
         {:ok, %{envelope: envelope, ref: ref}} <- Envelope.sign(evidence, state.signer) do
      Log.append(state.log, %{
        stream: state.stream,
        seq: seq,
        ref: ref,
        kind_path: prepared.request.kind_path,
        envelope: envelope,
        content: prepared.content
      })

      Signals.publish(state.signals, :captured, state.stream, seq)
      receipt = %{ref: ref, stream: state.stream, seq: seq}
      {:ok, receipt, remember(%{state | head: {seq, ref}}, prepared, receipt)}
    end
  end

  # A retry under the same submission handle gets the same answer and no
  # second record. The same handle with different content is an error.
  defp prior_submission(%{request: %{submission_id: id}, digest: digest}, state)
       when is_binary(id) do
    case state.submissions do
      %{^id => {^digest, receipt}} -> {:replay, receipt}
      %{^id => _different} -> {:error, :submission_reused_with_different_content}
      _ -> :new
    end
  end

  defp prior_submission(_prepared, _state), do: :new

  # Only recent handles are kept: a retry arrives soon after its first
  # attempt, and an unbounded table would grow with the stream.
  defp remember(state, %{request: %{submission_id: id}, digest: digest}, receipt)
       when is_binary(id) do
    order = :queue.in(id, state.submission_order)
    submissions = Map.put(state.submissions, id, {digest, receipt})

    if map_size(submissions) > @submissions_kept do
      {{:value, oldest}, order} = :queue.out(order)
      %{state | submissions: Map.delete(submissions, oldest), submission_order: order}
    else
      %{state | submissions: submissions, submission_order: order}
    end
  end

  defp remember(state, _prepared, _receipt), do: state
end
