defmodule Recurse.Provenance.Pipeline do
  @moduledoc """
  Evidence capture for one node, start to finish.

      caller ──prepare──▶ writer ──signed──▶ log ──durable──▶ shipper ──▶ index + content store
               (own CPU)   (position,         (batched          (batched,
                            signature)         write + sync)     idempotent)

  A capture is a short conversation with one writer: the caller prepares
  the request on its own time, the writer gives it a position and signs
  it, and the caller has the record's reference. Nothing in that touches
  a disk or a network. The log makes the record durable a moment later,
  the shipper moves it to the index after that, and each step announces
  itself through `Recurse.Provenance.Signals`.

  ## Processes

  There are several writers, each with its own stream, log and shipper.
  A request is routed by its session (or its actor), so one session's
  records stay in order in one stream while different sessions proceed
  in parallel. One further writer owns the control stream, where seals
  are recorded.

  Each writer, log and shipper trio is supervised as a unit. If any of
  the three fails they restart together and the writer opens a new
  stream, because a chain whose tail may not have reached the disk must
  not be continued.

  A stream that stopped without closing its log is reported by the
  stream that replaces it; see `Recurse.Provenance.Writer`.

  Sealing runs when asked, through `seal_all/2`; the host decides when.
  """

  use Supervisor

  alias Recurse.Provenance.{
    Capture,
    Definitions,
    Envelope,
    Epoch,
    Evidence,
    Log,
    Profile,
    Ref,
    Shipper,
    Signals,
    Staging,
    Writer
  }

  @type t :: atom()

  @doc """
  Start a pipeline.

    * `:name` — an atom that identifies this pipeline (required)
    * `:dir` — directory for segments and waiting content (required)
    * `:stream_prefix` — the stream id prefix the profile grants (required)
    * `:signer`, `:profile` — as for `Recurse.Provenance.Writer` (required)
    * `:index` — `{module, handle}` implementing `Recurse.Provenance.Store` (required)
    * `:actor` — the identity under which the pipeline records its own
      observations, such as an earlier unclean stop. The profile must
      grant it. Without one, an unclean stop is logged and not recorded.
    * `:partitions` — number of data writers (default: schedulers online)
    * `:flush_interval_ms`, `:max_batch` — passed to each log
    * `:staging` — how content waits on disk until it is shipped
      (`Recurse.Provenance.Staging`); plain files by default
  """
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    Supervisor.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def init(opts) do
    name = Keyword.fetch!(opts, :name)
    dir = Keyword.fetch!(opts, :dir)
    profile = Keyword.fetch!(opts, :profile)
    {index_module, index_handle} = index = Keyword.fetch!(opts, :index)
    partitions = Keyword.get(opts, :partitions, System.schedulers_online())
    staging = Keyword.get(opts, :staging) || Staging.plain()
    content_dir = Path.join(dir, "content")
    File.mkdir_p!(content_dir)

    :ok = Profile.validate(profile)
    :ok = retain_definitions(index_module, index_handle, profile)
    signer = Keyword.fetch!(opts, :signer)

    :ok =
      index_module.put_key(index_handle, %{
        key_id: signer.key_id,
        algorithm: signer.algorithm,
        public_key: signer.public_key
      })

    :persistent_term.put({__MODULE__, name}, %{
      key_id: signer.key_id,
      stream_prefix: Keyword.fetch!(opts, :stream_prefix),
      names: names(name),
      signals: signals(name),
      partitions: partitions,
      profile: profile,
      profile_ref: Profile.ref(profile),
      content_dir: content_dir,
      staging: staging,
      index: index
    })

    prefix = Keyword.fetch!(opts, :stream_prefix)

    trio = fn id, stream_base ->
      Supervisor.child_spec(
        {__MODULE__.Trio,
         id: id,
         names: names(name),
         signals: signals(name),
         stream_base: stream_base,
         signer: Keyword.fetch!(opts, :signer),
         actor: Keyword.get(opts, :actor),
         profile: profile,
         index: index,
         dir: Path.join([dir, "segments", to_string(id)]),
         content_dir: content_dir,
         staging: staging,
         log_opts: Keyword.take(opts, [:flush_interval_ms, :max_batch])},
        id: {:trio, id}
      )
    end

    children =
      [
        {Registry, keys: :unique, name: names(name)},
        Signals.child_spec(signals(name))
      ] ++
        for(i <- 0..(partitions - 1), do: trio.(i, "#{prefix}gateway:#{i}")) ++
        [trio.(:control, "#{prefix}control")]

    # The registries come first and the trios depend on them.
    Supervisor.init(children, strategy: :rest_for_one)
  end

  # -- API ---------------------------------------------------------------

  @doc """
  Capture one fact. Answers with the record's reference, stream and
  position as soon as it is signed. Durability and shipping follow as
  signals; this never waits for them.
  """
  @spec capture(t(), Capture.request()) :: {:ok, Writer.receipt()} | {:error, term()}
  def capture(pipeline, request) do
    info = info(pipeline)

    with {:ok, prepared} <-
           Capture.prepare(request, info.profile, info.content_dir, &installed(info, &1),
             staging: info.staging
           ) do
      partition = :erlang.phash2(request[:session] || request.actor, info.partitions)
      Writer.append(via(info, {:writer, partition}), prepared)
    end
  end

  @doc """
  Record an envelope that was signed outside this pipeline, as the first
  and only record of a stream of its own.

  This is for records that more than one party signs, such as a badge:
  the payload has to be fixed before the second party can sign it, so its
  stream and position cannot be handed out by a writer at the moment of
  signing. Giving each such record its own stream means an exchange that
  is abandoned half way leaves no gap in anybody's sequence.

  The record is taken only when all of this holds:

    * its first signer is this pipeline's own key: a pipeline records
      what it issued, not what it was handed;
    * every signature verifies against `keys` (this pipeline's key is
      added);
    * it is at position 1 with no predecessor, on a stream beginning with
      this pipeline's prefix followed by `authority:`, and cites this
      pipeline's profile;
    * its body matches its definition, including the number of signers
      and any field the definition binds to one, and the profile allows it.

  Answers like `capture/2`, as soon as the record is handed to the log.
  Offering a record that is already held answers the same again and
  records nothing new.
  """
  @spec admit(t(), Envelope.t(), Envelope.keys()) :: {:ok, Writer.receipt()} | {:error, term()}
  def admit(pipeline, envelope, keys \\ %{}) do
    info = info(pipeline)
    {module, handle} = info.index
    wanted = info.stream_prefix <> "authority:"

    with {:ok, %{evidence: evidence, ref: ref} = opened} <- Envelope.open(envelope),
         {:ok, own} <- module.get_key(handle, info.key_id),
         keys = Map.put(keys, info.key_id, %{algorithm: own.algorithm, bytes: own.public_key}),
         :ok <- Envelope.verify(opened, keys),
         :new <- already(module, handle, ref),
         %{"issuer" => issuer, "stream" => stream, "seq" => 1} <- evidence,
         true <- issuer == info.key_id || {:error, :not_issued_here},
         true <- is_nil(evidence["previous"]) || {:error, :not_first_in_stream},
         true <- String.starts_with?(stream, wanted) || {:error, :stream_not_admissible},
         true <- evidence["profileRef"] == info.profile_ref || {:error, :another_profile},
         {:ok, :validated} <-
           Evidence.validate(evidence,
             definitions: &installed(info, &1),
             signers: Envelope.signers(opened)
           ),
         :ok <- Profile.check(info.profile, evidence) do
      Log.append(via(info, {:log, :control}), %{
        stream: stream,
        seq: 1,
        ref: ref,
        kind_path: Evidence.kind_path(evidence),
        envelope: envelope,
        content: []
      })

      Signals.publish(info.signals, :captured, stream, 1)
      {:ok, %{ref: ref, stream: stream, seq: 1}}
    else
      {:held, receipt} -> {:ok, receipt}
      {:error, _} = error -> error
      {:ok, :body_unsupported} -> {:error, :definition_not_available}
      %{} -> {:error, :not_first_in_stream}
      other -> {:error, other}
    end
  end

  @doc """
  Record an envelope that somebody else issued, under that issuer's own
  profile, on a stream inside this pipeline's prefix.

  Two things a deployment must hold are written by keys that are not this
  pipeline's: the records of how the chain began, signed by the node's
  bootstrap key, and the grants a customer's root gives, signed by that
  root. They are recorded here so that they are sealed and exported like
  everything else, which is what fixes them in time.

  `profile` is the issuer's capture profile; the record must cite it and
  fit inside it. `under` is the part of this pipeline's stream space the
  record may be written to (for example `"start"` or
  `"authority:root:"`). `keys` are the public keys of every signer.

  The record is taken only when every signature verifies, its body
  matches its definition, and it sits where the stream says the next
  record goes: position 1 with nothing before it, or the position after
  the stream's last record, naming that record as the one before. A
  different record at a position already taken is refused as a fork.
  The same record offered again answers the same.

  The issuer's profile and the signers' keys are kept with the record,
  so an export can carry them.
  """
  @spec accept(t(), Envelope.t(), Envelope.keys(), Profile.t(), String.t()) ::
          {:ok, Writer.receipt()} | {:error, term()}
  def accept(pipeline, envelope, keys, profile, under) when is_binary(under) do
    info = info(pipeline)
    {module, handle} = info.index
    wanted = info.stream_prefix <> under

    with {:ok, %{evidence: evidence, ref: ref} = opened} <- Envelope.open(envelope),
         :ok <- Envelope.verify(opened, keys),
         # Whatever was accepted a moment ago is in the index before this
         # one is compared with it.
         :ok <- flush(pipeline),
         :new <- already(module, handle, ref),
         %{"stream" => stream, "seq" => seq} <- evidence,
         true <- String.starts_with?(stream, wanted) || {:error, :stream_not_admissible},
         true <- evidence["profileRef"] == Profile.ref(profile) || {:error, :another_profile},
         {:ok, :validated} <-
           Evidence.validate(evidence,
             definitions: &installed(info, &1),
             signers: Envelope.signers(opened)
           ),
         :ok <- Profile.check(profile, evidence),
         :ok <- next_in_stream(module, handle, stream, seq, evidence["previous"]),
         :ok <- module.put_blob(handle, Profile.ref(profile), Profile.encode(profile)),
         :ok <- keep_keys(module, handle, keys) do
      Log.append(via(info, {:log, :control}), %{
        stream: stream,
        seq: seq,
        ref: ref,
        kind_path: Evidence.kind_path(evidence),
        envelope: envelope,
        content: []
      })

      Signals.publish(info.signals, :captured, stream, seq)
      {:ok, %{ref: ref, stream: stream, seq: seq}}
    else
      {:held, receipt} -> {:ok, receipt}
      {:error, _} = error -> error
      {:ok, :body_unsupported} -> {:error, :definition_not_available}
      other -> {:error, other}
    end
  end

  # A record goes at position 1 of an empty stream, or straight after the
  # stream's last record, naming it.
  defp next_in_stream(module, handle, stream, seq, previous) do
    case module.head(handle, stream) do
      {:ok, nil} when seq == 1 and is_nil(previous) -> :ok
      {:ok, {last, ref}} when seq == last + 1 and previous == ref -> :ok
      {:ok, {last, _ref}} when seq <= last -> {:error, :stream_fork_refused}
      {:ok, _} -> {:error, :not_next_in_stream}
      {:error, reason} -> {:error, reason}
    end
  end

  defp keep_keys(module, handle, keys) do
    Enum.reduce_while(keys, :ok, fn {key_id, %{algorithm: algorithm, bytes: bytes}}, :ok ->
      case module.put_key(handle, %{key_id: key_id, algorithm: algorithm, public_key: bytes}) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  # The same record offered again, as when a caller did not hear the first
  # answer and retries: it is already held, and the answer is the same.
  defp already(module, handle, ref) do
    case module.fetch(handle, ref) do
      {:ok, %{stream: stream, seq: seq}} -> {:held, %{ref: ref, stream: stream, seq: seq}}
      :error -> :new
    end
  end

  @doc "The signals registry, for `Recurse.Provenance.Signals.subscribe/2`."
  @spec signals(t()) :: atom()
  def signals(pipeline), do: Module.concat(pipeline, Signals)

  @doc "The streams the data writers currently own."
  @spec streams(t()) :: [String.t()]
  def streams(pipeline) do
    info = info(pipeline)
    for i <- 0..(info.partitions - 1), do: Writer.stream(via(info, {:writer, i}))
  end

  @doc "The profile reference every record of this pipeline cites."
  @spec profile_ref(t()) :: Ref.t()
  def profile_ref(pipeline), do: info(pipeline).profile_ref

  @doc """
  Write, sync and ship everything captured so far, and answer when it is
  in the index. For shutdown, sealing and tests; never on a request path.
  """
  @spec flush(t()) :: :ok | {:error, term()}
  def flush(pipeline) do
    info = info(pipeline)

    Enum.reduce_while(ids(info), :ok, fn id, :ok ->
      :ok = Log.flush(via(info, {:log, id}))

      case Shipper.sync(via(info, {:shipper, id})) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  @doc """
  Seal the shipped records of `stream` that no seal covers yet, as an
  `EpochSeal` on the control stream. `{:ok, :nothing_to_seal}` when there
  are none.
  """
  @spec seal(t(), String.t(), String.t()) ::
          {:ok, Writer.receipt() | :nothing_to_seal} | {:error, term()}
  def seal(pipeline, stream, actor) do
    info = info(pipeline)
    {module, handle} = info.index

    with {:ok, covered} <- module.last_seal(handle, stream),
         {:ok, head} <- module.head(handle, stream) do
      {previous_seal, sealed_through} = covered || {nil, 0}

      case head do
        {last, _ref} when last > sealed_through ->
          first = sealed_through + 1
          {:ok, entries} = module.range(handle, stream, first, last)

          {body, manifest} =
            Epoch.seal_body(stream, first, Enum.map(entries, & &1.ref), previous_seal)

          {kind_path, _ref} = Epoch.seal_kind()
          request = %{kind_path: kind_path, body: body, actor: actor, blobs: [manifest]}

          with {:ok, prepared} <-
                 Capture.prepare(request, info.profile, info.content_dir, &installed(info, &1),
                   recorder?: true,
                   staging: info.staging
                 ) do
            Writer.append(via(info, {:writer, :control}), prepared)
          end

        _nothing_new ->
          {:ok, :nothing_to_seal}
      end
    end
  end

  @doc """
  Flush, then seal every data stream and every admitted record's stream
  that no seal covers yet. Returns the seals written.
  """
  @spec seal_all(t(), String.t()) :: {:ok, [Writer.receipt()]} | {:error, term()}
  def seal_all(pipeline, actor) do
    with :ok <- flush(pipeline) do
      %{index: {module, handle}} = info = info(pipeline)

      # Admitted records are found in the index, not remembered here, so
      # one admitted before a restart is sealed after it.
      with {:ok, admitted} <- module.unsealed_firsts(handle, info.stream_prefix <> "authority:"),
           {:ok, start} <- module.unsealed_firsts(handle, info.stream_prefix <> "start"),
           {:ok, kept} <- module.unsealed_firsts(handle, info.stream_prefix <> "retention"),
           # Records workloads signed themselves, and what the gateway
           # noted about them. A seal is the only thing that bounds a
           # workload's own date on a record.
           {:ok, endpoint} <- module.unsealed_firsts(handle, info.stream_prefix <> "endpoint:"),
           {:ok, security} <- module.unsealed_firsts(handle, info.stream_prefix <> "security"),
           # Definitions a publisher added while the deployment ran.
           {:ok, defined} <- module.unsealed_firsts(handle, info.stream_prefix <> "definitions:"),
           # What was provided to whom outside the deployment.
           {:ok, disclosed} <- module.unsealed_firsts(handle, info.stream_prefix <> "disclosures") do
        seals =
          for stream <-
                streams(pipeline) ++
                  admitted ++ start ++ kept ++ endpoint ++ security ++ defined ++ disclosed,
              {:ok, %{ref: _} = receipt} <- [seal(pipeline, stream, actor)],
              do: receipt

        with :ok <- flush(pipeline), do: {:ok, seals}
      end
    end
  end

  # -- internals ---------------------------------------------------------

  defp info(pipeline), do: :persistent_term.get({__MODULE__, pipeline})
  defp names(pipeline), do: Module.concat(pipeline, Names)
  defp via(info, key), do: {:via, Registry, {info.names, key}}
  defp ids(info), do: Enum.to_list(0..(info.partitions - 1)) ++ [:control]

  # An extension definition document the index holds.
  defp installed(%{index: {module, handle}}, ref), do: module.get_blob(handle, ref)

  # The profile and every base definition it maps are held before the
  # first record, so a later export can always carry them.
  defp retain_definitions(module, handle, profile) do
    profile_bytes = Profile.encode(profile)

    blobs =
      [{Ref.bytes(profile_bytes), profile_bytes}] ++
        for(%{ref: ref, bytes: bytes} <- Definitions.documents(), do: {ref, bytes})

    Enum.reduce_while(blobs, :ok, fn {ref, bytes}, :ok ->
      case module.put_blob(handle, ref, bytes) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defmodule Trio do
    @moduledoc """
    One writer with its log and its shipper, supervised as a unit.

    The three depend on one another: the log tells its shipper what is
    durable, and the writer hands its log what it signed. If any of them
    fails, all three restart and the writer opens a new stream.
    """
    use Supervisor

    alias Recurse.Provenance.{Log, Shipper, Writer}

    def start_link(opts), do: Supervisor.start_link(__MODULE__, opts)

    @impl true
    def init(opts) do
      id = Keyword.fetch!(opts, :id)
      names = Keyword.fetch!(opts, :names)
      via = fn role -> {:via, Registry, {names, {role, id}}} end

      children = [
        {Shipper,
         name: via.(:shipper),
         dir: opts[:dir],
         content_dir: opts[:content_dir],
         staging: opts[:staging],
         index: opts[:index],
         signals: opts[:signals]},
        {Log,
         [name: via.(:log), dir: opts[:dir], signals: opts[:signals], notify: via.(:shipper)] ++
           opts[:log_opts]},
        {Writer,
         name: via.(:writer),
         stream_base: opts[:stream_base],
         signer: opts[:signer],
         profile: opts[:profile],
         log: via.(:log),
         signals: opts[:signals],
         actor: opts[:actor],
         content_dir: opts[:content_dir]}
      ]

      Supervisor.init(children, strategy: :one_for_all)
    end
  end
end
