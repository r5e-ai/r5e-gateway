defmodule Recurse.Gateway.Provenance.Disclosing do
  @moduledoc """
  Providing recorded evidence to someone outside the deployment, and
  serving what was provided to the public.

  Everything recorded is kept under a key. Nothing leaves that way of
  keeping by default. To provide named records to someone, a person who
  is allowed to asks for it, and the gateway:

    1. finds each record asked for. A record that keeps, holds or
       disposes of other content, or that the gateway wrote about a
       fault, is not one that can be provided;
    2. looks through the record itself and through all the content it
       names for things that look like secrets (`Secrets`). A record's
       own content is what its `contentRef` names. Anything else its body
       refers to (the policy a call was judged by, the inputs to that
       judgement) belongs to the deployment and is provided only when the
       request names it in `include`. It is read here all the same,
       except the policy a call was judged by, which is the same text
       for every call and is read only when asked for;
    3. leaves a record out whole when its own fields, or any content it
       names, are flagged. A provided record shows the hash and size of
       everything it names, and a secret inside a predictable document
       can be found by trying values against that hash. Content that
       could not be read (the key service did not answer, or the content
       was disposed of) or could not be scanned keeps its record out as
       well, unless the request names that content in `withhold`;
    4. withholds, from a record that is provided, content the request
       asked to withhold. Its hash and size stay visible in the record.
       To hide them, do not ask for the record;
    5. signs one `Disclosure` record saying what was asked for, what was
       provided, to whom, on whose request, and what the scan did.

  The `Disclosure` goes on a stream of its own, so it is sealed and
  exported like anything else and the records it is about are untouched.

  When the recipient is the public (`urn:r5e:audience:public`) and this
  deployment has public reading switched on (`R5E_EVIDENCE_PUBLIC_READ`),
  a record that was provided can be fetched with no login, as a bundle
  that verifies like any other. Content that was withheld is listed in
  it as withheld.

  ## What is public, and for which record

  The set of public things is kept per record: for each record provided
  to the public, the content that was provided *with it*. Content that
  is public through one record is not thereby public through another
  that happens to hold the same bytes and withheld them.

  The set is ETS, owned by the evidence runtime's supervisor, read by
  the public route without touching the database, and rebuilt as capture
  starts from the `Disclosure` records on the disclosures stream. This
  module is functions over that table, not a process. The table is this
  node's: a disclosure made on another node sharing the database is seen
  here at the next start.

  ## The public route is open to anyone

  So a built bundle is kept for a short while and served again, only a
  few are built at once, and a request beyond that is asked to come back.
  A stranger cannot make the gateway decrypt the same content over and
  over.

  Providing cannot be taken back. A copy made by a reader stays made.
  """

  require Logger

  alias Recurse.Gateway.Provenance.{Carried, Enrolment, Runtime, Secrets}
  alias Recurse.Provenance.{Body, Definitions, Envelope, Evidence, Exporter, Pipeline, Ref}
  alias RecurseVerify.Canonical

  @table __MODULE__
  @kind "Disclosure"
  @public "urn:r5e:audience:public"
  @most 256
  @identity ~r/\A[A-Za-z][A-Za-z0-9+.-]*:[^\s]+\z/
  # Records about the deployment's own keeping of content and its own
  # faults. Their fields name other people's sessions and say why content
  # was held; they are never what someone asks to have published.
  @not_provided ~w[RetentionHold RetentionHoldRelease PayloadDisposition Disclosure
                   EpochSeal Checkpoint]
  @building 4
  @kept_ms 300_000
  @kept_bytes 1_048_576

  @type error ::
          :malformed_request
          | :gateway_may_not_record_this
          | :stream_fork_refused
          | atom()

  @doc "The identity that stands for the public as a recipient."
  @spec public() :: String.t()
  def public, do: @public

  @doc "The stream a deployment's disclosures are written to."
  @spec stream(String.t()) :: String.t()
  def stream(deployment), do: "urn:r5e:stream:#{deployment}:disclosures"

  # -- what is public ----------------------------------------------------------

  @doc """
  Create the table and fill it from the disclosures already recorded on
  this deployment's disclosures stream. Called once as capture starts.

  Only the gateway writes to that stream: records are taken onto it
  under the gateway's own profile, and workloads are refused any stream
  outside their own. So what is on it counts whichever of the gateway's
  keys signed it, including one since replaced.
  """
  @spec init({module(), term()}, String.t()) :: :ok
  def init({module, handle}, deployment) do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    end

    :ets.delete_all_objects(@table)
    :ets.insert(@table, {:building, 0})
    wanted = stream(deployment)

    case module.by_kind(handle, path(), wanted) do
      {:ok, entries} ->
        # The read is by prefix; only this exact stream makes anything public.
        for %{stream: ^wanted, evidence: evidence} <- entries,
            do: note(evidence["body"])

      {:error, reason} ->
        Logger.warning("evidence: disclosures not read at start: #{inspect(reason)}")
    end

    :ok
  end

  @doc "Forget what is public. Called as capture stops."
  @spec unload() :: :ok
  def unload do
    if :ets.whereis(@table) != :undefined, do: :ets.delete_all_objects(@table)
    :ok
  end

  @doc "Whether a record was provided to the public."
  @spec public?(String.t()) :: boolean()
  def public?(ref) when is_binary(ref),
    do: :ets.whereis(@table) != :undefined and :ets.member(@table, {:record, ref})

  def public?(_other), do: false

  @doc """
  Whether `content` was provided to the public together with `record`.
  The same bytes provided with another record do not count.
  """
  @spec public_with?(String.t(), String.t()) :: boolean()
  def public_with?(record, content), do: MapSet.member?(provided_with(record), content)

  defp provided_with(record) do
    with true <- :ets.whereis(@table) != :undefined,
         [{_key, content}] <- :ets.lookup(@table, {:record, record}) do
      content
    else
      _ -> MapSet.new()
    end
  end

  # A disclosure to the public makes each record it provided public, with
  # the content provided in that same disclosure. A bundle carries only
  # the content its record names, so content provided for one record goes
  # with another only when both were provided together and both name it.
  # A record provided again keeps what was provided with it before:
  # providing is not taken back.
  defp note(%{"recipient" => @public, "providedRefs" => refs}) when is_list(refs) do
    if :ets.whereis(@table) != :undefined do
      content = refs |> Enum.filter(&Ref.valid?(&1, :bytes)) |> MapSet.new()

      for ref <- refs, Ref.valid?(ref, :evidence) do
        :ets.insert(@table, {{:record, ref}, MapSet.union(provided_with(ref), content)})
        :ets.delete(@table, {:bundle, ref})
      end
    end

    :ok
  end

  defp note(_not_to_the_public), do: :ok

  # -- providing ---------------------------------------------------------------

  @doc """
  Provide named records. `request` has `records` (their `evidence:`
  references, at most #{@most}) and `recipient` (an identity; the public
  is `#{@public}`), and may have `include` (content references, beyond a
  record's own content, to provide as well), `withhold` (content
  references to leave out whatever the scan says) and `reason`.
  `on_behalf_of` is who asked, as authenticated; it is never taken from
  the request.

  Returns the `Disclosure`'s reference with what was provided and what
  was withheld and why.
  """
  @spec disclose(term(), String.t()) :: {:ok, map()} | {:error, error()}
  def disclose(%{"records" => [_ | _] = asked, "recipient" => recipient} = request, on_behalf_of)
      when length(asked) <= @most and is_binary(recipient) and is_binary(on_behalf_of) do
    info = Runtime.info()

    # The whole request is judged before anything is read or signed.
    with :ok <- well_formed(asked, recipient, request),
         :ok <- may_record(info),
         :ok <- Runtime.flush() do
      judged = judge_all(info, asked, request)
      records = for {ref, :provided, _pieces} <- judged, do: ref
      pieces = for {_ref, :provided, pieces} <- judged, piece <- pieces, do: piece
      clean = Enum.uniq(for {ref, :clean} <- pieces, do: ref)

      # The same bytes provided through one record and withheld through
      # another are provided; the record that withheld them still does
      # not bring them.
      withheld =
        for({ref, why} <- judged_reasons(judged) ++ pieces, why != :clean, do: {ref, why})
        |> Enum.uniq()
        |> Enum.reject(fn {ref, _why} -> ref in clean end)

      outcome =
        cond do
          records == [] -> "denied"
          length(records) == length(asked) and withheld == [] -> "provided"
          true -> "partial"
        end

      body =
        Body.disclosure(
          requested_refs: asked,
          provided_refs: records ++ clean,
          recipient: recipient,
          outcome: outcome,
          reason: request["reason"],
          details: %{
            "scan.rules" => Enum.join(Secrets.rules(), ","),
            "scan.pieces" => length(pieces),
            "scan.withheld" => length(withheld)
          }
        )

      with {:ok, receipt} <- record(info, body, on_behalf_of) do
        # From the signed body, exactly as it is read back at the next
        # start, so what is public does not change across a restart.
        note(body)

        {:ok,
         %{
           "ref" => receipt.ref,
           "outcome" => outcome,
           "provided" => records ++ clean,
           "notProvided" => asked -- Enum.map(judged, &elem(&1, 0)),
           "withheld" => for({ref, why} <- withheld, do: %{"ref" => ref, "reason" => why})
         }}
      end
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :malformed_request}
    end
  catch
    :key_service_unavailable -> {:error, :key_service_unavailable}
  end

  def disclose(_request, _on_behalf_of), do: {:error, :malformed_request}

  # Each record is judged on its own: its fields, then everything it
  # names by hash. Returns `{record, :provided, pieces}` or
  # `{record, reason, []}` for a record that is not provided. What one
  # piece of content was found to be through one scope is asked once.
  defp judge_all(%{store: {module, handle}} = info, asked, request) do
    include = MapSet.new(List.wrap(request["include"]))
    hold_back = MapSet.new(List.wrap(request["withhold"]))
    security = "urn:r5e:stream:#{info.deployment}:security"

    {judged, _seen} =
      Enum.flat_map_reduce(asked, %{}, fn ref, seen ->
        with {:ok, entry} <- module.fetch(handle, ref),
             true <- entry.evidence["kind"] not in @not_provided and entry.stream != security do
          {verdict, seen} = judge_record(entry, include, hold_back, {module, handle}, seen)
          {[verdict], seen}
        else
          _ -> {[], seen}
        end
      end)

    judged
  end

  defp judge_record(entry, include, hold_back, store, seen) do
    case Secrets.scan(Canonical.encode(entry.evidence["body"])) do
      :clean ->
        bring = content_of(entry, include)
        named = Enum.uniq(bring ++ (Exporter.content_refs([entry]) -- policy_of(entry)))
        scope = Evidence.content_scope(entry.evidence)

        {scans, seen} =
          Enum.map_reduce(named, seen, fn content, seen ->
            case seen do
              %{{^content, ^scope} => verdict} ->
                {{content, verdict}, seen}

              _ ->
                verdict = judge(content, scope, store)
                {{content, verdict}, Map.put(seen, {content, scope}, verdict)}
            end
          end)

        case standing_in_the_way(scans, hold_back) do
          nil ->
            pieces =
              for content <- bring do
                if MapSet.member?(hold_back, content),
                  do: {content, "asked-to-withhold"},
                  else: {content, :clean}
              end

            {{entry.ref, :provided, pieces}, seen}

          reason ->
            {{entry.ref, reason, []}, seen}
        end

      {:flagged, names} ->
        {{entry.ref, "record-flagged:" <> Enum.join(names, ","), []}, seen}

      :not_scanned ->
        {{entry.ref, "record-not-scanned", []}, seen}
    end
  end

  # The policy a call was judged by is the deployment's own text, the
  # same for every call, and not something a session produced. It is
  # read only when the request asks for it to be provided; otherwise one
  # phrase in it that resembles a secret would keep every call back.
  defp policy_of(entry) do
    body = entry.evidence["body"]

    for field <- ["policy", "evaluation"],
        %{"policyRef" => ref} when is_binary(ref) <- [body[field]],
        do: ref
  end

  # Why a record that names this content cannot be provided, or nil. A
  # provided record shows the hash and the size of everything it names.
  # Flagged content is typically a predictable document around one short
  # unknown value, which can be found by trying values against that hash,
  # so it always keeps its record back. Content that could not be read
  # or could not be scanned may be the same thing unseen, so it keeps the
  # record back too, unless the request names it in `withhold`: whoever
  # asks has then said they know that content and accept its hash being
  # shown.
  defp standing_in_the_way(scans, hold_back) do
    flagged =
      for({_content, "flagged:" <> names} <- scans, name <- String.split(names, ","), do: name)
      |> Enum.uniq()
      |> Enum.sort()

    unseen =
      for(
        {content, why} <- scans,
        why in ["not-readable", "not-scanned"],
        not MapSet.member?(hold_back, content),
        do: why
      )
      |> Enum.uniq()
      |> Enum.sort()

    cond do
      flagged != [] -> "content-flagged:" <> Enum.join(flagged, ",")
      unseen != [] -> "content-" <> Enum.join(unseen, ",")
      true -> nil
    end
  end

  defp judged_reasons(judged),
    do: for({ref, why, _pieces} <- judged, why != :provided, do: {ref, why})

  defp well_formed(asked, recipient, request) do
    refs? = fn field ->
      case request[field] do
        nil -> true
        list when is_list(list) -> Enum.all?(list, &Ref.valid?(&1, :bytes))
        _ -> false
      end
    end

    reason = request["reason"]

    if Enum.all?(asked, &Ref.valid?(&1, :evidence)) and asked == Enum.uniq(asked) and
         Regex.match?(@identity, recipient) and byte_size(recipient) <= 512 and
         refs?.("include") and refs?.("withhold") and
         (is_nil(reason) or (is_binary(reason) and reason != "" and byte_size(reason) <= 1024)),
       do: :ok,
       else: {:error, :malformed_request}
  end

  # A record's own content, and whatever else of its content the request
  # asked for by name.
  defp content_of(entry, include) do
    own = entry.evidence["body"]["contentRef"]
    named = [entry] |> Exporter.content_refs() |> Enum.filter(&MapSet.member?(include, &1))
    Enum.uniq(Enum.filter([own], &Ref.valid?(&1, :bytes)) ++ named)
  end

  # What a piece of content is found to be, read as the record that
  # names it may read it: through that record's own scope.
  defp judge(content, scope, {module, handle}) do
    case module.get_content(handle, content, scope) do
      {:ok, bytes} when is_binary(bytes) -> scanned(Secrets.scan(bytes))
      # Nothing lasting is concluded from a key service that did not
      # answer: the whole request stops and nothing is signed.
      {:error, :key_service_unavailable} -> throw(:key_service_unavailable)
      _ -> "not-readable"
    end
  end

  defp scanned(:clean), do: :clean
  defp scanned({:flagged, names}), do: "flagged:" <> Enum.join(names, ",")
  defp scanned(:not_scanned), do: "not-scanned"

  # Signed by the gateway as the next record on the disclosures stream.
  # If another request took that position first this one is refused as a
  # fork and nothing is recorded.
  defp record(%{store: {module, handle}} = info, body, on_behalf_of) do
    {seq, previous} =
      case module.head(handle, stream(info.deployment)) do
        {:ok, {seq, ref}} -> {seq + 1, ref}
        _ -> {1, nil}
      end

    {:ok, %{ref: schema_ref}} = Definitions.fetch(path())

    evidence =
      Evidence.new(
        kind_path: path(),
        schema_ref: schema_ref,
        profile_ref: info.profile_ref,
        issuer: info.key_id,
        actor: info.actor,
        stream: stream(info.deployment),
        seq: seq,
        previous: previous,
        captured_at: DateTime.utc_now(),
        on_behalf_of: on_behalf_of,
        body: body
      )

    with {:ok, signed} <- Envelope.sign(evidence, info.signer),
         {:ok, receipt} <-
           Pipeline.accept(
             Runtime.pipeline(),
             signed.envelope,
             %{info.key_id => %{algorithm: info.algorithm, bytes: info.public_key}},
             info.profile,
             "disclosures"
           ),
         :ok <- Pipeline.flush(Runtime.pipeline()) do
      {:ok, receipt}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :malformed_request}
    end
  end

  # A deployment with roots records nothing its key holds no grant for:
  # the record would count for nothing with any reader.
  defp may_record(%{start_chain?: true, authority: standing}) do
    if Enrolment.covers?(standing, path()),
      do: :ok,
      else: {:error, :gateway_may_not_record_this}
  end

  defp may_record(_info), do: :ok

  defp path, do: Definitions.kind_path(Definitions.api_version(), @kind)

  # -- reading what is public --------------------------------------------------

  @doc "Whether this deployment serves what was provided to the public without a login."
  @spec public_reading?() :: boolean()
  def public_reading?,
    do: Application.get_env(:recurse_gateway, :evidence_public_read?, false) == true

  @doc """
  A record that was provided to the public, as the text of a bundle. It
  carries the content that was provided with that record and lists the
  rest as withheld. `:not_public` for anything else, whether or not it
  exists. `:busy` when too many are being built at once; ask again.
  """
  @spec public_bundle(String.t()) :: {:ok, binary()} | {:error, :not_public | :busy}
  def public_bundle(ref) do
    if is_binary(ref) and public_reading?() and public?(ref) do
      now = System.monotonic_time(:millisecond)

      case :ets.lookup(@table, {:bundle, ref}) do
        [{_key, text, until}] when until > now -> {:ok, text}
        _ -> build(ref, now)
      end
    else
      {:error, :not_public}
    end
  end

  # Building reads the database and may ask the key service to open
  # content, so only a few run at once.
  defp build(ref, now) do
    if :ets.update_counter(@table, :building, 1) > @building do
      :ets.update_counter(@table, :building, -1)
      {:error, :busy}
    else
      try do
        assemble(ref, now)
      after
        :ets.update_counter(@table, :building, -1)
      end
    end
  end

  defp assemble(ref, now) do
    with %{store: {module, handle} = store} <- Runtime.info(),
         {:ok, entry} <- module.fetch(handle, ref),
         {:ok, bundle} <-
           Exporter.bundle(store, [entry], %{"record" => ref}, content: provided_with(ref)) do
      text = JSON.encode!(Carried.carry(bundle, retention: false, security: false))

      if byte_size(text) <= @kept_bytes,
        do: :ets.insert(@table, {{:bundle, ref}, text, now + @kept_ms})

      {:ok, text}
    else
      _ -> {:error, :not_public}
    end
  end
end
