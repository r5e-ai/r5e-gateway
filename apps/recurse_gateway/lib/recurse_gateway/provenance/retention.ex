defmodule Recurse.Gateway.Provenance.Retention do
  @moduledoc """
  Holds on content, their release, and disposal of content, each as a
  record on this deployment's retention stream.

  Content is kept for ever unless the profile a record was made under
  says otherwise. Three things can then happen to it, and each is
  recorded before it is done, so that a reader of a later export can see
  what became of content that is no longer there:

    * a **hold** says named content, or everything recorded under a
      scope such as a session, must be kept. The gateway records it and
      the store gives that content one more lock, under the hold.
    * a **release** ends a hold. The gateway cannot do this alone: the
      person releasing signs the record as well, with their own key, in
      two steps. A gateway that has been taken over cannot quietly drop
      a hold.
    * a **disposal** destroys the key a scope's content is encrypted
      under. It is refused while a hold covers anything in the scope,
      and unless every record in the scope was made under a profile
      that allows disposal and the period that profile gives has run.

  All three go on one stream, `urn:r5e:stream:<deployment>:retention`,
  in order, so the order of a hold, its release and a disposal is never
  in doubt. Two requests arriving together compete for the next
  position; the loser is told and asks again.

  Disposal is by scope only. Naming single pieces of content to dispose
  of is not offered, because the store destroys keys by scope.
  """

  require Logger

  alias Recurse.Gateway.Provenance.{Carried, Claim, Enrolment, Grants, Runtime, SessionName}
  alias Recurse.Provenance.{Definitions, Envelope, Evidence, Export, Key, Pipeline, Publication}
  alias Recurse.Provenance.Retention, as: Rules
  alias RecurseVerify.Canonical

  @hold "RetentionHold"
  @release "RetentionHoldRelease"
  @disposal "PayloadDisposition"
  @ticket_context "r5e.hold-release-ticket/v1"
  @ticket_seconds 300
  @hold_scope "urn:r5e:hold:"
  @default_auto_hold_kinds ["education.r5e.io/v1/SafeguardingFlag"]

  @type error ::
          :malformed_request
          | :gateway_may_not_record_this
          | :stream_fork_refused
          | :no_such_hold
          | :hold_already_released
          | :releaser_has_no_standing
          | :nothing_to_dispose
          | :store_unavailable
          | {:under_hold, String.t()}
          | {:safeguarding_hold_pending, String.t()}
          | {:never_disposed_of | :kept_until | :profile_not_held, String.t()}
          | atom()

  @doc "This deployment's retention stream."
  @spec stream(String.t()) :: String.t()
  def stream(deployment), do: "urn:r5e:stream:#{deployment}:retention"

  @doc """
  Parse a comma-separated `R5E_EVIDENCE_AUTO_HOLD_KINDS` value into a
  deduplicated list of record kind paths (`namespace/version/Kind`).

  When `nil` (env var unset), defaults to `#{inspect(@default_auto_hold_kinds)}`.
  An explicit empty string (`""`) disables automatic holds.
  """
  @spec parse_auto_hold_kinds(String.t() | nil) :: [String.t()]
  def parse_auto_hold_kinds(nil), do: @default_auto_hold_kinds

  def parse_auto_hold_kinds(raw) when is_binary(raw) do
    raw
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  @doc """
  Return the configured record kind paths that automatically trigger an
  indefinite gateway-signed `RetentionHold` upon admission.

  Standing note: any party holding an active badge permitted to submit one of
  these kinds can trigger an indefinite `RetentionHold` on its own sessions,
  blocking owner/FERPA disposal until the two-step counselor/retention release
  completes. That is intentional so flagged evidence cannot be erased before
  review.
  """
  @spec auto_hold_kinds() :: [String.t()]
  def auto_hold_kinds do
    case Application.fetch_env(:recurse_gateway, :evidence_auto_hold_kinds) do
      {:ok, kinds} when is_list(kinds) ->
        kinds
        |> Enum.filter(&(is_binary(&1) and String.trim(&1) != ""))
        |> Enum.map(&String.trim/1)
        |> Enum.uniq()

      _ ->
        @default_auto_hold_kinds
    end
  end

  # -- holds ----------------------------------------------------------------

  @doc """
  Place a hold. `request` has `reason` and exactly one of `scope` (a
  session or other content scope) and `targets` (references to content
  or records), and may have `until` and `details`. `on_behalf_of` is who
  asked, as authenticated; it is never taken from the request.

  Returns the hold's reference, how many pieces of content were given a
  lock, and any that could no longer be opened.
  """
  @spec hold(map(), String.t() | nil) :: {:ok, map()} | {:error, error()}
  def hold(%{"reason" => _} = request, on_behalf_of) do
    info = Runtime.info()
    body = Map.take(request, ["reason", "scope", "targets", "until", "details"])

    with {:ok, receipt} <- record(info, @hold, body, on_behalf_of, DateTime.utc_now()) do
      outcome =
        case lock(info, receipt.ref, body) do
          {:ok, outcome} ->
            outcome

          # Nothing is encrypted here, so nothing here can be disposed of
          # either: the hold is on the record and there is no lock to add.
          {:error, :no_key_service} ->
            %{held: 0, lost: []}

          # The hold is on the record and could not be applied because the
          # key service cannot be reached. The caller is told, not given
          # "held: 0" as if nothing needed holding.
          {:error, {:key_service_unavailable, _}} ->
            :not_applied

          {:error, reason} ->
            Logger.error(
              "evidence: hold #{receipt.ref} is recorded but was not applied: " <>
                inspect(reason)
            )

            %{held: 0, lost: []}
        end

      seal()

      if outcome == :not_applied,
        do: throw({:hold_not_applied, receipt.ref})

      {:ok,
       %{
         "hold" => receipt.ref,
         "seq" => receipt.seq,
         "held" => outcome.held,
         "lost" => outcome.lost
       }}
    end
  catch
    # Recorded, sealed, and standing in the way of any disposal through
    # this gateway from now on. Its locks are added when the gateway next
    # starts, or sooner if the hold is placed on the same content again.
    {:hold_not_applied, ref} -> {:error, {:hold_recorded_not_applied, ref}}
  end

  def hold(_request, _on_behalf_of), do: {:error, :malformed_request}

  @doc """
  Ensure an active (unreleased, unexpired) hold covers `scope`.

  If an active hold on `scope` is already recorded on the retention stream
  (matching indefinitely when `request` carries no `until`), re-applies its
  lock so any newly arrived content is covered and returns
  `{:ok, %{"hold" => ref, "seq" => seq, "already_held" => true}}` without
  appending a duplicate `RetentionHold`. Otherwise records and seals a new
  gateway-signed `RetentionHold`.
  """
  @spec ensure_hold(map(), String.t() | nil) :: {:ok, map()} | {:error, error()}
  def ensure_hold(%{"scope" => scope, "reason" => _} = request, on_behalf_of)
      when is_binary(scope) do
    info = Runtime.info()
    at = DateTime.utc_now()
    entries = entries(info)
    counting = counting(info, entries)
    indefinite? = is_nil(request["until"])

    existing =
      Enum.find(active_holds(entries, counting, at), fn %{evidence: %{"body" => body}} ->
        body["scope"] == scope and (not indefinite? or is_nil(body["until"]))
      end)

    case existing do
      %{ref: ref, seq: seq, evidence: %{"body" => body}} ->
        _ = lock(info, ref, body)
        {:ok, %{"hold" => ref, "seq" => seq, "already_held" => true}}

      nil ->
        hold(request, on_behalf_of)
    end
  end

  def ensure_hold(_request, _on_behalf_of), do: {:error, :malformed_request}

  defp lock(%{store: {module, handle}}, ref, %{"scope" => scope}) when is_binary(scope),
    do: module.hold_content(handle, ref, {:scope, scope})

  defp lock(%{store: {module, handle}}, ref, %{"targets" => targets}) when is_list(targets) do
    {content, unknown} =
      Enum.reduce(targets, {[], []}, fn
        "bytes:" <> _ = target, {content, unknown} ->
          {content ++ [target], unknown}

        "evidence:" <> _ = target, {content, unknown} ->
          case module.fetch(handle, target) do
            {:ok, %{evidence: evidence}} -> {content ++ Rules.content_refs(evidence), unknown}
            # A record this deployment does not hold: said, not passed over.
            _ -> {content, unknown ++ [target]}
          end

        _other, acc ->
          acc
      end)

    with {:ok, outcome} <- module.hold_content(handle, ref, {:content, content}),
         do: {:ok, %{outcome | lost: outcome.lost ++ unknown}}
  end

  defp lock(_info, _ref, _body), do: {:ok, %{held: 0, lost: []}}

  # -- release ----------------------------------------------------------------

  @doc """
  Begin releasing a hold. `request` has `hold` (its reference), `reason`
  and `releasedBy`, the public key of the person releasing as
  `%{"algorithm", "bytes"}`. Returns the exact bytes that person must
  sign and a ticket for `release_finalize/1`.
  """
  @spec release_prepare(map(), String.t() | nil) ::
          {:ok, %{payload: binary(), ticket: String.t()}} | {:error, error()}
  def release_prepare(
        %{
          "hold" => hold,
          "reason" => reason,
          "releasedBy" => %{"algorithm" => algorithm, "bytes" => text}
        } =
          request,
        on_behalf_of
      )
      when is_binary(hold) and is_binary(text) do
    info = Runtime.info()

    with :ok <- may_record(info, @release),
         {:ok, bytes} <- strict64(text),
         {:ok, releaser} <- Key.id(algorithm, bytes),
         entries = entries(info),
         :ok <- open_hold(info, entries, hold),
         body =
           %{"hold" => hold, "reason" => reason, "releasedBy" => releaser}
           |> put("details", request["details"]),
         evidence = evidence(info, @release, body, on_behalf_of, DateTime.utc_now(), entries),
         {:ok, payload} <- Evidence.encode(evidence),
         {:ok, ticket} <- ticket(payload, info) do
      {:ok, %{payload: payload, ticket: ticket}}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :malformed_request}
    end
  end

  def release_prepare(_request, _on_behalf_of), do: {:error, :malformed_request}

  @doc """
  Finish releasing a hold. `request` has the `payload` and `ticket` from
  `release_prepare/2`, the releaser's `signature` as `%{"keyid", "sig"}`,
  their public key again as `releasedBy`, and, where this deployment has
  roots, `authority`: the grant from a root that lets this person
  release holds, as a set of records, keys and blobs.

  Where the deployment has roots, the release is recorded only if a
  reader who pins this deployment's chain would find it in order, the
  second signer included. A release such a reader would not accept
  would leave the hold standing in their eyes while the content's lock
  was gone.
  """
  @spec release_finalize(map()) :: {:ok, map()} | {:error, error()}
  def release_finalize(
        %{
          "payload" => payload64,
          "ticket" => ticket,
          "signature" => %{"keyid" => keyid, "sig" => sig64},
          "releasedBy" => %{"algorithm" => algorithm, "bytes" => text}
        } = request
      )
      when is_binary(payload64) and is_binary(ticket) do
    info = Runtime.info()

    with {:ok, payload} <- strict64(payload64),
         :ok <- check_ticket(ticket, payload, info),
         {:ok, %{"body" => %{"hold" => hold, "releasedBy" => ^keyid}}} <-
           Canonical.decode_json(payload),
         {:ok, bytes} <- strict64(text),
         {:ok, ^keyid} <- Key.id(algorithm, bytes),
         {:ok, signature} <- strict64(sig64),
         message = Envelope.message(payload),
         true <- Key.verify(algorithm, message, signature, bytes) || {:error, :bad_signature},
         {:ok, ours} <- info.signer.sign.(message),
         envelope = Envelope.assemble(payload, [{info.key_id, ours}, {keyid, signature}]),
         {:ok, %{ref: ref}} <- Envelope.open(envelope),
         wire = %{"keyid" => keyid, "algorithm" => algorithm, "bytes" => text},
         :ok <- releaser_stands(info, request["authority"], ref, envelope, wire),
         keys = Map.put(own_keys(info), keyid, %{algorithm: algorithm, bytes: bytes}),
         {:ok, receipt} <-
           Pipeline.accept(Runtime.pipeline(), envelope, keys, info.profile, "retention"),
         :ok <- Pipeline.flush(Runtime.pipeline()) do
      # The hold's own lock on the content is left in place. It is
      # destroyed when a disposal relies on this release, which is the
      # one step that cannot be undone, and by then the release has been
      # judged again: a release can stop counting after it is recorded,
      # if the releaser's grant turns out to have been taken back first.
      #
      # Sealed at once: the seal is what shows the release was made while
      # the releaser's grant stood, should that grant later be taken back.
      seal()
      {:ok, %{"release" => receipt.ref, "seq" => receipt.seq, "hold" => hold}}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      {:ok, _other} -> {:error, :signature_is_not_the_releasers}
      _ -> {:error, :malformed_request}
    end
  end

  def release_finalize(_request), do: {:error, :malformed_request}

  # Where the deployment has roots, the releaser needs a grant from one,
  # handed over with the release unless the deployment already holds it.
  # The release and the grant are read together, with everything the
  # deployment carries, as a reader who pins its chain would read them.
  # Only if both are in order is anything written: the grant first, like
  # any grant, so that it is sealed and carried from then on, and then
  # the release.
  defp releaser_stands(%{start_chain?: true}, authority, ref, envelope, wire) do
    with %{"state" => "claimed", "chain" => chain} <- Claim.describe() || {:error, :not_claimed},
         {:ok, given} <- given(authority) do
      {:ok, bare} = Export.build(records: [])
      release = %{"records" => [%{"ref" => ref, "envelope" => envelope}], "keys" => [wire]}

      findings =
        bare
        |> Carried.carry()
        |> Publication.carry([given, release])
        |> Export.verify(trusted_chain: chain)
        |> Map.fetch!(:findings)

      wanted = [ref | Enum.map(given["records"], & &1["ref"])]

      cond do
        not Enum.all?(wanted, &in_order?(findings, &1)) -> {:error, :releaser_has_no_standing}
        given["records"] == [] -> :ok
        true -> with {:ok, _refs} <- Grants.keep(given), do: :ok
      end
    else
      %{} -> {:error, :not_claimed}
      {:error, reason} -> {:error, reason}
    end
  end

  defp releaser_stands(_info, _authority, _ref, _envelope, _wire), do: :ok

  defp given(nil), do: {:ok, %{"records" => [], "keys" => [], "blobs" => []}}
  defp given(%{} = authority), do: Grants.shape(authority)
  defp given(_other), do: {:error, :malformed_request}

  # Signed, well formed, and with authority, in a reader's eyes.
  defp in_order?(findings, ref) do
    about = Enum.filter(findings, &(&1.subject == ref))

    Enum.any?(about, &(&1.check == :authority)) and
      Enum.all?(about, &(&1.result == :ok or &1.check == :publication))
  end

  # The retention records a reader who pins this deployment's chain would
  # count, or `:all` where the deployment has no chain to pin. A release
  # that reader would not count has released nothing, whatever the stream
  # says: acting on it would dispose of content a reader sees as held.
  defp counting(%{start_chain?: true}, entries) do
    case Claim.describe() do
      %{"state" => "claimed", "chain" => chain} when entries != [] ->
        {:ok, bare} = Export.build(records: [])
        findings = Export.verify(Carried.carry(bare), trusted_chain: chain).findings
        for %{ref: ref} <- entries, in_order?(findings, ref), into: MapSet.new(), do: ref

      _ ->
        MapSet.new()
    end
  end

  defp counting(_info, _entries), do: :all

  defp counts?(:all, _ref), do: true
  defp counts?(counting, ref), do: MapSet.member?(counting, ref)

  # Seal what was just recorded. A failure here loses nothing: the
  # periodic sealer covers it later.
  defp seal do
    case Runtime.seal() do
      {:ok, _seals} ->
        :ok

      {:error, reason} ->
        Logger.warning("evidence: retention record not sealed yet: #{inspect(reason)}")
    end
  end

  # -- disposal -----------------------------------------------------------------

  @doc """
  Dispose of everything recorded under a scope. `request` has `scope`
  and `reason`, and may say `action` (`"deleted"`, the default, or
  `"expired"`) and `details`.

  Refused, with nothing recorded, while a hold covers anything in the
  scope, when any record in the scope was made under a profile that
  does not yet allow it, or when the scope has no content key left to
  destroy: content that was never encrypted, or was disposed of before,
  cannot be made unreadable now, and a record saying it was would be
  false. Otherwise the disposal is recorded first and
  the scope's key destroyed after, so content is never gone without a
  record saying so.
  """
  @spec dispose(map(), String.t() | nil) :: {:ok, map()} | {:error, error()}
  def dispose(%{"scope" => scope, "reason" => _} = request, on_behalf_of) when is_binary(scope) do
    %{store: {module, handle}} = info = Runtime.info()
    # Everything captured so far is in the index before the scope is
    # judged, so a record still on its way there cannot be missed.
    :ok = Pipeline.flush(Runtime.pipeline())
    # The time the disposal will state, exactly: the store judges by it
    # now and a reader judges by it later, so it is not rounded.
    at = DateTime.utc_now()

    body =
      request
      |> Map.take(["scope", "reason", "details"])
      |> Map.put("action", Map.get(request, "action", "deleted"))

    with true <- body["action"] in ["deleted", "expired"] || {:error, :malformed_request},
         :ok <- may_record(info, @disposal),
         {:ok, ended} <- holds_over(info, scope, at),
         :ok <- no_pending_auto_holds(info, scope),
         :ok <- module.disposal_allowed(handle, scope, at),
         :ok <- key_left(module, handle, scope),
         {:ok, receipt} <- record(info, @disposal, body, on_behalf_of, at) do
      # Holds that touched this scope and have ended, by a release that
      # counts or by running out, give up their locks now, so that what
      # is disposed of is really gone.
      for {hold, release} <- ended do
        case module.release_hold(handle, hold, release || receipt.ref) do
          {:error, reason} ->
            Logger.error(
              "evidence: the lock of ended hold #{hold} was not destroyed: #{inspect(reason)}"
            )

          _released ->
            :ok
        end
      end

      outcome =
        case module.dispose_content(handle, scope, %{ref: receipt.ref, at: at}) do
          :ok ->
            "disposed"

          :already ->
            "already_disposed"

          :none ->
            "nothing_encrypted_under_scope"

          {:error, reason} ->
            Logger.error(
              "evidence: disposal #{receipt.ref} is recorded but was not carried out: " <>
                inspect(reason)
            )

            "recorded_not_carried_out"
        end

      # Content of the disposed scope may have waited on this gateway's own
      # disk. A new spool epoch now means the old one retires as soon as
      # nothing waits under it, and with it anything left in freed blocks.
      Recurse.Gateway.Provenance.SpoolKeys.rotate_async()

      seal()

      {:ok, %{"disposal" => receipt.ref, "seq" => receipt.seq, "outcome" => outcome}}
    end
  end

  def dispose(_request, _on_behalf_of), do: {:error, :malformed_request}

  @doc """
  Dispose of everything recorded in every session of one person.
  `request` has `owner` (the person's identity, as records name them)
  and `reason`, and may have `action` and `details`. `tenant` is the
  tenant whose sessions are meant.

  A session's recorded name carries its owner (see
  `Recurse.Gateway.Provenance.SessionName`), so the person's sessions
  are found by name, whatever their records say and whenever they were
  made. Each one is disposed of as if it had been asked for by itself:
  one disposal record per session, each judged by that session's holds
  and its records' retention, each checkable by a reader on its own.

  The answer lists what was disposed of and what was refused and why.
  A session with nothing left to make unreadable is passed over.
  `complete` is true when no session of theirs was refused. A session
  the person begins afterwards is not covered: ask again.

  `{:error, :nothing_to_dispose}` when no session of theirs had
  anything to make unreadable, and `{:error, :store_unavailable}`, with
  nothing recorded, when the sessions could not be looked up.
  """
  @spec dispose_owner(map(), String.t(), String.t() | nil) :: {:ok, map()} | {:error, error()}
  def dispose_owner(%{"owner" => owner, "reason" => _} = request, tenant, on_behalf_of)
      when is_binary(owner) and owner != "" and is_binary(tenant) and
             not is_map_key(request, "scope") and not is_map_key(request, "targets") do
    with {:ok, sessions} <- sessions_of(tenant, owner) do
      asked = Map.delete(request, "owner")

      outcomes =
        for session <- sessions do
          {session, dispose(Map.put(asked, "scope", session), on_behalf_of)}
        end

      summed(owner, outcomes)
    end
  end

  def dispose_owner(_request, _tenant, _on_behalf_of), do: {:error, :malformed_request}

  defp summed(owner, outcomes) do
    disposed = for {session, {:ok, done}} <- outcomes, do: Map.put(done, "session", session)

    refused =
      for {session, {:error, reason}} <- outcomes, reason != :nothing_to_dispose do
        %{"session" => session, "error" => refusal(reason)}
      end

    if disposed == [] and refused == [] do
      {:error, :nothing_to_dispose}
    else
      {:ok,
       %{
         "owner" => owner,
         "disposed" => disposed,
         "refused" => refused,
         "complete" => refused == []
       }}
    end
  end

  defp sessions_of(tenant, owner) do
    %{store: {module, handle}} = Runtime.info()
    # The owner's part of a session's name, up to the dot that ends it.
    prefix = SessionName.for(tenant, owner, "")

    if function_exported?(module, :sessions_owned, 2),
      do: {:ok, module.sessions_owned(handle, prefix)},
      else: {:error, :malformed_request}
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp refusal({reason, about}) when is_atom(reason),
    do: %{"reason" => Atom.to_string(reason), "about" => about}

  defp refusal(reason) when is_atom(reason), do: %{"reason" => Atom.to_string(reason)}
  defp refusal(_other), do: %{"reason" => "not_recorded"}

  # A disposal destroys a key. With none left there is nothing it can do.
  defp key_left(module, handle, scope) do
    case module.live_scopes(handle, [scope]) do
      [] -> {:error, :nothing_to_dispose}
      _live -> :ok
    end
  end

  # The holds that touch a scope: one that names the scope, or names a
  # record made under it or content such a record refers to. If any is
  # in force, a reader would call a disposal over it a failure, so none
  # is made. Otherwise the ended ones are returned, each with the release
  # that ended it, or nil if it ran out.
  defp holds_over(%{store: {module, handle}} = info, scope, at) do
    entries = entries(info)
    counting = counting(info, entries)
    holds = for %{evidence: %{"kind" => @hold}} = entry <- entries, do: entry

    in_scope =
      if Enum.any?(holds, &is_list(&1.evidence["body"]["targets"])) do
        for %{ref: ref, evidence: evidence} <- scope_records(module, handle, scope),
            each <- [ref | Rules.content_refs(evidence)],
            into: MapSet.new(),
            do: each
      else
        MapSet.new()
      end

    touching =
      Enum.filter(holds, fn %{evidence: %{"body" => body}} ->
        body["scope"] == scope or
          Enum.any?(List.wrap(body["targets"]), &MapSet.member?(in_scope, &1))
      end)

    active = MapSet.new(active_holds(entries, counting, at), & &1.ref)

    case Enum.find(touching, &MapSet.member?(active, &1.ref)) do
      nil ->
        by =
          for %{ref: ref, evidence: %{"kind" => @release, "body" => body}} <- entries,
              counts?(counting, ref),
              into: %{},
              do: {body["hold"], ref}

        {:ok, for(%{ref: ref} <- touching, do: {ref, by[ref]})}

      covering ->
        {:error, {:under_hold, covering.ref}}
    end
  end

  defp scope_records(module, handle, "stream:" <> stream) do
    with {:ok, {last, _ref}} <- module.head(handle, stream),
         {:ok, entries} <- module.range(handle, stream, 1, last) do
      Enum.filter(entries, &(Evidence.content_scope(&1.evidence) == "stream:" <> stream))
    else
      _ -> []
    end
  end

  defp scope_records(module, handle, session) do
    case module.by_session(handle, session) do
      {:ok, entries} -> entries
      _ -> []
    end
  end

  # Fail closed if an admitted record of a configured auto-hold kind exists for
  # `scope` without a matching counselor-released hold. Closes both hold
  # placement failures and any race window between admission and hold flush.
  defp no_pending_auto_holds(info, scope) do
    case auto_hold_kinds() do
      [] ->
        :ok

      kinds ->
        with {:ok, triggers} <- auto_hold_triggers(info, scope, kinds) do
          verify_auto_hold_triggers(info, scope, triggers)
        end
    end
  end

  defp auto_hold_triggers(%{store: {module, handle}, deployment: deployment}, scope, kinds) do
    prefix = "urn:r5e:stream:#{deployment}:"

    Enum.reduce_while(kinds, {:ok, []}, fn kind, {:ok, acc} ->
      case module.by_kind(handle, kind, prefix) do
        {:ok, entries} ->
          matched = Enum.filter(entries, &trigger_for_scope?(&1.evidence, scope))
          {:cont, {:ok, acc ++ matched}}

        {:error, _reason} ->
          {:halt, {:error, :store_unavailable}}
      end
    end)
  end

  defp trigger_for_scope?(evidence, scope) do
    evidence["session"] == scope or
      Evidence.content_scope(evidence) == scope or
      get_in(evidence, ["body", "session"]) == scope
  end

  defp verify_auto_hold_triggers(_info, _scope, []), do: :ok

  defp verify_auto_hold_triggers(info, scope, triggers) do
    entries = entries(info)
    counting = counting(info, entries)

    holds =
      for %{evidence: %{"kind" => @hold, "body" => %{"scope" => ^scope}}} = entry <- entries,
          do: entry

    releases = release_times(entries, counting)

    case Enum.find(triggers, &(not trigger_covered?(&1, holds, releases))) do
      nil -> :ok
      %{ref: ref} -> {:error, {:safeguarding_hold_pending, ref}}
    end
  end

  defp release_times(entries, counting) do
    for %{ref: ref, evidence: %{"kind" => @release, "capturedAt" => text, "body" => body}} <-
          entries,
        counts?(counting, ref),
        {:ok, at, _} <- [DateTime.from_iso8601(text)],
        into: %{} do
      {body["hold"], at}
    end
  end

  defp trigger_covered?(trigger, holds, releases) do
    trigger_at = parse_captured_at(trigger.evidence["capturedAt"])
    Enum.any?(holds, &hold_satisfies_trigger?(&1, trigger.ref, trigger_at, releases))
  end

  defp hold_satisfies_trigger?(hold, trigger_ref, trigger_at, releases) do
    case Map.fetch(releases, hold.ref) do
      {:ok, release_at} ->
        get_in(hold.evidence, ["body", "details", "triggerRef"]) == trigger_ref or
          (not is_nil(trigger_at) and DateTime.compare(release_at, trigger_at) != :lt)

      :error ->
        false
    end
  end

  defp parse_captured_at(text) when is_binary(text) do
    case DateTime.from_iso8601(text) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp parse_captured_at(_), do: nil

  # -- after a restart ---------------------------------------------------------

  @doc """
  Carry out what the retention stream says and the store has not done.

  A hold or a disposal is recorded first and applied after. If the
  gateway stops between the two, the record stands and the act is
  missing: a hold with no lock behind it, or a disposal whose content is
  still there. This puts that right, and is run when capture starts.

  Every hold in force is given its locks again, which changes nothing
  where they exist. A disposal whose scope still has a key is carried
  out now if it still may be: no hold now in force touches the scope,
  and the store finds nothing recorded in the scope that the disposal's
  own date does not cover. Otherwise it is left, and said in the log.
  """
  @spec reconcile() :: :ok
  def reconcile do
    %{store: {module, handle}} = info = Runtime.info()
    entries = entries(info)
    counting = counting(info, entries)
    now = DateTime.utc_now()

    for %{ref: ref, evidence: %{"body" => body}} <- active_holds(entries, counting, now) do
      lock(info, ref, body)
    end

    # Only a disposal a reader would count is ever carried out.
    disposals =
      for %{ref: ref, evidence: %{"kind" => @disposal, "capturedAt" => text, "body" => body}} <-
            entries,
          counts?(counting, ref),
          is_binary(body["scope"]),
          body["action"] in ["deleted", "expired"],
          {:ok, at, _} <- [DateTime.from_iso8601(text)],
          do: {body["scope"], ref, at}

    if disposals != [] and function_exported?(module, :disposed_by?, 3) do
      live = MapSet.new(module.live_scopes(handle, Enum.map(disposals, &elem(&1, 0))))

      holds =
        for %{ref: ref, evidence: %{"kind" => @hold}} <- entries, do: @hold_scope <> ref

      held = module.live_scopes(handle, holds) != []

      for {scope, ref, at} <- disposals do
        cond do
          # Carried out. A hold that had ended may still have its lock,
          # if the gateway stopped between the two.
          module.disposed_by?(handle, scope, ref) ->
            if held, do: release_ended(info, scope, ref, now)

          # Recorded, and the scope's key is still there.
          MapSet.member?(live, scope) ->
            carry_out(info, scope, ref, at, now)

          true ->
            :ok
        end
      end
    end

    :ok
  rescue
    error ->
      Logger.warning("evidence: retention records could not be reconciled: #{inspect(error)}")
      :ok
  end

  defp release_ended(%{store: {module, handle}} = info, scope, ref, now) do
    with {:ok, ended} <- holds_over(info, scope, now) do
      for {hold, release} <- ended, do: module.release_hold(handle, hold, release || ref)
    end

    :ok
  end

  defp carry_out(%{store: {module, handle}} = info, scope, ref, at, now) do
    with {:ok, ended} <- holds_over(info, scope, now),
         :ok <- module.disposal_allowed(handle, scope, at) do
      for {hold, release} <- ended, do: module.release_hold(handle, hold, release || ref)
      outcome = module.dispose_content(handle, scope, %{ref: ref, at: at})
      Logger.info("evidence: disposal #{ref}, recorded earlier, carried out: #{inspect(outcome)}")
    else
      {:error, reason} ->
        Logger.warning(
          "evidence: disposal #{ref} is recorded and its content is still held " <>
            "(#{inspect(reason)}); it is not carried out"
        )
    end
  end

  # -- reading the stream ----------------------------------------------------------

  @doc """
  What the retention stream says now: each hold with whether it has been
  released, and each disposal.
  """
  @spec list() :: %{String.t() => [map()]}
  def list do
    info = Runtime.info()
    entries = entries(info)
    released = released(entries, counting(info, entries))

    %{
      "holds" =>
        for %{ref: ref, seq: seq, evidence: %{"kind" => @hold} = evidence} <- entries do
          evidence["body"]
          |> Map.take(["scope", "targets", "until", "reason"])
          |> Map.merge(%{
            "ref" => ref,
            "seq" => seq,
            "capturedAt" => evidence["capturedAt"],
            "releasedBy" => released[ref]
          })
        end,
      "disposals" =>
        for %{ref: ref, seq: seq, evidence: %{"kind" => @disposal} = evidence} <- entries do
          evidence["body"]
          |> Map.take(["scope", "targets", "action", "reason"])
          |> Map.merge(%{"ref" => ref, "seq" => seq, "capturedAt" => evidence["capturedAt"]})
        end
    }
  end

  @doc """
  The retention stream with the keys of everyone who signed on it and
  the profiles its records cite, as a set to carry in an export. A
  reader told that content was disposed of needs the whole stream up to
  the disposal, to see that no hold stood in its way.
  """
  @spec carried({module(), term()}, String.t()) :: Publication.set()
  def carried({module, handle} = store, deployment) do
    entries = entries(%{store: store, deployment: deployment})

    signers =
      for %{envelope: envelope} <- entries,
          {:ok, opened} <- [Envelope.open(envelope)],
          keyid <- Envelope.signers(opened),
          uniq: true,
          do: keyid

    keys =
      for keyid <- signers,
          {:ok, key} <- [module.get_key(handle, keyid)],
          do: %{
            "keyid" => key.key_id,
            "algorithm" => key.algorithm,
            "bytes" => Base.encode64(key.public_key)
          }

    blobs =
      for ref <- entries |> Enum.map(& &1.evidence["profileRef"]) |> Enum.uniq(),
          {:ok, bytes} <- [module.get_blob(handle, ref)],
          do: %{"ref" => ref, "base64" => Base.encode64(bytes)}

    %{
      "records" => for(e <- entries, do: %{"ref" => e.ref, "envelope" => e.envelope}),
      "keys" => keys,
      "blobs" => blobs
    }
  end

  defp entries(%{store: {module, handle}, deployment: deployment}) do
    with {:ok, {last, _ref}} <- module.head(handle, stream(deployment)),
         {:ok, entries} <- module.range(handle, stream(deployment), 1, last) do
      entries
    else
      _ -> []
    end
  end

  # Which holds have been released, and by whom. Only a release that
  # counts releases anything.
  defp released(entries, counting) do
    for %{ref: ref, evidence: %{"kind" => @release, "body" => body}} <- entries,
        counts?(counting, ref),
        into: %{},
        do: {body["hold"], body["releasedBy"]}
  end

  # Holds not released and not past the time they say they run until.
  # Every hold on the stream stands in the way, whether or not a reader
  # would count it: refusing a disposal loses nothing.
  defp active_holds(entries, counting, at) do
    released = released(entries, counting)

    for %{ref: ref, evidence: %{"kind" => @hold, "body" => body}} = entry <- entries,
        not is_map_key(released, ref),
        not past?(body["until"], at),
        do: entry
  end

  defp past?(nil, _at), do: false

  defp past?(text, at) do
    case DateTime.from_iso8601(text) do
      {:ok, until, _} -> DateTime.compare(at, until) != :lt
      _ -> false
    end
  end

  defp open_hold(info, entries, hold) do
    cond do
      not Enum.any?(entries, &(&1.ref == hold and &1.evidence["kind"] == @hold)) ->
        {:error, :no_such_hold}

      is_map_key(released(entries, counting(info, entries)), hold) ->
        {:error, :hold_already_released}

      true ->
        :ok
    end
  end

  # -- recording ---------------------------------------------------------------------

  # Sign a record as the next on the retention stream and hand it to the
  # log. If another request took that position first this one is refused
  # as a fork and nothing is recorded.
  defp record(info, kind, body, on_behalf_of, at) do
    evidence = evidence(info, kind, body, on_behalf_of, at, entries(info))

    with :ok <- may_record(info, kind),
         {:ok, signed} <- Envelope.sign(evidence, info.signer),
         {:ok, receipt} <-
           Pipeline.accept(
             Runtime.pipeline(),
             signed.envelope,
             own_keys(info),
             info.profile,
             "retention"
           ),
         :ok <- Pipeline.flush(Runtime.pipeline()) do
      {:ok, receipt}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      {:error, _violations} -> {:error, :malformed_request}
      _ -> {:error, :malformed_request}
    end
  end

  defp evidence(info, kind, body, on_behalf_of, at, entries) do
    path = Definitions.kind_path(Definitions.api_version(), kind)
    {:ok, %{ref: schema_ref}} = Definitions.fetch(path)

    {seq, previous} =
      case List.last(entries) do
        nil -> {1, nil}
        %{seq: seq, ref: ref} -> {seq + 1, ref}
      end

    Evidence.new(
      kind_path: path,
      schema_ref: schema_ref,
      profile_ref: info.profile_ref,
      issuer: info.key_id,
      actor: info.actor,
      stream: stream(info.deployment),
      seq: seq,
      previous: previous,
      captured_at: at,
      on_behalf_of: on_behalf_of,
      body: body
    )
  end

  # A deployment with roots records nothing its key holds no grant for:
  # the record would be on the stream and count for nothing with any
  # reader, and a disposal that does not count is content gone unexplained.
  defp may_record(%{start_chain?: true, authority: standing}, kind) do
    if Enrolment.covers?(standing, Definitions.kind_path(Definitions.api_version(), kind)),
      do: :ok,
      else: {:error, :gateway_may_not_record_this}
  end

  defp may_record(_info, _kind), do: :ok

  defp own_keys(info), do: %{info.key_id => %{algorithm: info.algorithm, bytes: info.public_key}}

  defp put(map, _key, nil), do: map
  defp put(map, key, value), do: Map.put(map, key, value)

  # -- the ticket -----------------------------------------------------------------------

  defp ticket(payload, info) do
    expires = System.os_time(:second) + @ticket_seconds

    with {:ok, signature} <- info.signer.sign.(ticket_message(payload, expires)) do
      {:ok, Base.url_encode64(<<expires::unsigned-64, signature::binary>>, padding: false)}
    end
  end

  defp check_ticket(ticket, payload, info) do
    with {:ok, <<expires::unsigned-64, signature::binary>>} <-
           Base.url_decode64(ticket, padding: false),
         true <- expires >= System.os_time(:second) || {:error, :ticket_expired},
         true <-
           Key.verify(
             info.algorithm,
             ticket_message(payload, expires),
             signature,
             info.public_key
           ) ||
             {:error, :ticket_does_not_match} do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :ticket_does_not_match}
    end
  end

  defp ticket_message(payload, expires),
    do: @ticket_context <> <<0>> <> :crypto.hash(:sha256, payload) <> <<expires::unsigned-64>>

  defp strict64(text) when is_binary(text) do
    case Base.decode64(text) do
      {:ok, bytes} when bytes != "" ->
        if Base.encode64(bytes) == text, do: {:ok, bytes}, else: {:error, :malformed_request}

      _ ->
        {:error, :malformed_request}
    end
  end

  defp strict64(_other), do: {:error, :malformed_request}
end
