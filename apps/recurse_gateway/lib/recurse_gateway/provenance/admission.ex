defmodule Recurse.Gateway.Provenance.Admission do
  @moduledoc """
  Takes records a workload signed itself, and records them here.

  A workload with a badge signs its own evidence: what a tool was asked
  and what it answered, on the machine where it happened. Until that
  evidence reaches this deployment it can only be read from the
  workload's own file. Once it is here it is sealed by the gateway's
  sealer, which is the one thing that bounds the workload's own date on
  it; its content is encrypted, held and disposed of like any other; and
  it is exported with the session it belongs to.

  The gateway does not sign these records and does not vouch for what
  they say. It checks that each is what it claims, that its signer has a
  badge in force from this gateway, and that it goes where the signer
  may write. The seal over it afterwards is the acknowledgement.

  ## Whose session

  A session's recorded name carries a fingerprint of whose it is
  (`Recurse.Gateway.Provenance.SessionName`), so the id a client chooses
  can only ever name one of that caller's own sessions. A workload may
  write into a session only when its name is the submitter's and the
  gateway itself has already recorded something there: by a proxied
  call, or by `open_session/2`. A session name seen in someone else's
  records is no use to anyone else.

  ## Badges a root gave offline

  A signer this gateway gave no badge may hold one a root of this
  deployment gave offline (`Recurse.Gateway.Provenance.OfflineBadges`).
  It is accepted only once it has been handed over and sealed, while the
  root above it is still a root, while every link is in force and none
  has been taken back, and only for the person it acts for.
  """

  require Logger

  alias Recurse.Gateway.Personal.Policy, as: PersonalPolicy

  alias Recurse.Gateway.Provenance.{
    Carried,
    Claim,
    OfflineBadges,
    Retention,
    Runtime,
    SessionName
  }

  alias Recurse.Provenance.{Body, Definitions, Envelope, Evidence, Export, Key, Pipeline}
  alias Recurse.Provenance.{Profile, Publication, Ref}
  alias Recurse.Provenance.Retention, as: Rules
  alias RecurseVerify.Canonical

  @most 64
  @largest_blob 4_194_304
  @largest_profile 65_536
  @ahead_seconds 30
  @auto_hold_reason "auto_hold"
  @hold_retry_attempts 3

  # Kinds that say who may do what, how the chain began, what was sealed
  # or what became of content. No workload writes these, whatever its
  # badge lists.
  @refused ~w[ChainStarted Deployment RootsChanged RootChangeApproval Endorsement Badge
              Succession Revocation EpochSeal Checkpoint DefinitionPublished PublishedView
              RetentionHold RetentionHoldRelease PayloadDisposition Disclosure Principal]

  @type caller :: %{tenant: String.t(), principal: String.t()}

  @doc "Kinds no workload writes, whatever a badge lists (bare names)."
  @spec refused_kinds() :: [String.t()]
  def refused_kinds, do: @refused

  # -- sessions ------------------------------------------------------------

  @doc """
  Open a session for the caller and return its recorded name.

  With `clientSessionId` in the request, the session is the one the
  caller's own client names by that id on its model calls: opened now
  if the gateway has recorded nothing in it yet, and answered as it
  stands otherwise. A helper that only knows its client's id joins the
  client's session this way without ever working out the name itself.
  Without it, the gateway makes an id from random bytes.

  Either way the name carries the caller's fingerprint, and the record
  that opens it is signed by the gateway with the caller as its actor.
  """
  @spec open_session(map(), caller()) :: {:ok, :opened | :already, map()} | {:error, atom()}
  def open_session(request, %{tenant: tenant, principal: principal}) do
    info = Runtime.info()
    details = if is_map(request["details"]), do: request["details"]

    with {:ok, id} <- session_id(request["clientSessionId"]),
         session = SessionName.for(URI.decode(tenant), principal, id),
         {:ok, _parts} <- SessionName.parts(session) || :error,
         :ok <- Runtime.flush() do
      case anchor(info, session) do
        nil ->
          with {:ok, receipt} <-
                 Pipeline.capture(Runtime.pipeline(), %{
                   kind_path: path("SessionOpened"),
                   actor: principal,
                   session: session,
                   body: Body.session_opened(session: session, details: details)
                 }),
               :ok <- Runtime.flush() do
            {:ok, :opened, %{"session" => session, "ref" => receipt.ref, "seq" => receipt.seq}}
          else
            {:error, reason} when is_atom(reason) -> {:error, reason}
            _ -> {:error, :session_not_opened}
          end

        _owner ->
          {:ok, :already, %{"session" => session}}
      end
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :invalid_session_scope}
    end
  end

  defp session_id(nil),
    do: {:ok, Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)}

  # As long as the proxy lets a client's own session id be.
  defp session_id(id) when is_binary(id) and byte_size(id) in 1..128, do: {:ok, id}
  defp session_id(_other), do: {:error, :invalid_session_scope}

  # -- records -------------------------------------------------------------

  @doc """
  Take a batch of records. `request` is `%{"records" => [%{"envelope"}],
  "keys" => [...], "blobs" => [...], "authority" => %{"records" =>
  [badge]}}`. `caller` is who is submitting, as authenticated.

  Everything is checked for the whole batch before anything is written.
  Returns, for each record, where it went, whether it was new, and which
  of the content it refers to is now held and which is not.
  """
  @spec submit(term(), caller()) :: {:ok, [map()]} | {:error, term()}
  def submit(%{"records" => [_ | _] = offered} = request, caller) when length(offered) <= @most do
    info = Runtime.info()
    now = DateTime.utc_now()
    # A call that has just finished, or a session just opened, is in the
    # index before sessions are judged.
    :ok = Runtime.flush()

    with {:ok, blobs} <- blobs(request["blobs"]),
         {:ok, opened} <- open_all(offered),
         :ok <- PersonalPolicy.check_admission_batch(opened, request["authority"]),
         {:ok, keys} <- keys(info, request, opened),
         :ok <- each(opened, &signed(&1, keys)),
         :ok <- each(opened, &admissible(&1, info)),
         {:ok, profiles} <- profiles(info, opened, blobs),
         :ok <- each(opened, &about_the_caller(&1, caller)),
         :ok <- each(opened, &session_owned(&1, info, caller)),
         {:ok, placed} <- place(info, opened, now),
         {:ok, badges} <-
           standing(info, request["authority"], opened, keys, profiles, now, caller) do
      case Enum.find(placed, &match?({_, {:fork, _}}, &1)) do
        {record, {:fork, existing}} ->
          equivocation(info, record, existing, badges)

          {:error,
           {:stream_fork_refused,
            %{
              "stream" => record.evidence["stream"],
              "seq" => record.evidence["seq"],
              "existingRef" => existing
            }}}

        nil ->
          write(info, placed, keys, profiles, blobs, badges, caller)
      end
    end
  end

  def submit(_request, _caller), do: {:error, :malformed_request}

  # -- reading what was sent ---------------------------------------------------

  defp blobs(nil), do: {:ok, %{}}

  defp blobs(list) when is_list(list) do
    Enum.reduce_while(list, {:ok, %{}}, fn
      %{"ref" => ref, "base64" => text}, {:ok, acc} when is_binary(text) ->
        with {:ok, bytes} <- Base.decode64(text),
             true <- byte_size(bytes) <= @largest_blob || :too_large,
             true <- Ref.bytes(bytes) == ref do
          {:cont, {:ok, Map.put(acc, ref, bytes)}}
        else
          :too_large -> {:halt, {:error, :blob_too_large}}
          _ -> {:halt, {:error, :blob_hash_mismatch}}
        end

      _other, _acc ->
        {:halt, {:error, :malformed_request}}
    end)
  end

  defp blobs(_other), do: {:error, :malformed_request}

  defp open_all(offered) do
    Enum.reduce_while(offered, {:ok, []}, fn
      %{"envelope" => envelope} = entry, {:ok, acc} ->
        given = Map.get(entry, "ref")

        case Envelope.open(envelope) do
          {:ok, %{ref: ref, evidence: evidence} = opened} when is_nil(given) or given == ref ->
            if well_formed?(evidence),
              do: {:cont, {:ok, acc ++ [Map.put(opened, :envelope, envelope)]}},
              else: {:halt, {:error, :bad_envelope}}

          _ ->
            {:halt, {:error, :bad_envelope}}
        end

      _other, _acc ->
        {:halt, {:error, :malformed_request}}
    end)
  end

  # What a signature covers can be any JSON. Everything after this reads
  # these fields, so a record without them, or with them of the wrong
  # sort, is turned away here and never reaches code that assumes them.
  defp well_formed?(evidence) do
    is_binary(evidence["stream"]) and is_binary(evidence["issuer"]) and
      is_binary(evidence["actor"]) and is_binary(evidence["profileRef"]) and
      is_binary(evidence["kind"]) and is_binary(evidence["apiVersion"]) and
      is_integer(evidence["seq"]) and evidence["seq"] >= 1 and
      (is_nil(evidence["previous"]) or is_binary(evidence["previous"])) and
      (is_nil(evidence["session"]) or is_binary(evidence["session"])) and
      (is_nil(evidence["onBehalfOf"]) or is_binary(evidence["onBehalfOf"])) and
      is_map(evidence["body"]) and
      is_binary(evidence["capturedAt"]) and
      match?({:ok, _, _}, DateTime.from_iso8601(evidence["capturedAt"]))
  end

  # Every signer's public key: sent with the batch, or held from before.
  defp keys(%{store: {module, handle}}, request, opened) do
    sent =
      for %{"keyid" => id, "algorithm" => algorithm, "bytes" => text} <-
            List.wrap(request["keys"]) ++ List.wrap(get_in(request, ["authority", "keys"])),
          is_binary(text),
          {:ok, bytes} <- [Base.decode64(text)],
          {:ok, ^id} <- [Key.id(algorithm, bytes)],
          into: %{},
          do: {id, %{algorithm: algorithm, bytes: bytes}}

    opened
    |> Enum.flat_map(&Envelope.signers/1)
    |> Enum.uniq()
    |> Enum.reduce_while({:ok, sent}, fn id, {:ok, acc} ->
      cond do
        is_map_key(acc, id) ->
          {:cont, {:ok, acc}}

        match?({:ok, _}, module.get_key(handle, id)) ->
          {:ok, key} = module.get_key(handle, id)
          {:cont, {:ok, Map.put(acc, id, %{algorithm: key.algorithm, bytes: key.public_key})}}

        true ->
          {:halt, {:error, :unknown_signer_key}}
      end
    end)
  end

  defp each(opened, check) do
    Enum.reduce_while(opened, :ok, fn record, :ok ->
      case check.(record) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp signed(record, keys) do
    case Envelope.verify(record, keys) do
      :ok -> :ok
      _ -> {:error, :bad_signature}
    end
  end

  # -- what may be offered at all ------------------------------------------------

  defp admissible(%{evidence: evidence}, info) do
    cond do
      evidence["issuer"] == info.key_id ->
        {:error, :gateway_key_not_admissible_as_workload}

      evidence["apiVersion"] == Definitions.api_version() and evidence["kind"] in @refused ->
        {:error, :kind_not_admissible_from_workload}

      not String.starts_with?(evidence["stream"], endpoint(info)) ->
        {:error, :stream_outside_endpoint_namespace}

      not defined?(evidence) ->
        {:error, :definition_not_admitted}

      true ->
        :ok
    end
  end

  defp endpoint(info), do: "urn:r5e:stream:#{info.deployment}:endpoint:"

  # A record follows either a definition built into this gateway or one a
  # publisher it believes has added since. Any other is turned away before
  # its body is read: the gateway would not know what to check it against.
  defp defined?(%{"schemaRef" => schema_ref} = evidence) do
    kind_path = Evidence.kind_path(evidence)

    match?({:ok, %{ref: ^schema_ref}}, Definitions.fetch(kind_path)) or
      Recurse.Gateway.Provenance.Published.admitted?(kind_path, schema_ref)
  end

  defp defined?(_evidence), do: false

  # Each record's profile, sent or held, and saying the same about how
  # long content is kept as this deployment does. Looser would undercut
  # the deployment's period; stricter would let any caller pin content
  # for ever. Keeping something longer is what a hold is for.
  defp profiles(%{store: {module, handle}} = info, opened, blobs) do
    opened
    |> Enum.map(& &1.evidence["profileRef"])
    |> Enum.uniq()
    |> Enum.reduce_while({:ok, %{}}, fn ref, {:ok, acc} ->
      bytes =
        case blobs do
          %{^ref => bytes} -> {:ok, bytes}
          _ -> module.get_blob(handle, ref)
        end

      with {:ok, bytes} when byte_size(bytes) <= @largest_profile <- bytes,
           {:ok, %{} = profile} <- Canonical.decode_json(bytes),
           :ok <- Profile.validate(profile) do
        if keeps(profile) == keeps(info.profile),
          do: {:cont, {:ok, Map.put(acc, ref, profile)}},
          else: {:halt, {:error, :profile_retention_mismatch}}
      else
        _ -> {:halt, {:error, :profile_not_carried}}
      end
    end)
  end

  defp keeps(%{"retention" => %{"disposal" => "by-record", "keepContentForSeconds" => seconds}}),
    do: {:keep_for, seconds}

  defp keeps(_never_or_unsaid), do: :never

  # -- sessions --------------------------------------------------------------------

  @doc "Who a record is about: the person it was made on behalf of, or else its actor."
  @spec principal_of(map()) :: String.t() | nil
  def principal_of(evidence), do: evidence["onBehalfOf"] || evidence["actor"]

  # Every record is about whoever is submitting it, and nobody else,
  # whether or not it names a session. A badge may allow many actor
  # names; that does not let its holder sign as someone else.
  defp about_the_caller(%{evidence: evidence}, caller) do
    if principal_of(evidence) == caller.principal,
      do: :ok,
      else: {:error, :record_is_not_about_the_caller}
  end

  # A session's name says whose it is. A record goes into a session only
  # if the name is the caller's, and only once the gateway itself has
  # recorded something there: by a proxied call or by opening it.
  defp session_owned(%{evidence: %{"session" => session}}, info, caller)
       when is_binary(session) do
    case SessionName.parts(session) do
      {:ok, %{tenant: tenant}} when tenant != caller.tenant ->
        {:error, :session_outside_tenant}

      {:ok, _parts} ->
        cond do
          not SessionName.owned_by?(session, caller.principal) ->
            {:error, {:session_belongs_to_another_principal, %{"session" => session}}}

          is_nil(anchor(info, session)) ->
            {:error, {:session_not_opened, %{"session" => session}}}

          true ->
            :ok
        end

      :error ->
        {:error, :invalid_session_scope}
    end
  end

  defp session_owned(_no_session, _info, _caller), do: :ok

  # The earliest record in the session that the gateway itself signed.
  # Uses `session_anchor/3` (SQL `LIMIT 1` over `(session, captured_at)`) when
  # available so long sessions never load and decode every record on every batch.
  defp anchor(%{store: {module, handle}, key_id: gateway}, session) do
    if Code.ensure_loaded?(module) and function_exported?(module, :session_anchor, 3) do
      case module.session_anchor(handle, session, gateway) do
        {:ok, entry} -> entry.evidence
        _ -> nil
      end
    else
      anchor_from_session_scan(module, handle, gateway, session)
    end
  end

  defp anchor_from_session_scan(module, handle, gateway, session) do
    case module.by_session(handle, session) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&(&1.evidence["issuer"] == gateway))
        |> Enum.min_by(&{instant(&1.evidence["capturedAt"]), &1.stream, &1.seq}, fn -> nil end)
        |> case do
          nil -> nil
          entry -> entry.evidence
        end

      _ ->
        nil
    end
  end

  # -- position and time --------------------------------------------------------------

  # Where each record goes on its stream: new, already here, or in the
  # place of a different record. A gap, or a date out of order, stops the
  # batch.
  defp place(%{store: {module, handle}}, opened, now) do
    limit = DateTime.add(now, @ahead_seconds, :second)

    opened
    |> Enum.reduce_while({:ok, [], %{}}, fn %{evidence: evidence, ref: ref} = record,
                                            {:ok, acc, heads} ->
      %{"stream" => stream, "seq" => seq} = evidence
      # Within a batch, a stream's records come one after another.
      in_turn? = not is_map_key(heads, {:batch, stream}) or heads[{:batch, stream}] + 1 == seq
      heads = Map.put(heads, {:batch, stream}, seq)

      head =
        Map.get_lazy(heads, stream, fn ->
          case module.head(handle, stream) do
            {:ok, {last, last_ref}} -> {last, last_ref, captured(module, handle, last_ref)}
            _ -> {0, nil, nil}
          end
        end)

      {last, last_ref, last_at} = head
      at = instant(evidence["capturedAt"])

      cond do
        not in_turn? ->
          {:halt, {:error, :not_next_in_stream}}

        at > DateTime.to_unix(limit, :nanosecond) ->
          {:halt, {:error, :captured_at_in_future}}

        seq <= last ->
          case module.range(handle, stream, seq, seq) do
            {:ok, [%{ref: ^ref}]} -> {:cont, {:ok, acc ++ [{record, :already}], heads}}
            {:ok, [%{ref: other}]} -> {:cont, {:ok, acc ++ [{record, {:fork, other}}], heads}}
            _ -> {:halt, {:error, :not_next_in_stream}}
          end

        seq == last + 1 and evidence["previous"] == last_ref ->
          if is_nil(last_at) or at >= last_at do
            heads = Map.put(heads, stream, {seq, ref, at})
            {:cont, {:ok, acc ++ [{record, :new}], heads}}
          else
            {:halt, {:error, :captured_at_before_previous_record}}
          end

        seq == last + 1 and last > 0 ->
          {:cont, {:ok, acc ++ [{record, {:fork, last_ref}}], heads}}

        true ->
          {:halt,
           {:error,
            {:not_next_in_stream,
             %{"stream" => stream, "expectedSeq" => last + 1, "expectedPrevious" => last_ref}}}}
      end
    end)
    |> case do
      {:ok, placed, _heads} -> {:ok, placed}
      error -> error
    end
  end

  defp captured(module, handle, ref) do
    case module.fetch(handle, ref) do
      {:ok, %{evidence: evidence}} -> instant(evidence["capturedAt"])
      _ -> nil
    end
  end

  defp instant(text) do
    {:ok, at, _} = DateTime.from_iso8601(text)
    DateTime.to_unix(at, :nanosecond)
  end

  # -- standing ------------------------------------------------------------------------

  # Each signer's badge: one this gateway issued and holds, in force now,
  # hanging from a grant the gateway acts under now, and not taken back.
  # Then the whole batch is read once, with everything the deployment
  # carries, as an outside reader would read it.
  defp standing(%{store: {module, handle}} = info, authority, opened, keys, profiles, now, caller) do
    issuers = opened |> Enum.map(& &1.evidence["issuer"]) |> Enum.uniq()
    noted = module.authority_of(handle, issuers)

    offered =
      for %{"ref" => ref} <- List.wrap(is_map(authority) && authority["records"]),
          is_binary(ref),
          do: ref

    held =
      for ref <- Enum.uniq(Enum.map(noted, &elem(&1, 1)) ++ offered),
          {:ok, entry} <- [module.fetch(handle, ref)],
          do: entry

    badges =
      for issuer <- issuers, into: %{} do
        badge =
          Enum.find(held, fn %{evidence: e} ->
            e["kind"] == "Badge" and e["issuer"] == info.key_id and e["body"]["subject"] == issuer
          end)

        {issuer, badge}
      end

    # Badges a root gave offline, for signers this gateway gave none.
    offline_candidates =
      for {issuer, nil} <- badges,
          [_ | _] = found <- [OfflineBadges.candidates(info, issuer, held)],
          into: %{},
          do: {issuer, found}

    gateway = for {issuer, %{} = badge} <- badges, into: %{}, do: {issuer, badge}

    revoked =
      for %{evidence: %{"kind" => "Revocation", "body" => %{"target" => target}}} <- held,
          into: MapSet.new(),
          do: target

    acting =
      case info.authority do
        %{endorsements: grants} -> Map.new(grants, &{&1.ref, &1.body})
        _ -> %{}
      end

    live? = fn body ->
      DateTime.compare(now, time(body["notBefore"])) != :lt and
        DateTime.compare(now, time(body["notAfter"])) != :gt
    end

    cond do
      Enum.any?(badges, fn {issuer, badge} ->
        is_nil(badge) and not is_map_key(offline_candidates, issuer)
      end) ->
        Logger.warning(
          "evidence: workload records refused: no badge from this gateway is held for their signer"
        )

        {:error, :no_standing}

      Enum.any?(gateway, fn {_issuer, badge} ->
        parent = acting[badge.evidence["body"]["parent"]]

        MapSet.member?(revoked, badge.ref) or not live?.(badge.evidence["body"]) or
          is_nil(parent) or not live?.(parent)
      end) ->
        {:error, :authority_ended}

      true ->
        case resolve_offline(info, offline_candidates, caller, now) do
          {:ok, offline} ->
            chains = Enum.flat_map(Map.values(offline), &(&1.links ++ [&1.badge]))
            keys = Map.merge(OfflineBadges.keys_of(info, chains), keys)

            with :ok <-
                   read_as_a_reader(info, opened, keys, profiles, Map.values(gateway) ++ chains),
                 do: {:ok, Map.merge(gateway, Map.new(offline, fn {i, f} -> {i, f.badge} end))}

          {:error, _} = refusal ->
            refusal
        end
    end
  end

  # For each offline signer in the batch, pick an active badge chain or
  # stop at the first signer whose chains all fail.
  defp resolve_offline(info, candidates_by_issuer, caller, now) do
    Enum.reduce_while(candidates_by_issuer, {:ok, %{}}, fn {issuer, list}, {:ok, acc} ->
      case OfflineBadges.resolve(info, list, caller, now) do
        {:ok, found} -> {:cont, {:ok, Map.put(acc, issuer, found)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp time(text) do
    {:ok, at, _} = DateTime.from_iso8601(text)
    at
  end

  defp read_as_a_reader(%{store: {module, handle}} = info, opened, keys, profiles, badges) do
    set = %{
      "records" =>
        for(b <- badges, do: %{"ref" => b.ref, "envelope" => b.envelope}) ++
          for(r <- opened, do: %{"ref" => r.ref, "envelope" => r.envelope}),
      "keys" =>
        for(
          # The gateway's own key too: it signed the badges.
          {id, key} <-
            Map.put(keys, info.key_id, %{algorithm: info.algorithm, bytes: info.public_key}),
          do: %{"keyid" => id, "algorithm" => key.algorithm, "bytes" => Base.encode64(key.bytes)}
        ),
      "blobs" =>
        for(
          {ref, profile} <- profiles,
          do: %{"ref" => ref, "base64" => Base.encode64(Profile.encode(profile))}
        ) ++
          for(
            b <- badges,
            {:ok, bytes} <- [module.get_blob(handle, b.evidence["profileRef"])],
            do: %{"ref" => b.evidence["profileRef"], "base64" => Base.encode64(bytes)}
          )
    }

    {:ok, bare} = Export.build(records: [])
    bundle = bare |> Carried.carry() |> Publication.carry([set])

    trust =
      case {Map.get(info, :start_chain?, false), Claim.describe(), info.authority} do
        {true, %{"state" => "claimed", "chain" => chain}, _} ->
          {:ok, [trusted_chain: chain]}

        {false, _, %{records: records}} ->
          tops =
            for %{"envelope" => envelope} <- records,
                {:ok, %{evidence: %{"kind" => "Endorsement", "issuer" => issuer, "body" => body}}} <-
                  [Envelope.open(envelope)],
                is_nil(body["parent"]),
                uniq: true,
                do: issuer

          {:ok, [trusted_roots: tops]}

        _ ->
          {:error, :gateway_has_no_endorsement}
      end

    with {:ok, trust} <- trust do
      # Admitted definitions are read from the store; `admissible/2` has
      # already turned away any record citing one that was not admitted.
      installed = [definitions: &module.get_blob(handle, &1)]
      findings = Export.verify(bundle, trust ++ installed).findings
      wanted = MapSet.new(opened, & &1.ref)

      about =
        Enum.filter(findings, fn f ->
          MapSet.member?(wanted, f.subject) and
            f.check in [:signature, :body, :identity, :profile_bounds, :authority]
        end)

      cond do
        Enum.any?(about, &(&1.check == :body and &1.result != :ok)) ->
          {:error, :invalid_body}

        Enum.any?(about, &(&1.check == :profile_bounds and &1.result != :ok)) ->
          {:error, :profile_bounds_not_satisfied}

        Enum.any?(about, &(&1.result != :ok)) ->
          # Said in the log, since the caller is told only that it has none.
          %{check: check, code: code, subject: subject} = Enum.find(about, &(&1.result != :ok))
          Logger.warning("evidence: workload record #{subject} refused: #{check} #{code}")
          {:error, :no_standing}

        not Enum.all?(wanted, fn ref ->
          Enum.any?(about, &(&1.subject == ref and &1.check == :authority))
        end) ->
          {:error, :no_standing}

        true ->
          :ok
      end
    end
  end

  # -- writing ----------------------------------------------------------------------------

  defp write(%{store: {module, handle}}, placed, keys, profiles, blobs, badges, caller) do
    Enum.reduce_while(placed, {:ok, []}, fn {%{evidence: evidence} = record, status},
                                            {:ok, acc} ->
      scope = Evidence.content_scope(evidence)
      wanted = Rules.content_refs(evidence)

      # Content first, each piece under the record's own scope and never
      # as the workload chooses: whatever a body refers to is encrypted
      # and can be disposed of with the rest. A reference sent without
      # its bytes counts as held only if this scope holds it already;
      # naming another session's content gives no way to read it.
      {held, missing} =
        Enum.split_with(wanted, fn ref ->
          content = Map.get(blobs, ref, :own)
          module.put_content(handle, ref, content, scope) == :ok
        end)

      result =
        case status do
          :already ->
            {:ok, "already_admitted"}

          :new ->
            signers = Map.take(keys, Envelope.signers(record))
            profile = Map.fetch!(profiles, evidence["profileRef"])

            case Pipeline.accept(
                   Runtime.pipeline(),
                   record.envelope,
                   signers,
                   profile,
                   "endpoint:"
                 ) do
              {:ok, _receipt} -> {:ok, "admitted"}
              {:error, reason} -> {:error, reason}
            end
        end

      case result do
        {:ok, status} ->
          module.note_authority(handle, evidence["issuer"], [badges[evidence["issuer"]].ref])

          {:cont,
           {:ok,
            acc ++
              [
                %{
                  "ref" => record.ref,
                  "stream" => evidence["stream"],
                  "seq" => evidence["seq"],
                  "status" => status,
                  "contentHeld" => held,
                  "contentMissing" => missing
                }
              ]}}

        {:error, reason} ->
          Logger.warning(
            "evidence: a workload record that passed every check was not recorded: #{inspect(reason)}"
          )

          {:halt, {:error, if(is_atom(reason), do: reason, else: :not_recorded)}}
      end
    end)
    |> case do
      {:ok, admitted} ->
        :ok = Runtime.flush()
        finalize_auto_holds(placed, caller, admitted)

      error ->
        error
    end
  end

  defp finalize_auto_holds(placed, caller, admitted) do
    case place_auto_holds(placed, caller) do
      :ok ->
        {:ok, admitted}

      {:error, _reason} ->
        {:error, {:safeguarding_hold_failed, Enum.map(admitted, & &1["ref"])}}
    end
  end

  # When a valid record whose kind is configured in `Retention.auto_hold_kinds/0`
  # is admitted for a session, automatically place an idempotent gateway-signed
  # `RetentionHold` on that session so no owner disposal or retention sweep can
  # erase flagged evidence before two-step release completes. Fails closed if
  # hold placement errors (client retries, and `Retention.dispose` also refuses
  # disposal with `hold_pending`).
  defp place_auto_holds(placed, caller) do
    case Retention.auto_hold_kinds() do
      [] ->
        :ok

      kinds ->
        placed
        |> Enum.reduce(%{}, &collect_auto_hold_session(&1, &2, caller, kinds))
        |> apply_auto_holds()
    end
  end

  defp apply_auto_holds(sessions) do
    Enum.reduce_while(sessions, :ok, fn {session, {kind, trigger_ref}}, :ok ->
      case ensure_auto_hold(session, kind, trigger_ref, @hold_retry_attempts) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp collect_auto_hold_session({%{evidence: evidence, ref: ref}, _status}, acc, caller, kinds) do
    kind = Evidence.kind_path(evidence)

    if kind in kinds do
      put_auto_hold_session(acc, auto_hold_session(evidence, caller), kind, ref)
    else
      acc
    end
  end

  defp put_auto_hold_session(acc, nil, _kind, _ref), do: acc

  defp put_auto_hold_session(acc, session, kind, ref),
    do: Map.put_new(acc, session, {kind, ref})

  defp auto_hold_session(%{"session" => session}, _caller)
       when is_binary(session) and session != "",
       do: session

  defp auto_hold_session(%{"body" => %{"session" => candidate}}, caller)
       when is_binary(candidate) do
    owned_body_session(candidate, caller)
  end

  defp auto_hold_session(_evidence, _caller), do: nil

  defp owned_body_session(candidate, %{tenant: tenant, principal: principal}) do
    case SessionName.parts(candidate) do
      {:ok, %{tenant: ^tenant}} ->
        if SessionName.owned_by?(candidate, principal), do: candidate

      _ ->
        nil
    end
  end

  defp ensure_auto_hold(session, trigger_kind, trigger_ref, attempts_left) do
    request = %{
      "scope" => session,
      "reason" => @auto_hold_reason,
      "details" => %{
        "triggerKind" => trigger_kind,
        "triggerRef" => trigger_ref
      }
    }

    case Retention.ensure_hold(request, nil) do
      {:ok, _held} ->
        :ok

      {:error, {:hold_recorded_not_applied, ref}} ->
        Logger.warning(
          "evidence: auto-hold #{ref} recorded for #{session} (#{trigger_kind}) " <>
            "but key service was unavailable; locks will be reconciled on restart"
        )

        :ok

      {:error, reason}
      when reason in [:stream_fork_refused, :not_next_in_stream] and attempts_left > 1 ->
        ensure_auto_hold(session, trigger_kind, trigger_ref, attempts_left - 1)

      {:error, reason} ->
        Logger.error(
          "evidence: auto-hold could not be placed for #{session} (#{trigger_kind}): " <>
            inspect(reason)
        )

        {:error, reason}
    end
  end

  # -- two records at one position ------------------------------------------------------------

  # A different record, validly signed by a key in good standing, at a
  # position already taken: the signer has signed two histories. The
  # stream keeps the first. What was offered is noted once, by the
  # gateway, with both records to hand.
  defp equivocation(%{store: {module, handle}} = info, record, existing, badges) do
    %{"stream" => stream, "seq" => seq, "issuer" => issuer} = record.evidence
    security = "urn:r5e:stream:#{info.deployment}:security"

    entries =
      with {:ok, {last, _}} <- module.head(handle, security),
           {:ok, entries} <- module.range(handle, security, 1, last) do
        entries
      else
        _ -> []
      end

    seen? =
      Enum.any?(entries, fn %{evidence: %{"body" => body}} ->
        body["about"] == stream and get_in(body, ["details", "seq"]) == seq
      end)

    unless seen? do
      offered = Canonical.encode(record.envelope)
      :ok = module.put_blob(handle, Ref.bytes(offered), offered)

      {next, previous} =
        case List.last(entries) do
          nil -> {1, nil}
          %{seq: last, ref: ref} -> {last + 1, ref}
        end

      {:ok, %{ref: schema_ref}} = Definitions.fetch(path("Observation"))

      evidence =
        Evidence.new(
          kind_path: path("Observation"),
          schema_ref: schema_ref,
          profile_ref: info.profile_ref,
          issuer: info.key_id,
          actor: info.actor,
          stream: security,
          seq: next,
          previous: previous,
          captured_at: DateTime.utc_now(),
          body:
            Body.observation(
              topic: "stream_equivocation",
              about: stream,
              content_refs: [existing, Ref.bytes(offered)],
              details: %{
                "seq" => seq,
                "conflictingRef" => record.ref,
                "issuer" => issuer,
                "badgeRef" => badges[issuer].ref
              }
            )
        )

      own = %{info.key_id => %{algorithm: info.algorithm, bytes: info.public_key}}

      with {:ok, signed} <- Envelope.sign(evidence, info.signer),
           {:ok, _} <-
             Pipeline.accept(Runtime.pipeline(), signed.envelope, own, info.profile, "security") do
        Runtime.flush()
      else
        error ->
          Logger.warning(
            "evidence: two records at one position were not noted: #{inspect(error)}"
          )
      end
    end

    :ok
  rescue
    error ->
      Logger.warning("evidence: two records at one position were not noted: #{inspect(error)}")
      :ok
  end

  # -- taking a badge back -------------------------------------------------------------------

  @doc """
  The badge a reference names, if this gateway issued it: its subject
  and who it acts for.
  """
  @spec badge(String.t()) :: {:ok, map()} | :error
  def badge(ref) when is_binary(ref) do
    %{store: {module, handle}, key_id: gateway} = Runtime.info()
    # A badge issued a moment ago is in the index before it is looked for.
    Runtime.flush()

    case module.fetch(handle, ref) do
      {:ok, %{evidence: %{"kind" => "Badge", "issuer" => ^gateway, "body" => body}}} ->
        {:ok, body}

      _ ->
        :error
    end
  end

  def badge(_other), do: :error

  @doc """
  Take back a badge this gateway issued. Everything already taken under
  the badge is sealed first, so a reader can see it came before; then
  the revocation is recorded and sealed, and nothing more is taken under
  the badge.
  """
  @spec revoke_badge(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def revoke_badge(ref, reason) when is_binary(reason) and reason != "" do
    %{store: {module, handle}} = info = Runtime.info()

    with {:ok, %{"subject" => subject}} <- badge(ref) || {:error, :no_such_badge},
         :ok <- Runtime.flush(),
         {:ok, _seals} <- Runtime.seal(),
         {:ok, %{ref: schema_ref}} <- Definitions.fetch(path("Revocation")),
         token = Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false),
         evidence =
           Evidence.new(
             kind_path: path("Revocation"),
             schema_ref: schema_ref,
             profile_ref: info.profile_ref,
             issuer: info.key_id,
             actor: info.actor,
             stream: "urn:r5e:stream:#{info.deployment}:authority:revocation:#{token}",
             seq: 1,
             previous: nil,
             captured_at: DateTime.utc_now(),
             body: %{"target" => ref, "reason" => reason}
           ),
         {:ok, signed} <- Envelope.sign(evidence, info.signer),
         {:ok, receipt} <- Pipeline.admit(Runtime.pipeline(), signed.envelope),
         :ok <- Runtime.flush() do
      module.note_authority(handle, subject, [ref, receipt.ref])
      Runtime.seal()
      {:ok, %{"revocation" => receipt.ref, "badge" => ref}}
    else
      :error -> {:error, :no_such_badge}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :not_recorded}
    end
  end

  def revoke_badge(_ref, _reason), do: {:error, :malformed_request}

  defp path(kind), do: Definitions.kind_path(Definitions.api_version(), kind)
end
