defmodule Recurse.Gateway.Provenance.Enrolment do
  @moduledoc """
  Gives a workload a badge: a short-lived credential, signed by this
  gateway and by the workload's own key, that lets the workload sign
  evidence a reader can trace to the organisation's root.

  A badge takes two signatures over the same bytes, and the workload's
  private key never leaves its machine. So enrolment is two steps:

    1. `prepare/2` builds the badge this gateway is willing to issue and
       returns its exact bytes with a ticket. Nothing is stored.
    2. The workload checks those bytes say what it asked for, signs them,
       and sends bytes, ticket and signature to `finalize/1`. The gateway
       checks the ticket and the signature, signs in first position, and
       records the badge.

  The ticket is this gateway's own signature over the badge's digest and
  an expiry. It is what lets step 1 keep no state: any node holding the
  deployment's signing key can finish what another began, and an
  abandoned enrolment leaves nothing behind.

  ## Where the gateway's own standing comes from

  A gateway cannot vouch for anyone on its own word. The operator installs
  the records that give this gateway's key its standing: an `Endorsement`
  naming it, issued by the organisation's root or by a key the root
  endorsed, with every record above it. `standing/3` checks that chain
  leads to this key and allows it to vouch for others. Without it,
  nothing is enrolled.

  A badge never grants more than the endorsement it is issued under: its
  kinds, its window and its prefixes are cut down to fit.
  """

  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Provenance.{Definitions, Envelope, Evidence, Export, Key, Pipeline, Ref}
  alias RecurseVerify.Canonical

  @badge "provenance.r5e.io/v2/Badge"
  @endorsement "provenance.r5e.io/v2/Endorsement"
  @revocation "provenance.r5e.io/v2/Revocation"
  @ticket_context "r5e.badge-ticket/v1"
  @ticket_seconds 300
  @max_ttl_seconds 43_200

  @typedoc "The checked chain that gives this gateway its standing."
  @type standing :: %{
          endorsement: %{ref: Ref.t(), body: map()} | nil,
          endorsements: [%{ref: Ref.t(), body: map()}],
          records: [%{String.t() => term()}],
          keys: [%{String.t() => String.t()}]
        }

  @doc """
  Check the installed records and return this gateway's standing.

  `chain` is `%{"records" => [%{"ref", "envelope"}], "keys" => [%{"keyid",
  "algorithm", "bytes"}]}`: the endorsement of `key_id` and everything
  above it, with the public keys of their issuers. The chain is walked
  from its own top key, so this establishes that the records are
  consistent and reach this gateway; which top key deserves trust is for
  whoever reads the evidence.
  """
  @spec standing(map(), String.t(), map(), [String.t()] | nil, [String.t()]) ::
          {:ok, standing()} | {:error, term()}
  def standing(chain, key_id, own_key, roots \\ nil, preferred \\ [])

  def standing(%{"records" => records, "keys" => keys} = chain, key_id, own_key, roots, preferred)
      when is_list(records) and is_list(keys) do
    chain_blobs = Map.get(chain, "blobs", [])

    opened =
      for %{"envelope" => envelope} <- records,
          {:ok, %{evidence: evidence, ref: ref}} <- [Envelope.open(envelope)],
          do: %{ref: ref, evidence: evidence, envelope: envelope}

    grants = Enum.filter(opened, &(Evidence.kind_path(&1.evidence) == @endorsement))
    naming = Enum.filter(grants, &(&1.evidence["body"]["subject"] == key_id))

    # The keys the chain is read from: the roots a claimed deployment
    # declared, or, for a file an operator installed, whoever issued a
    # grant that rests on nothing above it.
    tops =
      roots ||
        for(
          %{evidence: %{"issuer" => issuer, "body" => body}} <- grants,
          is_nil(body["parent"]),
          uniq: true,
          do: issuer
        )

    with [_ | _] <- naming || [],
         [_ | _] <- tops || {:error, :chain_has_no_top},
         {:ok, wire} <- wire_keys(keys),
         {:ok, bundle} <-
           Export.build(records: Enum.map(opened, & &1.envelope), keys: wire ++ [own_key]),
         report = Export.verify(bundle, trusted_roots: tops),
         true <- all_sound?(report) || {:error, :chain_does_not_hold},
         revoked = taken_back(opened, report),
         # A grant that was taken back is no longer acted under.
         [_ | _] = holding <-
           Enum.reject(holding(naming, report), &MapSet.member?(revoked, &1.ref)) ||
             {:error, :chain_does_not_hold} do
      {:ok,
       %{
         # The grant badges are issued under, if any lets this gateway vouch.
         endorsement:
           best(Enum.filter(holding, &(&1.evidence["body"]["mayEndorse"] == true)), preferred),
         # Every grant to this gateway's key that holds. What the gateway
         # may do is everything any of them allows while it is in force, so
         # a further grant can add to its standing and never take from it.
         endorsements: for(g <- holding, do: %{ref: g.ref, body: g.evidence["body"]}),
         records: Enum.map(opened, &%{"ref" => &1.ref, "envelope" => &1.envelope}),
         keys: keys,
         # Content the chain's records cite, such as the root's profile,
         # when the operator's file carries it.
         blobs: for(%{"ref" => _, "base64" => _} = blob <- List.wrap(chain_blobs), do: blob)
       }}
    else
      [] when naming == [] -> {:error, :no_endorsement_names_this_key}
      [] -> {:error, :chain_does_not_hold}
      {:error, _} = error -> error
      _ -> {:error, :unreadable_chain}
    end
  rescue
    # A file an operator wrote by hand can be wrong in any way. The
    # gateway must come up and say so, not fall over.
    _ -> {:error, :unreadable_chain}
  end

  def standing(_chain, _key_id, _own_key, _roots, _preferred), do: {:error, :unreadable_chain}

  @doc """
  Whether any grant the gateway holds, in force now, lets it issue
  records of `kind_path`.
  """
  @spec covers?(standing() | nil, String.t()) :: boolean()
  def covers?(%{endorsements: endorsements}, kind_path) do
    now = DateTime.utc_now()

    Enum.any?(endorsements, fn %{body: body} ->
      kind_path in body["kinds"] and not before?(now, body["notBefore"]) and
        before?(now, body["notAfter"])
    end)
  end

  def covers?(_no_standing, _kind_path), do: false

  defp wire_keys(keys) do
    Enum.reduce_while(keys, {:ok, []}, fn key, {:ok, acc} ->
      with %{"keyid" => id, "algorithm" => algorithm, "bytes" => text} <- key,
           {:ok, bytes} <- strict64(text) do
        {:cont, {:ok, acc ++ [%{key_id: id, algorithm: algorithm, public_key: bytes}]}}
      else
        _ -> {:halt, {:error, :unreadable_key}}
      end
    end)
  end

  # Every record in the file is what it says and is signed.
  defp all_sound?(%{findings: findings}) do
    Enum.all?(findings, fn f ->
      f.check not in [:signature, :body, :identity] or f.result == :ok
    end)
  end

  # The grants to this gateway's key that hold when the chain is read
  # from its tops.
  defp holding(naming, %{findings: findings}) do
    held =
      for %{check: :authority, result: :ok, subject: ref} <- findings, into: MapSet.new(), do: ref

    Enum.filter(naming, &MapSet.member?(held, &1.ref))
  end

  # The grants that someone entitled has taken back. A revocation counts
  # when the same reading of the chain gives it authority.
  defp taken_back(opened, %{findings: findings}) do
    entitled =
      for %{check: :authority, result: :ok, subject: ref} <- findings, into: MapSet.new(), do: ref

    for %{ref: ref, evidence: evidence} <- opened,
        Evidence.kind_path(evidence) == @revocation,
        MapSet.member?(entitled, ref),
        into: MapSet.new(),
        do: evidence["body"]["target"]
  end

  # Of the grants that let this gateway vouch, the one in force now that
  # runs longest; failing that, the one that runs longest at all, so that
  # a grant not yet begun is reported as such. A grant given by a key in
  # `preferred` (the roots now in place) comes before one given by any
  # other, so new badges hang from a root that is still a root and do not
  # die if an earlier root's grant is later taken back. Times are
  # compared as instants, never as text.
  defp best([], _preferred), do: nil

  defp best(vouching, preferred) do
    now = DateTime.utc_now()

    until = fn grant ->
      {:ok, instant, _} = DateTime.from_iso8601(grant.evidence["body"]["notAfter"])
      {DateTime.to_unix(instant, :microsecond), grant.ref}
    end

    in_force =
      Enum.filter(vouching, fn grant ->
        body = grant.evidence["body"]
        not before?(now, body["notBefore"]) and before?(now, body["notAfter"])
      end)

    candidates = if in_force == [], do: vouching, else: in_force
    current = Enum.filter(candidates, &(&1.evidence["issuer"] in preferred))
    chosen = Enum.max_by(if(current == [], do: candidates, else: current), until)
    %{ref: chosen.ref, body: chosen.evidence["body"]}
  end

  defp before?(time, iso) do
    {:ok, limit, _} = DateTime.from_iso8601(iso)
    DateTime.compare(time, limit) == :lt
  end

  @doc """
  The badge this gateway would issue for a request, as exact bytes, and a
  ticket for `finalize/1`.

  `request` is the caller's JSON: `subjectKey`, `holder`, optional
  `workload`, `requestedKinds`, `requestedActorPrefixes`,
  `requestedTtlSeconds`. `acts_for` is who the caller was authenticated
  as, or nil for a workload with no person behind it; it is never taken
  from the request.
  """
  @spec prepare(map(), String.t() | nil) ::
          {:ok, %{payload: binary(), ticket: String.t()}} | {:error, atom()}
  def prepare(request, acts_for) do
    info = Runtime.info()

    with %{authority: %{endorsement: %{} = parent}} <-
           info || {:error, :gateway_has_no_endorsement},
         {:ok, subject_key, subject} <- subject(request["subjectKey"]),
         id = Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false),
         {:ok, body} <-
           body(request, parent, subject, subject_key, acts_for, endpoint_prefix(info, id)),
         evidence =
           Evidence.new(
             kind_path: @badge,
             schema_ref: schema_ref(),
             profile_ref: info.profile_ref,
             issuer: info.key_id,
             actor: info.actor,
             stream: "urn:r5e:stream:#{info.deployment}:authority:badge:#{id}",
             seq: 1,
             previous: nil,
             captured_at: now(),
             body: body
           ),
         {:ok, payload} <- Evidence.encode(evidence),
         {:ok, ticket} <- ticket(payload, info) do
      {:ok, %{payload: payload, ticket: ticket}}
    else
      %{} -> {:error, :gateway_has_no_endorsement}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      {:error, _other} -> {:error, :badge_not_issuable}
    end
  end

  @doc """
  Finish an enrolment: check the ticket and the workload's signature,
  sign first, record the badge, and return what the workload needs to
  produce evidence a reader can check with nothing else to hand.
  """
  @spec finalize(map(), String.t() | nil) :: {:ok, map()} | {:error, atom()}
  def finalize(request, acts_for)

  def finalize(
        %{"payload" => payload64, "ticket" => ticket, "subjectSignature" => given},
        acts_for
      )
      when is_binary(payload64) and is_binary(ticket) and is_map(given) do
    info = Runtime.info()

    with %{authority: %{} = authority} <- info || {:error, :gateway_has_no_endorsement},
         {:ok, payload} <- strict64(payload64),
         :ok <- check_ticket(ticket, payload, info),
         {:ok, %{"body" => %{"subject" => subject, "subjectKey" => key}} = evidence} <-
           Canonical.decode_json(payload),
         # A ticket is good for whoever it was prepared for, and nobody else:
         # another caller must not finish it and come away with a badge that
         # acts for the first.
         true <-
           evidence["body"]["actsFor"] == acts_for ||
             {:error, :caller_does_not_match_prepared_badge},
         %{"keyid" => ^subject, "sig" => sig64} <- given,
         {:ok, signature} <- strict64(sig64),
         {:ok, bytes} <- strict64(key["bytes"]),
         message = Envelope.message(payload),
         true <-
           Key.verify(key["algorithm"], message, signature, bytes) || {:error, :bad_signature},
         {:ok, ours} <- info.signer.sign.(message),
         envelope = Envelope.assemble(payload, [{info.key_id, ours}, {subject, signature}]),
         {:ok, %{ref: ref}} <-
           Pipeline.admit(Runtime.pipeline(), envelope, %{
             subject => %{algorithm: key["algorithm"], bytes: bytes}
           }),
         # In the index before the answer goes out, so the workload's
         # first record, sent straight away, finds its badge.
         :ok <- Pipeline.flush(Runtime.pipeline()) do
      # Noted against the workload's key, so that its records can be
      # taken without the badge being sent again, and so that an export
      # of those records carries the badge.
      with {module, handle} <- info.store,
           true <- function_exported?(module, :note_authority, 3) do
        module.note_authority(handle, subject, [ref])
      end

      profile = Recurse.Provenance.Profile.encode(info.profile)
      published = Map.get(info, :publications, [])
      # How this deployment's chain began, so the workload's own exports
      # can be read by someone who pins the chain by name.
      start = Recurse.Gateway.Provenance.Claim.carried()

      {:ok,
       %{
         "badge" => %{"ref" => ref, "envelope" => envelope},
         "streamPrefix" => hd(evidence["body"]["streamPrefixes"]),
         "authorityChain" => start["records"] ++ authority.records,
         # The publisher's statements about the definitions, so the workload's
         # own exports can say whose definitions its records cite.
         "publications" => Enum.flat_map(published, & &1["records"]),
         "keys" =>
           Enum.uniq_by(
             authority.keys ++
               start["keys"] ++
               Enum.flat_map(published, & &1["keys"]) ++
               [
                 %{
                   "keyid" => info.key_id,
                   "algorithm" => info.algorithm,
                   "bytes" => Base.encode64(info.public_key)
                 }
               ],
             & &1["keyid"]
           ),
         "blobs" =>
           Enum.uniq_by(
             Map.get(authority, :blobs, []) ++
               start["blobs"] ++
               Enum.flat_map(published, & &1["blobs"]) ++
               [
                 %{
                   "ref" => Ref.bytes(profile),
                   "mediaType" => "application/json",
                   "base64" => Base.encode64(profile)
                 }
               ],
             & &1["ref"]
           )
       }}
    else
      %{} -> {:error, :signature_is_not_the_subjects}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :badge_not_admissible}
    end
  end

  def finalize(_request, _acts_for), do: {:error, :malformed_request}

  # -- what the badge says -------------------------------------------------

  defp subject(%{"algorithm" => algorithm, "bytes" => text} = key) when is_binary(text) do
    with {:ok, bytes} <- strict64(text),
         {:ok, id} <- Key.id(algorithm, bytes) do
      {:ok, Map.take(key, ["algorithm", "bytes"]), id}
    else
      _ -> {:error, :not_a_public_key}
    end
  end

  defp subject(_other), do: {:error, :not_a_public_key}

  # Everything is cut down to what the gateway's own endorsement allows.
  defp body(request, parent, subject, subject_key, acts_for, stream_prefix) do
    granted = parent.body
    kinds = for k <- List.wrap(request["requestedKinds"]), k in granted["kinds"], do: k
    now = now()
    ttl = min(ttl(request["requestedTtlSeconds"]), @max_ttl_seconds)
    until = earliest(DateTime.add(now, ttl, :second), granted["notAfter"])
    holder = request["holder"]

    cond do
      kinds == [] ->
        {:error, :no_requested_kind_is_grantable}

      not (is_binary(holder) and holder =~ ~r/\A[a-z][a-z0-9-]*\z/) ->
        {:error, :holder_not_acceptable}

      granted["actsFor"] != nil and granted["actsFor"] != acts_for ->
        {:error, :caller_is_not_whom_the_gateway_acts_for}

      before?(now, granted["notBefore"]) ->
        {:error, :gateway_endorsement_not_yet_in_force}

      DateTime.compare(until, now) != :gt ->
        {:error, :gateway_endorsement_has_run_out}

      # A badge whose streams fall outside the endorsement's would be
      # issued happily and then cover nothing its holder ever signed.
      granted["streamPrefixes"] != nil and
          not Enum.any?(granted["streamPrefixes"], &String.starts_with?(stream_prefix, &1)) ->
        {:error, :gateway_endorsement_does_not_cover_endpoint_streams}

      true ->
        {:ok,
         %{
           "subject" => subject,
           "subjectKey" => subject_key,
           "holder" => holder,
           "kinds" => Enum.uniq(kinds),
           "notBefore" => DateTime.to_iso8601(now),
           "notAfter" => DateTime.to_iso8601(until),
           "parent" => parent.ref,
           "streamPrefixes" => [stream_prefix]
         }
         |> put_present("actsFor", acts_for)
         |> put_present("workload", workload(request["workload"]))
         |> put_present(
           "actorPrefixes",
           prefixes(request["requestedActorPrefixes"], granted["actorPrefixes"])
         )}
    end
  end

  defp ttl(seconds) when is_integer(seconds) and seconds > 0, do: seconds
  defp ttl(_other), do: @max_ttl_seconds

  defp earliest(time, limit) do
    {:ok, limit, _} = DateTime.from_iso8601(limit)
    if DateTime.compare(time, limit) == :gt, do: limit, else: time
  end

  defp workload(uri) when is_binary(uri),
    do: if(uri =~ ~r/\A[A-Za-z][A-Za-z0-9+.-]*:\S+\z/, do: uri)

  defp workload(_other), do: nil

  # What the caller asked for, kept where the endorsement allows it; with
  # nothing usable asked for, exactly what the endorsement allows.
  defp prefixes(asked, allowed) do
    asked = for p <- List.wrap(asked), is_binary(p) and p != "", do: p

    kept =
      case allowed do
        nil -> asked
        _ -> Enum.filter(asked, fn p -> Enum.any?(allowed, &String.starts_with?(p, &1)) end)
      end

    cond do
      kept != [] -> kept
      allowed != nil -> allowed
      true -> nil
    end
  end

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  defp endpoint_prefix(info, id), do: "urn:r5e:stream:#{info.deployment}:endpoint:#{id}:"

  defp schema_ref do
    {:ok, %{ref: ref}} = Definitions.fetch(@badge)
    ref
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  # -- the ticket ------------------------------------------------------------

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
        if Base.encode64(bytes) == text, do: {:ok, bytes}, else: {:error, :not_strict_base64}

      _ ->
        {:error, :not_strict_base64}
    end
  end

  defp strict64(_other), do: {:error, :not_strict_base64}
end
