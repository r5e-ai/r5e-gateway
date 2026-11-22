defmodule Recurse.Gateway.Provenance.Grants do
  @moduledoc """
  Takes the grants a customer's root gives this gateway, and records them.

  After a deployment is claimed, the gateway's working key has no
  standing until one of the customer's roots endorses it. That
  endorsement is made offline, by the root, and handed to the gateway
  here. The gateway records it and seals it like any other record,
  which is what fixes it in time: a grant that was only ever a file
  beside the gateway could be backdated by whoever later held a
  replaced root.

  What is handed over authorises itself. It is accepted only if, read by
  the rules any outside reader would use, every record in it stands
  under the roots this deployment declared when it was claimed, and it
  ends in a grant to this gateway's own key. Nothing else is taken: only
  endorsements, only a few, only the profiles they cite. Without that
  narrowness an open door that accepts "anything with authority" would
  let anyone holding a valid credential push records past sign-in and
  policy.
  """

  require Logger

  alias Recurse.Gateway.Provenance.{Claim, Enrolment, Runtime}
  alias Recurse.Provenance.{Envelope, Evidence, Export, Key, Pipeline, Profile, Ref}
  alias RecurseVerify.Canonical

  @endorsement "provenance.r5e.io/v2/Endorsement"
  @revocation "provenance.r5e.io/v2/Revocation"
  @principal "provenance.r5e.io/v2/Principal"
  @most 16
  @largest 262_144
  @file_name "grants.json"

  @type error ::
          :not_claimed
          | :too_large
          | :only_endorsements
          | :unreadable_grant
          | :grant_does_not_hold
          | :no_grant_names_this_gateway
          | :grant_not_in_force
          | :profile_not_carried
          | :stream_not_admissible
          | :stream_fork_refused
          | :principal_without_its_grant

  @doc "Where the accepted grants are kept between restarts."
  @spec file(Path.t()) :: Path.t()
  def file(dir), do: Path.join(dir, @file_name)

  @doc """
  Accept a set of grants: `%{"records" => [...], "keys" => [...],
  "blobs" => [...]}`. On success the references recorded are returned
  and the gateway acts under the grant at once.
  """
  @spec accept(term()) :: {:ok, [Ref.t()]} | {:error, error()}
  def accept(%{"records" => [_ | _] = records, "keys" => keys} = set)
      when is_list(keys) and length(records) <= @most do
    info = Runtime.info()
    blobs = for %{"ref" => _, "base64" => _} = blob <- List.wrap(set["blobs"]), do: blob
    set = %{"records" => records, "keys" => keys, "blobs" => blobs}

    with true <- byte_size(JSON.encode!(set)) <= @largest || {:error, :too_large},
         %{"state" => "claimed", "chain" => chain} <- Claim.describe() || {:error, :not_claimed},
         roots = Claim.roots(),
         {:ok, opened, introduced} <- endorsements_and_principals(records),
         {:ok, by_key} <- keys(keys),
         # A new grant must come from a root in force now.
         :ok <- holds(set, opened ++ introduced, roots.current, info),
         # And must stand as a reader pinning this chain will read it:
         # a grant dated before the chain began would be taken here and
         # then count for nothing in every export.
         :ok <- stands_on_chain(set, opened, chain),
         :ok <- in_force(opened, info),
         {:ok, refs} <- record(opened, by_key, blobs, :grant),
         {:ok, more} <- record(introduced, by_key, blobs, :principal) do
      :ok = Pipeline.flush(Runtime.pipeline())
      install(minimal(set, opened ++ introduced), info)
      {:ok, refs ++ more}
    else
      %{} -> {:error, :not_claimed}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :unreadable_grant}
    end
  end

  def accept(_other), do: {:error, :unreadable_grant}

  @doc """
  Check that a set is a few endorsements with readable keys, without
  judging whether they hold. For a caller that will read them itself,
  together with a record they are meant to support, before `keep/1`.
  """
  @spec shape(term()) :: {:ok, map()} | {:error, error()}
  def shape(%{"records" => [_ | _] = records, "keys" => keys} = set)
      when is_list(keys) and length(records) <= @most do
    blobs = for %{"ref" => _, "base64" => _} = blob <- List.wrap(set["blobs"]), do: blob
    set = %{"records" => records, "keys" => keys, "blobs" => blobs}

    with true <- byte_size(JSON.encode!(set)) <= @largest || {:error, :too_large},
         {:ok, _opened} <- endorsements(records),
         {:ok, _by_key} <- keys(keys) do
      {:ok, set}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :unreadable_grant}
    end
  end

  def shape(_other), do: {:error, :unreadable_grant}

  @doc """
  Record grants the caller has already read as an outside reader would
  and found to hold: a grant to someone other than this gateway, such as
  the person releasing a hold. Nothing is judged here. The grants are
  recorded on their issuers' streams, kept and carried in every export.
  """
  @spec keep(map()) :: {:ok, [Ref.t()]} | {:error, error()}
  def keep(set) do
    with {:ok, set} <- shape(set),
         {:ok, opened} <- endorsements(set["records"]),
         {:ok, by_key} <- keys(set["keys"]),
         {:ok, refs} <- record(opened, by_key, set["blobs"], :grant) do
      :ok = Pipeline.flush(Runtime.pipeline())
      install(minimal(set, opened), Runtime.info())
      {:ok, refs}
    end
  end

  @doc """
  Accept a set of revocations: the same shape as grants, holding
  `Revocation` records. Each takes back a grant on this deployment's
  chain and is accepted when whoever signed it is entitled to, by the
  rules any reader would use: someone above the grant, the grant's own
  subject, or a root now in place. What is accepted is recorded and
  sealed, carried in every export from then on, and the gateway stops
  acting under any grant of its own that was taken back.
  """
  @spec revoke(term()) :: {:ok, [Ref.t()]} | {:error, error() | :only_revocations | :not_entitled}
  def revoke(%{"records" => [_ | _] = records, "keys" => keys} = set)
      when is_list(keys) and length(records) <= @most do
    info = Runtime.info()
    blobs = for %{"ref" => _, "base64" => _} = blob <- List.wrap(set["blobs"]), do: blob
    set = %{"records" => records, "keys" => keys, "blobs" => blobs}

    with true <- byte_size(JSON.encode!(set)) <= @largest || {:error, :too_large},
         %{"state" => "claimed", "chain" => chain} <- Claim.describe() || {:error, :not_claimed},
         {:ok, opened} <- of_kind(records, @revocation, :only_revocations),
         {:ok, by_key} <- keys(keys),
         # Each stands alone at the first position of a stream of its own.
         true <-
           Enum.all?(opened, &(&1.evidence["seq"] == 1 and is_nil(&1.evidence["previous"]))) ||
             {:error, :stream_not_admissible},
         :ok <- entitled(set, opened, chain),
         {:ok, refs} <- record(opened, by_key, blobs, :revocation) do
      :ok = Pipeline.flush(Runtime.pipeline())
      note_badges(opened, refs)

      # Only revocations of grants kept in `grants.json` belong there; a
      # revocation of a workload badge or an offline endorsement goes with
      # that workload's exports via `note_badges`, never into every export.
      held_grants = held(info.dir)
      in_grants = MapSet.new(held_grants["records"], & &1["ref"])

      about_grants =
        Enum.filter(opened, &MapSet.member?(in_grants, &1.evidence["body"]["target"]))

      if about_grants != [] do
        File.write!(
          file(info.dir),
          JSON.encode!(merge(held_grants, minimal(set, about_grants)))
        )

        # Taking a grant back is the one thing that may leave the gateway
        # with less standing than it had, or none.
        refresh(lose?: true)
      end

      {:ok, refs}
    else
      %{} -> {:error, :not_claimed}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :unreadable_grant}
    end
  end

  def revoke(_other), do: {:error, :unreadable_grant}

  # Read with everything this deployment already carries, by someone who
  # pins its chain: every revocation sent must be signed, well formed and
  # have authority.
  defp entitled(set, opened, chain) do
    # Everything an export would carry, seals included: whether an
    # earlier change of roots or an earlier grant is established can
    # depend on a seal, and a revocation is judged on top of those.
    {:ok, bare} = Export.build(records: [])
    named = badges_named(opened)

    bundle =
      bare
      |> Recurse.Gateway.Provenance.Carried.carry()
      |> Recurse.Provenance.Publication.carry([
        named,
        Recurse.Gateway.Provenance.Carried.seals_over([named]),
        set
      ])

    report = Export.verify(bundle, trusted_chain: chain)
    refs = MapSet.new(opened, & &1.ref)

    sound? =
      Enum.all?(report.findings, fn f ->
        not MapSet.member?(refs, f.subject) or f.check == :publication or f.result == :ok
      end)

    if sound? and
         Enum.all?(refs, fn ref ->
           Enum.any?(report.findings, &(&1.subject == ref and &1.check == :authority))
         end),
       do: :ok,
       else: {:error, :not_entitled}
  end

  # A revocation may name a badge this gateway gave a workload, or a badge
  # a root gave offline, or an endorsement above one. None of these is
  # among what every export carries, so the ones named are added for the
  # reading, with the endorsements above them: a revocation of something
  # not shown, or shown without the chain it hangs from, cannot be judged.
  defp badges_named(opened) do
    {module, handle} = Runtime.info().store
    # A badge issued a moment ago is in the index before it is looked for.
    Pipeline.flush(Runtime.pipeline())

    named =
      for %{evidence: %{"body" => %{"target" => target}}} <- opened,
          {:ok, %{evidence: %{"kind" => kind}} = entry} <- [module.fetch(handle, target)],
          kind in ["Badge", "Endorsement"],
          do: entry

    entries =
      named
      |> Enum.flat_map(&with_parents(module, handle, &1, 0))
      |> Enum.uniq_by(& &1.ref)

    badges = Enum.filter(entries, &(&1.evidence["kind"] == "Badge"))

    signers =
      for %{envelope: envelope} <- entries,
          {:ok, opened} <- [Envelope.open(envelope)],
          id <- Envelope.signers(opened),
          {:ok, key} <- [module.get_key(handle, id)],
          do: %{
            "keyid" => id,
            "algorithm" => key.algorithm,
            "bytes" => Base.encode64(key.public_key)
          }

    %{
      "records" => for(e <- entries, do: %{"ref" => e.ref, "envelope" => e.envelope}),
      "keys" =>
        Enum.uniq_by(
          for(
            %{evidence: %{"body" => %{"subject" => id, "subjectKey" => key}}} <- badges,
            do: %{"keyid" => id, "algorithm" => key["algorithm"], "bytes" => key["bytes"]}
          ) ++ signers,
          & &1["keyid"]
        ),
      "blobs" =>
        for(
          ref <- entries |> Enum.map(& &1.evidence["profileRef"]) |> Enum.uniq(),
          {:ok, bytes} <- [module.get_blob(handle, ref)],
          do: %{"ref" => ref, "base64" => Base.encode64(bytes)}
        )
    }
  end

  # An entry and the endorsements above it that the index holds.
  defp with_parents(_module, _handle, entry, depth) when depth > 16, do: [entry]

  defp with_parents(module, handle, %{evidence: %{"body" => body}} = entry, depth) do
    case body["parent"] do
      parent when is_binary(parent) ->
        case module.fetch(handle, parent) do
          {:ok, %{evidence: %{"kind" => "Endorsement"}} = above} ->
            [entry | with_parents(module, handle, above, depth + 1)]

          _ ->
            [entry]
        end

      _ ->
        [entry]
    end
  end

  # A badge taken back is noted against the workload's key, so that
  # nothing more is taken under it and exports of its records say so. So
  # is a revocation of anything a workload's key was noted with, such as
  # an endorsement above a badge a root gave offline.
  defp note_badges(opened, refs) do
    {module, handle} = Runtime.info().store

    if function_exported?(module, :note_authority, 3) do
      for {%{evidence: %{"body" => %{"target" => target}}}, ref} <- Enum.zip(opened, refs),
          {:ok, %{evidence: %{"kind" => "Badge", "body" => %{"subject" => subject}}}} <-
            [module.fetch(handle, target)],
          do: module.note_authority(handle, subject, [target, ref])

      if function_exported?(module, :issuers_noting, 2) do
        for {%{evidence: %{"body" => %{"target" => target}}}, ref} <- Enum.zip(opened, refs),
            issuer <- module.issuers_noting(handle, target),
            do: module.note_authority(handle, issuer, [ref])
      end
    end

    :ok
  end

  # -- checking -------------------------------------------------------------

  defp endorsements(records), do: of_kind(records, @endorsement, :only_endorsements)

  # A set of grants may also carry the record by which a key introduces
  # itself, for a key one of those grants is to. A root that endorses a
  # person's key says what the key may do; the key's own `Principal` says
  # whose it is and how it is kept, and a reader wants both. It is taken
  # only alongside a grant to that key, signed by that key, alone at the
  # first position of its stream.
  defp endorsements_and_principals(records) do
    {principals, rest} =
      Enum.split_with(records, fn
        %{"envelope" => envelope} ->
          match?(
            {:ok, %{evidence: %{"kind" => "Principal"} = evidence}}
            when is_map(evidence),
            Envelope.open(envelope)
          ) and principal?(envelope)

        _ ->
          false
      end)

    with {:ok, opened} <- endorsements(rest),
         {:ok, introduced} <- of_kind(principals, @principal, :unreadable_grant) do
      subjects = MapSet.new(opened, & &1.evidence["body"]["subject"])

      if Enum.all?(introduced, fn %{evidence: evidence} ->
           key = evidence["body"]["key"]

           evidence["issuer"] == key and evidence["seq"] == 1 and is_nil(evidence["previous"]) and
             MapSet.member?(subjects, key)
         end),
         do: {:ok, opened, introduced},
         else: {:error, :principal_without_its_grant}
    end
  end

  defp principal?(envelope) do
    case Envelope.open(envelope) do
      {:ok, %{evidence: evidence}} -> Evidence.kind_path(evidence) == @principal
      _ -> false
    end
  end

  # Read with everything an export carries, by someone who knows only the
  # chain's name.
  defp stands_on_chain(set, opened, chain) do
    {:ok, bare} = Export.build(records: [])

    bundle =
      bare
      |> Recurse.Gateway.Provenance.Carried.carry()
      |> Recurse.Provenance.Publication.carry([set])

    report = Export.verify(bundle, trusted_chain: chain)
    refs = MapSet.new(opened, & &1.ref)

    sound? =
      Enum.all?(report.findings, fn f ->
        not MapSet.member?(refs, f.subject) or f.check == :publication or f.result == :ok
      end)

    if sound? and
         Enum.all?(refs, fn ref ->
           Enum.any?(report.findings, &(&1.subject == ref and &1.check == :authority))
         end),
       do: :ok,
       else: {:error, :grant_does_not_hold}
  end

  defp of_kind(records, kind, otherwise) do
    Enum.reduce_while(records, {:ok, []}, fn
      %{"ref" => ref, "envelope" => envelope}, {:ok, acc} ->
        case Envelope.open(envelope) do
          {:ok, %{ref: ^ref, evidence: evidence} = opened} ->
            if Evidence.kind_path(evidence) == kind,
              do: {:cont, {:ok, acc ++ [Map.put(opened, :envelope, envelope)]}},
              else: {:halt, {:error, otherwise}}

          _ ->
            {:halt, {:error, :unreadable_grant}}
        end

      _other, _acc ->
        {:halt, {:error, :unreadable_grant}}
    end)
  end

  defp keys(entries) do
    Enum.reduce_while(entries, {:ok, %{}}, fn
      %{"keyid" => id, "algorithm" => algorithm, "bytes" => text}, {:ok, acc}
      when is_binary(text) ->
        with {:ok, bytes} <- Base.decode64(text),
             {:ok, ^id} <- Key.id(algorithm, bytes) do
          {:cont, {:ok, Map.put(acc, id, %{algorithm: algorithm, bytes: bytes})}}
        else
          _ -> {:halt, {:error, :unreadable_grant}}
        end

      _other, _acc ->
        {:halt, {:error, :unreadable_grant}}
    end)
  end

  # Read as an outside reader would read it, trusting only the roots this
  # deployment declared: every grant must be signed, well formed and have
  # authority, and one must be to this gateway's key.
  defp holds(set, opened, roots, info) do
    wire =
      for %{"keyid" => id, "algorithm" => algorithm, "bytes" => text} <- set["keys"],
          do: %{key_id: id, algorithm: algorithm, public_key: Base.decode64!(text)}

    {:ok, bundle} =
      Export.build(
        records: Enum.map(opened, & &1.envelope),
        keys: wire,
        blobs: for(%{"base64" => text} <- set["blobs"], do: {Base.decode64!(text), nil})
      )

    report = Export.verify(bundle, trusted_roots: roots)

    sound? =
      Enum.all?(report.findings, fn f ->
        f.check not in [:signature, :body, :identity, :authority, :profile_bounds] or
          f.result == :ok
      end)

    cond do
      not sound? ->
        {:error, :grant_does_not_hold}

      not Enum.any?(opened, &(&1.evidence["body"]["subject"] == info.key_id)) ->
        {:error, :no_grant_names_this_gateway}

      true ->
        :ok
    end
  end

  # A grant to this gateway must be in force now. Grants are public once
  # exported, and this route asks for no sign-in, so without this anyone
  # could send back last year's grant; it would be perfectly valid as a
  # record of the past and must change nothing about the present.
  defp in_force(opened, info) do
    now = DateTime.utc_now()

    before? = fn text, at ->
      case DateTime.from_iso8601(text) do
        {:ok, instant, _} -> DateTime.compare(instant, at) != :gt
        _ -> false
      end
    end

    live? =
      Enum.any?(opened, fn %{evidence: %{"body" => body}} ->
        body["subject"] == info.key_id and before?.(body["notBefore"], now) and
          not before?.(body["notAfter"], now)
      end)

    if live?, do: :ok, else: {:error, :grant_not_in_force}
  end

  # Only what the accepted grants themselves cite is kept.
  defp minimal(set, opened) do
    issuers = MapSet.new(opened, & &1.evidence["issuer"])
    profiles = MapSet.new(opened, & &1.evidence["profileRef"])

    %{
      "records" => for(o <- opened, do: %{"ref" => o.ref, "envelope" => o.envelope}),
      "keys" => Enum.filter(set["keys"], &MapSet.member?(issuers, &1["keyid"])),
      "blobs" => Enum.filter(set["blobs"], &MapSet.member?(profiles, &1["ref"]))
    }
  end

  # -- recording --------------------------------------------------------------

  # Each grant goes on its issuer's own stream inside this deployment,
  # under the profile its issuer made for that stream.
  defp record(opened, by_key, blobs, what) do
    held = Map.new(blobs, &{&1["ref"], &1["base64"]})

    Enum.reduce_while(opened, {:ok, []}, fn grant, {:ok, refs} ->
      %{"issuer" => issuer, "profileRef" => profile_ref} = grant.evidence
      "key:" <> rest = issuer

      # A grant goes on its issuer's own stream. A revocation goes alone
      # on a stream of its own, so taking a grant back never has to be
      # fitted in after whatever that issuer wrote last.
      under =
        case what do
          :grant -> "authority:root:" <> (rest |> String.split(":") |> List.last())
          :principal -> "authority:principal:" <> (rest |> String.split(":") |> List.last())
          :revocation -> "authority:revocation:"
        end

      with {:ok, text} <- Map.fetch(held, profile_ref),
           {:ok, bytes} <- Base.decode64(text),
           true <- Ref.bytes(bytes) == profile_ref,
           {:ok, %{} = profile} <- Canonical.decode_json(bytes),
           :ok <- Profile.validate(profile),
           {:ok, %{ref: ref}} <-
             Pipeline.accept(
               Runtime.pipeline(),
               grant.envelope,
               Map.take(by_key, [issuer]),
               profile,
               under
             ) do
        {:cont, {:ok, refs ++ [ref]}}
      else
        :error -> {:halt, {:error, :profile_not_carried}}
        {:error, reason} when is_atom(reason) -> {:halt, {:error, reason}}
        _ -> {:halt, {:error, :profile_not_carried}}
      end
    end)
  end

  # The gateway acts under the grants it has been given, and finds them
  # all again after a restart. What is accepted is added to what was
  # accepted before, never put in its place.
  defp install(set, info) do
    File.write!(file(info.dir), JSON.encode!(merge(held(info.dir), set)))
    refresh()
  end

  @doc """
  The grants to this gateway's key that it holds, for an operator who
  needs to see them or name one to take back: each one's reference,
  issuer and window, whether it has been taken back, and whether the
  gateway is acting under it now.
  """
  @spec list() :: [map()]
  def list do
    info = Runtime.info()
    set = held(info.dir)

    opened =
      for %{"envelope" => envelope} <- set["records"],
          {:ok, %{ref: ref, evidence: evidence}} <- [Envelope.open(envelope)],
          do: {ref, evidence}

    revoked =
      for {_ref, %{"kind" => "Revocation", "body" => %{"target" => target}}} <- opened,
          into: MapSet.new(),
          do: target

    acting =
      case info.authority do
        %{endorsements: endorsements} -> MapSet.new(endorsements, & &1.ref)
        _ -> MapSet.new()
      end

    for {ref, %{"kind" => "Endorsement", "issuer" => issuer, "body" => body}} <- opened,
        body["subject"] == info.key_id do
      %{
        "ref" => ref,
        "issuer" => issuer,
        "notBefore" => body["notBefore"],
        "notAfter" => body["notAfter"],
        "mayEndorse" => body["mayEndorse"] == true,
        "revoked" => MapSet.member?(revoked, ref),
        "active" => MapSet.member?(acting, ref)
      }
    end
  end

  @doc """
  Work out again what the gateway may do from the grants it holds and
  the roots as they now are, and act under it. Called when a grant is
  accepted, when the roots change, and when a claimed deployment starts.

  The standing the gateway already has is replaced only by a standing,
  never by nothing: a grant that cannot be acted under must not be able
  to take away one that can.
  """
  @spec refresh(keyword()) :: :ok
  def refresh(opts \\ []) do
    info = Runtime.info()
    own = %{key_id: info.key_id, algorithm: info.algorithm, public_key: info.public_key}
    roots = Claim.roots()

    # Read from every key that has been a root, since a grant an earlier
    # root gave while it was one still stands; badges are issued under a
    # grant from a root now in place when there is one.
    case Enrolment.standing(held(info.dir), info.key_id, own, roots.ever, roots.current) do
      {:ok, standing} ->
        Runtime.put_authority(standing)

      {:error, :no_endorsement_names_this_key} ->
        :ok

      {:error, reason} ->
        if Keyword.get(opts, :lose?, false) do
          Logger.warning(
            "evidence: every grant to this gateway has been taken back or no longer holds " <>
              "(#{inspect(reason)}); it has no standing until a root gives it a new one"
          )

          Runtime.put_authority(nil)
        else
          Logger.warning(
            "evidence: the grants held do not give this gateway standing " <>
              "(#{inspect(reason)}); its standing is unchanged"
          )
        end
    end

    :ok
  end

  defp held(dir) do
    with {:ok, text} <- File.read(file(dir)),
         {:ok, %{"records" => _, "keys" => _} = set} <- Jason.decode(text) do
      set
    else
      _ -> %{"records" => [], "keys" => [], "blobs" => []}
    end
  end

  defp merge(old, new) do
    for {field, id} <- [{"records", "ref"}, {"keys", "keyid"}, {"blobs", "ref"}], into: %{} do
      {field, Enum.uniq_by(List.wrap(old[field]) ++ List.wrap(new[field]), & &1[id])}
    end
  end
end
