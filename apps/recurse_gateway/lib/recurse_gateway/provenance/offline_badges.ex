defmodule Recurse.Gateway.Provenance.OfflineBadges do
  @moduledoc """
  Badges a deployment's root gave a workload offline, so that the
  workload can hand over records it signed itself (A8) without ever
  enrolling with this gateway.

  A badge always hangs from an endorsement (A5: a `Badge` has a parent,
  and nobody endorses themselves), so what a root makes offline is a
  short chain: a parentless `Endorsement` from a root now in place to an
  issuing key `K` (another root, or a key made for the ceremony and
  thrown away), possibly further endorsements, and the `Badge` from the
  last of them to the workload's key `W`, signed by its issuer and then by
  `W`. It is handed over on `POST /v1/deployment/grants`, in the same
  shape as a grant, and taken only when all of this holds:

    * the deployment has been claimed, and every record in the set reads
      as signed, well formed, within its profile and with authority, by
      the rules any outside reader uses, trusting only the deployment's
      chain;
    * the set is exactly one badge and the endorsements above it, each
      once, up to one a root now in place gave;
    * the badge names whom it acts for (`actsFor`), and the badge and every
      endorsement above it name exactly one stream prefix, the same one,
      of the form `urn:r5e:stream:<deployment>:endpoint:offline-<24 hex>:`,
      which no badge for another key has claimed; they all act for the
      same person;
    * none of them grants a kind a workload may never write, none runs for
      longer than `max_ttl_seconds` (twelve hours, as an enrolled badge),
      all are in force now, and none has been taken back.

  What is taken is recorded on the deployment's own streams, sealed before
  the route answers, and noted against `W`, so that every export of `W`'s
  records carries the chain. None of it is added to the grants the gateway
  acts under itself (`grants.json`).

  `Admission` takes a record signed under such a badge only while the
  chain's top is a root still in place, every link is in force and sealed,
  none has been taken back, and the badge acts for the person submitting.
  A root takes a badge or any endorsement above it back through
  `POST /v1/deployment/revocations`; the gateway itself cannot, since it
  did not issue it.
  """

  require Logger

  alias Recurse.Gateway.Provenance.{Admission, Carried, Claim, Runtime}
  alias Recurse.Provenance.{Definitions, Envelope, Evidence, Export, Key, Pipeline}
  alias Recurse.Provenance.{Profile, Publication, Ref}
  alias RecurseVerify.Canonical

  @badge "provenance.r5e.io/v2/Badge"
  @endorsement "provenance.r5e.io/v2/Endorsement"
  @most 16
  @largest 262_144
  @max_ttl_seconds 43_200
  @max_links 15
  @file_name "offline-badges.json"

  @doc "Whether a grants set carries a badge, and so is a badge registration."
  @spec badge_set?(term()) :: boolean()
  def badge_set?(%{"records" => records}) when is_list(records) do
    records
    |> Enum.take(@most + 1)
    |> Enum.any?(fn
      %{"envelope" => envelope} ->
        case Envelope.open(envelope) do
          {:ok, %{evidence: %{} = evidence}} -> Evidence.kind_path(evidence) == @badge
          _ -> false
        end

      _ ->
        false
    end)
  rescue
    _ -> false
  end

  def badge_set?(_other), do: false

  @doc "The longest a root-issued badge, or an endorsement above one, may run."
  @spec max_ttl_seconds() :: pos_integer()
  def max_ttl_seconds,
    do: Application.get_env(:recurse_gateway, :offline_badge_max_ttl_seconds, @max_ttl_seconds)

  # -- registration ------------------------------------------------------------

  @doc """
  Take a badge and the endorsements above it. Answers `{:ok, :created |
  :already, body}` with the references recorded and the badge's.
  """
  @spec accept(map()) :: {:ok, :created | :already, map()} | {:error, atom()}
  def accept(%{"records" => [_ | _] = records, "keys" => keys})
      when is_list(keys) and length(records) > @most,
      do: {:error, :too_large}

  def accept(%{"records" => [_ | _] = records, "keys" => keys} = set)
      when is_list(keys) and length(records) <= @most do
    %{store: {module, handle}} = info = Runtime.info()
    blobs = for %{"ref" => _, "base64" => _} = blob <- List.wrap(set["blobs"]), do: blob
    set = %{"records" => records, "keys" => keys, "blobs" => blobs}
    now = DateTime.utc_now()

    with true <- byte_size(JSON.encode!(set)) <= @largest || {:error, :too_large},
         %{"state" => "claimed", "chain" => chain} <- Claim.describe() || {:error, :not_claimed},
         roots = Claim.roots(),
         {:ok, opened} <- open_all(records),
         {:ok, badge, links} <- chain_of(opened),
         {:ok, by_key} <- keys(keys),
         {:ok, profiles} <- profiles(opened, blobs),
         {:ok, prefix} <- bounds(info, badge, links, now),
         :ok <- from_a_current_root(links, roots),
         :ok <- streams(info, badge, links, roots),
         :ok <- Runtime.flush(),
         :ok <- not_taken_back(module, handle, [badge | links]),
         :ok <- prefix_free(info, prefix, badge),
         :ok <- no_stream_fork(module, handle, links ++ [badge]),
         :ok <- holds(set, opened, chain),
         fresh? = not Enum.all?([badge | links], &match?({:ok, _}, module.fetch(handle, &1.ref))),
         {:ok, refs} <- record(links ++ [badge], by_key, profiles),
         :ok <- Runtime.flush() do
      subject = badge.evidence["body"]["subject"]
      module.note_authority(handle, subject, refs)
      claim_prefix(info, prefix, subject)

      # Sealed before the route answers, so that nothing signed under the
      # badge is ever taken before a seal fixes the badge in time.
      _ = Runtime.seal()

      if sealed?(module, handle, links ++ [badge]) do
        {:ok, if(fresh?, do: :created, else: :already),
         %{"recorded" => refs, "badge" => badge.ref, "sealed" => true}}
      else
        Logger.warning("evidence: offline badge #{badge.ref} recorded but not sealed yet")
        {:error, :badge_recorded_not_sealed}
      end
    else
      %{} -> {:error, :not_claimed}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :unreadable_grant}
    end
  end

  def accept(_other), do: {:error, :unreadable_grant}

  defp open_all(records) do
    Enum.reduce_while(records, {:ok, []}, fn
      %{"ref" => ref, "envelope" => envelope}, {:ok, acc} ->
        with {:ok, %{ref: ^ref, evidence: %{} = evidence} = opened} <- Envelope.open(envelope),
             kind when kind in [@badge, @endorsement] <- Evidence.kind_path(evidence),
             %{"body" => %{} = _body, "stream" => s, "seq" => q, "issuer" => i}
             when is_binary(s) and is_integer(q) and is_binary(i) <- evidence do
          {:cont, {:ok, acc ++ [Map.put(opened, :envelope, envelope)]}}
        else
          kind when is_binary(kind) -> {:halt, {:error, :only_badges_and_endorsements}}
          _ -> {:halt, {:error, :unreadable_grant}}
        end

      _other, _acc ->
        {:halt, {:error, :unreadable_grant}}
    end)
  end

  # Exactly one badge, and the endorsements above it in order, each used
  # once, ending at one with no parent. Returned top first.
  defp chain_of(opened) do
    {badges, endorsements} = Enum.split_with(opened, &(Evidence.kind_path(&1.evidence) == @badge))

    with [badge] <- badges || [],
         by_ref = Map.new(endorsements, &{&1.ref, &1}),
         {:ok, links} <- walk(badge.evidence["body"]["parent"], by_ref, []),
         true <- length(links) == length(endorsements) || {:error, :set_is_not_one_chain} do
      {:ok, badge, links}
    else
      [] -> {:error, :set_is_not_one_chain}
      [_, _ | _] -> {:error, :set_is_not_one_chain}
      {:error, _} = error -> error
    end
  end

  defp walk(_ref, _by_ref, acc) when length(acc) > @max_links, do: {:error, :set_is_not_one_chain}

  defp walk(ref, by_ref, acc) when is_binary(ref) do
    case by_ref do
      %{^ref => link} ->
        if Enum.any?(acc, &(&1.ref == ref)),
          do: {:error, :set_is_not_one_chain},
          else: walk(link.evidence["body"]["parent"], by_ref, [link | acc])

      _ ->
        {:error, :set_is_not_one_chain}
    end
  end

  defp walk(nil, _by_ref, [_ | _] = acc), do: {:ok, acc}
  defp walk(_other, _by_ref, _acc), do: {:error, :set_is_not_one_chain}

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

  defp profiles(opened, blobs) do
    held = Map.new(blobs, &{&1["ref"], &1["base64"]})

    Enum.reduce_while(opened, {:ok, %{}}, fn %{evidence: %{"profileRef" => ref}}, {:ok, acc} ->
      with {:ok, text} <- Map.fetch(held, ref),
           {:ok, bytes} <- Base.decode64(text),
           true <- Ref.bytes(bytes) == ref,
           {:ok, %{} = profile} <- Canonical.decode_json(bytes),
           :ok <- Profile.validate(profile) do
        {:cont, {:ok, Map.put(acc, ref, profile)}}
      else
        _ -> {:halt, {:error, :profile_not_carried}}
      end
    end)
  end

  # What every enrolled badge is held to, and what keeps a durable
  # endorsement from becoming a wide one.
  defp bounds(info, badge, links, now) do
    body = badge.evidence["body"]
    prefix = List.first(List.wrap(body["streamPrefixes"]))

    refused =
      MapSet.new(Admission.refused_kinds(), &Definitions.kind_path(Definitions.api_version(), &1))

    all = [badge | links]

    cond do
      not (is_binary(body["actsFor"]) and body["actsFor"] != "") ->
        {:error, :badge_must_act_for_someone}

      not (is_binary(prefix) and body["streamPrefixes"] == [prefix] and
               offline_prefix?(info, prefix)) ->
        {:error, :badge_streams_not_offline_endpoint}

      Enum.any?(links, &(&1.evidence["body"]["streamPrefixes"] != [prefix])) ->
        {:error, :endorsement_wider_than_badge}

      Enum.any?(links, &(&1.evidence["body"]["actsFor"] != body["actsFor"])) ->
        {:error, :endorsement_wider_than_badge}

      Enum.any?(all, fn r ->
        Enum.any?(List.wrap(r.evidence["body"]["kinds"]), &MapSet.member?(refused, &1))
      end) ->
        {:error, :kind_not_admissible_from_workload}

      Enum.any?(all, &(window_seconds(&1) > max_ttl_seconds())) ->
        {:error, :window_too_long}

      not Enum.all?(all, &in_force?(&1.evidence["body"], now)) ->
        {:error, :not_in_force}

      true ->
        {:ok, prefix}
    end
  end

  defp offline_prefix?(info, prefix),
    do:
      Regex.match?(
        ~r/\Aurn:r5e:stream:#{Regex.escape(info.deployment)}:endpoint:offline-[0-9a-f]{24}:\z/,
        prefix
      )

  defp window_seconds(%{evidence: %{"body" => body}}) do
    with {:ok, from, _} <- DateTime.from_iso8601(to_string(body["notBefore"])),
         {:ok, until, _} <- DateTime.from_iso8601(to_string(body["notAfter"])) do
      DateTime.diff(until, from, :second)
    else
      _ -> :infinity
    end
  end

  @doc false
  def in_force?(body, now) do
    with {:ok, from, _} <- DateTime.from_iso8601(to_string(body["notBefore"])),
         {:ok, until, _} <- DateTime.from_iso8601(to_string(body["notAfter"])) do
      DateTime.compare(now, from) != :lt and DateTime.compare(now, until) != :gt
    else
      _ -> false
    end
  end

  # Where each record goes on this deployment's streams: the top link on
  # its root's own stream, any further endorsement on its root's stream or
  # a delegation stream of its own, and one badge stream for the badge.
  defp streams(info, badge, links, roots) do
    base = "urn:r5e:stream:#{info.deployment}:authority:"

    badge_ok? =
      Regex.match?(
        ~r/\A#{Regex.escape(base)}badge:offline-[0-9a-f]{24}\z/,
        badge.evidence["stream"]
      ) and
        badge.evidence["seq"] == 1 and is_nil(badge.evidence["previous"])

    links_ok? =
      Enum.all?(links, fn %{evidence: e} ->
        delegation_ok? =
          not is_nil(e["body"]["parent"]) and
            Regex.match?(~r/\A#{Regex.escape(base)}delegation:[0-9a-f]{16,64}\z/, e["stream"]) and
            e["seq"] == 1 and is_nil(e["previous"])

        root_ok? =
          case root_under(e, roots) do
            "root:" <> _ = under ->
              e["stream"] == base <> under or
                String.starts_with?(e["stream"], base <> under <> ":")

            nil ->
              false
          end

        root_ok? or delegation_ok?
      end)

    if badge_ok? and links_ok?, do: :ok, else: {:error, :stream_not_admissible}
  end

  defp root_under(%{"issuer" => issuer}, roots) do
    if issuer in roots.ever do
      "key:" <> rest = issuer
      "root:" <> (rest |> String.split(":") |> List.last())
    end
  end

  defp from_a_current_root([%{evidence: %{"issuer" => top, "body" => body}} | _], roots) do
    if is_nil(body["parent"]) and top in roots.current,
      do: :ok,
      else: {:error, :grant_not_from_a_current_root}
  end

  defp not_taken_back(module, handle, records) do
    if function_exported?(module, :revocations_of, 2) and
         module.revocations_of(handle, Enum.map(records, & &1.ref)) != [],
       do: {:error, :badge_taken_back},
       else: :ok
  end

  # A stream prefix belongs to the first key a badge gave it to. Checked
  # against both the local file and stored `Badge` records in the index so
  # rebuilding the local directory cannot hand the prefix to another key.
  defp prefix_free(%{store: {module, handle}} = info, prefix, badge) do
    subject = badge.evidence["body"]["subject"]

    stored =
      if function_exported?(module, :badge_subjects_for_prefix, 2),
        do: module.badge_subjects_for_prefix(handle, prefix),
        else: []

    known =
      case Map.get(prefixes(info), prefix) do
        nil -> stored
        owner -> Enum.uniq([owner | stored])
      end

    if Enum.all?(known, &(&1 == subject)), do: :ok, else: {:error, :stream_prefix_taken}
  end

  # Checked across the whole chain before any record is handed to the
  # pipeline, so a collision on a later link never leaves an earlier link
  # half-recorded.
  defp no_stream_fork(module, handle, records) do
    Enum.reduce_while(records, {:ok, %{}}, fn %{ref: ref, evidence: e}, {:ok, heads} ->
      %{"stream" => stream, "seq" => seq} = e
      previous = e["previous"]

      head =
        Map.get_lazy(heads, stream, fn ->
          case module.head(handle, stream) do
            {:ok, {last, last_ref}} -> {last, last_ref}
            _ -> {0, nil}
          end
        end)

      case head do
        {last, _last_ref} when seq <= last ->
          case module.range(handle, stream, seq, seq) do
            {:ok, [%{ref: ^ref}]} -> {:cont, {:ok, heads}}
            _ -> {:halt, {:error, :stream_fork_refused}}
          end

        {0, nil} when seq == 1 and is_nil(previous) ->
          {:cont, {:ok, Map.put(heads, stream, {1, ref})}}

        {last, last_ref} when last > 0 and seq == last + 1 and previous == last_ref ->
          {:cont, {:ok, Map.put(heads, stream, {seq, ref})}}

        {last, _last_ref} when last > 0 and seq == last + 1 ->
          {:halt, {:error, :stream_fork_refused}}

        _ ->
          {:halt, {:error, :stream_not_admissible}}
      end
    end)
    |> case do
      {:ok, _} -> :ok
      {:error, _} = error -> error
    end
  end

  defp prefixes(info) do
    with {:ok, text} <- File.read(Path.join(info.dir, @file_name)),
         {:ok, %{"prefixes" => %{} = prefixes}} <- Jason.decode(text) do
      prefixes
    else
      _ -> %{}
    end
  end

  defp claim_prefix(info, prefix, subject) do
    path = Path.join(info.dir, @file_name)
    partial = path <> ".partial"
    File.write!(partial, Jason.encode!(%{"prefixes" => Map.put(prefixes(info), prefix, subject)}))
    File.rename!(partial, path)
  end

  # Read with everything this deployment already carries, by someone who
  # pins its chain.
  defp holds(set, opened, chain) do
    {:ok, bare} = Export.build(records: [])
    bundle = bare |> Carried.carry() |> Publication.carry([set])
    report = Export.verify(bundle, trusted_chain: chain)
    refs = MapSet.new(opened, & &1.ref)

    sound? =
      Enum.all?(report.findings, fn f ->
        not MapSet.member?(refs, f.subject) or
          f.check not in [:signature, :body, :identity, :authority, :profile_bounds] or
          f.result == :ok
      end)

    with_authority? =
      Enum.all?(refs, fn ref ->
        Enum.any?(
          report.findings,
          &(&1.subject == ref and &1.check == :authority and &1.result == :ok)
        )
      end)

    if sound? and with_authority? do
      :ok
    else
      for f <- report.findings,
          MapSet.member?(refs, f.subject),
          f.result != :ok,
          f.check != :publication do
        Logger.warning(
          "evidence: offline badge set refused: #{f.check} #{f.code} on #{f.subject}"
        )
      end

      {:error, :grant_does_not_hold}
    end
  end

  defp record(records, by_key, profiles) do
    info = Runtime.info()
    roots = Claim.roots()
    delegation = "urn:r5e:stream:#{info.deployment}:authority:delegation:"

    Enum.reduce_while(records, {:ok, []}, fn record, {:ok, refs} ->
      %{"profileRef" => profile_ref} = e = record.evidence

      under =
        cond do
          Evidence.kind_path(e) == @badge -> "authority:badge:"
          String.starts_with?(e["stream"], delegation) -> "authority:delegation:"
          true -> "authority:" <> root_under(e, roots)
        end

      signers = Map.take(by_key, Envelope.signers(record))

      case Pipeline.accept(
             Runtime.pipeline(),
             record.envelope,
             signers,
             profiles[profile_ref],
             under
           ) do
        {:ok, %{ref: ref}} -> {:cont, {:ok, refs ++ [ref]}}
        {:error, reason} when is_atom(reason) -> {:halt, {:error, reason}}
        _ -> {:halt, {:error, :unreadable_grant}}
      end
    end)
  end

  defp sealed?(module, handle, records) do
    Enum.all?(records, fn %{evidence: %{"stream" => stream, "seq" => seq}} ->
      case module.last_seal(handle, stream) do
        {:ok, {_seal, through}} when is_integer(through) -> through >= seq
        _ -> false
      end
    end)
  end

  # -- admission ----------------------------------------------------------------

  @doc """
  Every offline badge chain held for a workload key, newest first, each
  with the endorsements above it top first.
  """
  @spec candidates(map(), String.t(), [map()]) :: [%{badge: map(), links: [map()]}]
  def candidates(%{store: {module, handle}, key_id: gateway}, subject, held) do
    held
    |> Enum.filter(fn %{evidence: e} ->
      e["kind"] == "Badge" and e["issuer"] != gateway and e["body"]["subject"] == subject
    end)
    |> Enum.sort_by(
      fn %{evidence: e} ->
        {to_string(e["body"]["notAfter"]), to_string(e["capturedAt"]), to_string(e["stream"])}
      end,
      :desc
    )
    |> Enum.flat_map(fn badge ->
      case stored_chain(module, handle, badge.evidence["body"]["parent"], []) do
        {:ok, links} -> [%{badge: badge, links: links}]
        _ -> []
      end
    end)
  end

  @doc """
  The newest offline badge held for a workload key, with the endorsements
  above it, top first, as stored entries; nil when there is none.
  """
  @spec find(map(), String.t(), [map()]) :: %{badge: map(), links: [map()]} | nil
  def find(info, subject, held), do: List.first(candidates(info, subject, held))

  @doc """
  Pick the first offline badge chain for a workload key that stands now
  for `caller`, or return why the newest chain does not stand.
  """
  @spec resolve(map(), [%{badge: map(), links: [map()]}], map(), DateTime.t()) ::
          {:ok, %{badge: map(), links: [map()]}} | {:error, atom()}
  def resolve(info, [first | _] = chains, caller, now) do
    case Enum.find(chains, &(standing(info, &1, caller, now) == :ok)) do
      %{} = active -> {:ok, active}
      nil -> standing(info, first, caller, now)
    end
  end

  defp stored_chain(_module, _handle, _ref, acc) when length(acc) > @max_links, do: :error
  defp stored_chain(_module, _handle, nil, [_ | _] = acc), do: {:ok, acc}

  defp stored_chain(module, handle, ref, acc) when is_binary(ref) do
    case module.fetch(handle, ref) do
      {:ok, %{evidence: %{"kind" => "Endorsement", "body" => body}} = link} ->
        stored_chain(module, handle, body["parent"], [link | acc])

      _ ->
        :error
    end
  end

  defp stored_chain(_module, _handle, _ref, _acc), do: :error

  @doc """
  Whether a record may be taken now under an offline badge `find/3`
  found, for `caller`. Everything here is read from memory or the index;
  nothing is recorded, except that an unsealed chain is sealed once.
  """
  @spec standing(map(), %{badge: map(), links: [map()]}, map(), DateTime.t()) ::
          :ok | {:error, atom()}
  def standing(%{store: {module, handle}} = info, %{badge: badge, links: links}, caller, now) do
    roots = Claim.roots()
    [top | _] = links
    all = [badge | links]

    cond do
      badge.evidence["body"]["actsFor"] != caller.principal ->
        {:error, :badge_does_not_act_for_caller}

      top.evidence["issuer"] not in roots.current or not is_nil(top.evidence["body"]["parent"]) ->
        {:error, :authority_ended}

      not Enum.all?(all, &in_force?(&1.evidence["body"], now)) ->
        {:error, :authority_ended}

      not_taken_back(module, handle, all) != :ok ->
        {:error, :authority_ended}

      not offline_prefix?(
        info,
        List.first(List.wrap(badge.evidence["body"]["streamPrefixes"])) || ""
      ) ->
        {:error, :no_standing}

      sealed?(module, handle, all) ->
        :ok

      true ->
        _ = Runtime.seal()
        if sealed?(module, handle, all), do: :ok, else: {:error, :badge_not_sealed}
    end
  end

  @doc "Every signer's key of a chain, from the index, for reading it."
  @spec keys_of(map(), [map()]) :: %{String.t() => map()}
  def keys_of(%{store: {module, handle}}, entries) do
    for %{envelope: envelope} <- entries,
        {:ok, opened} <- [Envelope.open(envelope)],
        id <- Envelope.signers(opened),
        {:ok, key} <- [module.get_key(handle, id)],
        into: %{},
        do: {id, %{algorithm: key.algorithm, bytes: key.public_key}}
  end
end
