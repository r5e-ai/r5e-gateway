defmodule Recurse.Provenance.Authority do
  @moduledoc """
  Establishes who was entitled to issue each record, starting from keys
  the reader chose to trust and following signed records outward.

  A capture profile lists the keys an operator says may issue. That is the
  operator's word. This module is the other way to answer the question: a
  reader names a few root keys, and a record's issuer has standing only if
  a chain of `Endorsement` and `Badge` records leads from a root to it,
  each link granting no more than the one above, with `Revocation` and
  `Succession` records taken into account.

  Time is the hard part. Every record states its own time, and a stolen
  key can state any time. So a record that claims to predate the end of
  its key's standing is believed only when a seal by someone else, with
  standing of its own, shows it existed by then; otherwise the answer is
  "could not be established", never "fine".

  Everything here is a pure function over the records of one bundle. The
  rules are amendment A5 of the Provenance contract.
  """

  alias Recurse.Provenance.{Evidence, Start}
  alias Recurse.Provenance.Grammar.Schema, as: GrammarSchema

  @base "provenance.r5e.io/v2/"
  @endorsement @base <> "Endorsement"
  @badge @base <> "Badge"
  @succession @base <> "Succession"
  @revocation @base <> "Revocation"
  @principal @base <> "Principal"
  @publication @base <> "DefinitionPublished"
  @seal @base <> "EpochSeal"
  @max_links 16

  @typedoc """
  One opened record and what the earlier layers found: whether every
  signature verified, whether the body matched its definition, and
  whether either of those checks failed outright (as against merely
  not being possible, for want of a key or a definition).
  """
  @type record :: %{
          ref: String.t(),
          evidence: map(),
          signed?: boolean(),
          body_ok?: boolean(),
          broken?: boolean()
        }

  @typedoc "The outcome for one record: result, code, and what it is about."
  @type outcome :: {:ok | :failed | :incomplete, String.t(), String.t() | nil}

  @doc """
  The authority outcome for every record that needs one.

  `records` maps a reference to its record. `roots` is the reader's
  trusted key ids. `seal_cover` maps the reference of each seal whose
  epoch or membership check held to the references it was shown to cover.

  Returns a map from record reference to outcome. `Principal` and
  `Succession` records have no entry: they need nobody's permission.
  Neither does a `DefinitionPublished`: a publisher stands outside the
  reader's roots, and whether its word counts is the reader's separate
  choice of trusted publishers, reported by the publication check.
  """
  @spec outcomes(
          %{String.t() => record()},
          [String.t()] | %{String.t() => [Start.tenure()]},
          %{String.t() => MapSet.t()}
        ) :: %{String.t() => outcome()}
  def outcomes(records, roots, seal_cover) do
    world = world(records, roots, seal_cover)

    for {ref, record} <- records,
        kind = Evidence.kind_path(record.evidence),
        kind not in [@principal, @succession, @publication | Start.kinds()],
        into: %{} do
      {ref, outcome(kind, record, world)}
    end
  end

  @doc """
  The seals whose sealer has standing: the ones that may be used to show
  that something existed by a certain time.
  """
  @spec qualifying_seals(
          %{String.t() => record()},
          [String.t()] | %{String.t() => [Start.tenure()]},
          %{String.t() => MapSet.t()}
        ) :: MapSet.t()
  def qualifying_seals(records, roots, seal_cover) do
    world = world(records, roots, seal_cover)

    for {seal_ref, _covered} <- seal_cover,
        %{signed?: true, evidence: evidence} <- [Map.get(records, seal_ref)],
        Evidence.kind_path(evidence) == @seal,
        untouched_standing?(evidence, world),
        into: MapSet.new(),
        do: seal_ref
  end

  # -- the world: everything the bundle states about authority -------------

  defp world(records, roots, seal_cover) do
    stated = for {_ref, r} <- records, r.signed? and r.body_ok?, do: r

    links =
      for r <- stated, Evidence.kind_path(r.evidence) in [@endorsement, @badge], into: %{} do
        {r.ref, link(r)}
      end

    revocations =
      for r <- stated, Evidence.kind_path(r.evidence) == @revocation do
        %{
          ref: r.ref,
          issuer: r.evidence["issuer"],
          target: r.evidence["body"]["target"],
          at: at(r.evidence)
        }
      end

    {stand_ins, key_ends} = successions(stated)

    # Each root's time as a root. A plain list of keys means each was a
    # root for all time, which is what a reader who pins keys says.
    tenures =
      if is_map(roots),
        do: roots,
        else: Map.new(roots, &{&1, [%{from: 0, ended: nil}]})

    world = %{
      records: records,
      tenures: tenures,
      links: links,
      revocations: revocations,
      stand_ins: stand_ins,
      key_ends: key_ends,
      seal_cover: seal_cover,
      seal_times: %{}
    }

    %{world | seal_times: seal_times(world)}
  end

  defp link(%{ref: ref, evidence: evidence}) do
    body = evidence["body"]

    %{
      ref: ref,
      badge?: Evidence.kind_path(evidence) == @badge,
      issuer: evidence["issuer"],
      subject: body["subject"],
      kinds: body["kinds"],
      streams: body["streamPrefixes"],
      actors: body["actorPrefixes"],
      acts_for: body["actsFor"],
      not_before: ns(body["notBefore"]),
      not_after: ns(body["notAfter"]),
      parent: body["parent"],
      may_endorse?: body["mayEndorse"] == true,
      at: at(evidence)
    }
  end

  defp at(evidence), do: ns(evidence["capturedAt"])

  defp ns(text) do
    case GrammarSchema.timestamp_ns(text) do
      {:ok, ns} -> ns
      :error -> nil
    end
  end

  # Who stands in for whom, and which keys handed over.
  #
  # `stand_ins` maps a key to the keys it stands in for, each with the
  # instant from which it does. `key_ends` maps a key to the succession
  # that ended it. A key with two different successors, or in a loop of
  # successions, is ended and nobody stands in for it.
  defp successions(stated) do
    all =
      for r <- stated, Evidence.kind_path(r.evidence) == @succession do
        body = r.evidence["body"]
        %{ref: r.ref, from: body["predecessor"], to: body["successor"], at: at(r.evidence)}
      end

    by_from = Enum.group_by(all, & &1.from)

    key_ends =
      Map.new(by_from, fn {from, list} ->
        first = Enum.min_by(list, &{&1.at, &1.ref})
        {from, %{ref: first.ref, at: first.at}}
      end)

    edges =
      for {from, list} <- by_from,
          [to] <- [list |> Enum.map(& &1.to) |> Enum.uniq()],
          into: %{} do
        {from, %{to: to, at: list |> Enum.map(& &1.at) |> Enum.min()}}
      end

    # A loop of hand-overs ends every key on the loop, from the earliest
    # of them, and none stands in for another. A key that handed over
    # into the loop from outside is not on it and keeps its own hand-over.
    loops =
      for {from, _} <- edges, loop = loop_through(from, edges), loop != nil, do: {from, loop}

    looped = MapSet.new(loops, &elem(&1, 0))

    key_ends =
      Enum.reduce(loops, key_ends, fn {from, loop}, acc ->
        earliest = loop |> Enum.map(&Map.fetch!(key_ends, &1)) |> Enum.min_by(&{&1.at, &1.ref})
        Map.put(acc, from, earliest)
      end)

    edges = Map.reject(edges, fn {from, _} -> MapSet.member?(looped, from) end)

    stand_ins =
      Enum.reduce(edges, %{}, fn {from, _edge}, acc ->
        from
        |> forward(edges, nil, @max_links)
        |> Enum.reduce(acc, fn {successor, since}, acc ->
          Map.update(acc, successor, [{from, since}], &[{from, since} | &1])
        end)
      end)

    {stand_ins, key_ends}
  end

  # The keys of the loop that `start` is on, or nil when following
  # hand-overs from it never comes back to it.
  defp loop_through(start, edges), do: loop_through(start, start, edges, [start])

  defp loop_through(start, key, edges, seen) do
    case edges do
      %{^key => %{to: ^start}} ->
        seen

      %{^key => %{to: to}} ->
        if to in seen, do: nil, else: loop_through(start, to, edges, [to | seen])

      _ ->
        nil
    end
  end

  # Every key that comes to stand in for `key`, with the instant it starts:
  # the latest hand-over on the way, since each must have happened.
  defp forward(_key, _edges, _since, 0), do: []

  defp forward(key, edges, since, left) do
    case edges do
      %{^key => %{to: to, at: at}} ->
        since = if since, do: max(since, at), else: at
        [{to, since} | forward(to, edges, since, left - 1)]

      _ ->
        []
    end
  end

  # Whether `key`, signing at instant `t`, acts as `as`.
  # A key is itself, even after it has handed over: what it signs after
  # that is caught as an ending, so that the report can say which one.
  defp acts_as?(key, key, _t, _world), do: true

  defp acts_as?(key, as, t, world) do
    world.stand_ins
    |> Map.get(key, [])
    |> Enum.any?(fn {original, since} -> original == as and since <= t end)
  end

  # Whether `key` had become a root by instant `t`. Only a key listed as
  # a root is one: a root's place never passes to another key by a
  # hand-over, only by a change of roots on the start stream.
  defp root_by?(key, t, world) do
    t != nil and Enum.any?(Map.get(world.tenures, key, []), &(&1.from <= t))
  end

  # What ended the time as a root under which `key` signed something at
  # `t`, as an ending to weigh; nothing when that time has not ended. A
  # root that was removed is believed about nothing: what it signed
  # stands only if something shows it existed before the removal.
  defp root_ending(key, item_ref, item_at, world) do
    held = world.tenures |> Map.get(key, []) |> Enum.filter(&(&1.from <= item_at))

    case {Enum.any?(held, &is_nil(&1.ended)), Enum.max_by(held, & &1.from, fn -> nil end)} do
      {false, %{ended: %{ref: ref, at: at}}} ->
        [
          %{
            ref: ref,
            at: at,
            own?: false,
            item: item_ref,
            item_at: item_at,
            trusted_clock?: false
          }
        ]

      _ ->
        []
    end
  end

  defp root_open?(key, t, world) do
    world.tenures |> Map.get(key, []) |> Enum.any?(&(&1.from <= t and is_nil(&1.ended)))
  end

  # -- seals that show something existed by a time ---------------------------

  # A seal counts only when it is signed and its own issuer has a chain
  # that covers it, with no link of that chain ever taken back or handed
  # over, and with a root that is still a root. A sealer whose chain
  # hangs from a root since removed still counts if a root now in place
  # also vouches for that sealer over the same stream: the gateway that
  # sealed the old root's grants and was then endorsed by the new root.
  # A sealer that only a removed root ever vouched for does not, so
  # whoever holds a removed root cannot make a sealer of their own and
  # date their own history. Nothing here needs a seal to judge a seal.
  defp seal_times(world) do
    for {seal_ref, covered} <- world.seal_cover,
        %{signed?: true, evidence: evidence} <- [Map.get(world.records, seal_ref)],
        Evidence.kind_path(evidence) == @seal,
        untouched_standing?(evidence, world),
        item <- covered,
        reduce: %{} do
      acc -> Map.update(acc, item, [at(evidence)], &[at(evidence) | &1])
    end
  end

  defp untouched_standing?(evidence, world) do
    issuer = evidence["issuer"]
    clean = clean_chains(issuer, at(evidence), evidence, world)
    covering = Enum.filter(clean, fn chain -> Enum.all?(chain, &covers?(&1, evidence)) end)

    Enum.any?(covering, fn [top | _] -> root_open?(top.issuer, top.at, world) end) or
      (covering != [] and
         Enum.any?(clean, fn [top | _] = chain ->
           root_open?(top.issuer, top.at, world) and
             Enum.all?(chain, fn link ->
               @seal in link.kinds and prefixed?(link.streams, evidence["body"]["stream"])
             end)
         end))
  end

  # The complete chains for `key` that nothing below the root has ended.
  defp clean_chains(key, t, evidence, world) do
    for last <- last_links(key, t, world),
        {:complete, chain} <- [ancestry(last, world)],
        item = %{ref: nil, at: at(evidence), issuer: evidence["issuer"]},
        revoked(chain, item, world) == [],
        key_ended(
          Enum.map(tl(chain), &%{ref: &1.ref, at: &1.at, issuer: &1.issuer}) ++ [item],
          world
        ) ==
          [],
        do: chain
  end

  # -- chains ----------------------------------------------------------------

  # The links that could be the last link of a chain for `key` signing at
  # `t`: those naming it as subject, and endorsements naming a key it
  # stands in for. A badge dies with its key.
  defp last_links(key, t, world) do
    for {_ref, l} <- world.links,
        l.subject == key or (not l.badge? and acts_as?(key, l.subject, t, world)),
        l.issuer != l.subject,
        do: l
  end

  # The chain above a link, root first.
  #
  #   {:complete, links}        reaches a trusted root, every step valid
  #   {:missing, ref, links}    valid as far as carried; `ref` is the parent
  #                             the top carried link names and nobody carried
  #   :invalid                  a step breaks a rule
  defp ancestry(link, world), do: ancestry(link, [link], world)

  defp ancestry(_link, chain, _world) when length(chain) > @max_links, do: :invalid

  defp ancestry(%{parent: nil} = top, chain, world) do
    if not top.badge? and top.issuer != top.subject and root_by?(top.issuer, top.at, world),
      do: {:complete, chain},
      else: :invalid
  end

  defp ancestry(%{parent: parent_ref} = child, chain, world) do
    case world.links do
      %{^parent_ref => parent} ->
        if parent not in chain and step_ok?(parent, child, world),
          do: ancestry(parent, [parent | chain], world),
          else: :invalid

      _ ->
        if could_be_a_grant?(parent_ref, [@endorsement], world),
          do: {:missing, parent_ref, chain},
          else: :invalid
    end
  end

  # A reference nobody carried, or a grant that is carried but could not
  # be checked (its key or definition is missing), might yet be a valid
  # grant. A badge is never a parent, so only an endorsement will do there. One that is carried and failed a check, or is some other kind
  # of record, is not.
  defp could_be_a_grant?(ref, kinds, world) do
    case world.records do
      %{^ref => %{evidence: evidence, broken?: broken?}} ->
        not broken? and Evidence.kind_path(evidence) in kinds and
          not is_map_key(world.links, ref)

      _ ->
        true
    end
  end

  # A link never grants more than its parent, and was issued by the
  # parent's subject while the parent was in force.
  defp step_ok?(parent, child, world) do
    not parent.badge? and parent.may_endorse? and child.issuer != child.subject and
      acts_as?(child.issuer, parent.subject, child.at, world) and
      within?(child.at, parent) and
      child.kinds -- parent.kinds == [] and
      parent.not_before <= child.not_before and child.not_after <= parent.not_after and
      narrower?(child.streams, parent.streams) and
      narrower?(child.actors, parent.actors) and
      (parent.acts_for == nil or child.acts_for == parent.acts_for)
  end

  defp within?(t, link), do: t != nil and link.not_before <= t and t <= link.not_after

  defp narrower?(_child, nil), do: true
  defp narrower?(nil, _parent), do: false

  defp narrower?(child, parent),
    do: Enum.all?(child, fn c -> Enum.any?(parent, &String.starts_with?(c, &1)) end)

  # Whether a link covers a record. A seal is tested on the stream it
  # seals, not the stream it sits in.
  defp covers?(link, evidence) do
    stream =
      if Evidence.kind_path(evidence) == @seal,
        do: evidence["body"]["stream"],
        else: evidence["stream"]

    Evidence.kind_path(evidence) in link.kinds and
      prefixed?(link.streams, stream) and
      prefixed?(link.actors, evidence["actor"]) and
      (link.acts_for == nil or evidence["onBehalfOf"] == link.acts_for) and
      within?(at(evidence), link)
  end

  defp prefixed?(nil, _value), do: true

  defp prefixed?(prefixes, value) when is_binary(value),
    do: Enum.any?(prefixes, &String.starts_with?(value, &1))

  defp prefixed?(_prefixes, _value), do: false

  # -- endings ----------------------------------------------------------------

  # Every ending that touches a chain, for the item signed under it.
  #
  # Each is `%{ref, at, own?, item, item_at}`: the ending record, when it
  # says it happened, whether the key it ends signed it, and the thing
  # whose time it is compared with. A revocation is compared with the item
  # itself. A hand-over is compared with whatever the old key signed after
  # it: the next link down, or the item.
  defp endings(chain, evidence, item_ref, world) do
    item = %{ref: item_ref, at: at(evidence), issuer: evidence["issuer"]}
    revoked(chain, item, world) ++ handed_over(chain, item, world)
  end

  # A revocation of a link reaches everything issued beneath it: each
  # link below, and the item. So a link minted under a grant after that
  # grant was taken back fails, whatever date the record under it claims.
  defp revoked(chain, item, world) do
    for {link, index} <- Enum.with_index(chain),
        rv <- world.revocations,
        rv.target == link.ref,
        standing = revoker(rv, link, Enum.take(chain, index + 1), world),
        standing != :none,
        thing <- Enum.drop(chain, index + 1) ++ [item] do
      %{
        ref: rv.ref,
        at: rv.at,
        own?: standing == :own,
        item: thing.ref,
        item_at: thing.at,
        trusted_clock?: false
      }
    end
  end

  # Whether a revocation comes from above the link, from the link's own
  # subject, or from nobody entitled.
  #
  # A key that has handed over no longer revokes. A revocation it dates
  # before its hand-over is its own word about its own past, so it counts
  # only when a seal shows the revocation existed by then, or when the
  # key is a trusted root.
  defp revoker(rv, link, link_and_above, world) do
    cond do
      Enum.any?(link_and_above, &revokes_as?(rv, &1.issuer, world)) -> :above
      root_revokes?(rv, link_and_above, world) -> :above
      revokes_as?(rv, link.subject, world) -> :own
      true -> :none
    end
  end

  # A key that is a root when it revokes may take back any grant on its
  # own deployment's chain, including one a root before it gave.
  # Otherwise replacing a stolen root would leave the new root unable to
  # undo what the thief granted. "Its own chain" has to be shown: the
  # links carried above the grant must reach one that a root of this
  # deployment gave. A grant whose top is missing, or was given by some
  # other party's key, is not this root's to take back. A root since
  # removed counts only if a seal shows its revocation existed before it
  # was removed.
  defp root_revokes?(rv, [%{parent: nil, issuer: top} | _], world)
       when is_map_key(world.tenures, top) do
    world.tenures
    |> Map.get(rv.issuer, [])
    |> Enum.any?(fn tenure ->
      tenure.from <= rv.at and
        case tenure.ended do
          nil -> true
          %{at: ended} -> Enum.any?(Map.get(world.seal_times, rv.ref, []), &(&1 < ended))
        end
    end)
  end

  defp root_revokes?(_rv, _chain, _world), do: false

  defp revokes_as?(rv, as, world) do
    acts_as?(rv.issuer, as, rv.at, world) and
      case world.key_ends do
        %{^as => %{at: ended}} when as == rv.issuer ->
          Enum.any?(Map.get(world.seal_times, rv.ref, []), &(&1 < ended))

        _ ->
          true
      end
  end

  # What each key in the chain signed: the root signed the first link,
  # each subject signed the next link, the last subject signed the item.
  # A root's time is ended by a change of roots; any other key's by its
  # own hand-over.
  defp handed_over([%{parent: nil} = top | rest], item, world) do
    signed = Enum.map(rest, &%{ref: &1.ref, at: &1.at, issuer: &1.issuer}) ++ [item]
    root_ending(top.issuer, top.ref, top.at, world) ++ key_ended(signed, world)
  end

  defp handed_over(chain, item, world) do
    signed = Enum.map(chain, &%{ref: &1.ref, at: &1.at, issuer: &1.issuer}) ++ [item]
    key_ended(signed, world)
  end

  defp key_ended(signed, world) do
    for %{issuer: key} = thing <- signed,
        %{ref: ref, at: at} <- [Map.get(world.key_ends, key)] do
      %{
        ref: ref,
        at: at,
        own?: true,
        item: thing.ref,
        item_at: thing.at,
        trusted_clock?: false
      }
    end
  end

  # :precedes — shown to have existed before the ending took hold
  # :applies  — the ending reaches it
  # :clock    — neither can be shown; it rests on the signer's word
  #
  # An ending signed from above is believed about its own date. One signed
  # by the key it ends is not: it reaches a record only when the record is
  # dated at or after it and was not shown to exist before the ending was.
  # And such a record is in the clear only when it was shown to exist
  # before the date the ending itself claims.
  defp weigh(%{trusted_clock?: true} = ending, _world),
    do: if(ending.item_at < ending.at, do: :precedes, else: :applies)

  defp weigh(%{own?: false} = ending, world) do
    shown = Map.get(world.seal_times, ending.item, [])

    cond do
      Enum.any?(shown, &(&1 < ending.at)) -> :precedes
      ending.item_at >= ending.at -> :applies
      true -> :clock
    end
  end

  defp weigh(%{own?: true} = ending, world) do
    shown = Map.get(world.seal_times, ending.item, [])
    ending_shown = Map.get(world.seal_times, ending.ref, [])
    first? = fn s -> not Enum.any?(ending_shown, &(&1 <= s)) end

    cond do
      Enum.any?(shown, &(&1 < ending.at and first?.(&1))) -> :precedes
      ending.item_at >= ending.at and not Enum.any?(shown, first?) -> :applies
      true -> :clock
    end
  end

  # What the endings make of a chain: `:ok`, or the lowest-referenced
  # ending that applies, or the lowest that rests on the signer's clock.
  defp verdict(ends, world) do
    weighed = Enum.group_by(ends, &weigh(&1, world), & &1.ref)

    cond do
      weighed[:applies] -> {:ended, Enum.min(weighed[:applies])}
      weighed[:clock] -> {:clock, Enum.min(weighed[:clock])}
      true -> :ok
    end
  end

  # -- outcomes ---------------------------------------------------------------

  defp outcome(@revocation, %{ref: ref, evidence: evidence}, world) do
    target = evidence["body"]["target"]
    issuer = evidence["issuer"]

    case world.links do
      %{^target => link} ->
        {chain, missing} =
          case ancestry(link, world) do
            {:complete, chain} -> {chain, nil}
            {:missing, missing, chain} -> {chain, missing}
            :invalid -> {[link], nil}
          end

        rv = %{ref: ref, issuer: issuer, at: at(evidence)}

        cond do
          revoker(rv, link, chain, world) != :none -> {:ok, "ok", target}
          # Someone above the carried links may be the issuer; it cannot be told.
          missing -> {:incomplete, "chain_not_carried", missing}
          true -> {:failed, "no_standing", issuer}
        end

      _ ->
        if could_be_a_grant?(target, [@endorsement, @badge], world),
          do: {:incomplete, "chain_not_carried", target},
          else: {:failed, "not_covered", nil}
    end
  end

  # A grant's own authority is judged from what it says, whether or not
  # its signature could be checked: that is the signature finding's
  # business. Whether others may rest on it is a separate matter (§1).
  defp outcome(kind, %{body_ok?: false}, _world) when kind in [@endorsement, @badge],
    do: {:failed, "not_covered", nil}

  defp outcome(kind, %{ref: ref, evidence: evidence} = record, world)
       when kind in [@endorsement, @badge] do
    case link(record) do
      %{parent: nil, issuer: same, subject: same} ->
        {:failed, "not_covered", nil}

      %{parent: nil} = link ->
        case ancestry(link, world) do
          {:complete, _chain} ->
            # A root's own grant: only a change of roots can end it.
            own = root_ending(link.issuer, ref, at(evidence), world)
            decide([{:candidate, link.issuer, own}], world)

          _ ->
            # A key that became a root only later had no standing yet.
            if Map.has_key?(world.tenures, link.issuer),
              do: {:failed, "not_covered", nil},
              else: {:failed, "no_standing", link.issuer}
        end

      link ->
        case ancestry(link, world) do
          {:complete, chain} ->
            decide([{:candidate, link.parent, grant_endings(chain, evidence, world)}], world)

          {:missing, missing, chain} ->
            decide([{:missing, missing, grant_endings(chain, evidence, world)}], world)

          :invalid ->
            nil
        end || {:failed, "not_covered", nil}
    end
  end

  # An ordinary record needs every one of its signers to have authority
  # for it, not only the first. A record a kind requires two parties to
  # sign means nothing if the second can be anybody. The worst outcome
  # among the signers is the record's, and among equals the earliest
  # signer's.
  defp outcome(_kind, %{count_differs?: true}, _world), do: {:failed, "not_covered", nil}

  defp outcome(_kind, %{evidence: evidence} = record, world) do
    signers = Map.get(record, :signers, [evidence["issuer"]])
    each = Enum.map(signers, &as_signer(&1, record, world))
    rank = fn {result, _, _} -> Enum.find_index([:failed, :incomplete, :ok], &(&1 == result)) end

    case Enum.min_by(each, rank) do
      {:ok, _, _} -> hd(each)
      worst -> worst
    end
  end

  defp as_signer(issuer, %{ref: ref, evidence: evidence}, world) do
    evidence = Map.put(evidence, "issuer", issuer)
    lasts = last_links(issuer, at(evidence), world)

    paths =
      for last <- lasts do
        case ancestry(last, world) do
          {:complete, chain} ->
            if Enum.all?(chain, &covers?(&1, evidence)),
              do: {:candidate, last.ref, endings(chain, evidence, ref, world)},
              else: :none

          {:missing, missing, chain} ->
            if Enum.all?(chain, &covers?(&1, evidence)),
              do: {:missing, missing, endings(chain, evidence, ref, world)},
              else: :none

          :invalid ->
            :none
        end
      end

    cond do
      found = decide(paths, world) ->
        found

      lasts == [] and not root_by?(issuer, at(evidence), world) ->
        {:failed, "no_standing", issuer}

      true ->
        {:failed, "not_covered", nil}
    end
  end

  # A grant's own item is the grant; the chain above it is everything but
  # the grant itself.
  defp grant_endings(chain, evidence, world) do
    endings(Enum.drop(chain, -1), evidence, List.last(chain).ref, world)
  end

  # The first row of the table that some path satisfies, or nil.
  defp decide(paths, world) do
    judged =
      for path <- paths, path != :none do
        {kind, about, ends} = path
        {kind, about, verdict(ends, world)}
      end

    ok = for {:candidate, about, :ok} <- judged, do: about
    clock = for {:candidate, _about, {:clock, ending}} <- judged, do: ending
    missing = for {:missing, about, v} <- judged, not match?({:ended, _}, v), do: about
    ended = for {:candidate, _about, {:ended, ending}} <- judged, do: ending

    cond do
      ok != [] -> {:ok, "ok", Enum.min(ok)}
      clock != [] -> {:incomplete, "time_rests_on_the_signer", Enum.min(clock)}
      missing != [] -> {:incomplete, "chain_not_carried", Enum.min(missing)}
      ended != [] -> {:failed, "ended", Enum.min(ended)}
      true -> nil
    end
  end
end
