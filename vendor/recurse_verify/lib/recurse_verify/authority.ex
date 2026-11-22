defmodule RecurseVerify.Authority do
  @moduledoc """
  Spec 011 §0's succession relation and §5's effectiveness walk, over a
  **bundle** rather than over a running kernel.

  Everything here is a function of the decoded payloads: the authority
  events, the Revocations, the Succession edges, and the `ts` each event
  carries. Nothing consults a producer's opinion, which is the point —
  the kernel records `resolvedAuthority` as a claim about a derivation,
  and this module is what re-performs the derivation so the claim can be
  checked rather than believed.

  The walk is §5's recurrence clause for clause, with the numbering as
  the reason precedence. Clause 7 re-checks facts issuance already
  enforced: on a chain the kernel wrote it can never fail, and on a
  bundle somebody assembled it can — which is exactly why the contract
  keeps it, and why the verifier needs no separate forged-event rule.

  ## The `s` and the `ts`

  Both are the citing event's, not "now": the walk asks whether an
  authority was effective **at the position the act was recorded at**,
  against the timestamp that act carries. A verifier that asked about the
  present would report a bundle differently on Tuesday than on Monday,
  and an offline check whose answer moves is not a check.
  """

  import RecurseVerify.Value, only: [dig: 2, text: 1]

  @authority_kinds ["core.r5e.io/v1/Endorsement", "core.r5e.io/v1/Badge"]
  @succession "core.r5e.io/v1/Succession"
  @revocation "core.r5e.io/v1/Revocation"

  @doc "The two Kinds whose events are authority (§5)."
  def authority_kinds, do: @authority_kinds

  @doc "Whether a target path names an authority event."
  def authority_kind?(path), do: path in @authority_kinds

  @doc """
  The empty index: three collections and nothing else.

  A reader building one incrementally (the kernel does — it is fed one
  event at a time as the chain grows) starts here and folds `observe/3`
  over the chain; a reader holding a whole bundle calls `build/1`, which
  is the same fold.
  """
  @spec empty() :: map()
  def empty, do: %{events: %{}, revocations: %{}, edges: []}

  @doc """
  Fold one `{event, payload}` into an index.

  **Granted admissions only**: a denial admitted nothing, so it endorses
  nothing, revokes nothing and succeeds nobody. Anything else is ignored,
  so a caller may feed the whole chain through without filtering.

  The three effects, in the order an event can have them:

    * an `Endorsement` or `Badge` becomes an entry in `events`, in §5's
      link shape — the thirteen fields `resolvedAuthority` records, so a
      recorded link and a re-derived one are the same value or they are
      not;
    * a `Revocation` is appended to `revocations` under the ref it names.
      Nothing is decided here: §5 clause 3 asks
      `matches(e.actor, R.actor, R.seq)` of each at query time, because a
      Revocation by a stranger withdraws nothing and must still be
      visible (it is the verifier's `revocation-actor` finding);
    * a `Succession` appends an edge, and a `Revocation` naming a
      Succession stamps that edge's `revoked_at` — **the first one only**.
      §5 clause 3's rule that the earliest qualifying Revocation is the
      one that took effect applies to an edge as much as to an
      endorsement: a later duplicate withdraws nothing that is already
      withdrawn and must not move the position the edge died at.
  """
  @spec observe(map(), map(), map()) :: map()
  def observe(index, event, payload) do
    if payload["outcome"] == "admitted",
      do: observe_granted(index, event, payload, path(payload)),
      else: index
  end

  defp observe_granted(index, event, payload, path) do
    cond do
      authority_kind?(path) ->
        put_in(index, [:events, ref(event)], record(event, payload))

      path == @succession ->
        Map.update!(index, :edges, &(&1 ++ [edge(event, payload)]))

      path == @revocation ->
        index |> revoke_edge(event, payload) |> add_revocation(event, payload)

      true ->
        index
    end
  end

  defp add_revocation(index, event, payload) do
    case dig(payload, ["spec", "revokes", "$ref"]) do
      target when is_binary(target) ->
        entry = %{seq: event["seq"], actor: dig(payload, ["actor", "id"]), ref: ref(event)}

        update_in(
          index,
          [:revocations],
          &Map.update(&1, target, [entry], fn l -> l ++ [entry] end)
        )

      _ ->
        index
    end
  end

  defp revoke_edge(index, event, payload) do
    revoked = dig(payload, ["spec", "revokes", "$ref"])

    Map.update!(index, :edges, fn edges ->
      Enum.map(edges, fn
        %{ref: ^revoked, revoked_at: nil} = edge -> %{edge | revoked_at: event["seq"]}
        edge -> edge
      end)
    end)
  end

  defp edge(event, payload) do
    spec = object(payload["spec"])

    %{
      ref: ref(event),
      seq: event["seq"],
      predecessor: spec["predecessor"],
      successor: spec["successor"],
      revoked_at: nil
    }
  end

  @doc """
  Build the index every question is asked of, from `[{event, payload}]` in
  chain order — the fold of `observe/3` from `empty/0`.
  """
  @spec build([{map(), map()}]) :: map()
  def build(decoded) do
    Enum.reduce(decoded, empty(), fn {e, p}, index -> observe(index, e, p) end)
  end

  defp path(payload) do
    t = object(payload["target"])
    "#{text(t["group"])}/#{text(t["version"])}/#{text(t["kind"])}"
  end

  defp ref(event), do: "event:" <> text(event["hash"])

  # A bundle is a file: a key read as an object may hold anything, and
  # reading through one that is not an object answers "nothing recorded"
  # (spec/07 §2.6). Rendering one into a sentence is `text/1`, the same
  # section's other half.
  defp object(value) when is_map(value), do: value
  defp object(_value), do: %{}

  # §5's link shape, exactly the thirteen fields — re-derived here from the
  # event, which is what `resolvedAuthority` is compared against.
  defp record(event, payload) do
    spec = object(payload["spec"])

    %{
      "value" => ref(event),
      "kind" => path(payload),
      "seq" => event["seq"],
      "actor" => dig(payload, ["actor", "id"]),
      "subject" => spec["subject"],
      "role" => spec["role"],
      "scope" => spec["scope"],
      "kinds" => normal_form(spec["kinds"]),
      "mayIssue" => spec["mayIssue"] == true,
      "notBefore" => spec["notBefore"],
      "notAfter" => spec["notAfter"],
      "parent" => dig(spec, ["parent", "$ref"]),
      "depth" => payload["depth"]
    }
  end

  # -- §5's `kinds` lattice ----------------------------------------------

  @doc "§5's normal form: deduplicated, sorted, exactly `[\"*\"]` when `*` is present."
  @spec normal_form(term()) :: [String.t()]
  def normal_form(kinds) when is_list(kinds) do
    kinds = kinds |> Enum.filter(&is_binary/1) |> Enum.uniq() |> Enum.sort()
    if "*" in kinds, do: ["*"], else: kinds
  end

  def normal_form(_kinds), do: []

  @doc "§5's `⊆` with `*` as top."
  @spec covered?(term(), term()) :: boolean()
  def covered?(narrow, wide) do
    wide = normal_form(wide)
    wide == ["*"] or MapSet.subset?(MapSet.new(normal_form(narrow)), MapSet.new(wide))
  end

  # -- §0's relation ------------------------------------------------------

  @doc "§0's `matches(a, b, s)` — a is b, or an ancestor of b."
  @spec matches(map(), String.t() | nil, String.t() | nil, integer()) :: boolean()
  def matches(_index, a, b, _s) when a == b and a != nil, do: true
  def matches(_index, nil, _b, _s), do: false
  def matches(_index, _a, nil, _s), do: false
  def matches(index, a, b, s), do: a in ancestors(index, b, s)

  @doc "§0's `pred*(k, s)`."
  @spec ancestors(map(), String.t(), integer()) :: [String.t()]
  def ancestors(index, key, s), do: walk_path(index, key, s, :up, [])

  @doc "§0's `head(k, s)`: the terminal successor."
  @spec head(map(), String.t(), integer()) :: String.t()
  def head(index, key, s) do
    case walk_path(index, key, s, :down, []) do
      [] -> key
      path -> List.last(path)
    end
  end

  @doc "Live edges as of `s` (§0: admitted, unrevoked as of s, at seq < s)."
  @spec edges_at(map(), integer()) :: [map()]
  def edges_at(index, s) do
    Enum.filter(index.edges, fn e ->
      e.seq < s and (e.revoked_at == nil or e.revoked_at >= s)
    end)
  end

  defp walk_path(index, key, s, direction, seen) do
    edges = edges_at(index, s)

    next =
      case direction do
        :up -> Enum.find_value(edges, &if(&1.successor == key, do: &1.predecessor))
        :down -> Enum.find_value(edges, &if(&1.predecessor == key, do: &1.successor))
      end

    cond do
      next == nil -> Enum.reverse(seen)
      next in seen -> Enum.reverse(seen)
      true -> walk_path(index, next, s, direction, [next | seen])
    end
  end

  @doc """
  §0's four shape rules, asked of a proposed edge. `:ok`, or
  `{:error, reason}` carrying one of the contract's four `resolve:`
  reasons.

  They are what keeps the relation a set of **disjoint simple paths**, so
  that `head(k, s)` is a single key and not a choice — which is the whole
  point of the Kind: a reader can say who speaks for a former self
  without guessing.

  The order is §0's listing order, and it decides one case: a key naming
  *itself* as its successor when it already has a live outgoing edge
  earns `succession slot taken`, not `self succession`. Both sentences
  are true of that request, and the first is the one the submitter can
  act on.
  """
  @spec check_edge(map(), String.t() | nil, String.t() | nil, integer()) ::
          :ok | {:error, String.t()}
  def check_edge(index, predecessor, successor, s) do
    edges = edges_at(index, s)

    cond do
      Enum.any?(edges, &(&1.predecessor == predecessor)) ->
        {:error, "succession slot taken"}

      Enum.any?(edges, &(&1.successor == successor)) ->
        {:error, "successor already succeeded"}

      predecessor == successor ->
        {:error, "self succession"}

      successor in ancestors(index, predecessor, s) ->
        {:error, "succession cycle"}

      true ->
        :ok
    end
  end

  @doc """
  §9's `contested-succession`: a predecessor with a revoked edge **and a
  later one** — an edge admitted after the revocation that withdrew the
  first. The verifier prints it; the kernel does not refuse it, because a
  stolen key and its rightful holder both leave a record and the record is
  what the endorsers read.

  "Later" is against the **revocation's** seq and not merely the count of
  edges: a predecessor with two edges of which the second was itself
  revoked, or whose second edge predates the revocation of the first, has
  not renamed a successor after withdrawing one. Counting edges reported
  the shape §9 names *and* shapes it does not.
  """
  @spec contested(map()) :: [map()]
  def contested(index) do
    index.edges
    |> Enum.group_by(& &1.predecessor)
    |> Enum.filter(fn {_key, edges} -> contested?(edges) end)
    |> Enum.map(fn {key, edges} -> %{key: key, edges: Enum.sort_by(edges, & &1.seq)} end)
    |> Enum.sort_by(& &1.key)
  end

  defp contested?(edges) do
    Enum.any?(edges, fn revoked ->
      revoked.revoked_at != nil and Enum.any?(edges, &(&1.seq > revoked.revoked_at))
    end)
  end

  # -- §5's walk ----------------------------------------------------------

  @doc """
  §5's `effective(E, s, ∅)` at the citing event's position and timestamp.
  Returns `%{ok:, reason:, root:, visited:}`.
  """
  @spec effective(map(), String.t(), integer(), String.t() | nil) :: map()
  def effective(index, ref, s, ts) do
    {result, _memo} = walk(index, ref, s, ts, MapSet.new(), %{})
    result
  end

  defp walk(index, ref, s, ts, seen, memo) do
    cond do
      Map.has_key?(memo, ref) ->
        {memo[ref], memo}

      MapSet.member?(seen, ref) ->
        {deny("cycle", [ref]), memo}

      true ->
        {result, memo} = clauses(index, ref, s, ts, seen, memo)
        {result, Map.put(memo, ref, result)}
    end
  end

  defp clauses(index, ref, s, ts, seen, memo) do
    e = index.events[ref]

    cond do
      e == nil or e["seq"] >= s ->
        {deny("not an authority event", [ref]), memo}

      (r = revocation(index, ref, s, e)) != nil ->
        {deny("revoked at #{text(r.seq)}", [ref]), memo}

      not in_term?(e, ts) ->
        {deny("out of term", [ref]), memo}

      e["parent"] == nil ->
        {ok("root " <> text(e["actor"]), e["actor"], [ref]), memo}

      true ->
        parent_clauses(index, ref, e, s, ts, seen, memo)
    end
  end

  defp parent_clauses(index, ref, e, s, ts, seen, memo) do
    parent_ref = e["parent"]
    p = index.events[parent_ref]

    case p && clause_seven(index, e, p) do
      {:error, reason} ->
        {deny(reason, [ref]), memo}

      _ ->
        {parent, memo} = walk(index, parent_ref, s, ts, MapSet.put(seen, ref), memo)
        visited = [ref | parent.visited]

        if parent.ok,
          do: {ok("chain to root " <> text(parent.root), parent.root, visited), memo},
          else: {deny("parent: " <> parent.reason, visited), memo}
    end
  end

  defp clause_seven(index, e, p) do
    cond do
      not matches(index, p["subject"], e["actor"], e["seq"]) -> {:error, "parent subject"}
      not p["mayIssue"] -> {:error, "parent may not issue"}
      not covered?(e["kinds"], p["kinds"]) -> {:error, "kinds exceed parent"}
      not term_within?(e, p) -> {:error, "term exceeds parent"}
      true -> :ok
    end
  end

  @doc """
  The Revocation that withdrew `ref` before `s`, or `nil` — §5 clause 3's
  `matches(e.actor, R.actor, R.seq)`. A Revocation by anyone else
  withdraws nothing, and is the `revocation-actor` finding.
  """
  @spec revocation(map(), String.t(), integer(), map()) :: map() | nil
  def revocation(index, ref, s, e) do
    index.revocations
    |> Map.get(ref, [])
    |> Enum.filter(&(&1.seq < s and matches(index, e["actor"], &1.actor, &1.seq)))
    |> Enum.min_by(& &1.seq, fn -> nil end)
  end

  @doc """
  §5 clause 4: is `ts` inside the link's term?

  `ts` is a **string** — the instant the record carries. The kernel asks
  with `ts(s)`, the second-truncated instant it is about to write; the
  verifier asks with the `ts` the citing event already carries. Either
  way the comparison is against what the chain says, never against a
  clock at a higher resolution than the record has.
  """
  @spec in_term?(map(), term()) :: boolean()
  def in_term?(e, ts) do
    case {RecurseVerify.Instant.compare(e["notBefore"], ts),
          RecurseVerify.Instant.compare(ts, e["notAfter"])} do
      {{:ok, from}, {:ok, to}} -> from in [:lt, :eq] and to in [:lt, :eq]
      _ -> false
    end
  end

  @doc "§5's greatest issuance depth."
  @spec max_depth() :: pos_integer()
  def max_depth, do: 16

  @doc """
  The depth recorded on a link, for the cap.

  A link admitted before `depth` existed, or by a producer that omitted
  it, counts as 0. The cap is the *record's*, so a link with no recorded
  depth cannot deepen a chain it never joined; refusing to issue under it
  instead would make a chain's admissibility depend on when its root
  happened to be written.
  """
  @spec depth_of(map() | nil) :: non_neg_integer()
  def depth_of(%{"depth" => depth}) when is_integer(depth), do: depth
  def depth_of(_record), do: 0

  @doc """
  §5's `resolvedAuthority` chain for a cited ref: that event first, each
  link exactly the thirteen fields §5 lists, up to the root.

  The kernel writes it onto the payload; the verifier re-derives it from
  the bundle and compares. One function, so "the chain the producer wrote
  down" and "the chain this bundle supports" are the same expression
  evaluated over two indexes.
  """
  @spec links(map(), String.t() | nil) :: [map()]
  def links(index, ref), do: links(index, ref, MapSet.new(), [])

  defp links(_index, nil, _seen, acc), do: Enum.reverse(acc)

  defp links(index, ref, seen, acc) do
    case index.events[ref] do
      nil ->
        Enum.reverse(acc)

      record ->
        if MapSet.member?(seen, ref),
          do: Enum.reverse(acc),
          else: links(index, record["parent"], MapSet.put(seen, ref), [record | acc])
    end
  end

  @doc """
  §5's `term(e) ⊆ term(p)`: the child starts no earlier and ends no later.

  An unparseable end of either term is not a subset — a term nobody can
  compare narrows nothing.
  """
  @spec term_within?(map(), map()) :: boolean()
  def term_within?(e, p) do
    case {RecurseVerify.Instant.compare(e["notBefore"], p["notBefore"]),
          RecurseVerify.Instant.compare(e["notAfter"], p["notAfter"])} do
      {{:ok, from}, {:ok, to}} -> from in [:gt, :eq] and to in [:lt, :eq]
      _ -> false
    end
  end

  defp ok(reason, root, visited), do: %{ok: true, reason: reason, root: root, visited: visited}
  defp deny(reason, visited), do: %{ok: false, reason: reason, root: nil, visited: visited}
end
