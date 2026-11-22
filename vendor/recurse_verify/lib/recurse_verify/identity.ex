defmodule RecurseVerify.Identity do
  @moduledoc """
  Spec 011 §9: the three identity lines, their counts, and the findings
  that go with them.

  Three questions, and they are separate on purpose:

    * **signatures** — is every admission signed, and does every signature
      verify with the key on its own payload? And does the *decoded
      request* say the same thing the record says (§1's projection
      invariant)? A signature over some bytes proves nothing until the
      bytes are shown to be the act beside them.
    * **endorsements** — every `resolvedAuthority` link re-derived from the
      bundle and compared, and the walk re-executed at the citing event's
      own position. The producer's account of a derivation is a claim; the
      derivation is a fact.
    * **identities** — who published a profile, who acted under a badge,
      and who did the second without the first. That last count is the one
      the Charter cares about, and it is computed **regardless of the
      declared `subjectKind`**, because the issuer must not hold the switch
      for the check that watches issuers.

  ## What the counts mean

  `T`, `A` and `C` count **granted** admissions only. A denial resolved
  nothing and endorsed nobody; counting it would make a chain look busier
  the more it refused. `U` is payloads carrying no `identity` field at all
  — the legacy definition, and the only one: absence is the marker, and a
  defaulted `"unsigned"` would erase the difference between a chain that
  predates signatures and one that stopped using them.
  """

  import RecurseVerify.Value, only: [dig: 2, q: 1, text: 1]

  alias RecurseVerify.Authority
  alias RecurseVerify.Trust

  @subject_kinds ~w(person agent org instrument service)
  @badge "core.r5e.io/v1/Badge"
  @principal "core.r5e.io/v1/Principal"
  @deployment "core.r5e.io/v1/Deployment"
  @request_type "application/vnd.r5e.admission-request+json;v=1"

  @doc "Whether this bundle carries an admitted Badge instance (§9: what makes `--posture` required)."
  @spec badge_present?([{map(), map()}]) :: boolean()
  def badge_present?(decoded) do
    Enum.any?(decoded, fn {_e, p} -> p["outcome"] == "admitted" and path(p) == @badge end)
  end

  # -- signatures (§9) ----------------------------------------------------

  @doc """
  `{line, findings, counts}` for §9's `signatures:` line.

  Every signature on every `identity: signed` payload is verified against
  the `publicKeys` recorded on that same payload — which proves the
  envelope is internally consistent, and **not** that the key belongs to
  anyone. That second thing is what the endorsement lines and the reader's
  own pins are for, and the not-checked block says so.
  """
  @spec check_signatures([{map(), map()}]) :: {String.t(), [String.t()], map()}
  def check_signatures(decoded) do
    granted = for {e, p} <- decoded, p["outcome"] == "admitted", do: {e, p}
    t = length(granted)
    u = Enum.count(decoded, fn {_e, p} -> not Map.has_key?(p, "identity") end)

    results =
      for {event, payload} <- granted,
          Map.has_key?(payload, "identity"),
          do: {event, payload, verify_one(payload)}

    s = Enum.count(results, fn {_e, _p, r} -> r == :ok end)

    findings =
      for {event, _payload, {:error, reason}} <- results,
          do: finding(event, "signature", reason)

    projection =
      for {event, payload} <- granted,
          Map.has_key?(payload, "identity"),
          reason <- projection_problems(payload),
          do: finding(event, "projection", reason)

    line =
      "signatures: #{s} of #{t} admissions signed and verified with the keys on their " <>
        "payloads; #{u} legacy unsigned"

    {line, findings ++ projection, %{signed: s, admissions: t, legacy: u}}
  end

  # Every signature, against the `publicKeys` on the payload's own
  # `signed` envelope. A signature that does not verify is the whole
  # record's problem, not one signer's, so the first failure names itself
  # and stops.
  defp verify_one(payload) do
    envelope = payload["signed"]

    with true <- is_map(envelope) or {:error, "carries identity but no signed envelope"},
         type = envelope["payloadType"] || @request_type,
         true <- is_binary(type) or {:error, "the recorded payloadType is not a string"},
         {:ok, bytes} <- decode64(envelope["payload"], "payload"),
         signatures = envelope["signatures"] || [],
         true <- is_list(signatures) or {:error, "the recorded signatures are not a list"},
         keys = public_keys(envelope["publicKeys"]),
         message = RecurseVerify.DSSE.pae(type, bytes) do
      Enum.reduce_while(signatures, :ok, fn sig, _ ->
        case verify_signature(sig, keys, message) do
          :ok -> {:cont, :ok}
          error -> {:halt, error}
        end
      end)
    else
      {:error, _} = error -> error
      _ -> {:error, "the signed envelope is not readable"}
    end
  end

  defp verify_signature(%{"keyid" => keyid, "sig" => sig}, keys, message) do
    with {:ok, signature} <- decode64(sig, "signature"),
         key when is_binary(key) <- Map.get(keys, keyid) do
      if RecurseVerify.DSSE.verify_ed25519(message, signature, key),
        do: :ok,
        else:
          {:error, "the signature by #{text(keyid)} does not verify over the recorded payload"}
    else
      nil -> {:error, "no recorded publicKeys entry for signer #{text(keyid)}"}
      error -> error
    end
  end

  defp verify_signature(_sig, _keys, _message), do: {:error, "a malformed signatures entry"}

  defp public_keys(list) when is_list(list) do
    for %{"keyid" => id, "bytes" => b64} <- list,
        is_binary(b64),
        {:ok, bytes} <- [Base.decode64(b64)],
        into: %{},
        do: {id, bytes}
  end

  defp public_keys(_other), do: %{}

  defp decode64(value, what) when is_binary(value) do
    case Base.decode64(value) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, "the recorded #{what} is not base64"}
    end
  end

  defp decode64(_value, what), do: {:error, "the recorded #{what} is missing"}

  # §1's projection invariant: the decoded request and the recorded fields
  # are the same act. This is the check that turns "a key signed some
  # bytes" into "a key signed *this*" — without it, a hostile producer can
  # keep a valid signature over a harmless request and record something
  # else beside it, and both the signature and the hash chain still check.
  @doc "The §1 projection problems on one payload, as prose. `[]` when it projects."
  @spec projection_problems(map()) :: [String.t()]
  def projection_problems(payload) do
    with envelope when is_map(envelope) <- payload["signed"],
         {:ok, bytes} <- decode64(envelope["payload"], "payload"),
         {:ok, request} <- RecurseVerify.Canonical.decode_json(bytes) do
      compare_projection(request, payload)
    else
      _ -> ["the signed request cannot be decoded, so nothing about it can be projected"]
    end
  end

  defp compare_projection(request, payload) do
    spec_address =
      if is_map(payload["spec"]) or is_list(payload["spec"]),
        do: RecurseVerify.Canonical.address(payload["spec"]),
        else: nil

    checks = [
      {"origin", request["origin"], payload["origin"]},
      {"actor.id", request["actor"], dig(payload, ["actor", "id"])},
      {"submittedTarget", request["target"], payload["submittedTarget"]},
      {"derivedFrom", request["derivedFrom"], payload["derivedFrom"]},
      {"authority", request["authority"], payload["authority"]},
      {"nonce", request["nonce"], payload["nonce"]},
      {"expires", request["expires"], payload["expires"]}
    ]

    mismatches =
      for {field, signed, recorded} <- checks,
          signed != recorded,
          do:
            "the signed request's #{field} is #{q(signed)} and the record says " <>
              q(recorded)

    spec_mismatch =
      if spec_address != nil and request["specAddress"] != spec_address do
        [
          "the signed request covers specAddress #{q(request["specAddress"])} and the " <>
            "recorded spec hashes to #{q(spec_address)}"
        ]
      else
        []
      end

    mismatches ++ spec_mismatch ++ target_projection(payload)
  end

  # The effective `target` is `submittedTarget` with the kernel's naming
  # applied, so the group/version/Kind must be identical and a name the
  # caller supplied must survive. A name the *kernel* assigned (content,
  # server) is not re-derivable from the payload alone and is stated as
  # not-checked rather than guessed at.
  defp target_projection(payload) do
    submitted = object(payload["submittedTarget"])
    effective = object(payload["target"])

    identity_mismatch =
      for field <- ~w(group version kind),
          submitted[field] != effective[field],
          do:
            "the signed target's #{field} is #{q(submitted[field])} and the effective " <>
              "target's is #{q(effective[field])}"

    name_mismatch =
      if is_binary(submitted["name"]) and submitted["name"] != effective["name"] do
        [
          "the signed target names #{q(submitted["name"])} and the admission was " <>
            "recorded under #{q(effective["name"])}"
        ]
      else
        []
      end

    identity_mismatch ++ name_mismatch
  end

  # -- endorsements (§9) --------------------------------------------------

  @doc """
  `{line, findings, counts}` for §9's `endorsements:` line.

  Every cited authority is re-walked **at the citing event's own seq and
  timestamp**, and every `resolvedAuthority` link is re-derived from the
  bundle and compared field by field. The producer wrote the chain down;
  this is where writing it down stops being enough.
  """
  @spec check_endorsements([{map(), map()}], [map()]) :: {String.t(), [String.t()], map()}
  def check_endorsements(decoded, pins) do
    index = Authority.build(decoded)
    granted = for {e, p} <- decoded, p["outcome"] == "admitted", do: {e, p}

    citing =
      for {event, payload} <- granted,
          entries = list(payload["resolvedAuthority"]),
          refs = list(payload["authority"]),
          refs != [] or entries != [],
          do: {event, payload, refs, entries}

    results = Enum.flat_map(citing, &check_citation(&1, index, pins))

    c = length(results)
    a = length(citing)
    resolved = Enum.count(results, & &1.pinned)
    cut = Enum.filter(results, &(not &1.ok))
    findings = Enum.flat_map(results, & &1.findings) ++ contested_findings(index)

    line =
      "endorsements: #{c} chains cited across #{a} admissions; #{resolved} resolved to a " <>
        "pinned root; #{length(cut)} cut#{first_cut(cut)}"

    {line, findings, %{chains: c, citing: a, resolved: resolved, cut: length(cut)}}
  end

  @doc """
  §9/§11's two **conditional** not-checked lines: what this verifier does
  not check about a bundle that carries the thing in question.

  Both follow the discipline §9 already applies to the two legacy identity
  lines, which print only when `U > 0`: a not-checked line is printed when
  it is *about* something in this bundle. A block that listed every gap in
  every checker on every run would be read by nobody, and the ones that
  matter would be the ones lost in it.
  """
  @spec conditional_not_checked([{map(), map()}]) :: [String.t()]
  def conditional_not_checked(decoded) do
    admitted = for {_e, p} <- decoded, p["outcome"] == "admitted", do: path(p)

    succession =
      if "core.r5e.io/v1/Succession" in admitted do
        [
          "revocation of a Succession is not checked against the rule §0 applies to every other " <>
            "withdrawal (matches(target.actor, revoker, R.seq)): an edge is treated as revoked " <>
            "by any Revocation naming it. On a bundle somebody assembled, a Revocation of a " <>
            "Succession that no kernel would have admitted therefore removes the edge -- which " <>
            "can cut an authority chain that should stand, and can **suppress** the " <>
            "revocation-actor finding on a genuine later withdrawal whose validity depended on " <>
            "that edge. A chain this kernel wrote cannot contain one (resolve: sameActor refuses " <>
            "it); a bundle can"
        ]
      else
        []
      end

    shape =
      if Enum.any?(admitted, &String.ends_with?(&1, "/PolicyShape")) do
        [
          "a PolicyShape citing a retired envelope field is refused by the **policy engine** at " <>
            "authorize and not by the kernel (spec/06 §11): the envelope grammar belongs to the " <>
            "engine, and the kernel does not interpret a shape's paths. On a deployment running " <>
            "no engine, or one that does not implement the grammar, such a shape is admitted and " <>
            "the stale-shape finding is the only signal there is"
        ]
      else
        []
      end

    succession ++ shape
  end

  @doc """
  §9's succession sentence, as not-checked lines: for every root this
  bundle's cited chains resolve to that has itself been **succeeded** on
  this same bundle,

      root succeeded at seq n by <key>; not trusted unless pinned

  A pin names a key, not a principal. Letting succession extend the
  reader's trust would let the bundle enlarge the set of keys the reader
  trusts, which is the one direction a reader can never audit — so the
  verifier does not follow it, and says so rather than leaving the reader
  to notice. A reader who accepts the succession pins the successor too.
  """
  @spec succeeded_roots([{map(), map()}]) :: [String.t()]
  def succeeded_roots(decoded) do
    index = Authority.build(decoded)
    tip = 1 + Enum.reduce(decoded, 0, fn {e, _p}, acc -> max(acc, e["seq"] || 0) end)

    roots =
      for {event, payload} <- decoded,
          payload["outcome"] == "admitted",
          ref <- list(payload["authority"]),
          walk = Authority.effective(index, ref, event["seq"], event["ts"]),
          walk.root != nil,
          do: walk.root

    for root <- roots |> Enum.uniq() |> Enum.sort(),
        edge = Enum.find(Authority.edges_at(index, tip), &(&1.predecessor == root)) do
      "root succeeded at seq #{text(edge.seq)} by #{text(edge.successor)}; not trusted unless pinned"
    end
  end

  defp first_cut([]), do: ""

  defp first_cut(cut) do
    first = Enum.min_by(cut, & &1.seq)
    " (first at seq #{text(first.seq)} by #{text(first.ref)})"
  end

  defp check_citation({event, payload, refs, entries}, index, pins) do
    s = event["seq"]
    ts = event["ts"]
    actor = dig(payload, ["actor", "id"])
    kind_path = path(payload)

    for {ref, i} <- Enum.with_index(refs) do
      record = index.events[ref]
      walk = Authority.effective(index, ref, s, ts)
      entry = Enum.find(entries, &(dig(&1, ["index"]) == i)) || %{}

      findings =
        subject_findings(event, index, record, ref, actor, s) ++
          ineffective_findings(event, walk, ref) ++
          kind_findings(event, record, ref, kind_path) ++
          chain_findings(event, index, ref, entry) ++
          revocation_findings(event, index, record, ref)

      root = walk.root

      %{
        seq: s,
        ref: ref,
        ok: walk.ok,
        pinned: walk.ok and match?({true, _}, Trust.admits(pins, root, kind_path, ts)),
        root: root,
        findings: findings
      }
    end
  end

  defp subject_findings(event, index, record, ref, actor, s) do
    if record && not Authority.matches(index, record["subject"], actor, s) do
      [
        finding(
          event,
          "authority-subject",
          "cites #{text(ref)}, which endorses #{q(record["subject"])} and not the acting key " <>
            "#{q(actor)} or a key it succeeded"
        )
      ]
    else
      []
    end
  end

  defp ineffective_findings(event, walk, ref) do
    if walk.ok,
      do: [],
      else: [finding(event, "authority-ineffective", "cites #{text(ref)}: #{walk.reason}")]
  end

  defp kind_findings(event, record, ref, kind_path) do
    if record && not Authority.covered?([kind_path], record["kinds"]) do
      [
        finding(
          event,
          "kind-outside-authority",
          "cites #{text(ref)}, which covers #{q(record["kinds"])}, for an act of #{kind_path}"
        )
      ]
    else
      []
    end
  end

  # §5: the recorded chain is compared link by link against the one this
  # bundle produces. A producer that recorded a chain the bundle does not
  # support has written down a derivation nobody can repeat.
  defp chain_findings(event, index, ref, entry) do
    derived = Authority.links(index, ref)
    recorded = entry["chain"]

    cond do
      recorded == nil ->
        [
          finding(
            event,
            "projection",
            "cites #{text(ref)} and records no resolvedAuthority chain for it"
          )
        ]

      recorded == derived ->
        []

      true ->
        [
          finding(
            event,
            "projection",
            "records a resolvedAuthority chain for #{text(ref)} that this bundle does not derive " <>
              "(#{length(recorded)} link(s) recorded, #{length(derived)} re-derived)"
          )
        ]
    end
  end

  # A Revocation by a key that is not the target's actor (nor a key that
  # actor succeeded) withdraws nothing. The kernel refuses it at
  # `resolve: sameActor`; one injected into a bundle is this finding, and
  # the chain stays effective — which is the point of reporting it rather
  # than acting on it.
  defp revocation_findings(event, index, record, ref) do
    if record == nil do
      []
    else
      for r <- Map.get(index.revocations, ref, []),
          not Authority.matches(index, record["actor"], r.actor, r.seq),
          do:
            finding(
              event,
              "revocation-actor",
              "the Revocation at seq #{text(r.seq)} purports to withdraw #{text(ref)}, whose actor of " <>
                "record is #{q(record["actor"])}, and was made by #{q(r.actor)}; " <>
                "it withdraws nothing and the chain stays effective"
            )
    end
  end

  defp contested_findings(index) do
    for %{key: key, edges: edges} <- Authority.contested(index) do
      later = Enum.find(edges, &(&1.revoked_at == nil))

      "contested-succession: #{text(key)} has a revoked Succession and a later one" <>
        if(later,
          do:
            " (at seq #{text(later.seq)}); which continuation speaks for it is the reader's " <>
              "question, and the record is what they read",
          else: ""
        )
    end
  end

  # -- identities (§9) ----------------------------------------------------

  @doc """
  `{line, findings, counts}` for §9's `identities:` line, plus
  `badge-only-person` under a `commons` posture.
  """
  @spec check_identities([{map(), map()}], String.t() | nil) :: {String.t(), [String.t()], map()}
  def check_identities(decoded, posture) do
    granted = for {e, p} <- decoded, p["outcome"] == "admitted", do: {e, p}

    profiles = self_profiles(granted)
    badge_users = badge_users(granted)
    badge_only = badge_only(granted, profiles, badge_users)
    composition = composition(granted, badge_only)

    line =
      "identities: #{MapSet.size(profiles)} keys with self profiles; " <>
        "#{MapSet.size(badge_users)} keys acting under badges; #{MapSet.size(badge_only)} keys " <>
        "acting only under badges with no self profile; badge-only keys by declared kind: " <>
        composition_text(composition) <>
        "; deployment declaration: " <>
        declaration(granted) <> "; reader posture: " <> (posture || "not stated")

    findings =
      if posture == "commons" and MapSet.size(badge_only) > 0 do
        [
          "badge-only-person: #{MapSet.size(badge_only)} key(s) act only under badges and " <>
            "publish no profile of their own — on a deployment that governs people's " <>
            "participation in the world, that is a principal who cannot speak for themselves " <>
            "(" <> Enum.map_join(Enum.sort(MapSet.to_list(badge_only)), ", ", &text/1) <> ")"
        ]
      else
        []
      end

    {line, findings,
     %{
       profiles: MapSet.size(profiles),
       badge_users: MapSet.size(badge_users),
       badge_only: MapSet.size(badge_only)
     }}
  end

  # A **self** profile: a Principal whose `key` is the key that admitted
  # it. Anything else is somebody's account of somebody, and §9 counts
  # only keys that have spoken for themselves.
  defp self_profiles(granted) do
    for {_e, p} <- granted,
        path(p) == @principal,
        dig(p, ["spec", "key"]) == dig(p, ["actor", "id"]),
        into: MapSet.new(),
        do: dig(p, ["actor", "id"])
  end

  defp badge_users(granted) do
    for {_e, p} <- granted,
        cites_badge?(p),
        into: MapSet.new(),
        do: dig(p, ["actor", "id"])
  end

  defp cites_badge?(payload) do
    Enum.any?(list(payload["resolvedAuthority"]), fn entry ->
      case dig(entry, ["chain"]) do
        [first | _] -> first["kind"] == @badge
        _ -> false
      end
    end)
  end

  # §9: keys in `B` with no self profile **whose every signed act cites a
  # badge**. A key that has acted once as itself is not badge-only, however
  # many badges it holds.
  defp badge_only(granted, profiles, badge_users) do
    signed_acts =
      granted
      |> Enum.filter(fn {_e, p} -> Map.has_key?(p, "identity") end)
      |> Enum.group_by(fn {_e, p} -> dig(p, ["actor", "id"]) end)

    for key <- badge_users,
        not MapSet.member?(profiles, key),
        acts = Map.get(signed_acts, key, []),
        acts != [],
        Enum.all?(acts, fn {_e, p} -> cites_badge?(p) end),
        into: MapSet.new(),
        do: key
  end

  # §9: printed **regardless of the declared `subjectKind`** — the issuer
  # must not hold the switch for the check that watches issuers. A key
  # whose badges disagree with each other is `mixed`, which is itself
  # worth seeing.
  defp composition(granted, badge_only) do
    kinds_by_key =
      Enum.reduce(granted, %{}, fn {_e, p}, acc ->
        if path(p) == @badge do
          Map.update(
            acc,
            dig(p, ["spec", "subject"]),
            MapSet.new([dig(p, ["spec", "subjectKind"])]),
            &MapSet.put(&1, dig(p, ["spec", "subjectKind"]))
          )
        else
          acc
        end
      end)

    # Six buckets and no others, and every key in `H` lands in exactly
    # one of them, so the buckets sum to `H` and a reader can check the
    # line against itself. `mixed` is therefore "not exactly one of the
    # five": badges that disagree, a `subjectKind` outside the five, a
    # null one, and a key whose badges are cited by this chain but whose
    # Badge admissions are not in this bundle. A bucket the issuer could
    # empty by declaring something the verifier does not print would
    # hand the issuer the switch for the check that watches issuers.
    Enum.reduce(badge_only, Map.new(@subject_kinds ++ ["mixed"], &{&1, 0}), fn key, acc ->
      case MapSet.to_list(Map.get(kinds_by_key, key, MapSet.new())) do
        [one] when one in @subject_kinds -> Map.update!(acc, one, &(&1 + 1))
        _other -> Map.update!(acc, "mixed", &(&1 + 1))
      end
    end)
  end

  defp composition_text(composition) do
    (@subject_kinds ++ ["mixed"])
    |> Enum.map(&"#{&1} #{Map.get(composition, &1, 0)}")
    |> Enum.join(", ")
  end

  # §9: printed beside the identities line and deciding nothing. The
  # reader's posture is the reader's; a deployment saying it is a house
  # does not make badge-only persons unremarkable.
  defp declaration(granted) do
    case Enum.find(granted, fn {_e, p} -> path(p) == @deployment end) do
      nil ->
        "none"

      {event, payload} ->
        "commons=#{q(dig(payload, ["spec", "commons"]))} by " <>
          "#{text(dig(payload, ["actor", "id"]))} at seq #{text(event["seq"])}"
    end
  end

  # -- shapes -------------------------------------------------------------

  @doc """
  KS-7: `actor.keyFingerprint` is retired. A shape admitted before the
  retirement still cites it, and a policy engine reading it would be
  reading a field the kernel no longer supplies — so it is reported rather
  than left to be discovered at evaluation time.
  """
  @spec check_shapes([{map(), map()}]) :: [String.t()]
  def check_shapes(decoded) do
    for {event, payload} <- decoded,
        payload["outcome"] == "admitted",
        String.ends_with?(path(payload), "/PolicyShape"),
        cites_key_fingerprint?(payload["spec"]),
        do:
          finding(
            event,
            "stale-shape",
            "an admitted PolicyShape cites the retired envelope field actor.keyFingerprint (KS-7)"
          )
  end

  # §11 (KS-7): `actor.keyFingerprint` is removed from the envelope-field
  # grammar. What makes a shape *stale* is **using** it — so the check is
  # over §8's five path-valued slots and not over the whole spec. A
  # `description` explaining the removal is documentation, and a
  # substring search over the encoded spec made that read as a use of it.
  defp cites_key_fingerprint?(spec) when is_map(spec),
    do: Enum.any?(shape_slots(spec), &(&1 == "@actor.keyFingerprint"))

  defp cites_key_fingerprint?(_spec), do: false

  defp shape_slots(spec) do
    context =
      case spec["context"] do
        map when is_map(map) -> for {_key, entry} <- map, is_map(entry), do: entry["path"]
        _ -> []
      end

    [spec["action"], spec["resourceType"], spec["resourceId"] | context]
    |> Enum.filter(&is_binary/1)
  end

  # -- shared -------------------------------------------------------------

  defp path(payload) do
    t = object(payload["target"])
    "#{text(t["group"])}/#{text(t["version"])}/#{text(t["kind"])}"
  end

  # A bundle is a file: a key this codebase reads as an object may hold
  # anything at all. Reading through one that is not an object answers
  # "nothing recorded" (spec/07 §2.6), which is what every check here
  # then reports.
  defp object(value) when is_map(value), do: value
  defp object(_value), do: %{}

  # And the same for a key this codebase reads as a list.
  defp list(value) when is_list(value), do: value
  defp list(_value), do: []

  defp finding(event, code, prose), do: "#{code}: seq #{text(event["seq"])} -- #{prose}"
end
