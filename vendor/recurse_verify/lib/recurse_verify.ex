defmodule RecurseVerify do
  @moduledoc """
  Offline verification of an r5e export bundle. Runs against a bundle
  directory with no connection to any r5e deployment.

  Output doctrine (README.md beside this project — normative): the
  verifier never prints a bare "valid". It prints what was checked and
  what was not; tampering and gaps are findings, and honesty about what
  it cannot establish is what makes the rest worth anything.
  """

  import RecurseVerify.Value, only: [dig: 2, q: 1, text: 1]

  defstruct bundle: nil,
            checked: [],
            findings: [],
            not_checked: [],
            kinds: [],
            counts: %{}

  @sth_payload_type "application/vnd.r5e.checkpoint+json"

  # Printed on every run. The checkpoint-key line is conditional in one
  # word — "self-declared" unless the reader has pinned the node key —
  # because a pin is the only thing that can tie it to anything, and it
  # comes from the reader rather than from the bundle.
  @not_checked_always [
    "the policy decision itself: a recorded decision is never re-derived -- this verifier runs no policy engine; it establishes that the policy object a receipt cites is present and unaltered, not that evaluating it would yield the recorded outcome",
    "endorsement and badge terms are compared against timestamps this deployment wrote; sequence order is proven, wall-clock validity is not",
    "kernel-assigned instance names (content and server naming) are not re-derived from the signed target, which carries no name for them",
    "equivocation/split-view: consistency is proven only between the checkpoints presented to this run; detecting a forked log served to different audiences requires independent witnesses gossiping STHs",
    "completeness attestations (none present; absence of events from the world is never provable)"
  ]

  # Spec 011 §9: printed only when the bundle carries payloads that predate
  # signatures (`U > 0`). On a chain where every admission is signed they
  # would be false, and a not-checked block that lists checks the run *did*
  # perform is worth as little as one that omits checks it did not.
  @not_checked_legacy [
    "admissions are not yet signed: this bundle carries payloads admitted before spec 011, and nothing about those acts is proven by signature",
    "actor fingerprints are asserted at admission, not proven by signature"
  ]

  defp checkpoint_not_checked(pins, node_key) do
    if RecurseVerify.Trust.pinned?(pins, node_key) do
      "key-to-identity binding: the checkpoint key is pinned by this reader -- the binding is the reader's own, not the chain's (spec/03)"
    else
      "key-to-identity binding: the checkpoint key is self-declared -- no endorsement chain ties it to a person, office, or deployment (spec/03)"
    end
  end

  @doc """
  Verify a bundle directory; returns a report struct. Options:

    * `:prior` — path to an earlier export (bundle directory or its
      `manifest.json`); its STH is checked for consistency with this
      bundle's log.
    * `:posture` — `"house"` or `"commons"`, the **reader's** own stance
      (spec 011 §9). Required when the bundle carries an admitted Badge
      instance, and refused otherwise only in the sense that it decides
      nothing else.
    * `:trust` — trust pins (`RecurseVerify.Trust`).
  """
  @spec run(Path.t(), keyword()) :: {:ok, %__MODULE__{}} | {:error, String.t()}
  def run(bundle, opts \\ []) do
    log_path = Path.join(bundle, "log.jsonl")

    if File.exists?(log_path) do
      {:ok, events} = RecurseVerify.Chain.read_log(log_path)
      decoded = decoded_payloads(events, Path.join(bundle, "cas"))
      pins = opts[:trust] || []

      with :ok <- posture_required(decoded, opts[:posture]) do
        report =
          %__MODULE__{bundle: bundle, not_checked: @not_checked_always}
          |> check_chain(events)
          |> check_checkpoint(events)
          |> check_consistency(events, opts[:prior])
          |> check_payloads(events, bundle)
          |> count_claims(events, bundle)
          |> check_identity(decoded, pins, opts[:posture], bundle)
          |> check_policy(events, bundle)
          |> read_kinds(bundle)
          |> check_refs(events, bundle)
          |> check_cas(events, bundle)
          |> sort_findings()

        {:ok, report}
      end
    else
      {:error, "no log.jsonl in #{bundle} -- not an r5e bundle"}
    end
  end

  @doc """
  §9: `--posture` is **required** whenever the bundle carries an admitted
  Badge instance. The Badge *Kind* alone does not trigger it — a
  deployment that has defined the vocabulary and issued nothing has
  nothing for a posture to be about. There is no default, because the two
  readings of a badge-only person are genuinely different judgements and
  the tool must not make one silently.
  """
  @spec posture_required([{map(), map()}], String.t() | nil) :: :ok | {:error, String.t()}
  def posture_required(decoded, posture) do
    cond do
      posture in ["house", "commons"] ->
        :ok

      posture != nil ->
        {:error, "--posture takes house or commons, got #{q(posture)}"}

      RecurseVerify.Identity.badge_present?(decoded) ->
        {:error,
         "this bundle carries an admitted Badge, so --posture house|commons is required: " <>
           "whether a key acting only under badges is a finding is the reader's judgement, " <>
           "not this tool's"}

      true ->
        :ok
    end
  end

  # Spec 011 §9's three lines, and the findings behind them.
  defp check_identity(report, decoded, pins, posture, bundle) do
    {signatures, sig_findings, sig_counts} = RecurseVerify.Identity.check_signatures(decoded)

    {endorsements, end_findings, end_counts} =
      RecurseVerify.Identity.check_endorsements(decoded, pins)

    {identities, id_findings, id_counts} =
      RecurseVerify.Identity.check_identities(decoded, posture)

    # §9's "unless a pin equals the node key". The manifest's own `keyId`
    # is the **checkpoint** convention (`sha256(pubkey)`), which predates
    # §0's tag-prefixed key id and is not what a reader pins — so the §0
    # id is derived from the bundled public key rather than read off the
    # manifest. Two conventions, both live, told apart here.
    node_key =
      with {:ok, manifest} <- read_manifest(bundle),
           {:ok, public_key} <- bundled_public_key(manifest),
           {:ok, id} <- RecurseVerify.DSSE.key_id("ed25519", public_key) do
        id
      else
        _ -> nil
      end

    report
    |> add_checked(signatures)
    |> add_checked(endorsements)
    |> add_checked(identities)
    |> add_findings(sig_findings ++ end_findings ++ id_findings)
    |> add_findings(RecurseVerify.Identity.check_shapes(decoded))
    |> Map.update!(
      :counts,
      &Map.merge(&1, Map.merge(sig_counts, Map.merge(end_counts, id_counts)))
    )
    |> Map.update!(:not_checked, fn lines ->
      # The checkpoint line first and the legacy pair second, where they
      # have always been: a reader who has quoted this block before should
      # find it reordered only where the content changed.
      legacy = if sig_counts.legacy > 0, do: @not_checked_legacy, else: []
      succeeded = RecurseVerify.Identity.succeeded_roots(decoded)
      conditional = RecurseVerify.Identity.conditional_not_checked(decoded)
      [checkpoint_not_checked(pins, node_key)] ++ legacy ++ succeeded ++ conditional ++ lines
    end)
  end

  # §9: findings by (seq, code). The seq is parsed back out of the line
  # because a finding is a *string* by the output doctrine — what a reader
  # quotes is the sentence, so the sentence is the record and the ordering
  # is derived from it.
  defp sort_findings(report) do
    Map.update!(report, :findings, fn findings ->
      Enum.sort_by(findings, fn line ->
        case Regex.run(~r/^([a-z-]+): (?:.*?)seq (\d+)/, line) do
          [_, code, seq] -> {String.to_integer(seq), code}
          _ -> {-1, line}
        end
      end)
    end)
  end

  @doc "Render a report per the output doctrine."
  @spec format(%__MODULE__{}) :: String.t()
  def format(%__MODULE__{} = r) do
    findings_block =
      case r.findings do
        [] -> ["  none -- every check above passed on this bundle's contents"]
        findings -> Enum.map(findings, &("  " <> &1))
      end

    kinds_block =
      case r.kinds do
        [] -> ["  no KindDefinitions present in bundle"]
        kinds -> Enum.flat_map(kinds, &format_kind/1)
      end

    """
    r5e verifier -- bundle: #{r.bundle}

    checked:
    #{r.checked |> Enum.map(&("  " <> &1)) |> Enum.join("\n")}

    epistemic scope of Kinds involved:
    #{Enum.join(kinds_block, "\n")}

    findings:
    #{Enum.join(findings_block, "\n")}

    not checked (state this wherever the output is quoted):
    #{r.not_checked |> Enum.map(&("  " <> &1)) |> Enum.join("\n")}
    """
  end

  # -- chain -------------------------------------------------------------

  defp check_chain(report, events) do
    case RecurseVerify.Chain.verify_events(events) do
      {:ok, count} ->
        add_checked(
          report,
          "chain: intact -- #{count} events, seq contiguous, every hash recomputed from canonical encoding, every prev link verified"
        )

      {:error, problems} ->
        report
        |> add_checked(
          "chain: BROKEN -- #{length(events)} events read, #{length(problems)} integrity failure(s)"
        )
        |> add_findings(
          Enum.map(problems, fn p -> "tamper: event seq #{q(p.seq)} -- #{p.problem}" end)
        )
    end
  end

  # -- checkpoint / STH --------------------------------------------------

  defp check_checkpoint(report, events) do
    case read_manifest(report.bundle) do
      {:ok, manifest} ->
        case manifest["checkpoint"] do
          %{"envelope" => envelope, "checkpoint" => claim} ->
            check_signed_checkpoint(report, manifest, envelope, claim, events)

          %{"root" => _} = legacy ->
            add_finding(
              report,
              "unsigned checkpoint (legacy placeholder shape, seq #{text(legacy["seq"])}) -- " <>
                "chain integrity rests on this bundle's own contents alone; nothing attests the head"
            )

          _ ->
            add_finding(report, "no checkpoint in manifest -- nothing attests the chain head")
        end

      _ ->
        add_finding(report, "no readable manifest.json -- checkpoint not checkable")
    end
  end

  defp check_signed_checkpoint(report, manifest, envelope, claim, events) do
    with {:ok, pub} <- bundled_public_key(manifest),
         {:ok, payload, key_id} <- RecurseVerify.DSSE.verify(envelope, pub),
         {:ok, signed_claim} <- Jason.decode(payload) do
      report
      |> check_key_id(pub, key_id)
      |> check_claim_match(signed_claim, claim)
      |> check_sth_contents(signed_claim, events)
    else
      {:error, :no_public_key} ->
        add_finding(
          report,
          "checkpoint is signed but the bundle carries no public key -- signature not checkable offline"
        )

      {:error, reason} ->
        add_finding(
          report,
          "checkpoint signature FAILED verification against the bundled key (#{format_reason(reason)}) -- " <>
            "the attested head cannot be trusted from this bundle"
        )
    end
  end

  defp check_key_id(report, pub, key_id) do
    if RecurseVerify.DSSE.fingerprint(pub) == key_id do
      add_checked(
        report,
        "checkpoint signature: verified (ed25519 over DSSE PAE) against bundled key #{short_key(key_id)} -- " <>
          "proves log integrity as attested by that key, NOT the key holder's identity"
      )
    else
      add_finding(
        report,
        "checkpoint key id #{q(key_id)} is not the fingerprint of the bundled public key -- " <>
          "signature verified against a key the bundle does not honestly identify"
      )
    end
  end

  defp check_claim_match(report, signed_claim, claim) do
    if signed_claim == claim do
      report
    else
      add_finding(
        report,
        "manifest checkpoint claim differs from the DSSE-signed claim -- the signed bytes are authoritative"
      )
    end
  end

  # New STH shape: treeSize + merkleRoot + chainHead.
  defp check_sth_contents(
         report,
         %{"treeSize" => tree_size, "merkleRoot" => root_hex} = claim,
         events
       ) do
    last_hash = events |> List.last() |> then(&(&1 && &1["hash"]))
    leaves = Enum.map(events, & &1["hash"])

    report =
      if claim["chainHead"] == last_hash do
        add_checked(
          report,
          "STH: signed chain head matches the last event hash (seq #{text(tree_size)})"
        )
      else
        add_finding(
          report,
          "signed STH chain head #{q(claim["chainHead"])} does not match last event hash #{q(last_hash)} -- the log and the attested head disagree"
        )
      end

    cond do
      not Enum.all?(leaves, &is_binary/1) ->
        add_finding(
          report,
          "the log carries an event with no hash, so no Merkle tree can be built over it -- " <>
            "inclusion is not checkable against the signed STH root"
        )

      tree_size != length(events) ->
        add_finding(
          report,
          "signed STH tree size #{text(tree_size)} != #{length(events)} events in the bundle log -- the log and the attested tree disagree"
        )

      match?(:error, RecurseVerify.Merkle.unhex(root_hex)) ->
        add_finding(report, "signed STH merkle root is not a well-formed 32-byte hex hash")

      true ->
        {:ok, signed_root} = RecurseVerify.Merkle.unhex(root_hex)
        check_merkle(report, leaves, tree_size, signed_root)
    end
  end

  # Pre-Merkle signed shape (chain head only): degrade honestly.
  defp check_sth_contents(report, %{"root" => root} = claim, events) do
    last_hash = events |> List.last() |> then(&(&1 && &1["hash"]))

    report =
      if root == last_hash do
        add_checked(
          report,
          "checkpoint: signed root matches the last event hash (seq #{text(claim["seq"])})"
        )
      else
        add_finding(
          report,
          "signed checkpoint root #{text(root)} does not match last event hash #{q(last_hash)}"
        )
      end

    add_finding(
      report,
      "checkpoint predates Merkle STHs (no treeSize/merkleRoot) -- inclusion and consistency are not checkable from this bundle"
    )
  end

  defp check_sth_contents(report, _claim, _events) do
    add_finding(
      report,
      "signed checkpoint claim has neither STH nor chain-head shape -- not checkable"
    )
  end

  defp check_merkle(report, leaves, tree_size, signed_root) do
    rebuilt = RecurseVerify.Merkle.root(leaves)

    if rebuilt != signed_root do
      add_finding(
        report,
        "merkle root rebuilt from the #{text(tree_size)} event hashes does NOT match the signed STH root -- " <>
          "the attested tree is not the tree this log builds"
      )
    else
      failed =
        for {leaf, index} <- Enum.with_index(leaves),
            {:ok, proof} = RecurseVerify.Merkle.inclusion_proof(leaves, index),
            not RecurseVerify.Merkle.verify_inclusion(leaf, index, tree_size, proof, signed_root) do
          index + 1
        end

      case failed do
        [] ->
          add_checked(
            report,
            "merkle: root rebuilt from #{text(tree_size)} event hashes matches the signed STH root; " <>
              "inclusion proofs generated and verified for all #{text(tree_size)} events"
          )

        seqs ->
          add_finding(
            report,
            "inclusion proofs FAILED for event seq(s) #{Enum.join(seqs, ", ")} against the signed STH root"
          )
      end
    end
  end

  # -- consistency between two exports -----------------------------------

  defp check_consistency(report, _events, nil) do
    %{
      report
      | not_checked:
          report.not_checked ++
            [
              "consistency with an earlier checkpoint: no prior export presented (pass --prior PATH_TO_EARLIER_BUNDLE)"
            ]
    }
  end

  defp check_consistency(report, events, prior_path) do
    with {:ok, prior_manifest} <- read_prior_manifest(prior_path),
         {:ok, prior_claim, prior_key_note} <- verified_prior_sth(prior_manifest) do
      leaves = Enum.map(events, & &1["hash"])
      n = length(leaves)
      m = prior_claim["treeSize"]

      with true <- is_integer(m) and m > 0 and is_binary(prior_claim["merkleRoot"]),
           {:ok, prior_root} <- RecurseVerify.Merkle.unhex(prior_claim["merkleRoot"]) do
        cond do
          not Enum.all?(leaves, &is_binary/1) ->
            add_finding(
              report,
              "the log carries an event with no hash, so no Merkle tree can be built over it -- " <>
                "consistency with the prior checkpoint is not checkable"
            )

          m > n ->
            add_finding(
              report,
              "prior STH tree size #{m} exceeds this log's #{n} events -- this bundle cannot extend that checkpoint"
            )

          true ->
            {:ok, proof} = RecurseVerify.Merkle.consistency_proof(leaves, m, n)
            current_root = RecurseVerify.Merkle.root(leaves)

            if RecurseVerify.Merkle.verify_consistency(m, n, prior_root, current_root, proof) do
              add_checked(
                report,
                "consistency: prior STH (tree size #{m}#{prior_key_note}) is consistent with this log (tree size #{n}) -- " <>
                  "the log extends the earlier checkpoint append-only, nothing before seq #{m} was rewritten"
              )
            else
              add_finding(
                report,
                "prior STH (tree size #{m}) is NOT consistent with this log -- the log the prior checkpoint attested is not a prefix of this one (rewrite, truncation, or split view)"
              )
            end
        end
      else
        _ ->
          add_finding(
            report,
            "prior checkpoint carries no verifiable STH (treeSize/merkleRoot) -- consistency not checkable against it"
          )
      end
    else
      {:error, message} -> add_finding(report, "prior checkpoint: #{message}")
    end
  end

  defp read_prior_manifest(path) do
    manifest_path = if File.dir?(path), do: Path.join(path, "manifest.json"), else: path

    with {:ok, bytes} <- File.read(manifest_path),
         {:ok, manifest} <- Jason.decode(bytes) do
      {:ok, manifest}
    else
      _ -> {:error, "no readable manifest at #{manifest_path}"}
    end
  end

  # The prior STH must itself verify against the prior bundle's own key
  # before its claim is worth checking consistency against.
  defp verified_prior_sth(manifest) do
    with %{"envelope" => envelope, "checkpoint" => _} <- manifest["checkpoint"],
         {:ok, pub} <- bundled_public_key(manifest),
         {:ok, payload, key_id} <- RecurseVerify.DSSE.verify(envelope, pub),
         {:ok, claim} <- Jason.decode(payload) do
      note =
        if RecurseVerify.DSSE.fingerprint(pub) == key_id,
          do: ", signature verified against its own bundled key #{short_key(key_id)}",
          else: ", WARNING: prior key id does not match its bundled key"

      {:ok, claim, note}
    else
      _ ->
        {:error,
         "prior STH signature did not verify (or prior manifest has no signed checkpoint)"}
    end
  end

  # -- payloads ----------------------------------------------------------

  defp check_payloads(report, events, bundle) do
    cas_root = Path.join(bundle, "cas")

    {present, missing} =
      Enum.split_with(events, fn event ->
        RecurseVerify.CAS.intact?(cas_root, event["payload"] || "")
      end)

    report =
      add_checked(
        report,
        "payloads: #{length(present)}/#{length(events)} event payloads present in bundle CAS and matching their address"
      )

    add_findings(
      report,
      Enum.map(missing, fn event ->
        "gap: payload #{payload_label(event)} for event seq #{text(event["seq"])} is missing from the bundle (or does not hash to its address) -- that event's content cannot be examined"
      end)
    )
  end

  # -- claims / actors ---------------------------------------------------

  defp count_claims(report, events, bundle) do
    payloads =
      events
      |> decoded_payloads(Path.join(bundle, "cas"))
      |> Enum.map(fn {_event, payload} -> payload end)

    granted = Enum.count(payloads, &(&1["outcome"] == "admitted"))
    denied = Enum.count(payloads, &(&1["outcome"] == "denied"))

    actors =
      payloads |> Enum.map(&dig(&1, ["actor", "id"])) |> Enum.reject(&is_nil/1) |> Enum.uniq()

    add_checked(
      report,
      "claims: #{granted} admissions, #{denied} denials, by #{length(actors)} actor(s) " <>
        "(#{Enum.map_join(actors, ", ", &text/1)}) -- actor identity is a recorded fingerprint, NOT a verified signature"
    )
    |> Map.update!(
      :counts,
      &Map.merge(&1, %{granted: granted, denied: denied, actors: length(actors)})
    )
  end

  # -- policy ------------------------------------------------------------

  # A payload may carry `"policy" => meta` recording the decision the
  # admission gate made, and — when a policy was in force — the CAS
  # address of the admitted policy object it was made under. What is
  # checkable offline is that the cited object is in this bundle and
  # unaltered. Whether re-evaluating it would produce the recorded
  # decision is not checkable here and is stated as not-checked.
  #
  # Since spec/05 §8, a policy block may also cite a **policy evaluation
  # record**: the kernel-derived object holding the exact bytes the engine
  # was handed. That one is not merely present-checked. §8 states an
  # equality invariant — `engine`, `engineBuild`, `bundle`, `source`,
  # `shape`, `decision` and `matched` on the record equal the receipt's
  # policy block byte for byte — and a receipt that disagrees with its own
  # evidence is a finding here, which is what turns "the producer says so"
  # into something an offline reader can falsify.
  defp check_policy(report, events, bundle) do
    cas_root = Path.join(bundle, "cas")
    decoded = decoded_payloads(events, cas_root)

    recorded =
      Enum.flat_map(decoded, fn {event, payload} ->
        case Map.fetch(payload, "policy") do
          {:ok, meta} -> [{event["seq"], meta}]
          :error -> []
        end
      end)

    case recorded do
      [] -> report
      _ -> report_policy(report, recorded, length(events), cas_root, decoded, bundle)
    end
  end

  defp report_policy(report, recorded, event_count, cas_root, decoded, bundle) do
    {metas, malformed} = Enum.split_with(recorded, fn {_seq, meta} -> is_map(meta) end)

    engines =
      metas
      |> Enum.map(fn {_seq, meta} -> engine_name(meta["engine"]) end)
      |> Enum.uniq()
      |> Enum.sort()

    cited = for {seq, meta} <- metas, is_binary(meta["bundle"]), do: {seq, meta["bundle"]}
    # An allow with no bundle cited is the bootstrap fixpoint: the Kinds
    # and the first policy bundle must be admitted before any bundle can
    # govern an admission. A *denial* with no bundle is not that, and is
    # reported as a finding below.
    bootstrap =
      Enum.count(metas, fn {_seq, meta} ->
        is_nil(meta["bundle"]) and meta["decision"] == "allow"
      end)

    denials = Enum.filter(metas, fn {_seq, meta} -> meta["decision"] == "deny" end)
    errors = Enum.count(metas, fn {_seq, meta} -> meta["decision"] == "error" end)

    broken =
      for {seq, addr} <- cited, not RecurseVerify.CAS.intact?(cas_root, addr), do: {seq, addr}

    blind_denials = for {seq, meta} <- denials, is_nil(meta["bundle"]), do: {seq, meta}
    broken_seqs = for {seq, _addr} <- broken, do: seq

    # A denial whose rule cannot be read from this bundle: none cited, or
    # the cited object absent or altered.
    unexaminable_denials =
      for {seq, meta} <- denials,
          is_nil(meta["bundle"]) or seq in broken_seqs,
          do: seq

    # §8 (KP-3): every other address in a policy block — the policy text
    # itself, the shape that presented the instance, the engine build
    # descriptor — is fetchable, so its presence is checkable and checked.
    absent_objects = absent_policy_objects(metas, cas_root)

    # §8's equality invariant, plus the record's own two decodable fields
    # and its `kindDefinition`.
    {evaluations, evaluation_findings} =
      check_evaluations(metas, cas_root, derived_addresses(bundle), kind_spec_addresses(decoded))

    line =
      "policy: #{length(recorded)}/#{event_count} receipts record a policy decision " <>
        "(engines: #{Enum.join(engines, ", ")}); " <>
        cited_clause(cited, broken) <>
        "; #{bootstrap} allowed with no bundle in force (bootstrap); " <>
        denial_clause(denials, unexaminable_denials) <>
        error_clause(errors) <>
        evaluation_clause(evaluations, evaluation_findings, absent_objects) <>
        " -- the cited object is the policy the gate read, NOT proof that evaluating it yields the recorded decision"

    report
    |> add_checked(line)
    |> add_findings(absent_objects)
    |> add_findings(evaluation_findings)
    |> add_findings(
      for {seq, addr} <- broken do
        "gap: receipt at seq #{text(seq)} cites policy object #{addr}, which is missing from the bundle " <>
          "(or does not hash to its address) -- the rule that decided cannot be examined"
      end
    )
    |> add_findings(
      for {seq, meta} <- blind_denials do
        "gap: receipt at seq #{text(seq)} records a denial under engine #{q(meta["engine"])} " <>
          "with no policy object in force -- nothing in this bundle shows the rule that denied"
      end
    )
    |> add_findings(
      for {seq, _meta} <- malformed do
        "gap: receipt at seq #{text(seq)} carries a policy record that is not an object -- " <>
          "what decided is not readable"
      end
    )
  end

  # The engine's own name, as the receipt spells it. A receipt that names
  # no engine says `unstated`; one that names something that is not a
  # string has it spelled back (spec/07 §2.6) rather than coerced, because
  # a bundle may put anything there and a verifier that stopped on it
  # would have said nothing about the bundle at all.
  defp engine_name(nil), do: "unstated"
  defp engine_name(name) when is_binary(name), do: name
  defp engine_name(other), do: q(other)

  defp cited_clause([], _broken), do: "none cites an admitted policy object"

  defp cited_clause(cited, broken) do
    distinct = cited |> Enum.map(fn {_seq, addr} -> addr end) |> Enum.uniq() |> length()

    presence =
      case broken do
        [] ->
          "all #{length(cited)} present in bundle CAS and matching their address"

        _ ->
          "#{length(cited) - length(broken)} present in bundle CAS and matching their address, " <>
            "#{length(broken)} missing or altered (see findings)"
      end

    "#{length(cited)} cite an admitted policy object (#{distinct} distinct), #{presence}"
  end

  defp denial_clause([], _unexaminable), do: "denials: none"

  defp denial_clause([_one], []), do: "denials: 1, citing the policy object that denied"

  defp denial_clause(denials, []),
    do: "denials: #{length(denials)}, each citing the policy object that denied"

  defp denial_clause(denials, unexaminable) do
    verb = if length(unexaminable) == 1, do: "cites", else: "cite"

    "denials: #{length(denials)}, of which #{length(unexaminable)} #{verb} " <>
      "no policy object this bundle can produce (see findings)"
  end

  defp error_clause(0), do: ""

  defp error_clause(count),
    do: "; #{count} fail-closed on a malformed engine answer (a receipt, not a finding)"

  # -- the policy evaluation record (spec/05 §8) -------------------------
  #
  # The seven keys §8 says must agree between the record and the receipt
  # that cites it. They are the whole of what the invariant covers: the
  # record's `requestBytes`, `entitiesBytes` and `resolution` are what
  # replay needs, not what the receipt repeats, so they are checked for
  # form and not for agreement.
  @evaluation_invariant ~w(engine engineBuild bundle source shape decision matched)

  # The three addresses a policy block may carry besides `bundle` and
  # `evaluation`. All three are objects (`sha256:` or `bytes:`), so
  # "resolves" means "is in this bundle's CAS and hashes to its address".
  @policy_objects ~w(source shape engineBuild)

  defp absent_policy_objects(metas, cas_root) do
    for {seq, meta} <- metas,
        key <- @policy_objects,
        address = meta[key],
        is_binary(address),
        not RecurseVerify.CAS.intact?(cas_root, address) do
      "gap: receipt at seq #{text(seq)} cites policy #{key} #{text(address)}, which is missing from the " <>
        "bundle (or does not hash to its address)"
    end
  end

  defp check_evaluations(metas, cas_root, derived, kind_specs) do
    cited = for {seq, meta} <- metas, is_binary(meta["evaluation"]), do: {seq, meta}

    findings =
      Enum.flat_map(cited, fn {seq, meta} ->
        check_evaluation(seq, meta, cas_root, derived, kind_specs)
      end)

    {length(cited), findings}
  end

  defp check_evaluation(seq, meta, cas_root, derived, kind_specs) do
    address = meta["evaluation"]

    case RecurseVerify.CAS.get(cas_root, address) do
      {:error, _} ->
        [
          "gap: receipt at seq #{text(seq)} cites policy evaluation record #{text(address)}, which is " <>
            "missing from the bundle -- the input the engine was handed cannot be examined " <>
            "(spec/05 §8; an erased record reads as \"input erased\", not as a pass)"
        ]

      {:ok, bytes} ->
        case Jason.decode(bytes) do
          {:ok, record} when is_map(record) ->
            declared_derived(seq, address, derived) ++
              invariant_findings(seq, address, record, meta) ++
              base64_findings(seq, address, record) ++
              kind_definition_finding(seq, address, record, kind_specs)

          _ ->
            [
              "gap: the policy evaluation record at #{text(address)}, cited by seq #{text(seq)}, is not a " <>
                "JSON object -- spec/05 §8 closes its schema"
            ]
        end
    end
  end

  # §5: a record is a kernel-derived object, and the export declares the
  # class. One the export does not declare is bytes with nobody's account
  # of where they came from, even though a receipt names them.
  defp declared_derived(seq, address, derived) do
    if MapSet.member?(derived, RecurseVerify.CAS.object_hash(address)) do
      []
    else
      [
        "gap: receipt at seq #{text(seq)} cites policy evaluation record #{text(address)}, which the " <>
          "export does not list under derivedObjects -- spec/05 §5: an evaluation record is a " <>
          "kernel-derived object and the export declares the class"
      ]
    end
  end

  defp invariant_findings(seq, address, record, meta) do
    for key <- @evaluation_invariant, record[key] != meta[key] do
      "policy: the evaluation record at #{text(address)} says #{key} = #{q(record[key])} " <>
        "and the receipt at seq #{text(seq)} says #{q(meta[key])} -- spec/05 §8 makes those " <>
        "equal, so one of the two is not the record of this decision"
    end
  end

  defp base64_findings(seq, address, record) do
    for key <- ~w(requestBytes entitiesBytes),
        not decodes_base64?(record[key]) do
      "policy: the evaluation record at #{text(address)}, cited by seq #{text(seq)}, carries #{key} that " <>
        "is not base64 -- the bytes the engine was handed cannot be recovered, so the record " <>
        "cannot be replayed"
    end
  end

  defp decodes_base64?(value) when is_binary(value), do: match?({:ok, _}, Base.decode64(value))
  defp decodes_base64?(_value), do: false

  # §8: `kindDefinition` is the target Kind's admitted `specAddress`. A
  # record naming an address no KindDefinition on this chain was admitted
  # at is citing a schema this bundle cannot produce.
  defp kind_definition_finding(seq, address, record, kind_specs) do
    case record["kindDefinition"] do
      nil ->
        []

      value when is_binary(value) ->
        if MapSet.member?(kind_specs, value) do
          []
        else
          [
            "policy: the evaluation record at #{text(address)}, cited by seq #{text(seq)}, names " <>
              "kindDefinition #{text(value)}, which is not the specAddress of any KindDefinition " <>
              "admitted on this chain (spec/05 §8)"
          ]
        end

      other ->
        [
          "policy: the evaluation record at #{text(address)}, cited by seq #{text(seq)}, carries " <>
            "kindDefinition #{q(other)}, which is not an address"
        ]
    end
  end

  defp kind_spec_addresses(decoded) do
    MapSet.new(
      for {_event, payload} <- decoded,
          payload["outcome"] == "admitted",
          target_path(payload) == "core.r5e.io/v1/KindDefinition",
          is_map(payload["spec"]),
          do: RecurseVerify.Canonical.address(payload["spec"])
    )
  end

  defp derived_addresses(bundle) do
    MapSet.new(
      case read_manifest(bundle) do
        {:ok, %{"derivedObjects" => list}} when is_list(list) ->
          for address <- list, is_binary(address), do: RecurseVerify.CAS.object_hash(address)

        _ ->
          []
      end
    )
  end

  defp evaluation_clause(0, _findings, absent) do
    case absent do
      [] -> "; no receipt cites a policy evaluation record (spec/05 §8)"
      _ -> "; #{length(absent)} policy object(s) cited but absent (see findings)"
    end
  end

  defp evaluation_clause(count, findings, absent) do
    verdict =
      case findings ++ absent do
        [] ->
          "each present, each declared kernel-derived, each agreeing with its receipt on " <>
            "engine, engineBuild, bundle, source, shape, decision and matched (spec/05 §8), " <>
            "with decodable requestBytes/entitiesBytes and a kindDefinition admitted on this chain"

        problems ->
          "#{length(problems)} of them could not be reconciled with the receipts that cite " <>
            "them (see findings)"
      end

    "; #{count} cite a policy evaluation record: " <> verdict
  end

  # -- refs (spec/05 §4, §10) --------------------------------------------
  #
  # A payload's `resolvedRefs` is the kernel's account of what the spec
  # cited and what it found. None of it is taken on faith: every entry is
  # re-derived from this bundle's own log and CAS, and the *declaration*
  # it was produced under is read back from the exported KindDefinition,
  # so "resolved to the declared Kind and outcome" is checked against the
  # declaration rather than against the manifest's own summary of it.
  #
  # The other direction matters as much: a `$ref` in an admitted spec with
  # no manifest entry is a citation nobody looked up, and it is a finding
  # even though the record looks complete.

  defp check_refs(report, events, bundle) do
    cas_root = Path.join(bundle, "cas")
    decoded = decoded_payloads(events, cas_root)
    index = ref_index(events, decoded, report.kinds, bundle)

    entries =
      for {event, payload} <- decoded,
          entry <- manifest_of(payload),
          do: {event, entry}

    findings =
      Enum.flat_map(entries, fn {event, entry} -> check_entry(event, entry, index, cas_root) end) ++
        Enum.flat_map(decoded, fn {event, payload} -> check_complete(event, payload) end)

    counts = Enum.frequencies_by(entries, fn {_event, entry} -> class_of(entry) end)

    report
    |> add_checked(refs_line(entries, decoded, counts, findings))
    |> add_findings(findings)
  end

  defp manifest_of(%{"resolvedRefs" => refs}) when is_list(refs), do: refs
  defp manifest_of(_payload), do: []

  defp class_of(entry) when is_map(entry), do: class_name(entry["class"])
  defp class_of(_entry), do: "malformed"

  defp class_name(nil), do: "unstated"
  defp class_name(class) when is_binary(class), do: class
  defp class_name(other), do: q(other)

  defp ref_index(events, decoded, kinds, bundle) do
    %{
      by_hash: Map.new(events, &{&1["hash"], &1}),
      payloads: Map.new(decoded, fn {event, payload} -> {event["hash"], payload} end),
      payload_addrs: MapSet.new(events, & &1["payload"]),
      spec_addrs:
        MapSet.new(
          for {_event, payload} <- decoded,
              payload["outcome"] == "admitted",
              is_map(payload["spec"]),
              do: RecurseVerify.Canonical.address(payload["spec"])
        ),
      # spec/05 §5: the `CasObject` admissions on this chain, by the bare
      # address each one put on the record — what a `bytes:` ref must be
      # backed by, re-derived here from the log rather than trusted from
      # the manifest entry that claims it.
      cas_objects: cas_admissions(decoded, "core.r5e.io/v1/CasObject"),
      cas_expired: cas_admissions(decoded, "core.r5e.io/v1/CasExpired"),
      # The one class that legitimately has no admission (§5). It is read
      # from the export manifest, which is a claim the producing kernel
      # makes and this verifier reports as such — see `check_cas/3`.
      derived:
        MapSet.new(
          case read_manifest(bundle) do
            {:ok, %{"derivedObjects" => list}} when is_list(list) ->
              for address <- list, is_binary(address), do: RecurseVerify.CAS.object_hash(address)

            _ ->
              []
          end
        ),
      kinds:
        Map.new(kinds, fn kind ->
          {"#{kind["group"]}/#{kind["version"]}/#{kind["kind"]}", kind}
        end)
    }
  end

  # Every granted admission of one of §5's two core Kinds, keyed by the
  # bare address its spec names. The first admission of an address wins,
  # matching the producing kernel: a re-put is a second act, and what a
  # citation names is the act that put the object there.
  defp cas_admissions(decoded, kind) do
    for {event, payload} <- decoded,
        payload["outcome"] == "admitted",
        target_path(payload) == kind,
        is_map(payload["spec"]),
        is_binary(payload["spec"]["address"]),
        reduce: %{} do
      acc ->
        address = RecurseVerify.CAS.object_hash(payload["spec"]["address"])

        Map.put_new(acc, address, %{
          "seq" => event["seq"],
          "eventRef" => "event:" <> event["hash"],
          "mediaType" => dig(payload, ["spec", "mediaType"])
        })
    end
  end

  defp refs_line([], _decoded, _counts, _findings),
    do: "refs: no typed refs recorded on this chain"

  defp refs_line(entries, decoded, counts, findings) do
    receipts = entries |> Enum.map(fn {event, _} -> event["seq"] end) |> Enum.uniq() |> length()

    breakdown =
      counts
      |> Enum.sort()
      |> Enum.map(fn {class, n} -> "#{class} #{n}" end)
      |> Enum.join(", ")

    verdict =
      case findings do
        [] ->
          "every one re-derived from this bundle: kind refs resolve to an admission at a lower " <>
            "seq whose spec hashes to the recorded address, event refs to an event at the " <>
            "recorded seq with the recorded target Kind and outcome, bytes objects present, " <>
            "coinciding with no event payload address and no admitted spec address, and backed " <>
            "by the CasObject admission the entry names (or declared kernel-derived)"

        _ ->
          "#{length(findings)} could not be re-derived from this bundle (see findings)"
      end

    "refs: #{length(entries)} typed refs recorded across #{receipts}/#{length(decoded)} " <>
      "receipts (#{breakdown}); " <> verdict
  end

  # -- raw objects (spec/05 §5) ------------------------------------------
  #
  # The refs pass asks whether every *citation* is backed. This one asks
  # the other direction: whether every raw object the bundle carries is
  # accounted for. A bundle's CAS holds exactly four kinds of thing —
  # event payloads and admitted specs (both kernel-written), objects a
  # `CasObject` admission put there, and objects the export declares
  # kernel-derived. Anything else is bytes in a directory with nobody's
  # name on them, and a bundle whose contents are not all accounted for is
  # exactly the thing this verifier exists to notice.
  #
  # Also here, because it is a claim about the chain rather than about one
  # citation: a `CasExpired` for an address something cites with
  # `retention: "public-record"` is a finding. The producing kernel refuses
  # it at `validateConstraints`; a chain that carries one anyway is either
  # not that kernel's or has been rewritten, and the point of an offline
  # check is that it does not have to take the producer's word for it.

  defp check_cas(report, events, bundle) do
    cas_root = Path.join(bundle, "cas")
    decoded = decoded_payloads(events, cas_root)
    index = ref_index(events, decoded, report.kinds, bundle)

    unaccounted = unaccounted_objects(cas_root, index)
    public_record_expiries = public_record_expiries(decoded)
    uncited_derived = uncited_derived(decoded, index)

    # §5: the manifest's `derivedObjects` is the union over the payloads,
    # so it is re-derived from them here rather than read from the export.
    declared = declared_derived(decoded)
    union = union_findings(index.derived, declared)
    absent_derived = absent_declared_derived(cas_root, declared)

    objects = map_size(index.cas_objects)
    expired = map_size(index.cas_expired)
    derived = MapSet.size(index.derived)

    report =
      if objects + expired + derived + map_size(declared) == 0 do
        # A chain with no raw objects on it has nothing to say here, and
        # a line saying "0 objects" would be noise on every chain that
        # never used any.
        report
      else
        add_checked(
          report,
          cas_line(objects, expired, derived, unaccounted, uncited_derived ++ union)
        )
      end

    report
    |> add_findings(unaccounted)
    |> add_findings(uncited_derived)
    |> add_findings(union)
    |> add_findings(absent_derived)
    |> add_findings(public_record_expiries)
  end

  # -- §5: the manifest is the union over the payloads --------------------
  #
  # A kernel-derived object is the one class with no admission of its own,
  # so the export has to *declare* the class — and a declaration a reader
  # cannot check against the chain is worth nothing. Since the producing
  # kernel copies each engine's report onto the event payload beside
  # `policy` (schema-lite v2 §5, §9), the class is on the record and the
  # manifest is re-derivable from it. Two directions of disagreement, and
  # each is a different fault:
  #
  #   * an address in the manifest that no payload names — the export
  #     declared an object no act on this chain accounts for;
  #   * an address a payload names that the manifest omits — the export
  #     **lost** the class. That is the exact shape of the fold-v2 defect:
  #     the records were registered in memory only, a restart dropped
  #     them, and the export taken afterwards listed none while every
  #     receipt citing one stayed on the log.
  #
  # Both name the differing addresses, because "the manifest disagrees
  # with the payloads" is not something a reader can act on.
  defp declared_derived(decoded) do
    Enum.reduce(decoded, %{}, fn {event, payload}, acc ->
      for address <- payload_derived(payload), reduce: acc do
        seen -> Map.put_new(seen, RecurseVerify.CAS.object_hash(address), {address, event["seq"]})
      end
    end)
  end

  defp payload_derived(%{"derivedObjects" => list}) when is_list(list) do
    for address <- list,
        is_binary(address),
        RecurseVerify.CAS.object_address?(address),
        do: address
  end

  defp payload_derived(_payload), do: []

  defp union_findings(manifest_derived, declared) do
    on_record = MapSet.new(Map.keys(declared))

    exported_only =
      for bare <- MapSet.difference(manifest_derived, on_record) |> Enum.sort() do
        "cas: the export lists #{text(bare)} under derivedObjects and no event payload declares it -- " <>
          "spec/05 §5 makes the manifest the union over the payloads, so this object is " <>
          "accounted for by the export alone and by nothing on the chain"
      end

    recorded_only =
      for {_bare, {address, seq}} <-
            Enum.sort(Map.drop(declared, MapSet.to_list(manifest_derived))) do
        "cas: the payload at seq #{text(seq)} declares #{text(address)} a kernel-derived object and the " <>
          "export does not list it under derivedObjects -- spec/05 §5 makes the manifest the " <>
          "union over the payloads; an export that lists fewer has lost the class, and every " <>
          "citation of this object reads as unbacked bytes"
      end

    exported_only ++ recorded_only
  end

  # §5: an object a payload declares derived is bytes this deployment
  # wrote inside an admission, so the bundle is the one place it can come
  # from — there is no `CasObject` admission to fall back on and no other
  # producer to ask.
  defp absent_declared_derived(cas_root, declared) do
    for {_bare, {address, seq}} <- Enum.sort(declared),
        not RecurseVerify.CAS.intact?(cas_root, address) do
      "gap: the payload at seq #{text(seq)} declares #{text(address)} a kernel-derived object, and it is " <>
        "missing from the bundle (or does not hash to its address) -- such an object has no " <>
        "CasObject admission to recover it from, so what the engine wrote cannot be examined"
    end
  end

  # The other half of §5's kernel-derived class, and the half amendment C6
  # said the verifier could not falsify until §8 landed. `derivedObjects`
  # is still a producer claim in one direction — the export says these
  # bytes were written inside an admission and no chain fact contradicts
  # that. But a derived object the chain cites *nowhere* is a claim about
  # an act that left no other trace, and that much is falsifiable: the
  # export declared it and nothing on the chain wanted it.
  #
  # Four things count as citing one, and they are the four ways a derived
  # object can be reached from the record: a receipt's policy
  # `evaluation`, a resolution manifest entry, a `bytes:` string in an
  # admitted spec, and the `derivedObjects` of the payload whose own
  # admission wrote it. The fourth is the strongest of the four — it is
  # the act that produced the bytes saying so — and it is why the union
  # check above is the sharper instrument now: an export can no longer
  # invent a derived object at all, so what is left for this check is the
  # object a payload declared and nothing ever wanted.
  defp uncited_derived(decoded, index) do
    cited =
      MapSet.new(
        Enum.flat_map(decoded, fn {_event, payload} ->
          policy_evaluation_addresses(payload) ++
            manifest_addresses(payload) ++
            admitted_spec_addresses(payload) ++
            Enum.map(payload_derived(payload), &RecurseVerify.CAS.object_hash/1)
        end)
      )

    for bare <- Enum.sort(index.derived), not MapSet.member?(cited, bare) do
      "cas: the object at #{text(bare)} is declared kernel-derived by this export and is cited by " <>
        "nothing on the chain -- no receipt's policy evaluation, no resolution manifest entry, " <>
        "no admitted spec and no payload's derivedObjects names it (spec/05 §5)"
    end
  end

  defp policy_evaluation_addresses(%{"policy" => %{"evaluation" => address}})
       when is_binary(address),
       do: [RecurseVerify.CAS.object_hash(address)]

  defp policy_evaluation_addresses(_payload), do: []

  defp manifest_addresses(payload) do
    for entry <- manifest_of(payload),
        is_map(entry),
        is_binary(entry["value"]),
        String.starts_with?(entry["value"], "bytes:"),
        do: RecurseVerify.CAS.object_hash(entry["value"])
  end

  defp admitted_spec_addresses(%{"outcome" => "admitted", "spec" => spec}) when is_map(spec),
    do: for(address <- bytes_strings(spec), do: RecurseVerify.CAS.object_hash(address))

  defp admitted_spec_addresses(_payload), do: []

  defp bytes_strings(%{} = map), do: Enum.flat_map(map, fn {_k, v} -> bytes_strings(v) end)
  defp bytes_strings(list) when is_list(list), do: Enum.flat_map(list, &bytes_strings/1)

  defp bytes_strings("bytes:" <> _ = value),
    do: if(RecurseVerify.CAS.object_address?(value), do: [value], else: [])

  defp bytes_strings(_value), do: []

  defp cas_line(objects, expired, derived, unaccounted, uncited_derived) do
    verdict =
      case unaccounted do
        [] ->
          "every object in this bundle's CAS is accounted for: an event payload, an admitted " <>
            "spec, an admitted CasObject, or a declared kernel-derived object"

        _ ->
          "#{length(unaccounted)} object(s) in this bundle's CAS are accounted for by nothing " <>
            "on the chain (see findings)"
      end

    "cas: #{objects} object(s) admitted, #{expired} expired, #{derived} kernel-derived" <>
      derived_clause(derived, uncited_derived) <> "; " <> verdict
  end

  defp derived_clause(0, []), do: ""

  defp derived_clause(0, problems),
    do: " (#{length(problems)} declared on the chain and not by this export -- see findings)"

  defp derived_clause(_derived, []),
    do:
      " (each cited by a receipt's policy evaluation, a resolution manifest, or an admitted spec, " <>
        "and the export's list is exactly the union of the payloads' own derivedObjects)"

  defp derived_clause(_derived, problems),
    do: " (#{length(problems)} of them could not be reconciled with the chain -- see findings)"

  defp unaccounted_objects(cas_root, index) do
    for address <- objects_in(cas_root),
        bare = RecurseVerify.CAS.object_hash(address),
        not MapSet.member?(index.payload_addrs, bare),
        not MapSet.member?(index.spec_addrs, bare),
        not Map.has_key?(index.cas_objects, bare),
        not MapSet.member?(index.derived, bare) do
      "cas: the object at #{text(bare)} is in this bundle and nothing on the chain put it there -- " <>
        "no event payload, no admitted spec, no CasObject admission, and not listed under " <>
        "the export's derivedObjects (spec/05 §5)"
    end
  end

  # The bundle's CAS layout is `<root>/<2 hex>/<62 hex>` (§6), so the
  # address is readable from the path. Anything else under `cas/` is not
  # an object and is left alone rather than reported as a mystery.
  # Sorted, because the order is the order two findings are printed in
  # and a directory listing is not a rule (spec/07 §4.10).
  defp objects_in(cas_root) do
    case File.ls(cas_root) do
      {:ok, shards} ->
        shards = Enum.sort(shards)

        for shard <- shards,
            String.match?(shard, ~r/\A[0-9a-f]{2}\z/),
            {:ok, names} <- [File.ls(Path.join(cas_root, shard))],
            rest <- Enum.sort(names),
            String.match?(rest, ~r/\A[0-9a-f]{62}\z/) do
          "sha256:" <> shard <> rest
        end

      {:error, _} ->
        []
    end
  end

  defp public_record_expiries(decoded) do
    for {event, payload} <- decoded,
        payload["outcome"] == "admitted",
        target_path(payload) == "core.r5e.io/v1/CasExpired",
        is_map(payload["spec"]),
        is_binary(dig(payload, ["spec", "address"])),
        bare = RecurseVerify.CAS.object_hash(dig(payload, ["spec", "address"])),
        citation = public_record_citation(decoded, bare),
        citation != nil do
      "cas: event seq #{text(event["seq"])} expired #{dig(payload, ["spec", "address"])}, which the " <>
        "admission at seq #{text(citation["seq"])} cites at #{text(citation["path"])} with retention " <>
        "\"public-record\" -- a public-record object is never expired (spec/05 §5)" <>
        order_note(event["seq"], citation["seq"])
    end
  end

  # The rule as written is about the chain as a whole: an address a
  # public-record ref cites is one no `CasExpired` may name. The order the
  # two events landed in changes what a reader should conclude, though, so
  # it is said rather than left to be worked out from two seq numbers. An
  # expiry after the citation is a gate admitting what §5 says it must
  # refuse. An expiry before it means the object was re-admitted and only
  # then declared a public record -- legal at every step, and still a
  # chain that records these bytes having once been removed.
  defp order_note(expiry_seq, citation_seq) when citation_seq < expiry_seq,
    do: "; the citation was already on the chain when the expiry was admitted"

  defp order_note(_expiry_seq, _citation_seq),
    do:
      "; the citation is later than the expiry, so the object was re-admitted after being " <>
        "expired -- nothing was refused out of turn, and the chain still records that a " <>
        "now-public-record object was once removed"

  defp public_record_citation(decoded, bare) do
    Enum.find_value(decoded, fn {event, payload} ->
      Enum.find_value(manifest_of(payload), fn entry ->
        with true <- is_map(entry),
             "bytes" <- entry["class"],
             "public-record" <- entry["retention"],
             true <- is_binary(entry["value"]),
             ^bare <- RecurseVerify.CAS.object_hash(entry["value"]) do
          %{"seq" => event["seq"], "path" => entry["path"]}
        else
          _ -> nil
        end
      end)
    end)
  end

  # -- one manifest entry ------------------------------------------------

  defp check_entry(event, entry, index, cas_root) when is_map(entry) do
    declared = declaration_for(event, entry, index)

    case entry["class"] do
      "kind" ->
        check_kind_ref(event, entry, declared, index)

      "event" ->
        check_event_ref(event, entry, declared, index)

      "bytes" ->
        check_bytes_ref(event, entry, declared, index, cas_root)

      other ->
        [finding(event, entry, "records class #{q(other)}, which is not a ref class")]
    end
  end

  defp check_entry(event, entry, _index, _cas_root),
    do: [
      "refs: event seq #{text(event["seq"])} carries a manifest entry that is not an object: #{q(entry)}"
    ]

  defp check_kind_ref(event, entry, declared, index) do
    hash = strip_event(entry["admissionEvent"])
    target = index.by_hash[hash]
    payload = target && index.payloads[hash]

    cond do
      not is_binary(entry["value"]) ->
        [finding(event, entry, "records no ref value")]

      is_nil(target) ->
        [
          finding(
            event,
            entry,
            "cites admission #{q(entry["admissionEvent"])}, which is not an event on this chain"
          )
        ]

      target["seq"] >= event["seq"] ->
        [
          finding(
            event,
            entry,
            "cites an admission at seq #{text(target["seq"])}, which is not lower than #{text(event["seq"])}"
          )
        ]

      target["seq"] != entry["generation"] ->
        [
          finding(
            event,
            entry,
            "records generation #{q(entry["generation"])}, but that admission is at seq #{text(target["seq"])}"
          )
        ]

      is_nil(payload) ->
        [finding(event, entry, "cites an admission whose payload is missing from this bundle")]

      payload["outcome"] != "admitted" ->
        [finding(event, entry, "cites an admission that was denied")]

      instance_path(payload, hash) != entry["value"] ->
        [finding(event, entry, "cites an admission of #{q(instance_path(payload, hash))}")]

      RecurseVerify.Canonical.address(payload["spec"]) != entry["specAddress"] ->
        [
          finding(
            event,
            entry,
            "records specAddress #{q(entry["specAddress"])}, but that admission's spec hashes to #{q(RecurseVerify.Canonical.address(payload["spec"]))}"
          )
        ]

      true ->
        check_declaration(
          event,
          entry,
          declared,
          "kind",
          declared && declared["kind"],
          target_path(payload)
        )
    end
  end

  defp check_event_ref(event, entry, declared, index) do
    hash = strip_event(entry["value"])
    target = index.by_hash[hash]
    payload = target && index.payloads[hash]

    cond do
      is_nil(target) ->
        [finding(event, entry, "names no event on this chain")]

      target["seq"] != entry["seq"] ->
        [
          finding(
            event,
            entry,
            "records seq #{q(entry["seq"])}, but that event is at seq #{text(target["seq"])}"
          )
        ]

      target["seq"] >= event["seq"] ->
        [
          finding(
            event,
            entry,
            "cites an event at seq #{text(target["seq"])}, which is not lower than #{text(event["seq"])}"
          )
        ]

      is_nil(payload) ->
        [finding(event, entry, "cites an event whose payload is missing from this bundle")]

      payload["outcome"] != entry["outcome"] ->
        [
          finding(
            event,
            entry,
            "records outcome #{q(entry["outcome"])}, but that event is a #{q(payload["outcome"])} one"
          )
        ]

      target_path(payload) != entry["targetKind"] ->
        [
          finding(
            event,
            entry,
            "records targetKind #{q(entry["targetKind"])}, but that event admitted #{q(target_path(payload))}"
          )
        ]

      true ->
        check_declaration(
          event,
          entry,
          declared,
          "event",
          declared && declared["event"],
          entry["targetKind"]
        ) ++
          check_facet(event, entry, declared, payload)
    end
  end

  defp check_bytes_ref(event, entry, declared, index, cas_root) do
    address = entry["value"]
    bare = RecurseVerify.CAS.object_hash(address || "")

    cond do
      not RecurseVerify.CAS.object_address?(address) ->
        [finding(event, entry, "records a value that is not an object address")]

      not RecurseVerify.CAS.intact?(cas_root, address) ->
        [
          finding(
            event,
            entry,
            "names an object that is missing from this bundle (or does not hash to its address)"
          )
        ]

      MapSet.member?(index.payload_addrs, bare) ->
        [
          finding(
            event,
            entry,
            "names an event payload address — §4 partitions admitted raw bytes from what the kernel writes"
          )
        ]

      MapSet.member?(index.spec_addrs, bare) ->
        [
          finding(
            event,
            entry,
            "names an admitted spec address — §4 partitions admitted raw bytes from what the kernel writes"
          )
        ]

      true ->
        {:ok, bytes} = RecurseVerify.CAS.get(cas_root, address)

        size_finding =
          if entry["size"] == byte_size(bytes),
            do: [],
            else: [
              finding(
                event,
                entry,
                "records size #{q(entry["size"])}, but that object is #{byte_size(bytes)} bytes"
              )
            ]

        size_finding ++
          check_backing(event, entry, index, bare) ++
          check_declaration(event, entry, declared, "bytes", nil, nil)
    end
  end

  # spec/05 §5: presence is not admission. A `bytes:` ref must name an
  # object a `CasObject` admission put on the record — at a lower seq than
  # the citing event, because a citation of something not yet admitted is
  # a citation of nothing — or one the export declares kernel-derived.
  #
  # The manifest entry's own `casObjectEvent` is not taken on faith: the
  # backing admission is found on this bundle's log and the recorded value
  # is compared to what was found, so a manifest that names the wrong
  # admission is as much a finding as one that names none.
  defp check_backing(event, entry, index, bare) do
    recorded = entry["casObjectEvent"]

    case Map.fetch(index.cas_objects, bare) do
      {:ok, %{"seq" => seq, "eventRef" => ref}} ->
        cond do
          seq >= event["seq"] ->
            [
              finding(
                event,
                entry,
                "names an object whose CasObject admission is at seq #{text(seq)}, not below this " <>
                  "event's seq #{text(event["seq"])} -- a citation cannot precede what it cites"
              )
            ]

          recorded != ref ->
            [
              finding(
                event,
                entry,
                "records casObjectEvent #{q(recorded)}, but the CasObject admission for " <>
                  "that address on this chain is #{ref} (seq #{text(seq)})"
              )
            ]

          true ->
            []
        end

      :error ->
        if MapSet.member?(index.derived, bare) do
          # A kernel-derived object has no admission of its own, and the
          # manifest must say so rather than naming one.
          if recorded == nil do
            []
          else
            [
              finding(
                event,
                entry,
                "is listed in the export's derivedObjects, which have no CasObject admission, " <>
                  "yet records casObjectEvent #{q(recorded)}"
              )
            ]
          end
        else
          [
            finding(
              event,
              entry,
              "names an object that no CasObject admission on this chain put there, and that " <>
                "the export does not list under derivedObjects -- spec/05 §5: bytes present in " <>
                "a bundle is not bytes anybody admitted"
            )
          ]
        end
    end
  end

  # The class the exported KindDefinition declares at this pointer, and —
  # for kind and event refs — the target Kind it names. A Kind absent from
  # the bundle leaves `declared` nil and these checks unmade; the manifest
  # is then only checked against the chain, which is less than §10 asks
  # for and is why the export carries the Kinds at all.
  defp check_declaration(_event, _entry, nil, _class, _declared_target, _found), do: []

  defp check_declaration(event, entry, declared, class, declared_target, found) do
    cond do
      declared_class(declared) != class ->
        [
          finding(
            event,
            entry,
            "is recorded as a #{class} ref, but its property declares a #{declared_class(declared)} ref"
          )
        ]

      declared_target != nil and not target_declared?(declared_target, found) ->
        [
          finding(
            event,
            entry,
            "resolved to #{q(found)}, but its property declares #{q(declared_target)}"
          )
        ]

      true ->
        []
    end
  end

  # §5/KS-5: an `event` refdecl accepts a **list** of Kinds — `parent` on
  # an Endorsement may be either authority Kind, `revokes` on a Revocation
  # any of three. Membership is the test, and equality is its one-Kind
  # case; comparing a list to a string reported every correctly declared
  # list ref as a mismatch.
  defp target_declared?(declared, found) when is_list(declared), do: found in declared
  defp target_declared?(declared, found), do: declared == found

  defp check_facet(event, entry, declared, payload) do
    facet = (declared && declared["outcome"]) || "admitted"

    if facet == "any" or payload["outcome"] == "admitted" do
      []
    else
      [
        finding(
          event,
          entry,
          "resolved to a denied event, but its property declares outcome #{q(facet)}"
        )
      ]
    end
  end

  defp declared_class(%{"kind" => _}), do: "kind"
  defp declared_class(%{"event" => _}), do: "event"
  defp declared_class(%{"bytes" => _}), do: "bytes"
  defp declared_class(_), do: "unrecognized"

  # The ref declaration at an RFC 6901 pointer, walked out of the Kind the
  # citing event admitted.
  defp declaration_for(_event, entry, _index) when not is_map(entry), do: nil

  defp declaration_for(event, entry, index) do
    with payload when is_map(payload) <- index.payloads[event["hash"]],
         kind when is_map(kind) <- index.kinds[target_path(payload)],
         pointer when is_binary(pointer) <- entry["path"],
         prop when is_map(prop) <- declaration_at(kind["schema"], pointer) do
      prop["ref"]
    else
      _ -> nil
    end
  end

  defp declaration_at(level, ""), do: level

  defp declaration_at(level, "/" <> rest) when is_map(level) do
    [segment | tail] = String.split(rest, "/")
    segment = segment |> String.replace("~1", "/") |> String.replace("~0", "~")
    tail = if tail == [], do: "", else: "/" <> Enum.join(tail, "/")

    next =
      cond do
        is_map(level["items"]) and Regex.match?(~r/\A[0-9]+\z/, segment) ->
          level["items"]

        is_map(level["properties"]) and is_map(level["properties"][segment]) ->
          level["properties"][segment]

        is_map(level["values"]) ->
          level["values"]

        true ->
          nil
      end

    next && declaration_at(next, tail)
  end

  defp declaration_at(_level, _pointer), do: nil

  # -- completeness ------------------------------------------------------
  # A denial's spec may hold refs that were never resolved (the denial may
  # be the reason), so completeness is asked only of admissions.

  defp check_complete(event, %{"outcome" => "admitted", "spec" => spec} = payload)
       when is_map(spec) do
    recorded = for entry <- manifest_of(payload), is_map(entry), do: entry["path"]
    cited = for {pointer, _ref} <- ref_sites(spec, ""), do: pointer

    missing =
      for pointer <- cited -- recorded do
        "refs: unresolved ref recorded without a manifest entry -- event seq #{text(event["seq"])}, " <>
          "pointer #{pointer}, ref #{q(ref_at(spec, pointer))}"
      end

    extra =
      for pointer <- recorded -- cited do
        "refs: manifest entry at event seq #{text(event["seq"])}, pointer #{q(pointer)} names " <>
          "no ref in the admitted spec"
      end

    missing ++ extra
  end

  defp check_complete(_event, _payload), do: []

  defp ref_at(spec, pointer) do
    Enum.find_value(ref_sites(spec, ""), fn {p, ref} -> p == pointer && ref end)
  end

  defp ref_sites(%{"$ref" => ref} = node, path) when map_size(node) == 1 and is_binary(ref),
    do: [{path, ref}]

  defp ref_sites(node, path) when is_map(node) do
    node
    |> Enum.sort_by(fn {k, _} -> k end)
    |> Enum.flat_map(fn {k, v} -> ref_sites(v, path <> "/" <> escape(k)) end)
  end

  defp ref_sites(node, path) when is_list(node) do
    node
    |> Enum.with_index()
    |> Enum.flat_map(fn {v, i} -> ref_sites(v, "#{path}/#{i}") end)
  end

  defp ref_sites(_node, _path), do: []

  defp escape(segment),
    do: segment |> String.replace("~", "~0") |> String.replace("/", "~1")

  # -- ref helpers -------------------------------------------------------

  defp strip_event("event:" <> hash), do: hash
  defp strip_event(other), do: other

  defp target_path(payload) do
    target = object(payload["target"])
    "#{text(target["group"])}/#{text(target["version"])}/#{text(target["kind"])}"
  end

  # §2 `server`: the payload deliberately carries no `target.name`, and the
  # name is the admission event's own hash. The path is rebuilt the way the
  # kernel and replay build it, from the event.
  defp instance_path(payload, admission_hash) do
    target = object(payload["target"])
    name = target["name"] || "event:" <> admission_hash
    "#{target_path(payload)}/#{name}"
  end

  defp finding(event, entry, what) do
    "refs: event seq #{text(event["seq"])}, pointer #{q(entry["path"])}, " <>
      "ref #{q(entry["value"])} #{what}"
  end

  # -- kinds / epistemic scope -------------------------------------------

  defp read_kinds(report, bundle) do
    kinds =
      Path.join(bundle, "kinds/*.json")
      |> Path.wildcard()
      |> Enum.sort()
      |> Enum.flat_map(fn path ->
        case path |> File.read!() |> Jason.decode() do
          {:ok, kind} -> [kind]
          _ -> []
        end
      end)

    %{report | kinds: kinds}
  end

  defp format_kind(kind) do
    id = "#{text(kind["group"])}/#{text(kind["version"])} #{text(kind["kind"])}"
    scope = object(kind["epistemicScope"])

    flag =
      if kind["scopeDefaulted"],
        do: " [scope: defaulted -- author declared nothing beyond the modest default]",
        else: ""

    [
      "  #{id}#{flag}"
    ] ++
      declared(kind) ++
      [
        "    claims: #{Enum.map_join(list(scope["claims"]), "; ", &text/1)}",
        "    does NOT claim: #{Enum.map_join(list(scope["doesNotClaim"]), "; ", &text/1)}"
      ]
  end

  # §10: `naming`, `description` and `derivedFrom`, printed where the
  # exported definition carries them. A Kind admitted before schema-lite
  # v2 carries none, and gains no lines it never declared — the block says
  # what the record says, and silence about a keyword that was not yet in
  # the language is the honest rendering of it.
  defp declared(kind) do
    naming =
      case kind["naming"] do
        %{"mode" => mode} = naming ->
          detail =
            cond do
              is_binary(naming["value"]) -> " (value #{q(naming["value"])})"
              is_binary(naming["derive"]) -> " (derive #{q(naming["derive"])})"
              true -> ""
            end

          ["    naming: #{mode}#{detail}"]

        _ ->
          []
      end

    description =
      case kind["description"] do
        text when is_binary(text) ->
          ["    description: " <> String.replace(text, "\n", "\n      ")]

        _ ->
          []
      end

    derived =
      case kind["derivedFrom"] do
        address when is_binary(address) -> ["    derivedFrom: #{text(address)}"]
        _ -> []
      end

    naming ++ description ++ derived
  end

  # -- helpers -----------------------------------------------------------

  def sth_payload_type, do: @sth_payload_type

  # Every event whose payload is present in CAS and decodes as JSON,
  # paired with its event header. Events whose payload is missing are
  # already reported as gaps by check_payloads/3.
  defp decoded_payloads(events, cas_root) do
    for event <- events,
        address = event["payload"] || "",
        {:ok, bytes} <- [RecurseVerify.CAS.get(cas_root, address)],
        # spec/07 §1.6: a payload that does not hash to its address is
        # **absent** for every check but §4.4, which reports it. Bytes at
        # the right path are not the payload the chain names; reading
        # them anyway would let anyone edit a payload in place and still
        # be answered about its contents, which is the opposite of what
        # a content address is for.
        RecurseVerify.Canonical.hash_bytes(bytes) == RecurseVerify.CAS.object_hash(address),
        {:ok, decoded} <- [Jason.decode(bytes)] do
      {event, decoded}
    end
  end

  defp read_manifest(bundle) do
    with {:ok, bytes} <- File.read(Path.join(bundle, "manifest.json")),
         {:ok, manifest} <- Jason.decode(bytes) do
      {:ok, manifest}
    end
  end

  defp bundled_public_key(%{"signer" => %{"publicKey" => b64}}) when is_binary(b64) do
    case Base.decode64(b64) do
      {:ok, pub} when byte_size(pub) == 32 -> {:ok, pub}
      _ -> {:error, :no_public_key}
    end
  end

  defp bundled_public_key(_), do: {:error, :no_public_key}

  defp short_key("sha256:" <> hex), do: "sha256:" <> String.slice(hex, 0, 12) <> "..."
  defp short_key(other), do: q(other)

  defp format_reason(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp format_reason(reason), do: q(reason)

  # A bundle is a file: a key read as an object may hold anything at all,
  # and reading through one that is not an object answers "nothing
  # recorded" (spec/07 §2.6) rather than stopping the run.
  defp object(value) when is_map(value), do: value
  defp object(_value), do: %{}

  defp list(value) when is_list(value), do: value
  defp list(_value), do: []

  # §4.4 names the address the event cites, and `(absent)` when it cites
  # none — a bare empty span would leave the sentence saying nothing.
  defp payload_label(event) do
    case event["payload"] do
      nil -> "(absent)"
      address -> text(address)
    end
  end

  defp add_checked(report, line), do: %{report | checked: report.checked ++ [line]}
  defp add_finding(report, line), do: %{report | findings: report.findings ++ [line]}
  defp add_findings(report, lines), do: %{report | findings: report.findings ++ lines}
end
