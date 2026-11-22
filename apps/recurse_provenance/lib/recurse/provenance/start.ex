defmodule Recurse.Provenance.Start do
  @moduledoc """
  Checks how a deployment's chain began and how its roots have changed.

  A deployment's start stream holds, in order: `ChainStarted`, signed by
  a key the node made for itself, saying which published definitions the
  node was built from; `Deployment`, signed by that key and by one of
  the customer's roots, which accepts the first and names the customer's
  roots; and then any number of `RootsChanged` records, each replacing
  the terms before it. The `Deployment` record's reference is the
  chain's name and never changes.

  A change of roots is authorised in one of two ways the terms before it
  declared: by a recovery key, alone; or by a quorum, where each of the
  required number of roots has filed a `RootChangeApproval` signed by
  that root and by the personal key of the person who holds it.

  This module reads those records out of a bundle and reports, for each,
  whether it is what it should be and whether the reader's own trust
  input backs it. A start that is perfectly well formed and was made by
  somebody the reader never chose is reported as not trusted, never as
  fine.

  It also answers what the authority walk needs: which keys were roots,
  from when, and what ended each one's time as a root.
  """

  alias Recurse.Provenance.Evidence
  alias Recurse.Provenance.Grammar.Schema, as: GrammarSchema

  @base "provenance.r5e.io/v2/"
  @chain_started @base <> "ChainStarted"
  @deployment @base <> "Deployment"
  @roots_changed @base <> "RootsChanged"
  @approval @base <> "RootChangeApproval"
  @principal @base <> "Principal"
  @kinds [@chain_started, @deployment, @roots_changed]

  @candidate ~r/^urn:r5e:stream:[^:]+:start$/
  @well_named ~r/^urn:r5e:stream:[a-z0-9][a-z0-9-]*:start$/

  # A start record that is sound in itself and merely not backed by the
  # reader's trust input. The record after it is still checked against it.
  @untrusted ["chain_not_trusted", "new_roots_not_trusted"]

  @type raw ::
          {subject :: String.t(), result :: :ok | :failed | :incomplete, code :: String.t(),
           about :: String.t() | nil}

  @typedoc """
  A stretch of time during which a key was a root: from when (in
  nanoseconds, 0 for a key the reader pinned directly), and the record
  that ended it, if one did.
  """
  @type tenure :: %{from: non_neg_integer(), ended: %{ref: String.t(), at: integer()} | nil}

  @type state :: :none | :established | :incomplete | :failed

  @doc "The kinds judged here and not by the authority walk."
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds ++ [@approval]

  @doc """
  Check every record on a start stream, and every approval of a change.

  `opened` maps a reference to its opened record. `held` answers, for a
  reference, the result of its body check and of each signature check
  (`%{body: result, signatures: [result]}`).

  Options: `:trusted_roots` (a list or nil), `:trusted_chain` (a
  `Deployment` reference or nil), `:min_start_seq` (an integer or nil),
  and `:binding`, a function that says whether a custodian's personal
  key, not named in the terms, was bound to them by a root before a
  change (`:bound`, `{:unsealed, ref}` or `:none`).

  Returns the findings, the summary of the start stream to show in a
  report (or nil), what a pinned chain came to, and each root's tenures.
  """
  @spec check(%{String.t() => map()}, (String.t() -> map()), keyword()) ::
          %{
            findings: [raw()],
            head: map() | nil,
            state: state(),
            tenures: %{String.t() => [tenure()]}
          }
  def check(opened, held, opts) do
    chain = Keyword.get(opts, :trusted_chain)
    roots = Keyword.get(opts, :trusted_roots)
    minimum = Keyword.get(opts, :min_start_seq)
    all = Map.values(opened)
    approvals = Enum.filter(all, &(Evidence.kind_path(&1.evidence) == @approval))

    streams =
      all
      |> Enum.group_by(& &1.evidence["stream"])
      |> Enum.filter(fn {stream, records} ->
        Regex.match?(@candidate, stream) or
          Enum.any?(records, &(Evidence.kind_path(&1.evidence) in @kinds))
      end)
      |> Enum.sort_by(&elem(&1, 0))

    names = Enum.map(streams, &elem(&1, 0))

    env = %{
      opened: opened,
      all: all,
      approvals: approvals,
      names: names,
      held: held,
      chain: chain,
      roots: roots,
      binding: Keyword.get(opts, :binding, fn _key, _who, _terms, _approval, _change -> :none end)
    }

    # Start-stream records in order; each change of roots judges the
    # approvals that cite it just before counting them.
    {results, voted} =
      for {stream, records} <- streams, reduce: {%{}, %{}} do
        acc ->
          records
          |> Enum.sort_by(&{&1.evidence["seq"], &1.ref})
          |> Enum.reduce(acc, fn record, {done, voted} ->
            env =
              Map.merge(env, %{
                stream: stream,
                records: records,
                done: done,
                spent: spent(records, record)
              })

            {result, votes} = judge(record, env)
            {Map.put(done, record.ref, result), Map.merge(voted, votes)}
          end)
      end

    # Approvals that cite nothing on a start stream are judged last.
    stray =
      for a <- approvals, not Map.has_key?(voted, a.ref), into: %{} do
        {a.ref, approval(a, nil, Map.merge(env, %{done: results}))}
      end

    start_failed? = Enum.any?(results, fn {_ref, {result, _, _}} -> result == :failed end)
    reach = reach(streams, results)

    missing_chain =
      if chain && not Map.has_key?(results, chain) &&
           not Enum.any?(results, fn {_ref, {_, code, _}} ->
             code in ["chain_mismatch", "multiple_start_streams"]
           end) do
        [{chain, :incomplete, "chain_start_not_carried", nil}]
      else
        []
      end

    below =
      if minimum && not start_failed? && (reach == nil or reach.seq < minimum) do
        subject = if names == [], do: "bundle", else: hd(names)
        [{subject, :incomplete, "start_below_minimum_position", "seq:#{minimum}"}]
      else
        []
      end

    findings =
      for {ref, {result, code, about}} <- Enum.concat([results, voted, stray]),
          do: {ref, result, code, about}

    state = state(chain, streams, results, start_failed?, missing_chain ++ below)

    %{
      findings: findings ++ missing_chain ++ below,
      head: head(reach),
      state: state,
      tenures: tenures(chain, roots, state, streams, results)
    }
  end

  # The recovery keys already used by changes before this record on its stream.
  defp spent(records, record) do
    for r <- records,
        r.evidence["seq"] < record.evidence["seq"],
        Evidence.kind_path(r.evidence) == @roots_changed,
        r.evidence["body"]["authorization"] == "recovery",
        into: MapSet.new(),
        do: r.evidence["body"]["signer"]
  end

  # -- one start-stream record -------------------------------------------------

  defp judge(record, env) do
    evidence = record.evidence
    kind = Evidence.kind_path(evidence)
    seq = evidence["seq"]
    %{body: body, signatures: signatures} = env.held.(record.ref)

    simple = fn result -> {result, %{}} end

    cond do
      length(env.names) > 1 ->
        simple.({:failed, "multiple_start_streams", Enum.find(env.names, &(&1 != env.stream))})

      kind not in @kinds ->
        simple.({:failed, "not_a_start_record", kind})

      not Regex.match?(@well_named, env.stream) or (kind == @chain_started and seq != 1) or
        (kind == @deployment and seq != 2) or (kind == @roots_changed and seq < 3) ->
        simple.({:failed, "wrong_start_position", "seq:#{seq}"})

      Enum.count(env.records, &(&1.evidence["seq"] == seq)) > 1 ->
        simple.({:failed, "forked_start_stream", "seq:#{seq}"})

      body == :failed or :failed in signatures ->
        simple.({:failed, "invalid_start_record", nil})

      body == :incomplete or :incomplete in signatures ->
        simple.({:incomplete, "unverified_start_record", nil})

      kind == @chain_started ->
        simple.(chain_started(evidence, env))

      kind == @deployment ->
        simple.(deployment(record, env))

      true ->
        roots_changed(record, env)
    end
  end

  defp chain_started(%{"body" => body} = evidence, env) do
    kinds = Enum.map(body["definitions"], & &1["kind"])

    cond do
      env.stream != "urn:r5e:stream:" <> body["deployment"] <> ":start" ->
        {:failed, "deployment_stream_mismatch", evidence["stream"]}

      kinds != Enum.uniq(kinds) ->
        {:failed, "invalid_start_record", nil}

      not Enum.any?(env.records, &(&1.evidence["seq"] == 2)) ->
        {:incomplete, "deployment_not_carried", nil}

      true ->
        {:ok, "ok", body["bootstrap"]}
    end
  end

  defp deployment(%{ref: ref, evidence: %{"body" => body} = evidence}, env) do
    first = before(env, 2, body["accepts"])
    first_result = first && Map.get(env.done, first.ref)

    cond do
      not terms_hold?(body) or body["claimedBy"] not in root_keys(body) ->
        {:failed, "invalid_deployment_terms", nil}

      evidence["previous"] != body["accepts"] ->
        {:failed, "accepts_is_not_chain_started", body["accepts"]}

      first == nil ->
        {:incomplete, "chain_started_not_carried", body["accepts"]}

      first.ref != body["accepts"] or match?({:failed, _, _}, first_result) ->
        {:failed, "accepts_is_not_chain_started", first.ref}

      env.held.(first.ref).body == :ok and
          body["bootstrap"] != first.evidence["body"]["bootstrap"] ->
        {:failed, "bootstrap_signer_mismatch", first.evidence["body"]["bootstrap"]}

      match?({:incomplete, _, _}, first_result) ->
        {:incomplete, "unverified_start_record", first.ref}

      env.chain != nil and ref != env.chain ->
        {:failed, "chain_mismatch", env.chain}

      not (env.chain == ref or (is_list(env.roots) and body["claimedBy"] in env.roots)) ->
        {:incomplete, "chain_not_trusted", ref}

      true ->
        {:ok, "ok", first.ref}
    end
  end

  # A change of roots. Returns its own result and the results of the
  # approvals that cite it.
  defp roots_changed(%{ref: ref, evidence: %{"body" => body} = evidence}, env) do
    seq = evidence["seq"]
    prior = before(env, seq, body["replaces"])
    prior_result = prior && Map.get(env.done, prior.ref)
    prior_ok? = prior != nil and env.held.(prior.ref).body == :ok
    terms = prior && prior.evidence["body"]

    votes =
      for a <- env.approvals, a.evidence["body"]["change"] == ref, into: %{} do
        {a.ref, approval(a, %{ref: ref, evidence: evidence}, env)}
      end

    named =
      if prior_ok? do
        if seq == 3, do: prior.ref, else: terms["chain"]
      end

    spent =
      if body["authorization"] == "recovery",
        do: MapSet.put(env.spent, body["signer"]),
        else: env.spent

    retained =
      body
      |> Map.get("recoveryKeys", [])
      |> Enum.filter(&MapSet.member?(spent, &1))
      |> Enum.sort()

    result =
      cond do
        not terms_hold?(body) ->
          {:failed, "invalid_deployment_terms", nil}

        evidence["previous"] != body["replaces"] ->
          {:failed, "replaces_is_not_prior_start", body["replaces"]}

        prior == nil ->
          {:incomplete, "prior_start_not_carried", body["replaces"]}

        prior.ref != body["replaces"] or match?({:failed, _, _}, prior_result) ->
          {:failed, "replaces_is_not_prior_start", prior.ref}

        prior_ok? and body["chain"] != named ->
          {:failed, "start_chain_mismatch", named}

        prior_ok? and instant(evidence) < instant(prior.evidence) ->
          {:failed, "start_timestamp_regression", prior.ref}

        match?({:incomplete, code, _} when code not in @untrusted, prior_result) ->
          {:incomplete, "unverified_start_record", prior.ref}

        body["authorization"] == "recovery" and
            body["signer"] not in Map.get(terms, "recoveryKeys", []) ->
          {:failed, "unauthorized_recovery_signer", body["signer"]}

        retained != [] ->
          {:failed, "spent_recovery_key_retained", hd(retained)}

        body["authorization"] == "quorum" and body["signer"] not in root_keys(terms) ->
          {:failed, "proposer_not_a_root", body["signer"]}

        body["authorization"] == "quorum" and
            length(Map.get(terms, "custodians", [])) < terms["threshold"] ->
          {:failed, "quorum_not_configured", nil}

        body["authorization"] == "quorum" and quorum(votes, env) < terms["threshold"] ->
          {:incomplete, "quorum_not_carried", "need:#{terms["threshold"]}"}

        env.chain != nil and body["chain"] != env.chain ->
          {:failed, "chain_mismatch", env.chain}

        env.chain == nil and is_list(env.roots) and root_keys(body) -- env.roots != [] ->
          {:incomplete, "new_roots_not_trusted", Enum.min(root_keys(body) -- env.roots)}

        env.chain == nil and env.roots == nil ->
          {:incomplete, "chain_not_trusted", body["chain"]}

        true ->
          {:ok, "ok", prior.ref}
      end

    {result, votes}
  end

  # How many roots have approved. A root counts once when all its
  # approvals name the same person and personal key, and neither that
  # person nor that key appears under another root. Repeating an approval
  # is harmless; a root that says two different things does not count.
  defp quorum(votes, env) do
    held =
      for {ref, {:ok, _, _}} <- votes do
        body = env.opened[ref].evidence["body"]
        {body["root"], {body["custodian"], body["custodianKey"]}}
      end

    by_root = Enum.group_by(held, &elem(&1, 0), &elem(&1, 1))

    Enum.count(by_root, fn {root, pairs} ->
      case Enum.uniq(pairs) do
        [{who, key}] ->
          not Enum.any?(held, fn {other, {w, k}} -> other != root and (w == who or k == key) end)

        _ ->
          false
      end
    end)
  end

  # -- one approval --------------------------------------------------------------

  # `change` is the change the approval cites when that change is being
  # judged on a start stream, or nil when the approval is judged alone.
  defp approval(%{ref: ref, evidence: %{"body" => body} = evidence}, change, env) do
    %{body: own_body, signatures: signatures} = env.held.(ref)
    cited = change || Map.get(env.opened, body["change"])

    on_start? =
      cited != nil and length(env.names) == 1 and
        Evidence.kind_path(cited.evidence) == @roots_changed and
        cited.evidence["stream"] == hd(env.names) and cited.evidence["seq"] >= 3 and
        Enum.count(env.all, &same_position?(&1, cited)) == 1

    cited_body = cited && env.held.(cited.ref).body
    prior = on_start? && before_position(env, cited)
    prior_result = prior && Map.get(env.done, prior.ref)
    terms = prior && prior.evidence["body"]

    cond do
      own_body == :failed or :failed in signatures ->
        {:failed, "invalid_root_change_approval", nil}

      own_body == :incomplete or :incomplete in signatures ->
        {:incomplete, "unverified_root_change_approval", nil}

      evidence["seq"] != 1 or
          Enum.count(env.all, &(&1.evidence["stream"] == evidence["stream"])) > 1 ->
        {:failed, "approval_not_alone_on_stream", evidence["stream"]}

      cited == nil ->
        {:incomplete, "approved_change_not_carried", body["change"]}

      not on_start? or cited_body == :failed or
          (cited_body == :ok and cited.evidence["body"]["authorization"] != "quorum") ->
        {:failed, "approval_not_for_quorum_change", body["change"]}

      cited_body == :incomplete ->
        {:incomplete, "unverified_start_record", body["change"]}

      prior == nil ->
        {:incomplete, "prior_start_not_carried", cited.evidence["body"]["replaces"]}

      prior.ref != cited.evidence["body"]["replaces"] or match?({:failed, _, _}, prior_result) ->
        {:failed, "approval_not_for_quorum_change", prior.ref}

      match?({:incomplete, code, _} when code not in @untrusted, prior_result) ->
        {:incomplete, "unverified_start_record", prior.ref}

      true ->
        approver(evidence, cited, terms, env)
    end
  end

  defp approver(%{"body" => body} = evidence, cited, terms, env) do
    roots = root_keys(terms)
    recovery = Map.get(terms, "recoveryKeys", [])
    entry = Enum.find(Map.get(terms, "custodians", []), &(&1["identity"] == body["custodian"]))

    cond do
      body["root"] not in roots or agent?(body["root"], env) ->
        {:failed, "approver_not_in_quorum", body["root"]}

      body["custodianKey"] in roots or body["custodianKey"] in recovery or
          agent?(body["custodianKey"], env) ->
        {:failed, "approver_not_in_quorum", body["custodianKey"]}

      entry == nil ->
        {:failed, "approver_not_in_quorum", body["custodian"]}

      is_binary(entry["key"]) and entry["key"] != body["custodianKey"] ->
        {:failed, "custodian_key_not_bound", body["custodianKey"]}

      is_binary(entry["key"]) ->
        {:ok, "ok", body["change"]}

      true ->
        # The person was named without a key. The key must have been
        # bound to them by a root, and shown to have been before the change.
        case env.binding.(
               body["custodianKey"],
               body["custodian"],
               terms,
               evidence,
               cited.evidence
             ) do
          :bound -> {:ok, "ok", body["change"]}
          {:unsealed, ref} -> {:incomplete, "custodian_key_not_sealed_before_change", ref}
          :none -> {:failed, "custodian_key_not_bound", body["custodianKey"]}
        end
    end
  end

  # Whether a key has declared, in a record it signed, that an agent
  # holds it. A declaration, not a proof: it catches a mistake.
  defp agent?(key, env) do
    Enum.any?(env.all, fn r ->
      Evidence.kind_path(r.evidence) == @principal and r.evidence["body"]["key"] == key and
        r.evidence["body"]["holder"] == "agent" and
        match?(%{body: :ok, signatures: s} when s != [], env.held.(r.ref)) and
        Enum.all?(env.held.(r.ref).signatures, &(&1 == :ok))
    end)
  end

  # -- terms ------------------------------------------------------------------------

  defp root_keys(body), do: Enum.map(body["roots"], & &1["key"])

  defp terms_hold?(body) do
    roots = root_keys(body)
    recovery = Map.get(body, "recoveryKeys", [])
    custodians = Map.get(body, "custodians", [])
    identities = Enum.map(custodians, & &1["identity"])
    personal = for %{"key" => key} <- custodians, do: key

    unique?(roots) and body["threshold"] <= length(roots) and unique?(recovery) and
      Enum.all?(recovery, &(&1 not in roots)) and unique?(identities) and unique?(personal) and
      Enum.all?(personal, &(&1 not in roots and &1 not in recovery)) and
      Enum.all?(body["roots"], &(&1["holder"] != "agent"))
  end

  defp unique?(list), do: list == Enum.uniq(list)

  # The record at the position before `seq` on the stream being judged:
  # the one named if it is there, otherwise the lowest by reference.
  defp before(env, seq, named) do
    env.records
    |> Enum.filter(&(&1.evidence["seq"] == seq - 1))
    |> Enum.sort_by(&{&1.ref != named, &1.ref})
    |> List.first()
  end

  defp before_position(env, cited) do
    env.all
    |> Enum.filter(
      &(&1.evidence["stream"] == cited.evidence["stream"] and
          &1.evidence["seq"] == cited.evidence["seq"] - 1)
    )
    |> Enum.sort_by(&{&1.ref != cited.evidence["body"]["replaces"], &1.ref})
    |> List.first()
  end

  defp same_position?(record, cited),
    do:
      record.evidence["stream"] == cited.evidence["stream"] and
        record.evidence["seq"] == cited.evidence["seq"]

  defp instant(evidence) do
    {:ok, ns} = GrammarSchema.timestamp_ns(evidence["capturedAt"])
    ns
  end

  # -- the stream as a whole ----------------------------------------------------------

  # How far a single, unforked start stream goes with every record held:
  # the last position reached counting up from 1.
  defp reach([{stream, records}], results) do
    by_seq = Enum.group_by(records, & &1.evidence["seq"])

    last =
      1
      |> Stream.iterate(&(&1 + 1))
      |> Enum.take_while(fn seq ->
        match?([_one], by_seq[seq]) and match?({:ok, _, _}, results[hd(by_seq[seq]).ref])
      end)
      |> List.last()

    last && %{stream: stream, seq: last, record: hd(by_seq[last]), by_seq: by_seq}
  end

  defp reach(_none_or_several, _results), do: nil

  defp head(nil), do: nil

  defp head(%{stream: stream, seq: seq, record: record, by_seq: by_seq}) do
    %{
      "stream" => stream,
      "deployment" => hd(by_seq[1]).evidence["body"]["deployment"],
      "chain" => if(seq >= 2, do: hd(by_seq[2]).ref),
      "headSeq" => seq,
      "headRef" => record.ref,
      "headCapturedAt" => record.evidence["capturedAt"]
    }
  end

  # What a pinned chain came to. Established only when the chain's
  # deployment record holds and nothing on the start stream failed or was
  # left unestablished; failed when anything on it failed.
  defp state(nil, _streams, _results, _failed?, _wanting), do: :none

  defp state(chain, _streams, results, failed?, wanting) do
    all_ok? = Enum.all?(results, fn {_ref, {result, _, _}} -> result == :ok end)

    cond do
      failed? -> :failed
      match?({:ok, _, _}, results[chain]) and all_ok? and wanting == [] -> :established
      true -> :incomplete
    end
  end

  # Each root's tenures.
  #
  # Under a pinned chain that is established: every key the deployment
  # record or a later change lists, from the record that lists it, until
  # a later change leaves it out. Under pinned root keys: only the pinned
  # keys, for all time, except that a pinned key the carried start stream
  # shows was removed stops at the change that removed it. Pins never
  # follow a change of roots.
  defp tenures(chain, _roots, :established, [{_stream, records}], _results) when chain != nil do
    records
    |> steps()
    |> Enum.reduce(%{}, fn step, acc ->
      listed = root_keys(step.evidence["body"])
      at = instant(step.evidence)

      acc =
        Map.new(acc, fn {key, [latest | earlier] = all} ->
          if latest.ended == nil and key not in listed,
            do: {key, [%{latest | ended: %{ref: step.ref, at: at}} | earlier]},
            else: {key, all}
        end)

      Enum.reduce(listed, acc, fn key, acc ->
        case acc do
          %{^key => [%{ended: nil} | _]} -> acc
          _ -> Map.update(acc, key, [%{from: at, ended: nil}], &[%{from: at, ended: nil} | &1])
        end
      end)
    end)
  end

  defp tenures(nil, roots, _state, streams, results) when is_list(roots) do
    removed =
      case streams do
        [{_stream, records}] ->
          sound =
            records
            |> steps()
            |> Enum.take_while(fn r ->
              match?({:ok, _, _}, results[r.ref]) or
                match?({:incomplete, code, _} when code in @untrusted, results[r.ref])
            end)

          for {step, earlier} <- Enum.zip(Enum.drop(sound, 1), sound),
              key <- root_keys(earlier.evidence["body"]) -- root_keys(step.evidence["body"]),
              reduce: %{} do
            acc -> Map.put_new(acc, key, %{ref: step.ref, at: instant(step.evidence)})
          end

        _ ->
          %{}
      end

    Map.new(roots, &{&1, [%{from: 0, ended: Map.get(removed, &1)}]})
  end

  defp tenures(_chain, _roots, _state, _streams, _results), do: %{}

  # The deployment record and the changes after it, in order.
  defp steps(records) do
    records
    |> Enum.filter(&(Evidence.kind_path(&1.evidence) in [@deployment, @roots_changed]))
    |> Enum.sort_by(& &1.evidence["seq"])
  end
end
