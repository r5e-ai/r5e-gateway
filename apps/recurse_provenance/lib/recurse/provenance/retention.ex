defmodule Recurse.Provenance.Retention do
  @moduledoc """
  Says what became of content a record refers to and a bundle does not carry.

  A regulated customer must keep content, and the failure to guard
  against is content destroyed when it should have been kept, with the
  record not showing it. So a reader holding only a bundle is told one
  of several different things about missing content, and the comfortable
  answer needs proof for every part of it:

    * it was disposed of by a signed, authorised record, with every hold
      that came before shown, the keep-for period run, and the disposal
      fixed in time by a seal;
    * it was disposed of while a hold stood, or before its keep-until
      date, or by a disposal dated after its own seal: these fail;
    * something needed to tell is not in the bundle: the record's
      profile, a seal over the disposal, or the retention stream up to
      the disposal;
    * it is under a hold and simply not here;
    * the exporter says it was left out, or nothing is said at all.

  Holds, releases and disposals count only on the deployment's one
  retention stream, `urn:r5e:stream:<deployment>:retention`, where each
  disposal is linked to every hold before it. The deployment is the one
  named in the stream of the record whose content is missing, which an
  exporter cannot leave out.

  Content that was disposed of properly is still reported as not
  performed, never as held: the bytes were not checked, because they are
  not there.
  """

  alias Recurse.Provenance.{Evidence, Profile, Ref}
  alias Recurse.Provenance.Grammar.Schema, as: GrammarSchema
  alias RecurseVerify.Canonical

  @base "provenance.r5e.io/v2/"
  @hold @base <> "RetentionHold"
  @release @base <> "RetentionHoldRelease"
  @disposal @base <> "PayloadDisposition"
  @retention ~r/^urn:r5e:stream:[a-z0-9][a-z0-9-]*:retention$/
  @deployment ~r/^urn:r5e:stream:([a-z0-9][a-z0-9-]*):.+$/

  @type raw :: {result :: :ok | :failed | :incomplete, code :: String.t(), about :: String.t()}

  @typedoc """
  What the earlier checks established, as this module needs it:

    * `:blobs` — carried content by reference
    * `:omitted` — the first omission reason given for a reference
    * `:base?` — whether a reference is a base definition document
    * `:holds?` — `fn ref -> boolean` whether a record is signed, well
      formed and has authority
    * `:seal_cover` — which records each checked seal covers
    * `:qualifying` — the seals whose sealer has standing
  """
  @type facts :: map()

  @doc "The retention stream of the deployment a record belongs to, if its stream names one."
  @spec stream_for(Evidence.t()) :: String.t() | nil
  def stream_for(evidence) do
    case Regex.run(@deployment, evidence["stream"] || "") do
      [_, deployment] -> "urn:r5e:stream:" <> deployment <> ":retention"
      _ -> nil
    end
  end

  @doc """
  The content references in a record's body that are checked as its own
  content. A hold or a disposal names other records' content in
  `targets`; that is not content it produced.
  """
  @spec content_refs(Evidence.t()) :: [String.t()]
  def content_refs(evidence) do
    body =
      if Evidence.kind_path(evidence) in [@hold, @disposal],
        do: Map.delete(evidence["body"], "targets"),
        else: evidence["body"]

    body |> collect() |> Enum.uniq() |> Enum.filter(&Ref.valid?(&1, :bytes))
  end

  defp collect(value) when is_binary(value), do: [value]
  defp collect(value) when is_list(value), do: Enum.flat_map(value, &collect/1)
  defp collect(value) when is_map(value), do: value |> Map.values() |> Enum.flat_map(&collect/1)
  defp collect(_value), do: []

  @doc """
  One outcome for each content reference of one record.

  `opened` maps a reference to its opened record.
  """
  @spec outcomes(map(), %{String.t() => map()}, facts()) :: [raw()]
  def outcomes(%{evidence: evidence} = record, opened, facts) do
    for content <- content_refs(evidence) do
      cond do
        Map.has_key?(facts.blobs, content) or facts.base?.(content) ->
          {:ok, "ok", content}

        true ->
          missing(record, content, opened, facts)
      end
    end
  end

  # -- content that is not carried --------------------------------------------

  defp missing(%{ref: ref, evidence: evidence} = record, content, opened, facts) do
    stream = stream_for(evidence)
    on_stream = if stream, do: counting(opened, stream, facts), else: []

    covering = fn kind ->
      Enum.filter(on_stream, &(kind?(&1, kind) and covers?(&1, ref, evidence, content)))
    end

    disposals =
      @disposal
      |> covering.()
      |> Enum.filter(fn d ->
        d.evidence["body"]["action"] in ["expired", "deleted"] and
          instant(evidence) <= instant(d.evidence)
      end)
      |> Enum.sort_by(&{&1.evidence["seq"], &1.ref})

    case disposals do
      [disposal | _] -> disposed(record, disposal, covering.(@hold), on_stream, opened, facts)
      [] -> not_disposed(content, covering.(@hold), on_stream, facts)
    end
  end

  # A disposal covers the content. Rows 1 to 7, first that applies.
  defp disposed(%{evidence: evidence}, disposal, holds, on_stream, opened, facts) do
    at = instant(disposal.evidence)
    seq = disposal.evidence["seq"]

    standing =
      holds
      |> Enum.filter(fn hold ->
        hold.evidence["seq"] < seq and not released?(hold, on_stream, seq) and
          not past?(hold, at)
      end)
      |> Enum.sort_by(&{&1.evidence["seq"], &1.ref})

    seals =
      for {seal_ref, covered} <- facts.seal_cover,
          MapSet.member?(covered, disposal.ref),
          MapSet.member?(facts.qualifying, seal_ref),
          do: opened[seal_ref]

    early =
      seals |> Enum.filter(&(at > instant(&1.evidence))) |> Enum.map(& &1.ref) |> Enum.sort()

    cond do
      standing != [] ->
        {:failed, "disposed_under_hold", hd(standing).ref}

      match?({:ok, false}, allowed?(evidence, at, facts)) ->
        {:failed, "disposed_before_keep_until", disposal.ref}

      early != [] ->
        {:failed, "disposal_dated_after_its_seal", hd(early)}

      allowed?(evidence, at, facts) == :not_shown ->
        {:incomplete, "disposed_profile_not_shown", evidence["profileRef"]}

      seals == [] ->
        {:incomplete, "disposal_not_sealed", disposal.ref}

      not holds_shown?(disposal, opened, facts) ->
        {:incomplete, "disposed_holds_not_shown", disposal.ref}

      true ->
        {:incomplete, "disposed_by_record", disposal.ref}
    end
  end

  # No disposal covers it. Rows 8 to 10.
  defp not_disposed(content, holds, on_stream, facts) do
    reason = Map.get(facts.omitted, content)
    last = on_stream |> Enum.map(&instant(&1.evidence)) |> Enum.max(fn -> 0 end)

    in_force =
      holds
      |> Enum.filter(&(not released?(&1, on_stream, nil) and not past?(&1, last)))
      |> Enum.sort_by(&{&1.evidence["seq"], &1.ref})

    cond do
      reason not in ["not-selected", "withheld"] and in_force != [] ->
        {:incomplete, "missing_under_hold", hd(in_force).ref}

      reason != nil ->
        {:incomplete, "omitted_" <> String.replace(reason, "-", "_"), content}

      true ->
        {:incomplete, "not_carried", content}
    end
  end

  # -- what counts and what covers -----------------------------------------------

  # The holds, releases and disposals on a retention stream that are
  # signed, well formed and have authority.
  defp counting(opened, stream, facts) do
    for {ref, %{evidence: evidence} = record} <- opened,
        evidence["stream"] == stream,
        Regex.match?(@retention, stream),
        Evidence.kind_path(evidence) in [@hold, @release, @disposal],
        facts.holds?.(ref),
        do: record
  end

  defp kind?(record, kind), do: Evidence.kind_path(record.evidence) == kind

  defp covers?(%{evidence: %{"body" => body}}, ref, evidence, content) do
    scope = Evidence.content_scope(evidence)

    case body do
      %{"targets" => targets} when is_list(targets) -> content in targets or ref in targets
      %{"scope" => named} -> scope != nil and named == scope
      _ -> false
    end
  end

  # Whether a release of the hold counts on the stream, after the hold
  # and, when `before` is given, before that position.
  defp released?(hold, on_stream, before) do
    Enum.any?(on_stream, fn r ->
      kind?(r, @release) and r.evidence["body"]["hold"] == hold.ref and
        r.evidence["seq"] > hold.evidence["seq"] and (before == nil or r.evidence["seq"] < before)
    end)
  end

  # A hold with an end is in force up to, and not at, that instant.
  defp past?(%{evidence: %{"body" => %{"until" => until}}}, at) when is_binary(until),
    do: at >= ns(until)

  defp past?(_hold, _at), do: false

  # Whether the record's own profile allowed its content to be disposed
  # of at `at`: `{:ok, boolean}`, or `:not_shown` when the profile is not
  # carried or cannot be read.
  defp allowed?(evidence, at, facts) do
    with {:ok, bytes} <- Map.fetch(facts.blobs, evidence["profileRef"]),
         {:ok, %{} = profile} <- Canonical.decode_json(bytes),
         :ok <- Profile.validate(profile) do
      case profile["retention"] do
        %{"disposal" => "by-record", "keepContentForSeconds" => seconds} ->
          {:ok, instant(evidence) + seconds * 1_000_000_000 <= at}

        _never_or_unsaid ->
          {:ok, false}
      end
    else
      _ -> :not_shown
    end
  end

  # Every position of the retention stream up to the disposal is carried
  # once, each linked to the one before, and every hold among them
  # counts. Leaving a hold's key or grant out of the bundle must not be a
  # way to make the hold disappear.
  defp holds_shown?(disposal, opened, facts) do
    stream = disposal.evidence["stream"]
    seq = disposal.evidence["seq"]

    by_seq =
      opened
      |> Map.values()
      |> Enum.filter(&(&1.evidence["stream"] == stream and &1.evidence["seq"] <= seq))
      |> Enum.group_by(& &1.evidence["seq"])

    chain = for k <- 1..seq, do: Map.get(by_seq, k, [])

    Enum.all?(chain, &match?([_one], &1)) and
      (
        [first | _] = records = Enum.map(chain, &hd/1)

        first.evidence["previous"] == nil and
          records
          |> Enum.chunk_every(2, 1, :discard)
          |> Enum.all?(fn [a, b] -> b.evidence["previous"] == a.ref end) and
          Enum.all?(Enum.drop(records, -1), &(not kind?(&1, @hold) or facts.holds?.(&1.ref)))
      )
  end

  defp instant(evidence), do: ns(evidence["capturedAt"])

  defp ns(text) do
    case GrammarSchema.timestamp_ns(text) do
      {:ok, ns} -> ns
      :error -> 0
    end
  end
end
