defmodule Recurse.Provenance.Export do
  @moduledoc """
  The offline export bundle and its verification (contract §8).

  A bundle carries a selected set of signed records together with what a
  reader needs to check them without calling anyone: definitions and
  profiles as raw bytes, public keys, seals, membership proofs, and an
  explicit list of what was left out. It can hold one call or a bounded
  neighbourhood; it never has to hold an origin's whole history.

  `verify/2` reports in layers and never collapses them into one flag:

    1. identity and signature of each record
    2. each record's body against its definition, its profile's bounds,
       same-stream links, and the bytes behind its references
    3. seals: a complete epoch when every covered record is present,
       otherwise each supplied membership proof

  Three outcomes are kept apart for every check: it held, it failed, or
  it could not be performed with what the bundle carries. A missing key,
  an omitted record or an untrusted profile is the third kind, and is
  never reported as success.
  """

  alias Recurse.Provenance.{
    Authority,
    Definitions,
    Envelope,
    Epoch,
    Evidence,
    Profile,
    Ref,
    Retention,
    Schema,
    Start
  }

  alias RecurseVerify.Canonical

  @format "r5e.provenance-export/v2"
  @seal_path "provenance.r5e.io/v2/EpochSeal"

  @typedoc """
  One check and its outcome. `code` is a fixed word for what happened
  and `about` is the reference or key it concerns, when there is one.
  Both are part of the contract: every implementation of this verifier
  reports the same codes for the same bundle.
  """
  @type finding :: %{
          layer: 1 | 2 | 3,
          subject: String.t(),
          check: atom(),
          result: :ok | :failed | :incomplete,
          code: String.t(),
          about: String.t() | nil
        }

  # -- building ----------------------------------------------------------

  @doc """
  Assemble a bundle.

    * `:query`, `:at` — the requested selection and frontier
    * `:records` — signed envelopes (maps)
    * `:blobs` — `[{bytes, media_type | nil}]`; references are computed
    * `:keys` — `[%{key_id:, algorithm:, public_key:}]`
    * `:seals`, `:checkpoints` — evidence references among the records
    * `:proofs` — `[%{record:, seal:, index:, siblings:}]`
    * `:omissions` — `[%{ref:, reason:, detail: nil}]`
  """
  @spec build(keyword() | map()) :: {:ok, map()} | {:error, term()}
  def build(fields) do
    f = Map.new(fields)

    with {:ok, records} <- records(Map.get(f, :records, [])) do
      bundle = %{
        "format" => @format,
        "scope" => %{"query" => Map.get(f, :query, %{}), "at" => Map.get(f, :at, [])},
        "records" => records,
        "blobs" =>
          f
          |> Map.get(:blobs, [])
          |> Enum.map(fn {bytes, media_type} ->
            put_optional(
              %{"ref" => Ref.bytes(bytes), "base64" => Base.encode64(bytes)},
              "mediaType",
              media_type
            )
          end)
          |> Enum.uniq_by(& &1["ref"]),
        "keys" =>
          f
          |> Map.get(:keys, [])
          |> Enum.map(
            &%{
              "keyid" => &1.key_id,
              "algorithm" => &1.algorithm,
              "bytes" => Base.encode64(&1.public_key)
            }
          )
          |> Enum.uniq_by(& &1["keyid"]),
        "seals" => Map.get(f, :seals, []),
        "checkpoints" => Map.get(f, :checkpoints, []),
        "proofs" =>
          Enum.map(Map.get(f, :proofs, []), fn p ->
            %{
              "record" => p.record,
              "seal" => p.seal,
              "index" => p.index,
              "siblings" => p.siblings
            }
          end),
        "publicationProofs" => [],
        "omissions" =>
          Enum.map(Map.get(f, :omissions, []), fn o ->
            put_optional(%{"ref" => o.ref, "reason" => o.reason}, "detail", o[:detail])
          end)
      }

      case Schema.validate(Definitions.export_schema(), bundle) do
        :ok -> {:ok, bundle}
        {:error, problems} -> {:error, {:malformed_export, problems}}
      end
    end
  end

  defp records(envelopes) do
    Enum.reduce_while(envelopes, {:ok, []}, fn envelope, {:ok, acc} ->
      case Envelope.open(envelope) do
        {:ok, %{ref: ref}} -> {:cont, {:ok, acc ++ [%{"ref" => ref, "envelope" => envelope}]}}
        {:error, reason} -> {:halt, {:error, {:unreadable_record, reason}}}
      end
    end)
  end

  # -- verifying ---------------------------------------------------------

  @report_format "r5e.provenance-verify-report/v2"

  @doc """
  Verify a bundle offline.

  Options:

    * `:trusted_profiles` — `profileRef`s the reader accepts as in force.
      Without one, authority is reported as unestablished.
    * `:trusted_publishers` — the publishers whose word the reader takes
      for which definition belongs to which kind. Each is a key id, or a
      key id, `=` and a comma-separated list of domains
      (`key:…=r5e.io,example.com`). With domains, the publisher is
      believed only about kinds whose group is one of those domains or
      lies under one, so a customer's publisher cannot speak for r5e's
      kinds on the strength of being trusted for its own. A bare key id
      is believed about every kind. Without any publisher, whose
      definition a record cites is reported as unestablished.
    * `:definitions` — `schemaRef -> {:ok, bytes}` for definition
      documents the reader has installed beyond the base set and the
      bundle's blobs.

  With `:trusted_roots` (a list of key ids), each record's authority is
  established by following endorsements and badges from those keys
  (`Recurse.Provenance.Authority`); without it, from `:trusted_profiles`.

  Returns `%{findings: [...], summary: %{ok:, failed:, incomplete:}}`,
  with findings in a fixed order.
  """
  @spec verify(map(), keyword()) :: %{findings: [finding()], summary: map()}
  def verify(bundle, opts \\ []) do
    {findings, start} =
      with :ok <- Schema.validate(Definitions.export_schema(), bundle),
           refs = Enum.map(bundle["records"], & &1["ref"]),
           true <- refs == Enum.uniq(refs) do
        verify_bundle(bundle, opts)
      else
        # Two entries under one reference would report under one subject
        # and could not be told apart.
        _ -> {[finding(1, "bundle", :shape, :failed, "malformed_bundle")], nil}
      end

    findings =
      Enum.sort_by(
        findings,
        &{&1.layer, &1.subject, Atom.to_string(&1.check), &1.code, &1.about || ""}
      )

    %{
      start: start,
      findings: findings,
      summary: %{
        ok: Enum.count(findings, &(&1.result == :ok)),
        failed: Enum.count(findings, &(&1.result == :failed)),
        incomplete: Enum.count(findings, &(&1.result == :incomplete))
      }
    }
  end

  @doc "Whether a report has no failed check. Incomplete checks are not failures and not successes."
  @spec sound?(%{summary: map()}) :: boolean()
  def sound?(%{summary: %{failed: failed}}), do: failed == 0

  @doc """
  The report as a plain JSON value, the same from every implementation
  for the same bundle and trust input.
  """
  @spec report(%{findings: [finding()], summary: map()}) :: map()
  def report(%{findings: findings, summary: summary} = result) do
    # How far the carried start stream goes is part of the report, so a
    # reader can see when a file stops short of what they expected.
    start = if head = Map.get(result, :start), do: %{"start" => head}, else: %{}

    Map.merge(start, %{
      "format" => @report_format,
      "summary" => %{
        "ok" => summary.ok,
        "failed" => summary.failed,
        "incomplete" => summary.incomplete
      },
      "findings" =>
        Enum.map(findings, fn f ->
          %{
            "layer" => f.layer,
            "subject" => f.subject,
            "check" => Atom.to_string(f.check),
            "result" => Atom.to_string(f.result),
            "code" => f.code,
            "about" => f.about
          }
        end)
    })
  end

  @doc "The report in Core canonical JSON bytes."
  @spec report_json(%{findings: [finding()], summary: map()}) :: binary()
  def report_json(result), do: Canonical.encode(report(result))

  defp verify_bundle(bundle, opts) do
    {blobs, blob_findings} = blobs(bundle["blobs"])
    {keys, key_findings} = keys(bundle["keys"])
    # The first reason given for a reference is the one reported.
    omitted =
      Enum.reduce(bundle["omissions"], %{}, &Map.put_new(&2, &1["ref"], &1["reason"]))

    trusted = MapSet.new(Keyword.get(opts, :trusted_profiles, []))

    ctx = %{
      blobs: blobs,
      keys: keys,
      omitted: omitted,
      trusted: trusted,
      roots: Keyword.get(opts, :trusted_roots),
      chain: Keyword.get(opts, :trusted_chain),
      opts: opts
    }

    {opened, record_findings} =
      Enum.reduce(bundle["records"], {%{}, []}, fn entry, {opened, acc} ->
        case layer1(entry, ctx) do
          {:ok, record, fs} -> {Map.put(opened, record.ref, record), acc ++ fs}
          {:error, fs} -> {opened, acc ++ fs}
        end
      end)

    signature_results =
      for %{check: :signature, subject: s, result: r} <- record_findings, reduce: %{} do
        acc -> Map.update(acc, s, [r], &[r | &1])
      end

    ctx =
      ctx
      |> Map.put(:signature_results, signature_results)
      |> Map.put(:records, opened)
      |> Map.put(:publications, publications(opened, keys))
      |> Map.put(:publishers, publishers(Keyword.get(opts, :trusted_publishers, [])))

    findings =
      blob_findings ++
        key_findings ++
        record_findings ++
        Enum.flat_map(Map.values(opened), &layer2(&1, ctx)) ++
        stream_links(opened) ++
        (bundle
         |> seals_to_check()
         |> Enum.flat_map(&layer3_seal(&1, ctx))
         |> one_line(bundle, ctx)) ++
        Enum.flat_map(bundle["proofs"], &layer3_proof(&1, ctx))

    held = fn ref ->
      body = Enum.find(findings, &(&1.check == :body and &1.subject == ref))
      %{body: body && body.result, signatures: Map.get(signature_results, ref, [])}
    end

    {records, seal_cover} = for_authority(opened, findings, ctx)

    start =
      Start.check(opened, held,
        trusted_roots: ctx.roots,
        trusted_chain: ctx.chain,
        min_start_seq: Keyword.get(opts, :min_start_seq),
        binding: &binding(&1, &2, &3, &4, &5, records, seal_cover)
      )

    start_findings =
      for {subject, result, code, about} <- start.findings,
          do: finding(2, subject, :start, result, code, about)

    findings = findings ++ start_findings ++ authority(records, seal_cover, ctx, start)
    {findings ++ content(opened, findings, records, seal_cover, ctx, start), start.head}
  end

  # Authority from the reader's trusted roots or pinned chain (amendment
  # A5). With neither, authority comes from the profile and nothing is
  # produced here.
  defp authority(_records, _seal_cover, %{roots: nil, chain: nil}, _start), do: []

  # A reader who pins a chain by name gets the roots that chain declared
  # and each one's time as a root, once the start is established. If the
  # start could not be established for want of something in the file,
  # nothing under it is established either, and that is said as such; if
  # the start failed, nothing has standing.
  defp authority(records, seal_cover, %{roots: nil} = ctx, start) do
    case start.state do
      :established ->
        walk(records, start.tenures, seal_cover)

      :failed ->
        walk(records, [], seal_cover)

      _incomplete ->
        for %{subject: ref} <- walk(records, [], seal_cover),
            do: finding(2, ref, :authority, :incomplete, "chain_not_carried", ctx.chain)
    end
  end

  # Pinned root keys: each for all time, except one the carried start
  # stream shows was removed.
  defp authority(records, seal_cover, _ctx, start), do: walk(records, start.tenures, seal_cover)

  defp walk(records, roots, seal_cover) do
    for {ref, {result, code, about}} <- Authority.outcomes(records, roots, seal_cover) do
      finding(2, ref, :authority, result, code, about)
    end
  end

  # What the authority walk reads from the earlier checks: which records
  # are signed and well formed, and which records each seal was shown to
  # cover.
  defp for_authority(opened, findings, ctx) do
    held = fn check ->
      for %{check: ^check, subject: s, result: r} <- findings, reduce: %{} do
        acc -> Map.update(acc, s, r == :ok, &(&1 and r == :ok))
      end
    end

    signed = held.(:signature)
    body = held.(:body)

    broken =
      for %{check: check, subject: s, result: :failed} <- findings,
          check in [:signature, :body],
          into: MapSet.new(),
          do: s

    # A record whose kind asks for more signers than it carries is not
    # judged on the signers it happens to have.
    miscounted =
      for %{check: :body, code: "signature_count_differs_from_definition", subject: s} <- findings,
          into: MapSet.new(),
          do: s

    records =
      Map.new(opened, fn {ref, record} ->
        {ref,
         %{
           ref: ref,
           evidence: record.evidence,
           signed?: Map.get(signed, ref, false),
           body_ok?: Map.get(body, ref, false),
           broken?: MapSet.member?(broken, ref),
           signers: Envelope.signers(record),
           count_differs?: MapSet.member?(miscounted, ref)
         }}
      end)

    by_epoch =
      for %{check: :epoch, result: :ok, subject: seal_ref} <- findings,
          {:ok, bytes} <- [Map.fetch(ctx.blobs, opened[seal_ref].evidence["body"]["manifestRef"])],
          {:ok, %{"events" => events}} <- [Canonical.decode_json(bytes)],
          do: {seal_ref, events}

    by_proof =
      for %{check: :membership, result: :ok, subject: record, about: seal_ref} <- findings,
          do: {seal_ref, [record]}

    # A seal out of line with its stream's other seals shows nothing.
    out_of_line =
      for %{check: :seal_chain, result: :failed, subject: seal_ref} <- findings,
          into: MapSet.new(),
          do: seal_ref

    seal_cover =
      (by_epoch ++ by_proof)
      |> Enum.reject(fn {seal_ref, _refs} -> MapSet.member?(out_of_line, seal_ref) end)
      |> Enum.reduce(%{}, fn {seal_ref, refs}, acc ->
        Map.update(acc, seal_ref, MapSet.new(refs), &MapSet.union(&1, MapSet.new(refs)))
      end)

    {records, seal_cover}
  end

  # What became of each piece of content a record refers to. This comes
  # last, because whether a hold or a disposal counts depends on its
  # signatures, its body and its authority, and whether a disposal is
  # fixed in time depends on the seals.
  defp content(opened, findings, records, seal_cover, ctx, start) do
    sound =
      for %{check: check, subject: s, result: r} <- findings,
          check in [:signature, :body, :authority],
          reduce: %{} do
        acc -> Map.update(acc, s, MapSet.new([{check, r}]), &MapSet.put(&1, {check, r}))
      end

    holds? = fn ref ->
      seen = Map.get(sound, ref, MapSet.new())

      Enum.all?([:signature, :body, :authority], fn check ->
        Enum.any?(seen, &(elem(&1, 0) == check))
      end) and Enum.all?(seen, &(elem(&1, 1) == :ok))
    end

    qualifying =
      cond do
        ctx.roots == nil and ctx.chain == nil ->
          # Authority from the profile: a seal qualifies when its sealer
          # is authorised by a profile the reader trusts.
          for {seal_ref, _} <- seal_cover,
              holds?.(seal_ref),
              Enum.all?(findings, fn f ->
                f.subject != seal_ref or f.check not in [:sealer, :profile_bounds] or
                  f.result == :ok
              end),
              into: MapSet.new(),
              do: seal_ref

        ctx.roots == nil and start.state != :established ->
          MapSet.new()

        true ->
          Authority.qualifying_seals(records, start.tenures, seal_cover)
      end

    facts = %{
      blobs: ctx.blobs,
      omitted: ctx.omitted,
      base?: &Definitions.base_document?/1,
      holds?: holds?,
      seal_cover: seal_cover,
      qualifying: qualifying
    }

    for {ref, record} <- opened,
        {result, code, about} <- Retention.outcomes(record, opened, facts) do
      finding(2, ref, :content, result, code, about)
    end
  end

  @endorsement_path "provenance.r5e.io/v2/Endorsement"
  @revocation_path "provenance.r5e.io/v2/Revocation"
  @approval_path "provenance.r5e.io/v2/RootChangeApproval"

  # Whether a person's own key, not named in a deployment's terms, was
  # bound to them by one of the roots then in force, and shown to have
  # been before the change it is used to approve. The showing is a seal
  # made before the change by a sealer who stood under those same roots.
  defp binding(key, who, terms, approval, change, records, seal_cover) do
    roots = Enum.map(terms["roots"], & &1["key"])
    changed = instant(change["capturedAt"])
    approved = instant(approval["capturedAt"])

    revoked? = fn ref ->
      Enum.any?(records, fn {_ref, r} ->
        r.signed? and r.body_ok? and Evidence.kind_path(r.evidence) == @revocation_path and
          r.evidence["body"]["target"] == ref and r.evidence["issuer"] in roots and
          instant(r.evidence["capturedAt"]) <= changed
      end)
    end

    bindings =
      for {ref, %{signed?: true, body_ok?: true, evidence: e}} <- records,
          Evidence.kind_path(e) == @endorsement_path,
          body = e["body"],
          is_nil(body["parent"]),
          e["issuer"] in roots,
          body["subject"] == key,
          body["actsFor"] == who,
          @approval_path in body["kinds"],
          instant(body["notBefore"]) <= approved and approved <= instant(body["notAfter"]),
          not revoked?.(ref),
          do: {ref, instant(e["capturedAt"])}

    standing = Authority.outcomes(records, roots, seal_cover)

    sealed? = fn ref ->
      Enum.any?(seal_cover, fn {seal_ref, covered} ->
        MapSet.member?(covered, ref) and match?({:ok, _, _}, standing[seal_ref]) and
          instant(records[seal_ref].evidence["capturedAt"]) < changed
      end)
    end

    earlier = for {ref, at} <- bindings, at < changed, do: ref

    cond do
      Enum.any?(bindings, fn {ref, _at} -> sealed?.(ref) end) -> :bound
      earlier != [] -> {:unsealed, Enum.min(earlier)}
      true -> :none
    end
  end

  defp instant(text) do
    case Recurse.Provenance.Grammar.Schema.timestamp_ns(text) do
      {:ok, ns} -> ns
      :error -> 0
    end
  end

  defp blobs(entries) do
    Enum.reduce(entries, {%{}, []}, fn %{"ref" => ref, "base64" => b64}, {map, fs} ->
      case Base.decode64(b64) do
        {:ok, bytes} ->
          if Ref.matches?(ref, bytes),
            do: {Map.put(map, ref, bytes), fs},
            else:
              {map,
               fs ++ [finding(2, ref, :content_hash, :failed, "bytes_do_not_match_reference")]}

        :error ->
          {map, fs ++ [finding(2, ref, :content_hash, :failed, "invalid_base64")]}
      end
    end)
  end

  defp keys(entries) do
    Enum.reduce(entries, {%{}, []}, fn %{"keyid" => id, "algorithm" => alg, "bytes" => b64},
                                       {map, fs} ->
      with {:ok, bytes} <- Base.decode64(b64),
           false <- Map.has_key?(map, id) and map[id].bytes != bytes do
        {Map.put(map, id, %{algorithm: alg, bytes: bytes}), fs}
      else
        _ -> {map, fs ++ [finding(1, id, :key, :failed, "conflicting_or_unreadable_key")]}
      end
    end)
  end

  # Layer 1: the record is what its reference says, and its issuer signed it.
  defp layer1(%{"ref" => ref, "envelope" => envelope}, ctx) do
    case Envelope.open(envelope) do
      {:ok, %{ref: ^ref} = record} ->
        signatures =
          for {keyid, result} <- Envelope.verify_each(record, ctx.keys),
              do: signature_finding(ref, keyid, result)

        {:ok, record, [finding(1, ref, :identity, :ok, "ok") | signatures]}

      {:ok, %{ref: actual}} ->
        {:error,
         [finding(1, ref, :identity, :failed, "payload_hashes_to_another_reference", actual)]}

      {:error, reason} ->
        {:error, [finding(1, ref, :identity, :failed, open_code(reason))]}
    end
  end

  defp signature_finding(ref, keyid, :ok), do: finding(1, ref, :signature, :ok, "ok", keyid)

  defp signature_finding(ref, keyid, {:error, :missing_key}),
    do: finding(1, ref, :signature, :incomplete, "missing_key", keyid)

  defp signature_finding(ref, keyid, {:error, reason}),
    do: finding(1, ref, :signature, :failed, Atom.to_string(reason), keyid)

  defp open_code({:malformed_envelope, _problems}), do: "malformed_envelope"
  defp open_code({:noncanonical_base64, _what}), do: "invalid_base64"
  defp open_code({:invalid_base64, _what}), do: "invalid_base64"
  defp open_code({:payload_not_canonical, _reason}), do: "payload_not_canonical"
  defp open_code(reason) when is_atom(reason), do: Atom.to_string(reason)

  # Layer 2: body, profile bounds, authority, and the bytes behind references.
  defp layer2(%{ref: ref, evidence: evidence} = record, ctx) do
    definitions = fn schema_ref -> definition(schema_ref, ctx) end

    body =
      case envelope_then_body(evidence, definitions, Envelope.signers(record)) do
        :envelope ->
          finding(2, ref, :body, :failed, "envelope_does_not_match_schema")

        {:ok, :validated} ->
          finding(2, ref, :body, :ok, "ok", Evidence.kind_path(evidence))

        {:ok, :body_unsupported} ->
          finding(2, ref, :body, :incomplete, "definition_not_available", evidence["schemaRef"])

        {:error, [{path, _message} | _]} ->
          finding(2, ref, :body, :failed, body_code(path))
      end

    [body, publication(ref, evidence, ctx, body.result)] ++
      profile(ref, evidence, ctx)
  end

  @publication_path "provenance.r5e.io/v2/DefinitionPublished"

  # Every carried, correctly signed statement of "this kind's definition
  # is this document", with who made it. A publication whose signature
  # cannot be checked says nothing.
  defp publications(opened, keys) do
    for %{ref: ref, evidence: evidence} = record <- Map.values(opened),
        Evidence.kind_path(evidence) == @publication_path,
        Envelope.verify(record, keys) == :ok,
        %{"kind" => kind, "definition" => definition} <-
          List.wrap(evidence["body"]["definitions"]),
        do: %{ref: ref, issuer: evidence["issuer"], kind: kind, definition: definition}
  end

  # A definition is identified by its content, so anyone can carry one
  # under any kind name. Whose it is comes from a publisher the reader
  # trusts having said so.
  @chain_started_path "provenance.r5e.io/v2/ChainStarted"

  # A start record names the publication the node was built from. That
  # claim is checked against the publication itself: it must be carried,
  # be by the publisher named, and list exactly the definitions the start
  # record restates, before the reader's trust in that publisher counts.
  defp publication(
         ref,
         %{"kind" => "ChainStarted", "body" => body} = evidence,
         %{publishers: publishers} = ctx,
         :ok
       ) do
    cited = body["publication"]
    record = ctx.records[cited]
    signatures = Map.get(ctx.signature_results, cited, [])
    pairs = fn list -> MapSet.new(list, &{&1["kind"], &1["definition"]}) end
    kinds = Enum.map(body["definitions"], & &1["kind"])

    {result, code} =
      cond do
        Evidence.kind_path(evidence) != @chain_started_path ->
          {nil, nil}

        record == nil ->
          {:incomplete, "publication_not_carried"}

        Evidence.kind_path(record.evidence) != @publication_path or
          not body_ok?(record, ctx) or record.evidence["issuer"] != body["publisher"] or
            :failed in signatures ->
          {:failed, "cited_publication_mismatch"}

        :incomplete in signatures ->
          {:incomplete, "publication_not_verified"}

        kinds != Enum.uniq(kinds) or
          pairs.(body["definitions"]) != pairs.(record.evidence["body"]["definitions"]) or
            {@chain_started_path, evidence["schemaRef"]} not in pairs.(body["definitions"]) ->
          {:failed, "definitions_differ_from_publication"}

        not Enum.all?(kinds, &speaks_for?(publishers, body["publisher"], &1)) ->
          {:incomplete, "publisher_not_trusted"}

        true ->
          {:ok, "ok"}
      end

    if result,
      do: finding(2, ref, :publication, result, code, cited),
      else: publication(ref, evidence, ctx, nil)
  end

  defp publication(ref, evidence, ctx, _body) do
    kind = Evidence.kind_path(evidence)
    cited = evidence["schemaRef"]
    for_kind = ctx.publications |> Enum.filter(&(&1.kind == kind)) |> Enum.sort_by(& &1.ref)
    {trusted, others} = Enum.split_with(for_kind, &speaks_for?(ctx.publishers, &1.issuer, kind))

    # A publication is itself a claim to be a publisher. One made by a key
    # the reader does not trust as a publisher establishes nothing, however
    # well formed, and must not pass as "ok" on the strength of a trusted
    # publisher having published the publication kind. The same holds for
    # a publisher the reader believes about some domains that here speaks
    # about a kind outside them: the whole statement is one it was not
    # trusted to make.
    stranger? =
      kind == @publication_path and
        not Enum.all?(
          for(
            %{"kind" => k} when is_binary(k) <- List.wrap(evidence["body"]["definitions"]),
            do: k
          ),
          &speaks_for?(ctx.publishers, evidence["issuer"], &1)
        )

    cond do
      stranger? ->
        finding(2, ref, :publication, :incomplete, "publisher_not_trusted", ref)

      found = Enum.find(trusted, &(&1.definition == cited)) ->
        finding(2, ref, :publication, :ok, "ok", found.ref)

      # A trusted publisher has spoken for this kind, and not for this document.
      trusted != [] ->
        finding(
          2,
          ref,
          :publication,
          :failed,
          "definition_differs_from_published",
          hd(trusted).ref
        )

      found = Enum.find(others, &(&1.definition == cited)) ->
        finding(2, ref, :publication, :incomplete, "publisher_not_trusted", found.ref)

      true ->
        finding(2, ref, :publication, :incomplete, "publication_not_carried", cited)
    end
  end

  # The reader's publishers, as key id to `:every` or the domains the key
  # is believed about. A key given more than once is believed about the
  # union.
  defp publishers(entries) do
    Enum.reduce(entries, %{}, fn entry, acc ->
      {key, scope} =
        case String.split(entry, "=", parts: 2) do
          [key] -> {key, :every}
          [key, domains] -> {key, String.split(domains, ",", trim: true)}
        end

      Map.update(acc, key, scope, fn
        :every -> :every
        _held when scope == :every -> :every
        held -> Enum.uniq(held ++ scope)
      end)
    end)
  end

  # Whether the reader takes this publisher's word about this kind. A
  # kind path begins with its group, a domain name; the publisher speaks
  # for it when the group is one of its domains or a name under one.
  defp speaks_for?(publishers, issuer, kind) do
    case publishers do
      %{^issuer => :every} ->
        true

      %{^issuer => domains} ->
        [group | _] = String.split(kind, "/", parts: 2)
        Enum.any?(domains, &(group == &1 or String.ends_with?(group, "." <> &1)))

      _ ->
        false
    end
  end

  defp body_ok?(record, ctx) do
    definitions = fn schema_ref -> definition(schema_ref, ctx) end

    match?(
      {:ok, :validated},
      envelope_then_body(record.evidence, definitions, Envelope.signers(record))
    )
  end

  # The common fields are checked first and on their own, so a failure
  # there is never mistaken for one of the later, named rules.
  defp envelope_then_body(evidence, definitions, signers) do
    case Schema.validate(Definitions.envelope_schema(), evidence) do
      :ok -> Evidence.validate(evidence, definitions: definitions, signers: signers)
      {:error, _problems} -> :envelope
    end
  end

  # Which rule was broken. The wording of a validator's message is not
  # part of the contract; this word is.
  defp body_code("/causes" <> _), do: "causes_not_sorted_and_unique"
  defp body_code("/schemaRef" <> _), do: "definition_is_for_another_kind"
  defp body_code("/session" <> _), do: "session_differs_from_body"
  defp body_code("/signatures" <> _), do: "signature_count_differs_from_definition"
  defp body_code("/body" <> _), do: "body_does_not_match_definition"

  # A definition document: one the reader installed, else one carried as
  # a blob. Either way it is used only if its bytes hash to the
  # reference asked for.
  defp definition(schema_ref, ctx) do
    installed = Keyword.get(ctx.opts, :definitions, fn _ -> :error end)

    case installed.(schema_ref) do
      {:ok, bytes} when is_binary(bytes) -> {:ok, bytes}
      _ -> Map.fetch(ctx.blobs, schema_ref)
    end
  end

  defp profile(ref, evidence, ctx) do
    profile_ref = evidence["profileRef"]

    with {:ok, bytes} <- Map.fetch(ctx.blobs, profile_ref),
         {:ok, profile} when is_map(profile) <- Canonical.decode_json(bytes),
         :ok <- Profile.validate(profile) do
      bounds =
        case Profile.check(profile, evidence) do
          :ok ->
            finding(2, ref, :profile_bounds, :ok, "ok", profile_ref)

          {:error, reason} ->
            finding(2, ref, :profile_bounds, :failed, Atom.to_string(reason), profile_ref)
        end

      authority =
        if MapSet.member?(ctx.trusted, profile_ref),
          do: finding(2, ref, :authority, :ok, "ok", profile_ref),
          else: finding(2, ref, :authority, :incomplete, "profile_not_trusted", profile_ref)

      # With trusted roots, authority comes from the chain of records
      # and the profile says only what the operator claims.
      if ctx.roots || ctx.chain, do: [bounds], else: [bounds, authority]
    else
      :error ->
        [finding(2, ref, :profile_bounds, :incomplete, "profile_not_available", profile_ref)]

      _ ->
        [finding(2, ref, :profile_bounds, :failed, "unreadable_profile", profile_ref)]
    end
  end

  # Adjacent positions of one stream must link; two payloads at one
  # position are a fork, whatever else is true of them.
  defp stream_links(opened) do
    opened
    |> Map.values()
    |> Enum.group_by(& &1.evidence["stream"])
    |> Enum.flat_map(fn {stream, records} ->
      by_seq = Enum.group_by(records, & &1.evidence["seq"])

      forks =
        for {seq, [_, _ | _]} <- by_seq,
            do: finding(2, stream, :fork, :failed, "two_records_at_one_position", "seq:#{seq}")

      links =
        for {seq, [record]} <- by_seq, [prior] <- [Map.get(by_seq, seq - 1, :none)] do
          if record.evidence["previous"] == prior.ref,
            do: finding(2, record.ref, :previous, :ok, "ok", prior.ref),
            else:
              finding(
                2,
                record.ref,
                :previous,
                :failed,
                "previous_is_not_the_prior_record",
                prior.ref
              )
        end

      forks ++ links
    end)
  end

  # A seal is checked when the bundle lists it and also when a proof
  # rests on it. A proof says a record is under a root; that is worth
  # nothing unless whoever signed the root was allowed to seal, so a
  # bundle cannot avoid that question by leaving the seal off its list.
  defp seals_to_check(bundle),
    do: Enum.uniq(bundle["seals"] ++ Enum.map(bundle["proofs"], & &1["seal"]))

  # Layer 3: a seal, complete when its manifest and every covered record are here.
  defp layer3_seal(seal_ref, ctx) do
    with {:ok, %{evidence: seal}} <- Map.fetch(ctx.records, seal_ref),
         true <- Evidence.kind_path(seal) == @seal_path || :not_a_seal do
      body = seal["body"]

      [sealer(seal_ref, seal, ctx)] ++
        complete(seal_ref, body, ctx) ++ predecessor(seal_ref, body, ctx)
    else
      :error -> [finding(3, seal_ref, :seal, :incomplete, "seal_record_not_carried")]
      :not_a_seal -> [finding(3, seal_ref, :seal, :failed, "not_an_epoch_seal")]
    end
  end

  # Two seals of one stream that cover any position in common cannot both
  # be on the line, whatever each says of its predecessor: a sealer could
  # otherwise seal positions 1 to 5 and, later and without contradiction
  # on its own stream, seal 1 to 3 again over different records. Neither
  # can be preferred from the bundle alone, so both fail, each about the
  # other. A seal that already failed on its predecessor keeps that
  # finding.
  defp one_line(findings, bundle, ctx) do
    ranges =
      for ref <- seals_to_check(bundle),
          %{
            evidence:
              %{"body" => %{"stream" => stream, "firstSeq" => first, "lastSeq" => last}} = seal
          } <-
            [ctx.records[ref]],
          Evidence.kind_path(seal) == @seal_path,
          is_integer(first) and is_integer(last),
          do: {ref, stream, first, last}

    overlapping =
      for {ref, stream, first, last} <- ranges,
          others =
            for({other, ^stream, f, l} <- ranges, other != ref, f <= last, first <= l, do: other),
          others != [],
          into: %{},
          do: {ref, Enum.min(others)}

    already_failed =
      for %{check: :seal_chain, result: :failed, subject: ref} <- findings,
          into: MapSet.new(),
          do: ref

    kept =
      Enum.reject(findings, fn f ->
        f.check == :seal_chain and f.result == :ok and is_map_key(overlapping, f.subject)
      end)

    kept ++
      for {ref, other} <- Enum.sort(overlapping),
          not MapSet.member?(already_failed, ref),
          do: finding(3, ref, :seal_chain, :failed, "seal_ranges_overlap", other)
  end

  # A stream's seals form one line: the first covers position 1 and names
  # no seal before it; every later one names the seal whose range ends
  # just before its own begins. A seal that breaks this is refused, since
  # it would let a stream be sealed with positions left out between two
  # seals. When the named seal is not carried there is nothing to compare
  # and nothing is reported, as with a record whose predecessor is absent.
  defp predecessor(seal_ref, %{"firstSeq" => 1} = body, _ctx) do
    if is_map_key(body, "previousSeal"),
      do: [finding(3, seal_ref, :seal_chain, :failed, "first_seal_names_a_predecessor")],
      else: []
  end

  defp predecessor(seal_ref, %{"previousSeal" => previous} = body, ctx) do
    case Map.fetch(ctx.records, previous) do
      {:ok, %{evidence: %{"body" => %{"stream" => stream, "lastSeq" => last}} = before}} ->
        if Evidence.kind_path(before) == @seal_path and stream == body["stream"] and
             last + 1 == body["firstSeq"],
           do: [finding(3, seal_ref, :seal_chain, :ok, "ok", previous)],
           else: [
             finding(
               3,
               seal_ref,
               :seal_chain,
               :failed,
               "seal_predecessor_does_not_adjoin",
               previous
             )
           ]

      {:ok, _not_a_seal} ->
        [finding(3, seal_ref, :seal_chain, :failed, "seal_predecessor_does_not_adjoin", previous)]

      :error ->
        []
    end
  end

  defp predecessor(seal_ref, _body, _ctx),
    do: [finding(3, seal_ref, :seal_chain, :failed, "seal_predecessor_missing")]

  defp sealer(seal_ref, seal, ctx) do
    with {:ok, bytes} <- Map.fetch(ctx.blobs, seal["profileRef"]),
         {:ok, profile} <- Canonical.decode_json(bytes) do
      if Profile.sealer?(profile, seal["body"]["stream"], seal["issuer"]),
        do: finding(3, seal_ref, :sealer, :ok, "ok", seal["issuer"]),
        else: finding(3, seal_ref, :sealer, :failed, "unauthorized_seal", seal["issuer"])
    else
      _ -> finding(3, seal_ref, :sealer, :incomplete, "profile_not_available", seal["profileRef"])
    end
  end

  defp complete(seal_ref, body, ctx) do
    with {:ok, bytes} <- Map.fetch(ctx.blobs, body["manifestRef"]),
         {:ok, manifest} <- Canonical.decode_json(bytes),
         :ok <- Schema.validate(Definitions.manifest_schema(), manifest),
         records = Enum.map(manifest["events"], &Map.get(ctx.records, &1)),
         false <- Enum.any?(records, &is_nil/1) do
      case prior_last(body, records) do
        :unknown ->
          [finding(3, seal_ref, :epoch, :incomplete, "record_before_range_not_carried")]

        prior ->
          case Epoch.check_complete(body, manifest, records, prior) do
            :ok ->
              [
                finding(
                  3,
                  seal_ref,
                  :epoch,
                  :ok,
                  "ok",
                  "seq:#{body["firstSeq"]}-#{body["lastSeq"]}"
                )
              ]

            {:error, reason} ->
              [finding(3, seal_ref, :epoch, :failed, "epoch_" <> Atom.to_string(reason))]
          end
      end
    else
      true ->
        [finding(3, seal_ref, :epoch, :incomplete, "not_every_covered_record_is_carried")]

      :error ->
        [finding(3, seal_ref, :epoch, :incomplete, "manifest_not_carried", body["manifestRef"])]

      _ ->
        [finding(3, seal_ref, :epoch, :failed, "unreadable_manifest", body["manifestRef"])]
    end
  end

  # The record before a seal's range: nil at the start of a stream;
  # otherwise the first covered record's own `previous`, which the chain
  # check then holds the rest to.
  defp prior_last(%{"firstSeq" => 1}, _records), do: nil
  defp prior_last(_body, [%{evidence: %{"previous" => previous}} | _]), do: previous
  defp prior_last(_body, _records), do: :unknown

  # A membership proof for one named record under one carried seal.
  defp layer3_proof(
         %{"record" => record, "seal" => seal_ref, "index" => index, "siblings" => siblings},
         ctx
       ) do
    with {:ok, %{evidence: seal}} <- Map.fetch(ctx.records, seal_ref),
         {:ok, %{evidence: evidence}} <- Map.fetch(ctx.records, record) do
      body = seal["body"]
      size = body["lastSeq"] - body["firstSeq"] + 1

      cond do
        evidence["stream"] != body["stream"] or evidence["seq"] != body["firstSeq"] + index ->
          [finding(3, record, :membership, :failed, "position_does_not_match_seal", seal_ref)]

        Epoch.verify_proof(record, index, size, siblings, body["root"]) ->
          [finding(3, record, :membership, :ok, "ok", seal_ref)]

        true ->
          [finding(3, record, :membership, :failed, "proof_does_not_reach_root", seal_ref)]
      end
    else
      :error ->
        [finding(3, record, :membership, :incomplete, "seal_or_record_not_carried", seal_ref)]
    end
  end

  defp finding(layer, subject, check, result, code, about \\ nil),
    do: %{layer: layer, subject: subject, check: check, result: result, code: code, about: about}

  defp put_optional(map, _key, nil), do: map
  defp put_optional(map, key, value), do: Map.put(map, key, value)
end
