defmodule Recurse.Provenance.Exporter do
  @moduledoc """
  Assemble an offline bundle from the index.

  Given a selection, this gathers everything a stranger needs to check
  it without calling anyone: the signed records, the profile and
  definitions they cite, the public keys of their issuers, the seals
  that cover them with the proof that each record is inside its seal,
  and the content they refer to.

  What is selected but cannot be supplied is named as an omission. A
  bundle never implies it carries something it does not.

  A record that no seal covers yet is still exported; it simply arrives
  without a seal, and the verifier reports that.
  """

  alias Recurse.Provenance.{Epoch, Evidence, Export, Ref}

  @type index :: {module(), term()}

  @doc """
  Export every record of a session.

  Options:

    * `:content` — `true` (default) carries the content records refer
      to; `false` lists it as withheld; a `MapSet` of content references
      carries those and lists the rest as withheld.
  """
  @spec session(index(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def session({module, handle} = index, session, opts \\ []) do
    with {:ok, entries} <- module.by_session(handle, session) do
      bundle(index, entries, %{"session" => session}, opts)
    end
  end

  @doc "Export an explicit list of record entries, as returned by the index."
  @spec bundle(index(), [map()], map(), keyword()) :: {:ok, map()} | {:error, term()}
  def bundle({module, handle} = index, entries, query, opts \\ []) do
    selected = MapSet.new(entries, & &1.ref)
    {seals, proofs, manifests, extra} = coverage(index, entries, selected)
    records = Enum.uniq_by(entries ++ extra ++ seals, & &1.ref)

    all_content = content_refs(entries)

    wanted_content =
      case Keyword.get(opts, :content, true) do
        true -> all_content
        false -> []
        %MapSet{} = only -> Enum.filter(all_content, &MapSet.member?(only, &1))
      end

    definition_refs =
      records
      |> Enum.flat_map(&[&1.evidence["profileRef"], &1.evidence["schemaRef"]])
      |> Enum.uniq()

    # Structure is read as it is. Content is read only as a record that
    # refers to it may read it: through that record's own scope.
    scopes =
      for entry <- entries,
          ref <- content_refs([entry]),
          reduce: %{} do
        acc ->
          Map.update(
            acc,
            ref,
            [Evidence.content_scope(entry.evidence)],
            &[Evidence.content_scope(entry.evidence) | &1]
          )
      end

    {structure, missing_structure} = fetch_blobs(index, Enum.uniq(definition_refs ++ manifests))

    {content, missing_content} =
      fetch_content(index, for(ref <- wanted_content, do: {ref, Enum.uniq(scopes[ref])}))

    blobs = structure ++ content
    missing = missing_structure ++ missing_content

    withheld = for ref <- all_content -- wanted_content, do: %{ref: ref, reason: "withheld"}

    # A seal that covers more than was selected is carried with a proof
    # for each selected record. Its manifest lists every covered record
    # and is left out on purpose, which the bundle says.
    unselected =
      for seal <- seals,
          ref = seal.evidence["body"]["manifestRef"],
          ref not in manifests,
          do: %{ref: ref, reason: "not-selected"}

    keys =
      for key_id <- records |> Enum.map(& &1.evidence["issuer"]) |> Enum.uniq(),
          {:ok, key} <- [module.get_key(handle, key_id)],
          do: key

    Export.build(
      query: query,
      at: frontier(entries),
      records: Enum.map(records, & &1.envelope),
      blobs: Enum.map(blobs, &{&1, nil}),
      keys: keys,
      seals: Enum.map(seals, & &1.ref),
      proofs: proofs,
      omissions: Enum.map(missing, &%{ref: &1, reason: "unavailable"}) ++ withheld ++ unselected
    )
  end

  # For each selected record, the seal that covers it. When every record
  # a seal covers is in the selection, the seal's manifest is carried and
  # the whole range can be checked. Otherwise each selected record gets a
  # membership proof and the bundle stays small.
  defp coverage({module, handle}, entries, selected) do
    seals =
      entries
      |> Enum.reduce(%{}, fn entry, found ->
        case module.seal_covering(handle, entry.stream, entry.seq) do
          {:ok, seal} -> Map.put_new(found, seal.ref, seal)
          :error -> found
        end
      end)
      |> Map.values()

    Enum.reduce(seals, {seals, [], [], []}, fn seal, {seals, proofs, manifests, extra} ->
      body = seal.evidence["body"]

      case manifest(module, handle, body["manifestRef"]) do
        {:ok, events} ->
          if Enum.all?(events, &MapSet.member?(selected, &1)) do
            {seals, proofs, [body["manifestRef"] | manifests], extra}
          else
            new =
              for {ref, index} <- Enum.with_index(events), MapSet.member?(selected, ref) do
                {:ok, siblings} = Epoch.proof(events, index)
                %{record: ref, seal: seal.ref, index: index, siblings: siblings}
              end

            {seals, proofs ++ new, manifests, extra}
          end

        :error ->
          {seals, proofs, manifests, extra}
      end
    end)
  end

  defp manifest(module, handle, ref) do
    with {:ok, bytes} <- module.get_blob(handle, ref),
         {:ok, %{"events" => events}} <- Jason.decode(bytes) do
      {:ok, events}
    else
      _ -> :error
    end
  end

  defp fetch_blobs({module, handle}, refs) do
    Enum.reduce(refs, {[], []}, fn ref, {held, missing} ->
      case module.get_blob(handle, ref) do
        {:ok, bytes} -> {[bytes | held], missing}
        :error -> {held, [ref | missing]}
      end
    end)
  end

  defp fetch_content({module, handle}, wanted) do
    Enum.reduce(wanted, {[], []}, fn {ref, scopes}, {held, missing} ->
      case Enum.find_value(scopes, :error, fn scope ->
             with {:ok, bytes} <- module.get_content(handle, ref, scope), do: {:ok, bytes}
           end) do
        {:ok, bytes} -> {[bytes | held], missing}
        _ -> {held, [ref | missing]}
      end
    end)
  end

  @doc "Every content reference the bodies of these records name."
  @spec content_refs([map()]) :: [Ref.t()]
  def content_refs(entries) do
    entries
    |> Enum.flat_map(&refs_in(&1.evidence["body"]))
    |> Enum.filter(&Ref.valid?(&1, :bytes))
    |> Enum.uniq()
  end

  defp refs_in(value) when is_binary(value), do: [value]
  defp refs_in(value) when is_list(value), do: Enum.flat_map(value, &refs_in/1)
  defp refs_in(value) when is_map(value), do: value |> Map.values() |> Enum.flat_map(&refs_in/1)
  defp refs_in(_value), do: []

  # The last selected position of each stream, sorted by stream.
  defp frontier(entries) do
    entries
    |> Enum.group_by(& &1.stream)
    |> Enum.map(fn {stream, records} ->
      last = Enum.max_by(records, & &1.seq)
      %{"stream" => stream, "seq" => last.seq, "event" => last.ref}
    end)
    |> Enum.sort_by(& &1["stream"])
  end
end
