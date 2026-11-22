defmodule Recurse.Gateway.Provenance.Published do
  @moduledoc """
  Definitions a publisher adds while the deployment is running.

  A deployment starts with the base kinds built into it. A kind that is
  not one of those, or a newer definition of one that is, arrives here as
  a signed `DefinitionPublished` record together with the definition
  documents it names. Once admitted, records of that kind citing that
  definition are accepted from workloads, without a rebuild or a restart.

  The operator says whose word counts, and about what, in
  `R5E_EVIDENCE_PUBLISHERS`: each publisher's key id, `=`, and the
  domains it is believed about (`key:…=r5e.io key:…=acme.example`). It is
  the same statement a reader makes to the verifier, and it is required
  here: a gateway does not believe any publisher about every kind.

  A publication is admitted when

    * it is signed by one of those publishers, who is believed about
      every kind it lists;
    * every definition document it names is sent with it or already
      held, hashes to the reference given, and is a definition of the
      kind it is listed under;
    * it is written to this deployment's own chain, alone at the first
      position of a stream under `…:definitions:`.

  It is then a record like any other: sealed, and carried in every
  export, so a reader sees who published a definition and that it was
  published before the records that cite it.

  Admission only ever adds. A kind may have several admitted definitions
  and a record says which one it follows. Nothing is replaced or removed;
  withdrawing a definition would be a later record, which does not exist
  yet.

  What has been admitted is kept in a file beside the grants, so it is
  found again after a restart, and as a set in memory that admission of
  workload records reads without touching a disk or a process. That set
  changes only when a publisher publishes, which is rare.

  The route that takes a publication needs no login, so everything about
  it assumes a stranger is calling. The cheap questions come first: is
  the deployment claimed, is the record signed by a publisher believed
  about what it lists. Only then are documents hashed and read. What is
  kept from a request is exactly the record, its signer's key, its
  profile and the documents it names; nothing else a caller attached is
  kept or ever carried. The file is replaced whole by a rename, one
  writer at a time, so a reader never sees half of it.

  The file is this node's. Two nodes that share a database do not yet
  share what was admitted; the same is true of grants.
  """

  require Logger

  alias Recurse.Gateway.Provenance.{Claim, Runtime}
  alias Recurse.Provenance.{Definitions, Envelope, Evidence, Pipeline, Profile, Publication, Ref}
  alias RecurseVerify.Canonical

  @kind "provenance.r5e.io/v2/DefinitionPublished"
  @accepted {__MODULE__, :accepted}
  @file_name "definitions.json"
  @most 8
  @largest 4_194_304

  @type error ::
          :no_publisher_configured
          | :not_claimed
          | :too_large
          | :not_a_verifiable_publication
          | :publisher_not_believed
          | :definition_not_carried
          | :not_a_definition_of_that_kind
          | :profile_not_carried
          | :stream_not_admissible
          | :stream_fork_refused
          | atom()

  # -- whose word counts -----------------------------------------------------

  @doc """
  The publishers this gateway believes, as key id to the domains each is
  believed about. Entries without a domain are left out and said so in
  the log: at a gateway, trust in a publisher is always about named
  domains.
  """
  @spec publishers() :: %{String.t() => [String.t()]}
  def publishers do
    :recurse_gateway
    |> Application.get_env(:evidence_publishers)
    |> to_string()
    |> String.split([" ", ";", "\n", "\t"], trim: true)
    |> Enum.reduce(%{}, fn entry, acc ->
      case String.split(entry, "=", parts: 2) do
        [key, domains] when domains != "" ->
          Map.update(acc, key, split(domains), &Enum.uniq(&1 ++ split(domains)))

        _ ->
          Logger.warning(
            "evidence: publisher #{inspect(entry)} names no domain and is not believed about anything"
          )

          acc
      end
    end)
  end

  defp split(domains), do: String.split(domains, ",", trim: true)

  @doc "Whether `publisher` is believed about `kind_path`, by the same rule a reader uses."
  @spec believed?(%{String.t() => [String.t()]}, String.t(), String.t()) :: boolean()
  def believed?(publishers, publisher, kind_path) do
    [group | _] = String.split(kind_path, "/", parts: 2)

    publishers
    |> Map.get(publisher, [])
    |> Enum.any?(&(group == &1 or String.ends_with?(group, "." <> &1)))
  end

  # -- admitting ---------------------------------------------------------------

  @doc """
  Admit a publication: `%{"records" => [...], "keys" => [...], "blobs" =>
  [...]}` as `mix recurse.provenance.publish` writes it. Returns, for
  each record, its reference and the kinds it added.
  """
  @spec admit(term()) :: {:ok, [map()]} | {:error, error()}
  def admit(%{"records" => [_ | _] = records, "keys" => keys} = set)
      when length(records) <= @most and is_list(keys) do
    info = Runtime.info()
    believed = publishers()

    with true <- believed != %{} || {:error, :no_publisher_configured},
         :ok <- claimed(info),
         # Cheap first: who signed, and are they believed about what they
         # list. A stranger's request ends here, before anything is hashed.
         {:ok, opened} <- open_all(records),
         :ok <- each(opened, &believed_about_all(&1, believed)),
         blobs =
           for(%{"ref" => r, "base64" => t} <- List.wrap(set["blobs"]), into: %{}, do: {r, t}),
         # Only what these records need is looked at from here on.
         {:ok, kept} <- minimal(opened, keys, blobs, info),
         true <- byte_size(JSON.encode!(kept)) <= @largest || {:error, :too_large},
         {:ok, kept} <- Publication.check(kept),
         {:ok, by_key} <- keys(kept["keys"]),
         :ok <- each(opened, &documents_hold(&1, blobs, info)),
         # Every record is judged before any is written.
         {:ok, profiles} <- profiles(opened, blobs, info),
         {:ok, added} <- record(opened, profiles, by_key, blobs, info) do
      :ok = Pipeline.flush(Runtime.pipeline())
      install(kept, info)
      {:ok, added}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :not_a_verifiable_publication}
    end
  end

  def admit(_other), do: {:error, :not_a_verifiable_publication}

  # A deployment that starts its own chain takes nothing until its
  # customer has claimed it, as with grants.
  defp claimed(%{start_chain?: true}) do
    case Claim.describe() do
      %{"state" => "claimed"} -> :ok
      _ -> {:error, :not_claimed}
    end
  end

  defp claimed(_info), do: :ok

  defp open_all(records) do
    Enum.reduce_while(records, {:ok, []}, fn
      %{"envelope" => envelope}, {:ok, acc} ->
        case Envelope.open(envelope) do
          {:ok, %{evidence: %{"issuer" => issuer, "profileRef" => profile}} = opened}
          when is_binary(issuer) and is_binary(profile) ->
            if Evidence.kind_path(opened.evidence) == @kind,
              do: {:cont, {:ok, acc ++ [Map.put(opened, :envelope, envelope)]}},
              else: {:halt, {:error, :not_a_verifiable_publication}}

          _ ->
            {:halt, {:error, :not_a_verifiable_publication}}
        end

      _other, _acc ->
        {:halt, {:error, :not_a_verifiable_publication}}
    end)
  end

  # The part of a request that is kept: the records, their signers' keys,
  # their profiles and the documents they name. A document not sent is
  # taken from the store when it is held there.
  defp minimal(opened, keys, blobs, %{store: {module, handle}}) do
    issuers = MapSet.new(opened, & &1.evidence["issuer"])

    wanted =
      Enum.uniq(
        Enum.map(opened, & &1.evidence["profileRef"]) ++
          for(record <- opened, {_kind, ref} <- listed(record), do: ref)
      )

    found =
      Enum.reduce_while(wanted, {:ok, []}, fn ref, {:ok, acc} ->
        case blobs do
          %{^ref => text} when is_binary(text) ->
            {:cont, {:ok, acc ++ [%{"ref" => ref, "base64" => text}]}}

          _ ->
            case module.get_blob(handle, ref) do
              {:ok, bytes} ->
                {:cont, {:ok, acc ++ [%{"ref" => ref, "base64" => Base.encode64(bytes)}]}}

              _ ->
                {:halt, {:error, :definition_not_carried}}
            end
        end
      end)

    with {:ok, kept_blobs} <- found do
      {:ok,
       %{
         "records" => for(o <- opened, do: %{"ref" => o.ref, "envelope" => o.envelope}),
         "keys" =>
           keys
           |> Enum.filter(&(is_map(&1) and MapSet.member?(issuers, &1["keyid"])))
           |> Enum.uniq_by(& &1["keyid"]),
         "blobs" => kept_blobs
       }}
    end
  end

  defp each(list, check) do
    Enum.reduce_while(list, :ok, fn item, :ok ->
      case check.(item) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp keys(entries) do
    by_id =
      for %{"keyid" => id, "algorithm" => algorithm, "bytes" => text} <- entries,
          {:ok, bytes} <- [Base.decode64(text)],
          into: %{},
          do: {id, %{algorithm: algorithm, bytes: bytes}}

    {:ok, by_id}
  end

  defp listed(%{evidence: %{"body" => %{"definitions" => entries}}}) when is_list(entries) do
    for %{"kind" => kind, "definition" => ref} when is_binary(kind) and is_binary(ref) <- entries,
        do: {kind, ref}
  end

  defp listed(_other), do: []

  defp believed_about_all(%{evidence: %{"issuer" => issuer}} = record, believed) do
    pairs = listed(record)

    cond do
      pairs == [] -> {:error, :not_a_verifiable_publication}
      Enum.all?(pairs, fn {kind, _ref} -> believed?(believed, issuer, kind) end) -> :ok
      true -> {:error, :publisher_not_believed}
    end
  end

  # Every document named is here, is the bytes its reference says, and is
  # a definition of the kind it is listed under. A document may name its
  # ancestors by reference; those are looked for in the same places.
  defp documents_hold(record, blobs, %{store: {module, handle}}) do
    fetch = fn ref ->
      with {:ok, text} <- Map.fetch(blobs, ref),
           {:ok, bytes} <- Base.decode64(text) do
        {:ok, bytes}
      else
        _ -> module.get_blob(handle, ref)
      end
    end

    each(listed(record), &document_holds(&1, fetch))
  end

  defp document_holds({kind, ref}, fetch) do
    with {:ok, bytes} when is_binary(bytes) <- fetch.(ref),
         true <- Ref.bytes(bytes) == ref do
      case Definitions.check(kind, ref, %{}, fetch) do
        :unavailable -> {:error, :not_a_definition_of_that_kind}
        {:error, :definition_is_for_another_kind} -> {:error, :not_a_definition_of_that_kind}
        _conforms_or_not -> :ok
      end
    else
      _ -> {:error, :definition_not_carried}
    end
  end

  # Each record's profile, read and checked, and its stream inside this
  # deployment's definitions, before anything is written.
  defp profiles(opened, blobs, info) do
    wanted = "urn:r5e:stream:#{info.deployment}:definitions:"

    Enum.reduce_while(opened, {:ok, %{}}, fn record, {:ok, acc} ->
      ref = record.evidence["profileRef"]

      with true <-
             String.starts_with?(to_string(record.evidence["stream"]), wanted) ||
               {:error, :stream_not_admissible},
           {:ok, text} <- Map.fetch(blobs, ref),
           {:ok, bytes} <- Base.decode64(text),
           true <- Ref.bytes(bytes) == ref,
           {:ok, %{} = profile} <- Canonical.decode_json(bytes),
           :ok <- Profile.validate(profile) do
        {:cont, {:ok, Map.put(acc, ref, profile)}}
      else
        {:error, :stream_not_admissible} -> {:halt, {:error, :stream_not_admissible}}
        _ -> {:halt, {:error, :profile_not_carried}}
      end
    end)
  end

  # Each publication goes alone at the first position of a stream of its
  # own inside this deployment, under the profile its publisher made for
  # it. The documents it names are held before it is, so there is never
  # an admitted publication whose definition cannot be produced.
  defp record(opened, profiles, by_key, blobs, %{store: {module, handle}}) do
    Enum.reduce_while(opened, {:ok, []}, fn publication, {:ok, added} ->
      %{"issuer" => issuer, "profileRef" => profile_ref} = publication.evidence

      with :ok <- hold_documents(publication, blobs, module, handle),
           {:ok, %{ref: ref}} <-
             Pipeline.accept(
               Runtime.pipeline(),
               publication.envelope,
               Map.take(by_key, [issuer]),
               Map.fetch!(profiles, profile_ref),
               "definitions:"
             ) do
        kinds = for {kind, _ref} <- listed(publication), do: kind
        {:cont, {:ok, added ++ [%{"ref" => ref, "publisher" => issuer, "kinds" => kinds}]}}
      else
        {:error, reason} when is_atom(reason) -> {:halt, {:error, reason}}
        _ -> {:halt, {:error, :not_a_verifiable_publication}}
      end
    end)
  end

  defp hold_documents(publication, blobs, module, handle) do
    each(listed(publication), fn {_kind, ref} ->
      case Map.fetch(blobs, ref) do
        {:ok, text} -> module.put_blob(handle, ref, Base.decode64!(text))
        # Already held: `minimal/4` found it in the store.
        :error -> :ok
      end
    end)
  end

  # -- what has been admitted --------------------------------------------------

  @doc "Where admitted publications are kept between restarts."
  @spec file(Path.t()) :: Path.t()
  def file(dir), do: Path.join(dir, @file_name)

  # One writer at a time on this node, and the file replaced whole: a
  # reader sees the old file or the new one, never part of either. A
  # request that adds nothing writes nothing.
  defp install(set, info) do
    :global.trans({__MODULE__, info.dir}, fn ->
      old = held(info.dir)
      new = merge(old, set)

      if new != old do
        path = file(info.dir)
        temporary = path <> ".#{System.unique_integer([:positive])}.partial"

        File.open!(temporary, [:write, :binary], fn device ->
          IO.binwrite(device, JSON.encode!(new))
          :file.sync(device)
        end)

        File.rename!(temporary, path)
      end
    end)

    load(info.dir)
  end

  @doc """
  Read what was admitted before and make it the set in force. Called as
  capture starts and after each admission. A publisher no longer listed
  in `R5E_EVIDENCE_PUBLISHERS`, or no longer believed about a kind, stops
  counting from the next start; its records stay on the chain.
  """
  @spec load(Path.t()) :: :ok
  def load(dir) do
    believed = publishers()

    accepted =
      for %{"envelope" => envelope} <- held(dir)["records"],
          {:ok, %{evidence: %{"issuer" => issuer}} = opened} <- [Envelope.open(envelope)],
          {kind, ref} <- listed(opened),
          believed?(believed, issuer, kind),
          into: MapSet.new(),
          do: {kind, ref}

    if :persistent_term.get(@accepted, nil) != accepted,
      do: :persistent_term.put(@accepted, accepted)

    :ok
  end

  @doc "Forget the set in force. Called as capture stops."
  @spec unload() :: :ok
  def unload do
    :persistent_term.erase(@accepted)
    :ok
  end

  @doc """
  Whether a record of `kind_path` citing `schema_ref` follows a definition
  admitted here. The base definitions are not asked about; they are built in.
  """
  @spec admitted?(String.t(), Ref.t()) :: boolean()
  def admitted?(kind_path, schema_ref),
    do: MapSet.member?(:persistent_term.get(@accepted, MapSet.new()), {kind_path, schema_ref})

  @doc """
  Every admitted definition: its kind, the document's reference, who
  published it and in which record.
  """
  @spec list() :: [map()]
  def list do
    for %{"envelope" => envelope} <- held(dir())["records"],
        {:ok, %{ref: ref, evidence: %{"issuer" => issuer}} = opened} <- [Envelope.open(envelope)],
        {kind, definition} <- listed(opened) do
      %{
        "kind" => kind,
        "definition" => definition,
        "publisher" => issuer,
        "publication" => ref,
        "inForce" => admitted?(kind, definition)
      }
    end
  end

  @doc """
  The admitted publications a bundle needs: those that list a definition
  one of the bundle's records cites, each with its signer's key, its
  profile and the documents it names. A bundle whose records all follow
  built-in definitions gets none, so a reader who believes only the
  built-in publisher is not shown statements by publishers they never
  chose.
  """
  @spec carried_for(map()) :: Publication.set()
  def carried_for(%{"records" => records}) when is_list(records) do
    cited =
      for %{"envelope" => envelope} <- records,
          {:ok, %{evidence: %{"schemaRef" => ref} = evidence}} <- [Envelope.open(envelope)],
          into: MapSet.new(),
          do: {Evidence.kind_path(evidence), ref}

    set = held(dir())

    wanted =
      for %{"envelope" => envelope} = entry <- set["records"],
          {:ok, opened} <- [Envelope.open(envelope)],
          Enum.any?(listed(opened), &MapSet.member?(cited, &1)),
          do: {entry, opened}

    issuers = MapSet.new(wanted, fn {_entry, o} -> o.evidence["issuer"] end)

    refs =
      MapSet.new(
        for {_entry, o} <- wanted,
            ref <- [o.evidence["profileRef"] | Enum.map(listed(o), &elem(&1, 1))],
            do: ref
      )

    %{
      "records" => Enum.map(wanted, &elem(&1, 0)),
      "keys" => Enum.filter(set["keys"], &MapSet.member?(issuers, &1["keyid"])),
      "blobs" => Enum.filter(set["blobs"], &MapSet.member?(refs, &1["ref"]))
    }
  end

  def carried_for(_bundle), do: %{"records" => [], "keys" => [], "blobs" => []}

  # A running gateway's own directory, or the configured one for a
  # process that only exports.
  defp dir do
    case Runtime.info() do
      %{dir: dir} -> dir
      _ -> Runtime.dir(Application.get_env(:recurse_gateway, :evidence_deployment, "default"))
    end
  end

  defp held(dir) do
    with {:ok, text} <- File.read(file(dir)),
         {:ok, %{"records" => records, "keys" => keys} = set}
         when is_list(records) and is_list(keys) <- Jason.decode(text) do
      Map.put(set, "blobs", List.wrap(set["blobs"]))
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
