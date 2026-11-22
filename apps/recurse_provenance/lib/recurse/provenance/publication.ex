defmodule Recurse.Provenance.Publication do
  @moduledoc """
  A publisher's signed statement of which definition documents it issues.

  A definition is identified by its content, so anyone can hand a reader
  any document under any kind name. What tells the reader whose document
  it is is a `DefinitionPublished` record signed by a publisher the
  reader already trusts. This module makes that record and packages it
  as a *carried set*: the record, the publisher's public key, the
  publisher's profile and the definition documents themselves, which is
  everything a verifier needs to check the statement offline.

  The set is made once, by whoever holds the publisher's key, and is
  then only carried: a gateway installs the file and adds it to what it
  exports. A gateway never signs a publication on its publisher's
  behalf, so the publisher's key is never on a serving machine.

  A carried set is a map of `"records"`, `"keys"` and `"blobs"` in the
  forms an export bundle uses. The records that give a gateway its
  standing are installed in the same form, so one way of carrying
  serves both.
  """

  alias Recurse.Provenance.{Body, Definitions, Envelope, Evidence, Key, Profile, Ref}
  alias RecurseVerify.Canonical

  @kind "DefinitionPublished"

  @type set :: %{String.t() => [map()]}

  @doc """
  Sign a publication: by default of every installed base definition, or
  of the documents given.

  Options:

    * `:name` — the publisher's short name, used in its actor and stream
      (default `"r5e"`)
    * `:at` — the time the record states (default now)
    * `:package` — the package name the record states (default
      `"r5e.provenance"`)
    * `:documents` — the definition documents to publish, each
      `%{kind_path:, ref:, bytes:}`, in place of the base set. This is
      how a publisher issues kinds of its own
    * `:proposal` — the record these definitions were proposed in, which
      may be a `chain:` reference into another chain
    * `:stream_prefix` — where the record is written, in place of the
      publisher's own stream space. A publisher adding definitions to a
      running deployment gives `urn:r5e:stream:<deployment>:definitions:`,
      so the record is on that deployment's chain and sealed with it

  The stream is named after what is published, who publishes it and the
  proposal it names, so a different statement is a different stream and
  no publication ever forks another.
  """
  @spec issue(Key.signer(), keyword()) :: {:ok, set()} | {:error, term()}
  def issue(signer, opts \\ []) do
    name = Keyword.get(opts, :name, "r5e")
    documents = Keyword.get_lazy(opts, :documents, &Definitions.documents/0)
    definitions = Map.new(documents, &{&1.kind_path, &1.ref})
    path = Definitions.kind_path(Definitions.api_version(), @kind)
    own = "urn:r5e:stream:publisher:#{name}:"
    stream_prefix = Keyword.get(opts, :stream_prefix, own)
    stream = if stream_prefix == own, do: own <> "api:", else: stream_prefix

    # Who says it and in answer to what are part of the name too, so the
    # same definitions published again under a new key, or naming a
    # proposal, are a new statement and not a second record at a position
    # already taken.
    digest =
      definitions
      |> Enum.sort()
      |> Enum.map(fn {kind, ref} -> kind <> " " <> ref end)
      |> Kernel.++([signer.key_id, to_string(Keyword.get(opts, :proposal))])
      |> Enum.join("\n")
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)
      |> binary_part(0, 16)

    with {:ok, %{ref: schema_ref}} <- Definitions.fetch(path),
         {:ok, profile} <-
           Profile.new(
             bindings: [
               %{
                 stream_prefix: stream_prefix,
                 actor_prefixes: ["urn:r5e:publisher:"],
                 issuer_keys: [signer.key_id],
                 sealer_keys: []
               }
             ],
             failure_domain: "published once and carried",
             deployment_policy_ref: Ref.bytes("r5e.publisher/" <> name),
             policy_required_kinds: []
           ),
         evidence =
           Evidence.new(
             kind_path: path,
             schema_ref: schema_ref,
             profile_ref: Profile.ref(profile),
             issuer: signer.key_id,
             actor: "urn:r5e:publisher:#{name}",
             stream: stream <> digest,
             seq: 1,
             previous: nil,
             captured_at: Keyword.get_lazy(opts, :at, &DateTime.utc_now/0),
             body:
               Body.definition_published(
                 definitions: definitions,
                 package: Keyword.get(opts, :package, "r5e.provenance"),
                 proposal: Keyword.get(opts, :proposal)
               )
           ),
         {:ok, signed} <- Envelope.sign(evidence, signer) do
      {:ok,
       %{
         "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
         "keys" => [
           %{
             "keyid" => signer.key_id,
             "algorithm" => signer.algorithm,
             "bytes" => Base.encode64(signer.public_key)
           }
         ],
         "blobs" => Enum.map([Profile.encode(profile) | Enum.map(documents, & &1.bytes)], &blob/1)
       }}
    else
      :error -> {:error, :publication_kind_not_installed}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Read a carried set that came from a file or another party.

  Every record must open, be a publication, and carry signatures that
  verify with the keys in the set; every key must be the key its id
  names; every blob must be the bytes its reference names. A set that
  fails any of these is refused whole, because carrying a statement
  nobody can check helps no reader.
  """
  @spec check(term()) :: {:ok, set()} | {:error, atom()}
  def check(%{"records" => records, "keys" => keys} = set)
      when is_list(records) and is_list(keys) do
    blobs = Map.get(set, "blobs", [])
    path = Definitions.kind_path(Definitions.api_version(), @kind)

    with {:ok, by_id} <- keys(keys),
         :ok <- all(blobs, &blob_holds?/1, :blob_differs_from_its_reference),
         :ok <- all(records, &publication?(&1, path, by_id), :not_a_verifiable_publication) do
      {:ok, %{"records" => records, "keys" => keys, "blobs" => blobs}}
    end
  end

  def check(_other), do: {:error, :not_a_carried_set}

  @doc """
  The well-formed part of a carried set of any records, for a set that
  is only passed on and is judged by whoever reads the bundle: records
  that open under the reference they state, keys that are the key their
  id names, and blobs that are the bytes their reference names. Anything
  else is dropped, so passing a set on can never make a bundle
  unreadable.
  """
  @spec readable(term()) :: set()
  def readable(%{} = set) do
    %{
      "records" =>
        for(
          %{"ref" => ref, "envelope" => envelope} = entry <- list(set, "records"),
          match?({:ok, %{ref: ^ref}}, Envelope.open(envelope)),
          do: Map.take(entry, ["ref", "envelope"])
        ),
      "keys" => for(key <- list(set, "keys"), match?({:ok, %{}}, keys([key])), do: key),
      "blobs" => for(blob <- list(set, "blobs"), blob_holds?(blob), do: blob)
    }
  end

  def readable(_other), do: %{"records" => [], "keys" => [], "blobs" => []}

  defp list(set, field) do
    case set do
      %{^field => entries} when is_list(entries) -> entries
      _ -> []
    end
  end

  @doc "The key ids of the publishers whose statements a set carries."
  @spec publishers(set()) :: [String.t()]
  def publishers(%{"records" => records}) do
    for %{"envelope" => envelope} <- records,
        {:ok, %{evidence: %{"issuer" => issuer}}} <- [Envelope.open(envelope)],
        uniq: true,
        do: issuer
  end

  @doc """
  Add carried sets to a bundle that has already been built.

  Records, keys and blobs the bundle already has are left as they are;
  the rest are appended in order. Nothing else in the bundle changes, so
  its scope still says what was asked for and the carried records are
  recognisable as context.
  """
  @spec carry(map(), [set()]) :: map()
  def carry(bundle, sets) do
    Enum.reduce(sets, bundle, fn set, bundle ->
      bundle
      |> append("records", Map.get(set, "records", []), "ref")
      |> append("keys", Map.get(set, "keys", []), "keyid")
      |> append("blobs", Map.get(set, "blobs", []), "ref")
      |> list_seals(Map.get(set, "seals", []))
    end)
  end

  @doc "A carried set as the text of a file."
  @spec encode(set()) :: binary()
  def encode(set), do: Canonical.encode(set)

  # A carried seal is named among the bundle's seals, which is what asks
  # a verifier to check it.
  defp list_seals(bundle, []), do: bundle
  defp list_seals(bundle, refs), do: Map.update(bundle, "seals", refs, &Enum.uniq(&1 ++ refs))

  defp append(bundle, field, entries, id) do
    Map.update(bundle, field, entries, fn held ->
      have = MapSet.new(held, & &1[id])
      held ++ Enum.reject(Enum.uniq_by(entries, & &1[id]), &MapSet.member?(have, &1[id]))
    end)
  end

  defp blob(bytes), do: %{"ref" => Ref.bytes(bytes), "base64" => Base.encode64(bytes)}

  defp blob_holds?(%{"ref" => ref, "base64" => text}) when is_binary(text) do
    match?({:ok, bytes} when is_binary(bytes), Base.decode64(text)) and
      Ref.bytes(Base.decode64!(text)) == ref
  end

  defp blob_holds?(_other), do: false

  defp keys(entries) do
    Enum.reduce_while(entries, {:ok, %{}}, fn
      %{"keyid" => id, "algorithm" => algorithm, "bytes" => text}, {:ok, acc}
      when is_binary(text) ->
        with {:ok, bytes} <- Base.decode64(text),
             {:ok, ^id} <- Key.id(algorithm, bytes) do
          {:cont, {:ok, Map.put(acc, id, %{algorithm: algorithm, bytes: bytes})}}
        else
          _ -> {:halt, {:error, :key_differs_from_its_id}}
        end

      _other, _acc ->
        {:halt, {:error, :key_differs_from_its_id}}
    end)
  end

  defp publication?(%{"ref" => ref, "envelope" => envelope}, path, keys) do
    with {:ok, %{evidence: evidence, ref: ^ref} = opened} <- Envelope.open(envelope),
         true <- Evidence.kind_path(evidence) == path,
         :ok <- Envelope.verify(opened, keys) do
      true
    else
      _ -> false
    end
  end

  defp publication?(_other, _path, _keys), do: false

  defp all(entries, check, reason) do
    if Enum.all?(entries, check), do: :ok, else: {:error, reason}
  end
end
