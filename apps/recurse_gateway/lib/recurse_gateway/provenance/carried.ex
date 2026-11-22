defmodule Recurse.Gateway.Provenance.Carried do
  @moduledoc """
  The records this gateway hands out with every export although it did
  not write them.

  Two kinds of record are needed to read a gateway's evidence and are
  made elsewhere: the publisher's statement of whose definitions the
  records cite, and the chain that gives this gateway's key its
  standing under the operator's root. Both are installed as files by
  the operator. Without them an export still verifies as far as it
  goes, and a reader is told that whose definitions these are, or whose
  authority the gateway acted under, could not be established. With
  them the bundle answers both on its own.

  A running gateway reads the files once at start and keeps the result
  with the rest of its capture state, so nothing here touches a disk
  while a request is served. A process that only exports, without
  capturing, reads them when it asks.
  """

  require Logger

  alias Recurse.Gateway.Provenance.{Claim, Grants, Roots, Runtime}
  alias Recurse.Provenance.Envelope
  alias Recurse.Provenance.Publication

  @doc """
  The publication sets installed for this deployment, each checked.
  A file that cannot be read or does not check out is reported once in
  the log and left out; it never stops capture.
  """
  @spec load_publications() :: [Publication.set()]
  def load_publications do
    case Application.get_env(:recurse_gateway, :evidence_publications_file) do
      nil ->
        []

      path ->
        with {:ok, text} <- File.read(path),
             {:ok, decoded} <- Jason.decode(text),
             {:ok, set} <- Publication.check(decoded) do
          [set]
        else
          problem ->
            Logger.warning(
              "evidence: #{path} is not a publication this gateway can carry " <>
                "(#{inspect(reason(problem))}); exports will not say whose definitions they cite"
            )

            []
        end
    end
  end

  @doc "The installed publications: the running gateway's, or read now."
  @spec publications() :: [Publication.set()]
  def publications do
    case Runtime.info() do
      %{publications: sets} -> sets
      _ -> load_publications()
    end
  end

  @doc """
  Everything to add to an export: the publications, the records of how
  this deployment's chain began, and the chain that gives this gateway
  its standing. A running gateway carries the chain
  it checked at start; a process that only exports carries the
  installed file's well-formed records as they are.
  """
  @spec sets(keyword()) :: [Publication.set()]
  def sets(opts \\ []) do
    authority =
      case Runtime.info() do
        %{authority: %{records: records, keys: keys} = standing} ->
          [%{"records" => records, "keys" => keys, "blobs" => Map.get(standing, :blobs, [])}]

        # A gateway with no standing now, or a process that only exports,
        # passes on what was installed or given: the grants the record
        # was made under, and the revocations that ended them. A reader
        # of last year's records needs last year's grants whether or not
        # the gateway still acts under one.
        _ ->
          installed_authority()
      end

    # The retention stream goes with every export once it has a record:
    # a reader told that content was disposed of needs all of it to see
    # that no hold stood in the way.
    # Left out of a bundle served to the public: holds and disposals say
    # whose content was held and why, which is the deployment's business.
    kept =
      if Keyword.get(opts, :retention, true),
        do: Recurse.Gateway.Provenance.Retention.carried(store(), deployment()),
        else: %{"records" => [], "keys" => [], "blobs" => []}

    fixed = [Claim.carried(), Roots.carried(dir()), kept | authority]
    publications() ++ fixed ++ [seals_over(fixed)]
  end

  # The seals that cover the start records and the grants, with what a
  # reader needs to check them. A seal is what shows a record existed by
  # a certain time, which is the difference between a grant that was
  # recorded when it was made and one written afterwards and dated back.
  @doc false
  def seals_over(sets) do
    {module, handle} = store()

    seals =
      for %{"records" => records} <- sets,
          %{"envelope" => envelope} <- records,
          {:ok, %{evidence: %{"stream" => stream, "seq" => seq}}} <- [Envelope.open(envelope)],
          {:ok, seal} <- [module.seal_covering(handle, stream, seq)],
          uniq: true,
          do: seal

    blobs =
      for seal <- seals,
          ref <- [seal.evidence["body"]["manifestRef"], seal.evidence["profileRef"]],
          {:ok, bytes} <- [module.get_blob(handle, ref)],
          uniq: true,
          do: %{"ref" => ref, "base64" => Base.encode64(bytes)}

    keys =
      for seal <- seals,
          {:ok, key} <- [module.get_key(handle, seal.evidence["issuer"])],
          uniq: true,
          do: %{
            "keyid" => key.key_id,
            "algorithm" => key.algorithm,
            "bytes" => Base.encode64(key.public_key)
          }

    %{
      "records" => for(seal <- seals, do: %{"ref" => seal.ref, "envelope" => seal.envelope}),
      "keys" => keys,
      "blobs" => blobs,
      "seals" => Enum.map(seals, & &1.ref)
    }
  end

  defp store do
    case Runtime.info() do
      %{store: store} -> store
      _ -> Runtime.store(deployment())
    end
  end

  defp deployment do
    case Runtime.info() do
      %{deployment: deployment} -> deployment
      _ -> Application.get_env(:recurse_gateway, :evidence_deployment, "default")
    end
  end

  defp dir do
    case Runtime.info() do
      %{dir: dir} -> dir
      _ -> Runtime.dir(deployment())
    end
  end

  defp installed_authority do
    path =
      Application.get_env(:recurse_gateway, :evidence_authority_file) ||
        Grants.file(dir())

    with {:ok, text} <- File.read(path),
         {:ok, decoded} <- Jason.decode(text) do
      [Publication.readable(decoded)]
    else
      _ -> []
    end
  end

  @doc """
  Add what this gateway carries to a bundle it has built: everything in
  `sets/0`, and, for each record in the bundle that a workload signed,
  the workload's badge and any record that took the badge back, with
  the seals over them. Without the badge a reader cannot establish the
  workload's standing.
  """
  @spec carry(map(), keyword()) :: map()
  def carry(bundle, opts \\ []) do
    behind = behind_workloads(bundle)
    # What the gateway noted about a signer's fault names other people's
    # streams and carries what they offered; a public bundle leaves it out.
    noted =
      if Keyword.get(opts, :security, true),
        do: noted_about(bundle),
        else: %{"records" => [], "keys" => [], "blobs" => [], "proofs" => [], "omissions" => []}

    # Definitions added while the deployment ran, for the records here
    # that follow one. They are on this chain, so the seal over each
    # shows it was published before the records that cite it.
    defined = Recurse.Gateway.Provenance.Published.carried_for(bundle)

    bundle
    |> Publication.carry(sets(opts) ++ [behind, defined, seals_over([behind, defined]), noted])
    |> also("proofs", noted["proofs"])
    |> also("omissions", noted["omissions"])
  end

  defp also(bundle, _field, []), do: bundle

  defp also(bundle, field, entries),
    do: Map.update(bundle, field, entries, &Enum.uniq(&1 ++ entries))

  # What the gateway itself noted about a stream in the bundle: that its
  # signer offered a second, different record at a position already
  # taken. A reader of that stream's records should see it. The notes
  # share one stream, and a seal over it covers whichever notes were made
  # in the same interval, so when any note is about this bundle the whole
  # stream is carried: part of it would leave its seals unchecked, and a
  # reader would be told something could not be checked in an export
  # where nothing is wrong. The stream is short, and whoever may export
  # may read all of it.
  defp noted_about(bundle) do
    {module, handle} = store = store()

    streams =
      for %{"envelope" => envelope} <- List.wrap(bundle["records"]),
          {:ok, %{evidence: %{"stream" => stream}}} <- [Envelope.open(envelope)],
          into: MapSet.new(),
          do: stream

    security = "urn:r5e:stream:#{deployment()}:security"

    with true <- MapSet.size(streams) > 0,
         {:ok, {last, _ref}} <- module.head(handle, security),
         {:ok, entries} <- module.range(handle, security, 1, last),
         true <- Enum.any?(entries, &MapSet.member?(streams, &1.evidence["body"]["about"])),
         {:ok, carried} <- Recurse.Provenance.Exporter.bundle(store, entries, %{}) do
      Map.take(carried, ["records", "keys", "blobs", "seals", "proofs", "omissions"])
    else
      _ -> nothing_noted()
    end
  rescue
    _ -> nothing_noted()
  end

  defp nothing_noted,
    do: %{"records" => [], "keys" => [], "blobs" => [], "proofs" => [], "omissions" => []}

  defp behind_workloads(bundle) do
    {module, handle} = store()

    gateway =
      case Runtime.info() do
        %{key_id: key_id} -> key_id
        _ -> nil
      end

    issuers =
      for %{"envelope" => envelope} <- List.wrap(bundle["records"]),
          {:ok, %{evidence: %{"issuer" => issuer}}} <- [Envelope.open(envelope)],
          issuer != gateway,
          uniq: true,
          do: issuer

    behind =
      if function_exported?(module, :authority_of, 2) do
        for {_issuer, ref} <- module.authority_of(handle, issuers),
            {:ok, entry} <- [module.fetch(handle, ref)],
            uniq: true,
            do: entry
      else
        []
      end

    entries = behind

    signers =
      for %{envelope: envelope} <- entries,
          {:ok, opened} <- [Envelope.open(envelope)],
          keyid <- Envelope.signers(opened),
          uniq: true,
          do: keyid

    %{
      "records" => for(e <- entries, do: %{"ref" => e.ref, "envelope" => e.envelope}),
      "keys" =>
        for(
          keyid <- signers,
          {:ok, key} <- [module.get_key(handle, keyid)],
          do: %{
            "keyid" => key.key_id,
            "algorithm" => key.algorithm,
            "bytes" => Base.encode64(key.public_key)
          }
        ),
      "blobs" =>
        for(
          ref <- entries |> Enum.map(& &1.evidence["profileRef"]) |> Enum.uniq(),
          {:ok, bytes} <- [module.get_blob(handle, ref)],
          do: %{"ref" => ref, "base64" => Base.encode64(bytes)}
        )
    }
  rescue
    _ -> %{"records" => [], "keys" => [], "blobs" => []}
  end

  defp reason({:error, reason}), do: reason
  defp reason(other), do: other
end
