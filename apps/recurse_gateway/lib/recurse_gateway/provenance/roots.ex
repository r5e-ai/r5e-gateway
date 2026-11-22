defmodule Recurse.Gateway.Provenance.Roots do
  @moduledoc """
  Takes a change of this deployment's roots, and records it.

  After the claim, the customer may replace their roots, the number that
  must act together, their recovery keys or the people who may approve.
  The change is made offline: by a recovery key alone, or by one root
  proposing and the required number of roots approving, each with the
  personal key of the person who holds it. The finished change is handed
  to the gateway here.

  Like a grant, a change authorises itself. It is accepted only if a
  reader who pins this deployment's chain, given the start as it stands
  plus what was sent, would find the change in order. The approvals are
  recorded first and the change last, so the change is never on the
  start stream without the approvals that make it valid beside it.

  Nothing about the gateway's own standing changes here. Grants the old
  roots gave it, already recorded and sealed, still stand; a new root
  may take them back or give new ones.
  """

  alias Recurse.Gateway.Provenance.{Claim, Runtime}
  alias Recurse.Provenance.{Envelope, Evidence, Export, Key, Pipeline, Profile, Publication, Ref}
  alias RecurseVerify.Canonical

  @base "provenance.r5e.io/v2/"
  @most 16
  @largest 262_144
  @file_name "root-changes.json"

  @doc "Where approvals and the profiles of accepted changes are kept for exports."
  @spec file(Path.t()) :: Path.t()
  def file(dir), do: Path.join(dir, @file_name)

  @doc """
  Accept a change of roots: `%{"change" => %{"ref", "envelope"},
  "approvals" => [...], "keys" => [...], "blobs" => [...]}`.

  Returns the reference of the change and of each approval recorded. An
  approval that is not in order is left out and does not stop a change
  that has the approvals it needs.
  """
  @spec accept(term()) :: {:ok, map()} | {:error, atom() | {atom(), String.t()}}
  def accept(
        %{"change" => %{"ref" => ref, "envelope" => envelope} = change, "keys" => keys} = sent
      )
      when is_binary(ref) and is_list(keys) do
    info = Runtime.info()
    approvals = for %{"ref" => _, "envelope" => _} = a <- List.wrap(sent["approvals"]), do: a
    blobs = for %{"ref" => _, "base64" => _} = b <- List.wrap(sent["blobs"]), do: b
    set = %{"records" => approvals ++ [change], "keys" => keys, "blobs" => blobs}

    with true <- length(approvals) <= @most || {:error, :too_large},
         true <- byte_size(JSON.encode!(set)) <= @largest || {:error, :too_large},
         %{"state" => "claimed", "chain" => chain} <- Claim.describe() || {:error, :not_claimed},
         {:ok, %{ref: ^ref, evidence: evidence}} <- Envelope.open(envelope),
         true <-
           Evidence.kind_path(evidence) == @base <> "RootsChanged" || {:error, :not_a_change},
         {:ok, by_key} <- keys(keys),
         {:ok, good} <- in_order(set, ref, chain),
         {:ok, recorded} <-
           record(
             Enum.filter(approvals, &(&1["ref"] in good)),
             by_key,
             blobs,
             "authority:approval:"
           ),
         {:ok, [^ref]} <- record([change], by_key, blobs, "start") do
      :ok = Pipeline.flush(Runtime.pipeline())
      keep(info.dir, minimal(set, [change | Enum.filter(approvals, &(&1["ref"] in good))]))
      # The roots in place have changed, so which grant badges hang from may too.
      Recurse.Gateway.Provenance.Grants.refresh()
      {:ok, %{"change" => ref, "approvals" => recorded, "chain" => chain}}
    else
      %{} -> {:error, :not_claimed}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :unreadable_change}
    end
  end

  def accept(_other), do: {:error, :unreadable_change}

  @doc "The approvals and profiles of accepted changes, as a set to carry in an export."
  @spec carried(Path.t()) :: Publication.set()
  def carried(dir) do
    with {:ok, text} <- File.read(file(dir)),
         {:ok, %{} = set} <- Jason.decode(text) do
      Publication.readable(set)
    else
      _ -> %{"records" => [], "keys" => [], "blobs" => []}
    end
  end

  # Read as someone who pins this deployment's chain would read it: the
  # start as it stands, plus what was sent. The change must be in order
  # in every respect; the approvals in order are the ones recorded.
  defp in_order(set, ref, chain) do
    {:ok, bare} = Export.build(records: [])
    bundle = Publication.carry(bare, [Claim.carried(), carried(Runtime.info().dir), set])
    report = Export.verify(bundle, trusted_chain: chain)
    about = fn subject -> Enum.filter(report.findings, &(&1.subject == subject)) end

    case Enum.find(about.(ref), &(&1.result != :ok and &1.check != :publication)) do
      nil ->
        good =
          for %{check: :start, result: :ok, subject: subject} <- report.findings,
              subject != ref,
              Enum.all?(about.(subject), &(&1.result == :ok or &1.check == :publication)),
              do: subject

        if Enum.any?(about.(ref), &(&1.check == :start)),
          do: {:ok, good},
          else: {:error, :unreadable_change}

      %{code: code} ->
        {:error, {:change_not_in_order, code}}
    end
  end

  defp keys(entries) do
    Enum.reduce_while(entries, {:ok, %{}}, fn
      %{"keyid" => id, "algorithm" => algorithm, "bytes" => text}, {:ok, acc}
      when is_binary(text) ->
        with {:ok, bytes} <- Base.decode64(text),
             {:ok, ^id} <- Key.id(algorithm, bytes) do
          {:cont, {:ok, Map.put(acc, id, %{algorithm: algorithm, bytes: bytes})}}
        else
          _ -> {:halt, {:error, :unreadable_change}}
        end

      _other, _acc ->
        {:halt, {:error, :unreadable_change}}
    end)
  end

  # Each record goes where its kind belongs, under the profile its issuer
  # sent for it.
  defp record(records, by_key, blobs, under) do
    held = Map.new(blobs, &{&1["ref"], &1["base64"]})

    Enum.reduce_while(records, {:ok, []}, fn %{"envelope" => envelope}, {:ok, refs} ->
      with {:ok, %{evidence: evidence} = opened} <- Envelope.open(envelope),
           {:ok, text} <- Map.fetch(held, evidence["profileRef"]),
           {:ok, bytes} <- Base.decode64(text),
           true <- Ref.bytes(bytes) == evidence["profileRef"],
           {:ok, %{} = profile} <- Canonical.decode_json(bytes),
           :ok <- Profile.validate(profile),
           {:ok, %{ref: ref}} <-
             Pipeline.accept(
               Runtime.pipeline(),
               envelope,
               Map.take(by_key, Envelope.signers(opened)),
               profile,
               under
             ) do
        {:cont, {:ok, refs ++ [ref]}}
      else
        :error -> {:halt, {:error, :profile_not_carried}}
        {:error, reason} when is_atom(reason) -> {:halt, {:error, reason}}
        _ -> {:halt, {:error, :profile_not_carried}}
      end
    end)
  end

  # Only what the accepted records themselves need is kept: the approvals
  # (the change is on the start stream already), their signers' keys and
  # the change's, and the profiles they cite. Anything else that was sent
  # is dropped, so nothing sent alongside a good change can find its way
  # into every later export.
  defp minimal(set, [_change | approvals] = accepted) do
    opened =
      for %{"envelope" => envelope} <- accepted, {:ok, o} <- [Envelope.open(envelope)], do: o

    signers = opened |> Enum.flat_map(&Envelope.signers/1) |> MapSet.new()
    profiles = MapSet.new(opened, & &1.evidence["profileRef"])

    %{
      "records" => approvals,
      "keys" => Enum.filter(set["keys"], &MapSet.member?(signers, &1["keyid"])),
      "blobs" => Enum.filter(set["blobs"], &MapSet.member?(profiles, &1["ref"]))
    }
  end

  # What an export needs beyond the start stream itself: the approvals,
  # the keys of everyone who signed, and the profiles they wrote under.
  defp keep(dir, set) do
    old = carried(dir)

    merged =
      for {field, id} <- [{"records", "ref"}, {"keys", "keyid"}, {"blobs", "ref"}], into: %{} do
        {field, Enum.uniq_by(List.wrap(old[field]) ++ List.wrap(set[field]), & &1[id])}
      end

    File.write!(file(dir), JSON.encode!(merged))
  end
end
