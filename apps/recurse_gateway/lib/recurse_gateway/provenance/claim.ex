defmodule Recurse.Gateway.Provenance.Claim do
  @moduledoc """
  How this node's chain begins, and how a customer accepts it.

  The first time a node runs it knows only itself. It makes a bootstrap
  key, writes the first record of its start stream saying which
  published definitions it was built from, and waits. A customer then
  claims the deployment: their root key signs a deployment record that
  accepts that first record and names their roots. The node adds the
  bootstrap key's signature, records it, and destroys the bootstrap key.
  From then on the bootstrap key has no authority and no longer exists.

  The claim is made in two steps over HTTP, because the customer's root
  key is offline and the bootstrap key never leaves this node: `prepare`
  answers with the exact record to be signed, and `finalize` takes the
  root's signature. Before the claim there is nobody to sign in, so the
  two steps are guarded by a one-time code written to a file only this
  node's user can read.

  Nothing here is on the path of a request. The bootstrap key and the
  claim code live in two small files in the evidence directory until the
  claim, because they must survive a restart; both are removed as soon
  as the deployment record is durably stored.
  """

  require Logger

  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Provenance.{Definitions, Envelope, Evidence, Key, Pipeline, Profile, Ref}
  alias RecurseVerify.Canonical

  @base "provenance.r5e.io/v2"
  @ticket_context "r5e.claim-ticket/v1"
  @ticket_seconds 600
  @key_file "bootstrap.key"
  @code_file "claim.code"

  @type error ::
          :not_started
          | :wrong_claim_code
          | :already_claimed
          | :claimed_by_is_not_a_root
          | :threshold_exceeds_roots
          | :duplicate_root
          | :recovery_key_is_a_root
          | :unreadable_public_key
          | :ticket_does_not_match
          | :ticket_expired
          | :bad_signature
          | :signature_is_not_the_claimants
          | :terms_do_not_match_the_definition
          | :malformed_request

  @doc "The start stream of a deployment."
  @spec stream(String.t()) :: String.t()
  def stream(deployment), do: "urn:r5e:stream:#{deployment}:start"

  @doc """
  Begin this node's chain if it has not begun, and tidy up if it has
  already been claimed. Called once the pipeline is running.

  Returns `:claimed`, `:unclaimed`, or `{:not_started, reason}` when the
  node has no publication to cite or cannot use its evidence directory.
  """
  @spec ensure_started() :: :claimed | :unclaimed | {:not_started, term()}
  def ensure_started do
    info = Runtime.info()
    :ok = Pipeline.flush(Runtime.pipeline())

    case head(info) do
      {:ok, {last, _ref}} when last >= 2 ->
        forget(info)
        Runtime.put_claimed()
        # The gateway's standing is worked out again from the roots as
        # they now are.
        Recurse.Gateway.Provenance.Grants.refresh()
        :claimed

      {:ok, {1, _ref}} ->
        with {:ok, _signer} <- bootstrap(info, :load), :ok <- ensure_code(info) do
          :unclaimed
        else
          {:error, reason} ->
            Logger.warning(
              "evidence: this deployment was started and its bootstrap key is gone " <>
                "(#{inspect(reason)}); it cannot be claimed"
            )

            {:not_started, :bootstrap_key_lost}
        end

      {:ok, nil} ->
        begin(info)

      other ->
        {:not_started, other}
    end
  end

  defp begin(info) do
    with [published | _] <- Map.get(info, :publications, []),
         {:ok, signer} <- bootstrap(info, :make),
         {:ok, envelope} <- chain_started(info, signer, published),
         {:ok, _receipt} <-
           Pipeline.accept(
             Runtime.pipeline(),
             envelope,
             keys_of(signer),
             profile(info, signer),
             "start"
           ),
         :ok <- Pipeline.flush(Runtime.pipeline()),
         :ok <- ensure_code(info) do
      Logger.info(
        "evidence: this deployment's chain has started and is waiting to be claimed; " <>
          "the claim code is in #{Path.join(info.dir, @code_file)}"
      )

      :unclaimed
    else
      [] ->
        Logger.warning(
          "evidence: no publication is installed, so this deployment cannot say what it was " <>
            "built from and its chain is not started (set R5E_EVIDENCE_PUBLICATIONS_FILE)"
        )

        {:not_started, :no_publication}

      {:error, reason} ->
        Logger.warning(
          "evidence: this deployment's chain could not be started: #{inspect(reason)}"
        )

        {:not_started, reason}
    end
  end

  @doc "What anyone may know about this deployment's start."
  @spec describe() :: map()
  def describe do
    info = Runtime.info()
    records = records(info)

    base = %{"deployment" => info.deployment, "chain" => nil, "state" => "not_started"}

    case records do
      [first] ->
        Map.merge(base, %{
          "state" => "unclaimed",
          "chainStarted" => wire_record(first),
          "bootstrapKey" => wire_key_of(first)
        })

      [first, second | _later] ->
        Map.merge(base, %{
          "state" => "claimed",
          "chain" => second.ref,
          "chainStarted" => wire_record(first),
          "bootstrapKey" => wire_key_of(first),
          "deploymentRecord" => wire_record(second),
          "roots" => roots().current,
          "startHead" => length(records),
          "grants" => Recurse.Gateway.Provenance.Grants.list(),
          # The working key a root endorses, for a second root or a later
          # renewal that never saw the answer to the claim.
          "gatewayKey" => %{
            "keyid" => info.key_id,
            "algorithm" => info.algorithm,
            "bytes" => Base.encode64(info.public_key)
          }
        })

      _ ->
        base
    end
  end

  @doc """
  The records of this deployment's start as a set to carry in an export:
  the records themselves, the bootstrap key and the roots' keys, and the
  bootstrap key's profile. With them a bundle can be read by someone who
  pins the chain by name. An empty set when the chain has not started.
  """
  @spec carried() :: %{String.t() => [map()]}
  def carried do
    # A process that only exports is not capturing; it reads the same
    # store the gateway writes to.
    info =
      Runtime.info() ||
        (fn deployment -> %{deployment: deployment, store: Runtime.store(deployment)} end).(
          Application.get_env(:recurse_gateway, :evidence_deployment, "default")
        )

    carried(info, records(info))
  end

  defp carried(_info, []), do: %{"records" => [], "keys" => [], "blobs" => []}

  defp carried(%{store: {module, handle}}, [first | _] = records) do
    roots =
      for %{evidence: %{"kind" => kind, "body" => %{"roots" => roots} = body}} <- records,
          kind in ["Deployment", "RootsChanged"],
          entry <-
            roots ++
              if(kind == "RootsChanged",
                do: [%{"key" => body["signer"], "publicKey" => body["signerKey"]}],
                else: []
              ),
          %{"key" => key, "publicKey" => public} = entry,
          do: Map.put(public, "keyid", key)

    blobs =
      case module.get_blob(handle, first.evidence["profileRef"]) do
        {:ok, bytes} -> [%{"ref" => Ref.bytes(bytes), "base64" => Base.encode64(bytes)}]
        :error -> []
      end

    %{
      "records" => Enum.map(records, &wire_record/1),
      "keys" => Enum.uniq_by([wire_key_of(first) | roots], & &1["keyid"]),
      "blobs" => blobs
    }
  end

  @doc """
  The root keys of this deployment: those in force now, and every key
  that has ever been one. A new grant must come from a root in force; a
  grant an earlier root gave, recorded and sealed while it was one, still
  stands.
  """
  @spec roots() :: %{current: [String.t()], ever: [String.t()]}
  def roots do
    info = Runtime.info()

    steps =
      for %{evidence: %{"kind" => kind, "body" => %{"roots" => roots}}} <- records(info),
          kind in ["Deployment", "RootsChanged"],
          do: Enum.map(roots, & &1["key"])

    %{current: List.last(steps) || [], ever: steps |> List.flatten() |> Enum.uniq()}
  end

  @doc "Whether this deployment has been claimed."
  @spec claimed?() :: boolean()
  def claimed? do
    case Runtime.info() do
      nil -> false
      info -> match?({:ok, {last, _}} when last >= 2, head(info))
    end
  end

  @doc """
  The first step: answer with the exact deployment record this node is
  prepared to sign, for the roots the operator names.
  """
  @spec prepare(map()) :: {:ok, map()} | {:error, error()}
  def prepare(%{"code" => code, "claimedBy" => claimed_by, "roots" => roots} = request)
      when is_binary(code) and is_binary(claimed_by) and is_list(roots) do
    info = Runtime.info()

    with [first] <- records(info) || {:error, :not_started},
         :ok <- check_code(info, code),
         {:ok, signer} <- bootstrap(info, :load),
         {:ok, listed} <- roots(roots),
         {:ok, body} <- terms(request, listed, claimed_by, first, signer),
         evidence =
           Evidence.new(
             kind_path: @base <> "/Deployment",
             schema_ref: elem(Definitions.fetch(@base <> "/Deployment"), 1).ref,
             profile_ref: Profile.ref(profile(info, signer)),
             issuer: signer.key_id,
             actor: actor(info),
             stream: stream(info.deployment),
             seq: 2,
             previous: first.ref,
             captured_at: DateTime.utc_now(),
             body: body
           ),
         # Checked against the definition now, so a root is never asked to
         # sign something this node would then refuse to record.
         {:ok, :validated} <-
           Evidence.validate(evidence, signers: [signer.key_id, claimed_by])
           |> terms_match(),
         {:ok, payload} <- Evidence.encode(evidence),
         {:ok, ticket, expires} <- ticket(payload, signer) do
      encoded = Profile.encode(profile(info, signer))

      {:ok,
       %{
         "payloadType" => Envelope.payload_type(),
         "payload" => Base.encode64(payload),
         "ticket" => ticket,
         "expires" => expires |> DateTime.from_unix!() |> DateTime.to_iso8601(),
         "chainStarted" => wire_record(first),
         "bootstrapKey" => wire_key(signer),
         "publication" => published(info),
         "bootstrapProfile" => %{"ref" => Ref.bytes(encoded), "base64" => Base.encode64(encoded)}
       }}
    else
      [_first, _second | _later] -> {:error, :already_claimed}
      [] -> {:error, :not_started}
      {:error, reason} when is_atom(reason) -> {:error, reason}
      _ -> {:error, :malformed_request}
    end
  end

  def prepare(_request), do: {:error, :malformed_request}

  @doc """
  The second step: take the root's signature, add the bootstrap key's,
  record the deployment record, and destroy the bootstrap key.

  Offered again after it succeeded, with the same payload, it answers
  the same; the answer holds nothing that is not already on the record.
  """
  @spec finalize(map()) :: {:ok, :created | :already, map()} | {:error, error()}
  def finalize(
        %{"payload" => payload64, "rootSignature" => %{"keyid" => keyid, "sig" => sig64}} =
          request
      )
      when is_binary(payload64) and is_binary(keyid) and is_binary(sig64) do
    info = Runtime.info()

    with {:ok, payload} <- strict64(payload64),
         ref = Evidence.ref(payload) do
      case records(info) do
        [first, %{ref: ^ref} = second | _later] ->
          {:ok, :already, claimed(info, first, second)}

        [_first, _second | _later] ->
          {:error, :already_claimed}

        [first] ->
          complete(info, first, payload, keyid, sig64, request)

        _ ->
          {:error, :not_started}
      end
    end
  end

  def finalize(_request), do: {:error, :malformed_request}

  defp complete(info, first, payload, keyid, sig64, request) do
    with :ok <- check_code(info, request["code"]),
         {:ok, signer} <- bootstrap(info, :load),
         :ok <- check_ticket(request["ticket"], payload, signer),
         {:ok, %{"body" => %{"claimedBy" => ^keyid, "roots" => roots}}} <-
           Canonical.decode_json(payload),
         %{"publicKey" => %{"algorithm" => algorithm, "bytes" => bytes64}} <-
           Enum.find(roots, &(&1["key"] == keyid)),
         {:ok, bytes} <- strict64(bytes64),
         {:ok, signature} <- strict64(sig64),
         message = Envelope.message(payload),
         true <- Key.verify(algorithm, message, signature, bytes) || {:error, :bad_signature},
         {:ok, ours} <- signer.sign.(message),
         envelope = Envelope.assemble(payload, [{signer.key_id, ours}, {keyid, signature}]),
         keys = Map.put(keys_of(signer), keyid, %{algorithm: algorithm, bytes: bytes}),
         {:ok, %{ref: ref}} <-
           Pipeline.accept(Runtime.pipeline(), envelope, keys, profile(info, signer), "start"),
         # The record is in the index before the key that signed it is
         # destroyed; a crash between the two leaves a key to remove at the
         # next start, never a claim that was answered and not recorded.
         :ok <- Pipeline.flush(Runtime.pipeline()) do
      forget(info)
      Runtime.put_claimed()
      Logger.info("evidence: this deployment was claimed; its chain is #{ref}")
      {:ok, :created, claimed(info, first, %{ref: ref, envelope: envelope})}
    else
      {:error, reason} when is_atom(reason) -> {:error, reason}
      {:ok, _other_claimant} -> {:error, :signature_is_not_the_claimants}
      nil -> {:error, :signature_is_not_the_claimants}
      _ -> {:error, :malformed_request}
    end
  end

  defp claimed(info, first, second) do
    %{
      "deploymentRecord" => wire_record(second),
      "chain" => second.ref,
      "chainStarted" => wire_record(first),
      "gatewayKey" => %{
        "keyid" => info.key_id,
        "algorithm" => info.algorithm,
        "bytes" => Base.encode64(info.public_key)
      },
      "streamPrefix" => "urn:r5e:stream:#{info.deployment}:"
    }
  end

  # -- the start record ----------------------------------------------------

  defp chain_started(info, signer, %{"records" => [%{"ref" => ref, "envelope" => envelope} | _]}) do
    with {:ok, %{evidence: published}} <- Envelope.open(envelope),
         :ok <- built_from(published),
         evidence =
           Evidence.new(
             kind_path: @base <> "/ChainStarted",
             schema_ref: elem(Definitions.fetch(@base <> "/ChainStarted"), 1).ref,
             profile_ref: Profile.ref(profile(info, signer)),
             issuer: signer.key_id,
             actor: actor(info),
             stream: stream(info.deployment),
             seq: 1,
             previous: nil,
             captured_at: DateTime.utc_now(),
             body: %{
               "deployment" => info.deployment,
               "bootstrap" => signer.key_id,
               "bootstrapKey" => public_key(signer),
               "publication" => ref,
               "publisher" => published["issuer"],
               "definitions" => published["body"]["definitions"]
             }
           ),
         {:ok, signed} <- Envelope.sign(evidence, signer) do
      {:ok, signed.envelope}
    end
  end

  # A chain says at its start which definitions it began with, and every
  # record this node writes afterwards cites the definitions it has
  # installed. If the two differ the start still looks sound, and the
  # first record of a kind that differs fails for every reader who
  # checks it against the publication. So a chain is not started unless
  # the publication names exactly what is installed.
  defp built_from(published) do
    named =
      for %{"kind" => kind, "definition" => ref} <- List.wrap(published["body"]["definitions"]),
          into: MapSet.new(),
          do: {kind, ref}

    installed = MapSet.new(Definitions.documents(), &{&1.kind_path, &1.ref})

    if named == installed,
      do: :ok,
      else: {:error, :publication_is_not_what_is_installed}
  end

  # The bootstrap key's own profile: it may write the start stream and
  # nothing else.
  defp profile(info, signer) do
    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: stream(info.deployment),
            actor_prefixes: ["urn:r5e:node:"],
            issuer_keys: [signer.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "the node's own disk until shipped",
        deployment_policy_ref: Ref.bytes("r5e.bootstrap/" <> info.deployment),
        policy_required_kinds: []
      )

    profile
  end

  defp actor(info), do: "urn:r5e:node:" <> info.deployment

  # -- the terms of a claim --------------------------------------------------

  defp roots(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn
      %{"publicKey" => %{"algorithm" => algorithm, "bytes" => bytes64} = public} = entry,
      {:ok, acc} ->
        with {:ok, bytes} <- strict64(bytes64),
             {:ok, key_id} <- Key.id(algorithm, bytes) do
          root =
            entry
            |> Map.take(["holder", "custody", "identity"])
            |> Map.merge(%{
              "key" => key_id,
              "publicKey" => Map.take(public, ["algorithm", "bytes"])
            })

          {:cont, {:ok, acc ++ [root]}}
        else
          _ -> {:halt, {:error, :unreadable_public_key}}
        end

      _other, _acc ->
        {:halt, {:error, :unreadable_public_key}}
    end)
  end

  defp terms(request, roots, claimed_by, first, signer) do
    keys = Enum.map(roots, & &1["key"])
    threshold = Map.get(request, "threshold", 1)
    recovery = Map.get(request, "recoveryKeys")
    custodians = Map.get(request, "custodians")

    cond do
      roots == [] or keys != Enum.uniq(keys) ->
        {:error, :duplicate_root}

      claimed_by not in keys ->
        {:error, :claimed_by_is_not_a_root}

      not is_integer(threshold) or threshold < 1 or threshold > length(keys) ->
        {:error, :threshold_exceeds_roots}

      is_list(recovery) and Enum.any?(recovery, &(&1 in keys)) ->
        {:error, :recovery_key_is_a_root}

      true ->
        {:ok,
         %{
           "accepts" => first.ref,
           "bootstrap" => signer.key_id,
           "claimedBy" => claimed_by,
           "roots" => roots,
           "threshold" => threshold
         }
         |> put_list("recoveryKeys", recovery)
         |> put_list("custodians", custodians)}
    end
  end

  defp terms_match({:ok, :validated}), do: {:ok, :validated}
  defp terms_match(_other), do: {:error, :terms_do_not_match_the_definition}

  defp put_list(map, key, [_ | _] = list), do: Map.put(map, key, list)
  defp put_list(map, _key, _absent), do: map

  # -- the bootstrap key and the claim code ------------------------------------

  defp bootstrap(info, mode) do
    path = Path.join(info.dir, @key_file)

    case {File.read(path), mode} do
      {{:ok, text}, _mode} ->
        with {:ok, <<private::binary-32>>} <- Base.decode64(String.trim(text)) do
          {public, _} = :crypto.generate_key(:eddsa, :ed25519, private)
          {:ok, Key.local_signer("ed25519", public, private)}
        else
          _ -> {:error, :unreadable_bootstrap_key}
        end

      {{:error, :enoent}, :make} ->
        {public, private} = :crypto.generate_key(:eddsa, :ed25519)

        with :ok <- write_private(path, Base.encode64(private)),
             do: {:ok, Key.local_signer("ed25519", public, private)}

      {{:error, reason}, _mode} ->
        {:error, reason}
    end
  end

  defp ensure_code(info) do
    path = Path.join(info.dir, @code_file)

    if File.exists?(path),
      do: :ok,
      else: write_private(path, Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false))
  end

  defp check_code(info, given) when is_binary(given) do
    case File.read(Path.join(info.dir, @code_file)) do
      {:ok, held} ->
        if Plug.Crypto.secure_compare(String.trim(held), given),
          do: :ok,
          else: {:error, :wrong_claim_code}

      _ ->
        {:error, :wrong_claim_code}
    end
  end

  defp check_code(_info, _given), do: {:error, :wrong_claim_code}

  # Written private and complete: made under another name with owner-only
  # permissions before any byte is written, then linked into place.
  defp write_private(path, text) do
    File.mkdir_p!(Path.dirname(path))
    # The directory itself is closed to others first, so nothing made in
    # it is ever readable by anyone else, even for a moment.
    File.chmod(Path.dirname(path), 0o700)
    temporary = path <> ".new-" <> Base.encode16(:crypto.strong_rand_bytes(6), case: :lower)

    with {:ok, device} <- :file.open(temporary, [:raw, :write, :exclusive]) do
      try do
        :ok = :file.change_mode(temporary, 0o600)
        :ok = :file.write(device, text)
        :ok = :file.close(device)
        :file.make_link(temporary, path)
      after
        File.rm(temporary)
      end
    end
  end

  defp forget(info) do
    File.rm(Path.join(info.dir, @key_file))
    File.rm(Path.join(info.dir, @code_file))
    :ok
  end

  # -- the ticket ---------------------------------------------------------------

  defp ticket(payload, signer) do
    expires = System.os_time(:second) + @ticket_seconds

    with {:ok, signature} <- signer.sign.(ticket_message(payload, expires)) do
      {:ok, Base.url_encode64(<<expires::unsigned-64, signature::binary>>, padding: false),
       expires}
    end
  end

  defp check_ticket(ticket, payload, signer) when is_binary(ticket) do
    with {:ok, <<expires::unsigned-64, signature::binary>>} <-
           Base.url_decode64(ticket, padding: false),
         true <- expires >= System.os_time(:second) || {:error, :ticket_expired},
         true <-
           Key.verify("ed25519", ticket_message(payload, expires), signature, signer.public_key) ||
             {:error, :ticket_does_not_match} do
      :ok
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :ticket_does_not_match}
    end
  end

  defp check_ticket(_ticket, _payload, _signer), do: {:error, :ticket_does_not_match}

  defp ticket_message(payload, expires),
    do: @ticket_context <> <<0>> <> :crypto.hash(:sha256, payload) <> <<expires::unsigned-64>>

  # -- reading the start stream ---------------------------------------------------

  defp head(%{store: {module, handle}} = info), do: module.head(handle, stream(info.deployment))

  defp records(%{store: {module, handle}} = info) do
    case head(info) do
      {:ok, {last, _ref}} ->
        case module.range(handle, stream(info.deployment), 1, last) do
          {:ok, entries} -> entries
          _ -> []
        end

      _ ->
        []
    end
  end

  defp published(info) do
    case Map.get(info, :publications, []) do
      [set | _] -> set
      [] -> %{"records" => [], "keys" => [], "blobs" => []}
    end
  end

  defp wire_record(%{ref: ref, envelope: envelope}), do: %{"ref" => ref, "envelope" => envelope}

  defp wire_key_of(%{evidence: %{"body" => %{"bootstrap" => id, "bootstrapKey" => key}}}),
    do: Map.put(key, "keyid", id)

  defp wire_key(signer),
    do: %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }

  defp public_key(signer),
    do: %{"algorithm" => signer.algorithm, "bytes" => Base.encode64(signer.public_key)}

  defp keys_of(signer),
    do: %{signer.key_id => %{algorithm: signer.algorithm, bytes: signer.public_key}}

  defp strict64(text) when is_binary(text) do
    case Base.decode64(text) do
      {:ok, bytes} when bytes != "" ->
        if Base.encode64(bytes) == text, do: {:ok, bytes}, else: {:error, :malformed_request}

      _ ->
        {:error, :malformed_request}
    end
  end

  defp strict64(_other), do: {:error, :malformed_request}
end
