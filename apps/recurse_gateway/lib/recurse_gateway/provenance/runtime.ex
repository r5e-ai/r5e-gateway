defmodule Recurse.Gateway.Provenance.Runtime do
  @moduledoc """
  Evidence capture for this gateway.

  Starts a `Recurse.Provenance.Pipeline` configured for the deployment:
  the document-signing key from the secrets provider, a capture profile
  that grants this gateway its streams, a local directory for the log,
  and Postgres plus the storage provider as the index and content store.

  The proxy hands the pipeline each closed call. Nothing here is on the
  path of a request: capture answers once a record is signed, and
  writing, shipping and sealing follow on their own.
  """

  use Supervisor

  require Logger

  alias Recurse.Gateway.Provenance.{Carried, Enrolment, Signer}
  alias Recurse.Provenance.{Definitions, Pipeline, Profile, Ref}
  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore}

  @pipeline __MODULE__.Pipeline
  @info {__MODULE__, :info}

  def start_link(opts), do: Supervisor.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Whether evidence capture is running in this node."
  @spec running?() :: boolean()
  def running?, do: :persistent_term.get(@info, nil) != nil

  @doc "The pipeline to capture into."
  @spec pipeline() :: Pipeline.t()
  def pipeline, do: @pipeline

  @doc "Actor, profile, key and index of the running capture."
  @spec info() :: map() | nil
  def info, do: :persistent_term.get(@info, nil)

  @doc "Write, sync and ship everything captured so far."
  @spec flush() :: :ok | {:error, term()}
  def flush, do: Pipeline.flush(@pipeline)

  @doc """
  Flush, then seal every stream's unsealed records.

  A deployment that begins its own chain seals nothing until it has been
  claimed and its key holds a grant, in force now, that covers sealing.
  A seal made earlier would be dated before the gateway had any
  standing, and every later reader would find it without authority.
  """
  @spec seal() :: {:ok, [map()]} | {:error, term()}
  def seal do
    info = info()

    if Map.get(info, :start_chain?, false) and not may_seal?(info) do
      {:ok, []}
    else
      Pipeline.seal_all(@pipeline, info.actor)
    end
  end

  defp may_seal?(%{authority: standing}),
    do: Enrolment.covers?(standing, Definitions.api_version() <> "/EpochSeal")

  @doc """
  Whether this gateway may carry agent traffic. A deployment that begins
  its own chain serves nothing until a customer has claimed it; one that
  does not is unaffected. Read from memory, never from storage, because
  it is asked on every request.
  """
  @spec serving?() :: boolean()
  def serving? do
    case info() do
      %{start_chain?: true} = info -> Map.get(info, :claimed?, false)
      _ -> true
    end
  end

  @doc "Note that this deployment has been claimed."
  @spec put_claimed() :: :ok
  def put_claimed do
    :persistent_term.put(@info, Map.put(info(), :claimed?, true))
    :ok
  end

  @doc "Replace the standing this gateway acts under, when a grant is accepted."
  @spec put_authority(map() | nil) :: :ok
  def put_authority(standing) do
    :persistent_term.put(@info, %{info() | authority: standing})
    :ok
  end

  @impl true
  def init(opts) do
    deployment = Keyword.fetch!(opts, :deployment)

    {store_module, _} =
      index = Keyword.get_lazy(opts, :store, fn -> store(deployment) end)

    {:ok, signer} =
      case Keyword.fetch(opts, :signer) do
        {:ok, signer} ->
          {:ok, signer}

        :error ->
          {module, state} =
            Keyword.get_lazy(opts, :secrets, &Recurse.Gateway.ProviderRegistry.secrets_provider/0)

          Signer.from_secrets(module, state)
      end

    if match?({_, %{keys: _}}, index) do
      Logger.info("evidence: recorded content is encrypted before it is stored")
    else
      Logger.warning(
        "evidence: recorded content is stored unencrypted and cannot later be erased by " <>
          "destroying a key; set R5E_EVIDENCE_CONTENT_KEY_FILE"
      )
    end

    # An operator needs this to have the gateway's key endorsed.
    Logger.info("evidence: this gateway signs as #{signer.key_id}")

    prefix = "urn:r5e:stream:#{deployment}:"
    actor = "urn:r5e:gateway:#{deployment}"
    tool_call = Definitions.api_version() <> "/ToolCall"

    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: prefix,
            actor_prefixes: Keyword.get(opts, :actor_prefixes, ["urn:r5e:", "spiffe://"]),
            issuer_keys: [signer.key_id],
            sealer_keys: [signer.key_id]
          }
        ],
        failure_domain:
          Keyword.get(opts, :failure_domain, "local disk, then #{inspect(store_module)}"),
        policy_required_kinds:
          if(Keyword.get(opts, :policy_required?, false), do: [tool_call], else: []),
        deployment_policy_ref:
          Ref.bytes(Keyword.get(opts, :deployment_definition, "r5e.deployment/unspecified")),
        # Content is kept for ever unless the operator has said how long
        # it must be kept before it may be disposed of.
        retention: Keyword.get(opts, :retention)
      )

    dir = Keyword.get_lazy(opts, :dir, fn -> default_dir(deployment) end)

    # Content waiting on this gateway's own disk is encrypted whenever a
    # key service is configured: the spool's keys are kept only locked by
    # it. Without one there is nothing to lock them with, and content waits
    # as it always has.
    spool =
      case index do
        {_, %{keys: {_, _} = keys}} ->
          if Keyword.get(
               opts,
               :spool?,
               Application.get_env(:recurse_gateway, :evidence_spool?, true)
             ),
             do: keys

        _ ->
          nil
      end

    :persistent_term.put(@info, %{
      deployment: deployment,
      dir: dir,
      actor: actor,
      profile: profile,
      profile_ref: Profile.ref(profile),
      key_id: signer.key_id,
      algorithm: signer.algorithm,
      public_key: signer.public_key,
      signer: signer,
      start_chain?: Keyword.get(opts, :start_chain?, false),
      authority: authority(opts, signer, dir),
      publications: Keyword.get_lazy(opts, :publications, &Carried.load_publications/0),
      store: index,
      spool?: spool != nil
    })

    # What was provided to the public on earlier runs is public again.
    Recurse.Gateway.Provenance.Disclosing.init(index, deployment)

    # Definitions publishers added on earlier runs are in force again.
    Recurse.Gateway.Provenance.Published.load(dir)

    pipeline =
      {Pipeline,
       [
         name: @pipeline,
         dir: dir,
         stream_prefix: prefix,
         signer: signer,
         actor: actor,
         profile: profile,
         index: index,
         staging: if(spool, do: Recurse.Gateway.Provenance.SpoolStaging.new(dir))
       ] ++ Keyword.take(opts, [:partitions, :flush_interval_ms, :max_batch])}

    # Which recorded tool call a returning result answers. Owned by this
    # supervisor, so it lasts exactly as long as capture does.
    Recurse.Gateway.Provenance.ToolResults.init()

    # The spool's keys come before the pipeline, which writes under them.
    spool_keys =
      if spool do
        [
          {Recurse.Gateway.Provenance.SpoolKeys,
           [dir: dir, deployment: deployment, keys: spool, pipeline: @pipeline] ++
             Keyword.get(opts, :spool_opts, [])}
        ]
      else
        []
      end

    # The sealer comes after the pipeline, so on shutdown it stops first
    # and its last seal finds the pipeline still running.
    sealer =
      case Keyword.get(opts, :seal_interval_ms) do
        nil -> []
        interval -> [{Recurse.Gateway.Provenance.Sealer, interval_ms: interval}]
      end

    # Once the pipeline is up, begin this deployment's chain if it has not
    # begun. It runs once and off to the side: a node that cannot start
    # its chain still captures, and says why in its log.
    starter =
      if Keyword.get(opts, :start_chain?, false) do
        [
          Supervisor.child_spec(
            {Task, fn -> Recurse.Gateway.Provenance.Claim.ensure_started() end},
            id: :start_chain,
            restart: :temporary
          )
        ]
      else
        []
      end

    # A hold or disposal that was recorded and not applied before the last
    # stop is applied now. Off to the side, like the start of the chain.
    reconciler = [
      Supervisor.child_spec(
        {Task, fn -> Recurse.Gateway.Provenance.Retention.reconcile() end},
        id: :reconcile_retention,
        restart: :temporary
      )
    ]

    Supervisor.init(spool_keys ++ [pipeline] ++ starter ++ reconciler ++ sealer,
      strategy: :rest_for_one
    )
  end

  # The records that give this gateway's key its standing to vouch for
  # workloads, installed by the operator. Without them, or if they do not
  # hold together, the gateway captures as usual and enrols nobody.
  defp authority(opts, signer, dir) do
    chain =
      case Keyword.fetch(opts, :authority) do
        {:ok, chain} -> chain
        :error -> authority_file(Application.get_env(:recurse_gateway, :evidence_authority_file))
      end

    own = %{key_id: signer.key_id, algorithm: signer.algorithm, public_key: signer.public_key}

    # Grants accepted over HTTP in an earlier run take the place of an
    # installed file.
    chain = chain || grants_file(dir)

    with %{} <- chain,
         {:ok, standing} <- Enrolment.standing(chain, signer.key_id, own) do
      standing
    else
      nil ->
        nil

      {:error, reason} ->
        Logger.warning(
          "evidence: the installed authority records do not give this gateway standing " <>
            "(#{inspect(reason)}); no workload will be enrolled"
        )

        nil
    end
  end

  defp grants_file(dir) do
    with {:ok, text} <- File.read(Recurse.Gateway.Provenance.Grants.file(dir)),
         {:ok, %{} = chain} <- Jason.decode(text) do
      chain
    else
      _ -> nil
    end
  end

  defp authority_file(nil), do: nil

  defp authority_file(path) do
    with {:ok, text} <- File.read(path),
         {:ok, %{} = chain} <- Jason.decode(text) do
      chain
    else
      _ ->
        Logger.warning("evidence: #{path} is not a readable authority file")
        nil
    end
  end

  @doc "Where a deployment's local evidence files live."
  @spec dir(String.t()) :: Path.t()
  def dir(deployment), do: default_dir(deployment)

  # Where the local log lives. This is the one place a signed record
  # exists until it has been shipped, so a deployment points it at
  # storage that survives a restart.
  defp default_dir(deployment) do
    base =
      Application.get_env(:recurse_gateway, :evidence_dir) ||
        Path.join(System.tmp_dir!(), "r5e-evidence")

    Path.join(base, deployment)
  end

  @doc """
  The index and content store this deployment records into: records and
  content references in Postgres, content bytes in the storage provider
  when one is installed and inline otherwise.

  It can be opened by a process that is not capturing, which is how an
  export is made without touching the running gateway.
  """
  @spec store(String.t()) :: {module(), term()}
  def store(deployment) do
    repo = Recurse.Providers.Repo

    case Recurse.Gateway.ProviderRegistry.fetch() do
      {:ok, %{storage: {module, state}} = registry} ->
        issuer = "urn:r5e:gateway:#{deployment}"

        ctx =
          Recurse.Shared.IdentityContext.new(%{
            machine_identity: issuer,
            principal:
              Recurse.Shared.Principal.service_account(%{
                issuer: issuer,
                account_id: "evidence-recorder"
              }),
            tenant_id: Map.get(registry, :tenant_id) || deployment,
            correlation_id: "evidence-recorder"
          })

        {PostgresEvidenceStore,
         with_subjects(with_keys(%{repo: repo, content: {module, state, ctx}}))}

      _ ->
        {PostgresEvidenceStore, with_subjects(with_keys(%{repo: repo}))}
    end
  end

  # Which session owners get a key of their own, as a pattern the
  # owner's identity must match. The deployment says what its subjects
  # look like (a school: its student pseudonyms); the gateway does not
  # know what a student is. A pattern needs a key service to mean
  # anything, and a pattern that does not compile stops the node.
  defp with_subjects(handle) do
    case Application.get_env(:recurse_gateway, :evidence_subject_pattern) do
      nil ->
        handle

      pattern when is_binary(pattern) and is_map_key(handle, :keys) ->
        case Regex.compile(pattern) do
          {:ok, regex} ->
            Map.put(handle, :subjects, regex)

          {:error, reason} ->
            raise "R5E_EVIDENCE_SUBJECT_PATTERN is not a pattern: #{inspect(reason)}"
        end

      _pattern ->
        raise "R5E_EVIDENCE_SUBJECT_PATTERN is set but evidence content is not encrypted: " <>
                "set a key service as well"
    end
  end

  # The key service content is encrypted under. A deployment told to use
  # a key file that cannot be read does not start storing content in the
  # clear instead: it stops, because the operator asked for encryption.
  defp with_keys(handle) do
    case Application.get_env(:recurse_gateway, :evidence_key_service) do
      %{kind: :openbao} = config ->
        Map.put(handle, :keys, openbao(config))

      %{kind: :gcp_kms} = config ->
        Map.put(handle, :keys, gcp_kms(config))

      nil ->
        with_key_file(handle)

      other ->
        raise "evidence_key_service is set to something this node cannot use: #{inspect(other)}"
    end
  end

  # A key in Google Cloud KMS. As with OpenBao, the key that locks each
  # scope's key never leaves the service and every read of content asks
  # it. The access token is read from a file each time it is needed.
  defp gcp_kms(config) do
    alias Recurse.Providers.Impls.GcpKmsKeyService, as: Kms

    case Kms.new(Map.take(config, [:crypto_key, :token_path])) do
      {:ok, keys} ->
        {Kms, keys}

      {:error, reason} ->
        raise "the key service configured for evidence (R5E_EVIDENCE_KEY_SERVICE=gcp_kms) " <>
                "cannot be used: #{inspect(reason)}"
    end
  end

  # A key service the customer runs: OpenBao or Vault's Transit engine.
  # The key that locks each scope's key never leaves it, every read of
  # content asks it, and its own log shows each one. The token is read
  # from a file, so it is in no environment and no log.
  defp openbao(config) do
    alias Recurse.Providers.Impls.OpenBaoTransitKeyService, as: Transit

    case Transit.new(Map.take(config, [:url, :mount, :key_name, :token_path, :namespace])) do
      {:ok, keys} ->
        {Transit, keys}

      {:error, reason} ->
        raise "the key service configured for evidence (R5E_EVIDENCE_KEY_SERVICE=openbao) " <>
                "cannot be used: #{inspect(reason)}"
    end
  end

  defp with_key_file(handle) do
    case Application.get_env(:recurse_gateway, :evidence_content_key_file) do
      nil ->
        handle

      path ->
        case LocalKeyService.open(path) do
          {:ok, keys} ->
            Map.put(handle, :keys, {LocalKeyService, keys})

          {:error, reason} ->
            raise "R5E_EVIDENCE_CONTENT_KEY_FILE (#{path}) cannot be used: #{inspect(reason)}"
        end
    end
  end

  @doc false
  def stop do
    :persistent_term.erase(@info)
    Recurse.Gateway.Provenance.Published.unload()
    Recurse.Gateway.Provenance.Disclosing.unload()
    if pid = Process.whereis(__MODULE__), do: Supervisor.stop(pid)
    :ok
  end
end
