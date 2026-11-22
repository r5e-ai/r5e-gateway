defmodule Recurse.Provenance.Profile do
  @moduledoc """
  The capture profile: a small, versioned declaration every record cites
  (contract §5).

  It binds kind paths to their exact definitions, states which keys may
  issue records for which streams and actors, which keys may seal a
  stream, what a durable receipt means here, and which kinds must carry an
  inline policy evaluation. It is retained content addressed by its
  canonical bytes, not an event per call.

  A profile's own bytes confer no authority. Whether a given profile is
  the one in force is established outside it, and a reader that lacks
  that input reports authority as unestablished.
  """

  alias Recurse.Provenance.{Definitions, Evidence, Ref, Schema}
  alias RecurseVerify.Canonical

  @format "r5e.capture-profile/v2"

  @type t :: %{String.t() => term()}

  @doc """
  Build a profile.

    * `:schemas` — kind path to `schemaRef`; defaults to the base definitions
    * `:bindings` — list of `%{stream_prefix:, actor_prefixes:, issuer_keys:, sealer_keys:}`
    * `:checkpoint_keys` — default `[]`
    * `:failure_domain`, `:required_payloads` (`"submitted"` default),
      `:on_failure` (`"refuse"` default)
    * `:policy_required_kinds` — kind paths; default model and tool calls
    * `:deployment_policy_ref` — `bytes:` reference of the deployment definition
  """
  @spec new(keyword() | map()) :: {:ok, t()} | {:error, [Schema.problem()]}
  def new(fields) do
    f = Map.new(fields)
    base = Definitions.api_version()

    profile = %{
      "format" => @format,
      "schemas" => Map.get(f, :schemas, Definitions.schema_refs()),
      "authority" => %{
        "bindings" =>
          Enum.map(Map.fetch!(f, :bindings), fn b ->
            %{
              "streamPrefix" => Map.fetch!(b, :stream_prefix),
              "actorPrefixes" => Map.fetch!(b, :actor_prefixes),
              "issuerKeys" => Map.fetch!(b, :issuer_keys),
              "sealerKeys" => Map.get(b, :sealer_keys, [])
            }
          end),
        "checkpointKeys" => Map.get(f, :checkpoint_keys, [])
      },
      "durability" => %{
        "failureDomain" => Map.fetch!(f, :failure_domain),
        "requiredPayloads" => Map.get(f, :required_payloads, "submitted"),
        "onFailure" => Map.get(f, :on_failure, "refuse")
      },
      "policyRequiredKinds" =>
        Map.get(f, :policy_required_kinds, [base <> "/ModelCall", base <> "/ToolCall"]),
      "deploymentPolicyRef" => Map.fetch!(f, :deployment_policy_ref)
    }

    # How long content must be kept. Left out, content is never disposed
    # of; a customer who wants disposal says so here, with a period,
    # before the records it applies to are made.
    profile =
      case Map.get(f, :retention) do
        nil ->
          profile

        {:keep_for_seconds, seconds} ->
          Map.put(profile, "retention", %{
            "disposal" => "by-record",
            "keepContentForSeconds" => seconds
          })

        :never ->
          Map.put(profile, "retention", %{"disposal" => "never"})
      end

    with :ok <- validate(profile), do: {:ok, profile}
  end

  @doc "Check a profile's shape and that every policy-required kind is mapped."
  @spec validate(t()) :: :ok | {:error, [Schema.problem()]}
  def validate(profile) do
    with :ok <- Schema.validate(Definitions.profile_schema(), profile) do
      case Enum.reject(profile["policyRequiredKinds"], &Map.has_key?(profile["schemas"], &1)) do
        [] ->
          :ok

        missing ->
          {:error, [{"/policyRequiredKinds", "not in schemas: #{Enum.join(missing, ", ")}"}]}
      end
    end
  end

  @doc "Canonical bytes of a profile."
  @spec encode(t()) :: binary()
  def encode(profile), do: Canonical.encode(profile)

  @doc "The `profileRef` of a profile."
  @spec ref(t()) :: Ref.t()
  def ref(profile), do: profile |> encode() |> Ref.bytes()

  @doc """
  Check one record against the profile it cites: its kind is mapped to
  the definition it names, one authority binding covers its stream, actor
  and issuer together, and a policy-required kind carries `body.policy`.

  Prefixes match literal bytes. This says the record is within the
  profile's bounds; it does not say the profile is trusted.
  """
  @spec check(t(), Evidence.t()) :: :ok | {:error, atom()}
  def check(profile, evidence) do
    path = Evidence.kind_path(evidence)

    cond do
      Map.get(profile["schemas"], path) != evidence["schemaRef"] ->
        {:error, :kind_not_in_profile}

      not issuer_bound?(profile, evidence) ->
        {:error, :issuer_not_bound}

      path in profile["policyRequiredKinds"] and not is_map(evidence["body"]["policy"]) ->
        {:error, :policy_required}

      true ->
        :ok
    end
  end

  @doc "Whether one binding grants this stream, actor and issuer together."
  @spec issuer_bound?(t(), Evidence.t()) :: boolean()
  def issuer_bound?(profile, %{"stream" => stream, "actor" => actor, "issuer" => issuer}) do
    Enum.any?(profile["authority"]["bindings"], fn b ->
      String.starts_with?(stream, b["streamPrefix"]) and
        Enum.any?(b["actorPrefixes"], &String.starts_with?(actor, &1)) and
        issuer in b["issuerKeys"]
    end)
  end

  @doc "Whether `key_id` may seal `stream` under this profile."
  @spec sealer?(t(), String.t(), String.t()) :: boolean()
  def sealer?(profile, stream, key_id) do
    Enum.any?(profile["authority"]["bindings"], fn b ->
      String.starts_with?(stream, b["streamPrefix"]) and key_id in b["sealerKeys"]
    end)
  end
end
