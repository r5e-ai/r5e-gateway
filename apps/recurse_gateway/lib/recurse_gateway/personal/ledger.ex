defmodule Recurse.Gateway.Personal.Ledger do
  @moduledoc """
  Durable evidence-ledger bridge for `/v1/personal/*` operations.

  Guarantees that EVERY evidence reference returned by a personal route
  (`erasureRef`, `coSignRef`, `recoveryCompletedRef`, `rootsChangedRef`,
  `revocationRef`, `badgeRef`, `pairedRecordRef`) corresponds to a real
  signed record admitted to `evidence_records` and resolvable via
  `GET /v1/evidence/records/:ref`.

  Fails closed (`{:error, :evidence_runtime_unavailable}`) whenever the
  provenance runtime is not running rather than fabricating random refs.
  """

  alias Recurse.Gateway.Provenance.{Runtime, SessionName}
  alias Recurse.Provenance.{Body, Evidence, Pipeline, Ref}
  alias Recurse.Providers.Personal, as: Store

  @observation "provenance.r5e.io/v2/Observation"
  @erasure_kinds [
    "provenance.r5e.io/v2/PayloadDisposition",
    "personal.r5e.io/v1/PersonalErasure"
  ]

  @doc """
  Capture and flush a real signed `provenance.r5e.io/v2/Observation` record
  into the evidence runtime and return `{:ok, receipt.ref}`.
  """
  @spec record_observation(String.t(), String.t(), map(), keyword()) ::
          {:ok, String.t()} | {:error, atom()}
  def record_observation(topic, actor, details, opts \\ [])
      when is_binary(topic) and topic != "" and is_binary(actor) and is_map(details) do
    if Runtime.running?() do
      params =
        %{
          kind_path: @observation,
          actor: actor,
          body:
            Body.observation(
              topic: topic,
              content_refs: [],
              about: Keyword.get(opts, :about),
              details: sanitize_details(details)
            )
        }
        |> maybe_put_session(Keyword.get(opts, :session))

      with {:ok, receipt} <- Pipeline.capture(Runtime.pipeline(), params),
           :ok <- Runtime.flush() do
        {:ok, receipt.ref}
      else
        {:error, reason} when is_atom(reason) -> {:error, reason}
        _ -> {:error, :evidence_capture_failed}
      end
    else
      {:error, :evidence_runtime_unavailable}
    end
  end

  @doc """
  Verify that `ref` refers to a real record already admitted in `evidence_records`.
  """
  @spec verify_admitted_ref(term(), keyword()) :: {:ok, map()} | {:error, atom()}
  def verify_admitted_ref(ref, opts \\ [])

  def verify_admitted_ref(ref, opts) when is_binary(ref) do
    if Runtime.running?() do
      %{store: {module, handle}} = Runtime.info()

      with true <- Ref.valid?(ref, :evidence) || {:error, :invalid_evidence_ref},
           {:ok, entry} <- fetch_entry(module, handle, ref),
           :ok <- check_allowed_kinds(entry, Keyword.get(opts, :allowed_kinds)),
           :ok <- check_household_binding(entry, Keyword.get(opts, :household_id)) do
        {:ok, entry}
      end
    else
      {:error, :evidence_runtime_unavailable}
    end
  end

  def verify_admitted_ref(_other, _opts), do: {:error, :invalid_evidence_ref}

  @doc """
  Verify that `erasure_ref` is a real admitted erasure/disposition record in
  `evidence_records` belonging strictly to `household_id` (and covering
  `scope` or the whole household).
  """
  @spec verify_household_erasure_ref(term(), String.t(), String.t()) :: :ok | {:error, atom()}
  def verify_household_erasure_ref(erasure_ref, household_id, scope)
      when is_binary(erasure_ref) and is_binary(household_id) and is_binary(scope) do
    with {:ok, entry} <-
           verify_admitted_ref(erasure_ref,
             allowed_kinds: @erasure_kinds,
             household_id: household_id
           ),
         true <- erasure_covers_scope?(entry.evidence, household_id, scope) do
      :ok
    else
      {:error, :evidence_runtime_unavailable} = err -> err
      _ -> {:error, :erasure_record_required}
    end
  end

  def verify_household_erasure_ref(_, _, _), do: {:error, :erasure_record_required}

  @doc """
  Verify that a `session` target belongs strictly to `household_id` (either
  by household-scoped URN naming, existing personal E2EE wraps/blobs, or
  evidence records owned by a member of `household_id`).
  """
  @spec household_owns_session?(String.t(), String.t(), String.t()) :: boolean()
  def household_owns_session?(household_id, tenant_id, session_id)
      when is_binary(household_id) and is_binary(session_id) do
    cond do
      String.contains?(session_id, ":#{household_id}:") ->
        true

      Store.household_owns_scope?(household_id, session_id) ->
        true

      true ->
        session_owned_by_household_member?(household_id, tenant_id, session_id)
    end
  end

  def household_owns_session?(_, _, _), do: false

  @doc """
  Resolve all concrete evidence session scopes belonging strictly to a
  household target (`scope` in `["session", "member", "household"]`).
  """
  @spec resolve_household_sessions(map(), String.t(), String.t()) ::
          {:ok, [String.t()]} | {:error, atom()}
  def resolve_household_sessions(household, "session", target_id) do
    if household_owns_session?(household.household_id, household.tenant_id, target_id) do
      {:ok, [target_id]}
    else
      {:error, :not_found}
    end
  end

  def resolve_household_sessions(household, "member", member_id) do
    case Store.get_member(household.household_id, member_id) do
      {:ok, member} ->
        {:ok, sessions_for_members(household, [member])}

      :not_found ->
        {:error, :not_found}
    end
  end

  def resolve_household_sessions(household, "household", target_id) do
    if target_id == household.household_id do
      members = Store.list_members(household.household_id)
      {:ok, sessions_for_members(household, members)}
    else
      {:error, :not_found}
    end
  end

  def resolve_household_sessions(_household, _scope, _target_id), do: {:error, :not_found}

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp maybe_put_session(map, session) when is_binary(session) and session != "",
    do: Map.put(map, :session, session)

  defp maybe_put_session(map, _), do: map

  # `provenance.r5e.io/v2/Observation` `Details` permits only string, integer,
  # and boolean scalar values (no nil or list values).
  defp sanitize_details(details) when is_map(details) do
    Enum.reduce(details, %{}, fn
      {_k, nil}, acc ->
        acc

      {k, v}, acc when is_binary(k) and (is_binary(v) or is_integer(v) or is_boolean(v)) ->
        Map.put(acc, k, v)

      {k, v}, acc when is_binary(k) and is_list(v) ->
        Map.put(acc, k, Enum.map_join(v, ",", &to_string/1))

      _, acc ->
        acc
    end)
  end

  defp fetch_entry(module, handle, ref) do
    case module.fetch(handle, ref) do
      {:ok, entry} -> {:ok, entry}
      _ -> {:error, :evidence_record_not_found}
    end
  end

  defp check_allowed_kinds(_entry, nil), do: :ok

  defp check_allowed_kinds(%{evidence: ev}, allowed) when is_list(allowed) do
    if Evidence.kind_path(ev) in allowed, do: :ok, else: {:error, :invalid_evidence_kind}
  end

  defp check_household_binding(_entry, nil), do: :ok

  defp check_household_binding(%{evidence: ev}, household_id) do
    body = ev["body"] || %{}
    details = body["details"] || %{}

    if household_field_matches?(body, details, household_id) or
         scope_field_matches?(body, household_id) do
      :ok
    else
      {:error, :household_mismatch}
    end
  end

  defp household_field_matches?(body, details, household_id) do
    details["householdId"] == household_id or body["householdId"] == household_id
  end

  defp scope_field_matches?(body, household_id) do
    marker = ":#{household_id}:"
    candidates = [body["scope"], body["targetId"]]

    Enum.any?(candidates, fn
      val when is_binary(val) -> val == household_id or String.contains?(val, marker)
      _ -> false
    end)
  end

  defp erasure_covers_scope?(ev, household_id, scope) do
    body = ev["body"] || %{}
    details = body["details"] || %{}

    body["scope"] in [scope, household_id] or
      body["targetId"] in [scope, household_id] or
      details["scope"] in ["household", scope] or
      details["targetId"] in [household_id, scope]
  end

  defp session_owned_by_household_member?(household_id, tenant_id, session_id) do
    if Runtime.running?() do
      members = Store.list_members(household_id)
      prefixes = member_session_prefixes(tenant_id, members)
      actors = member_actor_set(tenant_id, members)

      Enum.any?(prefixes, &String.starts_with?(session_id, &1)) or
        session_records_belong_to?(session_id, actors)
    else
      false
    end
  end

  defp session_records_belong_to?(session_id, actors) do
    %{store: {module, handle}} = Runtime.info()

    case module.by_session(handle, session_id) do
      {:ok, [_ | _] = entries} ->
        Enum.all?(entries, &MapSet.member?(actors, &1.evidence["actor"]))

      _ ->
        false
    end
  end

  defp sessions_for_members(household, members) do
    if Runtime.running?() do
      %{store: {module, handle}} = Runtime.info()
      prefixes = member_session_prefixes(household.tenant_id, members)
      hh_prefix = "urn:r5e:session:#{household.household_id}:"
      all_prefixes = [hh_prefix | prefixes]

      all_prefixes
      |> Enum.flat_map(&sessions_matching_prefix(module, handle, &1))
      |> Enum.uniq()
    else
      []
    end
  end

  defp sessions_matching_prefix(module, handle, prefix) do
    if function_exported?(module, :sessions_with_prefix, 2),
      do: module.sessions_with_prefix(handle, prefix),
      else: []
  end

  defp member_session_prefixes(tenant_id, members) when is_binary(tenant_id) do
    tenant_id
    |> member_actor_set(members)
    |> Enum.map(&SessionName.for(tenant_id, &1, ""))
    |> Enum.uniq()
  end

  defp member_session_prefixes(_, _), do: []

  defp member_actor_set(tenant_id, members) when is_binary(tenant_id) and is_list(members) do
    encoded = SessionName.encode(tenant_id)

    members
    |> Enum.flat_map(&member_subject_forms(&1, encoded))
    |> MapSet.new()
  end

  defp member_actor_set(_, _), do: MapSet.new()

  defp member_subject_forms(member, encoded_tenant) do
    case Map.get(member, :auth_subject) do
      sub when is_binary(sub) and sub != "" ->
        urn =
          if String.contains?(sub, ":"),
            do: sub,
            else:
              "urn:r5e:principal:#{encoded_tenant}:" <> URI.encode(sub, &URI.char_unreserved?/1)

        [sub, urn]

      _ ->
        []
    end
  end
end
