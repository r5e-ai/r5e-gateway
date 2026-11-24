defmodule Recurse.Gateway.Evidence.ReleaseGate do
  @moduledoc """
  Opt-in custody content-release gate (`R5E_CUSTODY_REQUIRE_RELEASE_GRANT`,
  default `false`).

  When enabled, direct operator reads of stored content
  (`GET /v1/evidence/records/:ref/content/:bytes_ref`) and exports requesting
  content (`POST /v1/evidence/export` with `"content": true`) require a
  verified admitted `custody.r5e.io/v1/ReleaseGranted` record covering the
  requested session/scope within the referenced `ReleaseRequest` window and
  without an intervening power withdrawal.

  Preserves:
    * Self-scoped `ReadOwnPayload` reads (`scope == {:own, _}`).
    * Unilateral machine `custody.r5e.io/v1/WorkloadTerms` routine-debug
      carveout (`humanSubjectsPresent == false` with a routine-inspect power),
      never applied to sessions governed by human-subject `TermsAccepted`.
  """

  alias Recurse.Gateway.Provenance.Runtime

  @release_granted "custody.r5e.io/v1/ReleaseGranted"
  @release_request "custody.r5e.io/v1/ReleaseRequest"
  @workload_terms "custody.r5e.io/v1/WorkloadTerms"
  @terms_accepted "custody.r5e.io/v1/TermsAccepted"
  @terms_amendment "custody.r5e.io/v1/TermsAmendmentProposal"

  @doc "Whether `R5E_CUSTODY_REQUIRE_RELEASE_GRANT` is enabled."
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:recurse_gateway, :custody_require_release_grant?, false) == true
  end

  @doc """
  Authorize content read/export access for `content_scope` under `access_scope`
  (`:all` for operator/auditor reads; `{:own, _}` for self-scoped reads).

  Returns `:ok` or `{:error, :release_grant_required}`.
  """
  @spec authorize({module(), term()}, String.t() | nil, :all | {:own, map()}, keyword()) ::
          :ok | {:error, :release_grant_required}
  def authorize(index, content_scope, access_scope, opts \\ [])

  def authorize(_index, _content_scope, {:own, _}, _opts), do: :ok

  def authorize(index, content_scope, :all, opts) do
    if enabled?() do
      check_release_or_workload(index, content_scope, opts)
    else
      :ok
    end
  end

  defp check_release_or_workload(index, content_scope, opts) do
    now = Keyword.get(opts, :now, DateTime.utc_now())
    record_ref = Keyword.get(opts, :record_ref)
    prefix = stream_prefix()

    if workload_debug_carveout?(index, content_scope, prefix) or
         valid_release_grant?(index, content_scope, record_ref, prefix, now) do
      :ok
    else
      {:error, :release_grant_required}
    end
  end

  defp valid_release_grant?({module, handle} = index, content_scope, record_ref, prefix, now) do
    targets = Enum.reject([content_scope, record_ref], &is_nil/1)

    with [_ | _] <- targets,
         {:ok, grants} <- module.by_kind(handle, @release_granted, prefix) do
      withdrawals = load_power_withdrawals(index, prefix)

      Enum.any?(grants, fn %{evidence: %{"body" => grant_body}} ->
        grant_covers?(index, grant_body, targets, withdrawals, now)
      end)
    else
      _ -> false
    end
  end

  defp grant_covers?(
         {module, handle},
         %{"outcome" => outcome, "requestRef" => request_ref},
         targets,
         withdrawals,
         now
       )
       when outcome in ["released", "delivered"] and is_binary(request_ref) do
    with {:ok, %{evidence: req_ev}} <- module.fetch(handle, request_ref),
         true <- kind_path(req_ev) == @release_request,
         %{"targets" => req_targets, "windowStart" => start_s, "windowEnd" => end_s} = req_body <-
           req_ev["body"],
         true <- is_list(req_targets) and Enum.any?(targets, &(&1 in req_targets)),
         true <- within_window?(start_s, end_s, now),
         false <- power_withdrawn?(withdrawals, req_body["termsRef"], req_body["power"]) do
      true
    else
      _ -> false
    end
  end

  defp grant_covers?(_index, _grant_body, _targets, _withdrawals, _now), do: false

  defp within_window?(start_s, end_s, now) when is_binary(start_s) and is_binary(end_s) do
    with {:ok, start_dt, _} <- DateTime.from_iso8601(start_s),
         {:ok, end_dt, _} <- DateTime.from_iso8601(end_s) do
      DateTime.compare(now, start_dt) in [:gt, :eq] and
        DateTime.compare(now, end_dt) in [:lt, :eq]
    else
      _ -> false
    end
  end

  defp within_window?(_start_s, _end_s, _now), do: false

  defp load_power_withdrawals({module, handle}, prefix) do
    case module.by_kind(handle, @terms_amendment, prefix) do
      {:ok, entries} ->
        Enum.filter(entries, fn %{evidence: %{"body" => body}} ->
          body["proposalKind"] == "power-withdrawal" and is_list(body["affectedPowers"])
        end)

      _ ->
        []
    end
  end

  defp power_withdrawn?(_withdrawals, nil, _power), do: false
  defp power_withdrawn?(_withdrawals, _terms_ref, nil), do: false

  defp power_withdrawn?(withdrawals, terms_ref, power) do
    Enum.any?(withdrawals, fn %{evidence: %{"body" => body}} ->
      body["termsRef"] == terms_ref and power in (body["affectedPowers"] || [])
    end)
  end

  # D4 WorkloadTerms carveout: applies strictly when a machine workload with
  # `humanSubjectsPresent == false` grants routine engineer inspection AND no
  # human-subject `TermsAccepted` governs the session.
  defp workload_debug_carveout?({module, handle} = index, content_scope, prefix) do
    with {:ok, [_ | _] = workload_entries} <- module.by_kind(handle, @workload_terms, prefix),
         false <- session_has_human_terms?(index, content_scope, prefix) do
      session_terms_refs = session_referenced_terms(index, content_scope)

      Enum.any?(workload_entries, fn %{ref: ref, evidence: %{"body" => body}} ->
        routine_inspect_workload?(body) and
          (session_terms_refs == [] or ref in session_terms_refs)
      end)
    else
      _ -> false
    end
  end

  defp routine_inspect_workload?(%{"humanSubjectsPresent" => false, "powers" => powers})
       when is_list(powers) do
    Enum.any?(powers, fn
      %{"power" => "inspect", "purposeCode" => "routine-engineer-inspect"} -> true
      %{"power" => "inspect", "approvalMode" => "none"} -> true
      _ -> false
    end)
  end

  defp routine_inspect_workload?(_body), do: false

  defp session_referenced_terms({module, handle}, content_scope) when is_binary(content_scope) do
    case module.by_session(handle, content_scope) do
      {:ok, entries} ->
        entries
        |> Enum.map(&get_in(&1.evidence, ["body", "termsRef"]))
        |> Enum.filter(&is_binary/1)
        |> Enum.uniq()

      _ ->
        []
    end
  end

  defp session_referenced_terms(_index, _content_scope), do: []

  defp session_has_human_terms?({module, handle} = index, content_scope, prefix) do
    case session_referenced_terms(index, content_scope) do
      [_ | _] = refs -> Enum.any?(refs, &terms_accepted_ref?(module, handle, &1))
      [] -> any_session_terms_accepted?(module, handle, content_scope, prefix)
    end
  end

  defp terms_accepted_ref?(module, handle, ref) do
    case module.fetch(handle, ref) do
      {:ok, %{evidence: ev}} -> kind_path(ev) == @terms_accepted
      _ -> false
    end
  end

  defp any_session_terms_accepted?(module, handle, content_scope, prefix) do
    case module.by_kind(handle, @terms_accepted, prefix) do
      {:ok, [_ | _] = accepted} ->
        Enum.any?(accepted, fn %{evidence: ev} -> ev["session"] == content_scope end)

      _ ->
        false
    end
  end

  defp kind_path(%{"apiVersion" => v, "kind" => k}) when is_binary(v) and is_binary(k),
    do: v <> "/" <> k

  defp kind_path(_), do: ""

  defp stream_prefix do
    deployment =
      case Runtime.info() do
        %{deployment: dep} -> dep
        _ -> Application.get_env(:recurse_gateway, :evidence_deployment, "default")
      end

    "urn:r5e:stream:#{deployment}:"
  end
end
