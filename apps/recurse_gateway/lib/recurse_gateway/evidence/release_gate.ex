defmodule Recurse.Gateway.Evidence.ReleaseGate do
  @moduledoc """
  Opt-in custody content-release gate (`R5E_CUSTODY_REQUIRE_RELEASE_GRANT`,
  default `false`).

  When enabled, direct operator reads of stored content
  (`GET /v1/evidence/records/:ref/content/:bytes_ref`), exports requesting
  content (`POST /v1/evidence/export` with `"content": true`), and external
  disclosures (`POST /v1/evidence/disclosures`) require a verified admitted
  `custody.r5e.io/v1/ReleaseGranted` record covering the requested
  session/scope, bound to the authenticated caller (or disclosure recipient),
  within the referenced `ReleaseRequest` window, and without an intervening
  power withdrawal.

  ## Approval-Quorum Intake Boundary

  This module evaluates already-admitted custody records in the evidence store.
  Multi-party approval-quorum and signer-authority verification for
  `custody.r5e.io/v1/ReleaseGranted` and `custody.r5e.io/v1/TermsAccepted`
  MUST be enforced at `/v1/custody/*` intake and evidence admission before
  records enter the evidence store.

  ## Fail-Closed Guarantees

    * Store or index lookup errors NEVER degrade to `[]` or `false` (which
      would suppress withdrawal or human-terms checks); any lookup failure
      returns `{:error, :store_unavailable}` (`503`).
    * Preserves self-scoped `ReadOwnPayload` reads (`scope == {:own, _}`).
    * Preserves the D4 `custody.r5e.io/v1/WorkloadTerms` routine-debug carveout
      STRICTLY when `purpose == "routine-debug"`, the session is positively
      bound to a `WorkloadTerms` (`humanSubjectsPresent == false` with a
      routine-inspect power), AND no human subject (`subject`,
      `urn:r5e:principal:*` actor, or `TermsAccepted`) is present on the
      session.
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
  Authorize content read/export/disclosure access for `content_scope` under
  `access_scope` (`:all` for operator/auditor reads; `{:own, _}` for
  self-scoped reads).

  Options:
    * `:record_ref` — optional evidence ref for record-targeted grants
    * `:caller` — authenticated principal URN of the caller
    * `:caller_subject` — raw authenticated JWT subject of the caller
    * `:disclosure_recipient` — recipient URN on `POST /v1/evidence/disclosures`
    * `:purpose` — declared access purpose (carveout requires `"routine-debug"`)
    * `:now` — evaluation timestamp (defaults to `DateTime.utc_now/0`)

  Returns `:ok`, `{:error, :release_grant_required}`, or
  `{:error, :store_unavailable}`.
  """
  @spec authorize({module(), term()}, String.t() | nil, :all | {:own, map()}, keyword()) ::
          :ok | {:error, :release_grant_required | :store_unavailable}
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
    purpose = Keyword.get(opts, :purpose)
    recipients = expected_recipients(opts)
    prefix = stream_prefix()

    with {:ok, false} <- workload_debug_carveout?(index, content_scope, purpose, prefix),
         {:ok, false} <-
           valid_release_grant?(index, content_scope, record_ref, recipients, prefix, now) do
      {:error, :release_grant_required}
    else
      {:ok, true} -> :ok
      {:error, :store_unavailable} -> {:error, :store_unavailable}
    end
  end

  defp expected_recipients(opts) do
    case Keyword.get(opts, :disclosure_recipient) do
      rec when is_binary(rec) and rec != "" ->
        [rec]

      _ ->
        [Keyword.get(opts, :caller), Keyword.get(opts, :caller_subject)]
        |> Enum.filter(&(is_binary(&1) and &1 != ""))
        |> Enum.uniq()
    end
  end

  defp valid_release_grant?(
         {module, handle} = index,
         content_scope,
         record_ref,
         recipients,
         prefix,
         now
       ) do
    targets = Enum.reject([content_scope, record_ref], &is_nil/1)

    if targets == [] or recipients == [] do
      {:ok, false}
    else
      with {:ok, grants} <- fetch_by_kind(module, handle, @release_granted, prefix),
           {:ok, withdrawals} <- load_power_withdrawals(index, prefix) do
        any_grant_covers?(index, grants, targets, recipients, withdrawals, now)
      end
    end
  end

  defp any_grant_covers?(index, grants, targets, recipients, withdrawals, now) do
    Enum.reduce_while(grants, {:ok, false}, fn %{evidence: %{"body" => grant_body}},
                                               {:ok, false} ->
      case grant_covers?(index, grant_body, targets, recipients, withdrawals, now) do
        {:ok, true} -> {:halt, {:ok, true}}
        {:ok, false} -> {:cont, {:ok, false}}
        {:error, :store_unavailable} -> {:halt, {:error, :store_unavailable}}
      end
    end)
  end

  defp grant_covers?(
         {module, handle},
         %{"outcome" => outcome, "requestRef" => request_ref} = grant_body,
         targets,
         recipients,
         withdrawals,
         now
       )
       when outcome in ["released", "delivered"] and is_binary(request_ref) do
    case safe_fetch(module, handle, request_ref) do
      {:ok, %{evidence: req_ev}} ->
        {:ok, grant_matches_request?(grant_body, req_ev, targets, recipients, withdrawals, now)}

      :not_found ->
        {:ok, false}

      {:error, :store_unavailable} ->
        {:error, :store_unavailable}
    end
  end

  defp grant_covers?(_index, _grant_body, _targets, _recipients, _withdrawals, _now),
    do: {:ok, false}

  defp grant_matches_request?(grant_body, req_ev, targets, recipients, withdrawals, now) do
    with true <- kind_path(req_ev) == @release_request,
         %{"targets" => req_targets, "windowStart" => start_s, "windowEnd" => end_s} = req_body <-
           req_ev["body"],
         true <- is_list(req_targets) and Enum.any?(targets, &(&1 in req_targets)),
         true <- recipient_matches?(grant_body, req_body, recipients),
         true <- within_window?(start_s, end_s, now),
         false <- power_withdrawn?(withdrawals, req_body["termsRef"], req_body["power"]) do
      true
    else
      _ -> false
    end
  end

  defp recipient_matches?(grant_body, req_body, recipients) do
    grant_rec = grant_body["recipient"] || req_body["recipient"]
    is_binary(grant_rec) and grant_rec != "" and grant_rec in recipients
  end

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
    with {:ok, entries} <- fetch_by_kind(module, handle, @terms_amendment, prefix) do
      withdrawals =
        Enum.filter(entries, fn %{evidence: %{"body" => body}} ->
          body["proposalKind"] == "power-withdrawal" and is_list(body["affectedPowers"])
        end)

      {:ok, withdrawals}
    end
  end

  defp power_withdrawn?(_withdrawals, nil, _power), do: false
  defp power_withdrawn?(_withdrawals, _terms_ref, nil), do: false

  defp power_withdrawn?(withdrawals, terms_ref, power) do
    Enum.any?(withdrawals, fn %{evidence: %{"body" => body}} ->
      body["termsRef"] == terms_ref and power in (body["affectedPowers"] || [])
    end)
  end

  # D4 WorkloadTerms carveout: applies strictly when `purpose == "routine-debug"`,
  # a machine workload with `humanSubjectsPresent == false` grants routine
  # engineer inspection, the session is positively bound to that `WorkloadTerms`,
  # AND no human subject (`subject`, `urn:r5e:principal:*`, or `TermsAccepted`)
  # is present on the session.
  defp workload_debug_carveout?(_index, _content_scope, purpose, _prefix)
       when purpose != "routine-debug",
       do: {:ok, false}

  defp workload_debug_carveout?({module, handle} = index, content_scope, "routine-debug", prefix) do
    with {:ok, workload_entries} <- fetch_by_kind(module, handle, @workload_terms, prefix),
         true <- workload_entries != [],
         {:ok, session_entries} <- load_session_entries(index, content_scope),
         true <- session_entries != [],
         true <- not session_has_human_subject?(session_entries),
         session_terms_refs = extract_session_terms_refs(session_entries),
         session_actors = extract_session_actors(session_entries),
         {:ok, false} <-
           session_has_human_terms?(
             index,
             content_scope,
             session_terms_refs,
             session_actors,
             prefix
           ) do
      matched? =
        Enum.any?(workload_entries, fn %{ref: ref, evidence: %{"body" => body}} ->
          routine_inspect_workload?(body) and
            workload_bound_to_session?(ref, body, session_terms_refs, session_actors)
        end)

      {:ok, matched?}
    else
      false -> {:ok, false}
      {:ok, true} -> {:ok, false}
      {:error, :store_unavailable} -> {:error, :store_unavailable}
    end
  end

  defp session_has_human_subject?(entries) do
    Enum.any?(entries, fn %{evidence: ev} ->
      actor = ev["actor"] || ""
      body_subject = get_in(ev, ["body", "subject"])

      is_binary(ev["subject"]) or
        (is_binary(body_subject) and body_subject != "") or
        String.starts_with?(actor, "urn:r5e:principal:")
    end)
  end

  defp workload_bound_to_session?(ref, body, session_terms_refs, session_actors) do
    cond do
      ref in session_terms_refs ->
        true

      session_terms_refs == [] and is_binary(body["workload"]) and body["workload"] != "" ->
        session_actors != [] and Enum.all?(session_actors, &(&1 == body["workload"]))

      true ->
        false
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

  defp load_session_entries({module, handle}, content_scope) when is_binary(content_scope) do
    case module.by_session(handle, content_scope) do
      {:ok, entries} when is_list(entries) -> {:ok, entries}
      _ -> {:error, :store_unavailable}
    end
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp load_session_entries(_index, _content_scope), do: {:ok, []}

  defp extract_session_terms_refs(entries) do
    entries
    |> Enum.map(&get_in(&1.evidence, ["body", "termsRef"]))
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
  end

  defp extract_session_actors(entries) do
    entries
    |> Enum.map(& &1.evidence["actor"])
    |> Enum.filter(&is_binary/1)
    |> Enum.uniq()
  end

  defp session_has_human_terms?(
         {module, handle},
         content_scope,
         session_terms_refs,
         session_actors,
         prefix
       ) do
    with {:ok, false} <- any_terms_accepted_ref?(module, handle, session_terms_refs) do
      any_session_or_actor_terms_accepted?(module, handle, content_scope, session_actors, prefix)
    end
  end

  defp any_terms_accepted_ref?(module, handle, refs) do
    Enum.reduce_while(refs, {:ok, false}, fn ref, {:ok, false} ->
      check_terms_ref_step(safe_fetch(module, handle, ref))
    end)
  end

  defp check_terms_ref_step({:ok, %{evidence: ev}}) do
    if kind_path(ev) == @terms_accepted, do: {:halt, {:ok, true}}, else: {:cont, {:ok, false}}
  end

  defp check_terms_ref_step(:not_found), do: {:cont, {:ok, false}}

  defp check_terms_ref_step({:error, :store_unavailable}),
    do: {:halt, {:error, :store_unavailable}}

  defp any_session_or_actor_terms_accepted?(module, handle, content_scope, session_actors, prefix) do
    with {:ok, accepted} <- fetch_by_kind(module, handle, @terms_accepted, prefix) do
      found? =
        Enum.any?(accepted, fn %{evidence: ev} ->
          ev["session"] == content_scope or
            ev["actor"] in session_actors or
            get_in(ev, ["body", "subject"]) in session_actors
        end)

      {:ok, found?}
    end
  end

  defp fetch_by_kind(module, handle, kind_path, prefix) do
    case module.by_kind(handle, kind_path, prefix) do
      {:ok, entries} when is_list(entries) -> {:ok, entries}
      _ -> {:error, :store_unavailable}
    end
  rescue
    _ -> {:error, :store_unavailable}
  end

  defp safe_fetch(module, handle, ref) do
    case module.fetch(handle, ref) do
      {:ok, entry} -> {:ok, entry}
      :error -> :not_found
      _ -> {:error, :store_unavailable}
    end
  rescue
    _ -> {:error, :store_unavailable}
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
