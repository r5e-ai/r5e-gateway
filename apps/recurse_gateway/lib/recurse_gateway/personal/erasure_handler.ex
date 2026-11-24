defmodule Recurse.Gateway.Personal.ErasureHandler do
  @moduledoc """
  HTTP handlers for unified personal erasure (`POST /v1/personal/erasures`) and
  two-parent (`threshold: 2`) co-sign erasure proposals
  (`POST /v1/personal/erasures/proposals`, `.../proposals/:proposal_id/approve`).

  Security invariants:
    * Caller MUST be an authenticated `owner` or `parent` member of the target
      household (never a `child`).
    * Target (`session`, `member`, or `household`) is strictly verified to
      belong to the caller's household before any proposal or erasure executes.
    * `threshold >= 2` households require a distinct-parent approved `coSignRef`
      across ALL destructive scopes (`session`, `member`, `household`).
    * Every returned `coSignRef` and `erasureRef` is a real record admitted to
      `evidence_records` (failing closed `503` if the evidence runtime is down).
    * For `client-key-and-blob-deletion`, a durable `PayloadDisposition` is
      recorded (and hold-checked) on the retention stream BEFORE deleting any
      key wraps or ciphertext blobs.
  """

  alias Recurse.Gateway.Personal.{Common, Ledger}
  alias Recurse.Gateway.Provenance.{Retention, Runtime}
  alias Recurse.Provenance.Envelope
  alias Recurse.Providers.Personal, as: Store

  @manage_household ~s(Recurse::Action::"ManageHousehold")
  @manage_retention ~s(Recurse::Action::"ManageRetention")

  @proposal_ttl_seconds 259_200
  @common_errors [
    :not_found,
    :ambiguous_household,
    :parent_role_required,
    :evidence_runtime_unavailable
  ]

  @doc "`POST /v1/personal/erasures/proposals`"
  @spec create_proposal(Plug.Conn.t()) :: Plug.Conn.t()
  def create_proposal(
        %Plug.Conn{
          body_params:
            %{
              "scope" => scope,
              "targetId" => target_id,
              "erasureMethod" => method
            } = body
        } = conn
      )
      when scope in ["session", "member", "household"] and
             method in ["gateway-disposal", "client-key-and-blob-deletion"] and
             is_binary(target_id) do
    Common.gate(conn, @manage_household, "/v1/personal/erasures/proposals", fn conn, ctx ->
      with {:ok, household, proposer} <- Common.resolve_parent_member(conn, ctx),
           :ok <- verify_target_owned(household, scope, target_id),
           proposal_id = Common.random_id("ep_", 12),
           digest = proposal_digest(household.household_id, scope, target_id, method, proposal_id),
           expires_at = DateTime.add(DateTime.utc_now(), @proposal_ttl_seconds, :second),
           proposer_key = body["proposerKeyId"] || proposer.working_key_id || proposer.member_id,
           proposer_root = body["proposerRootKeyId"] || proposer.root_key_id || proposer.member_id,
           {:ok, proposal} <-
             Store.create_erasure_proposal(%{
               proposal_id: proposal_id,
               household_id: household.household_id,
               scope: scope,
               target_id: target_id,
               erasure_method: method,
               request_digest: digest,
               erasure_request_ref: body["erasureRequestRef"],
               proposer_member_id: proposer.member_id,
               proposer_key_id: proposer_key,
               proposer_root_key_id: proposer_root,
               expires_at: expires_at
             }) do
        Common.json(conn, 201, %{
          "proposalId" => proposal.proposal_id,
          "requestDigest" => proposal.request_digest,
          "expiresAt" => DateTime.to_iso8601(proposal.expires_at)
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, _} ->
          Common.json(conn, 422, %{"error" => "proposal_creation_failed"})
      end
    end)
  end

  def create_proposal(conn),
    do: Common.bad_request(conn, ~s(expected {"scope", "targetId", "erasureMethod"}))

  @doc "`POST /v1/personal/erasures/proposals/:proposal_id/approve`"
  @spec approve_proposal(Plug.Conn.t()) :: Plug.Conn.t()
  def approve_proposal(
        %Plug.Conn{path_params: %{"proposal_id" => proposal_id}, body_params: body} = conn
      )
      when is_map(body) do
    Common.gate(conn, @manage_household, "/v1/personal/erasures/proposals/approve", fn conn,
                                                                                       ctx ->
      with {:ok, household, approver} <- Common.resolve_parent_member(conn, ctx),
           :ok <- require_runtime_running(),
           {:ok, co_sign_ref, decision, req_digest} <-
             resolve_approval(body, household, proposal_id, approver, ctx),
           approver_key = body["approverKeyId"] || approver.working_key_id || approver.member_id,
           approver_root = body["approverRootKeyId"] || approver.root_key_id || approver.member_id,
           {:ok, approved} <-
             Store.approve_erasure_proposal(household.household_id, proposal_id, %{
               approver_member_id: approver.member_id,
               approver_key_id: approver_key,
               approver_root_key_id: approver_root,
               co_sign_ref: co_sign_ref,
               decision: decision,
               request_digest: req_digest
             }) do
        Common.json(conn, 201, %{
          "proposalId" => approved.proposal_id,
          "coSignRef" => approved.co_sign_ref,
          "decision" => decision,
          "state" => approved.state
        })
      else
        {:error, reason} when reason in @common_errors ->
          Common.send_common_error(conn, reason)

        {:error, reason} ->
          send_approval_error(conn, reason)
      end
    end)
  end

  def approve_proposal(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc "`POST /v1/personal/erasures`"
  @spec execute_erasure(Plug.Conn.t()) :: Plug.Conn.t()
  def execute_erasure(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate_any(
      conn,
      [@manage_household, @manage_retention],
      "/v1/personal/erasures",
      fn conn, ctx, _ ->
        with {:ok, household, member} <- Common.resolve_parent_member(conn, ctx),
             :ok <- require_runtime_running(),
             {:ok, parsed} <- parse_erasure_request(body, household),
             :ok <- verify_target_owned(household, parsed.scope, parsed.target_id),
             :ok <- check_two_parent_cosign(household, parsed),
             {:ok, result} <- run_erasure(household, member, parsed, ctx),
             :ok <- finalize_cosign_proposal(household, parsed, result.erasure_ref) do
          Common.json(conn, 201, %{
            "erasureRef" => result.erasure_ref,
            "erasureMethod" => parsed.erasure_method,
            "dispositionRefs" => result.disposition_refs,
            "keyWrapsDeleted" => result.key_wraps_deleted,
            "blobsTombstoned" => result.blobs_tombstoned,
            "erasureCoverage" =>
              if(household.profile_mode == "solo",
                do: "evidence-store-only-external-copies-excluded",
                else: "full-managed-runtime-and-evidence"
              )
          })
        else
          {:error, reason} when reason in @common_errors ->
            Common.send_common_error(conn, reason)

          {:error, reason} ->
            send_erasure_error(conn, reason)
        end
      end
    )
  end

  def execute_erasure(conn), do: Common.bad_request(conn, "expected JSON body")

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp require_runtime_running do
    if Runtime.running?(), do: :ok, else: {:error, :evidence_runtime_unavailable}
  end

  defp verify_target_owned(household, "household", target_id) do
    if target_id == household.household_id, do: :ok, else: {:error, :not_found}
  end

  defp verify_target_owned(household, "member", target_id) do
    case Store.get_member(household.household_id, target_id) do
      {:ok, _member} -> :ok
      :not_found -> {:error, :not_found}
    end
  end

  defp verify_target_owned(household, "session", target_id) do
    if Ledger.household_owns_session?(household.household_id, household.tenant_id, target_id) do
      :ok
    else
      {:error, :not_found}
    end
  end

  defp verify_target_owned(_household, _scope, _target_id), do: {:error, :not_found}

  defp proposal_digest(household_id, scope, target_id, method, proposal_id) do
    canonical =
      [
        ~s("erasureMethod":),
        JSON.encode!(method),
        ~s(,"householdId":),
        JSON.encode!(household_id),
        ~s(,"proposalId":),
        JSON.encode!(proposal_id),
        ~s(,"scope":),
        JSON.encode!(scope),
        ~s(,"targetId":),
        JSON.encode!(target_id)
      ]
      |> then(&["{", &1, "}"])
      |> IO.iodata_to_binary()

    "sha256:" <> Base.encode16(:crypto.hash(:sha256, canonical), case: :lower)
  end

  defp resolve_approval(
         %{"coParentApprovalEnvelope" => env},
         _household,
         _proposal_id,
         _approver,
         _ctx
       )
       when is_map(env) do
    with {:ok,
          %{
            ref: ref,
            evidence: %{
              "apiVersion" => "personal.r5e.io/v1",
              "kind" => "CoParentApproval",
              "body" => ev_body
            }
          }} <- Envelope.open(env),
         {:ok, _entry} <- Ledger.verify_admitted_ref(ref) do
      {:ok, ref, Map.get(ev_body, "decision", "approve"), ev_body["requestDigest"]}
    else
      {:error, :evidence_runtime_unavailable} = err -> err
      {:error, :evidence_record_not_found} -> {:error, :evidence_record_not_found}
      _ -> {:error, :invalid_co_parent_approval}
    end
  end

  defp resolve_approval(body, household, proposal_id, approver, ctx) do
    decision = Map.get(body, "decision", "approve")

    if decision in ["approve", "deny"] do
      resolve_approval_ref(body, household, proposal_id, approver, ctx, decision)
    else
      {:error, :invalid_decision}
    end
  end

  defp resolve_approval_ref(%{"coSignRef" => ref} = body, _hh, _pid, _approver, _ctx, decision)
       when is_binary(ref) and ref != "" do
    with {:ok, _entry} <- Ledger.verify_admitted_ref(ref) do
      {:ok, ref, decision, body["requestDigest"]}
    end
  end

  defp resolve_approval_ref(body, household, proposal_id, approver, ctx, decision) do
    details = %{
      "householdId" => household.household_id,
      "proposalId" => proposal_id,
      "approverMemberId" => approver.member_id,
      "decision" => decision,
      "requestDigest" => body["requestDigest"]
    }

    with {:ok, ref} <-
           Ledger.record_observation(
             "personal.erasure.cosign_decision",
             Common.actor_urn(ctx, approver),
             details
           ) do
      {:ok, ref, decision, body["requestDigest"]}
    end
  end

  defp parse_erasure_request(%{"personalErasureEnvelope" => env} = body, household)
       when is_map(env) do
    with {:ok,
          %{
            ref: ref,
            evidence: %{
              "apiVersion" => "personal.r5e.io/v1",
              "kind" => "PersonalErasure",
              "body" => ev_body
            }
          }} <- Envelope.open(env),
         {:ok, _entry} <- Ledger.verify_admitted_ref(ref),
         scope when scope in ["session", "member", "household"] <- ev_body["scope"],
         method when method in ["gateway-disposal", "client-key-and-blob-deletion"] <-
           ev_body["erasureMethod"],
         target_id when is_binary(target_id) <- ev_body["targetId"] do
      {:ok,
       %{
         scope: scope,
         target_id: target_id,
         erasure_method: method,
         co_sign_ref: ev_body["coSignRef"] || body["coSignRef"],
         erasure_ref: ref,
         household_id: household.household_id
       }}
    else
      {:error, :evidence_runtime_unavailable} = err -> err
      {:error, :evidence_record_not_found} -> {:error, :evidence_record_not_found}
      _ -> {:error, :invalid_personal_erasure_envelope}
    end
  end

  defp parse_erasure_request(
         %{"scope" => scope, "targetId" => target_id} = body,
         household
       )
       when scope in ["session", "member", "household"] and is_binary(target_id) do
    method =
      Map.get(
        body,
        "erasureMethod",
        if(household.custody_mode == "client-e2ee",
          do: "client-key-and-blob-deletion",
          else: "gateway-disposal"
        )
      )

    with true <-
           method in ["gateway-disposal", "client-key-and-blob-deletion"] ||
             {:error, :invalid_erasure_method},
         {:ok, explicit_ref} <- verify_optional_erasure_ref(body["erasureRef"]) do
      {:ok,
       %{
         scope: scope,
         target_id: target_id,
         erasure_method: method,
         co_sign_ref: body["coSignRef"],
         erasure_ref: explicit_ref,
         household_id: household.household_id
       }}
    end
  end

  defp parse_erasure_request(_, _), do: {:error, :malformed_erasure_request}

  defp verify_optional_erasure_ref(nil), do: {:ok, nil}
  defp verify_optional_erasure_ref(""), do: {:ok, nil}

  defp verify_optional_erasure_ref(ref) when is_binary(ref) do
    with {:ok, _entry} <-
           Ledger.verify_admitted_ref(ref,
             allowed_kinds: [
               "personal.r5e.io/v1/PersonalErasure",
               "provenance.r5e.io/v2/PayloadDisposition"
             ]
           ) do
      {:ok, ref}
    end
  end

  defp verify_optional_erasure_ref(_), do: {:error, :invalid_evidence_ref}

  # Enforce distinct two-parent co-sign across ALL destructive scopes when threshold >= 2.
  defp check_two_parent_cosign(%{threshold: threshold, household_id: hh_id}, %{
         scope: scope,
         target_id: target_id,
         co_sign_ref: co_sign_ref
       })
       when threshold >= 2 do
    if Store.approved_cosign?(hh_id, scope, target_id, co_sign_ref) do
      :ok
    else
      {:error, :co_sign_required}
    end
  end

  defp check_two_parent_cosign(_household, _parsed), do: :ok

  defp finalize_cosign_proposal(%{threshold: threshold, household_id: hh_id}, parsed, erasure_ref)
       when threshold >= 2 and is_binary(parsed.co_sign_ref) do
    case Store.mark_proposal_executed(hh_id, parsed.co_sign_ref, erasure_ref) do
      {:ok, :executed} -> :ok
      {:error, :proposal_not_approved} -> {:error, :co_sign_required}
    end
  end

  defp finalize_cosign_proposal(%{household_id: hh_id}, %{co_sign_ref: ref}, erasure_ref)
       when is_binary(ref) and ref != "" do
    _ = Store.mark_proposal_executed(hh_id, ref, erasure_ref)
    :ok
  end

  defp finalize_cosign_proposal(_household, _parsed, _erasure_ref), do: :ok

  # Order invariant: record durable PayloadDisposition FIRST (and enforce holds
  # across all covered scopes), ONLY THEN delete key wraps and tombstone blobs.
  defp run_erasure(
         household,
         member,
         %{erasure_method: "client-key-and-blob-deletion"} = parsed,
         ctx
       ) do
    disp_scope =
      if parsed.scope == "session",
        do: parsed.target_id,
        else: "urn:r5e:household:#{household.household_id}"

    covered_scopes = covered_client_e2ee_scopes(household, parsed.scope, parsed.target_id)

    details = %{
      "householdId" => household.household_id,
      "scope" => parsed.scope,
      "targetId" => parsed.target_id,
      "erasureMethod" => "client-key-and-blob-deletion"
    }

    with {:ok, %{"disposal" => disp_ref}} <-
           Retention.record_client_erasure_disposition(
             disp_scope,
             "personal_erasure",
             Common.actor_urn(ctx, member),
             details,
             covered_scopes
           ) do
      erasure_ref = parsed.erasure_ref || disp_ref

      {wraps, blobs} =
        execute_client_e2ee_deletions(household, parsed, covered_scopes, erasure_ref)

      {:ok,
       %{
         erasure_ref: erasure_ref,
         disposition_refs: [disp_ref],
         key_wraps_deleted: wraps,
         blobs_tombstoned: blobs
       }}
    end
  end

  defp run_erasure(household, member, %{erasure_method: "gateway-disposal"} = parsed, ctx) do
    actor = Common.actor_urn(ctx, member)

    with {:ok, sessions} <-
           Ledger.resolve_household_sessions(household, parsed.scope, parsed.target_id),
         {:ok, disp_refs} <- dispose_sessions(sessions, actor) do
      erasure_ref = parsed.erasure_ref || hd(disp_refs)

      {:ok,
       %{
         erasure_ref: erasure_ref,
         disposition_refs: disp_refs,
         key_wraps_deleted: 0,
         blobs_tombstoned: 0
       }}
    end
  end

  defp covered_client_e2ee_scopes(_household, "session", target_id), do: [target_id]

  defp covered_client_e2ee_scopes(household, "household", target_id) do
    e2ee_scopes = Store.list_client_e2ee_scopes(household.household_id)

    ledger_scopes =
      case Ledger.resolve_household_sessions(household, "household", target_id) do
        {:ok, list} -> list
        _ -> []
      end

    Enum.uniq(e2ee_scopes ++ ledger_scopes)
  end

  defp covered_client_e2ee_scopes(household, "member", target_id) do
    e2ee_scopes = Store.list_client_e2ee_scopes(household.household_id)

    matching_e2ee =
      case Store.get_member(household.household_id, target_id) do
        {:ok, m} ->
          Enum.filter(e2ee_scopes, fn scope ->
            scope == target_id or
              String.contains?(scope, m.member_id) or
              (is_binary(m.auth_subject) and m.auth_subject != "" and
                 String.contains?(scope, m.auth_subject))
          end)

        :not_found ->
          []
      end

    ledger_scopes =
      case Ledger.resolve_household_sessions(household, "member", target_id) do
        {:ok, list} -> list
        _ -> []
      end

    Enum.uniq(matching_e2ee ++ ledger_scopes)
  end

  defp execute_client_e2ee_deletions(household, %{scope: "household"}, _scopes, erasure_ref) do
    {:ok, %{key_wraps_deleted: wraps, blobs_tombstoned: blobs}} =
      Store.erase_client_e2ee(household.household_id, :household, erasure_ref)

    {wraps, blobs}
  end

  defp execute_client_e2ee_deletions(household, %{scope: "session", target_id: tid}, _scopes, ref) do
    {:ok, %{key_wraps_deleted: wraps, blobs_tombstoned: blobs}} =
      Store.erase_client_e2ee(household.household_id, {:scope, tid}, ref)

    {wraps, blobs}
  end

  defp execute_client_e2ee_deletions(household, %{scope: "member", target_id: tid}, scopes, ref) do
    targets = if scopes == [], do: [tid], else: scopes

    Enum.reduce(targets, {0, 0}, fn scope, {w_acc, b_acc} ->
      {:ok, %{key_wraps_deleted: wraps, blobs_tombstoned: blobs}} =
        Store.erase_client_e2ee(household.household_id, {:scope, scope}, ref)

      {w_acc + wraps, b_acc + blobs}
    end)
  end

  defp dispose_sessions([], _actor), do: {:error, :nothing_to_dispose}

  defp dispose_sessions(sessions, actor) do
    Enum.reduce_while(sessions, {:ok, []}, fn session, {:ok, acc} ->
      case Retention.dispose(%{"scope" => session, "reason" => "personal_erasure"}, actor) do
        {:ok, %{"disposal" => disp_ref}} -> {:cont, {:ok, [disp_ref | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, refs} -> {:ok, Enum.reverse(refs)}
      error -> error
    end
  end

  defp send_approval_error(conn, :self_approval_forbidden),
    do: Common.json(conn, 409, %{"error" => "self_approval_forbidden"})

  defp send_approval_error(conn, :proposal_expired),
    do: Common.json(conn, 410, %{"error" => "proposal_expired"})

  defp send_approval_error(conn, :proposal_not_pending),
    do: Common.json(conn, 409, %{"error" => "proposal_not_pending"})

  defp send_approval_error(conn, :digest_mismatch),
    do: Common.json(conn, 422, %{"error" => "digest_mismatch"})

  defp send_approval_error(conn, reason) when is_atom(reason),
    do: Common.json(conn, 422, %{"error" => Atom.to_string(reason)})

  defp send_erasure_error(conn, :co_sign_required),
    do: Common.json(conn, 409, %{"error" => "co_sign_required"})

  defp send_erasure_error(conn, :nothing_to_dispose),
    do: Common.json(conn, 409, %{"error" => "ERR_NOTHING_TO_DISPOSE"})

  defp send_erasure_error(conn, {reason, ref}) when is_atom(reason),
    do: Common.json(conn, 409, %{"error" => Atom.to_string(reason), "about" => ref})

  defp send_erasure_error(conn, :store_unavailable),
    do: Common.json(conn, 503, %{"error" => "ERR_UNAVAILABLE"})

  defp send_erasure_error(conn, reason) when is_atom(reason),
    do: Common.json(conn, 422, %{"error" => Atom.to_string(reason)})
end
