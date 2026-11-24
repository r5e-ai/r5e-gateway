defmodule Recurse.Gateway.Personal.ErasureHandler do
  @moduledoc """
  HTTP handlers for unified personal erasure (`POST /v1/personal/erasures`) and
  two-parent (`threshold: 2`) co-sign erasure proposals
  (`POST /v1/personal/erasures/proposals`, `.../proposals/:proposal_id/approve`).
  """

  alias Recurse.Gateway.Personal.Common
  alias Recurse.Gateway.Provenance.{Retention, Runtime}
  alias Recurse.Provenance.{Envelope, Ref}
  alias Recurse.Providers.Personal, as: Store

  @manage_household ~s(Recurse::Action::"ManageHousehold")
  @manage_retention ~s(Recurse::Action::"ManageRetention")

  @proposal_ttl_seconds 259_200

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
      with {:ok, household, proposer} <- Common.resolve_household_member(conn, ctx),
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
        {:error, :not_found} -> Common.not_found(conn)
        {:error, _} -> Common.json(conn, 422, %{"error" => "proposal_creation_failed"})
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
      with {:ok, household, approver} <- Common.resolve_household_member(conn, ctx),
           {:ok, co_sign_ref, decision, req_digest} <- extract_approval(body),
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
        {:error, :not_found} ->
          Common.not_found(conn)

        {:error, :self_approval_forbidden} ->
          Common.json(conn, 409, %{"error" => "self_approval_forbidden"})

        {:error, :proposal_expired} ->
          Common.json(conn, 410, %{"error" => "proposal_expired"})

        {:error, :proposal_not_pending} ->
          Common.json(conn, 409, %{"error" => "proposal_not_pending"})

        {:error, :digest_mismatch} ->
          Common.json(conn, 422, %{"error" => "digest_mismatch"})

        {:error, reason} ->
          Common.json(conn, 422, %{"error" => Atom.to_string(reason)})
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
        with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
             {:ok, parsed} <- parse_erasure_request(body, household),
             :ok <- check_two_parent_cosign(household, parsed),
             {:ok, result} <- run_erasure(household, parsed, ctx) do
          if is_binary(parsed.co_sign_ref) do
            Store.mark_proposal_executed(
              household.household_id,
              parsed.co_sign_ref,
              result.erasure_ref
            )
          end

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
          {:error, :not_found} ->
            Common.not_found(conn)

          {:error, :co_sign_required} ->
            Common.json(conn, 409, %{"error" => "co_sign_required"})

          {:error, :nothing_to_dispose} ->
            Common.json(conn, 409, %{"error" => "ERR_NOTHING_TO_DISPOSE"})

          {:error, reason} when is_atom(reason) ->
            Common.json(conn, 422, %{"error" => Atom.to_string(reason)})
        end
      end
    )
  end

  def execute_erasure(conn), do: Common.bad_request(conn, "expected JSON body")

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

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

  defp extract_approval(%{"coParentApprovalEnvelope" => env}) when is_map(env) do
    case Envelope.open(env) do
      {:ok,
       %{
         ref: ref,
         evidence: %{
           "apiVersion" => "personal.r5e.io/v1",
           "kind" => "CoParentApproval",
           "body" => body
         }
       }} ->
        {:ok, ref, Map.get(body, "decision", "approve"), body["requestDigest"]}

      _ ->
        {:error, :invalid_co_parent_approval}
    end
  end

  defp extract_approval(body) do
    co_sign_ref = body["coSignRef"] || Ref.evidence(:crypto.strong_rand_bytes(32))
    decision = Map.get(body, "decision", "approve")

    if decision in ["approve", "deny"] do
      {:ok, co_sign_ref, decision, body["requestDigest"]}
    else
      {:error, :invalid_decision}
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
          }} <-
           Envelope.open(env),
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

    if method in ["gateway-disposal", "client-key-and-blob-deletion"] do
      {:ok,
       %{
         scope: scope,
         target_id: target_id,
         erasure_method: method,
         co_sign_ref: body["coSignRef"],
         erasure_ref: body["erasureRef"] || Ref.evidence(:crypto.strong_rand_bytes(32)),
         household_id: household.household_id
       }}
    else
      {:error, :invalid_erasure_method}
    end
  end

  defp parse_erasure_request(_, _), do: {:error, :malformed_erasure_request}

  defp check_two_parent_cosign(%{threshold: threshold, household_id: hh_id}, %{
         scope: "household",
         target_id: target_id,
         co_sign_ref: co_sign_ref
       })
       when threshold >= 2 do
    if Store.approved_cosign?(hh_id, "household", target_id, co_sign_ref) do
      :ok
    else
      {:error, :co_sign_required}
    end
  end

  defp check_two_parent_cosign(_household, _parsed), do: :ok

  defp run_erasure(household, %{erasure_method: "client-key-and-blob-deletion"} = parsed, _ctx) do
    target = if parsed.scope == "household", do: :household, else: {:scope, parsed.target_id}

    {:ok, %{key_wraps_deleted: wraps, blobs_tombstoned: blobs}} =
      Store.erase_client_e2ee(household.household_id, target, parsed.erasure_ref)

    {:ok,
     %{
       erasure_ref: parsed.erasure_ref,
       disposition_refs: [],
       key_wraps_deleted: wraps,
       blobs_tombstoned: blobs
     }}
  end

  defp run_erasure(_household, %{erasure_method: "gateway-disposal"} = parsed, _ctx) do
    if Runtime.running?() do
      case Retention.dispose(%{"scope" => parsed.target_id, "reason" => "personal_erasure"}, nil) do
        {:ok, %{"disposition" => disp_ref}} ->
          {:ok,
           %{
             erasure_ref: parsed.erasure_ref,
             disposition_refs: [disp_ref],
             key_wraps_deleted: 0,
             blobs_tombstoned: 0
           }}

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:ok,
       %{
         erasure_ref: parsed.erasure_ref,
         disposition_refs: [],
         key_wraps_deleted: 0,
         blobs_tombstoned: 0
       }}
    end
  end
end
