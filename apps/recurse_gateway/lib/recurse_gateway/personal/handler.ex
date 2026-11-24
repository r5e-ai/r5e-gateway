defmodule Recurse.Gateway.Personal.Handler do
  @moduledoc """
  HTTP handlers for `/v1/personal/households`, `/v1/personal/settings`,
  `/v1/personal/digests`, bilateral QR child pairing (`/v1/personal/pairings*`),
  and child device revocation (`/v1/personal/devices/:device_key_id/revoke`).
  """

  alias Recurse.Gateway.Personal.{Common, Policy}
  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Provenance.{Envelope, Ref}
  alias Recurse.Providers.Personal, as: Store

  @manage_household ~s(Recurse::Action::"ManageHousehold")
  @read_household ~s(Recurse::Action::"ReadHouseholdEvidence")
  @pair_child ~s(Recurse::Action::"PairChildDevice")

  @pairing_ttl_seconds 300

  @doc "`POST /v1/personal/households`"
  @spec create_household(Plug.Conn.t()) :: Plug.Conn.t()
  def create_household(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate(conn, @manage_household, "/v1/personal/households", fn conn, ctx ->
      with {:ok, hh_attrs, owner_attrs} <- build_household_attrs(body, ctx),
           {:ok, hh, owner} <- Store.create_household(hh_attrs, owner_attrs),
           :ok <- insert_initial_members(hh.household_id, body["members"]) do
        Common.json(conn, 201, %{
          "householdId" => hh.household_id,
          "ownerMemberId" => owner.member_id,
          "profileMode" => hh.profile_mode,
          "custodyMode" => hh.custody_mode,
          "recoveryMode" => hh.recovery_mode,
          "threshold" => hh.threshold,
          "deploymentEndpoint" => "/v1/deployment"
        })
      else
        {:error, reason} when is_binary(reason) -> Common.bad_request(conn, reason)
        {:error, _reason} -> Common.json(conn, 422, %{"error" => "household_creation_failed"})
      end
    end)
  end

  def create_household(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc "`PATCH /v1/personal/settings`"
  @spec update_settings(Plug.Conn.t()) :: Plug.Conn.t()
  def update_settings(%Plug.Conn{body_params: body} = conn) when is_map(body) do
    Common.gate(conn, @manage_household, "/v1/personal/settings", fn conn, ctx ->
      with {:ok, household, _member} <- Common.resolve_household_member(conn, ctx),
           {:ok, updates} <- build_settings_updates(body, household),
           {:ok, updated} <- Store.update_household_settings(household.household_id, updates),
           :ok <- update_teen_modes(household.household_id, body["memberTeenConfidentiality"]) do
        Common.json(conn, 200, %{
          "householdId" => updated.household_id,
          "custodyMode" => updated.custody_mode,
          "recoveryMode" => updated.recovery_mode,
          "threshold" => updated.threshold,
          "quietHours" => render_quiet_hours(updated)
        })
      else
        {:error, :not_found} -> Common.not_found(conn)
        {:error, msg} when is_binary(msg) -> Common.json(conn, 422, %{"error" => msg})
        {:error, _} -> Common.json(conn, 422, %{"error" => "invalid_settings"})
      end
    end)
  end

  def update_settings(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc "`GET /v1/personal/digests`"
  @spec digests(Plug.Conn.t()) :: Plug.Conn.t()
  def digests(conn) do
    conn = Plug.Conn.fetch_query_params(conn)

    Common.gate(conn, @read_household, "/v1/personal/digests", fn conn, ctx ->
      case Common.resolve_household_member(conn, ctx) do
        {:ok, household, _member} ->
          items = load_digest_items(household, conn.query_params)
          Common.json(conn, 200, %{"items" => items, "nextCursor" => nil})

        {:error, :not_found} ->
          Common.not_found(conn)
      end
    end)
  end

  @doc "`POST /v1/personal/pairings`"
  @spec create_pairing(Plug.Conn.t()) :: Plug.Conn.t()
  def create_pairing(%Plug.Conn{body_params: %{"childMemberId" => child_id} = body} = conn)
      when is_binary(child_id) do
    Common.gate(conn, @pair_child, "/v1/personal/pairings", fn conn, ctx ->
      with {:ok, household, parent} <- Common.resolve_household_member(conn, ctx),
           {:ok, %{role: "child"}} <- Store.get_member(household.household_id, child_id),
           challenge_id = Common.random_id("pair_", 12),
           pairing_code = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false),
           nonce = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower),
           expires_at = DateTime.add(DateTime.utc_now(), @pairing_ttl_seconds, :second),
           {:ok, _row} <-
             Store.create_pairing_challenge(%{
               challenge_id: challenge_id,
               household_id: household.household_id,
               child_member_id: child_id,
               initiated_by_member: parent.member_id,
               pairing_code_hash: :crypto.hash(:sha256, pairing_code),
               nonce: nonce,
               device_meta_ref: body["deviceMetaRef"],
               expires_at: expires_at
             }) do
        Common.json(conn, 201, %{
          "challengeId" => challenge_id,
          "pairingCode" => pairing_code,
          "nonce" => nonce,
          "expiresAt" => DateTime.to_iso8601(expires_at),
          "badgeKinds" => Policy.child_badge_kinds()
        })
      else
        {:error, :not_found} -> Common.not_found(conn)
        :not_found -> Common.not_found(conn)
        {:ok, %{role: _other}} -> Common.json(conn, 422, %{"error" => "member_not_a_child"})
        {:error, _} -> Common.json(conn, 422, %{"error" => "pairing_create_failed"})
      end
    end)
  end

  def create_pairing(conn),
    do: Common.bad_request(conn, ~s(expected {"childMemberId": "mem_..."}))

  @doc "`POST /v1/personal/pairings/:challenge_id/device-claim` (public, code + PoP guarded)"
  @spec device_claim(Plug.Conn.t()) :: Plug.Conn.t()
  def device_claim(
        %Plug.Conn{
          path_params: %{"challenge_id" => challenge_id},
          body_params: %{
            "pairingCode" => pairing_code,
            "devicePublicKey" => pub_key,
            "popSignature" => pop_sig
          }
        } = conn
      )
      when is_binary(pairing_code) and is_map(pub_key) and is_binary(pop_sig) do
    Common.require_enabled(conn, fn conn ->
      with {:ok, challenge} <- Store.get_pairing_challenge(challenge_id),
           {:ok, device_key_id} <-
             Policy.verify_pairing_pop(pub_key, challenge_id, challenge.nonce, pop_sig),
           code_hash = :crypto.hash(:sha256, pairing_code),
           {:ok, claimed} <-
             Store.claim_pairing_challenge(challenge_id, code_hash, pub_key, device_key_id) do
        Common.json(conn, 200, %{
          "state" => claimed.state,
          "challengeId" => challenge_id,
          "deviceKeyId" => device_key_id,
          "badgeKinds" => Policy.child_badge_kinds()
        })
      else
        :not_found ->
          Common.not_found(conn)

        {:error, :not_found} ->
          Common.not_found(conn)

        {:error, :invalid_pairing_code} ->
          Common.json(conn, 401, %{"error" => "invalid_pairing_code"})

        {:error, :pairing_already_used} ->
          Common.json(conn, 409, %{"error" => "pairing_already_used"})

        {:error, :pairing_expired} ->
          Common.json(conn, 410, %{"error" => "pairing_expired"})

        {:error, :bad_pop_signature} ->
          Common.json(conn, 422, %{"error" => "bad_pop_signature"})
      end
    end)
  end

  def device_claim(conn) do
    Common.require_enabled(conn, fn conn ->
      Common.bad_request(
        conn,
        ~s(expected {"pairingCode", "devicePublicKey", "popSignature"})
      )
    end)
  end

  @doc """
  `POST /v1/personal/pairings/:challenge_id/finalize`

  Enforces the closed 5-kind child device `Badge.kinds` allowlist, rejecting
  wildcards (`personal.r5e.io/v1/*`) or parent-only kinds (`FamilyGuardrailSet`,
  `HouseholdProfile`, `PersonalErasure`) with `422 invalid_child_badge_kinds`.
  """
  @spec finalize_pairing(Plug.Conn.t()) :: Plug.Conn.t()
  def finalize_pairing(
        %Plug.Conn{path_params: %{"challenge_id" => challenge_id}, body_params: body} = conn
      )
      when is_map(body) do
    Common.gate(conn, @pair_child, "/v1/personal/pairings/finalize", fn conn, ctx ->
      with {:ok, household, _parent} <- Common.resolve_household_member(conn, ctx),
           {:ok, challenge} <- fetch_household_challenge(household.household_id, challenge_id),
           {:ok, badge_kinds, badge_ref} <- extract_and_validate_child_badge(body),
           {:ok, paired_ref} <- extract_paired_record_ref(body, challenge.device_key_id),
           {:ok, device} <-
             Store.finalize_pairing(household.household_id, challenge_id, %{
               device_key_id: challenge.device_key_id,
               child_member_id: challenge.child_member_id,
               paired_record_ref: paired_ref,
               badge_ref: badge_ref,
               badge_kinds: badge_kinds,
               device_meta_ref: challenge.device_meta_ref
             }) do
        Common.json(conn, 201, %{
          "pairedRecordRef" => device.paired_record_ref,
          "badgeRef" => device.badge_ref,
          "deviceKeyId" => device.device_key_id,
          "badgeKinds" => device.badge_kinds
        })
      else
        {:error, :not_found} ->
          Common.not_found(conn)

        {:error, :invalid_child_badge_kinds} ->
          Common.json(conn, 422, %{
            "error" => "invalid_child_badge_kinds",
            "allowedKinds" => Policy.child_badge_kinds()
          })

        {:error, :invalid_pairing_state} ->
          Common.json(conn, 409, %{"error" => "invalid_pairing_state"})

        {:error, reason} when is_atom(reason) ->
          Common.json(conn, 422, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  def finalize_pairing(conn), do: Common.bad_request(conn, "expected JSON body")

  @doc "`POST /v1/personal/devices/:device_key_id/revoke`"
  @spec revoke_device(Plug.Conn.t()) :: Plug.Conn.t()
  def revoke_device(%Plug.Conn{path_params: %{"device_key_id" => device_key_id}} = conn) do
    Common.gate(conn, @pair_child, "/v1/personal/devices/revoke", fn conn, ctx ->
      with {:ok, household, _parent} <- Common.resolve_household_member(conn, ctx),
           revocation_ref =
             Map.get(conn.body_params || %{}, "revocationRef") ||
               Ref.evidence(:crypto.strong_rand_bytes(32)),
           {:ok, device} <-
             Store.revoke_child_device(household.household_id, device_key_id, revocation_ref) do
        Common.json(conn, 200, %{
          "deviceKeyId" => device.device_key_id,
          "revocationRef" => device.revocation_ref,
          "tokensRevoked" => true
        })
      else
        {:error, :not_found} -> Common.not_found(conn)
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_household_attrs(body, ctx) do
    profile_mode = Map.get(body, "profileMode", "family")
    custody_mode = Map.get(body, "custodyMode", "client-e2ee")
    recovery_mode = Map.get(body, "recoveryMode", "self_only")
    threshold = Map.get(body, "threshold", 1)

    with :ok <-
           validate_choice(profile_mode, ["family", "solo"], "profileMode must be family or solo"),
         :ok <-
           validate_choice(
             custody_mode,
             ["client-e2ee", "gateway-managed"],
             "custodyMode must be client-e2ee or gateway-managed"
           ),
         :ok <-
           validate_choice(
             recovery_mode,
             ["self_only", "r5e_assisted"],
             "recoveryMode must be self_only or r5e_assisted"
           ),
         :ok <- validate_threshold(threshold) do
      quiet = Map.get(body, "quietHours") || %{}

      hh_attrs = %{
        household_id: resolve_new_household_id(ctx.tenant_id),
        tenant_id: ctx.tenant_id,
        profile_mode: profile_mode,
        custody_mode: custody_mode,
        recovery_mode: recovery_mode,
        threshold: threshold,
        active_terms_ref: body["activeTermsRef"],
        active_profile_ref: body["activeProfileRef"],
        quiet_hours_tz: quiet["tz"],
        quiet_hours_start_min: quiet["startMin"],
        quiet_hours_end_min: quiet["endMin"]
      }

      owner_attrs = %{
        member_id: resolve_owner_member_id(body["ownerMemberId"]),
        role: "owner",
        age_band: "adult",
        auth_subject: Common.subject_id(ctx),
        root_key_id: body["ownerRootKeyId"],
        working_key_id: body["ownerWorkingKeyId"]
      }

      {:ok, hh_attrs, owner_attrs}
    end
  end

  defp validate_choice(value, allowed, error_msg) do
    if value in allowed, do: :ok, else: {:error, error_msg}
  end

  defp validate_threshold(t) when is_integer(t) and t >= 1, do: :ok
  defp validate_threshold(_), do: {:error, "threshold must be a positive integer"}

  defp resolve_new_household_id(tenant_id) when is_binary(tenant_id) do
    if Regex.match?(~r/\Ahh_[a-f0-9]{12,64}\z/, tenant_id),
      do: tenant_id,
      else: Common.random_id("hh_", 16)
  end

  defp resolve_new_household_id(_), do: Common.random_id("hh_", 16)

  defp resolve_owner_member_id(id) when is_binary(id), do: id
  defp resolve_owner_member_id(_), do: Common.random_id("mem_", 12)

  defp insert_initial_members(_household_id, nil), do: :ok

  defp insert_initial_members(household_id, members) when is_list(members) do
    Enum.reduce_while(members, :ok, fn
      %{"memberId" => id, "role" => role, "ageBand" => age_band} = m, :ok ->
        case Store.add_member(household_id, %{
               member_id: id,
               role: role,
               age_band: age_band,
               auth_subject: m["authSubject"],
               root_key_id: m["rootKeyId"],
               working_key_id: m["workingKeyId"],
               teen_confidentiality: Map.get(m, "teenConfidentiality", "teen-private-crisis")
             }) do
          {:ok, _} -> {:cont, :ok}
          error -> {:halt, error}
        end

      _, _ ->
        {:halt, {:error, "each member requires memberId, role, and ageBand"}}
    end)
  end

  defp insert_initial_members(_, _), do: {:error, "members must be a list"}

  defp build_settings_updates(body, _household) do
    quiet = Map.get(body, "quietHours")

    updates =
      []
      |> maybe_put_setting(:custody_mode, body["custodyMode"], ["client-e2ee", "gateway-managed"])
      |> maybe_put_setting(:recovery_mode, body["recoveryMode"], ["self_only", "r5e_assisted"])
      |> maybe_put_threshold(body["threshold"])
      |> maybe_put_quiet(quiet)

    case updates do
      {:error, _} = err -> err
      kw -> {:ok, kw}
    end
  end

  defp maybe_put_setting({:error, _} = err, _k, _v, _allowed), do: err
  defp maybe_put_setting(acc, _k, nil, _allowed), do: acc

  defp maybe_put_setting(acc, k, v, allowed) do
    if v in allowed, do: Keyword.put(acc, k, v), else: {:error, "invalid_#{k}"}
  end

  defp maybe_put_threshold({:error, _} = err, _), do: err
  defp maybe_put_threshold(acc, nil), do: acc

  defp maybe_put_threshold(acc, t) when is_integer(t) and t >= 1,
    do: Keyword.put(acc, :threshold, t)

  defp maybe_put_threshold(_acc, _), do: {:error, "invalid_threshold"}

  defp maybe_put_quiet({:error, _} = err, _), do: err
  defp maybe_put_quiet(acc, nil), do: acc

  defp maybe_put_quiet(acc, %{"tz" => tz, "startMin" => s, "endMin" => e})
       when is_binary(tz) and is_integer(s) and s in 0..1439 and is_integer(e) and e in 0..1439 do
    acc
    |> Keyword.put(:quiet_hours_tz, tz)
    |> Keyword.put(:quiet_hours_start_min, s)
    |> Keyword.put(:quiet_hours_end_min, e)
  end

  defp maybe_put_quiet(_acc, _), do: {:error, "invalid_quiet_hours"}

  defp update_teen_modes(_household_id, nil), do: :ok

  defp update_teen_modes(household_id, map) when is_map(map) do
    Enum.reduce_while(map, :ok, fn {member_id, mode}, :ok ->
      case apply_teen_mode(household_id, member_id, mode) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp update_teen_modes(_, _), do: {:error, "invalid_member_teen_confidentiality"}

  defp apply_teen_mode(household_id, member_id, mode)
       when mode in ["standard", "teen-private-crisis"] do
    Store.update_member_teen_confidentiality(household_id, member_id, mode)
  end

  defp apply_teen_mode(_household_id, _member_id, _mode),
    do: {:error, "invalid_teen_confidentiality"}

  defp render_quiet_hours(%{quiet_hours_tz: nil}), do: nil

  defp render_quiet_hours(hh) do
    %{
      "tz" => hh.quiet_hours_tz,
      "startMin" => hh.quiet_hours_start_min,
      "endMin" => hh.quiet_hours_end_min
    }
  end

  defp fetch_household_challenge(household_id, challenge_id) do
    case Store.get_pairing_challenge(challenge_id) do
      {:ok, %{household_id: ^household_id} = challenge} -> {:ok, challenge}
      _ -> {:error, :not_found}
    end
  end

  defp extract_and_validate_child_badge(%{"badgeEnvelope" => envelope}) when is_map(envelope) do
    case Envelope.open(envelope) do
      {:ok, %{ref: ref, evidence: %{"kind" => "Badge", "body" => %{"kinds" => kinds}}}} ->
        with :ok <- Policy.validate_child_badge_kinds(kinds) do
          {:ok, kinds, ref}
        end

      _ ->
        {:error, :invalid_badge_envelope}
    end
  end

  defp extract_and_validate_child_badge(%{"badgeKinds" => kinds} = body) do
    with :ok <- Policy.validate_child_badge_kinds(kinds) do
      badge_ref =
        case body["badgeRef"] do
          ref when is_binary(ref) -> ref
          _ -> Ref.evidence(:crypto.strong_rand_bytes(32))
        end

      {:ok, kinds, badge_ref}
    end
  end

  defp extract_and_validate_child_badge(_body), do: {:error, :invalid_child_badge_kinds}

  defp extract_paired_record_ref(%{"childDevicePairedEnvelope" => envelope}, expected_key_id)
       when is_map(envelope) do
    with {:ok, %{ref: ref, evidence: ev}} <- Envelope.open(envelope),
         true <- ev["apiVersion"] == "personal.r5e.io/v1" and ev["kind"] == "ChildDevicePaired",
         true <- length(List.wrap(envelope["signatures"])) == 2,
         true <- is_nil(expected_key_id) or get_in(ev, ["body", "deviceKeyId"]) == expected_key_id do
      {:ok, ref}
    else
      _ -> {:error, :invalid_child_device_paired_envelope}
    end
  end

  defp extract_paired_record_ref(%{"pairedRecordRef" => ref}, _expected_key_id)
       when is_binary(ref),
       do: {:ok, ref}

  defp extract_paired_record_ref(_body, _expected_key_id),
    do: {:ok, Ref.evidence(:crypto.strong_rand_bytes(32))}

  defp load_digest_items(household, params) do
    members = Store.list_members(household.household_id)

    teen_private =
      MapSet.new(
        for m <- members, m.teen_confidentiality == "teen-private-crisis", do: m.member_id
      )

    member_filter = params["member_id"]

    deployment =
      case Runtime.info() do
        %{deployment: dep} -> dep
        _ -> Application.get_env(:recurse_gateway, :evidence_deployment, "default")
      end

    {module, handle} = Runtime.store(deployment)
    prefix = "urn:r5e:stream:#{deployment}:"

    case module.by_kind(handle, "personal.r5e.io/v1/SafetyIntervention", prefix) do
      {:ok, entries} ->
        entries
        |> Enum.filter(&digest_visible?(&1, member_filter, teen_private))
        |> Enum.group_by(& &1.evidence["session"])
        |> Enum.map(fn {session_scope, group} ->
          %{
            "sessionScope" => session_scope,
            "custodyMode" => household.custody_mode,
            "interventionCount" => length(group),
            "categories" =>
              group |> Enum.map(&get_in(&1.evidence, ["body", "category"])) |> Enum.uniq(),
            "summaryRefs" =>
              group
              |> Enum.map(&get_in(&1.evidence, ["body", "summaryRef"]))
              |> Enum.reject(&is_nil/1),
            "erased" =>
              match?(
                {:gone, _},
                Store.scope_tombstone(household.household_id, session_scope || "")
              )
          }
        end)

      _ ->
        []
    end
  rescue
    _ -> []
  end

  defp digest_visible?(%{evidence: ev}, member_filter, teen_private) do
    actor = ev["actor"] || ""
    category = get_in(ev, ["body", "category"])
    matches_member? = is_nil(member_filter) or String.contains?(actor, member_filter)

    suppressed_crisis? =
      category == "safety-redirect" and
        Enum.any?(teen_private, &String.contains?(actor, &1))

    matches_member? and not suppressed_crisis?
  end
end
