defmodule Recurse.Providers.Personal do
  @moduledoc """
  Postgres persistence context for opt-in `personal.r5e.io/v1` households,
  bilateral QR child pairing, mutable Phase-2 `client-e2ee` key-wraps and
  ciphertext blobs (with 410 tombstones), client-locked D19 recovery envelopes,
  and two-parent (`threshold: 2`) co-sign erasure proposals.

  Every query scopes strictly by `household_id` so two households sharing a
  gateway node can never read, mutate, or tombstone one another's rows.
  """

  import Ecto.Query

  alias Recurse.Providers.Repo

  @type household_id :: String.t()
  @type member_id :: String.t()

  # ---------------------------------------------------------------------------
  # Households & Members
  # ---------------------------------------------------------------------------

  @doc "Create a household and its founding owner/parent member in one transaction."
  @spec create_household(map(), map()) :: {:ok, map(), map()} | {:error, term()}
  def create_household(household_attrs, owner_attrs) do
    now = DateTime.utc_now()

    hh_row = %{
      household_id: household_attrs.household_id,
      tenant_id: household_attrs.tenant_id,
      profile_mode: Map.get(household_attrs, :profile_mode, "family"),
      custody_mode: Map.get(household_attrs, :custody_mode, "client-e2ee"),
      recovery_mode: Map.get(household_attrs, :recovery_mode, "self_only"),
      threshold: Map.get(household_attrs, :threshold, 1),
      active_terms_ref: Map.get(household_attrs, :active_terms_ref),
      active_profile_ref: Map.get(household_attrs, :active_profile_ref),
      quiet_hours_tz: Map.get(household_attrs, :quiet_hours_tz),
      quiet_hours_start_min: Map.get(household_attrs, :quiet_hours_start_min),
      quiet_hours_end_min: Map.get(household_attrs, :quiet_hours_end_min),
      settings: Map.get(household_attrs, :settings, %{}),
      inserted_at: now,
      updated_at: now
    }

    owner_row = %{
      household_id: household_attrs.household_id,
      member_id: owner_attrs.member_id,
      role: Map.get(owner_attrs, :role, "owner"),
      age_band: Map.get(owner_attrs, :age_band, "adult"),
      auth_subject: Map.get(owner_attrs, :auth_subject),
      root_key_id: Map.get(owner_attrs, :root_key_id),
      working_key_id: Map.get(owner_attrs, :working_key_id),
      teen_confidentiality: Map.get(owner_attrs, :teen_confidentiality, "teen-private-crisis"),
      inserted_at: now,
      updated_at: now
    }

    Repo.transaction(fn ->
      Repo.insert_all("personal_households", [hh_row])
      Repo.insert_all("personal_members", [owner_row])
      {hh_row, owner_row}
    end)
    |> case do
      {:ok, {hh, owner}} -> {:ok, hh, owner}
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, error}
  end

  @doc "Fetch a household by `household_id`."
  @spec get_household(household_id()) :: {:ok, map()} | :not_found
  def get_household(household_id) when is_binary(household_id) do
    query =
      from(h in "personal_households",
        where: h.household_id == ^household_id,
        select: %{
          household_id: h.household_id,
          tenant_id: h.tenant_id,
          profile_mode: h.profile_mode,
          custody_mode: h.custody_mode,
          recovery_mode: h.recovery_mode,
          threshold: h.threshold,
          active_terms_ref: h.active_terms_ref,
          active_profile_ref: h.active_profile_ref,
          quiet_hours_tz: h.quiet_hours_tz,
          quiet_hours_start_min: h.quiet_hours_start_min,
          quiet_hours_end_min: h.quiet_hours_end_min,
          settings: h.settings
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc """
  Find households in `tenant_id` where `auth_subject` is an active (non-revoked)
  member. Returns up to 2 `{household, member}` pairs so callers can detect
  ambiguous membership rather than silently selecting the newest household.
  """
  @spec find_member_households(String.t(), String.t()) :: [{map(), map()}]
  def find_member_households(tenant_id, auth_subject)
      when is_binary(tenant_id) and is_binary(auth_subject) do
    query =
      from(h in "personal_households",
        join: m in "personal_members",
        on: m.household_id == h.household_id,
        where:
          h.tenant_id == ^tenant_id and
            m.auth_subject == ^auth_subject and
            is_nil(m.revoked_at),
        limit: 2,
        select:
          {%{
             household_id: h.household_id,
             tenant_id: h.tenant_id,
             profile_mode: h.profile_mode,
             custody_mode: h.custody_mode,
             recovery_mode: h.recovery_mode,
             threshold: h.threshold,
             active_terms_ref: h.active_terms_ref,
             active_profile_ref: h.active_profile_ref,
             quiet_hours_tz: h.quiet_hours_tz,
             quiet_hours_start_min: h.quiet_hours_start_min,
             quiet_hours_end_min: h.quiet_hours_end_min,
             settings: h.settings
           },
           %{
             household_id: m.household_id,
             member_id: m.member_id,
             role: m.role,
             age_band: m.age_band,
             auth_subject: m.auth_subject,
             root_key_id: m.root_key_id,
             working_key_id: m.working_key_id,
             teen_confidentiality: m.teen_confidentiality,
             recovery_envelope_deleted_at: m.recovery_envelope_deleted_at
           }}
      )

    Repo.all(query)
  end

  def find_member_households(_, _), do: []

  @doc "Update mutable household settings (quiet hours, custody mode, recovery mode, threshold)."
  @spec update_household_settings(household_id(), keyword()) :: {:ok, map()} | {:error, term()}
  def update_household_settings(household_id, updates) when is_list(updates) do
    allowed =
      Keyword.take(updates, [
        :custody_mode,
        :recovery_mode,
        :threshold,
        :active_terms_ref,
        :active_profile_ref,
        :quiet_hours_tz,
        :quiet_hours_start_min,
        :quiet_hours_end_min,
        :settings
      ])

    set_fields = Keyword.put(allowed, :updated_at, DateTime.utc_now())

    case Repo.update_all(
           from(h in "personal_households", where: h.household_id == ^household_id),
           set: set_fields
         ) do
      {1, _} -> get_household(household_id)
      {0, _} -> {:error, :not_found}
    end
  rescue
    error -> {:error, error}
  end

  @doc "Insert a household member (`parent` or `child`)."
  @spec add_member(household_id(), map()) :: {:ok, map()} | {:error, term()}
  def add_member(household_id, attrs) do
    now = DateTime.utc_now()

    row = %{
      household_id: household_id,
      member_id: attrs.member_id,
      role: attrs.role,
      age_band: attrs.age_band,
      auth_subject: Map.get(attrs, :auth_subject),
      root_key_id: Map.get(attrs, :root_key_id),
      working_key_id: Map.get(attrs, :working_key_id),
      teen_confidentiality: Map.get(attrs, :teen_confidentiality, "teen-private-crisis"),
      inserted_at: now,
      updated_at: now
    }

    Repo.insert_all("personal_members", [row], on_conflict: :nothing)
    get_member(household_id, attrs.member_id)
  rescue
    error -> {:error, error}
  end

  @doc "Fetch a member scoped strictly to `household_id`."
  @spec get_member(household_id(), member_id()) :: {:ok, map()} | :not_found
  def get_member(household_id, member_id) do
    query =
      from(m in "personal_members",
        where: m.household_id == ^household_id and m.member_id == ^member_id,
        select: %{
          household_id: m.household_id,
          member_id: m.member_id,
          role: m.role,
          age_band: m.age_band,
          auth_subject: m.auth_subject,
          root_key_id: m.root_key_id,
          working_key_id: m.working_key_id,
          active_guardrail_ref: m.active_guardrail_ref,
          teen_confidentiality: m.teen_confidentiality,
          recovery_envelope_deleted_at: m.recovery_envelope_deleted_at,
          revoked_at: m.revoked_at
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc "Find active (non-revoked) member by `auth_subject` inside a household."
  @spec find_member_by_subject(household_id(), String.t()) :: {:ok, map()} | :not_found
  def find_member_by_subject(household_id, auth_subject) when is_binary(auth_subject) do
    query =
      from(m in "personal_members",
        where:
          m.household_id == ^household_id and
            m.auth_subject == ^auth_subject and
            is_nil(m.revoked_at),
        limit: 1,
        select: %{
          household_id: m.household_id,
          member_id: m.member_id,
          role: m.role,
          age_band: m.age_band,
          auth_subject: m.auth_subject,
          root_key_id: m.root_key_id,
          working_key_id: m.working_key_id,
          teen_confidentiality: m.teen_confidentiality,
          recovery_envelope_deleted_at: m.recovery_envelope_deleted_at
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc "Rotate a member's active root and working signing key IDs after verified recovery."
  @spec rotate_member_keys(household_id(), member_id(), String.t(), String.t()) ::
          {:ok, map()} | {:error, :not_found}
  def rotate_member_keys(household_id, member_id, new_root_key_id, new_working_key_id)
      when is_binary(new_root_key_id) and is_binary(new_working_key_id) do
    case Repo.update_all(
           from(m in "personal_members",
             where:
               m.household_id == ^household_id and
                 m.member_id == ^member_id and
                 is_nil(m.revoked_at)
           ),
           set: [
             root_key_id: new_root_key_id,
             working_key_id: new_working_key_id,
             updated_at: DateTime.utc_now()
           ]
         ) do
      {1, _} -> get_member(household_id, member_id)
      {0, _} -> {:error, :not_found}
    end
  end

  @doc "Update `teen_confidentiality` for a member inside `household_id`."
  @spec update_member_teen_confidentiality(household_id(), member_id(), String.t()) ::
          :ok | {:error, term()}
  def update_member_teen_confidentiality(household_id, member_id, mode)
      when mode in ["standard", "teen-private-crisis"] do
    case Repo.update_all(
           from(m in "personal_members",
             where: m.household_id == ^household_id and m.member_id == ^member_id
           ),
           set: [teen_confidentiality: mode, updated_at: DateTime.utc_now()]
         ) do
      {1, _} -> :ok
      {0, _} -> {:error, :not_found}
    end
  end

  @doc "List all members of a household."
  @spec list_members(household_id()) :: [map()]
  def list_members(household_id) do
    from(m in "personal_members",
      where: m.household_id == ^household_id,
      select: %{
        member_id: m.member_id,
        role: m.role,
        age_band: m.age_band,
        auth_subject: m.auth_subject,
        teen_confidentiality: m.teen_confidentiality
      }
    )
    |> Repo.all()
  end

  # ---------------------------------------------------------------------------
  # Bilateral QR Child-Device Pairing
  # ---------------------------------------------------------------------------

  @doc "Create a 5-minute single-use QR pairing challenge."
  @spec create_pairing_challenge(map()) :: {:ok, map()} | {:error, term()}
  def create_pairing_challenge(attrs) do
    now = DateTime.utc_now()

    row = %{
      challenge_id: attrs.challenge_id,
      household_id: attrs.household_id,
      child_member_id: attrs.child_member_id,
      initiated_by_member: attrs.initiated_by_member,
      pairing_code_hash: attrs.pairing_code_hash,
      nonce: attrs.nonce,
      device_meta_ref: Map.get(attrs, :device_meta_ref),
      state: "pending",
      expires_at: attrs.expires_at,
      inserted_at: now
    }

    Repo.insert_all("personal_pairing_challenges", [row])
    {:ok, row}
  rescue
    error -> {:error, error}
  end

  @doc "Fetch a pairing challenge by `challenge_id`."
  @spec get_pairing_challenge(String.t()) :: {:ok, map()} | :not_found
  def get_pairing_challenge(challenge_id) do
    query =
      from(p in "personal_pairing_challenges",
        where: p.challenge_id == ^challenge_id,
        select: %{
          challenge_id: p.challenge_id,
          household_id: p.household_id,
          child_member_id: p.child_member_id,
          initiated_by_member: p.initiated_by_member,
          pairing_code_hash: p.pairing_code_hash,
          nonce: p.nonce,
          device_meta_ref: p.device_meta_ref,
          device_public_key: p.device_public_key,
          device_key_id: p.device_key_id,
          state: p.state,
          expires_at: p.expires_at,
          completed_at: p.completed_at
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc "Atomically claim a pending, unexpired pairing challenge."
  @spec claim_pairing_challenge(String.t(), binary(), map(), String.t()) ::
          {:ok, map()} | {:error, atom()}
  def claim_pairing_challenge(challenge_id, code_hash, device_public_key, device_key_id) do
    now = DateTime.utc_now()

    case get_pairing_challenge(challenge_id) do
      :not_found ->
        {:error, :not_found}

      {:ok, %{pairing_code_hash: stored_hash}} when stored_hash != code_hash ->
        {:error, :invalid_pairing_code}

      {:ok, %{state: state}} when state != "pending" ->
        {:error, :pairing_already_used}

      {:ok, %{expires_at: expires_at} = challenge} ->
        apply_pairing_claim(
          challenge,
          challenge_id,
          device_public_key,
          device_key_id,
          expires_at,
          now
        )
    end
  end

  defp apply_pairing_claim(
         challenge,
         challenge_id,
         device_public_key,
         device_key_id,
         expires_at,
         now
       ) do
    if DateTime.compare(expires_at, now) != :gt do
      {:error, :pairing_expired}
    else
      {updated, _} =
        Repo.update_all(
          from(p in "personal_pairing_challenges",
            where:
              p.challenge_id == ^challenge_id and p.state == "pending" and p.expires_at > ^now
          ),
          set: [
            state: "device_claimed",
            device_public_key: device_public_key,
            device_key_id: device_key_id
          ]
        )

      if updated == 1 do
        {:ok,
         %{
           challenge
           | state: "device_claimed",
             device_public_key: device_public_key,
             device_key_id: device_key_id
         }}
      else
        {:error, :pairing_already_used}
      end
    end
  end

  @doc "Finalize a device-claimed pairing challenge and register the paired child device."
  @spec finalize_pairing(household_id(), String.t(), map()) :: {:ok, map()} | {:error, atom()}
  def finalize_pairing(household_id, challenge_id, device_attrs) do
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      {updated, _} =
        Repo.update_all(
          from(p in "personal_pairing_challenges",
            where:
              p.challenge_id == ^challenge_id and
                p.household_id == ^household_id and
                p.state == "device_claimed" and
                p.expires_at > ^now
          ),
          set: [state: "completed", completed_at: now]
        )

      if updated != 1 do
        Repo.rollback(:invalid_pairing_state)
      end

      device_row = %{
        device_key_id: device_attrs.device_key_id,
        household_id: household_id,
        child_member_id: device_attrs.child_member_id,
        paired_record_ref: device_attrs.paired_record_ref,
        badge_ref: device_attrs.badge_ref,
        badge_kinds: device_attrs.badge_kinds,
        device_meta_ref: Map.get(device_attrs, :device_meta_ref),
        inserted_at: now
      }

      Repo.insert_all("personal_child_devices", [device_row])
      device_row
    end)
  rescue
    error -> {:error, error}
  end

  @doc "Look up a registered child device by `device_key_id`."
  @spec get_child_device(String.t()) :: {:ok, map()} | :not_found
  def get_child_device(device_key_id) when is_binary(device_key_id) do
    query =
      from(d in "personal_child_devices",
        where: d.device_key_id == ^device_key_id,
        select: %{
          device_key_id: d.device_key_id,
          household_id: d.household_id,
          child_member_id: d.child_member_id,
          paired_record_ref: d.paired_record_ref,
          badge_ref: d.badge_ref,
          badge_kinds: d.badge_kinds,
          revoked_at: d.revoked_at,
          revocation_ref: d.revocation_ref
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc "Revoke a paired child device inside `household_id`."
  @spec revoke_child_device(household_id(), String.t(), String.t()) ::
          {:ok, map()} | {:error, :not_found}
  def revoke_child_device(household_id, device_key_id, revocation_ref) do
    now = DateTime.utc_now()

    case Repo.update_all(
           from(d in "personal_child_devices",
             where: d.household_id == ^household_id and d.device_key_id == ^device_key_id
           ),
           set: [revoked_at: now, revocation_ref: revocation_ref]
         ) do
      {1, _} -> get_child_device(device_key_id)
      {0, _} -> {:error, :not_found}
    end
  end

  # ---------------------------------------------------------------------------
  # Phase-2 `client-e2ee` Recipient Keys, Mutable Key-Wraps & Blobs
  # ---------------------------------------------------------------------------

  @doc "Register an X25519 recipient public key inside `household_id`."
  @spec upsert_recipient_key(household_id(), map()) :: {:ok, map()} | {:error, term()}
  def upsert_recipient_key(household_id, attrs) do
    now = DateTime.utc_now()

    row = %{
      household_id: household_id,
      recipient_key_id: attrs.recipient_key_id,
      member_id: Map.get(attrs, :member_id),
      recipient_kind: attrs.recipient_kind,
      algorithm: "x25519",
      public_key_bytes: attrs.public_key_bytes,
      inserted_at: now
    }

    Repo.insert_all("personal_e2ee_recipient_keys", [row],
      on_conflict: :nothing,
      conflict_target: [:household_id, :recipient_key_id]
    )

    {:ok, row}
  rescue
    error -> {:error, error}
  end

  @doc "Check whether a scope already carries a tombstoned blob inside `household_id`."
  @spec scope_tombstone(household_id(), String.t()) :: {:gone, String.t()} | :live
  def scope_tombstone(household_id, scope) do
    query =
      from(b in "personal_e2ee_blobs",
        where: b.household_id == ^household_id and b.scope == ^scope and not is_nil(b.deleted_at),
        limit: 1,
        select: b.erasure_ref
      )

    case Repo.one(query) do
      nil -> :live
      erasure_ref -> {:gone, erasure_ref}
    end
  end

  @doc "Check whether `household_id` already holds E2EE wraps or blobs for `scope`."
  @spec household_owns_scope?(household_id(), String.t()) :: boolean()
  def household_owns_scope?(household_id, scope)
      when is_binary(household_id) and is_binary(scope) do
    has_wrap? =
      not is_nil(
        Repo.one(
          from(w in "personal_e2ee_key_wraps",
            where: w.household_id == ^household_id and w.scope == ^scope,
            limit: 1,
            select: w.scope
          )
        )
      )

    has_blob? =
      not is_nil(
        Repo.one(
          from(b in "personal_e2ee_blobs",
            where: b.household_id == ^household_id and b.scope == ^scope,
            limit: 1,
            select: b.scope
          )
        )
      )

    has_wrap? or has_blob?
  end

  def household_owns_scope?(_, _), do: false

  @doc "Return all distinct live E2EE scopes (wraps or non-tombstoned blobs) for `household_id`."
  @spec list_client_e2ee_scopes(household_id()) :: [String.t()]
  def list_client_e2ee_scopes(household_id) when is_binary(household_id) do
    wrap_scopes =
      Repo.all(
        from(w in "personal_e2ee_key_wraps",
          where: w.household_id == ^household_id,
          distinct: true,
          select: w.scope
        )
      )

    blob_scopes =
      Repo.all(
        from(b in "personal_e2ee_blobs",
          where: b.household_id == ^household_id and is_nil(b.deleted_at),
          distinct: true,
          select: b.scope
        )
      )

    Enum.uniq(wrap_scopes ++ blob_scopes)
  end

  def list_client_e2ee_scopes(_), do: []

  @doc """
  Upsert wrapped per-session DEKs for authorized recipients in `household_id`.
  Prevents one parent from overwriting an existing wrap belonging to a
  recipient key owned by another member (`{:error, :wrap_overwrite_forbidden}`).
  """
  @spec put_key_wraps(household_id(), String.t(), [map()], member_id() | nil) ::
          {:ok, non_neg_integer()} | {:error, atom()} | {:gone, String.t()}
  def put_key_wraps(household_id, scope, wraps, caller_member_id \\ nil)

  def put_key_wraps(household_id, scope, wraps, caller_member_id)
      when is_list(wraps) and wraps != [] do
    case scope_tombstone(household_id, scope) do
      {:gone, erasure_ref} ->
        {:gone, erasure_ref}

      :live ->
        insert_key_wraps_tx(household_id, scope, wraps, caller_member_id)
    end
  rescue
    error -> {:error, error}
  end

  defp insert_key_wraps_tx(household_id, scope, wraps, caller_member_id) do
    recipient_ids = wraps |> Enum.map(& &1.recipient_key_id) |> Enum.uniq()

    {:ok, result} =
      Repo.transaction(fn ->
        existing_keys = fetch_active_recipient_keys(household_id, recipient_ids)

        with :ok <- verify_all_recipients_exist(existing_keys, recipient_ids),
             :ok <-
               check_foreign_wrap_overwrite(
                 household_id,
                 scope,
                 recipient_ids,
                 existing_keys,
                 caller_member_id
               ) do
          persist_key_wrap_rows(household_id, scope, wraps, existing_keys, caller_member_id)
        end
      end)

    result
  end

  defp fetch_active_recipient_keys(household_id, recipient_ids) do
    from(r in "personal_e2ee_recipient_keys",
      where:
        r.household_id == ^household_id and
          r.recipient_key_id in ^recipient_ids and
          is_nil(r.revoked_at),
      select: {r.recipient_key_id, %{recipient_kind: r.recipient_kind, member_id: r.member_id}}
    )
    |> Repo.all()
    |> Map.new()
  end

  defp verify_all_recipients_exist(existing_keys, recipient_ids) do
    if map_size(existing_keys) == length(recipient_ids),
      do: :ok,
      else: {:error, :recipient_not_found}
  end

  defp check_foreign_wrap_overwrite(_hh_id, _scope, _ids, _existing_keys, nil), do: :ok

  defp check_foreign_wrap_overwrite(household_id, scope, recipient_ids, existing_keys, caller_id) do
    existing_wrap_ids =
      from(w in "personal_e2ee_key_wraps",
        where:
          w.household_id == ^household_id and
            w.scope == ^scope and
            w.recipient_key_id in ^recipient_ids,
        select: w.recipient_key_id
      )
      |> Repo.all()

    foreign_conflict? =
      Enum.any?(existing_wrap_ids, fn rk_id ->
        owner = get_in(existing_keys, [rk_id, :member_id])
        is_binary(owner) and owner != caller_id
      end)

    if foreign_conflict?, do: {:error, :wrap_overwrite_forbidden}, else: :ok
  end

  defp persist_key_wrap_rows(household_id, scope, wraps, existing_keys, caller_id) do
    now = DateTime.utc_now()
    rows = build_key_wrap_rows(household_id, scope, wraps, existing_keys, now)

    {own_rows, other_rows} =
      Enum.split_with(rows, fn row ->
        owner = get_in(existing_keys, [row.recipient_key_id, :member_id])
        is_nil(caller_id) or is_nil(owner) or owner == caller_id
      end)

    own_count = insert_own_wrap_rows(own_rows)
    other_count = insert_other_wrap_rows(other_rows)
    {:ok, own_count + other_count}
  end

  defp insert_own_wrap_rows([]), do: 0

  defp insert_own_wrap_rows(rows) do
    {count, _} =
      Repo.insert_all("personal_e2ee_key_wraps", rows,
        on_conflict: {:replace, [:ephemeral_pub_key, :nonce, :wrapped_dek, :inserted_at]},
        conflict_target: [:household_id, :scope, :recipient_key_id]
      )

    count
  end

  defp insert_other_wrap_rows([]), do: 0

  defp insert_other_wrap_rows(rows) do
    {count, _} =
      Repo.insert_all("personal_e2ee_key_wraps", rows,
        on_conflict: :nothing,
        conflict_target: [:household_id, :scope, :recipient_key_id]
      )

    count
  end

  defp build_key_wrap_rows(household_id, scope, wraps, existing, now) do
    Enum.map(wraps, fn wrap ->
      %{
        household_id: household_id,
        scope: scope,
        recipient_key_id: wrap.recipient_key_id,
        recipient_kind:
          existing |> Map.fetch!(wrap.recipient_key_id) |> Map.fetch!(:recipient_kind),
        wrap_alg: wrap.wrap_alg,
        ephemeral_pub_key: wrap.ephemeral_pub_key,
        nonce: wrap.nonce,
        wrapped_dek: wrap.wrapped_dek,
        inserted_at: now
      }
    end)
  end

  @doc "List wrapped DEKs for `household_id` (optionally filtered by `scope`, `recipient_key_id`, and/or `member_id`)."
  @spec list_key_wraps(household_id(), keyword()) :: {:ok, [map()]} | {:gone, String.t()}
  def list_key_wraps(household_id, opts \\ []) do
    scope = Keyword.get(opts, :scope)
    recipient_key_id = Keyword.get(opts, :recipient_key_id)
    member_id = Keyword.get(opts, :member_id)

    case if(is_binary(scope), do: scope_tombstone(household_id, scope), else: :live) do
      {:gone, erasure_ref} ->
        {:gone, erasure_ref}

      :live ->
        query =
          from(w in "personal_e2ee_key_wraps",
            where: w.household_id == ^household_id,
            select: %{
              scope: w.scope,
              recipient_key_id: w.recipient_key_id,
              recipient_kind: w.recipient_kind,
              wrap_alg: w.wrap_alg,
              ephemeral_pub_key: w.ephemeral_pub_key,
              nonce: w.nonce,
              wrapped_dek: w.wrapped_dek
            }
          )
          |> maybe_where(:scope, scope)
          |> maybe_where(:recipient_key_id, recipient_key_id)
          |> maybe_where_member(household_id, member_id)

        {:ok, Repo.all(query)}
    end
  end

  defp maybe_where_member(query, _household_id, nil), do: query

  defp maybe_where_member(query, household_id, member_id) when is_binary(member_id) do
    from(w in query,
      join: r in "personal_e2ee_recipient_keys",
      on: r.household_id == ^household_id and r.recipient_key_id == w.recipient_key_id,
      where: r.member_id == ^member_id
    )
  end

  @doc "Hard-delete all key wraps for a scope inside `household_id`."
  @spec delete_key_wraps(household_id(), String.t()) :: {:ok, non_neg_integer()}
  def delete_key_wraps(household_id, scope) do
    {deleted, _} =
      Repo.delete_all(
        from(w in "personal_e2ee_key_wraps",
          where: w.household_id == ^household_id and w.scope == ^scope
        )
      )

    {:ok, deleted}
  end

  @doc "Store a client-encrypted ciphertext blob inside `household_id`."
  @spec put_blob(household_id(), map()) :: {:ok, map()} | {:gone, String.t()} | {:error, term()}
  def put_blob(household_id, attrs) do
    case scope_tombstone(household_id, attrs.scope) do
      {:gone, erasure_ref} ->
        {:gone, erasure_ref}

      :live ->
        now = DateTime.utc_now()

        row = %{
          household_id: household_id,
          bytes_ref: attrs.bytes_ref,
          scope: attrs.scope,
          cipher_alg: Map.get(attrs, :cipher_alg, "aes-256-gcm-v1"),
          nonce: attrs.nonce,
          size: byte_size(attrs.ciphertext),
          ciphertext: attrs.ciphertext,
          inserted_at: now
        }

        Repo.insert_all("personal_e2ee_blobs", [row],
          on_conflict: :nothing,
          conflict_target: [:household_id, :bytes_ref, :scope]
        )

        {:ok, row}
    end
  rescue
    error -> {:error, error}
  end

  @doc "Fetch a ciphertext blob strictly within `household_id`. Returns `{:gone, erasure_ref}` on tombstone."
  @spec get_blob(household_id(), String.t(), String.t()) ::
          {:ok, map()} | {:gone, String.t()} | :not_found
  def get_blob(household_id, bytes_ref, scope) do
    query =
      from(b in "personal_e2ee_blobs",
        where:
          b.household_id == ^household_id and
            b.bytes_ref == ^bytes_ref and
            b.scope == ^scope,
        select: %{
          bytes_ref: b.bytes_ref,
          scope: b.scope,
          cipher_alg: b.cipher_alg,
          nonce: b.nonce,
          size: b.size,
          ciphertext: b.ciphertext,
          deleted_at: b.deleted_at,
          erasure_ref: b.erasure_ref
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      %{deleted_at: deleted_at, erasure_ref: ref} when not is_nil(deleted_at) -> {:gone, ref}
      blob -> {:ok, blob}
    end
  end

  @doc "Wipe ciphertext to NULL and stamp a 410 tombstone bound to `erasure_ref`."
  @spec tombstone_blob(household_id(), String.t(), String.t(), String.t()) ::
          :ok | :not_found
  def tombstone_blob(household_id, bytes_ref, scope, erasure_ref) do
    now = DateTime.utc_now()

    case Repo.update_all(
           from(b in "personal_e2ee_blobs",
             where:
               b.household_id == ^household_id and
                 b.bytes_ref == ^bytes_ref and
                 b.scope == ^scope
           ),
           set: [ciphertext: nil, storage_uri: nil, deleted_at: now, erasure_ref: erasure_ref]
         ) do
      {1, _} -> :ok
      {0, _} -> :not_found
    end
  end

  @doc "Atomically hard-delete all key wraps and tombstone all blobs for `scope` (or `:household`)."
  @spec erase_client_e2ee(household_id(), :household | {:scope, String.t()}, String.t()) ::
          {:ok, %{key_wraps_deleted: non_neg_integer(), blobs_tombstoned: non_neg_integer()}}
  def erase_client_e2ee(household_id, target, erasure_ref) do
    now = DateTime.utc_now()

    {:ok, result} =
      Repo.transaction(fn ->
        {wraps_q, blobs_q} =
          case target do
            :household ->
              {
                from(w in "personal_e2ee_key_wraps", where: w.household_id == ^household_id),
                from(b in "personal_e2ee_blobs",
                  where: b.household_id == ^household_id and is_nil(b.deleted_at)
                )
              }

            {:scope, scope} ->
              {
                from(w in "personal_e2ee_key_wraps",
                  where: w.household_id == ^household_id and w.scope == ^scope
                ),
                from(b in "personal_e2ee_blobs",
                  where:
                    b.household_id == ^household_id and b.scope == ^scope and is_nil(b.deleted_at)
                )
              }
          end

        {wraps_deleted, _} = Repo.delete_all(wraps_q)

        {blobs_tombstoned, _} =
          Repo.update_all(blobs_q,
            set: [ciphertext: nil, storage_uri: nil, deleted_at: now, erasure_ref: erasure_ref]
          )

        %{key_wraps_deleted: wraps_deleted, blobs_tombstoned: blobs_tombstoned}
      end)

    {:ok, result}
  end

  # ---------------------------------------------------------------------------
  # D19 Parent-Locked Recovery Envelopes & Recovery Requests
  # ---------------------------------------------------------------------------

  @doc "Store or update a client-locked recovery envelope and clear `recovery_envelope_deleted_at`."
  @spec put_recovery_envelope(household_id(), member_id(), map()) ::
          {:ok, map()} | {:error, term()}
  def put_recovery_envelope(household_id, member_id, attrs) do
    now = DateTime.utc_now()

    row = %{
      household_id: household_id,
      member_id: member_id,
      recovery_x25519_key_id: attrs.recovery_x25519_key_id,
      recovery_x25519_pub_key: attrs.recovery_x25519_pub_key,
      envelope_alg: Map.get(attrs, :envelope_alg, "aes-256-gcm-v1"),
      kdf_kind: attrs.kdf_kind,
      kdf_params: attrs.kdf_params,
      envelope_nonce: attrs.envelope_nonce,
      envelope_ciphertext: attrs.envelope_ciphertext,
      r5e_custodian_key_id: Map.get(attrs, :r5e_custodian_key_id),
      r5e_custodian_kms_alias: Map.get(attrs, :r5e_custodian_kms_alias),
      inserted_at: now,
      updated_at: now
    }

    Repo.transaction(fn ->
      Repo.insert_all("personal_recovery_envelopes", [row],
        on_conflict:
          {:replace,
           [
             :recovery_x25519_key_id,
             :recovery_x25519_pub_key,
             :envelope_alg,
             :kdf_kind,
             :kdf_params,
             :envelope_nonce,
             :envelope_ciphertext,
             :r5e_custodian_key_id,
             :r5e_custodian_kms_alias,
             :updated_at
           ]},
        conflict_target: [:household_id, :member_id]
      )

      Repo.update_all(
        from(m in "personal_members",
          where: m.household_id == ^household_id and m.member_id == ^member_id
        ),
        set: [recovery_envelope_deleted_at: nil, updated_at: now]
      )

      row
    end)
  rescue
    error -> {:error, error}
  end

  @doc """
  Inspect recovery envelope state for `(household_id, member_id)`:
    * `{:present, envelope}` — opaque client-locked envelope exists
    * `:absent_deleted` — previously deleted via `DELETE /v1/personal/recovery-envelope`
    * `:absent_not_enrolled` — never uploaded
  """
  @spec envelope_state(household_id(), member_id()) ::
          {:present, map()} | :absent_deleted | :absent_not_enrolled
  def envelope_state(household_id, member_id) do
    query =
      from(e in "personal_recovery_envelopes",
        where: e.household_id == ^household_id and e.member_id == ^member_id,
        select: %{
          household_id: e.household_id,
          member_id: e.member_id,
          recovery_x25519_key_id: e.recovery_x25519_key_id,
          recovery_x25519_pub_key: e.recovery_x25519_pub_key,
          envelope_alg: e.envelope_alg,
          kdf_kind: e.kdf_kind,
          kdf_params: e.kdf_params,
          envelope_nonce: e.envelope_nonce,
          envelope_ciphertext: e.envelope_ciphertext,
          r5e_custodian_key_id: e.r5e_custodian_key_id,
          updated_at: e.updated_at
        }
      )

    case Repo.one(query) do
      %{} = env ->
        {:present, env}

      nil ->
        case get_member(household_id, member_id) do
          {:ok, %{recovery_envelope_deleted_at: deleted_at}} when not is_nil(deleted_at) ->
            :absent_deleted

          _ ->
            :absent_not_enrolled
        end
    end
  end

  @doc "Hard-delete the parent's recovery envelope and stamp `recovery_envelope_deleted_at`."
  @spec delete_recovery_envelope(household_id(), member_id()) ::
          {:ok, %{deleted: boolean(), envelope_status: String.t()}}
  def delete_recovery_envelope(household_id, member_id) do
    now = DateTime.utc_now()

    {:ok, res} =
      Repo.transaction(fn ->
        {count, _} =
          Repo.delete_all(
            from(e in "personal_recovery_envelopes",
              where: e.household_id == ^household_id and e.member_id == ^member_id
            )
          )

        if count > 0 do
          Repo.update_all(
            from(m in "personal_members",
              where: m.household_id == ^household_id and m.member_id == ^member_id
            ),
            set: [recovery_envelope_deleted_at: now, updated_at: now]
          )

          %{deleted: true, envelope_status: "absent_deleted"}
        else
          %{
            deleted: false,
            envelope_status: member_absent_envelope_status(household_id, member_id)
          }
        end
      end)

    {:ok, res}
  end

  defp member_absent_envelope_status(household_id, member_id) do
    case get_member(household_id, member_id) do
      {:ok, %{recovery_envelope_deleted_at: ts}} when not is_nil(ts) -> "absent_deleted"
      _ -> "absent_not_enrolled"
    end
  end

  @doc "Disable assisted recovery on a household: purge envelopes and recovery wraps."
  @spec disable_assisted_recovery(household_id()) ::
          {:ok, %{envelopes_deleted: non_neg_integer(), wraps_deleted: non_neg_integer()}}
  def disable_assisted_recovery(household_id) do
    now = DateTime.utc_now()

    {:ok, res} =
      Repo.transaction(fn ->
        {env_count, _} =
          Repo.delete_all(
            from(e in "personal_recovery_envelopes", where: e.household_id == ^household_id)
          )

        if env_count > 0 do
          Repo.update_all(
            from(m in "personal_members",
              where: m.household_id == ^household_id and m.role in ["owner", "parent"]
            ),
            set: [recovery_envelope_deleted_at: now, updated_at: now]
          )
        end

        {wrap_count, _} =
          Repo.delete_all(
            from(w in "personal_e2ee_key_wraps",
              where:
                w.household_id == ^household_id and
                  w.recipient_kind == "parent_recovery_envelope"
            )
          )

        Repo.update_all(
          from(h in "personal_households", where: h.household_id == ^household_id),
          set: [recovery_mode: "self_only", updated_at: now]
        )

        %{envelopes_deleted: env_count, wraps_deleted: wrap_count}
      end)

    {:ok, res}
  end

  @doc "Create a pending cooling-off assisted recovery request."
  @spec create_recovery_request(map()) :: {:ok, map()} | {:error, term()}
  def create_recovery_request(attrs) do
    now = DateTime.utc_now()

    row = %{
      request_id: attrs.request_id,
      household_id: attrs.household_id,
      member_id: attrs.member_id,
      new_root_public_key: attrs.new_root_public_key,
      new_working_public_key: attrs.new_working_public_key,
      new_x25519_public_key: Map.get(attrs, :new_x25519_public_key),
      rotate_authority: Map.get(attrs, :rotate_authority, true),
      state: "pending_window",
      unlock_at: attrs.unlock_at,
      inserted_at: now
    }

    Repo.insert_all("personal_recovery_requests", [row])
    {:ok, row}
  rescue
    error -> {:error, error}
  end

  @doc "Fetch a recovery request scoped strictly to `household_id`."
  @spec get_recovery_request(household_id(), String.t()) :: {:ok, map()} | :not_found
  def get_recovery_request(household_id, request_id) do
    query =
      from(r in "personal_recovery_requests",
        where: r.household_id == ^household_id and r.request_id == ^request_id,
        select: %{
          request_id: r.request_id,
          household_id: r.household_id,
          member_id: r.member_id,
          new_root_public_key: r.new_root_public_key,
          new_working_public_key: r.new_working_public_key,
          new_x25519_public_key: r.new_x25519_public_key,
          rotate_authority: r.rotate_authority,
          state: r.state,
          unlock_at: r.unlock_at,
          cancelled_by_member: r.cancelled_by_member,
          cancelled_at: r.cancelled_at,
          roots_changed_ref: r.roots_changed_ref,
          recovery_completed_ref: r.recovery_completed_ref,
          completed_at: r.completed_at,
          inserted_at: r.inserted_at
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc "Cancel a pending recovery request."
  @spec cancel_recovery_request(household_id(), String.t(), member_id(), String.t() | nil) ::
          {:ok, map()} | {:error, atom()}
  def cancel_recovery_request(household_id, request_id, cancelled_by, recovery_completed_ref) do
    now = DateTime.utc_now()

    case Repo.update_all(
           from(r in "personal_recovery_requests",
             where:
               r.household_id == ^household_id and
                 r.request_id == ^request_id and
                 r.state == "pending_window"
           ),
           set: [
             state: "cancelled",
             cancelled_by_member: cancelled_by,
             cancelled_at: now,
             recovery_completed_ref: recovery_completed_ref
           ]
         ) do
      {1, _} -> get_recovery_request(household_id, request_id)
      {0, _} -> {:error, :not_pending}
    end
  end

  @doc "Mark a recovery request completed with optional `roots_changed_ref` and `recovery_completed_ref`."
  @spec mark_recovery_completed(household_id(), String.t(), String.t() | nil, String.t() | nil) ::
          {:ok, map()} | {:error, atom()}
  def mark_recovery_completed(household_id, request_id, roots_changed_ref, recovery_completed_ref) do
    now = DateTime.utc_now()

    case Repo.update_all(
           from(r in "personal_recovery_requests",
             where:
               r.household_id == ^household_id and
                 r.request_id == ^request_id and
                 r.state == "pending_window"
           ),
           set: [
             state: "completed",
             roots_changed_ref: roots_changed_ref,
             recovery_completed_ref: recovery_completed_ref,
             completed_at: now
           ]
         ) do
      {1, _} -> get_recovery_request(household_id, request_id)
      {0, _} -> {:error, :not_pending}
    end
  end

  # ---------------------------------------------------------------------------
  # Two-Parent (`threshold: 2`) Erasure Proposals
  # ---------------------------------------------------------------------------

  @doc "Create a pending two-parent co-sign erasure proposal."
  @spec create_erasure_proposal(map()) :: {:ok, map()} | {:error, term()}
  def create_erasure_proposal(attrs) do
    now = DateTime.utc_now()

    row = %{
      proposal_id: attrs.proposal_id,
      household_id: attrs.household_id,
      scope: attrs.scope,
      target_id: attrs.target_id,
      erasure_method: attrs.erasure_method,
      request_digest: attrs.request_digest,
      erasure_request_ref: Map.get(attrs, :erasure_request_ref),
      proposer_member_id: attrs.proposer_member_id,
      proposer_key_id: attrs.proposer_key_id,
      proposer_root_key_id: attrs.proposer_root_key_id,
      state: "pending_cosign",
      expires_at: attrs.expires_at,
      inserted_at: now,
      updated_at: now
    }

    Repo.insert_all("personal_erasure_proposals", [row])
    {:ok, row}
  rescue
    error -> {:error, error}
  end

  @doc "Fetch an erasure proposal scoped strictly to `household_id`."
  @spec get_erasure_proposal(household_id(), String.t()) :: {:ok, map()} | :not_found
  def get_erasure_proposal(household_id, proposal_id) do
    query =
      from(p in "personal_erasure_proposals",
        where: p.household_id == ^household_id and p.proposal_id == ^proposal_id,
        select: %{
          proposal_id: p.proposal_id,
          household_id: p.household_id,
          scope: p.scope,
          target_id: p.target_id,
          erasure_method: p.erasure_method,
          request_digest: p.request_digest,
          proposer_member_id: p.proposer_member_id,
          proposer_key_id: p.proposer_key_id,
          proposer_root_key_id: p.proposer_root_key_id,
          approver_member_id: p.approver_member_id,
          approver_key_id: p.approver_key_id,
          approver_root_key_id: p.approver_root_key_id,
          co_sign_ref: p.co_sign_ref,
          state: p.state,
          expires_at: p.expires_at,
          executed_erasure_ref: p.executed_erasure_ref
        }
      )

    case Repo.one(query) do
      nil -> :not_found
      row -> {:ok, row}
    end
  end

  @doc "Approve a two-parent erasure proposal, enforcing distinct member, working key, and root key."
  @spec approve_erasure_proposal(household_id(), String.t(), map()) ::
          {:ok, map()} | {:error, atom()}
  def approve_erasure_proposal(household_id, proposal_id, approval_attrs) do
    now = DateTime.utc_now()

    with {:ok, proposal} <- fetch_pending_proposal(household_id, proposal_id),
         :ok <- validate_proposal_approval(proposal, approval_attrs, now) do
      persist_proposal_approval(household_id, proposal_id, approval_attrs, now)
    end
  rescue
    _error -> {:error, :self_approval_forbidden}
  end

  defp fetch_pending_proposal(household_id, proposal_id) do
    case get_erasure_proposal(household_id, proposal_id) do
      :not_found -> {:error, :not_found}
      {:ok, %{state: "pending_cosign"} = proposal} -> {:ok, proposal}
      {:ok, _} -> {:error, :proposal_not_pending}
    end
  end

  defp validate_proposal_approval(proposal, approval_attrs, now) do
    cond do
      DateTime.compare(proposal.expires_at, now) != :gt ->
        {:error, :proposal_expired}

      same_cosigner?(proposal, approval_attrs) ->
        {:error, :self_approval_forbidden}

      digest_mismatch?(proposal, approval_attrs) ->
        {:error, :digest_mismatch}

      true ->
        :ok
    end
  end

  defp same_cosigner?(proposal, attrs) do
    attrs.approver_member_id == proposal.proposer_member_id or
      attrs.approver_key_id == proposal.proposer_key_id or
      attrs.approver_root_key_id == proposal.proposer_root_key_id
  end

  defp digest_mismatch?(proposal, attrs) do
    is_binary(attrs[:request_digest]) and attrs[:request_digest] != proposal.request_digest
  end

  defp persist_proposal_approval(household_id, proposal_id, approval_attrs, now) do
    next_state =
      if Map.get(approval_attrs, :decision, "approve") == "deny",
        do: "cancelled",
        else: "approved"

    {count, _} =
      Repo.update_all(
        from(p in "personal_erasure_proposals",
          where:
            p.household_id == ^household_id and
              p.proposal_id == ^proposal_id and
              p.state == "pending_cosign"
        ),
        set: [
          approver_member_id: approval_attrs.approver_member_id,
          approver_key_id: approval_attrs.approver_key_id,
          approver_root_key_id: approval_attrs.approver_root_key_id,
          co_sign_ref: approval_attrs.co_sign_ref,
          state: next_state,
          updated_at: now
        ]
      )

    if count == 1,
      do: get_erasure_proposal(household_id, proposal_id),
      else: {:error, :proposal_not_pending}
  end

  @doc "Verify that `co_sign_ref` refers to an unexpired approved proposal for `(household_id, scope, target_id)`."
  @spec approved_cosign?(household_id(), String.t(), String.t(), String.t() | nil) :: boolean()
  def approved_cosign?(_household_id, _scope, _target_id, nil), do: false

  def approved_cosign?(household_id, scope, target_id, co_sign_ref) when is_binary(co_sign_ref) do
    now = DateTime.utc_now()

    query =
      from(p in "personal_erasure_proposals",
        where:
          p.household_id == ^household_id and
            p.scope == ^scope and
            p.target_id == ^target_id and
            p.co_sign_ref == ^co_sign_ref and
            p.state == "approved" and
            p.expires_at > ^now and
            p.approver_member_id != p.proposer_member_id and
            p.approver_key_id != p.proposer_key_id and
            p.approver_root_key_id != p.proposer_root_key_id,
        limit: 1,
        select: p.proposal_id
      )

    not is_nil(Repo.one(query))
  end

  @doc """
  Verify that `co_sign_ref` refers to a distinct-parent co-signed proposal for
  `(household_id, scope, target_id)` during evidence admission. Accepts both
  unexpired `"approved"` proposals (pre-execution) and `"executed"` proposals
  whose erasure was already performed under this exact `(co_sign_ref, scope,
  target_id)` so post-erasure `PersonalErasure` admission never conflicts with
  `mark_proposal_executed/3`.
  """
  @spec valid_cosign_for_admission?(
          household_id(),
          String.t(),
          String.t(),
          String.t() | nil,
          String.t() | nil
        ) :: boolean()
  def valid_cosign_for_admission?(_household_id, _scope, _target_id, nil, _record_ref), do: false

  def valid_cosign_for_admission?(household_id, scope, target_id, co_sign_ref, record_ref)
      when is_binary(co_sign_ref) do
    case fetch_admission_cosign(household_id, scope, target_id, co_sign_ref, DateTime.utc_now()) do
      %{state: "approved"} ->
        true

      %{state: "executed", executed_erasure_ref: exec_ref} ->
        matching_executed_ref?(exec_ref, record_ref)

      nil ->
        false
    end
  end

  defp fetch_admission_cosign(household_id, scope, target_id, co_sign_ref, now) do
    from(p in "personal_erasure_proposals",
      where: p.household_id == ^household_id and p.scope == ^scope and p.target_id == ^target_id,
      where: p.co_sign_ref == ^co_sign_ref,
      where:
        p.approver_member_id != p.proposer_member_id and
          p.approver_key_id != p.proposer_key_id and
          p.approver_root_key_id != p.proposer_root_key_id,
      where: (p.state == "approved" and p.expires_at > ^now) or p.state == "executed",
      limit: 1,
      select: %{state: p.state, executed_erasure_ref: p.executed_erasure_ref}
    )
    |> Repo.one()
  end

  defp matching_executed_ref?(exec_ref, record_ref) do
    is_nil(record_ref) or is_nil(exec_ref) or exec_ref == record_ref
  end

  @doc "Mark an approved proposal executed after erasure succeeds (strict state-transition guard)."
  @spec mark_proposal_executed(household_id(), String.t(), String.t()) ::
          {:ok, :executed} | {:error, :proposal_not_approved}
  def mark_proposal_executed(household_id, co_sign_ref, erasure_ref) do
    {count, _} =
      Repo.update_all(
        from(p in "personal_erasure_proposals",
          where:
            p.household_id == ^household_id and
              p.co_sign_ref == ^co_sign_ref and
              p.state == "approved"
        ),
        set: [
          state: "executed",
          executed_erasure_ref: erasure_ref,
          updated_at: DateTime.utc_now()
        ]
      )

    if count == 1, do: {:ok, :executed}, else: {:error, :proposal_not_approved}
  end

  defp maybe_where(query, _field, nil), do: query
  defp maybe_where(query, :scope, value), do: from(q in query, where: q.scope == ^value)

  defp maybe_where(query, :recipient_key_id, value),
    do: from(q in query, where: q.recipient_key_id == ^value)
end
