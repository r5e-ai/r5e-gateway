defmodule Recurse.Providers.Repo.Migrations.PersonalHouseholdsE2eeAndRecovery do
  @moduledoc """
  Additive Postgres tables for opt-in `personal.r5e.io/v1` households,
  bilateral QR child pairing, mutable Phase-2 `client-e2ee` key-wraps and
  ciphertext blobs (with 410 tombstones), parent-locked D19 recovery envelopes,
  and two-parent (`threshold: 2`) co-sign erasure proposals.

  Makes zero alterations to immutable `evidence_records`, `evidence_blobs`,
  `evidence_keys`, or their append-only database triggers.
  """

  use Ecto.Migration

  def up do
    execute("""
    CREATE TABLE personal_households (
      household_id          TEXT PRIMARY KEY
                            CHECK (household_id ~ '^hh_[a-f0-9]{12,64}$'),
      tenant_id             TEXT NOT NULL,
      profile_mode          TEXT NOT NULL DEFAULT 'family'
                            CHECK (profile_mode IN ('family', 'solo')),
      custody_mode          TEXT NOT NULL DEFAULT 'client-e2ee'
                            CHECK (custody_mode IN ('client-e2ee', 'gateway-managed')),
      recovery_mode         TEXT NOT NULL DEFAULT 'self_only'
                            CHECK (recovery_mode IN ('self_only', 'r5e_assisted')),
      threshold             INTEGER NOT NULL DEFAULT 1 CHECK (threshold >= 1),
      active_terms_ref      TEXT,
      active_profile_ref    TEXT,
      quiet_hours_tz        TEXT,
      quiet_hours_start_min INTEGER CHECK (quiet_hours_start_min BETWEEN 0 AND 1439),
      quiet_hours_end_min   INTEGER CHECK (quiet_hours_end_min BETWEEN 0 AND 1439),
      settings              JSONB NOT NULL DEFAULT '{}'::jsonb,
      inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """)

    execute("CREATE INDEX personal_households_tenant_idx ON personal_households (tenant_id)")

    execute("""
    CREATE TABLE personal_members (
      household_id                 TEXT NOT NULL
                                   REFERENCES personal_households(household_id) ON DELETE RESTRICT,
      member_id                    TEXT NOT NULL CHECK (member_id ~ '^mem_[a-f0-9]{12,64}$'),
      role                         TEXT NOT NULL CHECK (role IN ('owner', 'parent', 'child')),
      age_band                     TEXT NOT NULL
                                   CHECK (age_band IN ('under-8', '8-12', '13-15', '16-17', 'adult')),
      auth_subject                 TEXT,
      root_key_id                  TEXT,
      working_key_id               TEXT,
      active_guardrail_ref         TEXT,
      teen_confidentiality         TEXT NOT NULL DEFAULT 'teen-private-crisis'
                                   CHECK (teen_confidentiality IN ('standard', 'teen-private-crisis')),
      recovery_envelope_deleted_at TIMESTAMPTZ,
      revoked_at                   TIMESTAMPTZ,
      inserted_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (household_id, member_id)
    )
    """)

    execute("""
    CREATE UNIQUE INDEX personal_members_household_auth_subject_idx
      ON personal_members (household_id, auth_subject)
      WHERE auth_subject IS NOT NULL
    """)

    execute("""
    CREATE TABLE personal_pairing_challenges (
      challenge_id          TEXT PRIMARY KEY,
      household_id          TEXT NOT NULL
                            REFERENCES personal_households(household_id) ON DELETE CASCADE,
      child_member_id       TEXT NOT NULL,
      initiated_by_member   TEXT NOT NULL,
      pairing_code_hash     BYTEA NOT NULL UNIQUE,
      nonce                 TEXT NOT NULL,
      device_meta_ref       TEXT,
      device_public_key     JSONB,
      device_key_id         TEXT,
      state                 TEXT NOT NULL
                            CHECK (state IN ('pending', 'device_claimed', 'completed', 'cancelled', 'expired')),
      expires_at            TIMESTAMPTZ NOT NULL,
      completed_at          TIMESTAMPTZ,
      inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY (household_id, child_member_id)
        REFERENCES personal_members (household_id, member_id)
    )
    """)

    execute("""
    CREATE INDEX personal_pairing_challenges_household_state_idx
      ON personal_pairing_challenges (household_id, state, expires_at)
    """)

    execute("""
    CREATE TABLE personal_child_devices (
      device_key_id         TEXT PRIMARY KEY,
      household_id          TEXT NOT NULL
                            REFERENCES personal_households(household_id) ON DELETE CASCADE,
      child_member_id       TEXT NOT NULL,
      paired_record_ref     TEXT NOT NULL,
      badge_ref             TEXT NOT NULL,
      badge_kinds           TEXT[] NOT NULL,
      device_meta_ref       TEXT,
      revoked_at            TIMESTAMPTZ,
      revocation_ref        TEXT,
      inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY (household_id, child_member_id)
        REFERENCES personal_members (household_id, member_id)
    )
    """)

    execute("""
    CREATE INDEX personal_child_devices_household_idx
      ON personal_child_devices (household_id, child_member_id)
    """)

    execute("""
    CREATE TABLE personal_e2ee_recipient_keys (
      household_id          TEXT NOT NULL
                            REFERENCES personal_households(household_id) ON DELETE CASCADE,
      recipient_key_id      TEXT NOT NULL,
      member_id             TEXT,
      recipient_kind        TEXT NOT NULL
                            CHECK (recipient_kind IN ('parent_device', 'parent_recovery_card', 'parent_recovery_envelope')),
      algorithm             TEXT NOT NULL CHECK (algorithm = 'x25519'),
      public_key_bytes      BYTEA NOT NULL CHECK (octet_length(public_key_bytes) = 32),
      revoked_at            TIMESTAMPTZ,
      inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (household_id, recipient_key_id)
    )
    """)

    execute("""
    CREATE TABLE personal_e2ee_key_wraps (
      household_id          TEXT NOT NULL,
      scope                 TEXT NOT NULL,
      recipient_key_id      TEXT NOT NULL,
      recipient_kind        TEXT NOT NULL
                            CHECK (recipient_kind IN ('parent_device', 'parent_recovery_card', 'parent_recovery_envelope')),
      wrap_alg              TEXT NOT NULL CHECK (wrap_alg = 'x25519-hkdf-sha256-aes256gcm-v1'),
      ephemeral_pub_key     BYTEA NOT NULL CHECK (octet_length(ephemeral_pub_key) = 32),
      nonce                 BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
      wrapped_dek           BYTEA NOT NULL CHECK (octet_length(wrapped_dek) = 48),
      inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (household_id, scope, recipient_key_id),
      FOREIGN KEY (household_id, recipient_key_id)
        REFERENCES personal_e2ee_recipient_keys (household_id, recipient_key_id)
        ON DELETE CASCADE
    )
    """)

    execute("""
    CREATE INDEX personal_e2ee_key_wraps_recipient_idx
      ON personal_e2ee_key_wraps (household_id, recipient_key_id)
    """)

    execute("""
    CREATE INDEX personal_e2ee_key_wraps_scope_idx
      ON personal_e2ee_key_wraps (household_id, scope)
    """)

    execute("""
    CREATE TABLE personal_e2ee_blobs (
      household_id          TEXT NOT NULL
                            REFERENCES personal_households(household_id) ON DELETE CASCADE,
      bytes_ref             TEXT NOT NULL CHECK (bytes_ref ~ '^bytes:sha256:[0-9a-f]{64}$'),
      scope                 TEXT NOT NULL,
      cipher_alg            TEXT NOT NULL CHECK (cipher_alg = 'aes-256-gcm-v1'),
      nonce                 BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
      size                  BIGINT NOT NULL CHECK (size >= 0),
      ciphertext            BYTEA,
      storage_uri           TEXT,
      deleted_at            TIMESTAMPTZ,
      erasure_ref           TEXT,
      inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (household_id, bytes_ref, scope),
      CONSTRAINT personal_e2ee_blobs_live_or_tombstoned CHECK (
        (deleted_at IS NULL AND erasure_ref IS NULL AND ((ciphertext IS NULL) <> (storage_uri IS NULL)))
        OR
        (deleted_at IS NOT NULL AND erasure_ref IS NOT NULL AND ciphertext IS NULL AND storage_uri IS NULL)
      )
    )
    """)

    execute("""
    CREATE INDEX personal_e2ee_blobs_scope_idx
      ON personal_e2ee_blobs (household_id, scope)
      WHERE deleted_at IS NULL
    """)

    execute("""
    CREATE TABLE personal_recovery_envelopes (
      household_id                TEXT NOT NULL
                                  REFERENCES personal_households(household_id) ON DELETE CASCADE,
      member_id                   TEXT NOT NULL,
      recovery_x25519_key_id      TEXT NOT NULL
                                  CHECK (recovery_x25519_key_id ~ '^x25519:sha256:[0-9a-f]{64}$'),
      recovery_x25519_pub_key     BYTEA NOT NULL CHECK (octet_length(recovery_x25519_pub_key) = 32),
      envelope_alg                TEXT NOT NULL CHECK (envelope_alg = 'aes-256-gcm-v1'),
      kdf_kind                    TEXT NOT NULL
                                  CHECK (kdf_kind IN ('webauthn_prf_v1', 'signin_passphrase_argon2id_v1')),
      kdf_params                  JSONB NOT NULL,
      envelope_nonce              BYTEA NOT NULL CHECK (octet_length(envelope_nonce) = 12),
      envelope_ciphertext         BYTEA NOT NULL
                                  CHECK (octet_length(envelope_ciphertext) BETWEEN 32 AND 4096),
      r5e_custodian_key_id        TEXT,
      r5e_custodian_kms_alias     TEXT,
      inserted_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (household_id, member_id),
      FOREIGN KEY (household_id, member_id)
        REFERENCES personal_members (household_id, member_id)
    )
    """)

    execute("""
    CREATE TABLE personal_recovery_requests (
      request_id                  TEXT PRIMARY KEY,
      household_id                TEXT NOT NULL
                                  REFERENCES personal_households(household_id) ON DELETE CASCADE,
      member_id                   TEXT NOT NULL,
      new_root_public_key         JSONB NOT NULL,
      new_working_public_key      JSONB NOT NULL,
      new_x25519_public_key       BYTEA
                                  CHECK (new_x25519_public_key IS NULL OR octet_length(new_x25519_public_key) = 32),
      rotate_authority            BOOLEAN NOT NULL DEFAULT true,
      state                       TEXT NOT NULL
                                  CHECK (state IN ('pending_window', 'completed', 'cancelled', 'expired')),
      unlock_at                   TIMESTAMPTZ NOT NULL,
      cancelled_by_member         TEXT,
      cancelled_at                TIMESTAMPTZ,
      roots_changed_ref           TEXT,
      recovery_completed_ref      TEXT,
      completed_at                TIMESTAMPTZ,
      inserted_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
      FOREIGN KEY (household_id, member_id)
        REFERENCES personal_members (household_id, member_id)
    )
    """)

    execute("""
    CREATE INDEX personal_recovery_requests_household_state_idx
      ON personal_recovery_requests (household_id, state, unlock_at)
    """)

    execute("""
    CREATE TABLE personal_erasure_proposals (
      proposal_id                 TEXT PRIMARY KEY,
      household_id                TEXT NOT NULL
                                  REFERENCES personal_households(household_id) ON DELETE CASCADE,
      scope                       TEXT NOT NULL CHECK (scope IN ('session', 'member', 'household')),
      target_id                   TEXT NOT NULL,
      erasure_method              TEXT NOT NULL
                                  CHECK (erasure_method IN ('gateway-disposal', 'client-key-and-blob-deletion')),
      request_digest              TEXT NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
      erasure_request_ref         TEXT,
      proposer_member_id          TEXT NOT NULL,
      proposer_key_id             TEXT NOT NULL,
      proposer_root_key_id        TEXT NOT NULL,
      approver_member_id          TEXT,
      approver_key_id             TEXT,
      approver_root_key_id        TEXT,
      co_sign_ref                 TEXT,
      state                       TEXT NOT NULL
                                  CHECK (state IN ('pending_cosign', 'approved', 'executed', 'cancelled', 'expired')),
      expires_at                  TIMESTAMPTZ NOT NULL,
      executed_erasure_ref        TEXT,
      erasure_answer_ref          TEXT,
      inserted_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
      CONSTRAINT distinct_cosign_parents CHECK (
        approver_member_id IS NULL
        OR (
          approver_member_id <> proposer_member_id
          AND approver_key_id <> proposer_key_id
          AND approver_root_key_id <> proposer_root_key_id
        )
      )
    )
    """)

    execute("""
    CREATE INDEX personal_erasure_proposals_household_state_idx
      ON personal_erasure_proposals (household_id, state, expires_at)
    """)
  end

  def down do
    execute("DROP TABLE IF EXISTS personal_erasure_proposals")
    execute("DROP TABLE IF EXISTS personal_recovery_requests")
    execute("DROP TABLE IF EXISTS personal_recovery_envelopes")
    execute("DROP TABLE IF EXISTS personal_e2ee_blobs")
    execute("DROP TABLE IF EXISTS personal_e2ee_key_wraps")
    execute("DROP TABLE IF EXISTS personal_e2ee_recipient_keys")
    execute("DROP TABLE IF EXISTS personal_child_devices")
    execute("DROP TABLE IF EXISTS personal_pairing_challenges")
    execute("DROP TABLE IF EXISTS personal_members")
    execute("DROP TABLE IF EXISTS personal_households")
  end
end
