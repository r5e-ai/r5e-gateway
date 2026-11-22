defmodule Recurse.Providers.Repo.Migrations.EvidenceContentEncryption do
  @moduledoc """
  Content is encrypted once, and each session holds its own lock on it.

  `evidence_blobs` gains a `copy` column and is keyed by reference and
  copy. A row with an empty copy name is held as it is: the profile,
  definitions and seal manifests, which are structure and hold nothing
  private. Any other row is content encrypted under a random key of its
  own. There is normally one such row per reference; a second appears
  only if the content is recorded again after every lock on the first
  was lost.

  `evidence_content_locks` holds that key once per scope (session) that
  refers to the content, locked under the scope's key.

  `evidence_content_keys` holds each scope's key, locked by the
  customer's key service. Unlike the evidence tables it is not
  append-only: destroying a key is the one change this design exists to
  allow. A destroyed key keeps its row, with the time and the reason, so
  that content that was disposed of can be told apart from content that
  was never held.

  Backups: a backup of the keys table taken before a key was destroyed
  still holds the locked key. Disposal is complete once such backups
  have expired, or at once if the key-service key that locked it is
  retired.
  """

  use Ecto.Migration

  def up do
    alter table(:evidence_blobs) do
      add(:copy, :text, null: false, default: "")
    end

    execute("ALTER TABLE evidence_blobs DROP CONSTRAINT evidence_blobs_pkey")
    execute("ALTER TABLE evidence_blobs ADD PRIMARY KEY (ref, copy)")

    create table(:evidence_content_locks, primary_key: false) do
      add(:ref, :text, primary_key: true)
      add(:scope, :text, primary_key: true)
      add(:copy, :text, null: false)
      add(:locked, :binary, null: false)
      add(:inserted_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end

    create(index(:evidence_content_locks, [:scope]))

    create table(:evidence_content_keys, primary_key: false) do
      add(:scope, :text, primary_key: true)
      add(:wrapped, :binary)
      add(:key_service, :text, null: false)
      add(:created_at, :utc_datetime_usec, null: false, default: fragment("now()"))
      add(:destroyed_at, :utc_datetime_usec)
      add(:destroyed_reason, :text)
    end

    create(
      constraint(:evidence_content_keys, :evidence_content_keys_held_or_destroyed,
        check: "(wrapped IS NULL) = (destroyed_at IS NOT NULL)"
      )
    )
  end

  def down do
    drop(table(:evidence_content_keys))
    drop(table(:evidence_content_locks))
    execute("ALTER TABLE evidence_blobs DROP CONSTRAINT evidence_blobs_pkey")
    execute("ALTER TABLE evidence_blobs ADD PRIMARY KEY (ref)")

    alter table(:evidence_blobs) do
      remove(:copy)
    end
  end
end
