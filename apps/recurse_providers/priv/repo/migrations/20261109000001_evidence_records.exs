defmodule Recurse.Providers.Repo.Migrations.EvidenceRecords do
  @moduledoc """
  Durable storage for Provenance v2 evidence (contract §5).

    * `evidence_records` — one row per signed record. The envelope is
      kept whole; the other columns are a projection of its payload for
      lookup and are never a second source of truth. `(stream, seq)` is
      unique, which is what makes two payloads at one position a
      conflict rather than an overwrite. Append-only by trigger.
    * `evidence_keys` — the public key behind every issuer, kept for
      good.
    * `evidence_blobs` — where the content behind each `bytes:`
      reference is held: definitions, profiles, epoch manifests,
      policies and payloads. With a storage provider configured the row
      holds the provider's URI and the bytes live there (S3, a
      filesystem); otherwise the bytes are held inline. Insert-only; a
      reference names exactly one byte string.

  `kind_path` is open text. New kinds arrive as definitions, not as
  schema migrations.
  """

  use Ecto.Migration

  def up do
    create table(:evidence_records, primary_key: false) do
      add(:ref, :text, primary_key: true)
      add(:stream, :text, null: false)
      add(:seq, :bigint, null: false)
      add(:kind_path, :text, null: false)
      add(:envelope, :map, null: false)
      add(:issuer, :text, null: false)
      add(:actor, :text, null: false)
      add(:session, :text)
      add(:captured_at, :utc_datetime_usec, null: false)
      add(:submission_id, :text)
      add(:submission_digest, :text)
      # Set on EpochSeal rows: the stream a seal covers and through where.
      add(:sealed_stream, :text)
      add(:sealed_from, :bigint)
      add(:sealed_through, :bigint)
      add(:inserted_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end

    create(unique_index(:evidence_records, [:stream, :seq]))

    create(
      unique_index(:evidence_records, [:stream, :submission_id],
        where: "submission_id IS NOT NULL",
        name: :evidence_records_stream_submission_index
      )
    )

    create(index(:evidence_records, [:session, :captured_at]))
    create(index(:evidence_records, [:kind_path, :captured_at]))
    create(index(:evidence_records, [:sealed_stream, :sealed_through]))

    create(constraint(:evidence_records, :evidence_records_seq_positive, check: "seq >= 1"))

    create table(:evidence_blobs, primary_key: false) do
      add(:ref, :text, primary_key: true)
      add(:size, :bigint, null: false)
      add(:uri, :text)
      add(:bytes, :binary)
      add(:inserted_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end

    create(
      constraint(:evidence_blobs, :evidence_blobs_held_in_one_place,
        check: "(uri IS NULL) <> (bytes IS NULL)"
      )
    )

    # Public keys, kept for good so a record stays checkable after the
    # key that signed it has been retired.
    create table(:evidence_keys, primary_key: false) do
      add(:key_id, :text, primary_key: true)
      add(:algorithm, :text, null: false)
      add(:public_key, :binary, null: false)
      add(:inserted_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end

    execute("""
    CREATE OR REPLACE FUNCTION enforce_append_only_evidence()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
    END;
    $$;
    """)

    for table <- ~w[evidence_records evidence_blobs evidence_keys], op <- ~w[UPDATE DELETE] do
      execute("""
      CREATE TRIGGER enforce_append_only_#{table}_#{String.downcase(op)}
        BEFORE #{op} ON #{table}
        FOR EACH ROW
        EXECUTE FUNCTION enforce_append_only_evidence();
      """)
    end
  end

  def down do
    drop(table(:evidence_keys))
    drop(table(:evidence_blobs))
    drop(table(:evidence_records))
    execute("DROP FUNCTION IF EXISTS enforce_append_only_evidence()")
  end
end
