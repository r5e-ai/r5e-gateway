defmodule Recurse.Providers.Repo.Migrations.EvidenceIssuerAuthority do
  @moduledoc """
  Which authority records stand behind a key that signs evidence here
  without being the gateway's own.

  A workload signs its own records under a badge. When those records are
  exported, the bundle has to carry the badge, and any record that later
  took the badge back, or a reader cannot establish the workload's
  standing. This table is how an export finds them: for each signing
  key, the references of its badge and of every revocation of it.
  """

  use Ecto.Migration

  def change do
    create table(:evidence_issuer_authority, primary_key: false) do
      add(:issuer, :text, primary_key: true)
      add(:ref, :text, primary_key: true)
      add(:noted_at, :utc_datetime_usec, null: false, default: fragment("now()"))
    end
  end
end
