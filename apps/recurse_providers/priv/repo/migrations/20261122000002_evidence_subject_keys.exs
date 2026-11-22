defmodule Recurse.Providers.Repo.Migrations.EvidenceSubjectKeys do
  @moduledoc """
  A session's key can be locked by the key of whoever the session
  belongs to, instead of by the key service directly.

  `under` names the row whose key locks this one. It is empty for a key
  the key service locks. With it, everything one person's sessions
  recorded is disposed of together, and the key service holds one key
  per person, not one per session.

  `on_behalf_of` on a record is who it says it was made for, kept as a
  column so that every session recorded for a person can be found when
  that person is disposed of.
  """

  use Ecto.Migration

  def change do
    alter table(:evidence_content_keys) do
      add(:under, :text)
    end

    create(index(:evidence_content_keys, [:under], where: "under IS NOT NULL"))

    alter table(:evidence_records) do
      add(:on_behalf_of, :text)
    end

    create(index(:evidence_records, [:on_behalf_of], where: "on_behalf_of IS NOT NULL"))
  end
end
