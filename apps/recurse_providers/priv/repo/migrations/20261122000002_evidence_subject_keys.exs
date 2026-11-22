defmodule Recurse.Providers.Repo.Migrations.EvidenceSubjectKeys do
  @moduledoc """
  A session's key can be locked by the key of whoever the session
  belongs to, instead of by the key service directly.

  `under` names the row whose key locks this one. It is empty for a key
  the key service locks. With it, everything one person's sessions
  recorded can be made unreadable by destroying one key, and the key
  service is asked once per person, not once per session.
  """

  use Ecto.Migration

  def change do
    alter table(:evidence_content_keys) do
      add(:under, :text)
    end

    create(index(:evidence_content_keys, [:under], where: "under IS NOT NULL"))
  end
end
