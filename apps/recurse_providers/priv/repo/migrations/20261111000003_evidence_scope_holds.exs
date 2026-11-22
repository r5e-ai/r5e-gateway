defmodule Recurse.Providers.Repo.Migrations.EvidenceScopeHolds do
  @moduledoc """
  Which content scopes are under a hold.

  A hold placed on a whole scope, such as a session, must also cover
  content recorded under that scope afterwards. This table is what the
  store consults when content arrives: for every hold in force on the
  content's scope, the content is given one more lock, under the hold.
  A released hold keeps its row with the time, so the history of what
  was held is not lost.
  """

  use Ecto.Migration

  def change do
    create table(:evidence_scope_holds, primary_key: false) do
      add(:scope, :text, primary_key: true)
      add(:hold, :text, primary_key: true)
      add(:placed_at, :utc_datetime_usec, null: false, default: fragment("now()"))
      add(:released_at, :utc_datetime_usec)
    end

    create(index(:evidence_scope_holds, [:hold]))
  end
end
