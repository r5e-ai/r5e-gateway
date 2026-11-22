defmodule Recurse.Providers.Repo.Migrations.EvidenceListingIndexes do
  @moduledoc """
  Indexes for listing evidence newest first.

  A listing is ordered by capture time and then reference, and resumes
  from a record's place in that order, so the pair is indexed together.
  Listing one actor's records needs the actor beside the time, as kind
  and session already have.
  """

  use Ecto.Migration

  def change do
    create(index(:evidence_records, [:captured_at, :ref]))
    create(index(:evidence_records, [:actor, :captured_at]))
  end
end
