defmodule Recurse.Providers.Repo.Migrations.EvidenceFirstRecordsIndex do
  @moduledoc """
  An index over the first record of every stream, by stream name.

  Records that two parties sign, such as a badge, are each recorded on a
  stream of their own. The sealer finds the ones no seal covers yet by
  asking for first records under a stream prefix. Without this index
  that question reads the whole table; with it, it reads one entry per
  stream. `text_pattern_ops` is what lets a prefix match use the index
  whatever the database's collation.
  """

  use Ecto.Migration

  def change do
    create(
      index(:evidence_records, ["stream text_pattern_ops"],
        where: "seq = 1",
        name: :evidence_records_first_by_stream_index
      )
    )
  end
end
