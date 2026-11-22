defmodule Recurse.Providers.Repo.Migrations.EvidenceRecordLabels do
  @moduledoc """
  An index of what records can be searched and counted by.

  A reader of many records wants to narrow them by things the record
  table has no column for: how policy decided, which tool or model was
  called. Those live in each record's body, which differs by kind.
  `evidence_record_labels` holds them as name and value per record, so a
  new thing to search by is a new name here and never a new column or a
  rule about kinds. It is derived from the records and can be rebuilt
  from them; the record table itself stays append-only and unchanged.

  Records already held are labelled here as the table is made.
  """

  use Ecto.Migration
  import Ecto.Query

  alias Recurse.Provenance.{Envelope, Evidence}

  def up do
    create table(:evidence_record_labels, primary_key: false) do
      add(:ref, :text, primary_key: true)
      add(:name, :text, primary_key: true)
      add(:value, :text, null: false)
      add(:stream, :text, null: false)
      add(:captured_at, :utc_datetime_usec, null: false)
    end

    create(index(:evidence_record_labels, [:name, :value, :captured_at]))

    flush()
    label_existing(nil)
  end

  def down, do: drop(table(:evidence_record_labels))

  # In pages by reference, so a large table is never read whole.
  defp label_existing(after_ref) do
    page =
      from(r in "evidence_records",
        order_by: r.ref,
        limit: 500,
        select: {r.ref, r.stream, r.captured_at, r.envelope}
      )

    page = if after_ref, do: where(page, [r], r.ref > ^after_ref), else: page

    case repo().all(page) do
      [] ->
        :ok

      rows ->
        labels =
          for {ref, stream, captured_at, envelope} <- rows,
              {:ok, %{evidence: evidence}} <- [Envelope.open(envelope)],
              {name, value} <- Evidence.labels(evidence) do
            %{ref: ref, name: name, value: value, stream: stream, captured_at: captured_at}
          end

        if labels != [],
          do: repo().insert_all("evidence_record_labels", labels, on_conflict: :nothing)

        {last, _, _, _} = List.last(rows)
        label_existing(last)
    end
  end
end
