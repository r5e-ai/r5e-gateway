defmodule Recurse.Providers.Repo.Migrations.EvidenceRecordReasonLabels do
  @moduledoc """
  Records already held are labelled again, so that those made before a
  decision's reason became something to search and count by have it.
  Labelling is derived from the records and adds only what is missing.
  """

  use Ecto.Migration
  import Ecto.Query

  alias Recurse.Provenance.{Envelope, Evidence}

  def up do
    label_existing(nil)
  end

  def down, do: :ok

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
