defmodule RecurseVerify.Chain do
  @moduledoc """
  Verification side of the r5e linear hash chain (spec/01 §2).

  Each event line of `log.jsonl` is a JSON object whose `hash` is the
  sha256 of the canonical encoding of the event without its `hash` field,
  and whose `prev` is the previous event's `hash` (genesis: 64 zero hex).
  The kernel builds events with this same module's `recompute_hash/1`
  semantics; this module is the single source of chain-verification truth.
  """

  @genesis "sha256:" <> String.duplicate("0", 64)

  def genesis, do: @genesis

  @doc "Recompute an event's hash from its canonical encoding."
  @spec recompute_hash(map()) :: String.t()
  def recompute_hash(event), do: event |> Map.delete("hash") |> RecurseVerify.Canonical.hash()

  @doc """
  Verify a full chain. Returns `{:ok, count}` or `{:error, findings}` where
  each finding is `%{seq: n, problem: string}`. Checks per event, in this
  order: `seq` is contiguous from 1, `prev` links to the predecessor, the
  hash recomputes.

  Everything here is asked of a **file somebody handed the reader**, so
  every step has an answer for an event that is not the shape a kernel
  writes: a `seq` that is not the next integer is not contiguous *and*
  does not stop the count (the next event is still expected one further
  on), and an event §8 has no encoding for has no recomputed hash rather
  than raising out of the run.
  """
  @spec verify_events([map()]) :: {:ok, non_neg_integer()} | {:error, [map()]}
  def verify_events(events) do
    {findings, _prev, _expected} =
      Enum.reduce(events, {[], @genesis, 1}, fn event, {findings, prev, expected} ->
        seq = event["seq"]
        expected_hash = RecurseVerify.Canonical.address(Map.delete(event, "hash"))

        findings =
          findings
          |> prepend_if(
            seq != expected,
            %{seq: seq, problem: "seq not contiguous (expected #{expected})"}
          )
          |> prepend_if(
            event["prev"] != prev,
            %{seq: seq, problem: "prev does not link to preceding event hash"}
          )
          |> prepend_if(
            event["hash"] != expected_hash,
            %{
              seq: seq,
              problem:
                "recorded hash #{short(event["hash"])} != recomputed #{short(expected_hash)} " <>
                  "(event bytes were altered after recording)"
            }
          )

        {findings, event["hash"], if(is_integer(seq), do: seq + 1, else: expected + 1)}
      end)

    case findings do
      [] -> {:ok, length(events)}
      _ -> {:error, Enum.reverse(findings)}
    end
  end

  @doc "Parse a JSONL log file into events. Malformed lines become findings."
  @spec read_log(Path.t()) :: {:ok, [map()]} | {:error, term()}
  def read_log(path) do
    with {:ok, contents} <- File.read(path) do
      events =
        contents
        |> String.split("\n", trim: true)
        |> Enum.map(fn line ->
          case Jason.decode(line) do
            {:ok, event} -> event
            {:error, _} -> %{"seq" => nil, "malformed" => head(line)}
          end
        end)

      {:ok, events}
    end
  end

  # spec/07 §1.1: a line that is not JSON becomes a placeholder carrying
  # its first 80 **bytes**, cut back to the last whole character so the
  # placeholder is always valid UTF-8. Bytes rather than characters
  # because the count has to mean the same thing in every language, and
  # the placeholder is inside the recomputed hash — so "80 of what" is
  # an observable rule and not a diagnostic detail.
  defp head(line) when byte_size(line) <= 80, do: line
  defp head(line), do: trim_to_character(binary_part(line, 0, 80))

  defp trim_to_character(<<>>), do: ""

  defp trim_to_character(bytes) do
    if String.valid?(bytes),
      do: bytes,
      else: trim_to_character(binary_part(bytes, 0, byte_size(bytes) - 1))
  end

  defp prepend_if(list, true, item), do: [item | list]
  defp prepend_if(list, false, _item), do: list

  defp short(nil), do: "(absent)"
  defp short("sha256:" <> hex), do: "sha256:" <> String.slice(hex, 0, 12) <> "..."
  defp short(other), do: RecurseVerify.Value.q(other)
end
