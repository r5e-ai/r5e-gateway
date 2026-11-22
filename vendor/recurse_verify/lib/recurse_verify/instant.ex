defmodule RecurseVerify.Instant do
  @moduledoc """
  Spec 011 contract §0's `Instant`: RFC 3339 with a **mandatory** offset,
  seconds required, at most nine fractional digits, no `:60`; compared as
  UTC instants after normalization.

  The rules are narrower than `DateTime.from_iso8601/1` on purpose. A
  timestamp with no offset is not an instant — it is a wall-clock reading
  whose meaning depends on where the reader stands — and a term boundary
  that means different moments to two readers is exactly the ambiguity an
  endorsement term must not carry. `:60` is refused rather than smeared:
  the kernel does not know which deployments observe leap seconds, and
  guessing would put a second of authority in or out of a term silently.

  `parse/1` returns `{:ok, DateTime.t()}` in UTC, or `{:error, reason}`;
  `compare/2` compares at the **full declared precision**, up to nine
  digits, because two instants a nanosecond apart are two instants and a
  term boundary that swallowed the difference would put a moment of
  authority in or out of a term by accident of truncation.
  """

  @re ~r/\A(?<y>\d{4})-(?<mo>\d{2})-(?<d>\d{2})[Tt](?<h>\d{2}):(?<mi>\d{2}):(?<s>\d{2})(\.(?<frac>\d{1,9}))?((?<zulu>[Zz])|(?<sign>[+-])(?<oh>\d{2}):(?<om>\d{2}))\z/

  @doc "Parse an §0 instant into a UTC `DateTime`."
  @spec parse(term()) :: {:ok, DateTime.t()} | {:error, String.t()}
  def parse(value) when is_binary(value) do
    case Regex.named_captures(@re, value) do
      nil ->
        {:error,
         "#{inspect(value)} is not an RFC 3339 instant with a mandatory offset, " <>
           "seconds, and at most nine fractional digits"}

      captures ->
        build(captures, value)
    end
  end

  def parse(value), do: {:error, "#{inspect(value)} is not an instant"}

  @doc "Whether `value` is a well-formed §0 instant."
  @spec valid?(term()) :: boolean()
  def valid?(value), do: match?({:ok, _}, parse(value))

  @doc """
  Compare two instants as UTC. `{:ok, :lt | :eq | :gt}`, or
  `{:error, :left | :right}` naming the side that would not parse —
  which is what `ordered: unparseable <field>` reports.
  """
  @spec compare(term(), term()) :: {:ok, :lt | :eq | :gt} | {:error, :left | :right}
  def compare(left, right) do
    case {parse(left), parse(right)} do
      {{:ok, a}, {:ok, b}} -> {:ok, compare_exact(a, b, left, right)}
      {{:error, _}, _} -> {:error, :left}
      {_, {:error, _}} -> {:error, :right}
    end
  end

  # `DateTime` carries microseconds, so digits 7-9 of an authored
  # fraction do not survive `parse/1`. They still have to *decide* a
  # comparison, so the tail is compared separately when the microsecond
  # parts are equal — which is the only case where it can matter.
  defp compare_exact(a, b, left, right) do
    case DateTime.compare(a, b) do
      :eq -> compare_nanos(nanos(left), nanos(right))
      other -> other
    end
  end

  defp compare_nanos(a, b) when a < b, do: :lt
  defp compare_nanos(a, b) when a > b, do: :gt
  defp compare_nanos(_a, _b), do: :eq

  # The 7th, 8th and 9th fractional digits, as an integer 0..999.
  defp nanos(value) do
    case Regex.named_captures(@re, value) do
      %{"frac" => frac} when byte_size(frac) > 6 ->
        frac |> binary_part(6, byte_size(frac) - 6) |> String.pad_trailing(3, "0") |> int()

      _ ->
        0
    end
  end

  @doc "Render a `DateTime` as an §0 instant (UTC, `Z`, second precision)."
  @spec to_string(DateTime.t()) :: String.t()
  def to_string(%DateTime{} = dt) do
    dt |> DateTime.truncate(:second) |> DateTime.to_iso8601()
  end

  defp build(c, value) do
    with :ok <- no_leap_second(c["s"], value),
         {:ok, offset} <- offset(c),
         {:ok, naive} <- naive(c) do
      {:ok, naive |> DateTime.from_naive!("Etc/UTC") |> DateTime.add(-offset, :second)}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp no_leap_second("60", value),
    do: {:error, "#{inspect(value)} carries a :60 second; §0 admits no leap second"}

  defp no_leap_second(_s, _value), do: :ok

  defp offset(%{"zulu" => z}) when z != "", do: {:ok, 0}

  defp offset(%{"sign" => sign, "oh" => oh, "om" => om}) when sign in ["+", "-"] do
    magnitude = int(oh) * 3600 + int(om) * 60

    cond do
      int(oh) > 23 -> {:error, "offset hours out of range"}
      int(om) > 59 -> {:error, "offset minutes out of range"}
      sign == "-" -> {:ok, -magnitude}
      true -> {:ok, magnitude}
    end
  end

  defp offset(_c), do: {:error, "an instant must carry an offset"}

  defp naive(c) do
    case NaiveDateTime.new(
           int(c["y"]),
           int(c["mo"]),
           int(c["d"]),
           int(c["h"]),
           int(c["mi"]),
           int(c["s"]),
           fraction(c["frac"])
         ) do
      {:ok, naive} -> {:ok, naive}
      {:error, reason} -> {:error, "not a valid date or time: #{inspect(reason)}"}
    end
  end

  # `DateTime` resolves to microseconds, so an authored fraction is kept
  # to six digits here and its 7th-9th digits are compared separately by
  # `compare/2`. The declared precision is carried on the microsecond
  # tuple so a rendered instant keeps the width it was written at.
  defp fraction(""), do: {0, 0}

  defp fraction(digits) do
    precision = min(byte_size(digits), 6)
    micro = digits |> String.slice(0, 6) |> String.pad_trailing(6, "0") |> int()
    {micro, precision}
  end

  defp int(""), do: 0
  defp int(binary), do: String.to_integer(binary)
end
