defmodule RecurseVerify.Trust do
  @moduledoc """
  Trust pins (spec 011 §9): the reader's own list of keys whose
  endorsements they are willing to treat as rooted.

  The verifier has no opinion about which keys matter. It re-derives every
  chain to its root and says what the root is; whether that root means
  anything is the reader's question, and a pin is how the reader answers
  it *for this run*. Nothing about a pin is on the chain, and nothing on
  the chain suggests one.

  The schema is **closed** — `key`, and optionally `label`, `kinds`,
  `notBefore`, `notAfter`. A trust file with a key nobody implemented is
  a reader believing something the tool does not do.

  ## Pins never follow succession

  A pin names a key, not a principal. If the pinned key has been
  succeeded, the chain rooted at its successor is **not** admitted by that
  pin, and the report says so in those words:
  `root succeeded at seq n by <key>; not trusted unless pinned`. That is
  deliberate and it is the conservative direction: succession is a claim
  made *on the chain being examined*, and letting it extend the reader's
  own trust would let the bundle enlarge the set of keys the reader
  trusts. A reader who accepts the succession pins the successor too.
  """

  @keys ~w(key label kinds notBefore notAfter)

  @doc """
  Parse `--trust key[=label]` occurrences and an optional `--trust-file`
  into the pin list. `{:ok, pins}` or `{:error, reason}` — a duplicate key
  is an error rather than a merge, because two pins for one key with
  different terms is a reader who has not decided.
  """
  @spec load([String.t()], String.t() | nil) :: {:ok, [map()]} | {:error, String.t()}
  def load(inline, file) do
    with {:ok, from_flags} <- parse_inline(inline),
         {:ok, from_file} <- read_file(file),
         pins = from_file ++ from_flags,
         :ok <- no_duplicates(pins) do
      {:ok, Enum.sort_by(pins, & &1["key"])}
    end
  end

  defp parse_inline(inline) do
    Enum.reduce_while(inline, {:ok, []}, fn value, {:ok, acc} ->
      case String.split(value, "=", parts: 2) do
        [""] -> {:halt, {:error, "--trust needs a key"}}
        [key] -> {:cont, {:ok, acc ++ [%{"key" => key}]}}
        [key, label] -> {:cont, {:ok, acc ++ [%{"key" => key, "label" => label}]}}
      end
    end)
  end

  defp read_file(nil), do: {:ok, []}

  defp read_file(path) do
    with {:ok, bytes} <- File.read(path),
         {:ok, list} when is_list(list) <- Jason.decode(bytes),
         :ok <- Enum.reduce_while(list, :ok, &check_entry/2) do
      {:ok, list}
    else
      {:error, %Jason.DecodeError{}} -> {:error, "trust file #{path} is not JSON"}
      {:ok, _other} -> {:error, "trust file #{path} must be an array of pins"}
      {:error, :enoent} -> {:error, "no trust file at #{path}"}
      {:error, reason} when is_binary(reason) -> {:error, reason}
      {:error, reason} -> {:error, "trust file #{path}: #{RecurseVerify.Value.q(reason)}"}
    end
  end

  defp check_entry(entry, _acc) when is_map(entry) do
    cond do
      not is_binary(entry["key"]) ->
        {:halt, {:error, "every trust entry needs a string \"key\""}}

      extra = Enum.find(Enum.sort(Map.keys(entry)), &(&1 not in @keys)) ->
        {:halt,
         {:error, "trust entry carries the undeclared key #{RecurseVerify.Value.q(extra)}"}}

      entry["kinds"] != nil and not is_list(entry["kinds"]) ->
        {:halt, {:error, "a trust entry's \"kinds\" must be an array of group/version/Kind"}}

      true ->
        {:cont, :ok}
    end
  end

  defp check_entry(other, _acc),
    do:
      {:halt,
       {:error, "every trust entry must be an object, got #{RecurseVerify.Value.q(other)}"}}

  defp no_duplicates(pins) do
    keys = Enum.map(pins, & &1["key"])

    case keys -- Enum.uniq(keys) do
      [] -> :ok
      [dup | _] -> {:error, "#{dup} is pinned twice; a key is pinned once or not at all"}
    end
  end

  @doc """
  Does any pin admit this chain? `{true, pin}` or `false`.

  A pin admits a chain iff the **root actor** is the pinned key, the act's
  Kind is in the pin's `kinds` (absent = any), and the citing event's `ts`
  is inside the pin's term. All three, and the root is compared by
  equality — never through succession.
  """
  @spec admits([map()], String.t() | nil, String.t(), String.t() | nil) :: {true, map()} | false
  def admits(pins, root, kind_path, ts) do
    case Enum.find(pins, &pin_admits?(&1, root, kind_path, ts)) do
      nil -> false
      pin -> {true, pin}
    end
  end

  defp pin_admits?(pin, root, kind_path, ts) do
    pin["key"] == root and covers_kind?(pin, kind_path) and in_term?(pin, ts)
  end

  defp covers_kind?(%{"kinds" => kinds}, path) when is_list(kinds), do: path in kinds
  defp covers_kind?(_pin, _path), do: true

  defp in_term?(pin, ts) do
    with {:ok, at} <- RecurseVerify.Instant.parse(ts) do
      after_start?(pin["notBefore"], at) and before_end?(pin["notAfter"], at)
    else
      _ -> pin["notBefore"] == nil and pin["notAfter"] == nil
    end
  end

  defp after_start?(nil, _at), do: true

  defp after_start?(value, at) do
    case RecurseVerify.Instant.parse(value) do
      {:ok, from} -> DateTime.compare(from, at) != :gt
      _ -> false
    end
  end

  defp before_end?(nil, _at), do: true

  defp before_end?(value, at) do
    case RecurseVerify.Instant.parse(value) do
      {:ok, to} -> DateTime.compare(at, to) != :gt
      _ -> false
    end
  end

  @doc "Is this key pinned at all, whatever its term or Kinds?"
  @spec pinned?([map()], String.t() | nil) :: boolean()
  def pinned?(pins, key), do: key != nil and Enum.any?(pins, &(&1["key"] == key))
end
