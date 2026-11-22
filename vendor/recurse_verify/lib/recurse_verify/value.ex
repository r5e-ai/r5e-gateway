defmodule RecurseVerify.Value do
  @moduledoc """
  The two rules for a value that came out of a **bundle**: how to read
  one (`dig/2`) and how to spell one back at the reader (`q/1`). Both are
  spec/07 §2.6, normative.

  ## `q/1`

  Every finding that quotes something back at the reader — a recorded
  `generation`, a `targetKind`, a signed `submittedTarget`, a manifest
  entry that is not an object — has to put a decoded JSON value into a
  sentence. Which sentence it is is the finding's business; *how the
  value is spelled* is one rule, written down once, because a verifier in
  another language cannot reproduce a byte it cannot read a rule for.

  The rule is Elixir's `inspect/1` on the values that actually occur, and
  it is **not** `inspect/1`, because `inspect/1` is not a specification:

    * an object with more than 32 members prints its keys in the map's
      internal hash order, which is a property of the runtime rather
      than of the value;
    * a string carrying a control character prints as a bitstring
      (`<<1>>`) or with a name no other language shares (`"\\d"` for
      U+007F).

  Both are reachable only from a bundle somebody assembled, which is the
  bundle this tool exists for. So the rendering is defined here instead:

    * `null` → `nil`; `true` / `false`; an integer in decimal
    * a float as `<non-canonical number 0x…>`, the sixteen lowercase hex
      digits of its IEEE-754 binary64 big-endian bit pattern. §8 admits
      no floats, so the value is **outside the protocol's number space**
      and there is no canonical decimal for it; spelling the bits is
      lossless, is the same sixteen characters in every language, and
      says plainly what is wrong. Shortest-round-trip decimal is not:
      the digits agree everywhere, the exponent formatting does not
    * a string in double quotes, escaping `\\` and `"`, the nine named
      C0 escapes, every other character below U+0020 and U+007F as
      `\\x{<lowercase hex, no leading zeros>}`, and everything else raw
      UTF-8
    * a list as `[a, b]`, an object as `%{"k" => v}` with **keys sorted
      by UTF-8 byte order**, `[]` and `%{}` when empty
  """

  @named %{
    0x00 => "\\0",
    0x07 => "\\a",
    0x08 => "\\b",
    0x09 => "\\t",
    0x0A => "\\n",
    0x0B => "\\v",
    0x0C => "\\f",
    0x0D => "\\r",
    0x1B => "\\e"
  }

  @doc """
  Read a path out of a decoded value: the value at `keys`, or `nil` the
  moment the walk is standing on something that is not an object.

  A bundle is a file somebody handed the reader, so `payload.actor.id` is
  a question that has an answer even when `actor` is a string — and the
  answer is "nothing recorded", not a crash. Every `payload["…"]["…"]`
  in this codebase goes through here for that reason.
  """
  @spec dig(term(), [String.t()]) :: term()
  def dig(value, []), do: value
  def dig(value, [key | rest]) when is_map(value), do: dig(Map.get(value, key), rest)
  def dig(_value, _keys), do: nil

  @doc """
  A bundle-supplied value **interpolated into a sentence**: a string as
  itself, `null` as nothing at all, an integer in decimal, and anything
  else spelled by `q/1`.

  It is the other half of §2.6, and it exists because half the report's
  sentences read better with the value bare — `expired bytes:sha256:…`,
  `at seq 12` — while still having to answer for a bundle that put a
  map where the chain wants an address. `null` renders as an empty span
  on purpose: the sentence around it already says what is missing, and
  `at seq nil` reads worse than `at seq `.
  """
  @spec text(term()) :: String.t()
  def text(nil), do: ""
  def text(value) when is_binary(value), do: value
  def text(value) when is_integer(value), do: Integer.to_string(value)
  def text(value), do: q(value)

  @doc "Render a decoded JSON value as spec/07 §2.6 spells it."
  @spec q(term()) :: String.t()
  def q(nil), do: "nil"
  def q(true), do: "true"
  def q(false), do: "false"
  def q(value) when is_integer(value), do: Integer.to_string(value)

  def q(value) when is_float(value) do
    <<bits::binary-size(8)>> = <<value::big-float-64>>
    "<non-canonical number 0x" <> Base.encode16(bits, case: :lower) <> ">"
  end

  def q(value) when is_binary(value), do: IO.iodata_to_binary([?", escape(value), ?"])

  def q(value) when is_list(value),
    do: IO.iodata_to_binary(["[", value |> Enum.map(&q/1) |> Enum.intersperse(", "), "]"])

  def q(value) when is_map(value) do
    members =
      value
      |> Enum.map(fn {k, v} -> {to_key(k), v} end)
      |> Enum.sort_by(fn {k, _v} -> k end, :asc)
      |> Enum.map(fn {k, v} -> [q(k), " => ", q(v)] end)
      |> Enum.intersperse(", ")

    IO.iodata_to_binary(["%{", members, "}"])
  end

  # Nothing else can come out of a JSON decoder; an atom key would come
  # from this codebase's own maps and is rendered as its text.
  def q(value) when is_atom(value), do: q(Atom.to_string(value))

  defp to_key(k) when is_binary(k), do: k
  defp to_key(k) when is_atom(k), do: Atom.to_string(k)
  defp to_key(k), do: q(k)

  defp escape(binary), do: for(<<codepoint::utf8 <- binary>>, do: escaped(codepoint))

  defp escaped(?"), do: "\\\""
  defp escaped(?\\), do: "\\\\"

  defp escaped(codepoint) when codepoint < 0x20 or codepoint == 0x7F do
    case @named[codepoint] do
      nil -> "\\x{" <> String.downcase(Integer.to_string(codepoint, 16)) <> "}"
      named -> named
    end
  end

  defp escaped(codepoint), do: <<codepoint::utf8>>
end
