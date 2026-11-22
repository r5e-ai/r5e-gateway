defmodule RecurseVerify.Canonical do
  @moduledoc """
  Canonical JSON encoding — spec 011 contract §8 (KS-2), normative.

  Every hash on an r5e chain is computed over this encoding, so it must be
  deterministic across implementations: the kernel writes with this exact
  module (path dependency) and this verifier recomputes with it.

  The rules, in full. They are RFC 8785 (JCS) restricted to the values
  on which independent JCS libraries were measured to agree, so any
  conforming JCS library produces these bytes for a value this profile
  admits:

    * **Objects** — keys sorted by UTF-8 byte order; separators `,` and
      `:` only, never a space. A key may not contain a character above
      U+FFFF: without such keys, byte order and JCS's UTF-16 order are
      the same order. Duplicate keys in *raw input* are an error
      (`encode_json/1`); an Elixir map cannot carry one.
    * **Strings** — `"` → `\\"`, `\\` → `\\\\`; backspace, tab, newline,
      form feed and carriage return → `\\b`, `\\t`, `\\n`, `\\f`, `\\r`;
      every other character below U+0020 → the six-character `\\u00xx`
      form with lowercase hex; nothing else is escaped. `/` is never
      escaped (`\\/` in raw input decodes to `/`). U+007F and everything
      above is raw UTF-8.
    * **Integers** — decimal, optional `-`, no leading zeros, within
      ±(2^53 − 1). `-0` is not canonical and is an error. Floats and
      exponents are errors.
    * `true`, `false`, `null`.

  Two doors, because §8 has two halves. `encode/1` encodes a decoded
  term — what the kernel and the verifier hash. `encode_json/1` takes
  **raw JSON bytes** and canonicalizes them, which is the only door that
  can see a duplicate key, a `-0`, a `1.0` or a `\\/`: a decoder has
  already thrown those distinctions away. Its parser is strict on
  purpose; it is not a general JSON reader.
  """

  # The largest integer every JSON implementation represents exactly.
  @max_integer 9_007_199_254_740_991

  @doc """
  Encode a decoded term to its canonical JSON binary.

  Raises `ArgumentError` on a float (§8: floats are not canonical) or on
  a term with no JSON form. Callers that hold untrusted input should go
  through `encode_json/1` instead, which reports rather than raises.
  """
  @spec encode(term()) :: binary()
  def encode(term), do: IO.iodata_to_binary(enc(term))

  @doc "sha256 of the canonical encoding, as a `sha256:<hex>` address."
  @spec hash(term()) :: String.t()
  def hash(term), do: hash_bytes(encode(term))

  @doc """
  `hash/1` for a value that came out of a **bundle**: the address, or
  `nil` when §8 has no encoding for the value.

  A float is the only such value a JSON decoder can produce, and §8
  admits none — so a payload carrying one has no canonical address, and
  every check that wanted one has to say so rather than raise. A verifier
  that stops on a bundle has told the reader nothing about it, which is
  the one outcome spec/07 §11 forbids. `hash/1` keeps raising, because
  the kernel hashes values it wrote itself and a float there is a bug.
  """
  @spec address(term()) :: String.t() | nil
  def address(term) do
    hash(term)
  rescue
    ArgumentError -> nil
  end

  @doc "sha256 of raw bytes, as a `sha256:<hex>` address."
  @spec hash_bytes(binary()) :: String.t()
  def hash_bytes(bytes) do
    "sha256:" <> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  end

  @doc """
  Canonicalize **raw JSON bytes**: `{:ok, canonical_bytes}`, or
  `{:error, reason}` for anything §8 forbids — a duplicate key, `-0`, a
  float, an exponent, a malformed escape, trailing content.
  """
  @spec encode_json(binary()) :: {:ok, binary()} | {:error, String.t()}
  def encode_json(bytes) when is_binary(bytes) do
    case decode_json(bytes) do
      {:ok, term} -> {:ok, encode(term)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Parse raw JSON bytes under §8's input rules — duplicate keys, `-0`,
  floats and exponents are errors. Returns the decoded term.

  **Total**: every input returns `{:ok, term}` or `{:error, reason}` and
  nothing raises. That is load-bearing rather than tidy — this is the
  first thing `authenticate` does with bytes a stranger sent, so a parser
  that raised would turn a malformed request into a 500 with no answer
  instead of `authenticate: malformed envelope`, and the asking would
  leave no trace at all.
  """
  @spec decode_json(binary()) :: {:ok, term()} | {:error, String.t()}
  def decode_json(bytes) when is_binary(bytes) do
    with {:ok, value, rest} <- parse_value(skip_ws(bytes)) do
      case skip_ws(rest) do
        "" -> {:ok, value}
        trailing -> {:error, "trailing content after the JSON value: #{inspect(head(trailing))}"}
      end
    end
  end

  # -- encoding ----------------------------------------------------------

  defp enc(map) when is_map(map) do
    inner =
      map
      |> Enum.map(fn {k, v} -> {key_to_string(k), v} end)
      |> Enum.sort_by(fn {k, _} -> k end, :asc)
      |> Enum.map(fn {k, v} -> [string(k), ":", enc(v)] end)
      |> Enum.intersperse(",")

    ["{", inner, "}"]
  end

  defp enc(list) when is_list(list) do
    ["[", list |> Enum.map(&enc/1) |> Enum.intersperse(","), "]"]
  end

  defp enc(true), do: "true"
  defp enc(false), do: "false"
  defp enc(nil), do: "null"
  defp enc(int) when is_integer(int) and int >= -@max_integer and int <= @max_integer,
    do: Integer.to_string(int)

  defp enc(int) when is_integer(int),
    do:
      raise(
        ArgumentError,
        "canonical JSON (§8) admits integers within ±(2^53 − 1), got #{int}"
      )
  defp enc(binary) when is_binary(binary), do: string(binary)

  defp enc(float) when is_float(float),
    do: raise(ArgumentError, "canonical JSON (§8) admits no floats, got #{inspect(float)}")

  defp enc(other),
    do: raise(ArgumentError, "canonical JSON (§8) has no encoding for #{inspect(other)}")

  # §8's string rule, and nothing more: two literal escapes, the
  # six-character lowercase `\u00xx` form for C0, everything else raw.
  defp string(binary) when is_binary(binary), do: [?", escape(binary, 0, binary), ?"]

  # Copy-on-escape: a string with nothing to escape — almost all of them —
  # is emitted as the input binary itself, never rebuilt byte by byte.
  # Multibyte UTF-8 is safe under a byte scan: every continuation byte is
  # ≥ 0x80 and no byte in the escape set is.
  defp escape(<<>>, 0, original), do: original
  defp escape(<<>>, skip, original), do: binary_part(original, skip, byte_size(original) - skip)

  defp escape(<<byte, rest::binary>>, skip, original)
       when byte in [?", ?\\] or byte < 0x20 do
    at = byte_size(original) - byte_size(rest) - 1
    [binary_part(original, skip, at - skip), escaped(byte), escape(rest, at + 1, original)]
  end

  defp escape(<<_byte, rest::binary>>, skip, original), do: escape(rest, skip, original)

  defp escaped(?"), do: "\\\""
  defp escaped(?\\), do: "\\\\"
  defp escaped(?\b), do: "\\b"
  defp escaped(?\t), do: "\\t"
  defp escaped(?\n), do: "\\n"
  defp escaped(?\f), do: "\\f"
  defp escaped(?\r), do: "\\r"
  defp escaped(byte) when byte < 0x20, do: "\\u00" <> Base.encode16(<<byte>>, case: :lower)

  defp key_to_string(k) when is_binary(k) do
    if astral?(k),
      do:
        raise(
          ArgumentError,
          "canonical JSON (§8) object keys may not contain characters above U+FFFF, got #{inspect(k)}"
        ),
      else: k
  end

  defp key_to_string(k) when is_atom(k), do: key_to_string(Atom.to_string(k))


  defp key_to_string(k),
    do: raise(ArgumentError, "canonical JSON (§8) object keys must be strings, got #{inspect(k)}")

  # A character above U+FFFF is four bytes of UTF-8, and only those
  # begin with a byte of 0xF0 or more.
  defp astral?(<<>>), do: false
  defp astral?(<<byte, _rest::binary>>) when byte >= 0xF0, do: true
  defp astral?(<<_byte, rest::binary>>), do: astral?(rest)

  # -- the strict parser -------------------------------------------------

  defp skip_ws(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)
  defp skip_ws(bytes), do: bytes

  defp parse_value(<<"{", rest::binary>>), do: parse_object(skip_ws(rest), %{})
  defp parse_value(<<"[", rest::binary>>), do: parse_array(skip_ws(rest), [])
  defp parse_value(<<"true", rest::binary>>), do: {:ok, true, rest}
  defp parse_value(<<"false", rest::binary>>), do: {:ok, false, rest}
  defp parse_value(<<"null", rest::binary>>), do: {:ok, nil, rest}
  defp parse_value(<<"\"", rest::binary>>), do: parse_string(rest, [])

  defp parse_value(<<c, _::binary>> = bytes) when c == ?- or (c >= ?0 and c <= ?9),
    do: parse_number(bytes)

  defp parse_value(<<>>), do: {:error, "unexpected end of input"}
  defp parse_value(bytes), do: {:error, "unexpected input at #{inspect(head(bytes))}"}

  # `}` is admissible here only on the *first* pass, which is the empty
  # object. Every later pass arrives after a comma, and a comma promises
  # another member: `{"a":1,}` is refused rather than read as `{"a":1}`.
  defp parse_object(<<"}", rest::binary>>, acc) when map_size(acc) == 0, do: {:ok, acc, rest}

  defp parse_object(<<"\"", rest::binary>>, acc) do
    with {:ok, key, rest} <- parse_string(rest, []),
         :ok <- admissible_key(key),
         :ok <- fresh_key(acc, key),
         {:ok, rest} <- expect(skip_ws(rest), ":"),
         {:ok, value, rest} <- parse_value(skip_ws(rest)) do
      acc = Map.put(acc, key, value)

      case skip_ws(rest) do
        <<",", rest::binary>> -> parse_object(skip_ws(rest), acc)
        <<"}", rest::binary>> -> {:ok, acc, rest}
        other -> {:error, "expected \",\" or \"}\" in object at #{inspect(head(other))}"}
      end
    end
  end

  defp parse_object(<<"}", _rest::binary>>, _acc),
    do: {:error, "a trailing comma before \"}\"; a comma promises another member"}

  defp parse_object(bytes, _acc),
    do: {:error, "expected an object key at #{inspect(head(bytes))}"}

  defp admissible_key(key) do
    if astral?(key),
      do: {:error, "object key #{inspect(key)} contains a character above U+FFFF (§8)"},
      else: :ok
  end

  defp fresh_key(acc, key) do
    if Map.has_key?(acc, key),
      do: {:error, "duplicate object key #{inspect(key)} (§8: duplicate keys in raw input)"},
      else: :ok
  end

  # Same rule as the object's: the empty array only, never a trailing comma.
  defp parse_array(<<"]", rest::binary>>, []), do: {:ok, [], rest}

  defp parse_array(<<"]", _rest::binary>>, _acc),
    do: {:error, "a trailing comma before \"]\"; a comma promises another element"}

  defp parse_array(bytes, acc) do
    with {:ok, value, rest} <- parse_value(bytes) do
      case skip_ws(rest) do
        <<",", rest::binary>> -> parse_array(skip_ws(rest), [value | acc])
        <<"]", rest::binary>> -> {:ok, Enum.reverse([value | acc]), rest}
        other -> {:error, "expected \",\" or \"]\" in array at #{inspect(head(other))}"}
      end
    end
  end

  defp expect(<<c, rest::binary>>, <<c>>), do: {:ok, rest}
  defp expect(bytes, want), do: {:error, "expected #{inspect(want)} at #{inspect(head(bytes))}"}

  defp parse_string(<<"\"", rest::binary>>, acc),
    do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp parse_string(<<"\\", rest::binary>>, acc), do: parse_escape(rest, acc)

  defp parse_string(<<c, _::binary>>, _acc) when c < 0x20,
    do: {:error, "a raw control character (0x#{Base.encode16(<<c>>)}) inside a JSON string"}

  defp parse_string(<<c::utf8, rest::binary>>, acc),
    do: parse_string(rest, [<<c::utf8>> | acc])

  defp parse_string(<<>>, _acc), do: {:error, "unterminated string"}
  defp parse_string(_bytes, _acc), do: {:error, "invalid UTF-8 inside a JSON string"}

  # `\/` is legal input and decodes to `/`; the encoder never writes it
  # back (§8: `/` is never escaped).
  defp parse_escape(<<"\"", rest::binary>>, acc), do: parse_string(rest, [?" | acc])
  defp parse_escape(<<"\\", rest::binary>>, acc), do: parse_string(rest, [?\\ | acc])
  defp parse_escape(<<"/", rest::binary>>, acc), do: parse_string(rest, [?/ | acc])
  defp parse_escape(<<"b", rest::binary>>, acc), do: parse_string(rest, [?\b | acc])
  defp parse_escape(<<"f", rest::binary>>, acc), do: parse_string(rest, [?\f | acc])
  defp parse_escape(<<"n", rest::binary>>, acc), do: parse_string(rest, [?\n | acc])
  defp parse_escape(<<"r", rest::binary>>, acc), do: parse_string(rest, [?\r | acc])
  defp parse_escape(<<"t", rest::binary>>, acc), do: parse_string(rest, [?\t | acc])

  defp parse_escape(<<"u", a, b, c, d, rest::binary>>, acc) do
    with {:ok, code} <- hex4(<<a, b, c, d>>) do
      cond do
        code in 0xD800..0xDBFF ->
          parse_surrogate(code, rest, acc)

        code in 0xDC00..0xDFFF ->
          {:error, "an unpaired low surrogate escape \\u#{<<a, b, c, d>>}"}

        true ->
          parse_string(rest, [<<code::utf8>> | acc])
      end
    end
  end

  defp parse_escape(bytes, _acc),
    do: {:error, "invalid string escape at #{inspect(head(bytes))}"}

  defp parse_surrogate(high, <<"\\u", a, b, c, d, rest::binary>>, acc) do
    with {:ok, low} <- hex4(<<a, b, c, d>>) do
      if low in 0xDC00..0xDFFF do
        code = 0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00)
        parse_string(rest, [<<code::utf8>> | acc])
      else
        {:error, "a high surrogate escape not followed by a low surrogate"}
      end
    end
  end

  defp parse_surrogate(_high, _bytes, _acc),
    do: {:error, "a high surrogate escape not followed by a low surrogate"}

  # Four hex digits, and nothing else. `Integer.parse/2` accepts a sign,
  # so `\\u-001` and `\\u+041` both parsed as numbers under the old check —
  # which is how a stranger's request reached `String.to_integer` and
  # raised out of the gate.
  defp hex4(<<a, b, c, d>> = hex) do
    if hex_digit?(a) and hex_digit?(b) and hex_digit?(c) and hex_digit?(d),
      do: {:ok, String.to_integer(hex, 16)},
      else: {:error, "invalid \\u escape #{inspect(hex)}: four hex digits are required"}
  end

  defp hex_digit?(c), do: c in ?0..?9 or c in ?a..?f or c in ?A..?F

  # §8: integers only. `-0`, a fraction and an exponent are each an error,
  # and they are told apart so the message says which rule was broken.
  defp parse_number(bytes) do
    {digits, rest} = number_span(bytes)

    cond do
      String.contains?(digits, ".") ->
        {:error, "#{digits} is a float; canonical JSON (§8) admits integers only"}

      String.contains?(digits, "e") or String.contains?(digits, "E") ->
        {:error, "#{digits} carries an exponent; canonical JSON (§8) admits integers only"}

      digits == "-0" ->
        {:error, "-0 is not canonical (§8)"}

      leading_zero?(digits) ->
        {:error, "#{digits} has a leading zero"}

      # The span is greedy over `-+.eE` and digits so a float or an
      # exponent is *seen* and named rather than truncated to its integer
      # prefix. The cost is that the span can be something like `1-2`,
      # which is not a number at all — checked here, before it reaches
      # `String.to_integer` and raises.
      not integer?(digits) ->
        {:error, "#{inspect(digits)} is not a number"}

      true ->
        case String.to_integer(digits) do
          int when int >= -@max_integer and int <= @max_integer ->
            {:ok, int, rest}

          _ ->
            {:error, "#{digits} is outside ±(2^53 − 1); canonical JSON (§8) admits no larger integer"}
        end
    end
  end

  # The whole number-shaped span, so a float or an exponent is *seen* and
  # named rather than silently truncated to its integer prefix.
  defp number_span(bytes) do
    {rest, taken} = span(bytes, 0)
    {binary_part(bytes, 0, taken), rest}
  end

  defp span(<<c, rest::binary>>, taken)
       when c in ~c"-+.eE" or (c >= ?0 and c <= ?9),
       do: span(rest, taken + 1)

  defp span(rest, taken), do: {rest, taken}

  defp integer?(digits), do: String.match?(digits, ~r/\A-?(0|[1-9][0-9]*)\z/)

  defp leading_zero?("0"), do: false
  defp leading_zero?("-0"), do: false
  defp leading_zero?(<<"-0", _::binary>>), do: true
  defp leading_zero?(<<"0", _::binary>>), do: true
  defp leading_zero?(_), do: false

  defp head(bytes) when byte_size(bytes) > 24, do: binary_part(bytes, 0, 24) <> "..."
  defp head(bytes), do: bytes
end
