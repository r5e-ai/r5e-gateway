defmodule Recurse.Provenance.Grammar.Huml do
  @moduledoc """
  Reads a HUML v0.2.0 document into plain Elixir maps, lists and scalars.

  Definition packages are authored in HUML, so this reader is the first step
  of turning an authored package into something that can be hashed and
  compiled. It is written here, with no dependency, because the bytes a
  package hashes to depend on exactly how its text is read: the reader is
  part of the definition format, not a convenience around it.

  The reader is deliberately strict. It accepts the HUML v0.2.0 grammar
  (`:` for scalars and `::` for collections, two-space indentation, inline
  lists and dicts, `- ::` nested items, `[]` and `{}` for empty collections,
  triple-quoted multiline strings, `# ` comments) and refuses everything a
  lenient reader would silently repair: trailing spaces, duplicate keys,
  wrong indentation, and any number that is not an integer. Floats, `nan`
  and `inf` are refused because canonical JSON has no encoding for them, and
  integers are limited to the range every JSON implementation reads exactly
  (plus or minus 2^53 - 1).

  Errors are `{:error, {:huml_parse_error, line, message}}`.
  """

  @max_safe_integer 9_007_199_254_740_991

  @supported_version "v0.2.0"
  @multiline_indent 2

  defmodule State do
    @moduledoc """
    The reader's cursor: the normalised document, the byte offset reached and
    the line number used in error messages.
    """

    @type t :: %__MODULE__{data: binary(), pos: non_neg_integer(), line: pos_integer()}
    defstruct data: <<>>, pos: 0, line: 1
  end

  @doc """
  Reads the file at `path` and parses it as a HUML v0.2.0 document.
  """
  @spec decode_file(Path.t()) :: {:ok, term()} | {:error, term()}
  def decode_file(path) do
    case File.read(path) do
      {:ok, content} -> decode(content)
      {:error, reason} -> {:error, {:file_read_error, path, reason}}
    end
  end

  @doc """
  Parses a HUML v0.2.0 document held in a UTF-8 binary.

  Dicts become maps with string keys, lists become lists, and scalars become
  strings, integers, booleans or `nil`.
  """
  @spec decode(binary()) :: {:ok, term()} | {:error, term()}
  def decode(""), do: {:error, {:huml_parse_error, 1, "empty document is undefined"}}

  def decode(data) when is_binary(data) do
    if String.valid?(data) do
      normalized = String.replace(data, "\r\n", "\n")
      parse_document(%State{data: normalized, pos: 0, line: 1})
    else
      {:error, {:huml_parse_error, 1, "invalid UTF-8"}}
    end
  end

  defp parse_document(st) do
    with {:ok, st1} <- maybe_parse_header(st),
         {:ok, st2} <- skip_blank_lines(st1),
         :ok <- ensure_not_empty_or_indented(st2),
         {:ok, doc_type} <- determine_doc_type(st2),
         {:ok, result, st3} <- parse_by_type(st2, doc_type, 0),
         {:ok, st4} <- skip_blank_lines(st3) do
      if done?(st4) do
        {:ok, result}
      else
        err(st4, "unexpected content after root #{doc_type}")
      end
    end
  end

  defp maybe_parse_header(st) do
    if peek_string?(st, "%HUML") do
      st1 = advance(st, 5)
      parse_header_version(st1)
    else
      {:ok, st}
    end
  end

  defp parse_header_version(st) do
    case peek_byte(st) do
      ?\s ->
        st1 = advance(st, 1)
        {ver, st2} = take_until_chars(st1, [?\s, ?\n, ?#])

        if ver == "" or ver == @supported_version do
          consume_line(st2)
        else
          err(st2, "unsupported version '#{ver}'. expected '#{@supported_version}'")
        end

      _ ->
        consume_line(st)
    end
  end

  defp ensure_not_empty_or_indented(st) do
    cond do
      done?(st) -> err(st, "empty document is undefined")
      get_indent(st) != 0 -> err(st, "root element must not be indented")
      true -> :ok
    end
  end

  defp determine_doc_type(st) do
    cond do
      peek_string?(st, "::") -> err(st, "'::' indicator not allowed at document root")
      key_value_line?(st) -> {:ok, dict_root_type(st)}
      peek_string?(st, ":") -> err(st, "':' indicator not allowed at document root")
      true -> {:ok, non_dict_root_type(st)}
    end
  end

  defp dict_root_type(st) do
    if inline_dict_root?(st), do: :inline_dict, else: :multiline_dict
  end

  defp non_dict_root_type(st) do
    cond do
      peek_string?(st, "[]") -> :empty_list
      peek_string?(st, "{}") -> :empty_dict
      peek_byte(st) == ?- -> :multiline_list
      comma_on_line_without_colon?(st) -> :inline_list
      true -> :scalar
    end
  end

  defp parse_by_type(st, :empty_list, _indent) do
    case consume_line(advance(st, 2)) do
      {:ok, st1} -> {:ok, [], st1}
      {:error, _} = e -> e
    end
  end

  defp parse_by_type(st, :empty_dict, _indent) do
    case consume_line(advance(st, 2)) do
      {:ok, st1} -> {:ok, %{}, st1}
      {:error, _} = e -> e
    end
  end

  defp parse_by_type(st, :inline_dict, _indent), do: parse_inline_dict(st)
  defp parse_by_type(st, :inline_list, _indent), do: parse_inline_list(st)
  defp parse_by_type(st, :multiline_dict, indent), do: parse_multiline_dict(st, indent, %{})
  defp parse_by_type(st, :multiline_list, indent), do: parse_multiline_list(st, indent, [])

  defp parse_by_type(st, :scalar, indent) do
    with {:ok, val, st1} <- parse_value(st, indent),
         {:ok, st2} <- consume_line(st1) do
      {:ok, val, st2}
    end
  end

  defp parse_multiline_dict(st, indent, acc) do
    case skip_blank_lines(st) do
      {:error, _} = e ->
        e

      {:ok, st1} ->
        cur_indent = get_indent(st1)

        cond do
          done?(st1) or cur_indent < indent ->
            {:ok, acc, st1}

          cur_indent != indent ->
            err(st1, "bad indent #{cur_indent}, expected #{indent}")

          true ->
            parse_multiline_dict_entry(st1, indent, acc)
        end
    end
  end

  defp parse_multiline_dict_entry(st, indent, acc) do
    with {:ok, key, st1} <- parse_key(st),
         :ok <- check_dup_key(st1, acc, key),
         {:ok, val, st2} <- parse_dict_indicator_and_val(st1, indent) do
      parse_multiline_dict(st2, indent, Map.put(acc, key, val))
    end
  end

  defp parse_dict_indicator_and_val(st, indent) do
    cond do
      peek_string?(st, "::") ->
        parse_vector(advance(st, 2), indent + @multiline_indent)

      peek_byte(st) == ?: ->
        with {:ok, st1} <- expect_single_space(advance(st, 1), "after ':'") do
          parse_scalar_or_multiline(st1, indent)
        end

      true ->
        err(st, "expected ':' or '::' after key")
    end
  end

  defp parse_scalar_or_multiline(st, indent) do
    if peek_string?(st, ~s("""")) do
      parse_multiline_string(st, indent)
    else
      with {:ok, val, st1} <- parse_value(st, indent),
           {:ok, st2} <- consume_line(st1) do
        {:ok, val, st2}
      end
    end
  end

  defp parse_multiline_list(st, indent, acc) do
    case skip_blank_lines(st) do
      {:error, _} = e ->
        e

      {:ok, st1} ->
        cur_indent = get_indent(st1)

        cond do
          done?(st1) or cur_indent < indent ->
            {:ok, Enum.reverse(acc), st1}

          cur_indent != indent ->
            err(st1, "bad indent #{cur_indent}, expected #{indent}")

          peek_byte(st1) != ?- ->
            {:ok, Enum.reverse(acc), st1}

          true ->
            parse_multiline_list_item(st1, indent, acc)
        end
    end
  end

  defp parse_multiline_list_item(st, indent, acc) do
    with {:ok, st1} <- expect_single_space(advance(st, 1), "after '-'"),
         {:ok, val, st2} <- parse_list_item_body(st1, indent) do
      parse_multiline_list(st2, indent, [val | acc])
    end
  end

  defp parse_list_item_body(st, indent) do
    if peek_string?(st, "::") do
      parse_vector(advance(st, 2), indent + @multiline_indent)
    else
      with {:ok, val, st1} <- parse_value(st, indent),
           {:ok, st2} <- consume_line(st1) do
        {:ok, val, st2}
      end
    end
  end

  defp parse_vector(st, indent) do
    st_spaced = skip_spaces(st)

    if done?(st_spaced) or peek_byte(st_spaced) in [?\n, ?#] do
      parse_multiline_vector_after_newline(st, indent)
    else
      parse_inline_vector(st)
    end
  end

  defp parse_multiline_vector_after_newline(st, indent) do
    vector_line = st.line

    with {:ok, st1} <- consume_line(st),
         {:ok, st2} <- skip_blank_lines(st1) do
      if done?(st2) or get_indent(st2) < indent do
        {:error,
         {:huml_parse_error, vector_line, "ambiguous empty vector after '::'. Use [] or {}."}}
      else
        dispatch_multiline_vector(st2, indent)
      end
    end
  end

  defp dispatch_multiline_vector(st, indent) do
    if peek_byte(st) == ?- do
      parse_multiline_list(st, indent, [])
    else
      parse_multiline_dict(st, indent, %{})
    end
  end

  defp parse_inline_vector(st) do
    with {:ok, st1} <- expect_single_space(st, "after '::'") do
      cond do
        peek_string?(st1, "[]") ->
          parse_by_type(st1, :empty_list, 0)

        peek_string?(st1, "{}") ->
          parse_by_type(st1, :empty_dict, 0)

        has_inline_dict_colon?(st1) ->
          parse_inline_dict(st1)

        true ->
          parse_inline_list(st1)
      end
    end
  end

  defp parse_inline_dict(st), do: parse_inline_dict_loop(st, true, %{})

  defp parse_inline_dict_loop(st, is_first, acc) do
    if done?(st) or peek_byte(st) in [?\n, ?#] do
      case consume_line(st) do
        {:ok, st1} -> {:ok, acc, st1}
        {:error, _} = e -> e
      end
    else
      with {:ok, st1} <- maybe_expect_comma(st, is_first),
           {:ok, key, st2} <- parse_key(st1),
           :ok <- check_dup_key(st2, acc, key),
           {:ok, st3} <- expect_colon_and_space(st2),
           {:ok, val, st4} <- parse_value(st3, 0) do
        st5 = skip_spaces_before_comma(st4)
        parse_inline_dict_loop(st5, false, Map.put(acc, key, val))
      end
    end
  end

  defp expect_colon_and_space(st) do
    if peek_byte(st) == ?: do
      expect_single_space(advance(st, 1), "in inline dict")
    else
      err(st, "expected ':' in inline dict")
    end
  end

  defp parse_inline_list(st), do: parse_inline_list_loop(st, true, [])

  defp parse_inline_list_loop(st, is_first, acc) do
    if done?(st) or peek_byte(st) in [?\n, ?#] do
      case consume_line(st) do
        {:ok, st1} -> {:ok, Enum.reverse(acc), st1}
        {:error, _} = e -> e
      end
    else
      with {:ok, st1} <- maybe_expect_comma(st, is_first),
           {:ok, val, st2} <- parse_value(st1, 0) do
        st3 = skip_spaces_before_comma(st2)
        parse_inline_list_loop(st3, false, [val | acc])
      end
    end
  end

  defp maybe_expect_comma(st, true), do: {:ok, st}

  defp maybe_expect_comma(st, false) do
    st1 = skip_spaces(st)

    cond do
      done?(st1) or peek_byte(st1) != ?, ->
        err(st1, "expected a comma in inline collection")

      st1.pos > 0 and :binary.at(st1.data, st1.pos - 1) == ?\s ->
        err(st1, "no spaces allowed before comma")

      true ->
        expect_single_space(advance(st1, 1), "after comma")
    end
  end

  defp skip_spaces_before_comma(st) do
    if peek_byte(st) == ?\s do
      st_skipped = skip_spaces(st)
      if peek_byte(st_skipped) == ?,, do: st_skipped, else: st
    else
      st
    end
  end

  defp parse_key(st) do
    st1 = skip_spaces(st)

    case peek_byte(st1) do
      ?" ->
        parse_quoted_string(st1)

      c when c in ?a..?z or c in ?A..?Z ->
        {bare, st2} = take_bare_key(st1)
        {:ok, bare, st2}

      _ ->
        err(st1, "expected a key")
    end
  end

  defp take_bare_key(%State{data: data, pos: start} = st) do
    end_pos = scan_bare_key(data, start)
    {binary_part(data, start, end_pos - start), %{st | pos: end_pos}}
  end

  defp scan_bare_key(data, pos) when pos < byte_size(data) do
    c = :binary.at(data, pos)

    if c in ?a..?z or c in ?A..?Z or c in ?0..?9 or c in [?-, ?_] do
      scan_bare_key(data, pos + 1)
    else
      pos
    end
  end

  defp scan_bare_key(_data, pos), do: pos

  defp parse_value(st, key_indent) do
    if done?(st) do
      err(st, "unexpected end of input, expected a value")
    else
      dispatch_value_char(st, peek_byte(st), key_indent)
    end
  end

  defp dispatch_value_char(st, ?", key_indent) do
    if peek_string?(st, ~s("""")) do
      parse_multiline_string(st, key_indent)
    else
      parse_quoted_string(st)
    end
  end

  defp dispatch_value_char(st, c, _key_indent) do
    case match_keyword(st) do
      {:ok, val, st1} -> {:ok, val, st1}
      {:error, _} = e -> e
      :none -> parse_signed_or_digit(st, c)
    end
  end

  defp match_keyword(st) do
    Enum.find_value(
      [
        {"true", true},
        {"false", false},
        {"null", nil},
        {"nan", :forbidden_float},
        {"inf", :forbidden_float}
      ],
      :none,
      fn {kw, val} ->
        if keyword_token?(st, kw) do
          finalize_keyword(st, kw, val)
        else
          nil
        end
      end
    )
  end

  defp finalize_keyword(st, kw, :forbidden_float),
    do: err(st, "floating-point keyword '#{kw}' is forbidden")

  defp finalize_keyword(st, kw, val), do: {:ok, val, advance(st, byte_size(kw))}

  defp keyword_token?(%State{data: data, pos: pos} = st, kw) do
    len = byte_size(kw)

    if peek_string?(st, kw) do
      next_pos = pos + len

      if next_pos >= byte_size(data) do
        true
      else
        next_c = :binary.at(data, next_pos)
        not (next_c in ?a..?z or next_c in ?A..?Z or next_c in ?0..?9 or next_c == ?_)
      end
    else
      false
    end
  end

  defp parse_signed_or_digit(st, c) when c in [?+, ?-] do
    st1 = advance(st, 1)

    cond do
      peek_string?(st1, "inf") -> err(st, "floating-point inf is forbidden")
      peek_byte(st1) in ?0..?9 -> parse_number(st)
      true -> err(st, "invalid character after '#{<<c>>}'")
    end
  end

  defp parse_signed_or_digit(st, c) when c in ?0..?9, do: parse_number(st)

  defp parse_signed_or_digit(st, c),
    do: err(st, "unexpected character '#{<<c>>}' when parsing value")

  defp parse_quoted_string(st) do
    parse_quoted_loop(advance(st, 1), [])
  end

  defp parse_quoted_loop(st, acc) do
    if done?(st) do
      err(st, "unclosed string")
    else
      case current_codepoint(st) do
        {?", st1} -> {:ok, IO.iodata_to_binary(Enum.reverse(acc)), st1}
        {?\n, _} -> err(st, "newlines not allowed in single-line strings")
        {?\\, st1} -> parse_huml_escape(st1, acc)
        {cp_bin, st1} -> parse_quoted_loop(st1, [cp_bin | acc])
      end
    end
  end

  @huml_escapes %{
    ?" => ?",
    ?\\ => ?\\,
    ?/ => ?/,
    ?n => 0x0A,
    ?t => 0x09,
    ?r => 0x0D,
    ?b => 0x08,
    ?f => 0x0C
  }

  defp parse_huml_escape(st, acc) do
    if done?(st) do
      err(st, "incomplete escape sequence")
    else
      ch = peek_byte(st)

      case Map.fetch(@huml_escapes, ch) do
        {:ok, byte} -> parse_quoted_loop(advance(st, 1), [byte | acc])
        :error -> err(st, "invalid escape character '\\#{<<ch>>}'")
      end
    end
  end

  defp current_codepoint(%State{data: data, pos: pos} = st) do
    <<cp::utf8, _::binary>> = binary_part(data, pos, byte_size(data) - pos)
    cp_bin = <<cp::utf8>>

    case cp do
      ?" -> {?", %{st | pos: pos + 1}}
      ?\n -> {?\n, %{st | pos: pos + 1}}
      ?\\ -> {?\\, %{st | pos: pos + 1}}
      _ -> {cp_bin, %{st | pos: pos + byte_size(cp_bin)}}
    end
  end

  defp parse_multiline_string(st, key_indent) do
    with {:ok, st1} <- consume_line(advance(st, 3)) do
      collect_multiline_lines(st1, key_indent, [])
    end
  end

  defp collect_multiline_lines(st, key_indent, lines) do
    if done?(st) do
      err(st, "unclosed multiline string")
    else
      st_spaced = skip_spaces(st)
      indent = st_spaced.pos - st.pos

      if peek_string?(st_spaced, ~s("""")) do
        finish_multiline_string(st_spaced, indent, key_indent, lines)
      else
        {raw_line, st_next} = consume_line_raw(st)
        req_indent = key_indent + @multiline_indent
        stripped = strip_multiline_indent(raw_line, req_indent)
        collect_multiline_lines(st_next, key_indent, [stripped | lines])
      end
    end
  end

  defp finish_multiline_string(st, indent, key_indent, lines) do
    if indent != key_indent do
      err(
        st,
        "multiline closing delimiter must be at same indentation as the key (#{key_indent} spaces)"
      )
    else
      case consume_line(advance(st, 3)) do
        {:ok, st_done} -> {:ok, lines |> Enum.reverse() |> Enum.join("\n"), st_done}
        {:error, _} = e -> e
      end
    end
  end

  defp strip_multiline_indent(line, req_indent) do
    prefix = String.duplicate(" ", req_indent)

    if String.starts_with?(line, prefix) do
      binary_part(line, req_indent, byte_size(line) - req_indent)
    else
      line
    end
  end

  defp parse_number(%State{pos: start} = st) do
    st1 = if peek_byte(st) in [?+, ?-], do: advance(st, 1), else: st

    cond do
      peek_string?(st1, "0x") -> parse_base_int(st1, start, 16, "0x")
      peek_string?(st1, "0o") -> parse_base_int(st1, start, 8, "0o")
      peek_string?(st1, "0b") -> parse_base_int(st1, start, 2, "0b")
      true -> parse_decimal_int(st1, start)
    end
  end

  defp parse_base_int(st, start, base, prefix) do
    st1 = advance(st, byte_size(prefix))
    end_pos = scan_base_digits(st1.data, st1.pos, base)

    if end_pos == st1.pos do
      err(st1, "invalid #{prefix} number")
    else
      sign = if :binary.at(st1.data, start) == ?-, do: -1, else: 1
      digits = binary_part(st1.data, st1.pos, end_pos - st1.pos) |> String.replace("_", "")
      val = sign * String.to_integer(digits, base)
      validate_safe_int(%{st1 | pos: end_pos}, val)
    end
  end

  defp scan_base_digits(data, pos, base) when pos < byte_size(data) do
    c = :binary.at(data, pos)

    valid? =
      case base do
        2 -> c in [?0, ?1, ?_]
        8 -> c in ?0..?7 or c == ?_
        16 -> c in ?0..?9 or c in ?a..?f or c in ?A..?F or c == ?_
      end

    if valid?, do: scan_base_digits(data, pos + 1, base), else: pos
  end

  defp scan_base_digits(_data, pos, _base), do: pos

  defp parse_decimal_int(st, start) do
    {end_pos, saw_float?} = scan_decimal_token(st.data, st.pos, false)
    raw = binary_part(st.data, start, end_pos - start)
    st_end = %{st | pos: end_pos}

    if saw_float? do
      err(st_end, "floating-point number '#{raw}' is forbidden in definition packages")
    else
      cleaned = String.replace(raw, "_", "")

      case Integer.parse(cleaned) do
        {val, ""} -> validate_safe_int(st_end, val)
        _ -> err(st_end, "invalid integer '#{raw}'")
      end
    end
  end

  defp scan_decimal_token(data, pos, saw_float?) when pos < byte_size(data) do
    c = :binary.at(data, pos)

    cond do
      c in ?0..?9 or c == ?_ ->
        scan_decimal_token(data, pos + 1, saw_float?)

      c == ?. ->
        scan_decimal_token(data, pos + 1, true)

      c in [?e, ?E] ->
        next =
          if pos + 1 < byte_size(data) and :binary.at(data, pos + 1) in [?+, ?-],
            do: pos + 2,
            else: pos + 1

        scan_decimal_token(data, next, true)

      true ->
        {pos, saw_float?}
    end
  end

  defp scan_decimal_token(_data, pos, saw_float?), do: {pos, saw_float?}

  defp validate_safe_int(st, val) do
    max_int = @max_safe_integer

    if abs(val) <= max_int do
      {:ok, val, st}
    else
      err(st, "integer #{val} outside supported safe range +/-#{max_int}")
    end
  end

  # ---- Line / Whitespace / Lookahead Primitives ----

  defp done?(%State{data: data, pos: pos}), do: pos >= byte_size(data)

  defp peek_byte(%State{data: data, pos: pos}) when pos < byte_size(data),
    do: :binary.at(data, pos)

  defp peek_byte(_st), do: nil

  defp peek_string?(%State{data: data, pos: pos}, str) do
    len = byte_size(str)
    pos + len <= byte_size(data) and binary_part(data, pos, len) == str
  end

  defp advance(%State{pos: pos} = st, n), do: %{st | pos: pos + n}

  defp skip_spaces(%State{data: data, pos: pos} = st) when pos < byte_size(data) do
    if :binary.at(data, pos) == ?\s do
      skip_spaces(%{st | pos: pos + 1})
    else
      st
    end
  end

  defp skip_spaces(st), do: st

  defp line_start_pos(data, pos) when pos > 0 do
    if :binary.at(data, pos - 1) == ?\n, do: pos, else: line_start_pos(data, pos - 1)
  end

  defp line_start_pos(_data, 0), do: 0

  defp get_indent(%State{data: data, pos: pos}) do
    start = line_start_pos(data, pos)
    count_leading_spaces(data, start, 0)
  end

  defp count_leading_spaces(data, idx, count) when idx < byte_size(data) do
    if :binary.at(data, idx) == ?\s do
      count_leading_spaces(data, idx + 1, count + 1)
    else
      count
    end
  end

  defp count_leading_spaces(_data, _idx, count), do: count

  defp consume_line(%State{pos: content_start} = st) do
    st1 = skip_spaces(st)

    cond do
      done?(st1) or peek_byte(st1) == ?\n ->
        if st1.pos > content_start do
          err(st1, "trailing spaces are not allowed")
        else
          {:ok, consume_newline_if_present(st1)}
        end

      peek_byte(st1) == ?# ->
        consume_comment(st, st1, content_start)

      true ->
        err(st1, "unexpected content at end of line")
    end
  end

  defp consume_comment(orig_st, st_at_hash, content_start) do
    line_start = line_start_pos(orig_st.data, orig_st.pos)

    with :ok <- check_inline_comment_sep(orig_st, st_at_hash, content_start, line_start),
         st_after_hash = advance(st_at_hash, 1),
         :ok <- check_comment_hash_space(st_after_hash) do
      consume_comment_body(st_after_hash)
    end
  end

  defp check_inline_comment_sep(orig_st, st_at_hash, content_start, line_start) do
    if st_at_hash.pos == content_start and get_indent(orig_st) != st_at_hash.pos - line_start do
      err(st_at_hash, "a value must be separated from an inline comment by a space")
    else
      :ok
    end
  end

  defp check_comment_hash_space(st_after_hash) do
    if not done?(st_after_hash) and peek_byte(st_after_hash) not in [?\s, ?\n] do
      err(st_after_hash, "comment hash '#' must be followed by a space")
    else
      :ok
    end
  end

  defp consume_comment_body(st_after_hash) do
    {_comment, st_eol} = take_until_chars(st_after_hash, [?\n])

    if st_eol.pos > 0 and :binary.at(st_eol.data, st_eol.pos - 1) == ?\s do
      err(st_eol, "trailing spaces are not allowed")
    else
      {:ok, consume_newline_if_present(st_eol)}
    end
  end

  defp consume_newline_if_present(st) do
    if peek_byte(st) == ?\n do
      %{st | pos: st.pos + 1, line: st.line + 1}
    else
      st
    end
  end

  defp consume_line_raw(st) do
    {content, st_eol} = take_until_chars(st, [?\n])
    {content, consume_newline_if_present(st_eol)}
  end

  defp skip_blank_lines(st) do
    if done?(st) do
      {:ok, st}
    else
      skip_blank_lines_non_empty(st, skip_spaces(st))
    end
  end

  defp skip_blank_lines_non_empty(st, st_spaced) do
    cond do
      done?(st_spaced) ->
        check_trailing_spaces_at_eof(st, st_spaced)

      peek_byte(st_spaced) not in [?\n, ?#] ->
        {:ok, st_spaced}

      peek_byte(st_spaced) == ?\n and st_spaced.pos > st.pos ->
        err(st_spaced, "trailing spaces are not allowed")

      true ->
        advance_blank_or_comment_line(st)
    end
  end

  defp check_trailing_spaces_at_eof(st, st_spaced) do
    if st_spaced.pos > st.pos,
      do: err(st_spaced, "trailing spaces are not allowed"),
      else: {:ok, st_spaced}
  end

  defp advance_blank_or_comment_line(st) do
    case consume_line(st) do
      {:ok, st_next} -> skip_blank_lines(st_next)
      {:error, _} = e -> e
    end
  end

  defp expect_single_space(st, context) do
    if peek_byte(st) != ?\s do
      err(st, "expected single space #{context}")
    else
      st1 = advance(st, 1)

      if peek_byte(st1) == ?\s do
        err(st1, "expected single space #{context}, found multiple")
      else
        {:ok, st1}
      end
    end
  end

  defp take_until_chars(%State{data: data, pos: start} = st, stop_chars) do
    end_pos = scan_until_chars(data, start, stop_chars)
    {binary_part(data, start, end_pos - start), %{st | pos: end_pos}}
  end

  defp scan_until_chars(data, pos, stop_chars) when pos < byte_size(data) do
    if :binary.at(data, pos) in stop_chars do
      pos
    else
      scan_until_chars(data, pos + 1, stop_chars)
    end
  end

  defp scan_until_chars(_data, pos, _stop_chars), do: pos

  defp key_value_line?(st) do
    case parse_key(st) do
      {:ok, _k, st1} -> peek_byte(st1) == ?:
      _ -> false
    end
  end

  defp inline_dict_root?(%State{data: data, pos: pos}) do
    {line_str, end_pos} = take_unquoted_line_info(data, pos)

    if line_str.has_colon and line_str.has_comma and not line_str.has_double_colon do
      only_blanks_and_comments_remain?(data, end_pos)
    else
      false
    end
  end

  defp comma_on_line_without_colon?(%State{data: data, pos: pos}) do
    {info, _end_pos} = take_unquoted_line_info(data, pos)
    info.has_comma and not info.has_colon
  end

  defp has_inline_dict_colon?(%State{data: data, pos: pos}) do
    {info, _end_pos} = take_unquoted_line_info(data, pos)
    info.has_single_colon
  end

  defp take_unquoted_line_info(data, pos) do
    scan_line_unquoted(data, pos, false, %{
      has_colon: false,
      has_single_colon: false,
      has_double_colon: false,
      has_comma: false
    })
  end

  defp scan_line_unquoted(data, pos, true, info) when pos < byte_size(data) do
    case :binary.at(data, pos) do
      ?\n -> {info, pos + 1}
      ?\\ -> scan_line_unquoted(data, min(pos + 2, byte_size(data)), true, info)
      ?" -> scan_line_unquoted(data, pos + 1, false, info)
      _ -> scan_line_unquoted(data, pos + 1, true, info)
    end
  end

  defp scan_line_unquoted(data, pos, false, info) when pos < byte_size(data) do
    case :binary.at(data, pos) do
      ?\n -> {info, pos + 1}
      ?# -> {info, skip_to_eol(data, pos)}
      ?" -> scan_line_unquoted(data, pos + 1, true, info)
      ?: -> scan_unquoted_colon(data, pos, info)
      ?, -> scan_line_unquoted(data, pos + 1, false, %{info | has_comma: true})
      _ -> scan_line_unquoted(data, pos + 1, false, info)
    end
  end

  defp scan_line_unquoted(_data, pos, _in_quotes?, info), do: {info, pos}

  defp scan_unquoted_colon(data, pos, info) do
    if pos + 1 < byte_size(data) and :binary.at(data, pos + 1) == ?: do
      scan_line_unquoted(data, pos + 2, false, %{info | has_colon: true, has_double_colon: true})
    else
      scan_line_unquoted(data, pos + 1, false, %{info | has_colon: true, has_single_colon: true})
    end
  end

  defp skip_to_eol(data, pos) when pos < byte_size(data) do
    if :binary.at(data, pos) == ?\n, do: pos + 1, else: skip_to_eol(data, pos + 1)
  end

  defp skip_to_eol(_data, pos), do: pos

  defp only_blanks_and_comments_remain?(data, pos) do
    case skip_blank_lines(%State{data: data, pos: pos, line: 1}) do
      {:ok, st_end} -> done?(st_end)
      _ -> false
    end
  end

  defp check_dup_key(st, acc, key) do
    if Map.has_key?(acc, key), do: err(st, "duplicate key '#{key}' in dict"), else: :ok
  end

  defp err(%State{line: line}, msg), do: {:error, {:huml_parse_error, line, msg}}
end
