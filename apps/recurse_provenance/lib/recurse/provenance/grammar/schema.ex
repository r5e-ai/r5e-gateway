defmodule Recurse.Provenance.Grammar.Schema do
  @moduledoc """
  The rules about schema nodes themselves, shared by the compiler and the
  validator.

  A schema node is the map a definition uses to describe one value: its
  `type`, and for that type its `properties`, `items`, `pattern`, `enum`,
  bounds, typed `ref` and object constraints. An open part of a record is
  still bounded: `keys` and `maxEntries` limit what an object with
  undeclared properties may hold, `maxLength` limits a string in bytes, and
  `unique` forbids an array from repeating an item. This module answers three
  questions about such nodes, none of which needs a record to check:

    * Is the node coherent? `check_coherence/2` refuses unknown keywords,
      keywords that do not apply to the declared type, constraints that name
      properties the node does not declare, and patterns that do not compile.
      This is where "nothing a definition declares is ignored" is enforced for
      schema keywords: a keyword the validator would not act on is an error,
      not a no-op.
    * Does one node keep every guarantee of another? `property_preserves?/2`
      and `constraints_preserved?/2` are the conservative comparison behind
      protected floors and `conformsTo`. They answer `true` only when the
      guarantee is syntactically evident, so a `false` means "not shown", not
      "disproved".
    * What instant does a timestamp name? `timestamp_ns/1` reads an RFC 3339
      timestamp into nanoseconds so `ordered` compares instants, not text.

  Patterns are regular expressions matched against bytes, with one change to
  the author's text: an unescaped `$` outside a character class means the
  very end of the string, so a trailing newline never slips through.
  """

  @object_constraints ["nonEmpty", "ordered", "requires", "exactlyOne", "atMostOne"]
  @schema_keys MapSet.new([
                 "type",
                 "description",
                 "additionalProperties",
                 "required",
                 "properties",
                 "items",
                 "values",
                 "pattern",
                 "enum",
                 "minimum",
                 "maximum",
                 "maxLength",
                 "unique",
                 "keys",
                 "maxEntries",
                 "ref",
                 "matchesSigner",
                 "keyBytes",
                 "derives"
                 | @object_constraints
               ])
  @json_types MapSet.new(["string", "integer", "boolean", "object", "array", "ref"])
  @object_only_keys MapSet.new([
                      "properties",
                      "values",
                      "keys",
                      "maxEntries",
                      "additionalProperties",
                      "required"
                      | @object_constraints
                    ])

  @timestamp_pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"

  @doc """
  The object-level constraint keywords, beyond `required`: each holds a list
  of rules over the node's own properties.
  """
  @spec object_constraints() :: [String.t()]
  def object_constraints, do: @object_constraints

  @doc """
  The exact pattern text that marks a string as a timestamp. A string whose
  schema carries this pattern is also checked to be a real calendar instant.
  """
  @spec timestamp_pattern() :: String.t()
  def timestamp_pattern, do: @timestamp_pattern

  @doc """
  Rewrites every unescaped `$` outside a character class to `\\z`.

  In a regular expression `$` also matches just before a final newline, so
  `^[a-z]+$` would accept `"abc\\n"`. A definition's pattern must describe the
  whole value, so the end anchor is made strict before the pattern is compiled.
  """
  @spec strict_end_pattern(String.t()) :: String.t()
  def strict_end_pattern(pattern) when is_binary(pattern) do
    pattern
    |> String.to_charlist()
    |> rewrite_end_anchor(false, false, false, [])
    |> IO.iodata_to_binary()
  end

  defp rewrite_end_anchor([], _escaped?, _in_class?, _class_first?, acc), do: Enum.reverse(acc)

  defp rewrite_end_anchor([ch | rest], true, in_class?, _class_first?, acc) do
    rewrite_end_anchor(rest, false, in_class?, false, [<<ch::utf8>> | acc])
  end

  defp rewrite_end_anchor([?\\ | rest], false, in_class?, _class_first?, acc) do
    rewrite_end_anchor(rest, true, in_class?, false, ["\\" | acc])
  end

  defp rewrite_end_anchor([ch | rest], false, true, class_first?, acc) do
    cond do
      class_first? and ch == ?^ ->
        rewrite_end_anchor(rest, false, true, true, ["^" | acc])

      not class_first? and ch == ?] ->
        rewrite_end_anchor(rest, false, false, false, ["]" | acc])

      true ->
        rewrite_end_anchor(rest, false, true, false, [<<ch::utf8>> | acc])
    end
  end

  defp rewrite_end_anchor([?[ | rest], false, false, _class_first?, acc) do
    rewrite_end_anchor(rest, false, true, true, ["[" | acc])
  end

  defp rewrite_end_anchor([?$ | rest], false, false, _class_first?, acc) do
    rewrite_end_anchor(rest, false, false, false, ["\\z" | acc])
  end

  defp rewrite_end_anchor([ch | rest], false, false, _class_first?, acc) do
    rewrite_end_anchor(rest, false, false, false, [<<ch::utf8>> | acc])
  end

  @doc """
  Compiles a definition's pattern with the strict end anchor applied.

  Compiling is the expensive part of matching, so the compiler does it once
  per pattern and the validator reuses the result.
  """
  @spec compile_pattern(String.t()) :: {:ok, Regex.t()} | {:error, term()}
  def compile_pattern(pattern) when is_binary(pattern) do
    Regex.compile(strict_end_pattern(pattern))
  end

  @doc """
  Whether a decoded JSON value is of a schema `type`, or of any type in a list
  of them. A `ref` is carried as a string. Floats and `null` are of no type.
  """
  @spec matches_json_type?(term(), String.t() | [String.t()]) :: boolean()
  def matches_json_type?(value, types) when is_list(types) do
    Enum.any?(types, &matches_json_type?(value, &1))
  end

  def matches_json_type?(value, "string"), do: is_binary(value)
  def matches_json_type?(value, "ref"), do: is_binary(value)
  def matches_json_type?(value, "integer"), do: is_integer(value)
  def matches_json_type?(value, "boolean"), do: is_boolean(value)
  def matches_json_type?(value, "array"), do: is_list(value)
  def matches_json_type?(%_{}, "object"), do: false
  def matches_json_type?(value, "object"), do: is_map(value)
  def matches_json_type?(_value, _other), do: false

  @doc """
  Reads an RFC 3339 timestamp with up to nine fractional digits into
  nanoseconds on the UTC timeline.

  Returns `:error` for anything that is not a real instant in this profile:
  a date that is not on the calendar (`2026-02-30`), a leap second (`:60`),
  an out-of-range clock or offset, or the "unknown offset" form `-00:00`.
  """
  @spec timestamp_ns(String.t()) :: {:ok, integer()} | :error
  def timestamp_ns(
        <<y::binary-size(4), ?-, m::binary-size(2), ?-, d::binary-size(2), ?T, hr::binary-size(2),
          ?:, min::binary-size(2), ?:, sec::binary-size(2), rest::binary>>
      ) do
    with {:ok, [y, m, d, hr, min, sec]} <- all_digits([y, m, d, hr, min, sec]),
         {:ok, nanos, offset} <- split_fraction(rest),
         {:ok, offset_seconds} <- parse_utc_offset(offset),
         {:ok, date} <- Date.new(y, m, d),
         true <- hr <= 23 and min <= 59 and sec <= 59 do
      days = Date.diff(date, ~D[0001-01-01]) + 1
      utc_seconds = days * 86_400 + hr * 3_600 + min * 60 + sec - offset_seconds
      {:ok, utc_seconds * 1_000_000_000 + nanos}
    else
      _ -> :error
    end
  end

  def timestamp_ns(value) when is_binary(value), do: :error

  defp all_digits(parts) do
    if Enum.all?(parts, &digits?/1),
      do: {:ok, Enum.map(parts, &String.to_integer/1)},
      else: :error
  end

  defp digits?(<<>>), do: false
  defp digits?(binary), do: only_digits?(binary)

  defp only_digits?(<<c, rest::binary>>) when c in ?0..?9, do: only_digits?(rest)
  defp only_digits?(<<>>), do: true
  defp only_digits?(_), do: false

  # The optional fraction is a dot and one to nine digits; what follows it is
  # the offset.
  defp split_fraction(<<?., rest::binary>>) do
    {fraction, offset} = take_digits(rest, 0)

    if byte_size(fraction) in 1..9,
      do: {:ok, fraction |> String.pad_trailing(9, "0") |> String.to_integer(), offset},
      else: :error
  end

  defp split_fraction(offset), do: {:ok, 0, offset}

  defp take_digits(binary, count) do
    case binary do
      <<_::binary-size(count), c, _::binary>> when c in ?0..?9 -> take_digits(binary, count + 1)
      <<digits::binary-size(count), rest::binary>> -> {digits, rest}
    end
  end

  defp parse_utc_offset("Z"), do: {:ok, 0}
  defp parse_utc_offset("-00:00"), do: :error

  defp parse_utc_offset(<<sign, h::binary-size(2), ?:, m::binary-size(2)>>)
       when sign in [?+, ?-] do
    with {:ok, [oh, om]} <- all_digits([h, m]),
         true <- oh <= 23 and om <= 59 do
      mult = if sign == ?+, do: 1, else: -1
      {:ok, mult * (oh * 60 + om) * 60}
    else
      _ -> :error
    end
  end

  defp parse_utc_offset(_), do: :error

  @doc """
  Checks only that a schema node is built from the right kinds of value: the
  node and every nested node is a map, and `properties` is a map of nodes.

  The compiler merges a child's schema into its parent's before the result
  can be checked for coherence, and merging assumes this much. Checking it
  first turns a mistyped package into an error instead of a crash.
  """
  @spec check_shape(term(), String.t()) :: :ok | {:error, term()}
  def check_shape(schema, path) when is_map(schema) and not is_struct(schema) do
    with :ok <- check_properties_shape(Map.get(schema, "properties", %{}), path),
         :ok <- check_optional_shape(schema, "items", path) do
      check_optional_shape(schema, "values", path)
    end
  end

  def check_shape(_other, path), do: {:error, {:schema_not_object, path}}

  defp check_properties_shape(props, path) when is_map(props) and not is_struct(props) do
    Enum.reduce_while(props, :ok, fn {name, prop_schema}, :ok ->
      case check_shape(prop_schema, "#{path}.properties.#{name}") do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp check_properties_shape(_other, path), do: {:error, {:properties_not_object, path}}

  defp check_optional_shape(schema, key, path) do
    case Map.fetch(schema, key) do
      :error -> :ok
      {:ok, sub} -> check_shape(sub, "#{path}.#{key}")
    end
  end

  @doc """
  Checks that a schema node, and every node nested in it, is coherent.

  `path` names the node in the error. The first problem found is returned as
  `{:error, {reason, path, ...}}`.
  """
  @spec check_coherence(term(), String.t()) :: :ok | {:error, term()}
  def check_coherence(schema, path)

  def check_coherence(%_{}, path), do: {:error, {:schema_not_object, path}}

  def check_coherence(schema, path) when is_map(schema) do
    with :ok <- check_allowed_schema_keys(schema, path),
         {:ok, typ, types} <- normalize_schema_types(schema, path),
         :ok <- check_type_specific_keywords(schema, typ, types, path),
         {:ok, props, required} <- check_properties_and_required(schema, path),
         :ok <- check_object_constraint_coherence(schema, props, required, path),
         :ok <- check_child_properties(props, path),
         :ok <- check_derived_siblings(props, required, path) do
      check_collection_subschemas(schema, path)
    end
  end

  def check_coherence(_other, path), do: {:error, {:schema_not_object, path}}

  @doc """
  Whether `candidate` still carries every object-level rule (`required`,
  `nonEmpty`, `ordered`, `requires`, `exactlyOne`, `atMostOne`) that `base`
  declares. Rules are compared as written; an equivalent rule phrased
  differently does not count.
  """
  @spec constraints_preserved?(map(), map()) :: boolean()
  def constraints_preserved?(candidate, base) when is_map(candidate) and is_map(base) do
    Enum.all?(["required" | @object_constraints], fn sec ->
      cand_rules = Map.get(candidate, sec, [])

      base
      |> Map.get(sec, [])
      |> Enum.all?(&(&1 in cand_rules))
    end)
  end

  @doc """
  Whether every value `candidate` accepts is evidently one `base` accepts.

  Conservative: the same or a narrower type, the same pattern, `keys`,
  `unique` and typed `ref`, an enum that is a subset, bounds at least as
  tight, a closed object
  kept closed with no new properties, and the same holding recursively for
  nested properties, `items` and `values`.
  """
  @spec property_preserves?(map(), map()) :: boolean()
  def property_preserves?(candidate, base) when is_map(candidate) and is_map(base) do
    type_preserves?(Map.get(candidate, "type"), Map.get(base, "type")) and
      exact_keywords_preserved?(candidate, base) and
      closed_shape_preserved?(candidate, base) and
      enum_preserved?(candidate, base) and
      bounds_preserved?(candidate, base) and
      nested_collections_preserved?(candidate, base) and
      constraints_preserved?(candidate, base) and
      nested_properties_preserved?(candidate, base)
  end

  # ---- Coherence Internals ----

  defp check_allowed_schema_keys(schema, path) do
    unknown = schema |> Map.keys() |> Enum.reject(&MapSet.member?(@schema_keys, &1))

    case Enum.sort(unknown) do
      [] ->
        :ok

      sorted ->
        {:error, {:unsupported_schema_keys, path, sorted}}
    end
  end

  defp normalize_schema_types(schema, path) do
    typ = Map.get(schema, "type", "object")
    types = if is_list(typ), do: typ, else: [typ]

    if types != [] and Enum.all?(types, &(is_binary(&1) and MapSet.member?(@json_types, &1))) do
      {:ok, typ, types}
    else
      {:error, {:unsupported_schema_type, path, typ}}
    end
  end

  defp check_type_specific_keywords(schema, typ, types, path) do
    has_obj_keys? = Enum.any?(Map.keys(schema), &MapSet.member?(@object_only_keys, &1))

    with :ok <-
           require_when(
             has_obj_keys? and types != ["object"],
             {:object_rules_require_object, path}
           ),
         :ok <-
           require_when(
             Map.has_key?(schema, "items") and types != ["array"],
             {:items_requires_array, path}
           ),
         :ok <- check_numeric_bounds(schema, types, path),
         :ok <- check_size_bounds(schema, types, path),
         :ok <- check_unique_keyword(schema, types, path),
         :ok <- check_keys_keyword(schema, path),
         :ok <- check_additional_props_bool(schema, path),
         :ok <- check_pattern_keyword(schema, types, path),
         :ok <- check_ref_keyword(schema, types, path),
         :ok <- check_matches_signer(schema, types, path),
         :ok <- check_key_bytes(schema, types, path),
         :ok <- check_derives(schema, types, path) do
      check_enum_keyword(schema, typ, path)
    end
  end

  # `matchesSigner: N` binds a string to the key id of the record's Nth
  # signer. Sixteen is the most signatures an envelope carries.
  defp check_matches_signer(schema, types, path) do
    case Map.fetch(schema, "matchesSigner") do
      :error ->
        :ok

      {:ok, position} when is_integer(position) and position >= 1 and position <= 16 ->
        require_when(types != ["string"], {:matches_signer_requires_string, path})

      {:ok, other} ->
        {:error, {:invalid_matches_signer, path, other}}
    end
  end

  # `keyBytes: true` marks an object as a public key: an algorithm name
  # and the key's bytes, both always present.
  defp check_key_bytes(schema, types, path) do
    case Map.fetch(schema, "keyBytes") do
      :error ->
        :ok

      {:ok, true} ->
        props = Map.get(schema, "properties", %{})
        required = Map.get(schema, "required", [])

        require_when(
          types != ["object"] or
            not (is_map(props) and is_map_key(props, "algorithm") and is_map_key(props, "bytes")) or
            not (is_list(required) and "algorithm" in required and "bytes" in required),
          {:key_bytes_requires_algorithm_and_bytes, path}
        )

      {:ok, other} ->
        {:error, {:invalid_key_bytes, path, other}}
    end
  end

  # `derives: {keyIdOf: f}` says a string is the key id of the public key
  # in the neighbouring property `f`. That the neighbour exists and is a
  # public key that is always present is checked where both are in view
  # (`check_derived_siblings`).
  defp check_derives(schema, types, path) do
    case Map.fetch(schema, "derives") do
      :error ->
        :ok

      {:ok, %{"keyIdOf" => field} = rule} when is_binary(field) and map_size(rule) == 1 ->
        require_when(types != ["string"], {:derives_requires_string, path})

      {:ok, other} ->
        {:error, {:invalid_derives, path, other}}
    end
  end

  # The key must be required: an id that could appear without the key it
  # is said to come from would be derived from nothing.
  defp check_derived_siblings(props, required, path) do
    Enum.find_value(props, :ok, fn
      {name, %{"derives" => %{"keyIdOf" => field}}} ->
        case props do
          %{^field => %{"keyBytes" => true}} when is_list(required) ->
            if field in required,
              do: nil,
              else: {:error, {:derives_names_no_key, "#{path}.properties.#{name}", field}}

          _ ->
            {:error, {:derives_names_no_key, "#{path}.properties.#{name}", field}}
        end

      _ ->
        nil
    end)
  end

  @doc """
  Whether a schema's `matchesSigner` rules fit a kind that asks for
  `signatures` signatures: no rule anywhere names a position past the
  last, and every position after the first is named by a rule on a
  top-level property that is required. The first signer is always the
  record's issuer. A later position named only on something a body may
  leave out (an optional property, a nested object, an item of a list
  that may be empty) would be checked against nothing in such a body, and
  any key could fill it.
  """
  @spec signer_positions_fit(term(), pos_integer()) ::
          :ok | {:error, {:exceeds, pos_integer()} | {:unbound, pos_integer()}}
  def signer_positions_fit(schema, signatures) do
    highest = Enum.max([0 | signer_positions(schema)])
    bound = always_checked_positions(schema)

    cond do
      highest > signatures -> {:error, {:exceeds, highest}}
      unbound = Enum.find(2..signatures//1, &(&1 not in bound)) -> {:error, {:unbound, unbound}}
      true -> :ok
    end
  end

  defp always_checked_positions(schema) when is_map(schema) do
    required = schema |> Map.get("required", []) |> List.wrap()

    for {name, %{"matchesSigner" => position}} <- Map.get(schema, "properties", %{}),
        name in required,
        is_integer(position),
        do: position
  end

  defp always_checked_positions(_other), do: []

  defp signer_positions(node) when is_map(node) do
    Enum.flat_map(node, fn
      {"matchesSigner", position} when is_integer(position) -> [position]
      {_key, value} -> signer_positions(value)
    end)
  end

  defp signer_positions(node) when is_list(node), do: Enum.flat_map(node, &signer_positions/1)
  defp signer_positions(_leaf), do: []

  defp require_when(true, err_reason), do: {:error, err_reason}
  defp require_when(false, _err_reason), do: :ok

  defp check_numeric_bounds(schema, types, path) do
    has_bounds? = Map.has_key?(schema, "minimum") or Map.has_key?(schema, "maximum")

    with :ok <-
           require_when(
             has_bounds? and types != ["integer"],
             {:numeric_bounds_require_integer, path}
           ),
         {:ok, min_v} <- fetch_optional_int_bound(schema, "minimum", path),
         {:ok, max_v} <- fetch_optional_int_bound(schema, "maximum", path) do
      require_when(
        not is_nil(min_v) and not is_nil(max_v) and min_v > max_v,
        {:minimum_exceeds_maximum, path}
      )
    end
  end

  # `maxLength` counts the bytes of a string's UTF-8 form, so every
  # implementation counts the same thing. It may sit on a node that also
  # admits other types and then applies to the strings only. `maxEntries`
  # counts an object's properties.
  defp check_size_bounds(schema, types, path) do
    with :ok <-
           require_when(
             Map.has_key?(schema, "maxLength") and "string" not in types,
             {:max_length_requires_string, path}
           ),
         :ok <- positive_bound(schema, "maxLength", path) do
      positive_bound(schema, "maxEntries", path)
    end
  end

  defp positive_bound(schema, key, path) do
    case Map.fetch(schema, key) do
      :error -> :ok
      {:ok, n} when is_integer(n) and n >= 1 -> :ok
      {:ok, _} -> {:error, {:expected_positive_bound, "#{path}.#{key}"}}
    end
  end

  # `unique: true` is the only form: an array either may repeat an item or
  # may not, and `false` would be a rule that does nothing.
  defp check_unique_keyword(schema, types, path) do
    case Map.fetch(schema, "unique") do
      :error -> :ok
      {:ok, true} when types == ["array"] -> :ok
      {:ok, true} -> {:error, {:unique_requires_array, path}}
      {:ok, _} -> {:error, {:unique_must_be_true, path}}
    end
  end

  # `keys` is a pattern every property name of the object must match,
  # declared or not.
  defp check_keys_keyword(schema, path) do
    case Map.fetch(schema, "keys") do
      :error ->
        :ok

      {:ok, pat} when is_binary(pat) ->
        case compile_pattern(pat) do
          {:ok, _} -> :ok
          {:error, _} -> {:error, {:invalid_regex_pattern, path, pat}}
        end

      {:ok, _} ->
        {:error, {:keys_must_be_pattern, path}}
    end
  end

  defp fetch_optional_int_bound(schema, key, path) do
    case Map.fetch(schema, key) do
      :error -> {:ok, nil}
      {:ok, v} when is_integer(v) -> {:ok, v}
      {:ok, _} -> {:error, {:expected_integer_bound, "#{path}.#{key}"}}
    end
  end

  defp check_additional_props_bool(schema, path) do
    case Map.fetch(schema, "additionalProperties") do
      :error -> :ok
      {:ok, b} when is_boolean(b) -> :ok
      {:ok, _} -> {:error, {:additional_properties_not_boolean, path}}
    end
  end

  defp check_pattern_keyword(schema, types, path) do
    case Map.fetch(schema, "pattern") do
      :error ->
        :ok

      {:ok, pat} when is_binary(pat) and types == ["string"] ->
        case compile_pattern(pat) do
          {:ok, _} -> :ok
          {:error, _} -> {:error, {:invalid_regex_pattern, path, pat}}
        end

      {:ok, _} ->
        {:error, {:pattern_requires_string_schema, path}}
    end
  end

  defp check_ref_keyword(schema, types, path) do
    cond do
      Map.has_key?(schema, "ref") and types != ["ref"] ->
        {:error, {:ref_requires_type_ref, path}}

      types == ["ref"] and not is_map(Map.get(schema, "ref")) ->
        {:error, {:type_ref_missing_specifier, path}}

      true ->
        :ok
    end
  end

  defp check_enum_keyword(schema, typ, path) do
    case Map.fetch(schema, "enum") do
      :error ->
        :ok

      {:ok, choices} when is_list(choices) and choices != [] ->
        valid? =
          Enum.all?(choices, fn item ->
            (is_binary(item) or is_integer(item) or is_boolean(item)) and
              matches_json_type?(item, typ)
          end)

        if valid?, do: :ok, else: {:error, {:invalid_enum_choices, path}}

      {:ok, _} ->
        {:error, {:invalid_enum_choices, path}}
    end
  end

  defp check_properties_and_required(schema, path) do
    case Map.get(schema, "properties", %{}) do
      props when is_map(props) and not is_struct(props) ->
        case check_property_name_list(
               Map.get(schema, "required", []),
               "#{path}.required",
               props,
               false
             ) do
          {:ok, req} -> {:ok, props, req}
          {:error, _} = err -> err
        end

      _ ->
        {:error, {:properties_not_object, path}}
    end
  end

  defp check_object_constraint_coherence(schema, props, required, path) do
    with :ok <- check_non_empty_coherence(schema, props, path),
         :ok <- check_group_constraints(schema, props, required, path) do
      check_requires_coherence(Map.get(schema, "requires", []), props, path)
    end
  end

  defp check_non_empty_coherence(schema, props, path) do
    with {:ok, names} <-
           check_property_name_list(
             Map.get(schema, "nonEmpty", []),
             "#{path}.nonEmpty",
             props,
             false
           ) do
      case Enum.find(names, &(not non_empty_supported_prop?(props, &1))) do
        nil -> :ok
        bad -> {:error, {:non_empty_unsupported_type, path, bad}}
      end
    end
  end

  defp non_empty_supported_prop?(props, name) do
    t = Map.get(props[name], "type", "object")
    ts = if is_list(t), do: t, else: [t]
    Enum.all?(ts, &(&1 in ["string", "array", "object"]))
  end

  defp check_group_constraints(schema, props, required, path) do
    Enum.reduce_while(["ordered", "exactlyOne", "atMostOne"], :ok, fn sec, :ok ->
      case check_one_group_section(sec, Map.get(schema, sec, []), props, required, path) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp check_one_group_section(_sec, groups, _props, _req, path) when not is_list(groups) do
    {:error, {:expected_constraint_list, path}}
  end

  defp check_one_group_section(sec, groups, props, required, path) do
    req_set = MapSet.new(required)

    Enum.reduce_while(groups, :ok, fn group, :ok ->
      case validate_constraint_group(sec, group, props, req_set, "#{path}.#{sec}") do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp validate_constraint_group("ordered", group, props, _req_set, sec_path) do
    case check_property_name_list(group, sec_path, props, true) do
      {:ok, [a, b]} -> check_ordered_operand_types(props[a], props[b], sec_path)
      {:ok, _other} -> {:error, {:ordered_requires_two_fields, sec_path}}
      {:error, _} = err -> err
    end
  end

  defp validate_constraint_group(_one_of_sec, group, props, req_set, sec_path) do
    case check_property_name_list(group, sec_path, props, true) do
      {:ok, fields} ->
        overlap = MapSet.intersection(req_set, MapSet.new(fields)) |> MapSet.size()
        if overlap > 1, do: {:error, {:constraint_conflicts_with_required, sec_path}}, else: :ok

      {:error, _} = err ->
        err
    end
  end

  defp check_ordered_operand_types(prop_a, prop_b, sec_path) do
    operands = [Map.get(prop_a, "type", "object"), Map.get(prop_b, "type", "object")]

    if operands in [["integer", "integer"], ["string", "string"]] do
      :ok
    else
      {:error, {:invalid_ordered_operand_types, sec_path, operands}}
    end
  end

  defp check_requires_coherence(rules, _props, path) when not is_list(rules) do
    {:error, {:expected_requires_list, path}}
  end

  defp check_requires_coherence([], _props, _path), do: :ok

  defp check_requires_coherence([rule | rest], props, path) do
    with :ok <- check_single_requires_rule(rule, props, "#{path}.requires") do
      check_requires_coherence(rest, props, path)
    end
  end

  defp check_single_requires_rule(%{"when" => when_map, "then" => then_list} = rule, props, rpath)
       when map_size(rule) == 2 and is_map(when_map) do
    with :ok <- check_when_clause(when_map, props, rpath),
         {:ok, _} <- check_property_name_list(then_list, "#{rpath}.then", props, true) do
      :ok
    end
  end

  defp check_single_requires_rule(_bad, _props, rpath),
    do: {:error, {:invalid_requires_rule, rpath}}

  defp check_when_clause(%{"field" => f, "equals" => _eq} = w, props, rpath)
       when map_size(w) == 2 do
    case check_property_name_list([f], "#{rpath}.when", props, true) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  defp check_when_clause(%{"envelope" => env, "present" => pres} = w, _props, rpath)
       when map_size(w) == 2 do
    if is_binary(env) and env != "" and is_boolean(pres) do
      :ok
    else
      {:error, {:invalid_requires_envelope_condition, rpath}}
    end
  end

  defp check_when_clause(_other, _props, rpath),
    do: {:error, {:unsupported_requires_condition, rpath}}

  defp check_child_properties(props, path) do
    Enum.reduce_while(props, :ok, fn {name, prop_schema}, :ok ->
      case check_coherence(prop_schema, "#{path}.properties.#{name}") do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp check_collection_subschemas(schema, path) do
    Enum.reduce_while(["items", "values"], :ok, fn sec, :ok ->
      case check_optional_subschema(schema, sec, path) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp check_optional_subschema(schema, sec, path) do
    case Map.fetch(schema, sec) do
      :error -> :ok
      {:ok, sub} -> check_coherence(sub, "#{path}.#{sec}")
    end
  end

  defp check_property_name_list(list, path, props, nonempty?) when is_list(list) do
    cond do
      Enum.any?(list, &(not is_binary(&1))) ->
        {:error, {:expected_property_name_strings, path}}

      (nonempty? and list == []) or MapSet.size(MapSet.new(list)) != length(list) ->
        {:error, {:duplicate_or_empty_property_names, path}}

      true ->
        missing = Enum.find(list, &(not Map.has_key?(props, &1)))

        if is_nil(missing),
          do: {:ok, list},
          else: {:error, {:unknown_property_reference, path, missing}}
    end
  end

  defp check_property_name_list(_not_list, path, _props, _nonempty?) do
    {:error, {:expected_property_name_list, path}}
  end

  # ---- Preservation Internals ----

  defp type_preserves?(nil, nil), do: true
  defp type_preserves?(cand, nil) when not is_nil(cand), do: false
  defp type_preserves?(nil, base) when not is_nil(base), do: false

  defp type_preserves?(cand_t, base_t) do
    c_set = if is_list(cand_t), do: MapSet.new(cand_t), else: MapSet.new([cand_t])
    b_set = if is_list(base_t), do: MapSet.new(base_t), else: MapSet.new([base_t])
    MapSet.size(c_set) > 0 and MapSet.subset?(c_set, b_set)
  end

  defp exact_keywords_preserved?(candidate, base) do
    Enum.all?(
      ["pattern", "ref", "matchesSigner", "keyBytes", "derives", "unique", "keys"],
      fn kw ->
        not Map.has_key?(base, kw) or Map.get(candidate, kw) == Map.get(base, kw)
      end
    )
  end

  defp closed_shape_preserved?(candidate, base) do
    if Map.get(base, "additionalProperties") == false do
      cand_closed? = Map.get(candidate, "additionalProperties") == false
      cand_keys = candidate |> Map.get("properties", %{}) |> Map.keys() |> MapSet.new()
      base_keys = base |> Map.get("properties", %{}) |> Map.keys() |> MapSet.new()
      cand_closed? and MapSet.subset?(cand_keys, base_keys)
    else
      true
    end
  end

  defp enum_preserved?(candidate, base) do
    case Map.fetch(base, "enum") do
      :error ->
        true

      {:ok, base_enum} ->
        case Map.get(candidate, "enum") do
          c_enum when is_list(c_enum) -> Enum.all?(c_enum, &strict_member?(&1, base_enum))
          _ -> false
        end
    end
  end

  defp strict_member?(val, list), do: Enum.any?(list, &(&1 === val))

  defp bounds_preserved?(candidate, base) do
    at_least?(candidate, base, "minimum") and
      Enum.all?(["maximum", "maxLength", "maxEntries"], &at_most?(candidate, base, &1))
  end

  defp at_least?(candidate, base, key) do
    case Map.fetch(base, key) do
      :error -> true
      {:ok, limit} -> is_integer(candidate[key]) and candidate[key] >= limit
    end
  end

  defp at_most?(candidate, base, key) do
    case Map.fetch(base, key) do
      :error -> true
      {:ok, limit} -> is_integer(candidate[key]) and candidate[key] <= limit
    end
  end

  defp nested_collections_preserved?(candidate, base) do
    items_ok? =
      not Map.has_key?(base, "items") or
        (is_map(candidate["items"]) and property_preserves?(candidate["items"], base["items"]))

    values_ok? =
      not Map.has_key?(base, "values") or
        (is_map(candidate["values"]) and property_preserves?(candidate["values"], base["values"]))

    items_ok? and values_ok?
  end

  defp nested_properties_preserved?(candidate, base) do
    case Map.fetch(base, "properties") do
      :error ->
        true

      {:ok, b_props} ->
        c_props = Map.get(candidate, "properties", %{})

        Enum.all?(b_props, fn {k, v} ->
          is_map(c_props[k]) and property_preserves?(c_props[k], v)
        end)
    end
  end
end
