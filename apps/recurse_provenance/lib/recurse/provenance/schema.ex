defmodule Recurse.Provenance.Schema do
  @moduledoc """
  A strict JSON Schema 2020-12 subset: bundling and validation.

  A published definition is one self-contained schema document whose root
  validates one kind's body, with every `$ref` a local JSON pointer
  (contract §4). `bundle/2` produces that document from the authored
  sources; `validate/2` checks a value against it.

  Only the keywords listed in `@assertions` and `@annotations` are
  understood. `check/1` refuses a document that uses anything else, so no
  definition can declare a rule this implementation would silently skip.
  """

  @assertions ~w[type properties required additionalProperties propertyNames minProperties
                 enum const pattern minLength minimum items uniqueItems minItems maxItems
                 anyOf oneOf allOf if then else $ref format]
  @annotations ~w[$schema $id $comment $defs title description contentEncoding]
  @forbidden ~w[$anchor $dynamicAnchor $dynamicRef]

  @date_time ~r/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z/

  @type problem :: {path :: String.t(), message :: String.t()}

  # -- bundling ----------------------------------------------------------

  @doc """
  Bundle `entry` (`"file.schema.json#/$defs/Name"`) and everything it
  references into one self-contained document.

  `sources` maps a file name to its decoded schema. Each dependency
  document is included once under `$defs`, in a slot named after its file,
  and every reference is rewritten to a local pointer.
  """
  @spec bundle(String.t(), %{String.t() => map()}) :: {:ok, map()} | {:error, String.t()}
  def bundle(entry, sources) when is_binary(entry) and is_map(sources) do
    {name, pointer} = split_fragment(entry)

    by_id = Map.new(sources, fn {file, doc} -> {doc["$id"], file} end)
    source = if Map.has_key?(sources, name), do: name, else: Map.get(by_id, name)

    if is_nil(source) do
      {:error, "unknown schema source: #{entry}"}
    else
      ctx = %{sources: sources, by_id: by_id}
      selected = resolve_pointer!(sources[source], pointer)
      {root, included} = rewrite(selected, source, pointer == "", ctx, %{})

      {:ok,
       %{
         "$schema" => "https://json-schema.org/draft/2020-12/schema",
         "allOf" => [root],
         "$defs" => included
       }}
    end
  rescue
    e in [ArgumentError, KeyError] -> {:error, Exception.message(e)}
  end

  defp rewrite(list, source, _root?, ctx, acc) when is_list(list) do
    Enum.map_reduce(list, acc, fn item, acc -> rewrite(item, source, false, ctx, acc) end)
  end

  defp rewrite(map, source, root?, ctx, acc) when is_map(map) do
    if Map.has_key?(map, "$id") and not root?,
      do: raise(ArgumentError, "embedded schema resource ids are not supported")

    if Enum.any?(@forbidden, &Map.has_key?(map, &1)),
      do: raise(ArgumentError, "schema anchors and dynamic references are not supported")

    map
    |> Enum.reject(fn {key, _} -> key in ["$id", "$schema"] end)
    |> Enum.sort()
    |> Enum.reduce({%{}, acc}, fn
      {"$ref", ref}, {out, acc} ->
        {target, fragment} = locate(ref, source, ctx)
        acc = include(target, ctx, acc)
        {Map.put(out, "$ref", "#/$defs/#{slot(target)}#{fragment}"), acc}

      {key, value}, {out, acc} ->
        {value, acc} = rewrite(value, source, false, ctx, acc)
        {Map.put(out, key, value), acc}
    end)
  end

  defp rewrite(other, _source, _root?, _ctx, acc), do: {other, acc}

  defp include(target, ctx, acc) do
    name = slot(target)

    if Map.has_key?(acc, name) do
      acc
    else
      # Reserve the slot first so a document that references itself ends.
      {doc, acc} = rewrite(ctx.sources[target], target, true, ctx, Map.put(acc, name, %{}))
      Map.put(acc, name, doc)
    end
  end

  defp locate("#" <> _ = ref, source, _ctx), do: {source, ref_fragment(ref)}

  defp locate(ref, _source, ctx) do
    {name, pointer} = split_fragment(ref)

    cond do
      Map.has_key?(ctx.sources, name) -> {name, pointer}
      Map.has_key?(ctx.by_id, name) -> {ctx.by_id[name], pointer}
      true -> raise ArgumentError, "schema dependency not provided: #{ref}"
    end
  end

  defp ref_fragment("#" <> pointer), do: pointer

  defp split_fragment(ref) do
    case String.split(ref, "#", parts: 2) do
      [name, pointer] -> {name, check_pointer!(pointer)}
      [name] -> {name, ""}
    end
  end

  defp check_pointer!(""), do: ""
  defp check_pointer!("/" <> _ = pointer), do: pointer

  defp check_pointer!(other),
    do: raise(ArgumentError, "only JSON-pointer fragments are supported: ##{other}")

  defp slot(file),
    do:
      file |> String.replace_suffix(".schema.json", "") |> String.replace(~r/[^A-Za-z0-9_]/, "_")

  # -- structural check of a definition ----------------------------------

  @doc """
  Check that a schema document uses only supported keywords and that
  every `$ref` is a local pointer that resolves.
  """
  @spec check(term()) :: :ok | {:error, String.t()}
  def check(document) when is_map(document) do
    walk(document, document, "#")
  catch
    {:unsupported, message} -> {:error, message}
  end

  def check(_other), do: {:error, "a schema document is a JSON object"}

  defp walk(true, _root, _at), do: :ok
  defp walk(false, _root, _at), do: :ok

  defp walk(schema, root, at) when is_map(schema) do
    Enum.each(schema, fn {key, value} ->
      cond do
        key == "$ref" ->
          check_ref(value, root, at)

        key == "$defs" ->
          each_schema(value, root, at <> "/$defs")

        key in ["properties"] ->
          each_schema(value, root, at <> "/" <> key)

        key in ["anyOf", "oneOf", "allOf"] ->
          each_schema(value, root, at <> "/" <> key)

        key in ["items", "additionalProperties", "propertyNames", "if", "then", "else"] ->
          walk(value, root, at <> "/" <> key)

        key == "pattern" ->
          compile!(value, at)

        key in @assertions or key in @annotations ->
          :ok

        true ->
          throw({:unsupported, "unsupported schema keyword #{inspect(key)} at #{at}"})
      end
    end)

    :ok
  end

  defp walk(_other, _root, at), do: throw({:unsupported, "not a schema at #{at}"})

  defp each_schema(map, root, at) when is_map(map),
    do: Enum.each(map, fn {name, schema} -> walk(schema, root, at <> "/" <> name) end)

  defp each_schema(list, root, at) when is_list(list),
    do: list |> Enum.with_index() |> Enum.each(fn {s, i} -> walk(s, root, "#{at}/#{i}") end)

  defp each_schema(_other, _root, at), do: throw({:unsupported, "malformed keyword at #{at}"})

  defp check_ref("#" <> pointer, root, at) do
    resolve_pointer!(root, pointer)
    :ok
  rescue
    _ -> throw({:unsupported, "unresolved reference ##{pointer} at #{at}"})
  end

  defp check_ref(ref, _root, at),
    do: throw({:unsupported, "non-local reference #{inspect(ref)} at #{at}"})

  defp compile!(pattern, at) do
    case Regex.compile(pattern) do
      {:ok, _} -> :ok
      _ -> throw({:unsupported, "pattern does not compile at #{at}"})
    end
  end

  # -- validation --------------------------------------------------------

  @doc """
  Validate `value` against a self-contained schema document.

  Returns `:ok` or `{:error, problems}`, each problem a `{path, message}`
  pair naming where the value failed.
  """
  @spec validate(map(), term()) :: :ok | {:error, [problem()]}
  def validate(document, value) when is_map(document) do
    case v(document, value, document, "") do
      [] -> :ok
      problems -> {:error, Enum.reverse(problems)}
    end
  end

  @doc "Whether `value` satisfies the schema document."
  @spec valid?(map(), term()) :: boolean()
  def valid?(document, value), do: validate(document, value) == :ok

  defp v(true, _value, _root, _path), do: []
  defp v(false, _value, _root, path), do: [{path, "no value is allowed here"}]

  defp v(schema, value, root, path) when is_map(schema) do
    Enum.reduce(schema, [], fn {key, arg}, problems ->
      keyword(key, arg, schema, value, root, path) ++ problems
    end)
  end

  defp keyword("$ref", "#" <> pointer, _s, value, root, path),
    do: v(resolve_pointer!(root, pointer), value, root, path)

  defp keyword("type", types, _s, value, _root, path) do
    if Enum.any?(List.wrap(types), &type?(&1, value)),
      do: [],
      else: [{path, "expected #{Enum.join(List.wrap(types), " or ")}"}]
  end

  defp keyword("const", const, _s, value, _root, path),
    do: if(value === const, do: [], else: [{path, "must equal #{inspect(const)}"}])

  defp keyword("enum", options, _s, value, _root, path),
    do: if(value in options, do: [], else: [{path, "must be one of #{inspect(options)}"}])

  defp keyword("pattern", pattern, _s, value, _root, path) when is_binary(value),
    # `$` must mean the very end of the string. By default it also
    # matches before a final newline, which other languages' engines
    # do not do, and a reference with a newline after it is not one.
    do:
      if(Regex.match?(Regex.compile!(pattern, [:dollar_endonly]), value),
        do: [],
        else: [{path, "does not match #{pattern}"}]
      )

  defp keyword("minLength", min, _s, value, _root, path) when is_binary(value),
    do: if(String.length(value) >= min, do: [], else: [{path, "shorter than #{min}"}])

  defp keyword("minimum", min, _s, value, _root, path) when is_integer(value),
    do: if(value >= min, do: [], else: [{path, "below #{min}"}])

  defp keyword("format", "date-time", _s, value, _root, path) when is_binary(value) do
    with true <- Regex.match?(@date_time, value),
         {:ok, _, _} <- DateTime.from_iso8601(value) do
      []
    else
      _ -> [{path, "not an RFC 3339 date-time"}]
    end
  end

  defp keyword("required", names, _s, value, _root, path) when is_map(value) do
    for name <- names, not Map.has_key?(value, name), do: {path, "missing #{name}"}
  end

  defp keyword("minProperties", min, _s, value, _root, path) when is_map(value),
    do: if(map_size(value) >= min, do: [], else: [{path, "fewer than #{min} properties"}])

  defp keyword("properties", props, _s, value, root, path) when is_map(value) do
    Enum.flat_map(props, fn {name, schema} ->
      case value do
        %{^name => item} -> v(schema, item, root, path <> "/" <> name)
        _ -> []
      end
    end)
  end

  defp keyword("additionalProperties", schema, s, value, root, path) when is_map(value) do
    declared = Map.keys(Map.get(s, "properties", %{}))

    value
    |> Enum.reject(fn {name, _} -> name in declared end)
    |> Enum.flat_map(fn {name, item} ->
      case schema do
        false -> [{path, "unexpected property #{name}"}]
        _ -> v(schema, item, root, path <> "/" <> name)
      end
    end)
  end

  defp keyword("propertyNames", schema, _s, value, root, path) when is_map(value),
    do: Enum.flat_map(Map.keys(value), &v(schema, &1, root, path <> "/" <> &1))

  defp keyword("items", schema, _s, value, root, path) when is_list(value) do
    value
    |> Enum.with_index()
    |> Enum.flat_map(fn {item, index} -> v(schema, item, root, "#{path}/#{index}") end)
  end

  defp keyword("uniqueItems", true, _s, value, _root, path) when is_list(value),
    do:
      if(length(Enum.uniq(value)) == length(value),
        do: [],
        else: [{path, "items are not unique"}]
      )

  defp keyword("minItems", min, _s, value, _root, path) when is_list(value),
    do: if(length(value) >= min, do: [], else: [{path, "fewer than #{min} items"}])

  defp keyword("maxItems", max, _s, value, _root, path) when is_list(value),
    do: if(length(value) <= max, do: [], else: [{path, "more than #{max} items"}])

  defp keyword("allOf", schemas, _s, value, root, path),
    do: Enum.flat_map(schemas, &v(&1, value, root, path))

  defp keyword("anyOf", schemas, _s, value, root, path) do
    if Enum.any?(schemas, &(v(&1, value, root, path) == [])),
      do: [],
      else: [{path, "matches none of the allowed forms"}]
  end

  defp keyword("oneOf", schemas, _s, value, root, path) do
    case Enum.count(schemas, &(v(&1, value, root, path) == [])) do
      1 -> []
      0 -> [{path, "matches none of the allowed forms"}]
      _ -> [{path, "matches more than one exclusive form"}]
    end
  end

  defp keyword("if", condition, s, value, root, path) do
    branch = if v(condition, value, root, path) == [], do: "then", else: "else"

    case Map.fetch(s, branch) do
      {:ok, schema} -> v(schema, value, root, path)
      :error -> []
    end
  end

  # `then`/`else` are applied by `if`; every other keyword either does not
  # apply to this value's type or is an annotation.
  defp keyword(_key, _arg, _s, _value, _root, _path), do: []

  defp type?("object", v), do: is_map(v)
  defp type?("array", v), do: is_list(v)
  defp type?("string", v), do: is_binary(v)
  defp type?("integer", v), do: is_integer(v)
  defp type?("boolean", v), do: is_boolean(v)
  defp type?("null", v), do: is_nil(v)
  defp type?(_other, _v), do: false

  defp resolve_pointer!(document, ""), do: document

  defp resolve_pointer!(document, "/" <> pointer) do
    pointer
    |> String.split("/")
    |> Enum.reduce(document, fn token, at ->
      key = token |> String.replace("~1", "/") |> String.replace("~0", "~")

      case at do
        list when is_list(list) -> Enum.fetch!(list, String.to_integer(key))
        map when is_map(map) -> Map.fetch!(map, key)
      end
    end)
  end
end
