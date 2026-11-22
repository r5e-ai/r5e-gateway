defmodule Recurse.Provenance.Grammar.Validate do
  @moduledoc """
  Checks a decoded JSON value against a schema node and reports every rule it
  breaks.

  This is the body check: given the hydrated schema of a kind and the body of
  a record, does the body have the declared shape? It runs once per record,
  so it is split in two. `prepare/1` turns a schema node into a `Plan` once,
  when a package is compiled, and that is where every pattern is compiled to
  a regular expression. `validate/3` then walks a value against the plan and
  does no compilation at all. A plan is plain data: it can be kept in a
  variable, an ETS table or `:persistent_term` and read by any process in the
  VM that built it. It holds compiled regular expressions, so it cannot be
  written to disk or sent to another node; compile again there.

  ## What is reported

  Every broken rule is reported, not only the first, as
  `%{path: path, code: code}`. The list is sorted by path and then code, with
  duplicates removed, so two implementations that agree on the rules produce
  the same list whatever order they walk a value in.

  A path starts at `$` and adds `.name` for a property and `[index]` for a
  list item, as in `$.items[2].size`. A rule about one property (missing,
  unexpected, empty) is reported at that property's path. A rule about
  several properties of one object (`ordered`, `exactlyOne`, `atMostOne`) is
  reported at the object's path. When a value is of the wrong type nothing
  else is checked beneath it.

  ## Codes

  A code is a fixed word, never free text. These are all of them:

    * `wrong_type`: the value is not of the declared `type`. Floats and
      `null` are of no type.
    * `enum_mismatch`: the value is not one of the `enum` choices.
    * `pattern_mismatch`: the string does not match its `pattern`.
    * `signer_mismatch`: a string with `matchesSigner: N` is not the key id
      of the record's Nth signer. Checked only when the signers are given.
    * `not_a_public_key`: an object with `keyBytes` does not name a
      registered algorithm, or its `bytes` are not strict padded base64 of
      a key that algorithm admits.
    * `not_the_key_id_of`: a string with `derives.keyIdOf` is not the key
      id of the public key in the property it names.
    * `invalid_timestamp`: the string has the shape of a timestamp but names
      no real instant, either under the timestamp pattern or as an operand of
      `ordered`.
    * `integer_out_of_range`: the integer is beyond plus or minus 2^53 - 1.
    * `below_minimum`, `above_maximum`: the integer is outside its bounds.
    * `too_long`: the string is more than `maxLength` bytes of UTF-8.
    * `duplicate_item`: an array with `unique` holds the same item twice.
      Reported once, at the array.
    * `key_mismatch`: a property name does not match the object's `keys`
      pattern. Reported at that property.
    * `too_many_entries`: the object has more than `maxEntries` properties.
    * `unexpected_property`: the object is closed and does not declare this
      property.
    * `missing_required`: a `required` property is absent.
    * `missing_conditional`: a `requires` rule applies and a property it
      demands is absent.
    * `empty_value`: a `nonEmpty` property is `""`, `[]` or `{}`.
    * `out_of_order`: an `ordered` pair is present with the first greater
      than the second. Integers compare as numbers, strings as timestamps. A
      pair that is not two integers or two strings is not compared; one of
      the two is then of the wrong type and is reported as that.
    * `not_exactly_one`: an `exactlyOne` group has none, or more than one, of
      its properties present.
    * `more_than_one`: an `atMostOne` group has more than one present.
    * `envelope_required`: a `requires` rule depends on the record's envelope
      and no envelope was given to the check.
    * `cross_chain_forbidden`: a `chain:` reference where the `ref` does not
      allow one.
    * `malformed_cross_chain_ref`: a `chain:` reference that is not
      `chain:<chain name>/<reference>`, where the chain name is the
      reference of the record that founded that chain
      (`evidence:sha256:` and 64 hex digits).
    * `expected_bytes_ref`, `expected_event_ref`, `expected_evidence_ref`,
      `expected_definition_ref`, `expected_resource_ref`: the reference is
      not of the form its `ref` demands.
    * `ref_alternatives_mismatch`: the reference matches none of the `anyOf`
      alternatives.

  Whether a reference points at something that exists, or at a record of the
  kind the `ref` names, is not decided here. That needs the store; this
  check sees one body and nothing else.
  """

  alias Recurse.Provenance.Grammar.Schema
  alias Recurse.Provenance.Key

  @max_safe_integer 9_007_199_254_740_991

  # Reference forms, as pattern sources. They are compiled when a plan is
  # prepared and carried in it, so that checking a reference never compiles.
  @kind_path "[a-z0-9.-]+/v[0-9a-z]+/[A-Za-z0-9]+"
  @ref_forms %{
    bytes: {"\\Abytes:sha256:[0-9a-f]{64}\\z", "expected_bytes_ref"},
    event: {"\\Aevent:sha256:[0-9a-f]{64}\\z", "expected_event_ref"},
    evidence: {"\\Aevidence:sha256:[0-9a-f]{64}\\z", "expected_evidence_ref"},
    definition:
      {"\\Abytes:sha256:[0-9a-f]{64}#" <> @kind_path <> "\\z", "expected_definition_ref"},
    resource: {"\\A" <> @kind_path <> "/[^\\s#]+\\z", "expected_resource_ref"}
  }
  # A chain is named by the reference of the record that founded it.
  @chain_id "\\Aevidence:sha256:[0-9a-f]{64}\\z"

  @codes [
    "wrong_type",
    "enum_mismatch",
    "pattern_mismatch",
    "signer_mismatch",
    "not_a_public_key",
    "not_the_key_id_of",
    "invalid_timestamp",
    "integer_out_of_range",
    "below_minimum",
    "above_maximum",
    "too_long",
    "duplicate_item",
    "key_mismatch",
    "too_many_entries",
    "unexpected_property",
    "missing_required",
    "missing_conditional",
    "empty_value",
    "out_of_order",
    "not_exactly_one",
    "more_than_one",
    "envelope_required",
    "cross_chain_forbidden",
    "malformed_cross_chain_ref",
    "expected_bytes_ref",
    "expected_event_ref",
    "expected_evidence_ref",
    "expected_definition_ref",
    "expected_resource_ref",
    "ref_alternatives_mismatch"
  ]

  defmodule Plan do
    @moduledoc """
    A schema node made ready for checking: the same rules as the authored
    node, with defaults filled in, nested nodes prepared and the pattern
    compiled, so the check itself only reads fields.
    """

    defstruct types: ["object"],
              enum: nil,
              regex: nil,
              timestamp?: false,
              ref: nil,
              matches_signer: nil,
              key_bytes?: false,
              derived: [],
              minimum: nil,
              maximum: nil,
              max_length: nil,
              unique?: false,
              key_regex: nil,
              max_entries: nil,
              items: nil,
              properties: %{},
              closed?: false,
              values: nil,
              required: [],
              non_empty: [],
              ordered: [],
              exactly_one: [],
              at_most_one: [],
              requires: []

    @type ref_rule ::
            {chain_id :: Regex.t() | nil,
             {:form, Regex.t(), code :: String.t()} | {:any_of, [ref_rule()]} | :invalid}

    @type requires_rule ::
            {:field, String.t(), term(), [String.t()]}
            | {:envelope, String.t(), boolean(), [String.t()]}

    @type t :: %__MODULE__{
            types: [String.t()],
            enum: [term()] | nil,
            regex: Regex.t() | nil,
            timestamp?: boolean(),
            ref: ref_rule() | nil,
            matches_signer: pos_integer() | nil,
            key_bytes?: boolean(),
            derived: [{field :: String.t(), key_field :: String.t()}],
            minimum: integer() | nil,
            maximum: integer() | nil,
            max_length: pos_integer() | nil,
            unique?: boolean(),
            key_regex: Regex.t() | nil,
            max_entries: pos_integer() | nil,
            items: t() | nil,
            properties: %{optional(String.t()) => t()},
            closed?: boolean(),
            values: t() | nil,
            required: [String.t()],
            non_empty: [String.t()],
            ordered: [[String.t()]],
            exactly_one: [[String.t()]],
            at_most_one: [[String.t()]],
            requires: [requires_rule()]
          }
  end

  @type violation :: %{path: String.t(), code: String.t()}

  @doc """
  Every code `validate/3` can report, in the order the module documentation
  lists them.
  """
  @spec codes() :: [String.t()]
  def codes, do: @codes

  @doc """
  Turns a schema node into a plan, compiling each pattern once.

  The node must already be coherent (`Schema.check_coherence/2`). A pattern
  that does not compile raises `ArgumentError`, because a coherent node has
  none.
  """
  @spec prepare(map()) :: Plan.t()
  def prepare(schema) when is_map(schema) and not is_struct(schema) do
    types = schema |> Map.get("type", "object") |> List.wrap()
    pattern = Map.get(schema, "pattern")

    %Plan{
      types: types,
      enum: Map.get(schema, "enum"),
      regex: prepare_pattern(pattern),
      timestamp?: pattern == Schema.timestamp_pattern(),
      ref: prepare_ref_keyword(types, Map.get(schema, "ref")),
      matches_signer: Map.get(schema, "matchesSigner"),
      key_bytes?: Map.get(schema, "keyBytes") == true,
      derived:
        for(
          {name, %{"derives" => %{"keyIdOf" => key_field}}} <- Map.get(schema, "properties", %{}),
          do: {name, key_field}
        ),
      minimum: integer_or_nil(Map.get(schema, "minimum")),
      maximum: integer_or_nil(Map.get(schema, "maximum")),
      max_length: integer_or_nil(Map.get(schema, "maxLength")),
      unique?: Map.get(schema, "unique") == true,
      key_regex: prepare_pattern(Map.get(schema, "keys")),
      max_entries: integer_or_nil(Map.get(schema, "maxEntries")),
      items: prepare_optional(Map.get(schema, "items")),
      properties:
        schema |> Map.get("properties", %{}) |> Map.new(fn {k, v} -> {k, prepare(v)} end),
      closed?: Map.get(schema, "additionalProperties") == false,
      values: prepare_optional(Map.get(schema, "values")),
      required: Map.get(schema, "required", []),
      non_empty: Map.get(schema, "nonEmpty", []),
      ordered: Map.get(schema, "ordered", []),
      exactly_one: Map.get(schema, "exactlyOne", []),
      at_most_one: Map.get(schema, "atMostOne", []),
      requires: schema |> Map.get("requires", []) |> Enum.map(&prepare_requires/1)
    }
  end

  @doc """
  Checks `value` against a plan, or against a schema node that is prepared on
  the spot.

  Pass a plan wherever the same schema is checked more than once. Options:

    * `:envelope`, a map of the record's envelope fields, which `requires`
      rules of the form `when: {envelope: <field>, present: <bool>}` read.
      A field counts as present when the map has it with a value other
      than `nil`.
    * `:signers`, the key ids that signed the record, in signer order,
      which `matchesSigner` rules read. Before a record is signed they are
      not known; leave the option out and those rules are not checked.
  """
  @spec validate(Plan.t() | map(), term(), keyword()) :: :ok | {:error, [violation()]}
  def validate(plan_or_schema, value, opts \\ [])

  def validate(%Plan{} = plan, value, opts) do
    context = %{envelope: Keyword.get(opts, :envelope), signers: Keyword.get(opts, :signers)}

    case check(value, plan, [], context, []) do
      [] -> :ok
      found -> {:error, render(found)}
    end
  end

  def validate(schema, value, opts) when is_map(schema) do
    validate(prepare(schema), value, opts)
  end

  @doc """
  Checks one reference string against a `ref` rule as authored (`bytes`,
  `definition`, `event`, `evidence`, `kind`, `anyOf`, with optional
  `crossChain`).

  Returns the code `validate/3` would report for it.
  """
  @spec check_ref(String.t(), map()) :: :ok | {:error, String.t()}
  def check_ref(value, ref_spec) when is_binary(value) and is_map(ref_spec) do
    ref_verdict(value, prepare_ref(ref_spec))
  end

  # ---- Preparing ----

  defp prepare_optional(nil), do: nil
  defp prepare_optional(schema), do: prepare(schema)

  defp integer_or_nil(n) when is_integer(n), do: n
  defp integer_or_nil(_), do: nil

  defp prepare_pattern(nil), do: nil

  defp prepare_pattern(pattern) do
    case Schema.compile_pattern(pattern) do
      {:ok, regex} -> regex
      {:error, reason} -> raise ArgumentError, "pattern does not compile: #{inspect(reason)}"
    end
  end

  defp prepare_ref_keyword(["ref"], ref_spec) when is_map(ref_spec), do: prepare_ref(ref_spec)
  defp prepare_ref_keyword(_types, _ref_spec), do: nil

  # A rule is `{chain_id, form}`: `chain_id` is the compiled chain-id pattern
  # when a `chain:` prefix is allowed and `nil` when it is not.
  defp prepare_ref(ref_spec) do
    chain_id = if Map.get(ref_spec, "crossChain") == true, do: Regex.compile!(@chain_id)
    {chain_id, ref_form(ref_spec)}
  end

  defp ref_form(%{"anyOf" => branches}) when is_list(branches),
    do: {:any_of, Enum.map(branches, &prepare_ref/1)}

  defp ref_form(%{"bytes" => true}), do: compiled_form(:bytes)
  defp ref_form(%{"evidence" => true}), do: compiled_form(:evidence)
  defp ref_form(%{"definition" => true}), do: compiled_form(:definition)
  defp ref_form(%{"event" => _}), do: compiled_form(:event)
  defp ref_form(%{"kind" => _}), do: compiled_form(:resource)
  # The compiler refuses a `ref` with no address form, so this is reached only
  # for a node that was never checked; it then matches nothing.
  defp ref_form(_), do: :invalid

  defp compiled_form(name) do
    {source, code} = Map.fetch!(@ref_forms, name)
    {:form, Regex.compile!(source), code}
  end

  defp prepare_requires(%{"when" => %{"field" => field, "equals" => equals}, "then" => then}),
    do: {:field, field, equals, then}

  defp prepare_requires(%{"when" => %{"envelope" => key, "present" => present}, "then" => then}),
    do: {:envelope, key, present, then}

  # ---- Checking ----
  #
  # `path` is the list of steps from the root, innermost first, and is only
  # turned into text for a value that breaks a rule. `acc` collects
  # `{path, code}` pairs.

  defp check(value, %Plan{} = plan, path, envelope, acc) do
    if Schema.matches_json_type?(value, plan.types) do
      acc = check_enum(value, plan.enum, path, acc)
      check_typed(value, plan, path, envelope, acc)
    else
      [{path, "wrong_type"} | acc]
    end
  end

  defp check_enum(_value, nil, _path, acc), do: acc

  defp check_enum(value, choices, path, acc) do
    if Enum.any?(choices, &(&1 === value)), do: acc, else: [{path, "enum_mismatch"} | acc]
  end

  defp check_typed(value, plan, path, context, acc) when is_binary(value) do
    acc = check_pattern(value, plan, path, acc)

    acc =
      if plan.max_length != nil and byte_size(value) > plan.max_length,
        do: [{path, "too_long"} | acc],
        else: acc

    acc = check_signer(value, plan.matches_signer, context.signers, path, acc)

    case plan.ref && ref_verdict(value, plan.ref) do
      {:error, code} -> [{path, code} | acc]
      _ -> acc
    end
  end

  defp check_typed(value, plan, path, _envelope, acc) when is_integer(value) do
    acc = if abs(value) > @max_safe_integer, do: [{path, "integer_out_of_range"} | acc], else: acc

    acc =
      if plan.minimum != nil and value < plan.minimum,
        do: [{path, "below_minimum"} | acc],
        else: acc

    if plan.maximum != nil and value > plan.maximum,
      do: [{path, "above_maximum"} | acc],
      else: acc
  end

  defp check_typed(value, plan, path, envelope, acc) when is_list(value) do
    # Items are decoded JSON with no floats, so two items are the same
    # item exactly when they are equal terms.
    acc =
      if plan.unique? and length(Enum.uniq(value)) != length(value),
        do: [{path, "duplicate_item"} | acc],
        else: acc

    if plan.items == nil, do: acc, else: check_items(value, plan.items, path, 0, envelope, acc)
  end

  defp check_typed(value, plan, path, envelope, acc) when is_map(value) do
    acc =
      if plan.max_entries != nil and map_size(value) > plan.max_entries,
        do: [{path, "too_many_entries"} | acc],
        else: acc

    acc = check_entries(value, plan, path, envelope, acc)
    acc = check_present(plan.required, value, path, "missing_required", acc)
    acc = check_public_key(value, plan.key_bytes?, path, acc)
    acc = check_derived(plan.derived, value, path, acc)
    acc = check_non_empty(plan.non_empty, value, path, acc)
    acc = check_ordered(plan.ordered, value, path, acc)
    acc = check_groups(plan.exactly_one, value, path, "not_exactly_one", acc)
    acc = check_groups(plan.at_most_one, value, path, "more_than_one", acc)
    check_requires(plan.requires, value, path, envelope, acc)
  end

  defp check_typed(_boolean, _plan, _path, _envelope, acc), do: acc

  defp check_pattern(_value, %Plan{regex: nil}, _path, acc), do: acc

  defp check_pattern(value, %Plan{regex: regex, timestamp?: timestamp?}, path, acc) do
    cond do
      not Regex.match?(regex, value) -> [{path, "pattern_mismatch"} | acc]
      timestamp? and Schema.timestamp_ns(value) == :error -> [{path, "invalid_timestamp"} | acc]
      true -> acc
    end
  end

  defp check_items([], _item_plan, _path, _index, _envelope, acc), do: acc

  defp check_items([item | rest], item_plan, path, index, envelope, acc) do
    acc = check(item, item_plan, [index | path], envelope, acc)
    check_items(rest, item_plan, path, index + 1, envelope, acc)
  end

  # One pass over the object's entries: a declared property is checked against
  # its own plan, an undeclared one is an error when the object is closed, and
  # `values`, when declared, applies to every entry.
  defp check_entries(
         value,
         %Plan{properties: props, closed?: closed?, values: values, key_regex: key_regex},
         path,
         envelope,
         acc
       ) do
    Enum.reduce(value, acc, fn {key, item}, acc ->
      item_path = [key | path]

      acc =
        if key_regex != nil and not Regex.match?(key_regex, key),
          do: [{item_path, "key_mismatch"} | acc],
          else: acc

      acc =
        case props do
          %{^key => prop_plan} -> check(item, prop_plan, item_path, envelope, acc)
          _ when closed? -> [{item_path, "unexpected_property"} | acc]
          _ -> acc
        end

      if values == nil, do: acc, else: check(item, values, item_path, envelope, acc)
    end)
  end

  defp check_present([], _value, _path, _code, acc), do: acc

  defp check_present([name | rest], value, path, code, acc) do
    acc = if is_map_key(value, name), do: acc, else: [{[name | path], code} | acc]
    check_present(rest, value, path, code, acc)
  end

  defp check_non_empty([], _value, _path, acc), do: acc

  defp check_non_empty([name | rest], value, path, acc) do
    acc =
      case value do
        %{^name => empty} when empty == "" or empty == [] or empty == %{} ->
          [{[name | path], "empty_value"} | acc]

        _ ->
          acc
      end

    check_non_empty(rest, value, path, acc)
  end

  defp check_ordered([], _value, _path, acc), do: acc

  defp check_ordered([[left, right] | rest], value, path, acc) do
    acc =
      case value do
        %{^left => a, ^right => b} -> compare_ordered(a, b, left, right, path, acc)
        _ -> acc
      end

    check_ordered(rest, value, path, acc)
  end

  defp compare_ordered(a, b, _left, _right, path, acc) when is_integer(a) and is_integer(b) do
    if a <= b, do: acc, else: [{path, "out_of_order"} | acc]
  end

  defp compare_ordered(a, b, left, right, path, acc) when is_binary(a) and is_binary(b) do
    case {Schema.timestamp_ns(a), Schema.timestamp_ns(b)} do
      {{:ok, ns_a}, {:ok, ns_b}} when ns_a <= ns_b ->
        acc

      {{:ok, _}, {:ok, _}} ->
        [{path, "out_of_order"} | acc]

      {res_a, res_b} ->
        acc = if res_a == :error, do: [{[left | path], "invalid_timestamp"} | acc], else: acc
        if res_b == :error, do: [{[right | path], "invalid_timestamp"} | acc], else: acc
    end
  end

  defp compare_ordered(_a, _b, _left, _right, _path, acc), do: acc

  defp check_groups([], _value, _path, _code, acc), do: acc

  defp check_groups([group | rest], value, path, code, acc) do
    present = Enum.count(group, &is_map_key(value, &1))

    ok? =
      case code do
        "not_exactly_one" -> present == 1
        "more_than_one" -> present <= 1
      end

    acc = if ok?, do: acc, else: [{path, code} | acc]
    check_groups(rest, value, path, code, acc)
  end

  defp check_public_key(_value, false, _path, acc), do: acc

  defp check_public_key(value, true, path, acc) do
    case public_key_id(value) do
      {:ok, _id} -> acc
      :error -> [{path, "not_a_public_key"} | acc]
    end
  end

  defp public_key_id(%{"algorithm" => algorithm, "bytes" => text})
       when is_binary(algorithm) and is_binary(text) do
    with {:ok, bytes} <- Base.decode64(text),
         true <- Base.encode64(bytes) == text,
         {:ok, id} <- Key.id(algorithm, bytes) do
      {:ok, id}
    else
      _ -> :error
    end
  end

  defp public_key_id(_other), do: :error

  defp check_derived([], _value, _path, acc), do: acc

  defp check_derived([{field, key_field} | rest], value, path, acc) do
    acc =
      case value do
        %{^field => id, ^key_field => key} ->
          if public_key_id(key) == {:ok, id},
            do: acc,
            else: [{[field | path], "not_the_key_id_of"} | acc]

        _ ->
          acc
      end

    check_derived(rest, value, path, acc)
  end

  defp check_signer(_value, nil, _signers, _path, acc), do: acc
  defp check_signer(_value, _position, nil, _path, acc), do: acc

  defp check_signer(value, position, signers, path, acc) do
    if Enum.at(signers, position - 1) == value, do: acc, else: [{path, "signer_mismatch"} | acc]
  end

  defp check_requires([], _value, _path, _envelope, acc), do: acc

  defp check_requires([{:field, field, equals, then} | rest], value, path, envelope, acc) do
    acc =
      case value do
        %{^field => actual} when actual === equals ->
          check_present(then, value, path, "missing_conditional", acc)

        _ ->
          acc
      end

    check_requires(rest, value, path, envelope, acc)
  end

  defp check_requires(
         [{:envelope, _key, _present, _then} | rest],
         value,
         path,
         %{envelope: nil} = context,
         acc
       ) do
    check_requires(rest, value, path, context, [{path, "envelope_required"} | acc])
  end

  defp check_requires([{:envelope, key, present, then} | rest], value, path, envelope, acc) do
    acc =
      if Map.get(envelope.envelope, key) != nil == present,
        do: check_present(then, value, path, "missing_conditional", acc),
        else: acc

    check_requires(rest, value, path, envelope, acc)
  end

  # ---- References ----

  defp ref_verdict("chain:" <> _, {nil, _form}), do: {:error, "cross_chain_forbidden"}

  defp ref_verdict("chain:" <> rest, {chain_id, form}) do
    case String.split(rest, "/", parts: 2) do
      [_id, "chain:" <> _] ->
        {:error, "malformed_cross_chain_ref"}

      [id, inner] ->
        if Regex.match?(chain_id, id),
          do: form_verdict(inner, form),
          else: {:error, "malformed_cross_chain_ref"}

      _ ->
        {:error, "malformed_cross_chain_ref"}
    end
  end

  defp ref_verdict(value, {_chain_id, form}), do: form_verdict(value, form)

  defp form_verdict(value, {:form, regex, code}) do
    if Regex.match?(regex, value), do: :ok, else: {:error, code}
  end

  defp form_verdict(value, {:any_of, branches}) do
    if Enum.any?(branches, &(ref_verdict(value, &1) == :ok)),
      do: :ok,
      else: {:error, "ref_alternatives_mismatch"}
  end

  defp form_verdict(_value, :invalid), do: {:error, "ref_alternatives_mismatch"}

  # ---- Reporting ----

  defp render(found) do
    found
    |> Enum.map(fn {path, code} -> %{path: render_path(path), code: code} end)
    |> Enum.sort_by(&{&1.path, &1.code})
    |> Enum.dedup()
  end

  defp render_path(path) do
    path
    |> Enum.reverse()
    |> Enum.map(fn
      index when is_integer(index) -> ["[", Integer.to_string(index), "]"]
      name -> [".", name]
    end)
    |> then(&IO.iodata_to_binary(["$" | &1]))
  end
end
