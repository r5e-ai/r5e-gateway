defmodule Recurse.Provenance.Grammar.Compiler do
  @moduledoc """
  Compiles authored definition packages into kinds that records can be
  checked against, and gives every package and every kind an identity that
  depends only on what was written.

  ## What goes in

  A package is one decoded HUML document: a `package` name, the `group` and
  `version` its kinds live under, the packages it `imports` (alias to package
  name), reusable `types`, and a map of `kinds`. A kind is addressed by its
  kind path, `<group>/<version>/<Kind>`. Exactly one package in a compilation
  is the foundation (`foundation: true`); it holds the root meta-kind
  `core.r5e.io/v1/KindDefinition` and is the only package that may declare
  `protected` floors. Every other package must import it.

  ## Identity

  A package is identified by the hash of its manifest:

      {
        "format":  "r5e.definition-package/v1",
        "package": <the authored package, exactly as parsed>,
        "imports": {<imported package name>: <that package's manifest ref>}
      }

  The manifest's bytes are the Core canonical JSON encoding of that value and
  its reference is `bytes:sha256:<hex>` of those bytes. `package` is the
  authored text as data: no inheritance applied, no `use:` expanded.
  `imports` has one entry per distinct package the author imported, keyed by
  package name, and nothing else is in the manifest.

  Because a manifest contains the references of its imports, packages are
  hashed in dependency order, an import cycle is an error, and changing any
  package changes the reference of every package that imports it, directly
  or not. A kind may only name kinds (in `extends`, `definedBy` or a typed
  `ref`) from its own package or one its package imports, so everything a
  definition depends on is reachable from its manifest reference alone.

  A definition reference is `<manifest ref>#<kind path>`. Who wrote or
  published a package plays no part: the same package text with the same
  imports has the same reference everywhere.

  ## What is enforced

    * Imports form an acyclic graph; `use:` types expand across packages with
      cycle detection.
    * A child states only what it adds. Redeclaring an inherited property
      differently is an error; changes go through `overrides` (`drop`,
      `optional`, `replace`, `dropConstraints`) with a stated `reason`.
    * Fields, constraints, naming, signature count and `requiresAuthority`
      that the foundation protects cannot be dropped or weakened by any
      descendant. A tightening made by another package is not a floor.
    * `conformsTo` is computed conservatively: a kind conforms to an ancestor
      only if it evidently keeps every guarantee, and conformance lost at one
      level is never regained below it.
    * A meta-kind is an ordinary extension of `KindDefinition`, chosen with
      `definedBy`. A definition is checked against its meta-kind's schema and
      predicates (`schemaPropertyType`, `schemaPropertyExists`).
    * Nothing declared is ignored. Unknown package keys, kind keys, schema
      keywords, `ref` keys and predicate checks are errors.
    * `keyBytes: true` marks an object as a public key (`algorithm` and
      `bytes`, both required). `derives: {keyIdOf: f}` on a string says it
      is the key id of the public key in the neighbouring property `f`,
      which must be a `keyBytes` object.
    * `matchesSigner: N` on a string says it is the key id of the record's
      Nth signer. A kind that uses it must ask for at least N `signatures`,
      or it is refused with `{:matches_signer_exceeds_signatures, kind, N,
      signatures}`. A kind that asks for more than one signature must name
      every position after the first with such a rule on a required
      top-level property, or it is refused with
      `{:signer_position_unbound, kind, position}`.

  The result is plain data; no process is involved. It holds compiled
  regular expressions, so it is valid in the VM that built it and is not
  something to serialise.
  """

  alias Recurse.Provenance.Grammar.{Schema, Validate}

  @format "r5e.contract-package/v2"
  @manifest_format "r5e.definition-package/v1"
  @bootstrap_def_kind "core.r5e.io/v1/KindDefinition"
  @derive_field_re ~r/\{([A-Za-z0-9_]+)\}/
  @kind_path_re ~r/\A[a-z0-9.-]+\/v[0-9a-z]+\/[A-Za-z0-9]+\z/

  @package_keys MapSet.new([
                  "format",
                  "package",
                  "group",
                  "version",
                  "foundation",
                  "imports",
                  "types",
                  "kinds"
                ])

  @droppable_constraints Schema.object_constraints() ++ ["predicates", "terminal"]

  @list_constraint_keys MapSet.new([
                          "required",
                          "nonEmpty",
                          "enum",
                          "ordered",
                          "requires",
                          "then",
                          "exactlyOne",
                          "atMostOne",
                          "protected",
                          "drop",
                          "optional",
                          "dropConstraints",
                          "predicates",
                          "anyOf"
                        ])

  @base_kinddef_keys MapSet.new([
                       "group",
                       "version",
                       "kind",
                       "substrate",
                       "definedBy",
                       "extends",
                       "derivedFrom",
                       "protected",
                       "overrides",
                       "pins",
                       "naming",
                       "description",
                       "schema",
                       "epistemicScope",
                       "predicates",
                       "signatures",
                       "requiresAuthority",
                       "terminal"
                     ])

  defmodule Kind do
    @moduledoc """
    One compiled kind: its identity, its place in the inheritance tree, and
    its hydrated contract (the schema and rules that apply to it after every
    ancestor and override has been taken into account).

    `definition_ref` is `<manifest_ref>#<path>`. `conforms_to` is the set of
    definition references, its own included, whose guarantees this kind
    evidently keeps. `validator` is `effective_schema` prepared for checking
    records. The `protected_*` fields carry the foundation's floors down the
    tree and matter only while compiling descendants.
    """
    defstruct [
      :path,
      :package,
      :is_foundation,
      :authored,
      :published_spec,
      :manifest_ref,
      :definition_ref,
      :validator,
      :substrate,
      :defined_by,
      :extends,
      :effective_schema,
      :effective_naming,
      :effective_predicates,
      :effective_signatures,
      :effective_requires_authority,
      :effective_terminal,
      protected_floors: %{},
      protected_min_signatures: 1,
      protected_naming: nil,
      protected_requires_authority: false,
      protected_constraints: %{},
      property_ref_bindings: %{},
      conforms_to: MapSet.new()
    ]

    @type t :: %__MODULE__{}

    @doc """
    The kind paths of everything this kind conforms to, without the manifest
    references. Readable, but only meaningful within one compilation.
    """
    @spec conforms_to_paths(t()) :: MapSet.t(String.t())
    def conforms_to_paths(%__MODULE__{conforms_to: refs}) do
      MapSet.new(refs, fn ref ->
        [_pub, kpath] = String.split(ref, "#", parts: 2)
        kpath
      end)
    end
  end

  defstruct [
    :foundation_pkg,
    packages: %{},
    manifests: %{},
    raw_kinds: %{},
    expanded_kinds: %{},
    external_targets: %{},
    compiled: %{},
    compiled_by_ref: %{}
  ]

  @type manifest :: %{value: map(), bytes: binary(), ref: String.t()}

  @type t :: %__MODULE__{
          foundation_pkg: String.t() | nil,
          packages: %{optional(String.t()) => map()},
          manifests: %{optional(String.t()) => manifest()},
          raw_kinds: map(),
          expanded_kinds: map(),
          external_targets: %{optional(String.t()) => MapSet.t(String.t())},
          compiled: %{optional(String.t()) => Kind.t()},
          compiled_by_ref: %{optional(String.t()) => Kind.t()}
        }

  @doc """
  The kind path of the root meta-kind: the definition every other definition
  is checked against unless it names another with `definedBy`.
  """
  @spec root_definition_kind() :: String.t()
  def root_definition_kind, do: @bootstrap_def_kind

  @doc """
  The fields of a compiled kind that its meta-kind asked for: everything
  in its published form that is not one of the fields every kind
  definition has. For a metric kind this is its `metric` contract. Empty
  for a kind defined by the root definition kind alone.
  """
  @spec metakind_fields(Kind.t()) :: %{String.t() => term()}
  def metakind_fields(%Kind{published_spec: spec}) when is_map(spec),
    do: Map.reject(spec, fn {key, _value} -> MapSet.member?(@base_kinddef_keys, key) end)

  def metakind_fields(_kind), do: %{}

  @doc """
  The `format` value of a package manifest.
  """
  @spec manifest_format() :: String.t()
  def manifest_format, do: @manifest_format

  @doc """
  Compiles decoded packages together.

  Returns the compilation, with a manifest for every package under
  `manifests` and a `Kind` for every kind under `compiled`, or the first
  error found as `{:error, reason}`.
  """
  @spec compile_packages([map()]) :: {:ok, t()} | {:error, term()}
  def compile_packages(package_dicts) when is_list(package_dicts) do
    with {:ok, state0} <- init_packages(package_dicts),
         :ok <- check_foundation_imported(state0),
         {:ok, order} <- import_order(state0.packages),
         {:ok, state1} <- build_manifests(state0, order),
         :ok <- check_declared_types(state1),
         {:ok, expanded} <- expand_all_kinds(state1),
         :ok <- check_kind_shapes(expanded),
         state2 = %{state1 | expanded_kinds: expanded},
         {:ok, ext_targets} <- collect_external_targets(state2) do
      compile_all_kinds(%{state2 | external_targets: ext_targets})
    end
  end

  # ---- Initialization & Package-Level Checks ----

  defp init_packages(package_dicts) do
    foundations = Enum.filter(package_dicts, &(is_map(&1) and Map.get(&1, "foundation") == true))

    case foundations do
      [foundation_map] ->
        register_packages(package_dicts, %__MODULE__{foundation_pkg: foundation_map["package"]})

      other ->
        {:error, {:invalid_foundation_count, length(other)}}
    end
  end

  defp register_packages([], state), do: {:ok, state}

  defp register_packages([pkg | rest], state) when is_map(pkg) do
    pkg_name = Map.get(pkg, "package")

    with :ok <- check_package_header(pkg, pkg_name, state.packages),
         :ok <- check_constraint_list_types(pkg, pkg_name, ""),
         {:ok, next_raw} <- register_raw_kinds(pkg, state.raw_kinds) do
      next_state = %{
        state
        | packages: Map.put(state.packages, pkg_name, pkg),
          raw_kinds: next_raw
      }

      register_packages(rest, next_state)
    end
  end

  defp register_packages([_not_a_map | _rest], _state), do: {:error, :package_not_object}

  defp check_package_header(pkg, pkg_name, existing_packages) do
    cond do
      Map.get(pkg, "format") != @format ->
        {:error, {:invalid_package_format, pkg_name, Map.get(pkg, "format")}}

      not is_binary(pkg_name) or pkg_name == "" ->
        {:error, :missing_package_name}

      Map.has_key?(existing_packages, pkg_name) ->
        {:error, {:duplicate_package, pkg_name}}

      not is_binary(pkg["group"]) or not is_binary(pkg["version"]) ->
        {:error, {:missing_group_or_version, pkg_name}}

      true ->
        check_package_sections(pkg, pkg_name)
    end
  end

  defp check_package_sections(pkg, pkg_name) do
    cond do
      not valid_imports?(Map.get(pkg, "imports", %{})) ->
        {:error, {:invalid_imports, pkg_name}}

      not plain_map?(Map.get(pkg, "types", %{})) ->
        {:error, {:invalid_types_map, pkg_name}}

      true ->
        check_package_keys(pkg, pkg_name)
    end
  end

  defp valid_imports?(imports) do
    plain_map?(imports) and Enum.all?(imports, fn {_alias, target} -> is_binary(target) end)
  end

  defp plain_map?(value), do: is_map(value) and not is_struct(value)

  # A top-level key the compiler does not know would be hashed into the
  # manifest and then have no effect, so it is refused.
  defp check_package_keys(pkg, pkg_name) do
    case pkg |> Map.keys() |> Enum.reject(&MapSet.member?(@package_keys, &1)) |> Enum.sort() do
      [] -> :ok
      unknown -> {:error, {:unknown_package_keys, pkg_name, unknown}}
    end
  end

  defp register_raw_kinds(pkg, raw_kinds) do
    group = pkg["group"]
    version = pkg["version"]
    kinds_map = Map.get(pkg, "kinds", %{})

    if is_map(kinds_map) do
      Enum.reduce_while(kinds_map, {:ok, raw_kinds}, fn {kind_name, kind_body}, {:ok, acc} ->
        insert_raw_kind(acc, "#{group}/#{version}/#{kind_name}", pkg, kind_body)
      end)
    else
      {:error, {:invalid_kinds_map, pkg["package"]}}
    end
  end

  defp insert_raw_kind(acc, kpath, pkg, kind_body) do
    cond do
      Map.has_key?(acc, kpath) ->
        {:halt, {:error, {:duplicate_kind, kpath}}}

      # A definition reference ends in the kind path, so a path the reference
      # form cannot carry would give a kind no usable identity.
      not Regex.match?(@kind_path_re, kpath) ->
        {:halt, {:error, {:invalid_kind_path, kpath}}}

      not plain_map?(kind_body) ->
        {:halt, {:error, {:kind_not_object, kpath}}}

      true ->
        {:cont, {:ok, Map.put(acc, kpath, {pkg, kind_body})}}
    end
  end

  defp check_constraint_list_types(map, path, parent_key) when is_map(map) do
    Enum.reduce_while(map, :ok, fn {k, v}, :ok ->
      check_single_constraint_entry(k, v, path, parent_key)
    end)
  end

  defp check_constraint_list_types(list, path, parent_key) when is_list(list) do
    list
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {item, idx}, :ok ->
      case check_constraint_list_types(item, "#{path}[#{idx}]", parent_key) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp check_constraint_list_types(_scalar, _path, _parent_key), do: :ok

  defp check_single_constraint_entry(k, v, path, parent_key) do
    must_be_list? =
      parent_key not in ["properties", "replace", "predicates"] and
        MapSet.member?(@list_constraint_keys, k)

    if must_be_list? and not is_list(v) do
      {:halt, {:error, {:constraint_must_be_list, "#{path}.#{k}"}}}
    else
      case check_constraint_list_types(v, "#{path}.#{k}", k) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end
  end

  defp check_foundation_imported(%__MODULE__{packages: packages, foundation_pkg: foundation}) do
    missing =
      packages
      |> Enum.reject(fn {name, pkg} ->
        name == foundation or foundation in Map.values(Map.get(pkg, "imports", %{}))
      end)
      |> Enum.map(&elem(&1, 0))
      |> Enum.sort()

    case missing do
      [] -> :ok
      [name | _] -> {:error, {:foundation_not_imported, name}}
    end
  end

  # Packages in an order where each comes after everything it imports, which
  # is the order their manifests must be hashed in.
  defp import_order(packages) do
    names = packages |> Map.keys() |> Enum.sort()

    case visit_imports(names, packages, [], MapSet.new(), []) do
      {:ok, _done, order} -> {:ok, Enum.reverse(order)}
      {:error, _} = err -> err
    end
  end

  defp visit_imports([], _packages, _chain, done, order), do: {:ok, done, order}

  defp visit_imports([pkg_name | rest], packages, chain, done, order) do
    cond do
      MapSet.member?(done, pkg_name) ->
        visit_imports(rest, packages, chain, done, order)

      pkg_name in chain ->
        {:error, {:package_import_cycle, Enum.reverse([pkg_name | chain])}}

      true ->
        imports = Map.get(packages[pkg_name], "imports", %{})

        with {:ok, targets} <- resolve_import_targets(pkg_name, imports, packages),
             {:ok, done1, order1} <-
               visit_imports(Enum.sort(targets), packages, [pkg_name | chain], done, order) do
          visit_imports(rest, packages, chain, MapSet.put(done1, pkg_name), [pkg_name | order1])
        end
    end
  end

  defp build_manifests(state, order) do
    Enum.reduce_while(order, {:ok, state}, fn pkg_name, {:ok, st} ->
      case build_manifest(st, pkg_name) do
        {:ok, manifest} ->
          {:cont, {:ok, %{st | manifests: Map.put(st.manifests, pkg_name, manifest)}}}

        {:error, _} = err ->
          {:halt, err}
      end
    end)
  end

  defp build_manifest(state, pkg_name) do
    pkg = state.packages[pkg_name]

    imports =
      pkg
      |> Map.get("imports", %{})
      |> Map.values()
      |> Map.new(&{&1, state.manifests[&1].ref})

    value = %{"format" => @manifest_format, "package" => pkg, "imports" => imports}
    bytes = RecurseVerify.Canonical.encode(value)
    digest = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)
    {:ok, %{value: value, bytes: bytes, ref: "bytes:sha256:" <> digest}}
  rescue
    # Canonical JSON has no form for a float or a non-JSON term. A package
    # read from HUML never holds one; a package built by hand might.
    error in ArgumentError -> {:error, {:package_not_canonical, pkg_name, error.message}}
  end

  # Every declared type is checked whether or not a kind uses it, so an
  # unused type cannot carry a keyword nobody looked at.
  defp check_declared_types(%__MODULE__{packages: packages, raw_kinds: raw_kinds}) do
    declared =
      for {pkg_name, pkg} <- Enum.sort(packages),
          {type_name, _} <- Enum.sort(Map.get(pkg, "types", %{})),
          do: {pkg_name, pkg, type_name}

    Enum.reduce_while(declared, :ok, fn {pkg_name, pkg, type_name}, :ok ->
      path = "#{pkg_name}.types.#{type_name}"

      with {:ok, expanded} <- expand_types(pkg, %{"use" => type_name}, packages, []),
           :ok <- Schema.check_coherence(expanded, path),
           {:ok, _targets} <- collect_refs_in_node(path, expanded, raw_kinds, MapSet.new()) do
        {:cont, :ok}
      else
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp resolve_import_targets(pkg_name, imports, packages) when is_map(imports) do
    Enum.reduce_while(imports, {:ok, []}, fn {alias_name, target_pkg}, {:ok, acc} ->
      if Map.has_key?(packages, target_pkg) do
        {:cont, {:ok, [target_pkg | acc]}}
      else
        {:halt, {:error, {:unknown_imported_package, pkg_name, alias_name, target_pkg}}}
      end
    end)
  end

  # ---- Reusable `use:` Type Expansion ----

  defp expand_all_kinds(%__MODULE__{raw_kinds: raw_kinds, packages: packages}) do
    Enum.reduce_while(raw_kinds, {:ok, %{}}, fn {kpath, {pkg, body}}, {:ok, acc} ->
      case expand_types(pkg, body, packages, []) do
        {:ok, expanded} -> {:cont, {:ok, Map.put(acc, kpath, expanded)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # Composition reads these parts of a kind before anything has checked them
  # against the meta-kind, so their basic form is settled here.
  defp check_kind_shapes(expanded) do
    expanded
    |> Enum.sort()
    |> Enum.reduce_while(:ok, fn {kpath, body}, :ok ->
      case check_kind_shape(kpath, body) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp check_kind_shape(kpath, body) do
    overrides = Map.get(body, "overrides", %{})
    naming = Map.get(body, "naming", %{})

    cond do
      not plain_map?(overrides) ->
        {:error, {:overrides_not_object, kpath}}

      not plain_map?(Map.get(overrides, "replace", %{})) ->
        {:error, {:replace_not_object, kpath}}

      not plain_map?(naming) or not is_binary(Map.get(naming, "derive", "")) ->
        {:error, {:invalid_naming, kpath}}

      not is_binary(Map.get(body, "extends", "")) or not is_binary(Map.get(body, "definedBy", "")) ->
        {:error, {:invalid_kind_reference, kpath}}

      true ->
        check_kind_schema_shapes(kpath, body, Map.get(overrides, "replace", %{}))
    end
  end

  defp check_kind_schema_shapes(kpath, body, replace) do
    schema_nodes =
      case Map.fetch(body, "schema") do
        {:ok, schema} when is_map(schema) -> [{"#{kpath}.schema", schema}]
        _ -> []
      end

    replace_nodes =
      for {prop, node} <- Enum.sort(replace), do: {"#{kpath}.overrides.replace.#{prop}", node}

    nodes = schema_nodes ++ replace_nodes

    Enum.reduce_while(nodes, :ok, fn {path, node}, :ok ->
      case Schema.check_shape(node, path) do
        :ok -> {:cont, :ok}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp expand_types(pkg, list, packages, stack) when is_list(list) do
    Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
      case expand_types(pkg, item, packages, stack) do
        {:ok, exp} -> {:cont, {:ok, [exp | acc]}}
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, rev} -> {:ok, Enum.reverse(rev)}
      {:error, _} = err -> err
    end
  end

  defp expand_types(pkg, %{"use" => ref_name} = node, packages, stack) when is_binary(ref_name) do
    with {:ok, target_pkg, type_name} <- resolve_type_source(pkg, ref_name, packages),
         key = {target_pkg["package"], type_name},
         :ok <- if(key in stack, do: {:error, {:type_expansion_cycle, stack ++ [key]}}, else: :ok),
         {:ok, raw_type} <- fetch_declared_type(target_pkg, type_name),
         {:ok, base_expanded} <- expand_types(target_pkg, raw_type, packages, stack ++ [key]) do
      overlay_use_fields(pkg, Map.delete(node, "use"), base_expanded, packages, stack)
    end
  end

  defp expand_types(pkg, map, packages, stack) when is_map(map) do
    Enum.reduce_while(map, {:ok, %{}}, fn {k, v}, {:ok, acc} ->
      case expand_types(pkg, v, packages, stack) do
        {:ok, exp_v} -> {:cont, {:ok, Map.put(acc, k, exp_v)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp expand_types(_pkg, scalar, _packages, _stack), do: {:ok, scalar}

  defp resolve_type_source(pkg, ref_name, packages) do
    case String.split(ref_name, ".", parts: 2) do
      [alias_name, type_name] ->
        target_pkg_name = get_in(pkg, ["imports", alias_name])

        if is_binary(target_pkg_name) and Map.has_key?(packages, target_pkg_name) do
          {:ok, packages[target_pkg_name], type_name}
        else
          {:error, {:unknown_import_alias, pkg["package"], alias_name, ref_name}}
        end

      [type_name] ->
        {:ok, pkg, type_name}
    end
  end

  defp fetch_declared_type(target_pkg, type_name) do
    case get_in(target_pkg, ["types", type_name]) do
      nil -> {:error, {:unknown_reusable_type, target_pkg["package"], type_name}}
      type_def when is_map(type_def) -> {:ok, type_def}
      _ -> {:error, {:invalid_reusable_type, target_pkg["package"], type_name}}
    end
  end

  defp overlay_use_fields(pkg, extra_fields, base_expanded, packages, stack) do
    Enum.reduce_while(extra_fields, {:ok, base_expanded}, fn {k, v}, {:ok, acc} ->
      case expand_types(pkg, v, packages, stack) do
        {:ok, exp_v} -> {:cont, {:ok, Map.put(acc, k, exp_v)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # ---- References To Kinds In Other Packages ----

  defp collect_external_targets(%__MODULE__{} = state) do
    init_ext = Map.new(state.packages, fn {name, _} -> {name, MapSet.new()} end)

    Enum.reduce_while(state.expanded_kinds, {:ok, init_ext}, fn {kpath, body}, {:ok, ext_acc} ->
      pkg = elem(state.raw_kinds[kpath], 0)

      with {:ok, t1} <-
             collect_refs_in_node(
               kpath,
               Map.get(body, "schema", %{}),
               state.raw_kinds,
               MapSet.new()
             ),
           replace_map = get_in(body, ["overrides", "replace"]) || %{},
           {:ok, t2} <- collect_refs_in_node(kpath, replace_map, state.raw_kinds, t1),
           targets = add_header_targets(body, t2),
           {:ok, ext_next} <- register_kind_targets(kpath, pkg, targets, state.raw_kinds, ext_acc) do
        {:cont, {:ok, ext_next}}
      else
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp add_header_targets(body, targets) do
    t1 = if is_binary(body["extends"]), do: MapSet.put(targets, body["extends"]), else: targets

    if is_binary(body["definedBy"]) and body["definedBy"] != @bootstrap_def_kind do
      MapSet.put(t1, body["definedBy"])
    else
      t1
    end
  end

  defp register_kind_targets(kpath, pkg, targets, raw_kinds, ext_acc) do
    Enum.reduce_while(targets, {:ok, ext_acc}, fn target, {:ok, acc} ->
      register_single_kind_target(kpath, pkg, target, raw_kinds, acc)
    end)
  end

  # A kind in another package may only be named if that package is imported:
  # the import is what pins it into this package's manifest.
  defp register_single_kind_target(kpath, pkg, target, raw_kinds, acc) do
    pkg_name = pkg["package"]
    imported = pkg |> Map.get("imports", %{}) |> Map.values()

    case Map.fetch(raw_kinds, target) do
      :error ->
        {:halt, {:error, {:unknown_kind_dependency, kpath, target}}}

      {:ok, {%{"package" => ^pkg_name}, _}} ->
        {:cont, {:ok, acc}}

      {:ok, {%{"package" => target_pkg}, _}} ->
        if target_pkg in imported do
          {:cont, {:ok, Map.update!(acc, pkg_name, &MapSet.put(&1, target))}}
        else
          {:halt, {:error, {:kind_reference_outside_imports, kpath, target, target_pkg}}}
        end
    end
  end

  defp collect_refs_in_node(kpath, map, raw_kinds, acc) when is_map(map) do
    with {:ok, acc1} <- maybe_inspect_ref_spec(kpath, map, raw_kinds, acc) do
      collect_refs_in_map_entries(kpath, map, raw_kinds, acc1)
    end
  end

  defp collect_refs_in_node(kpath, list, raw_kinds, acc) when is_list(list) do
    Enum.reduce_while(list, {:ok, acc}, fn item, {:ok, cur} ->
      case collect_refs_in_node(kpath, item, raw_kinds, cur) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp collect_refs_in_node(_kpath, _scalar, _raw_kinds, acc), do: {:ok, acc}

  defp collect_refs_in_map_entries(kpath, map, raw_kinds, acc) do
    Enum.reduce_while(map, {:ok, acc}, fn
      {"ref", _}, {:ok, cur} ->
        {:cont, {:ok, cur}}

      {_k, v}, {:ok, cur} ->
        case collect_refs_in_node(kpath, v, raw_kinds, cur) do
          {:ok, next} -> {:cont, {:ok, next}}
          {:error, _} = err -> {:halt, err}
        end
    end)
  end

  defp maybe_inspect_ref_spec(kpath, %{"ref" => ref_spec}, raw_kinds, acc)
       when is_map(ref_spec) do
    inspect_ref_spec(kpath, ref_spec, raw_kinds, acc)
  end

  defp maybe_inspect_ref_spec(_kpath, _map, _raw_kinds, acc), do: {:ok, acc}

  defp inspect_ref_spec(kpath, ref_spec, raw_kinds, acc) do
    allowed =
      MapSet.new([
        "bytes",
        "kind",
        "event",
        "evidence",
        "definition",
        "exact",
        "crossChain",
        "anyOf"
      ])

    unknown = ref_spec |> Map.keys() |> Enum.reject(&MapSet.member?(allowed, &1))

    with :ok <-
           if(unknown == [],
             do: :ok,
             else: {:error, {:unknown_ref_keys, kpath, Enum.sort(unknown)}}
           ),
         :ok <- check_ref_boolean_flags(kpath, ref_spec),
         :ok <- check_ref_single_mode(kpath, ref_spec),
         {:ok, acc1} <- inspect_ref_targets(kpath, "kind", ref_spec, raw_kinds, acc),
         {:ok, acc2} <- inspect_ref_targets(kpath, "event", ref_spec, raw_kinds, acc1) do
      inspect_ref_any_of(kpath, Map.get(ref_spec, "anyOf", []), raw_kinds, acc2)
    end
  end

  defp check_ref_boolean_flags(kpath, ref_spec) do
    bad =
      Enum.find(["bytes", "evidence", "definition", "exact", "crossChain"], fn flag ->
        Map.has_key?(ref_spec, flag) and not is_boolean(ref_spec[flag])
      end)

    if is_nil(bad), do: :ok, else: {:error, {:ref_flag_not_boolean, kpath, bad}}
  end

  defp check_ref_single_mode(kpath, ref_spec) do
    modes =
      ["bytes", "evidence", "definition", "kind", "event", "anyOf"]
      |> Enum.filter(&Map.has_key?(ref_spec, &1))

    false_flag? =
      Enum.any?(["bytes", "evidence", "definition"], &(Map.get(ref_spec, &1) == false))

    bad_any_of? =
      Map.has_key?(ref_spec, "anyOf") and
        (not is_list(ref_spec["anyOf"]) or ref_spec["anyOf"] == [])

    if length(modes) == 1 and not false_flag? and not bad_any_of? do
      :ok
    else
      {:error, {:invalid_ref_address_mode, kpath}}
    end
  end

  defp inspect_ref_targets(kpath, mode, ref_spec, raw_kinds, acc) do
    case Map.fetch(ref_spec, mode) do
      :error ->
        {:ok, acc}

      {:ok, val} ->
        targets = if is_binary(val), do: [val], else: val

        if is_list(targets) and targets != [] and Enum.all?(targets, &is_binary/1) do
          validate_each_ref_target(kpath, mode, targets, raw_kinds, acc)
        else
          {:error, {:invalid_ref_target_list, kpath, mode}}
        end
    end
  end

  defp validate_each_ref_target(_kpath, _mode, [], _raw_kinds, acc), do: {:ok, acc}

  defp validate_each_ref_target(kpath, mode, [t | rest], raw_kinds, acc) do
    if t == "*" or String.ends_with?(t, "/*") do
      validate_each_ref_target(kpath, mode, rest, raw_kinds, acc)
    else
      with :ok <- check_known_ref_target(kpath, mode, t, raw_kinds),
           :ok <- check_ref_kind_substrate(kpath, mode, t, raw_kinds) do
        validate_each_ref_target(kpath, mode, rest, raw_kinds, MapSet.put(acc, t))
      end
    end
  end

  defp check_known_ref_target(kpath, mode, t, raw_kinds) do
    if Map.has_key?(raw_kinds, t), do: :ok, else: {:error, {:unknown_ref_target, kpath, mode, t}}
  end

  defp check_ref_kind_substrate(kpath, "kind", target, raw_kinds) do
    case resolve_raw_substrate(target, raw_kinds, []) do
      {:ok, "resource"} -> :ok
      {:ok, other_sub} -> {:error, {:ref_kind_targets_non_resource, kpath, target, other_sub}}
      {:error, _} = err -> err
    end
  end

  defp check_ref_kind_substrate(_kpath, _event_mode, _target, _raw_kinds), do: :ok

  defp resolve_raw_substrate(kpath, raw_kinds, seen) do
    if kpath in seen do
      {:error, {:inheritance_cycle, seen ++ [kpath]}}
    else
      {_pkg, raw_body} = raw_kinds[kpath]
      resolve_raw_substrate_from_body(kpath, raw_body, raw_kinds, seen)
    end
  end

  defp resolve_raw_substrate_from_body(_kpath, %{"substrate" => sub}, _raw_kinds, _seen)
       when is_binary(sub) do
    {:ok, sub}
  end

  defp resolve_raw_substrate_from_body(kpath, raw_body, raw_kinds, seen) do
    parent = Map.get(raw_body, "extends")

    if is_binary(parent) and Map.has_key?(raw_kinds, parent) do
      resolve_raw_substrate(parent, raw_kinds, seen ++ [kpath])
    else
      {:error, {:missing_substrate, kpath}}
    end
  end

  defp inspect_ref_any_of(_kpath, [], _raw_kinds, acc), do: {:ok, acc}

  defp inspect_ref_any_of(kpath, [sub | rest], raw_kinds, acc) when is_map(sub) do
    case inspect_ref_spec(kpath, sub, raw_kinds, acc) do
      {:ok, acc1} -> inspect_ref_any_of(kpath, rest, raw_kinds, acc1)
      {:error, _} = err -> err
    end
  end

  defp inspect_ref_any_of(kpath, _bad, _raw_kinds, _acc),
    do: {:error, {:invalid_ref_any_of_entry, kpath}}

  # ---- Member Compilation ----

  defp compile_all_kinds(state) do
    sorted_paths = state.raw_kinds |> Map.keys() |> Enum.sort()
    ordered_paths = [@bootstrap_def_kind | List.delete(sorted_paths, @bootstrap_def_kind)]

    with {:ok, state1} <- compile_ordered_paths(ordered_paths, state),
         boot = state1.compiled[@bootstrap_def_kind],
         :ok <-
           validate_definition_against_metakind(
             @bootstrap_def_kind,
             boot.published_spec,
             boot.effective_schema,
             boot
           ) do
      {:ok, state1}
    end
  end

  defp compile_ordered_paths(ordered_paths, state) do
    Enum.reduce_while(ordered_paths, {:ok, state}, fn kpath, {:ok, st} ->
      case compile_one(st, kpath, []) do
        {:ok, _ck, st_next} -> {:cont, {:ok, st_next}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp compile_one(%__MODULE__{} = state, kpath, visiting) do
    cond do
      Map.has_key?(state.compiled, kpath) ->
        {:ok, state.compiled[kpath], state}

      kpath in visiting ->
        {:error, {:definition_dependency_cycle, visiting ++ [kpath]}}

      not Map.has_key?(state.raw_kinds, kpath) ->
        {:error, {:unknown_kind_reference, kpath}}

      true ->
        do_compile_one(state, kpath, visiting)
    end
  end

  defp do_compile_one(state, kpath, visiting) do
    {pkg, _raw} = state.raw_kinds[kpath]
    pkg_name = pkg["package"]
    is_foundation = pkg_name == state.foundation_pkg
    body = state.expanded_kinds[kpath]
    visiting_next = visiting ++ [kpath]

    with :ok <- validate_member_basics(kpath, pkg_name, is_foundation, body),
         {:ok, parent_ck, state2} <- maybe_compile_parent(state, body["extends"], visiting_next),
         {:ok, defined_by, def_ck, state3} <-
           resolve_defined_by(state2, kpath, body, parent_ck, visiting_next),
         {:ok, substrate} <- resolve_effective_substrate(kpath, body, parent_ck),
         {:ok, composed} <- compose_contract(kpath, is_foundation, body, parent_ck),
         :ok <-
           validate_schema_refs_post_compose(kpath, body, composed.eff_schema, state3.raw_kinds),
         {:ok, prop_bindings, prot_floors, state4} <-
           resolve_member_ref_bindings(
             state3,
             kpath,
             pkg_name,
             is_foundation,
             body,
             parent_ck,
             composed,
             visiting_next
           ),
         {:ok, dep_refs} <- merge_dependency_refs(kpath, composed.eff_schema, prop_bindings),
         published_spec =
           build_published_spec(state4, %{
             kpath: kpath,
             pkg_name: pkg_name,
             substrate: substrate,
             defined_by: defined_by,
             def_ck: def_ck,
             parent_ck: parent_ck,
             dep_refs: dep_refs,
             body: body
           }),
         :ok <-
           maybe_validate_against_metakind(kpath, published_spec, composed.eff_schema, def_ck),
         :ok <- check_signer_positions(kpath, composed.eff_schema, composed.eff_sigs) do
      rev_ref = definition_ref(state4, kpath)

      ck0 = %Kind{
        path: kpath,
        package: pkg_name,
        is_foundation: is_foundation,
        authored: body,
        published_spec: published_spec,
        manifest_ref: state4.manifests[pkg_name].ref,
        definition_ref: rev_ref,
        validator: Validate.prepare(composed.eff_schema),
        substrate: substrate,
        defined_by: defined_by,
        extends: body["extends"],
        effective_schema: composed.eff_schema,
        effective_naming: composed.eff_naming,
        effective_predicates: composed.eff_preds,
        effective_signatures: composed.eff_sigs,
        effective_requires_authority: composed.eff_req_auth,
        effective_terminal: composed.eff_term,
        protected_floors: prot_floors,
        protected_min_signatures: composed.prot_min_sigs,
        protected_naming: composed.prot_naming,
        protected_requires_authority: composed.prot_req_auth,
        protected_constraints: composed.prot_constraints,
        property_ref_bindings: prop_bindings
      }

      conforms = compute_conformance(state4, ck0, parent_ck)
      ck = %{ck0 | conforms_to: conforms}

      state5 = %{
        state4
        | compiled: Map.put(state4.compiled, kpath, ck),
          compiled_by_ref: Map.put(state4.compiled_by_ref, rev_ref, ck)
      }

      {:ok, ck, state5}
    end
  end

  defp definition_ref(state, kpath) do
    {pkg, _raw} = state.raw_kinds[kpath]
    "#{state.manifests[pkg["package"]].ref}##{kpath}"
  end

  defp validate_member_basics(kpath, pkg_name, is_foundation, body) do
    desc = Map.get(body, "description")

    cond do
      Map.has_key?(body, "protected") and not is_foundation ->
        {:error, {:non_foundation_protected_forbidden, kpath, pkg_name}}

      not is_binary(desc) or String.trim(desc) == "" ->
        {:error, {:missing_description, kpath}}

      not plain_map?(Map.get(body, "schema")) ->
        {:error, {:missing_schema_object, kpath}}

      true ->
        :ok
    end
  end

  defp maybe_compile_parent(state, nil, _visiting), do: {:ok, nil, state}

  defp maybe_compile_parent(state, parent_path, visiting) when is_binary(parent_path) do
    compile_one(state, parent_path, visiting)
  end

  defp resolve_defined_by(state, kpath, body, parent_ck, visiting) do
    with {:ok, boot_ck, state1} <- ensure_bootstrap_compiled(state, kpath, visiting) do
      defined_by = choose_defined_by(body, parent_ck, boot_ck)
      compile_defined_by_target(state1, kpath, defined_by, boot_ck, visiting)
    end
  end

  defp ensure_bootstrap_compiled(state, @bootstrap_def_kind, _visiting), do: {:ok, nil, state}

  defp ensure_bootstrap_compiled(state, _other, visiting),
    do: compile_one(state, @bootstrap_def_kind, visiting)

  defp choose_defined_by(body, parent_ck, boot_ck) do
    cond do
      Map.has_key?(body, "definedBy") ->
        body["definedBy"]

      not is_nil(parent_ck) and not is_nil(boot_ck) and
          not MapSet.member?(parent_ck.conforms_to, boot_ck.definition_ref) ->
        parent_ck.defined_by

      true ->
        @bootstrap_def_kind
    end
  end

  defp compile_defined_by_target(
         state,
         @bootstrap_def_kind,
         @bootstrap_def_kind,
         _boot_ck,
         _visiting
       ) do
    {:ok, @bootstrap_def_kind, nil, state}
  end

  defp compile_defined_by_target(_state, kpath, kpath, _boot_ck, _visiting) do
    {:error, {:self_defined_by_forbidden, kpath}}
  end

  defp compile_defined_by_target(state, kpath, defined_by, boot_ck, visiting) do
    with {:ok, def_ck, state1} <- compile_one(state, defined_by, visiting) do
      if MapSet.member?(def_ck.conforms_to, boot_ck.definition_ref) do
        {:ok, defined_by, def_ck, state1}
      else
        {:error, {:defined_by_not_kind_definition, kpath, defined_by}}
      end
    end
  end

  defp resolve_effective_substrate(kpath, body, parent_ck) do
    sub = Map.get(body, "substrate") || (parent_ck && parent_ck.substrate)

    cond do
      not is_binary(sub) or sub == "" ->
        {:error, {:missing_substrate, kpath}}

      not is_nil(parent_ck) and sub != parent_ck.substrate ->
        {:error, {:substrate_override_forbidden, kpath, parent_ck.substrate, sub}}

      true ->
        {:ok, sub}
    end
  end

  # ---- Contract Composition & Overrides ----

  defp compose_contract(kpath, is_foundation, body, parent_ck) do
    local_schema = Map.get(body, "schema", %{})

    with :ok <- validate_top_level_schema(kpath, local_schema),
         {:ok, base} <- compose_base_or_child(kpath, is_foundation, body, local_schema, parent_ck),
         {:ok, with_prot} <- register_foundation_protections(kpath, is_foundation, body, base),
         :ok <-
           check_effective_coherence(
             kpath,
             with_prot.eff_schema,
             with_prot.eff_naming,
             with_prot.eff_preds
           ) do
      {:ok, with_prot}
    end
  end

  defp validate_top_level_schema(kpath, local_schema) do
    allowed_root =
      MapSet.new([
        "type",
        "additionalProperties",
        "required",
        "properties" | Schema.object_constraints()
      ])

    extra = local_schema |> Map.keys() |> Enum.reject(&MapSet.member?(allowed_root, &1))

    cond do
      extra != [] or Map.get(local_schema, "type", "object") != "object" ->
        {:error, {:unsupported_top_level_schema, kpath}}

      Map.get(local_schema, "additionalProperties") == true ->
        {:error, {:top_level_additional_properties_true_forbidden, kpath}}

      true ->
        :ok
    end
  end

  defp compose_base_or_child(kpath, is_foundation, body, local_schema, nil) do
    if Map.has_key?(body, "overrides") do
      {:error, {:overrides_without_extends, kpath}}
    else
      with {:ok, eff_sigs} <- resolve_signatures(kpath, body, 1) do
        eff_schema =
          %{
            "additionalProperties" => false,
            "required" => Map.get(local_schema, "required", []),
            "properties" => Map.get(local_schema, "properties", %{})
          }
          |> copy_present_constraints(local_schema)

        eff_naming = Map.get(body, "naming", %{"mode" => "caller"})
        eff_preds = Map.get(body, "predicates", [])
        eff_req_auth = Map.get(body, "requiresAuthority", false) == true
        eff_term = Map.get(body, "terminal")

        {:ok,
         %{
           eff_schema: eff_schema,
           eff_naming: eff_naming,
           eff_preds: eff_preds,
           eff_sigs: eff_sigs,
           eff_req_auth: eff_req_auth,
           eff_term: eff_term,
           prot_floors: %{},
           prot_min_sigs: if(is_foundation, do: eff_sigs, else: 1),
           prot_naming: if(is_foundation, do: eff_naming, else: nil),
           prot_req_auth: if(is_foundation, do: eff_req_auth, else: false),
           prot_constraints: %{}
         }}
      end
    end
  end

  defp compose_base_or_child(
         kpath,
         is_foundation,
         body,
         local_schema,
         %Kind{} = parent_ck
       ) do
    with {:ok, eff_naming} <- inherit_or_override_naming(kpath, body, parent_ck),
         {:ok, eff_req_auth} <- inherit_or_override_req_auth(kpath, body, parent_ck),
         {:ok, eff_sigs} <- resolve_signatures(kpath, body, parent_ck.effective_signatures),
         :ok <- check_min_signatures_floor(kpath, eff_sigs, parent_ck.protected_min_signatures),
         {:ok, overridden} <-
           maybe_apply_overrides(
             kpath,
             Map.get(body, "overrides"),
             parent_ck.effective_schema,
             parent_ck.effective_predicates,
             parent_ck.effective_terminal,
             parent_ck.protected_floors,
             parent_ck.protected_constraints
           ),
         {:ok, eff_term} <-
           merge_terminal(kpath, body, overridden.eff_term, parent_ck.protected_constraints),
         {:ok, merged_schema} <- merge_child_schema(kpath, overridden.eff_schema, local_schema) do
      eff_preds = append_unique(overridden.eff_preds, Map.get(body, "predicates", []))

      prot_min_sigs =
        max(parent_ck.protected_min_signatures, if(is_foundation, do: eff_sigs, else: 1))

      {:ok,
       %{
         eff_schema: merged_schema,
         eff_naming: eff_naming,
         eff_preds: eff_preds,
         eff_sigs: eff_sigs,
         eff_req_auth: eff_req_auth,
         eff_term: eff_term,
         prot_floors: parent_ck.protected_floors,
         prot_min_sigs: prot_min_sigs,
         prot_naming: parent_ck.protected_naming,
         prot_req_auth: parent_ck.protected_requires_authority,
         prot_constraints: parent_ck.protected_constraints
       }}
    end
  end

  defp copy_present_constraints(base, local_schema) do
    Enum.reduce(Schema.object_constraints(), base, fn k, acc ->
      case Map.fetch(local_schema, k) do
        {:ok, v} -> Map.put(acc, k, v)
        :error -> acc
      end
    end)
  end

  defp check_signer_positions(kpath, schema, signatures) do
    case Schema.signer_positions_fit(schema, signatures) do
      :ok ->
        :ok

      {:error, {:exceeds, highest}} ->
        {:error, {:matches_signer_exceeds_signatures, kpath, highest, signatures}}

      {:error, {:unbound, position}} ->
        {:error, {:signer_position_unbound, kpath, position}}
    end
  end

  defp resolve_signatures(kpath, body, default_sigs) do
    case Map.fetch(body, "signatures") do
      :error -> {:ok, default_sigs}
      {:ok, n} when is_integer(n) and n >= 1 -> {:ok, n}
      {:ok, bad} -> {:error, {:invalid_signatures_count, kpath, bad}}
    end
  end

  defp check_min_signatures_floor(_kpath, eff_sigs, min_sigs) when eff_sigs >= min_sigs, do: :ok

  defp check_min_signatures_floor(kpath, eff_sigs, min_sigs) do
    {:error, {:weakened_protected_signatures, kpath, eff_sigs, min_sigs}}
  end

  defp inherit_or_override_naming(kpath, body, parent_ck) do
    case Map.fetch(body, "naming") do
      :error ->
        {:ok, parent_ck.effective_naming}

      {:ok, naming} ->
        if not is_nil(parent_ck.protected_naming) and naming != parent_ck.protected_naming do
          {:error, {:protected_naming_override_forbidden, kpath}}
        else
          {:ok, naming}
        end
    end
  end

  defp inherit_or_override_req_auth(kpath, body, parent_ck) do
    case Map.fetch(body, "requiresAuthority") do
      :error ->
        {:ok, parent_ck.effective_requires_authority}

      {:ok, val} ->
        cand = val == true

        if parent_ck.protected_requires_authority and not cand do
          {:error, {:protected_requires_authority_weakened, kpath}}
        else
          {:ok, cand}
        end
    end
  end

  defp maybe_apply_overrides(_kpath, nil, eff_schema, eff_preds, eff_term, _floors, _prot_con) do
    {:ok, %{eff_schema: eff_schema, eff_preds: eff_preds, eff_term: eff_term}}
  end

  defp maybe_apply_overrides(
         kpath,
         overrides,
         eff_schema,
         eff_preds,
         eff_term,
         prot_floors,
         prot_con
       )
       when is_map(overrides) do
    reason = Map.get(overrides, "reason", "")

    with :ok <-
           if(is_binary(reason) and String.trim(reason) != "",
             do: :ok,
             else: {:error, {:missing_override_reason, kpath}}
           ),
         {:ok, s1, preds1, term1} <-
           apply_drop_constraints(
             kpath,
             Map.get(overrides, "dropConstraints", []),
             eff_schema,
             eff_preds,
             eff_term,
             prot_con
           ),
         {:ok, s2} <- apply_drops(kpath, Map.get(overrides, "drop", []), s1, prot_floors),
         {:ok, s3} <- apply_optionals(kpath, Map.get(overrides, "optional", []), s2, prot_floors),
         {:ok, s4} <- apply_replaces(kpath, Map.get(overrides, "replace", %{}), s3, prot_floors) do
      {:ok, %{eff_schema: s4, eff_preds: preds1, eff_term: term1}}
    end
  end

  defp apply_drop_constraints(_kpath, [], schema, preds, term, _prot_con),
    do: {:ok, schema, preds, term}

  defp apply_drop_constraints(kpath, [sec | rest], schema, preds, term, prot_con) do
    cond do
      sec not in @droppable_constraints ->
        {:error, {:unknown_drop_constraint, kpath, sec}}

      Map.get(prot_con, sec, []) != [] ->
        {:error, {:protected_constraint_drop_forbidden, kpath, sec}}

      true ->
        apply_drop_constraint(kpath, sec, rest, schema, preds, term, prot_con)
    end
  end

  defp apply_drop_constraint(kpath, sec, rest, schema, preds, term, prot_con) do
    case sec do
      "predicates" ->
        apply_drop_constraints(kpath, rest, schema, [], term, prot_con)

      "terminal" ->
        apply_drop_constraints(kpath, rest, schema, preds, nil, prot_con)

      other ->
        apply_drop_constraints(kpath, rest, Map.delete(schema, other), preds, term, prot_con)
    end
  end

  defp apply_drops(_kpath, [], schema, _prot_floors), do: {:ok, schema}

  defp apply_drops(kpath, [prop | rest], schema, prot_floors) do
    cond do
      Map.has_key?(prot_floors, prop) ->
        {:error, {:protected_field_drop_forbidden, kpath, prop}}

      not Map.has_key?(schema["properties"], prop) ->
        {:error, {:drop_unknown_property, kpath, prop}}

      true ->
        next_schema =
          schema
          |> Map.put("properties", Map.delete(schema["properties"], prop))
          |> Map.put("required", List.delete(schema["required"], prop))
          |> maybe_delete_from_non_empty(prop)

        apply_drops(kpath, rest, next_schema, prot_floors)
    end
  end

  defp maybe_delete_from_non_empty(%{"nonEmpty" => ne} = schema, prop) do
    Map.put(schema, "nonEmpty", List.delete(ne, prop))
  end

  defp maybe_delete_from_non_empty(schema, _prop), do: schema

  defp apply_optionals(_kpath, [], schema, _prot_floors), do: {:ok, schema}

  defp apply_optionals(kpath, [prop | rest], schema, prot_floors) do
    cond do
      get_in(prot_floors, [prop, :required]) == true ->
        {:error, {:protected_required_field_optional_forbidden, kpath, prop}}

      not Map.has_key?(schema["properties"], prop) ->
        {:error, {:optional_unknown_property, kpath, prop}}

      prop not in schema["required"] ->
        {:error, {:optional_non_required_property, kpath, prop}}

      true ->
        apply_optionals(
          kpath,
          rest,
          Map.put(schema, "required", List.delete(schema["required"], prop)),
          prot_floors
        )
    end
  end

  defp apply_replaces(kpath, replace_map, schema, prot_floors) when is_map(replace_map) do
    Enum.reduce_while(replace_map, {:ok, schema}, fn {prop, replacement}, {:ok, cur_schema} ->
      cond do
        not Map.has_key?(cur_schema["properties"], prop) ->
          {:halt, {:error, {:replace_unknown_property, kpath, prop}}}

        Map.has_key?(prot_floors, prop) and
            not Schema.property_preserves?(replacement, prot_floors[prop].schema) ->
          {:halt, {:error, {:weakened_protected_field_floor, kpath, prop}}}

        true ->
          next_props = Map.put(cur_schema["properties"], prop, replacement)
          {:cont, {:ok, Map.put(cur_schema, "properties", next_props)}}
      end
    end)
  end

  defp merge_terminal(kpath, body, eff_term, prot_con) do
    case Map.fetch(body, "terminal") do
      :error ->
        {:ok, eff_term}

      {:ok, term} ->
        prot_terms = Map.get(prot_con, "terminal", [])

        if prot_terms != [] and term not in prot_terms do
          {:error, {:protected_terminal_override_forbidden, kpath}}
        else
          {:ok, term}
        end
    end
  end

  defp merge_child_schema(kpath, eff_schema, local_schema) do
    with {:ok, merged_props} <-
           merge_child_properties(
             kpath,
             eff_schema["properties"],
             Map.get(local_schema, "properties", %{})
           ),
         {:ok, merged_req} <-
           merge_child_required(
             kpath,
             eff_schema["required"],
             Map.get(local_schema, "required", []),
             merged_props
           ) do
      next_schema =
        eff_schema
        |> Map.put("properties", merged_props)
        |> Map.put("required", merged_req)
        |> merge_child_constraint_lists(local_schema)

      {:ok, next_schema}
    end
  end

  defp merge_child_properties(kpath, eff_props, local_props) do
    Enum.reduce_while(local_props, {:ok, eff_props}, fn {prop_name, prop_def}, {:ok, acc} ->
      case Map.fetch(acc, prop_name) do
        {:ok, ^prop_def} ->
          {:cont, {:ok, acc}}

        {:ok, _different} ->
          {:halt, {:error, {:implicit_property_shadowing, kpath, prop_name}}}

        :error ->
          {:cont, {:ok, Map.put(acc, prop_name, prop_def)}}
      end
    end)
  end

  defp merge_child_required(kpath, eff_req, local_req, merged_props) do
    Enum.reduce_while(local_req, {:ok, eff_req}, fn req_field, {:ok, acc} ->
      cond do
        not Map.has_key?(merged_props, req_field) ->
          {:halt, {:error, {:required_field_not_in_properties, kpath, req_field}}}

        req_field in acc ->
          {:cont, {:ok, acc}}

        true ->
          {:cont, {:ok, acc ++ [req_field]}}
      end
    end)
  end

  defp merge_child_constraint_lists(schema, local_schema) do
    Enum.reduce(Schema.object_constraints(), schema, fn list_key, acc ->
      case Map.fetch(local_schema, list_key) do
        :error -> acc
        {:ok, items} -> Map.put(acc, list_key, append_unique(Map.get(acc, list_key, []), items))
      end
    end)
  end

  defp append_unique(existing, additions) do
    Enum.reduce(additions, existing, fn item, acc ->
      if item in acc, do: acc, else: acc ++ [item]
    end)
  end

  defp register_foundation_protections(kpath, is_foundation, body, base) do
    base1 = maybe_freeze_foundation_constraints(base, is_foundation)

    Enum.reduce_while(Map.get(body, "protected", []), {:ok, base1}, fn prot_field, {:ok, cur} ->
      register_single_protected_field(cur, kpath, prot_field, is_foundation)
    end)
  end

  defp maybe_freeze_foundation_constraints(base, false), do: base

  defp maybe_freeze_foundation_constraints(base, true) do
    prot_con =
      Enum.reduce(Schema.object_constraints(), base.prot_constraints, fn sec, acc ->
        case Map.get(base.eff_schema, sec, []) do
          [] -> acc
          items -> Map.put(acc, sec, append_unique(Map.get(acc, sec, []), items))
        end
      end)
      |> maybe_protect_predicates(base.eff_preds)
      |> maybe_protect_terminal(base.eff_term)

    %{
      base
      | prot_naming: base.eff_naming,
        prot_req_auth: base.prot_req_auth or base.eff_req_auth,
        prot_constraints: prot_con
    }
  end

  defp register_single_protected_field(cur, kpath, prot_field, is_foundation) do
    if Map.has_key?(cur.eff_schema["properties"], prot_field) do
      next_floors = maybe_put_prot_floor(cur, prot_field, is_foundation)
      {:cont, {:ok, %{cur | prot_floors: next_floors}}}
    else
      {:halt, {:error, {:undeclared_protected_field, kpath, prot_field}}}
    end
  end

  defp maybe_put_prot_floor(cur, prot_field, true) do
    Map.put_new_lazy(cur.prot_floors, prot_field, fn ->
      %{
        required: prot_field in cur.eff_schema["required"],
        schema: cur.eff_schema["properties"][prot_field],
        ref_bindings: %{}
      }
    end)
  end

  defp maybe_put_prot_floor(cur, _prot_field, false), do: cur.prot_floors

  defp maybe_protect_predicates(prot_con, []), do: prot_con

  defp maybe_protect_predicates(prot_con, preds) do
    Map.put(prot_con, "predicates", append_unique(Map.get(prot_con, "predicates", []), preds))
  end

  defp maybe_protect_terminal(prot_con, nil), do: prot_con
  defp maybe_protect_terminal(prot_con, term), do: Map.put(prot_con, "terminal", [term])

  defp check_effective_coherence(kpath, eff_schema, eff_naming, eff_preds) do
    with :ok <- Schema.check_coherence(eff_schema, "#{kpath}.schema"),
         :ok <- check_derived_naming(kpath, eff_naming, eff_schema) do
      check_predicates_syntax(kpath, eff_preds)
    end
  end

  defp check_derived_naming(kpath, %{"mode" => "derived"} = naming, eff_schema) do
    tmpl = Map.get(naming, "derive", "")
    fields = Regex.scan(@derive_field_re, tmpl, capture: :all_but_first) |> List.flatten()

    if fields == [] do
      {:error, {:missing_derive_template_fields, kpath}}
    else
      props = eff_schema["properties"]
      req = eff_schema["required"]

      bad =
        Enum.find(fields, fn f ->
          get_in(props, [f, "type"]) != "string" or f not in req
        end)

      if is_nil(bad), do: :ok, else: {:error, {:invalid_derive_field, kpath, bad}}
    end
  end

  defp check_derived_naming(_kpath, _other_naming, _eff_schema), do: :ok

  defp check_predicates_syntax(_kpath, []), do: :ok

  defp check_predicates_syntax(kpath, [pred | rest]) do
    cond do
      not is_map(pred) or not Map.has_key?(pred, "id") or not Map.has_key?(pred, "check") ->
        {:error, {:malformed_predicate, kpath}}

      pred["check"] not in ["schemaPropertyType", "schemaPropertyExists"] ->
        {:error, {:unsupported_predicate_check, kpath, pred["check"]}}

      true ->
        check_predicates_syntax(kpath, rest)
    end
  end

  # ---- Per-Property Definition Reference Bindings ----

  defp validate_schema_refs_post_compose(kpath, body, eff_schema, raw_kinds) do
    replace_map = get_in(body, ["overrides", "replace"]) || %{}

    with {:ok, _} <-
           collect_refs_in_node(kpath, Map.get(body, "schema", %{}), raw_kinds, MapSet.new()),
         {:ok, _} <- collect_refs_in_node(kpath, replace_map, raw_kinds, MapSet.new()),
         {:ok, _} <- collect_refs_in_node(kpath, eff_schema, raw_kinds, MapSet.new()) do
      :ok
    end
  end

  defp resolve_member_ref_bindings(
         state,
         kpath,
         pkg_name,
         is_foundation,
         body,
         nil,
         composed,
         visiting
       ) do
    with {:ok, prop_bindings, state1} <-
           resolve_props_map(
             state,
             kpath,
             pkg_name,
             composed.eff_schema["properties"],
             visiting,
             %{}
           ) do
      floors =
        attach_foundation_floor_bindings(is_foundation, body, composed.prot_floors, prop_bindings)

      {:ok, prop_bindings, floors, state1}
    end
  end

  defp resolve_member_ref_bindings(
         state,
         kpath,
         pkg_name,
         is_foundation,
         body,
         %Kind{} = parent_ck,
         composed,
         visiting
       ) do
    overrides = Map.get(body, "overrides") || %{}
    drops = Map.get(overrides, "drop", [])
    replaces = Map.get(overrides, "replace", %{})

    inherited_props =
      parent_ck.effective_schema["properties"]
      |> Map.keys()
      |> MapSet.new()
      |> MapSet.difference(MapSet.new(drops))

    bindings0 = Map.drop(parent_ck.property_ref_bindings, drops)

    with {:ok, bindings1, state1} <-
           resolve_replace_bindings(
             state,
             kpath,
             pkg_name,
             replaces,
             composed.prot_floors,
             visiting,
             bindings0
           ),
         local_only_props =
           body
           |> get_in(["schema", "properties"])
           |> Kernel.||(%{})
           |> Enum.reject(fn {p, _} -> MapSet.member?(inherited_props, p) end),
         {:ok, bindings2, state2} <-
           resolve_props_map(state1, kpath, pkg_name, local_only_props, visiting, bindings1) do
      floors =
        attach_foundation_floor_bindings(is_foundation, body, composed.prot_floors, bindings2)

      {:ok, bindings2, floors, state2}
    end
  end

  defp resolve_props_map(state, kpath, pkg_name, props_enum, visiting, acc) do
    Enum.reduce_while(props_enum, {:ok, acc, state}, fn {prop_name, prop_schema},
                                                        {:ok, b_acc, st} ->
      case resolve_property_refs(st, kpath, pkg_name, prop_schema, visiting) do
        {:ok, resolved, st_next} when map_size(resolved) == 0 ->
          {:cont, {:ok, b_acc, st_next}}

        {:ok, resolved, st_next} ->
          {:cont, {:ok, Map.put(b_acc, prop_name, resolved), st_next}}

        {:error, _} = err ->
          {:halt, err}
      end
    end)
  end

  defp resolve_replace_bindings(state, kpath, pkg_name, replaces, prot_floors, visiting, acc) do
    Enum.reduce_while(replaces, {:ok, acc, state}, fn {prop, repl_schema}, {:ok, b_acc, st} ->
      resolve_single_replace_binding(
        st,
        kpath,
        pkg_name,
        prop,
        repl_schema,
        prot_floors,
        visiting,
        b_acc
      )
    end)
  end

  defp resolve_single_replace_binding(
         st,
         kpath,
         pkg_name,
         prop,
         repl_schema,
         prot_floors,
         visiting,
         b_acc
       ) do
    with {:ok, resolved, st1} <-
           resolve_property_refs(st, kpath, pkg_name, repl_schema, visiting),
         :ok <- check_protected_ref_rebind(kpath, prop, resolved, prot_floors) do
      next_acc =
        if map_size(resolved) == 0,
          do: Map.delete(b_acc, prop),
          else: Map.put(b_acc, prop, resolved)

      {:cont, {:ok, next_acc, st1}}
    else
      {:error, _} = err -> {:halt, err}
    end
  end

  defp check_protected_ref_rebind(kpath, prop, resolved, prot_floors) do
    case Map.fetch(prot_floors, prop) do
      {:ok, %{ref_bindings: floor_bindings}} when floor_bindings != resolved ->
        {:error, {:protected_ref_rebind_forbidden, kpath, prop}}

      _ ->
        :ok
    end
  end

  defp attach_foundation_floor_bindings(false, _body, prot_floors, _prop_bindings),
    do: prot_floors

  defp attach_foundation_floor_bindings(true, body, prot_floors, prop_bindings) do
    Enum.reduce(Map.get(body, "protected", []), prot_floors, fn prot_field, acc ->
      case Map.fetch(acc, prot_field) do
        {:ok, floor} ->
          Map.put(acc, prot_field, %{
            floor
            | ref_bindings: Map.get(prop_bindings, prot_field, %{})
          })

        :error ->
          acc
      end
    end)
  end

  defp resolve_property_refs(state, kpath, pkg_name, prop_schema, visiting) do
    with {:ok, targets} <- collect_refs_in_node(kpath, prop_schema, state.raw_kinds, MapSet.new()) do
      targets
      |> Enum.sort()
      |> Enum.reduce_while({:ok, %{}, state}, fn rtarget, {:ok, b_acc, st} ->
        resolve_single_property_ref(st, pkg_name, rtarget, visiting, b_acc)
      end)
    end
  end

  # The target's package is this one or one it imports, so its manifest
  # already exists and the reference needs nothing compiled.
  defp resolve_single_property_ref(st, _pkg_name, rtarget, _visiting, b_acc) do
    {:cont, {:ok, Map.put(b_acc, rtarget, definition_ref(st, rtarget)), st}}
  end

  defp merge_dependency_refs(kpath, eff_schema, prop_bindings) do
    eff_schema["properties"]
    |> Map.keys()
    |> Enum.sort()
    |> Enum.reduce_while({:ok, %{}}, fn prop_name, {:ok, dep_acc} ->
      prop_refs = Map.get(prop_bindings, prop_name, %{})

      case merge_prop_dependency_refs(kpath, prop_refs, dep_acc) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp merge_prop_dependency_refs(kpath, prop_refs, dep_acc) do
    Enum.reduce_while(prop_refs, {:ok, dep_acc}, fn {rtarget, def_ref}, {:ok, cur} ->
      case Map.fetch(cur, rtarget) do
        {:ok, ^def_ref} ->
          {:cont, {:ok, cur}}

        {:ok, other_ref} ->
          {:halt, {:error, {:conflicting_dependency_ref, kpath, rtarget, other_ref, def_ref}}}

        :error ->
          {:cont, {:ok, Map.put(cur, rtarget, def_ref)}}
      end
    end)
  end

  defp build_published_spec(state, %{
         kpath: kpath,
         pkg_name: pkg_name,
         substrate: substrate,
         defined_by: defined_by,
         def_ck: def_ck,
         parent_ck: parent_ck,
         dep_refs: dep_refs,
         body: body
       }) do
    [group, version, kind_name] = String.split(kpath, "/", parts: 3)

    pins =
      %{"manifestRef" => state.manifests[pkg_name].ref}
      |> maybe_put_pin(
        "definedByRef",
        defined_by != @bootstrap_def_kind and not is_nil(def_ck),
        fn ->
          def_ck.definition_ref
        end
      )
      |> maybe_put_pin("extendsRef", not is_nil(parent_ck), fn -> parent_ck.definition_ref end)
      |> maybe_put_pin("dependencyRefs", map_size(dep_refs) > 0, fn -> dep_refs end)

    base_spec =
      %{
        "group" => group,
        "version" => version,
        "kind" => kind_name,
        "substrate" => substrate,
        "description" => body["description"],
        "schema" => body["schema"],
        "pins" => pins
      }
      |> maybe_put_pin("definedBy", defined_by != @bootstrap_def_kind, fn -> defined_by end)
      |> copy_optional_kinddef_keys(body)
      |> inherit_metakind_fields(parent_ck, defined_by, def_ck)

    Enum.reduce(body, base_spec, fn {k, v}, acc ->
      if MapSet.member?(@base_kinddef_keys, k), do: acc, else: Map.put(acc, k, v)
    end)
  end

  defp maybe_put_pin(map, key, true, fun), do: Map.put(map, key, fun.())
  defp maybe_put_pin(map, _key, false, _fun), do: map

  defp copy_optional_kinddef_keys(spec, body) do
    Enum.reduce(
      [
        "extends",
        "derivedFrom",
        "protected",
        "overrides",
        "naming",
        "epistemicScope",
        "predicates",
        "signatures",
        "requiresAuthority",
        "terminal"
      ],
      spec,
      fn k, acc ->
        case Map.fetch(body, k) do
          {:ok, v} -> Map.put(acc, k, v)
          :error -> acc
        end
      end
    )
  end

  defp inherit_metakind_fields(
         spec,
         %Kind{} = parent_ck,
         defined_by,
         %Kind{} = def_ck
       )
       when defined_by != @bootstrap_def_kind do
    Enum.reduce(Map.keys(def_ck.effective_schema["properties"]), spec, fn m_key, acc ->
      if not MapSet.member?(@base_kinddef_keys, m_key) and
           Map.has_key?(parent_ck.published_spec, m_key) do
        Map.put(acc, m_key, parent_ck.published_spec[m_key])
      else
        acc
      end
    end)
  end

  defp inherit_metakind_fields(spec, _parent_ck, _defined_by, _def_ck), do: spec

  # ---- Meta-Kind Recursive Validation & Predicates ----

  defp maybe_validate_against_metakind(_kpath, _published_spec, _eff_schema, nil), do: :ok

  defp maybe_validate_against_metakind(
         kpath,
         published_spec,
         eff_schema,
         %Kind{} = def_ck
       ) do
    validate_definition_against_metakind(kpath, published_spec, eff_schema, def_ck)
  end

  defp validate_definition_against_metakind(kpath, published_spec, target_eff_schema, meta_ck) do
    case Validate.validate(meta_ck.validator, published_spec) do
      :ok ->
        evaluate_metakind_predicates(
          kpath,
          published_spec,
          target_eff_schema,
          meta_ck.effective_predicates
        )

      {:error, violations} ->
        {:error, {:definition_violates_meta_kind, kpath, meta_ck.path, violations}}
    end
  end

  defp evaluate_metakind_predicates(_kpath, _published_spec, _target_schema, []), do: :ok

  defp evaluate_metakind_predicates(kpath, published_spec, target_schema, [pred | rest]) do
    case evaluate_single_predicate(kpath, published_spec, target_schema, pred) do
      :ok -> evaluate_metakind_predicates(kpath, published_spec, target_schema, rest)
      {:error, _} = err -> err
    end
  end

  defp evaluate_single_predicate(
         kpath,
         published_spec,
         target_schema,
         %{
           "check" => "schemaPropertyType",
           "id" => id,
           "fieldFrom" => field_from,
           "expectedType" => exp_type
         } =
           pred
       ) do
    cur = resolve_dot_path(published_spec, field_from)
    props = target_schema["properties"]

    cond do
      not is_binary(cur) or not Map.has_key?(props, cur) ->
        {:error, {:predicate_property_missing, kpath, id, field_from, cur}}

      Map.get(props[cur], "type") != exp_type ->
        {:error,
         {:predicate_property_wrong_type, kpath, id, cur, exp_type, Map.get(props[cur], "type")}}

      Map.get(pred, "mustBeRequired") == true and cur not in target_schema["required"] ->
        {:error, {:predicate_property_not_required, kpath, id, cur}}

      true ->
        :ok
    end
  end

  defp evaluate_single_predicate(
         kpath,
         published_spec,
         target_schema,
         %{"check" => "schemaPropertyExists", "id" => id, "fieldFrom" => field_from} = pred
       ) do
    cur = resolve_dot_path(published_spec, field_from)

    cond do
      is_nil(cur) and Map.get(pred, "allowUnset") == true ->
        :ok

      is_binary(cur) and Map.has_key?(target_schema["properties"], cur) ->
        :ok

      true ->
        {:error, {:predicate_property_missing, kpath, id, field_from, cur}}
    end
  end

  defp evaluate_single_predicate(kpath, _published_spec, _target_schema, pred) do
    {:error, {:unsupported_predicate_check, kpath, Map.get(pred, "check")}}
  end

  defp resolve_dot_path(obj, dotted) when is_binary(dotted) do
    dotted
    |> String.split(".")
    |> Enum.reduce(obj, fn
      part, cur when is_map(cur) -> Map.get(cur, part)
      _part, _non_map -> nil
    end)
  end

  # ---- Inductive `conformsTo` Preservation ----

  defp compute_conformance(_state, %Kind{definition_ref: rev}, nil) do
    MapSet.new([rev])
  end

  defp compute_conformance(
         state,
         %Kind{definition_ref: rev} = ck,
         %Kind{} = parent_ck
       ) do
    preserved_ancestors =
      Enum.filter(parent_ck.conforms_to, fn anc_ref ->
        anc = state.compiled_by_ref[anc_ref]
        preserves_ancestor?(state, ck, anc)
      end)

    MapSet.new([rev | preserved_ancestors])
  end

  defp preserves_ancestor?(state, child, anc) do
    header_preserved?(state, child, anc) and
      schema_and_bindings_preserved?(child, anc)
  end

  defp header_preserved?(state, child, anc) do
    child.substrate == anc.substrate and
      child.effective_signatures >= anc.effective_signatures and
      child.effective_naming == anc.effective_naming and
      not (anc.effective_requires_authority and not child.effective_requires_authority) and
      (is_nil(anc.effective_terminal) or child.effective_terminal == anc.effective_terminal) and
      metakind_contract_preserved?(state, child, anc)
  end

  defp metakind_contract_preserved?(_state, _child, %Kind{defined_by: @bootstrap_def_kind}),
    do: true

  defp metakind_contract_preserved?(state, child, anc) do
    child_meta = state.compiled[child.defined_by]
    anc_meta = state.compiled[anc.defined_by]

    MapSet.member?(child_meta.conforms_to, anc_meta.definition_ref) and
      Enum.all?(Map.keys(anc_meta.effective_schema["properties"]), fn m_key ->
        MapSet.member?(@base_kinddef_keys, m_key) or
          Map.get(child.published_spec, m_key) == Map.get(anc.published_spec, m_key)
      end)
  end

  defp schema_and_bindings_preserved?(child, anc) do
    c_schema = child.effective_schema
    a_schema = anc.effective_schema

    closed_ok? =
      Map.get(a_schema, "additionalProperties") != false or
        Map.get(c_schema, "additionalProperties") == false

    preds_ok? = Enum.all?(anc.effective_predicates, &(&1 in child.effective_predicates))

    props_ok? =
      Enum.all?(a_schema["properties"], fn {prop_name, a_prop} ->
        c_prop = Map.get(c_schema["properties"], prop_name)

        not is_nil(c_prop) and
          Schema.property_preserves?(c_prop, a_prop) and
          Map.get(child.property_ref_bindings, prop_name, %{}) ==
            Map.get(anc.property_ref_bindings, prop_name, %{})
      end)

    closed_ok? and
      Schema.constraints_preserved?(c_schema, a_schema) and
      preds_ok? and
      props_ok?
  end
end
