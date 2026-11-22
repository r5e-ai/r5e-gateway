defmodule Recurse.Provenance.Grammar do
  @moduledoc """
  Definitions written in the definition grammar: compile them, identify them
  by content, and check record bodies against them.

  A definition package is a HUML document that declares kinds. A kind states
  the shape of a record body, may extend another kind, and is identified by
  the content of the package it is written in rather than by who published
  it. This module is the entry point to all of that; the modules beneath it
  (`Huml`, `Compiler`, `Schema`, `Validate`) are its parts.

      {:ok, compiled} = Grammar.compile([{"core.huml", core}, {"mine.huml", mine}])
      {:ok, %{ref: ref}} = Grammar.manifest(compiled, "my.package")
      :ok = Grammar.validate(compiled, "my.group/v1/Thing", body)

  ## Identity

  Each package has a manifest: the package exactly as authored, plus the
  manifest reference of every package it imports. `manifest/2` returns the
  manifest's canonical bytes and their `bytes:sha256:<hex>` reference. A kind
  is referred to as `<manifest ref>#<group>/<version>/<Kind>`. The same
  sources always produce the same bytes and references; `Compiler` documents
  the manifest's exact shape and everything the compiler enforces.

  ## Checking a body

  `validate/4` returns `:ok` or every rule the body breaks, each as
  `%{path: path, code: code}`, sorted by path and then code. Paths start at
  `$` (`$.size`, `$.items[0]`). A code is a fixed word, so that another
  implementation of the grammar can report exactly the same thing:

    * `unknown_kind`: the compilation has no kind at that kind path
    * `wrong_type`
    * `enum_mismatch`
    * `pattern_mismatch`
    * `signer_mismatch`
    * `not_a_public_key`
    * `not_the_key_id_of`
    * `invalid_timestamp`
    * `integer_out_of_range`
    * `below_minimum`
    * `above_maximum`
    * `too_long`
    * `duplicate_item`
    * `key_mismatch`
    * `too_many_entries`
    * `unexpected_property`
    * `missing_required`
    * `missing_conditional`
    * `empty_value`
    * `out_of_order`
    * `not_exactly_one`
    * `more_than_one`
    * `envelope_required`
    * `cross_chain_forbidden`
    * `malformed_cross_chain_ref`
    * `expected_bytes_ref`
    * `expected_event_ref`
    * `expected_evidence_ref`
    * `expected_definition_ref`
    * `expected_resource_ref`
    * `ref_alternatives_mismatch`

  `Validate` says what each one means and where it is reported.

  The check decides shape only. It does not look anything up, so it does not
  decide whether a reference resolves, whether a referenced record is of the
  kind a `ref` names, or anything about who signed the record.

  ## Cost

  Compiling parses, hashes and prepares everything, including every regular
  expression. Checking a body afterwards compiles nothing and involves no
  process: a compilation is plain data that any number of processes can read
  at once. It holds compiled regular expressions, so keep it in memory (a
  variable, ETS, `:persistent_term`) and compile again in another VM rather
  than serialising it.
  """

  alias Recurse.Provenance.Grammar.{Compiler, Huml, Validate}

  @typedoc "The result of `compile/1`. Treat it as opaque and pass it back in."
  @type compiled :: Compiler.t()

  @typedoc """
  A compiled kind.

    * `path`: its kind path, `<group>/<version>/<Kind>`
    * `package`: the name of the package that declares it
    * `manifest_ref`: the reference of that package's manifest
    * `definition_ref`: `<manifest_ref>#<path>`
    * `extends`: the kind path of its parent, or `nil`
    * `defined_by`: the kind path of the meta-kind it is checked against
    * `conforms_to`: the definition references, its own included, whose
      guarantees it keeps, sorted
    * `schema`: its hydrated schema, with every ancestor, override and
      `use:` type applied
    * `substrate`, `naming`, `signatures`, `requires_authority`, `terminal`:
      the rest of its hydrated contract. These are rules about a record's
      envelope and lifecycle, for the caller that has those to enforce; the
      body check does not read them.
  """
  @type kind :: %{
          path: String.t(),
          package: String.t(),
          manifest_ref: String.t(),
          definition_ref: String.t(),
          extends: String.t() | nil,
          defined_by: String.t(),
          conforms_to: [String.t()],
          schema: map(),
          substrate: String.t(),
          naming: map(),
          signatures: pos_integer(),
          requires_authority: boolean(),
          terminal: map() | nil
        }

  @type violation :: %{path: String.t(), code: String.t()}

  @doc """
  Parses and compiles a set of packages together.

  `sources` is a list of `{name, huml}`. `name` only labels the source in a
  parse error (a file name is a good choice); a package is known afterwards
  by the `package` name it declares. The set must be complete: every
  imported package must be in it, and exactly one must be the foundation.

  Errors are `{:error, {:source, name, reason}}` when a source does not
  parse, and otherwise the compiler's `{:error, reason}`.
  """
  @spec compile([{name :: String.t(), huml :: binary()}]) :: {:ok, compiled()} | {:error, term()}
  def compile(sources) when is_list(sources) do
    with {:ok, packages} <- decode_sources(sources, []) do
      Compiler.compile_packages(packages)
    end
  end

  @doc """
  The manifest of a package, by its declared package name: the canonical
  bytes and their `bytes:sha256:<hex>` reference.
  """
  @spec manifest(compiled(), String.t()) :: {:ok, %{bytes: binary(), ref: String.t()}} | :error
  def manifest(%Compiler{manifests: manifests}, package_name) do
    case manifests do
      %{^package_name => %{bytes: bytes, ref: ref}} -> {:ok, %{bytes: bytes, ref: ref}}
      _ -> :error
    end
  end

  @doc """
  A compiled kind, by kind path.
  """
  @spec kind(compiled(), String.t()) :: {:ok, kind()} | :error
  def kind(%Compiler{compiled: compiled}, kind_path) do
    case compiled do
      %{^kind_path => ck} ->
        {:ok,
         %{
           path: ck.path,
           package: ck.package,
           manifest_ref: ck.manifest_ref,
           definition_ref: ck.definition_ref,
           extends: ck.extends,
           defined_by: ck.defined_by,
           conforms_to: Enum.sort(ck.conforms_to),
           schema: ck.effective_schema,
           substrate: ck.substrate,
           naming: ck.effective_naming,
           signatures: ck.effective_signatures,
           requires_authority: ck.effective_requires_authority,
           terminal: ck.effective_terminal
         }}

      _ ->
        :error
    end
  end

  @doc """
  Every kind path in the compilation, sorted.
  """
  @spec kinds(compiled()) :: [String.t()]
  def kinds(%Compiler{compiled: compiled}), do: compiled |> Map.keys() |> Enum.sort()

  @doc """
  Checks a decoded record body against a kind.

  `body` is decoded JSON: maps with string keys, lists, strings, integers and
  booleans. The one option is `:envelope`, a map of the record's envelope
  fields, needed only by kinds with a rule that depends on the envelope;
  without it such a rule reports `envelope_required`.
  """
  @spec validate(compiled(), String.t(), term(), keyword()) :: :ok | {:error, [violation()]}
  def validate(%Compiler{compiled: compiled}, kind_path, body, opts \\ []) do
    case compiled do
      %{^kind_path => %{validator: plan}} -> Validate.validate(plan, body, opts)
      _ -> {:error, [%{path: "$", code: "unknown_kind"}]}
    end
  end

  defp decode_sources([], acc), do: {:ok, Enum.reverse(acc)}

  defp decode_sources([{name, huml} | rest], acc) when is_binary(name) and is_binary(huml) do
    case Huml.decode(huml) do
      {:ok, package} -> decode_sources(rest, [package | acc])
      {:error, reason} -> {:error, {:source, name, reason}}
    end
  end

  defp decode_sources([other | _rest], _acc), do: {:error, {:invalid_source, other}}
end
