defmodule Recurse.Provenance.Definitions do
  @moduledoc """
  The installed base definitions of `provenance.r5e.io/v2`, and the check
  of a record's body against the definition it cites.

  ## What a record cites

  A record's `schemaRef` is the content reference of one **definition
  document**: the complete definition of one kind, with every ancestor,
  override and shared type already applied. Nothing has to be resolved
  to read it, so checking a body needs a small validator and no
  knowledge of inheritance. Each kind has its own document and its own
  reference.

      {"format": "r5e.kind-definition/v1",
       "kind": "provenance.r5e.io/v2/ToolCall",
       "description": "…",
       "substrate": "artifact",
       "naming": {…}, "signatures": 1, "requiresAuthority": false,
       "schema": {…the whole shape of the body…},
       "extends": "bytes:sha256:…",
       "conformsTo": ["bytes:sha256:…"]}

  `extends` is the reference of the parent kind's document, and
  `conformsTo` lists the documents of every ancestor whose guarantees
  this kind still keeps, so "is this an Artifact" is a lookup.

  ## How it is written

  Nobody writes those documents by hand. Kinds are authored in packages
  in the definition grammar (`Recurse.Provenance.Grammar`), where a kind
  states only what it adds to its parent; the packages live in
  `priv/definitions`. `expand/1` turns a compiled set of packages into
  the documents. A document does not name the package it came from, so
  adding or changing one kind never changes another kind's reference.

  The base packages are compiled and expanded once per VM, on first use.
  A document beyond the base set (an extension kind) is read from bytes
  the caller supplies and used only if they hash to the cited reference.

  The schemas for the envelope, the signed wrapper, a capture profile,
  an epoch manifest and an export bundle are fixed parts of the wire
  format, not kind definitions, and remain JSON Schema documents here.
  """

  alias Recurse.Provenance.{Grammar, Ref, Schema}
  alias Recurse.Provenance.Grammar.{Compiler, Validate}
  alias Recurse.Provenance.Grammar.Schema, as: GrammarSchema
  alias RecurseVerify.Canonical

  @api_version "provenance.r5e.io/v2"
  @kinds ~w[ModelCall ModelResponse ToolCall ToolResult PolicyDecision SessionOpened
            SessionClosed Observation PublishedView EpochSeal Checkpoint RetentionHold
            RetentionHoldRelease PayloadDisposition Disclosure Verification
            DefinitionPublished Principal Endorsement Badge Succession Revocation
            ChainStarted Deployment RootsChanged RootChangeApproval]
  @recorder_only ~w[EpochSeal Checkpoint]
  @document_format "r5e.kind-definition/v1"

  @packages_dir Path.expand("../../../priv/definitions", __DIR__)
  @package_files ~w[r5e.core.huml r5e.provenance.huml]
  for file <- @package_files, do: @external_resource(Path.join(@packages_dir, file))
  @package_sources Enum.map(@package_files, &{&1, File.read!(Path.join(@packages_dir, &1))})

  @dir Path.expand("../../../priv/schemas", __DIR__)
  @files ~w[common bodies capture-profile epoch-manifest export signed-evidence evidence-envelope]

  for file <- @files, do: @external_resource(Path.join(@dir, file <> ".schema.json"))

  @sources Map.new(@files, fn file ->
             name = file <> ".schema.json"
             {name, @dir |> Path.join(name) |> File.read!() |> Jason.decode!()}
           end)

  bundle! = fn entry ->
    {:ok, doc} = Schema.bundle(entry, @sources)
    :ok = Schema.check(doc)
    doc
  end

  @envelope bundle!.("evidence-envelope.schema.json")
  @signed bundle!.("signed-evidence.schema.json")
  @profile bundle!.("capture-profile.schema.json")
  @manifest bundle!.("epoch-manifest.schema.json")
  @export bundle!.("export.schema.json")

  @typedoc "A function that returns the bytes behind a `bytes:` reference."
  @type fetch_bytes :: (Ref.t() -> {:ok, binary()} | :error)

  @typedoc "One rule a body breaks: where, and a fixed word for which rule."
  @type violation :: %{path: String.t(), code: String.t()}

  @doc "The base API group and version."
  @spec api_version() :: String.t()
  def api_version, do: @api_version

  @doc "`<apiVersion>/<kind>`, the name of a definition."
  @spec kind_path(String.t(), String.t()) :: String.t()
  def kind_path(api_version, kind), do: api_version <> "/" <> kind

  @doc "The base kind names."
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds

  @doc "Whether a base kind may only be issued by the recorder itself."
  @spec recorder_only?(String.t()) :: boolean()
  def recorder_only?(kind_path),
    do: kind_path in Enum.map(@recorder_only, &(@api_version <> "/" <> &1))

  @doc "The compiled base packages. Compiled on first use and kept."
  @spec compiled() :: Grammar.compiled()
  def compiled, do: base().compiled

  @doc """
  The definition document of every kind in the base packages, Core's
  included: kind path, exact bytes and reference. A deployment holds
  these so an export can carry the ones its records cite.
  """
  @spec documents() :: [%{kind_path: String.t(), ref: Ref.t(), bytes: binary()}]
  def documents do
    for {path, %{ref: ref, bytes: bytes}} <- Enum.sort(base().documents),
        do: %{kind_path: path, ref: ref, bytes: bytes}
  end

  @doc """
  The manifests of the authored base packages, Core first. These are
  what a publication names; no record cites them.
  """
  @spec manifests() :: [%{package: String.t(), ref: Ref.t(), bytes: binary()}]
  def manifests, do: base().manifests

  @doc "The kind-path to `schemaRef` map a capture profile carries."
  @spec schema_refs() :: %{String.t() => Ref.t()}
  def schema_refs do
    documents = base().documents
    Map.new(@kinds, &{@api_version <> "/" <> &1, documents[@api_version <> "/" <> &1].ref})
  end

  @doc "The definition of a base-package kind: its `schemaRef`, bytes and document."
  @spec fetch(String.t()) :: {:ok, %{ref: Ref.t(), bytes: binary(), document: map()}} | :error
  def fetch(kind_path) do
    case base().documents do
      %{^kind_path => %{ref: ref, bytes: bytes, document: document}} ->
        {:ok, %{ref: ref, bytes: bytes, document: document}}

      _ ->
        :error
    end
  end

  @doc "Whether `ref` is the reference of a base definition document."
  @spec base_document?(Ref.t()) :: boolean()
  def base_document?(ref), do: is_map_key(base().by_ref, ref)

  @doc """
  Turn compiled packages into definition documents, one per kind.
  Returns each kind path with its document, the document's canonical
  bytes and their reference.
  """
  @spec expand(Grammar.compiled()) ::
          %{String.t() => %{ref: Ref.t(), bytes: binary(), document: map()}}
  def expand(%Compiler{compiled: kinds}) do
    Enum.reduce(Map.keys(kinds), %{}, &expand_kind(&1, kinds, &2))
  end

  # A kind's document names its ancestors' documents by reference, so
  # ancestors are expanded first.
  defp expand_kind(path, _kinds, done) when is_map_key(done, path), do: done

  defp expand_kind(path, kinds, done) do
    kind = Map.fetch!(kinds, path)
    ancestors = kind |> Compiler.Kind.conforms_to_paths() |> MapSet.delete(path) |> Enum.to_list()
    parents = if kind.extends, do: [kind.extends | ancestors], else: ancestors

    # A kind made under a meta-kind names that meta-kind's document too.
    meta =
      if kind.defined_by not in [nil, Compiler.root_definition_kind(), path], do: kind.defined_by

    done = Enum.reduce(parents ++ List.wrap(meta), done, &expand_kind(&1, kinds, &2))

    document =
      %{
        "format" => @document_format,
        "kind" => path,
        "description" => kind.authored["description"],
        "substrate" => kind.substrate,
        "naming" => kind.effective_naming,
        "signatures" => kind.effective_signatures,
        "requiresAuthority" => kind.effective_requires_authority,
        "schema" => kind.effective_schema,
        "conformsTo" => ancestors |> Enum.map(&done[&1].ref) |> Enum.sort()
      }
      |> put_present("extends", kind.extends && done[kind.extends].ref)
      |> put_present("terminal", kind.effective_terminal)
      # What makes a kind one "of a sort": the meta-kind it was made
      # under, by the hash of that meta-kind's own document; the fields
      # the meta-kind asked it to declare; and, on a meta-kind, the rules
      # it lays on kinds made under it. Present only when there is
      # something to say, so a kind with none of these has the same
      # document it always had.
      |> put_present("definedBy", meta && done[meta].ref)
      |> put_present("predicates", non_empty(kind.effective_predicates))
      |> then(&Map.merge(Compiler.metakind_fields(kind), &1))

    bytes = Canonical.encode(document)
    Map.put(done, path, %{ref: Ref.bytes(bytes), bytes: bytes, document: document})
  end

  defp non_empty([_ | _] = list), do: list
  defp non_empty(_none), do: nil

  defp put_present(map, _key, nil), do: map
  defp put_present(map, key, value), do: Map.put(map, key, value)

  @doc """
  Check `body` against the definition document `schema_ref` names, as a
  record of kind `kind_path`.

    * `:ok` — the body has the declared shape
    * `{:error, violations}` — it does not; every broken rule is listed
    * `{:error, :definition_is_for_another_kind}` — the document defines
      a different kind
    * `{:error, :signature_count_differs}` — the record does not carry
      exactly as many signatures as the document's `signatures`
    * `:unavailable` — the document is neither a base one nor returned
      by `fetch_bytes`, or is not a definition document this build reads

  `signers` is the key ids that signed the record, in signer order. With
  it, the count is checked and so is every `matchesSigner` rule. Before a
  record is signed there are none to give; pass `nil` and those two
  checks are left for whoever reads the signed record.

  `fetch_bytes` is asked for any document that is not a base one. What
  it returns is used only if it hashes to the reference asked for.
  """
  @spec check(String.t(), Ref.t(), term(), fetch_bytes(), [String.t()] | nil) ::
          :ok
          | {:error, [violation()] | :definition_is_for_another_kind | :signature_count_differs}
          | :unavailable
  def check(kind_path, schema_ref, body, fetch_bytes \\ fn _ref -> :error end, signers \\ nil) do
    case load(schema_ref, fetch_bytes) do
      {:ok, ^kind_path, %{signatures: count}}
      when is_list(signers) and length(signers) != count ->
        {:error, :signature_count_differs}

      {:ok, ^kind_path, %{plan: plan}} ->
        Validate.validate(plan, body, signers: signers)

      {:ok, _other_kind, _loaded} ->
        {:error, :definition_is_for_another_kind}

      :unavailable ->
        :unavailable
    end
  end

  # -- loading -----------------------------------------------------------

  defp base do
    case :persistent_term.get({__MODULE__, :base}, nil) do
      nil ->
        {:ok, compiled} = Grammar.compile(@package_sources)

        manifests =
          for name <- ["r5e.core", "r5e.provenance"] do
            {:ok, %{bytes: bytes, ref: ref}} = Grammar.manifest(compiled, name)
            %{package: name, ref: ref, bytes: bytes}
          end

        documents = expand(compiled)

        by_ref =
          Map.new(documents, fn {path, %{ref: ref, document: document}} ->
            {ref,
             {path,
              %{plan: Validate.prepare(document["schema"]), signatures: document["signatures"]}}}
          end)

        base = %{compiled: compiled, manifests: manifests, documents: documents, by_ref: by_ref}
        :persistent_term.put({__MODULE__, :base}, base)
        base

      base ->
        base
    end
  end

  defp load(schema_ref, fetch_bytes) do
    case base().by_ref do
      %{^schema_ref => {kind_path, loaded}} ->
        {:ok, kind_path, loaded}

      _ ->
        # The bytes must be supplied on every call: a kept plan saves
        # the work, it does not stand in for the document.
        with {:ok, bytes} when is_binary(bytes) <- fetch_bytes.(schema_ref),
             true <- Ref.matches?(schema_ref, bytes) do
          prepare_once(schema_ref, bytes)
        else
          _ -> :unavailable
        end
    end
  end

  defp prepare_once(schema_ref, bytes) do
    case :persistent_term.get({__MODULE__, :document, schema_ref}, nil) do
      nil ->
        with {:ok, %{"format" => @document_format, "kind" => kind_path, "schema" => schema} = doc}
             when is_binary(kind_path) and is_map(schema) <- Canonical.decode_json(bytes),
             # Nothing a definition declares is ignored: a schema with a
             # rule this build does not know is not one it can check.
             :ok <- coherent(schema),
             count when is_integer(count) and count >= 1 and count <= 16 <-
               Map.get(doc, "signatures", 1),
             :ok <- GrammarSchema.signer_positions_fit(schema, count) do
          loaded = {:ok, kind_path, %{plan: Validate.prepare(schema), signatures: count}}
          :persistent_term.put({__MODULE__, :document, schema_ref}, loaded)
          loaded
        else
          _ -> :unavailable
        end

      loaded ->
        loaded
    end
  end

  defp coherent(schema) do
    case GrammarSchema.check_coherence(schema, "$") do
      :ok -> :ok
      _ -> :error
    end
  rescue
    _ -> :error
  end

  @doc "Schema for the common Evidence envelope (any kind)."
  def envelope_schema, do: @envelope
  @doc "Schema for the DSSE wrapper."
  def signed_schema, do: @signed
  @doc "Schema for a capture profile."
  def profile_schema, do: @profile
  @doc "Schema for an epoch manifest."
  def manifest_schema, do: @manifest
  @doc "Schema for an export bundle."
  def export_schema, do: @export
end
