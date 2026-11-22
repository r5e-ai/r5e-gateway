defmodule Recurse.Provenance.GrammarTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.Grammar

  @fixtures Path.expand("../fixtures/grammar", __DIR__)
  @files ["r5e.core.huml", "r5e.enterprise.huml", "r5e.harmony.huml", "r5e.examples.huml"]
  @packages ["r5e.core", "r5e.enterprise", "r5e.harmony", "r5e.examples"]

  @small_core """
  %HUML v0.2.0
  format: "r5e.contract-package/v2"
  package: "small.core"
  group: "core.r5e.io"
  version: "v1"
  foundation: true
  types::
    Name::
      type: "string"
      pattern: "^[a-z]+$"
  kinds::
    KindDefinition::
      substrate: "resource"
      description: "Root meta-kind"
      schema::
        required:: "group", "version", "kind", "substrate", "description", "schema", "pins"
        properties::
          group::
            type: "string"
          version::
            type: "string"
          kind::
            type: "string"
          substrate::
            type: "string"
          description::
            type: "string"
          schema::
            type: "object"
          pins::
            type: "object"
          extends::
            type: "string"
          overrides::
            type: "object"
    Thing::
      substrate: "event"
      description: "A named thing"
      schema::
        required:: "name"
        properties::
          name::
            use: "Name"
          count::
            type: "integer"
            minimum: 0
  """

  @small_child """
  %HUML v0.2.0
  format: "r5e.contract-package/v2"
  package: "small.child"
  group: "child.test"
  version: "v1"
  imports::
    core: "small.core"
  kinds::
    LabelledThing::
      extends: "core.r5e.io/v1/Thing"
      description: "A thing with a label"
      schema::
        required:: "label"
        properties::
          label::
            use: "core.Name"
  """

  defp sources do
    Enum.map(@files, &{&1, File.read!(Path.join(@fixtures, &1))})
  end

  setup_all do
    {:ok, compiled} = Grammar.compile(sources())
    %{compiled: compiled}
  end

  describe "compile/1" do
    test "two independent compilations of the same sources give byte-identical manifests" do
      {:ok, first} = Grammar.compile(sources())
      {:ok, second} = Grammar.compile(Enum.reverse(sources()))

      for package <- @packages do
        assert {:ok, %{bytes: bytes, ref: ref}} = Grammar.manifest(first, package)
        assert {:ok, %{bytes: ^bytes, ref: ^ref}} = Grammar.manifest(second, package)
        assert ref == "bytes:sha256:" <> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
      end
    end

    test "the source name plays no part in identity, and comments and layout do not either" do
      {:ok, a} = Grammar.compile([{"a.huml", @small_core}])

      reworded =
        String.replace(@small_core, "%HUML v0.2.0\n", "%HUML v0.2.0\n# a comment\n\n")

      {:ok, b} = Grammar.compile([{"somewhere/else.huml", reworded}])
      assert Grammar.manifest(a, "small.core") == Grammar.manifest(b, "small.core")

      {:ok, c} =
        Grammar.compile([{"a.huml", String.replace(@small_core, "A named thing", "A thing")}])

      refute Grammar.manifest(a, "small.core") == Grammar.manifest(c, "small.core")
    end

    test "a manifest is canonical JSON of the authored package and its imports' references" do
      {:ok, compiled} = Grammar.compile([{"child", @small_child}, {"core", @small_core}])
      {:ok, core} = Grammar.manifest(compiled, "small.core")
      {:ok, child} = Grammar.manifest(compiled, "small.child")

      assert {:ok,
              %{
                "format" => "r5e.definition-package/v1",
                "imports" => imports,
                "package" => %{"package" => "small.child", "kinds" => kinds}
              } = decoded} = RecurseVerify.Canonical.decode_json(child.bytes)

      assert imports == %{"small.core" => core.ref}
      assert Map.keys(decoded) == ["format", "imports", "package"]

      assert kinds["LabelledThing"]["schema"]["properties"] == %{
               "label" => %{"use" => "core.Name"}
             }

      assert {:ok, %{"imports" => %{}}} = RecurseVerify.Canonical.decode_json(core.bytes)
    end

    test "reports which source failed to parse, and passes compiler errors through" do
      assert {:error, {:source, "bad.huml", {:huml_parse_error, 2, _}}} =
               Grammar.compile([{"core", @small_core}, {"bad.huml", "%HUML v0.2.0\na: 1.5\n"}])

      assert {:error, {:invalid_foundation_count, 0}} = Grammar.compile([{"child", @small_child}])
      assert {:error, {:invalid_foundation_count, 0}} = Grammar.compile([])
      assert {:error, {:invalid_source, :nope}} = Grammar.compile([:nope])
    end
  end

  describe "manifest/2, kinds/1 and kind/2" do
    test "manifest/2 answers by declared package name", %{compiled: compiled} do
      assert {:ok, %{bytes: bytes, ref: "bytes:sha256:" <> hex}} =
               Grammar.manifest(compiled, "r5e.harmony")

      assert is_binary(bytes) and byte_size(hex) == 64
      assert :error = Grammar.manifest(compiled, "r5e.harmony.huml")
    end

    test "kinds/1 lists every kind path, sorted", %{compiled: compiled} do
      paths = Grammar.kinds(compiled)
      assert length(paths) == 48
      assert paths == Enum.sort(paths)
      assert "core.r5e.io/v1/Artifact" in paths
      assert "examples.r5e.io/v1/SecurityReview" in paths
    end

    test "kind/2 gives identity, ancestry, conformance and the hydrated schema", %{
      compiled: compiled
    } do
      {:ok, %{ref: examples_ref}} = Grammar.manifest(compiled, "r5e.examples")
      {:ok, artifact} = Grammar.kind(compiled, "core.r5e.io/v1/Artifact")
      {:ok, review} = Grammar.kind(compiled, "harmony.r5e.io/v1/Review")

      assert {:ok,
              %{
                path: "examples.r5e.io/v1/ExploratoryReview",
                package: "r5e.examples",
                manifest_ref: ^examples_ref,
                definition_ref: definition_ref,
                extends: "harmony.r5e.io/v1/Review",
                defined_by: "core.r5e.io/v1/KindDefinition",
                conforms_to: conforms_to,
                schema: schema,
                substrate: "artifact",
                signatures: 1
              }} = Grammar.kind(compiled, "examples.r5e.io/v1/ExploratoryReview")

      assert definition_ref == examples_ref <> "#examples.r5e.io/v1/ExploratoryReview"

      # It dropped `verdict`, so it conforms to Artifact and itself but not to Review.
      assert conforms_to == Enum.sort([artifact.definition_ref, definition_ref])
      refute review.definition_ref in conforms_to

      # Hydrated: inherited and own properties, `use:` expanded, the drop applied.
      assert schema["properties"]["contentRef"] == %{"type" => "ref", "ref" => %{"bytes" => true}}
      assert Map.has_key?(schema["properties"], "questions")
      refute Map.has_key?(schema["properties"], "verdict")
      assert "questions" in schema["required"] and "contentRef" in schema["required"]

      assert artifact.extends == nil
      assert :error = Grammar.kind(compiled, "examples.r5e.io/v1/Missing")
    end
  end

  describe "validate/4" do
    test "accepts a conforming body and reports each broken rule with a fixed code", %{
      compiled: compiled
    } do
      kind = "core.r5e.io/v1/Artifact"

      body = %{
        "contentRef" => "bytes:sha256:" <> String.duplicate("a", 64),
        "mediaType" => "application/json",
        "size" => 12
      }

      assert :ok = Grammar.validate(compiled, kind, body)

      assert {:error, [%{path: "$.size", code: "missing_required"}]} =
               Grammar.validate(compiled, kind, Map.delete(body, "size"))

      assert {:error, [%{path: "$.size", code: "wrong_type"}]} =
               Grammar.validate(compiled, kind, %{body | "size" => "12"})

      assert {:error, [%{path: "$.size", code: "below_minimum"}]} =
               Grammar.validate(compiled, kind, %{body | "size" => -1})

      assert {:error, [%{path: "$.surprise", code: "unexpected_property"}]} =
               Grammar.validate(compiled, kind, Map.put(body, "surprise", true))

      assert {:error, [%{path: "$.contentRef", code: "expected_bytes_ref"}]} =
               Grammar.validate(compiled, kind, %{body | "contentRef" => "sha256:abc"})

      assert {:error, [%{path: "$.derivedFrom[0]", code: "ref_alternatives_mismatch"}]} =
               Grammar.validate(compiled, kind, Map.put(body, "derivedFrom", ["nonsense"]))

      {:ok, %{definition_ref: definition_ref}} = Grammar.kind(compiled, kind)

      assert :ok =
               Grammar.validate(
                 compiled,
                 kind,
                 Map.put(body, "derivedFrom", [
                   definition_ref,
                   "chain:evidence:sha256:" <> String.duplicate("c", 64) <> "/" <> definition_ref
                 ])
               )

      assert {:error, [%{path: "$", code: "wrong_type"}]} =
               Grammar.validate(compiled, kind, "not an object")
    end

    test "patterns and enums from reusable types apply to the body", %{compiled: compiled} do
      kind = "core.r5e.io/v1/ChainAnchor"

      body = %{
        "chainId" => "edge-1",
        "fromSeq" => 1,
        "toSeq" => 9,
        "headDigest" => "sha256:" <> String.duplicate("0", 64),
        "rootKey" => "key:ed25519:sha256:" <> String.duplicate("1", 64)
      }

      assert :ok = Grammar.validate(compiled, kind, body)

      assert {:error,
              [
                %{path: "$", code: "out_of_order"},
                %{path: "$.chainId", code: "pattern_mismatch"},
                %{path: "$.headDigest", code: "pattern_mismatch"}
              ]} =
               Grammar.validate(compiled, kind, %{
                 body
                 | "chainId" => "edge 1",
                   "headDigest" => "sha256:xyz",
                   "fromSeq" => 10
               })

      {:ok, small} = Grammar.compile([{"core", @small_core}, {"child", @small_child}])

      assert :ok =
               Grammar.validate(small, "child.test/v1/LabelledThing", %{
                 "name" => "abc",
                 "label" => "def"
               })

      assert {:error,
              [
                %{path: "$.label", code: "pattern_mismatch"},
                %{path: "$.name", code: "missing_required"}
              ]} = Grammar.validate(small, "child.test/v1/LabelledThing", %{"label" => "DEF"})
    end

    test "an envelope-dependent rule reads the envelope given, and says so when none is", %{
      compiled: compiled
    } do
      kind = "core.r5e.io/v1/Endorsement"

      body = %{
        "subject" => "key:ed25519:sha256:" <> String.duplicate("2", 64),
        "subjectKey" => %{"algorithm" => "ed25519", "bytes" => "AAAA"},
        "kinds" => ["*"],
        "mayIssue" => true,
        "notBefore" => "2026-11-10T00:00:00Z",
        "notAfter" => "2026-11-11T00:00:00Z"
      }

      assert {:error, [%{path: "$", code: "envelope_required"}]} =
               Grammar.validate(compiled, kind, body)

      assert :ok = Grammar.validate(compiled, kind, body, envelope: %{})

      assert {:error, [%{path: "$.parent", code: "missing_conditional"}]} =
               Grammar.validate(compiled, kind, body, envelope: %{"authority" => "x"})
    end

    test "an unknown kind is an error with its own code", %{compiled: compiled} do
      assert {:error, [%{path: "$", code: "unknown_kind"}]} =
               Grammar.validate(compiled, "core.r5e.io/v1/Nope", %{})
    end

    test "the module documentation lists every code the check can report" do
      {:docs_v1, _, _, _, %{"en" => moduledoc}, _, _} = Code.fetch_docs(Grammar)

      for code <- ["unknown_kind" | Grammar.Validate.codes()] do
        assert moduledoc =~ "`#{code}`", "#{code} is not documented"
      end
    end
  end
end
