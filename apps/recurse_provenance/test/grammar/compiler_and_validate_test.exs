defmodule Recurse.Provenance.Grammar.CompilerAndValidateTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.Grammar.{Compiler, Huml, Schema, Validate}
  alias Recurse.Provenance.Grammar.Compiler.Kind

  @fixtures Path.expand("../fixtures/grammar", __DIR__)
  @ex "examples.r5e.io/v1/"
  @root Compiler.root_definition_kind()

  # Manifest references of the fixture packages. They change whenever a
  # fixture's content changes, and for no other reason.
  @expected_manifest_refs %{
    "r5e.core" => "bytes:sha256:c427e38e1e48cd26d9504cb754f93dc50c6bcedb9e2fcdd8fe4ca2ffe0bf1a70",
    "r5e.enterprise" =>
      "bytes:sha256:c93737fb0aa441062f677f75d88b9dac3512d21693ed126a4a26b1f526c8137d",
    "r5e.harmony" =>
      "bytes:sha256:df8b92bdf52905b91eb9e1e6ed83ca53bb65b1809e0b17d198a5b8ae41c5924d",
    "r5e.examples" =>
      "bytes:sha256:32237d80df97e2ce656bd05e182a183e36d40727ca911210e3c9d69d18c864ec"
  }

  setup_all do
    base_pkgs =
      for name <- ["r5e.core", "r5e.enterprise", "r5e.harmony", "r5e.examples"] do
        {:ok, pkg} = Huml.decode_file(Path.join(@fixtures, name <> ".huml"))
        pkg
      end

    {:ok, compiled_state} = Compiler.compile_packages(base_pkgs)
    %{base_pkgs: base_pkgs, state: compiled_state}
  end

  defp update_pkg(pkgs, name, fun) do
    Enum.map(pkgs, fn pkg ->
      if pkg["package"] == name, do: fun.(pkg), else: pkg
    end)
  end

  defp put_kind(pkgs, pkg_name, kind_name, kind_map) do
    update_pkg(pkgs, pkg_name, fn pkg ->
      put_in(pkg, ["kinds", kind_name], kind_map)
    end)
  end

  defp child(parent, extra) do
    Map.merge(
      %{
        "extends" => parent,
        "description" => "Semantic boundary fixture",
        "schema" => %{"properties" => %{}}
      },
      extra
    )
  end

  defp only(pkgs, names), do: Enum.filter(pkgs, &(&1["package"] in names))

  defp refs(%Compiler{manifests: manifests}), do: Map.new(manifests, fn {k, m} -> {k, m.ref} end)

  describe "the fixture packages" do
    test "compile to 48 kinds with pinned manifest references and conformance sets", %{state: st} do
      assert map_size(st.compiled) == 48
      assert refs(st) == @expected_manifest_refs

      cs = st.compiled

      for {kpath, ck} <- cs do
        has_def_ref? = Map.has_key?(ck.published_spec["pins"], "definedByRef")
        assert has_def_ref? == (ck.defined_by != @root), "#{kpath}: definedByRef mismatch"
        assert ck.published_spec["pins"]["manifestRef"] == ck.manifest_ref
        assert ck.definition_ref == ck.manifest_ref <> "#" <> kpath
      end

      assert Kind.conforms_to_paths(cs[@ex <> "SecurityReview"]) ==
               MapSet.new([
                 "core.r5e.io/v1/Artifact",
                 "harmony.r5e.io/v1/Review",
                 @ex <> "SecurityReview"
               ])

      assert Kind.conforms_to_paths(cs[@ex <> "ExploratoryReview"]) ==
               MapSet.new(["core.r5e.io/v1/Artifact", @ex <> "ExploratoryReview"])

      assert Kind.conforms_to_paths(cs[@ex <> "SpecializedExploratoryReview"]) ==
               MapSet.new([
                 "core.r5e.io/v1/Artifact",
                 @ex <> "ExploratoryReview",
                 @ex <> "SpecializedExploratoryReview"
               ])

      assert Kind.conforms_to_paths(cs["harmony.r5e.io/v1/MetricDefinition"]) ==
               MapSet.new(["core.r5e.io/v1/KindDefinition", "harmony.r5e.io/v1/MetricDefinition"])

      assert Kind.conforms_to_paths(cs[@ex <> "DocDiscoveryMetric"]) ==
               MapSet.new([
                 "core.r5e.io/v1/Artifact",
                 "harmony.r5e.io/v1/Assertion",
                 @ex <> "DocDiscoveryMetric"
               ])

      assert Kind.conforms_to_paths(cs[@ex <> "StrictDocDiscoveryMetric"]) ==
               MapSet.new([
                 "core.r5e.io/v1/Artifact",
                 "harmony.r5e.io/v1/Assertion",
                 @ex <> "DocDiscoveryMetric",
                 @ex <> "StrictDocDiscoveryMetric"
               ])
    end

    test "the foundation compiles alone, and to the same reference as in any larger set", %{
      base_pkgs: base
    } do
      assert {:ok, core_only} = Compiler.compile_packages(only(base, ["r5e.core"]))
      assert map_size(core_only.compiled) == 15
      assert refs(core_only) == Map.take(@expected_manifest_refs, ["r5e.core"])

      assert core_only.compiled["core.r5e.io/v1/Artifact"].definition_ref ==
               @expected_manifest_refs["r5e.core"] <> "#core.r5e.io/v1/Artifact"

      assert {:ok, three} =
               Compiler.compile_packages(
                 only(base, ["r5e.core", "r5e.enterprise", "r5e.harmony"])
               )

      assert map_size(three.compiled) == 43

      assert refs(three) ==
               Map.take(@expected_manifest_refs, ["r5e.core", "r5e.enterprise", "r5e.harmony"])
    end

    test "HUML reader rejects floats, trailing spaces, duplicate keys, and bad indentation" do
      assert {:error, {:huml_parse_error, _, _}} = Huml.decode("%HUML v0.2.0\nscore: 1.5\n")
      assert {:error, {:huml_parse_error, _, _}} = Huml.decode("%HUML v0.2.0\nscore: nan\n")
      assert {:error, {:huml_parse_error, _, _}} = Huml.decode("%HUML v0.2.0\na: 1 \n")
      assert {:error, {:huml_parse_error, _, _}} = Huml.decode("%HUML v0.2.0\na: 1\na: 2\n")
      assert {:error, {:huml_parse_error, _, _}} = Huml.decode("%HUML v0.2.0\na ::\n   b: 1\n")

      assert {:error, {:huml_parse_error, _, _}} =
               Huml.decode("%HUML v0.2.0\nn: 9007199254740992\n")

      assert {:ok, %{"n" => 9_007_199_254_740_991}} =
               Huml.decode("%HUML v0.2.0\nn: 9007199254740991\n")
    end
  end

  describe "identity by content" do
    test "a manifest is the authored package plus the references of its imports", %{
      state: st,
      base_pkgs: base
    } do
      examples = Enum.find(base, &(&1["package"] == "r5e.examples"))
      manifest = st.manifests["r5e.examples"]

      assert manifest.value == %{
               "format" => "r5e.definition-package/v1",
               "package" => examples,
               "imports" => %{
                 "r5e.core" => st.manifests["r5e.core"].ref,
                 "r5e.harmony" => st.manifests["r5e.harmony"].ref
               }
             }

      assert manifest.bytes == RecurseVerify.Canonical.encode(manifest.value)

      assert manifest.ref ==
               "bytes:sha256:" <>
                 Base.encode16(:crypto.hash(:sha256, manifest.bytes), case: :lower)

      # The authored package is unhydrated: `use:` and `extends` are still as written.
      assert get_in(manifest.value, [
               "package",
               "kinds",
               "SecurityReview",
               "schema",
               "properties",
               "policyBundleDigest"
             ]) == %{"use" => "core.Digest"}

      refute Map.has_key?(
               manifest.value["package"]["kinds"]["SecurityReview"]["schema"]["properties"],
               "verdict"
             )
    end

    test "the same content has the same reference whatever else is compiled or in what order", %{
      state: st,
      base_pkgs: base
    } do
      assert {:ok, reversed} = Compiler.compile_packages(Enum.reverse(base))
      assert refs(reversed) == refs(st)

      # An unrelated package beside it changes nothing.
      other = %{
        "format" => "r5e.contract-package/v2",
        "package" => "test.other",
        "group" => "other.test",
        "version" => "v1",
        "imports" => %{"core" => "r5e.core"},
        "kinds" => %{
          "Note" => %{
            "substrate" => "event",
            "description" => "Unrelated kind",
            "schema" => %{"properties" => %{"text" => %{"type" => "string"}}}
          }
        }
      }

      assert {:ok, with_other} = Compiler.compile_packages(base ++ [other])
      assert Map.delete(refs(with_other), "test.other") == refs(st)

      # A package that imports nothing changed keeps its reference when a
      # package it does not import changes.
      changed_enterprise =
        update_pkg(base, "r5e.enterprise", fn pkg ->
          put_in(pkg, ["kinds", "OrgUnit", "description"], "Reworded")
        end)

      assert {:ok, st2} = Compiler.compile_packages(changed_enterprise)
      refute refs(st2)["r5e.enterprise"] == refs(st)["r5e.enterprise"]
      assert Map.delete(refs(st2), "r5e.enterprise") == Map.delete(refs(st), "r5e.enterprise")
    end

    test "changing an imported package changes every importer's reference", %{
      state: st,
      base_pkgs: base
    } do
      changed_core =
        update_pkg(base, "r5e.core", fn pkg ->
          put_in(pkg, ["kinds", "Run", "description"], "Reworded")
        end)

      assert {:ok, st2} = Compiler.compile_packages(changed_core)

      for name <- ["r5e.core", "r5e.enterprise", "r5e.harmony", "r5e.examples"] do
        refute refs(st2)[name] == refs(st)[name], "#{name} kept its reference"
      end

      # Indirectly too: examples imports harmony, and only harmony changed.
      changed_harmony =
        update_pkg(base, "r5e.harmony", fn pkg ->
          put_in(pkg, ["kinds", "Task", "description"], "Reworded")
        end)

      assert {:ok, st3} = Compiler.compile_packages(changed_harmony)
      assert refs(st3)["r5e.core"] == refs(st)["r5e.core"]
      assert refs(st3)["r5e.enterprise"] == refs(st)["r5e.enterprise"]
      refute refs(st3)["r5e.harmony"] == refs(st)["r5e.harmony"]
      refute refs(st3)["r5e.examples"] == refs(st)["r5e.examples"]

      refute st3.compiled[@ex <> "SecurityReview"].definition_ref ==
               st.compiled[@ex <> "SecurityReview"].definition_ref
    end

    test "a kind may only name kinds from its own package or an imported one", %{base_pkgs: base} do
      not_imported =
        put_kind(
          base,
          "r5e.examples",
          "Stray",
          child("enterprise.r5e.io/v1/PolicyBundle", %{})
        )

      assert {:error,
              {:kind_reference_outside_imports, @ex <> "Stray",
               "enterprise.r5e.io/v1/PolicyBundle", "r5e.enterprise"}} =
               Compiler.compile_packages(not_imported)

      no_foundation =
        update_pkg(base, "r5e.examples", &put_in(&1, ["imports"], %{"harmony" => "r5e.harmony"}))

      assert {:error, {:foundation_not_imported, "r5e.examples"}} =
               Compiler.compile_packages(no_foundation)

      assert {:error, {:unknown_imported_package, "r5e.examples", "harmony", "r5e.harmony"}} =
               Compiler.compile_packages(only(base, ["r5e.core", "r5e.examples"]))
    end

    test "packages that import each other are refused", %{base_pkgs: base} do
      alpha = probe_package("test.alpha", "alpha.test", "test.beta", "beta.test/v1/Node")
      beta = probe_package("test.beta", "beta.test", "test.alpha", "alpha.test/v1/Node")

      assert {:error, {:package_import_cycle, cycle}} =
               Compiler.compile_packages(base ++ [alpha, beta])

      assert "test.alpha" in cycle and "test.beta" in cycle
    end
  end

  defp probe_package(name, group, peer_package, peer_kind) do
    %{
      "format" => "r5e.contract-package/v2",
      "package" => name,
      "group" => group,
      "version" => "v1",
      "imports" => %{"core" => "r5e.core", "peer" => peer_package},
      "kinds" => %{
        "Node" => %{
          "substrate" => "event",
          "description" => "Cycle probe",
          "schema" => %{
            "properties" => %{
              "peer" => %{"type" => "ref", "ref" => %{"event" => peer_kind}}
            }
          }
        }
      }
    }
  end

  describe "nothing declared is ignored" do
    test "matchesSigner must fit the kind's signature count", %{base_pkgs: base} do
      bound = fn signatures, properties, required ->
        put_kind(base, "r5e.examples", "Bound", %{
          "substrate" => "event",
          "description" => "Binds fields to signers",
          "signatures" => signatures,
          "schema" => %{"properties" => properties, "required" => required}
        })
      end

      bound = fn
        signatures, properties -> bound.(signatures, properties, Map.keys(properties))
      end

      optional = fn signatures, properties ->
        put_kind(base, "r5e.examples", "Bound", %{
          "substrate" => "event",
          "description" => "Binds fields to signers",
          "signatures" => signatures,
          "schema" => %{"properties" => properties}
        })
      end

      key = fn position -> %{"type" => "string", "matchesSigner" => position} end

      assert {:ok, _} = Compiler.compile_packages(bound.(1, %{"by" => key.(1)}))
      assert {:ok, _} = Compiler.compile_packages(bound.(2, %{"other" => key.(2)}))

      assert {:error, {:matches_signer_exceeds_signatures, @ex <> "Bound", 2, 1}} =
               Compiler.compile_packages(bound.(1, %{"other" => key.(2)}))

      assert {:error, {:signer_position_unbound, @ex <> "Bound", 2}} =
               Compiler.compile_packages(bound.(2, %{"by" => key.(1)}))

      # Named, but on a property a body may leave out, or below the top level.
      assert {:error, {:signer_position_unbound, @ex <> "Bound", 2}} =
               Compiler.compile_packages(optional.(2, %{"other" => key.(2)}))

      nested = %{
        "type" => "object",
        "required" => ["other"],
        "properties" => %{"other" => key.(2)}
      }

      assert {:error, {:signer_position_unbound, @ex <> "Bound", 2}} =
               Compiler.compile_packages(bound.(2, %{"party" => nested}))

      assert {:error, {:signer_position_unbound, @ex <> "Bound", 3}} =
               Compiler.compile_packages(bound.(3, %{"other" => key.(2)}))

      assert {:error, {:matches_signer_requires_string, _}} =
               Compiler.compile_packages(
                 bound.(1, %{"by" => %{"type" => "integer", "matchesSigner" => 1}})
               )

      assert {:error, {:invalid_matches_signer, _, 0}} =
               Compiler.compile_packages(bound.(1, %{"by" => key.(0)}))
    end

    test "a field bound to a signer is checked once the signers are known", %{state: state} do
      succession = state.compiled["core.r5e.io/v1/Succession"].validator
      old = "key:ed25519:sha256:" <> String.duplicate("a", 64)
      new = "key:ed25519:sha256:" <> String.duplicate("b", 64)

      body = %{
        "predecessor" => old,
        "successor" => new,
        "successorKey" => %{"algorithm" => "ed25519", "bytes" => "AAAA"}
      }

      assert :ok = Validate.validate(succession, body)
      assert :ok = Validate.validate(succession, body, signers: [old, new])

      assert {:error, [%{path: "$.successor", code: "signer_mismatch"}]} =
               Validate.validate(succession, body, signers: [old, old])

      assert {:error, violations} = Validate.validate(succession, body, signers: [new, old])
      assert Enum.map(violations, & &1.code) == ["signer_mismatch", "signer_mismatch"]
    end

    test "a public key field and a field derived from it are declared coherently", %{
      base_pkgs: base
    } do
      keyed = fn properties ->
        put_kind(base, "r5e.examples", "Keyed", %{
          "substrate" => "event",
          "description" => "Carries a key and its id",
          "schema" => %{"properties" => properties, "required" => ["key"]}
        })
      end

      key = %{
        "type" => "object",
        "keyBytes" => true,
        "required" => ["algorithm", "bytes"],
        "properties" => %{"algorithm" => %{"type" => "string"}, "bytes" => %{"type" => "string"}}
      }

      id = %{"type" => "string", "derives" => %{"keyIdOf" => "key"}}

      assert {:ok, _} = Compiler.compile_packages(keyed.(%{"key" => key, "id" => id}))

      # The key is there but a body may leave it out.
      optional_key =
        put_kind(base, "r5e.examples", "Keyed", %{
          "substrate" => "event",
          "description" => "Carries a key and its id",
          "schema" => %{"properties" => %{"key" => key, "id" => id}}
        })

      assert {:error, {:derives_names_no_key, _, "key"}} =
               Compiler.compile_packages(optional_key)

      assert {:error, {:derives_names_no_key, _, "key"}} =
               Compiler.compile_packages(keyed.(%{"key" => %{"type" => "string"}, "id" => id}))

      assert {:error, {:derives_requires_string, _}} =
               Compiler.compile_packages(
                 keyed.(%{"key" => key, "id" => Map.put(id, "type", "integer")})
               )

      assert {:error, {:key_bytes_requires_algorithm_and_bytes, _}} =
               Compiler.compile_packages(keyed.(%{"key" => Map.delete(key, "required")}))

      assert {:error, {:invalid_key_bytes, _, 1}} =
               Compiler.compile_packages(keyed.(%{"key" => Map.put(key, "keyBytes", 1)}))
    end

    test "a public key must be a real key, and a derived id must be that key's id" do
      schema = %{
        "required" => ["key"],
        "properties" => %{
          "id" => %{"type" => "string", "derives" => %{"keyIdOf" => "key"}},
          "key" => %{
            "type" => "object",
            "keyBytes" => true,
            "required" => ["algorithm", "bytes"],
            "properties" => %{
              "algorithm" => %{"type" => "string"},
              "bytes" => %{"type" => "string"}
            }
          }
        }
      }

      for algorithm <- ["ed25519", "es256", "es384"] do
        signer = Recurse.Provenance.Key.generate(algorithm)
        key = %{"algorithm" => algorithm, "bytes" => Base.encode64(signer.public_key)}
        other = Recurse.Provenance.Key.generate(algorithm)

        assert :ok = Validate.validate(schema, %{"id" => signer.key_id, "key" => key})

        assert {:error, [%{path: "$.id", code: "not_the_key_id_of"}]} =
                 Validate.validate(schema, %{"id" => other.key_id, "key" => key})
      end

      assert {:error, violations} =
               Validate.validate(schema, %{
                 "id" => "key:ed25519:sha256:" <> String.duplicate("a", 64),
                 "key" => %{"algorithm" => "ed25519", "bytes" => "AAAA"}
               })

      assert Enum.map(violations, & &1.code) |> Enum.sort() ==
               ["not_a_public_key", "not_the_key_id_of"]

      assert {:error, [%{path: "$.key", code: "not_a_public_key"}]} =
               Validate.validate(schema, %{"key" => %{"algorithm" => "rsa", "bytes" => "AAAA"}})
    end

    test "unknown package keys, schema keywords, ref keys and constraint sections are refused", %{
      base_pkgs: base
    } do
      assert {:error, {:unknown_package_keys, "r5e.examples", ["replaces"]}} =
               Compiler.compile_packages(
                 update_pkg(base, "r5e.examples", &Map.put(&1, "replaces", %{}))
               )

      odd_keyword =
        put_kind(base, "r5e.examples", "Odd", %{
          "substrate" => "event",
          "description" => "Unknown schema keyword",
          "schema" => %{"properties" => %{"n" => %{"type" => "integer", "multipleOf" => 2}}}
        })

      assert {:error, {:unsupported_schema_keys, _, ["multipleOf"]}} =
               Compiler.compile_packages(odd_keyword)

      odd_ref =
        put_kind(base, "r5e.examples", "OddRef", %{
          "substrate" => "event",
          "description" => "Unknown ref key",
          "schema" => %{
            "properties" => %{
              "r" => %{"type" => "ref", "ref" => %{"bytes" => true, "publication" => true}}
            }
          }
        })

      assert {:error, {:unknown_ref_keys, _, ["publication"]}} =
               Compiler.compile_packages(odd_ref)

      odd_kind_key =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(pkg, ["kinds", "SecurityReview", "replaces"], "something")
        end)

      assert {:error,
              {:definition_violates_meta_kind, @ex <> "SecurityReview", @root,
               [%{path: "$.replaces", code: "unexpected_property"}]}} =
               Compiler.compile_packages(odd_kind_key)

      odd_drop =
        put_kind(
          base,
          "r5e.examples",
          "OddDrop",
          child("harmony.r5e.io/v1/Review", %{
            "overrides" => %{"reason" => "drop a section", "dropConstraints" => ["properties"]}
          })
        )

      assert {:error, {:unknown_drop_constraint, _, "properties"}} =
               Compiler.compile_packages(odd_drop)
    end

    test "a mistyped package is an error, not a crash", %{base_pkgs: base} do
      for {path, value, reason} <- [
            {["kinds", "SecurityReview", "overrides"], "none", :overrides_not_object},
            {["kinds", "ExploratoryReview", "overrides", "replace"], [], :replace_not_object},
            {["kinds", "SecurityReview", "schema", "properties"], "none", :properties_not_object},
            {["kinds", "SecurityReview", "schema", "properties", "networkZone"], "string",
             :schema_not_object},
            {["kinds", "SecurityReview", "naming"], %{"derive" => 7}, :invalid_naming},
            {["kinds", "SecurityReview", "extends"], 7, :invalid_kind_reference},
            {["kinds", "SecurityReview"], "none", :kind_not_object},
            {["kinds", "SecurityReview", "schema", "required"], "verdict",
             :constraint_must_be_list},
            {["imports"], ["r5e.core"], :invalid_imports},
            {["types"], [], :invalid_types_map}
          ] do
        mutated = update_pkg(base, "r5e.examples", &put_in(&1, path, value))
        assert {:error, error} = Compiler.compile_packages(mutated)
        assert elem(error, 0) == reason, inspect({path, error})
      end

      assert {:error, {:invalid_kind_path, "Examples.r5e.io/v1/" <> _}} =
               Compiler.compile_packages(
                 update_pkg(base, "r5e.examples", &Map.put(&1, "group", "Examples.r5e.io"))
               )
    end

    test "a value canonical JSON cannot encode is an error, not a crash", %{base_pkgs: base} do
      with_float =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(pkg, ["kinds", "DocDiscoveryMetric", "metric", "targetValue"], 1.5)
        end)

      assert {:error, {:package_not_canonical, "r5e.examples", _}} =
               Compiler.compile_packages(with_float)
    end
  end

  describe "rules the compiler enforces on definitions" do
    test "rejects each invalid mutation of the fixture packages", %{base_pkgs: base} do
      # N1: a package other than the foundation declaring `protected`
      p_n1 =
        update_pkg(
          base,
          "r5e.harmony",
          &put_in(&1, ["kinds", "Review", "protected"], ["verdict"])
        )

      assert {:error, {:non_foundation_protected_forbidden, _, _}} =
               Compiler.compile_packages(p_n1)

      # N2: dropping the protected `Artifact.contentRef`
      p_n2 =
        update_pkg(base, "r5e.enterprise", fn pkg ->
          put_in(pkg, ["kinds", "WorkspaceTree", "overrides"], %{
            "reason" => "bad",
            "drop" => ["contentRef"]
          })
        end)

      assert {:error, {:protected_field_drop_forbidden, _, "contentRef"}} =
               Compiler.compile_packages(p_n2)

      # N3: implicit shadowing without `overrides.replace`
      p_n3 =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(pkg, ["kinds", "SecurityReview", "schema", "properties", "verdict"], %{
            "type" => "string"
          })
        end)

      assert {:error, {:implicit_property_shadowing, _, "verdict"}} =
               Compiler.compile_packages(p_n3)

      # N4: dropping the foundation's `ordered` via `dropConstraints`
      p_n4 =
        put_kind(
          base,
          "r5e.examples",
          "BrokenBadge",
          child("core.r5e.io/v1/Badge", %{
            "overrides" => %{"reason" => "try dropping ordered", "dropConstraints" => ["ordered"]}
          })
        )

      assert {:error, {:protected_constraint_drop_forbidden, _, "ordered"}} =
               Compiler.compile_packages(p_n4)

      # N5: changing the foundation's protected `naming` on `Principal`
      p_n5 =
        put_kind(
          base,
          "r5e.examples",
          "FakePrincipal",
          child("core.r5e.io/v1/Principal", %{"naming" => %{"mode" => "caller"}})
        )

      assert {:error, {:protected_naming_override_forbidden, _}} = Compiler.compile_packages(p_n5)

      # N6: malformed nested `MetricContract` enum on `DocDiscoveryMetric`
      p_n6 =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(pkg, ["kinds", "DocDiscoveryMetric", "metric", "direction"], "sideways")
        end)

      assert {:error,
              {:definition_violates_meta_kind, @ex <> "DocDiscoveryMetric",
               "harmony.r5e.io/v1/MetricDefinition",
               [%{path: "$.metric.direction", code: "enum_mismatch"}]}} =
               Compiler.compile_packages(p_n6)

      # N7a: `MetricDefinition` `valueField` with a non-integer type
      p_n7a_bounds =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(
            pkg,
            ["kinds", "DocDiscoveryMetric", "schema", "properties", "unnecessaryReads", "type"],
            "string"
          )
        end)

      assert {:error, {:numeric_bounds_require_integer, _}} =
               Compiler.compile_packages(p_n7a_bounds)

      p_n7a_pred =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(
            pkg,
            ["kinds", "DocDiscoveryMetric", "schema", "properties", "unnecessaryReads"],
            %{"type" => "string"}
          )
        end)

      assert {:error,
              {:predicate_property_wrong_type, _, _, "unnecessaryReads", "integer", "string"}} =
               Compiler.compile_packages(p_n7a_pred)

      # N7b: `MetricDefinition` `valueField` omitted from `schema.required`
      p_n7b =
        update_pkg(base, "r5e.examples", fn pkg ->
          put_in(pkg, ["kinds", "DocDiscoveryMetric", "schema"], %{
            "required" => ["relevantDocsFound"],
            "properties" => %{
              "unnecessaryReads" => %{"type" => "integer"},
              "relevantDocsFound" => %{"type" => "boolean"}
            }
          })
        end)

      assert {:error, {:predicate_property_not_required, _, _, "unnecessaryReads"}} =
               Compiler.compile_packages(p_n7b)

      # N8: an unknown predicate `check` fails closed
      p_n8 =
        update_pkg(base, "r5e.harmony", fn pkg ->
          update_in(
            pkg,
            ["kinds", "MetricDefinition", "predicates"],
            &(&1 ++ [%{"id" => "u", "check" => "magicOracle"}])
          )
        end)

      assert {:error, {:unsupported_predicate_check, _, "magicOracle"}} =
               Compiler.compile_packages(p_n8)

      # N9: opening the nested closed `PublicKey` on the protected `Endorsement.subjectKey`
      p_n9 =
        put_kind(
          base,
          "r5e.examples",
          "LeakyEndorsement",
          child("core.r5e.io/v1/Endorsement", %{
            "overrides" => %{
              "reason" => "try opening PublicKey",
              "replace" => %{
                "subjectKey" => %{
                  "type" => "object",
                  "additionalProperties" => true,
                  "required" => ["algorithm", "bytes"],
                  "properties" => %{
                    "algorithm" => %{"type" => "string", "pattern" => "^[a-z0-9._-]+$"},
                    "bytes" => %{"type" => "string"}
                  }
                }
              }
            }
          })
        )

      assert {:error, {:weakened_protected_field_floor, _, "subjectKey"}} =
               Compiler.compile_packages(p_n9)

      # N10: `ref.kind` naming a kind that is not a resource
      p_n10 =
        put_kind(
          base,
          "r5e.examples",
          "BadRefKind",
          child("core.r5e.io/v1/Artifact", %{
            "schema" => %{
              "properties" => %{
                "badReviewRef" => %{
                  "type" => "ref",
                  "ref" => %{"kind" => "harmony.r5e.io/v1/Review"}
                }
              }
            }
          })
        )

      assert {:error, {:ref_kind_targets_non_resource, _, "harmony.r5e.io/v1/Review", "artifact"}} =
               Compiler.compile_packages(p_n10)

      # N11: dropping a property still named in `exactlyOne`
      p_n11 =
        base
        |> put_kind(
          "r5e.examples",
          "ChoiceParent",
          child("core.r5e.io/v1/Artifact", %{
            "schema" => %{
              "exactlyOne" => [["left", "right"]],
              "properties" => %{"left" => %{"type" => "string"}, "right" => %{"type" => "string"}}
            }
          })
        )
        |> put_kind(
          "r5e.examples",
          "ChoiceBrokenChild",
          child(@ex <> "ChoiceParent", %{
            "overrides" => %{"reason" => "drop left without dropConstraints", "drop" => ["left"]}
          })
        )

      assert {:error, {:unknown_property_reference, _, "left"}} = Compiler.compile_packages(p_n11)
    end

    test "a foundation floor survives relaxation, a domain tightening does not, and replaced refs are pinned",
         %{base_pkgs: base} do
      pkgs_ok =
        base
        |> update_pkg("r5e.examples", &put_in(&1, ["imports", "enterprise"], "r5e.enterprise"))
        |> put_kind(
          "r5e.examples",
          "StrictBlob",
          child("core.r5e.io/v1/Artifact", %{
            "overrides" => %{
              "reason" => "require >= 100 bytes",
              "replace" => %{"size" => %{"type" => "integer", "minimum" => 100}}
            }
          })
        )
        |> put_kind(
          "r5e.examples",
          "RelaxedBlob",
          child(@ex <> "StrictBlob", %{
            "overrides" => %{
              "reason" => "relax back to the foundation floor of 0",
              "replace" => %{"size" => %{"type" => "integer", "minimum" => 0}}
            }
          })
        )
        |> put_kind(
          "r5e.examples",
          "DraftPolicyBundle",
          child("enterprise.r5e.io/v1/PolicyBundle", %{"requiresAuthority" => false})
        )
        |> put_kind(
          "r5e.examples",
          "LeaseDecision",
          child("harmony.r5e.io/v1/Decision", %{
            "overrides" => %{
              "reason" => "narrow subjectRef to SandboxLease",
              "replace" => %{
                "subjectRef" => %{
                  "type" => "ref",
                  "ref" => %{"kind" => "enterprise.r5e.io/v1/SandboxLease"}
                }
              }
            }
          })
        )

      assert {:ok, %{compiled: cs, manifests: manifests}} = Compiler.compile_packages(pkgs_ok)

      assert MapSet.member?(
               Kind.conforms_to_paths(cs[@ex <> "StrictBlob"]),
               "core.r5e.io/v1/Artifact"
             )

      assert MapSet.member?(
               Kind.conforms_to_paths(cs[@ex <> "RelaxedBlob"]),
               "core.r5e.io/v1/Artifact"
             )

      refute MapSet.member?(
               Kind.conforms_to_paths(cs[@ex <> "RelaxedBlob"]),
               @ex <> "StrictBlob"
             )

      assert MapSet.member?(
               Kind.conforms_to_paths(cs[@ex <> "DraftPolicyBundle"]),
               "core.r5e.io/v1/Artifact"
             )

      refute MapSet.member?(
               Kind.conforms_to_paths(cs[@ex <> "DraftPolicyBundle"]),
               "enterprise.r5e.io/v1/PolicyBundle"
             )

      assert cs[@ex <> "LeaseDecision"].published_spec["pins"]["dependencyRefs"][
               "enterprise.r5e.io/v1/SandboxLease"
             ] == manifests["r5e.enterprise"].ref <> "#enterprise.r5e.io/v1/SandboxLease"
    end
  end

  describe "definition references and typed refs" do
    test "a definition reference names a manifest and a member, and is its own ref form", %{
      state: st
    } do
      cs = st.compiled
      a = cs[@ex <> "SecurityReview"]
      b = cs[@ex <> "ExploratoryReview"]

      [a_manifest, a_member] = String.split(a.definition_ref, "#", parts: 2)
      [b_manifest, _b_member] = String.split(b.definition_ref, "#", parts: 2)

      assert a_manifest == b_manifest
      assert a_manifest == st.manifests["r5e.examples"].ref
      assert a_member == a.path
      refute a.definition_ref == b.definition_ref
      assert MapSet.member?(a.conforms_to, cs["core.r5e.io/v1/Artifact"].definition_ref)
      refute MapSet.member?(a.conforms_to, "core.r5e.io/v1/Artifact")

      assert :ok = Validate.check_ref(a.definition_ref, %{"definition" => true})

      # The publication-based forms are no longer definition references.
      for old <- [
            "event:sha256:" <> String.duplicate("a", 64) <> "#core.r5e.io/v1/Artifact",
            "foundation:sha256:" <> String.duplicate("a", 64) <> "#core.r5e.io/v1/Artifact"
          ] do
        assert {:error, "expected_definition_ref"} =
                 Validate.check_ref(old, %{"definition" => true})
      end

      assert {:error, "expected_event_ref"} =
               Validate.check_ref(a.definition_ref, %{"event" => "*"})

      # A bare manifest reference is a bytes ref, not a definition reference.
      assert {:error, "expected_definition_ref"} =
               Validate.check_ref(a_manifest, %{"definition" => true})

      assert :ok = Validate.check_ref(a_manifest, %{"bytes" => true})

      # `event:` and `bytes:` references keep their form.
      assert :ok =
               Validate.check_ref("event:sha256:" <> String.duplicate("c", 64), %{"event" => "*"})

      byte_schema = %{"type" => ["ref"], "ref" => %{"bytes" => true}}
      assert :ok = Schema.check_coherence(byte_schema, "contentRef")

      assert Schema.property_preserves?(byte_schema, %{
               "type" => "ref",
               "ref" => %{"bytes" => true}
             })

      assert {:error, [%{path: "$", code: "expected_bytes_ref"}]} =
               Validate.validate(byte_schema, "not-a-bytes-address")
    end

    test "a change to an imported parent or type reaches every dependent definition reference", %{
      base_pkgs: base
    } do
      ps1 =
        put_kind(base, "r5e.examples", "SiblingConsumer", %{
          "substrate" => "event",
          "description" => "Exact sibling consumer",
          "schema" => %{
            "properties" => %{
              "review" => %{
                "type" => "ref",
                "ref" => %{"event" => @ex <> "SecurityReview", "exact" => true}
              }
            }
          }
        })

      {:ok, %{compiled: ca}} = Compiler.compile_packages(ps1)

      ps2 =
        update_pkg(ps1, "r5e.harmony", fn pkg ->
          update_in(pkg, ["kinds", "Review", "schema", "required"], &(&1 ++ ["findingCount"]))
        end)

      {:ok, %{compiled: cb}} = Compiler.compile_packages(ps2)

      for name <- ["SecurityReview", "SiblingConsumer"] do
        refute ca[@ex <> name].definition_ref == cb[@ex <> name].definition_ref

        refute ca[@ex <> name].published_spec["pins"]["manifestRef"] ==
                 cb[@ex <> name].published_spec["pins"]["manifestRef"]
      end

      # Imported types and the refs embedded in them
      ps_imp1 =
        base
        |> update_pkg("r5e.harmony", fn pkg ->
          pkg
          |> put_in(["types", "ImportedText"], %{"type" => "string"})
          |> put_in(["types", "ImportedRef"], %{
            "type" => "ref",
            "ref" => %{"event" => "harmony.r5e.io/v1/Review"}
          })
        end)
        |> put_kind(
          "r5e.examples",
          "TypedSibling",
          child("core.r5e.io/v1/Artifact", %{
            "schema" => %{
              "properties" => %{
                "text" => %{"use" => "harmony.ImportedText"},
                "review" => %{"use" => "harmony.ImportedRef"}
              }
            }
          })
        )

      {:ok, st_imp1} = Compiler.compile_packages(ps_imp1)
      assert MapSet.member?(st_imp1.external_targets["r5e.examples"], "harmony.r5e.io/v1/Review")

      ps_imp2 =
        update_pkg(ps_imp1, "r5e.harmony", fn pkg ->
          put_in(pkg, ["types", "ImportedText", "pattern"], "^changed$")
        end)

      {:ok, st_imp2} = Compiler.compile_packages(ps_imp2)

      refute st_imp1.compiled[@ex <> "SecurityReview"].definition_ref ==
               st_imp2.compiled[@ex <> "SecurityReview"].definition_ref
    end

    test "kinds in one package may refer to each other in a cycle", %{state: st} do
      task = st.compiled["harmony.r5e.io/v1/Task"]
      spec = st.compiled["harmony.r5e.io/v1/Spec"]

      assert Enum.any?(task.property_ref_bindings, fn {_prop, targets} ->
               Map.has_key?(targets, "harmony.r5e.io/v1/Spec")
             end)

      assert Enum.any?(spec.property_ref_bindings, fn {_prop, targets} ->
               Map.has_key?(targets, "harmony.r5e.io/v1/Task")
             end)
    end
  end

  describe "checking values" do
    test "ordered compares instants, and a timestamp must be a real instant" do
      ts_schema = %{
        "type" => "object",
        "properties" => %{"a" => %{"type" => "string"}, "b" => %{"type" => "string"}},
        "ordered" => [["a", "b"]]
      }

      assert :ok = Schema.check_coherence(ts_schema, "times")
      plan = Validate.prepare(ts_schema)

      assert :ok = Validate.validate(plan, %{})
      assert :ok = Validate.validate(plan, %{"a" => "2026-01-01T00:00:00Z"})

      assert :ok =
               Validate.validate(plan, %{
                 "a" => "2026-01-01T01:00:00+02:00",
                 "b" => "2025-12-31T23:00:00Z"
               })

      assert :ok =
               Validate.validate(plan, %{
                 "a" => "2026-01-01T00:00:00.000000001Z",
                 "b" => "2026-01-01T00:00:00.000000002Z"
               })

      assert {:error, [%{path: "$", code: "out_of_order"}]} =
               Validate.validate(plan, %{
                 "a" => "2026-01-01T00:00:00.000000002Z",
                 "b" => "2026-01-01T00:00:00.000000001Z"
               })

      for bad <- [
            "2026-02-30T00:00:00Z",
            "2026-01-01T00:00:00-00:00",
            "2026-01-01T00:00:60Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00.0000000001Z",
            "2026-01-01T00:00:00+24:00",
            "2026-01-01 00:00:00Z",
            "not a timestamp"
          ] do
        assert {:error, [%{path: "$.a", code: "invalid_timestamp"}]} =
                 Validate.validate(plan, %{"a" => bad, "b" => "2026-03-01T00:00:00Z"}),
               bad
      end

      assert {:ok, 86_400_000_000_000} = Schema.timestamp_ns("0001-01-01T00:00:00Z")

      assert {:ok, 86_400_000_000_000} =
               Schema.timestamp_ns("0001-01-01T01:30:00.000+01:30")
    end

    test "a rule that depends on the envelope needs the envelope" do
      env_schema = %{
        "type" => "object",
        "properties" => %{"parent" => %{"type" => "string"}},
        "requires" => [
          %{"when" => %{"envelope" => "authority", "present" => true}, "then" => ["parent"]}
        ]
      }

      plan = Validate.prepare(env_schema)

      assert {:error, [%{path: "$", code: "envelope_required"}]} = Validate.validate(plan, %{})
      assert :ok = Validate.validate(plan, %{}, envelope: %{})
      assert :ok = Validate.validate(plan, %{}, envelope: %{"authority" => nil})

      assert {:error, [%{path: "$.parent", code: "missing_conditional"}]} =
               Validate.validate(plan, %{}, envelope: %{"authority" => "fixture"})

      assert :ok =
               Validate.validate(plan, %{"parent" => "p"}, envelope: %{"authority" => "fixture"})
    end

    test "a property dropped and declared again conforms only if it names the same target", %{
      base_pkgs: base
    } do
      ps_re =
        base
        |> put_kind(
          "r5e.examples",
          "DroppedTaskReview",
          child("harmony.r5e.io/v1/Review", %{
            "overrides" => %{"reason" => "drop optional taskRef", "drop" => ["taskRef"]}
          })
        )
        |> put_kind(
          "r5e.examples",
          "ReintroducedTaskReview",
          child("harmony.r5e.io/v1/Review", %{
            "overrides" => %{"reason" => "redeclare taskRef", "drop" => ["taskRef"]},
            "schema" => %{
              "properties" => %{
                "taskRef" => %{"type" => "ref", "ref" => %{"kind" => "harmony.r5e.io/v1/Task"}}
              }
            }
          })
        )
        |> put_kind(
          "r5e.examples",
          "ReintroducedSessionReview",
          child("harmony.r5e.io/v1/Review", %{
            "overrides" => %{"reason" => "redeclare taskRef to Session", "drop" => ["taskRef"]},
            "schema" => %{
              "properties" => %{
                "taskRef" => %{"type" => "ref", "ref" => %{"kind" => "core.r5e.io/v1/Session"}}
              }
            }
          })
        )

      {:ok, %{compiled: cs_re}} = Compiler.compile_packages(ps_re)

      assert MapSet.member?(
               Kind.conforms_to_paths(cs_re[@ex <> "ReintroducedTaskReview"]),
               "harmony.r5e.io/v1/Review"
             )

      refute MapSet.member?(
               Kind.conforms_to_paths(cs_re[@ex <> "ReintroducedSessionReview"]),
               "harmony.r5e.io/v1/Review"
             )
    end

    test "a pattern describes the whole value, and cross-chain refs have one prefix", %{state: st} do
      cas = st.compiled["core.r5e.io/v1/CasObject"].validator

      good = %{
        "address" => "bytes:sha256:" <> String.duplicate("a", 64),
        "size" => 1,
        "mediaType" => "text/plain",
        "retention" => "standard"
      }

      assert :ok = Validate.validate(cas, good)

      assert {:error, [%{path: "$.address", code: "pattern_mismatch"}]} =
               Validate.validate(cas, %{good | "address" => good["address"] <> "\n"})

      assert Schema.strict_end_pattern("^a$|[$]\\$") == "^a\\z|[$]\\$"

      event = "event:sha256:" <> String.duplicate("a", 64)
      cross = %{"crossChain" => true, "event" => "*"}

      c1 = "evidence:sha256:" <> String.duplicate("1", 64)
      c2 = "evidence:sha256:" <> String.duplicate("2", 64)

      assert :ok = Validate.check_ref("chain:" <> c1 <> "/" <> event, cross)

      # A chain is named by the record that founded it, not by a label.
      assert {:error, "malformed_cross_chain_ref"} =
               Validate.check_ref("chain:r5e:sub-1/" <> event, cross)

      assert {:error, "malformed_cross_chain_ref"} =
               Validate.check_ref("chain:" <> c1 <> "/chain:" <> c2 <> "/" <> event, cross)

      assert {:error, "malformed_cross_chain_ref"} = Validate.check_ref("chain:" <> c1, cross)

      assert {:error, "cross_chain_forbidden"} =
               Validate.check_ref("chain:" <> c1 <> "/" <> event, %{"event" => "*"})

      any = %{"anyOf" => [%{"bytes" => true}, %{"kind" => "*"}]}
      assert :ok = Validate.check_ref("core.r5e.io/v1/Session/abc", any)
      assert {:error, "ref_alternatives_mismatch"} = Validate.check_ref(event, any)
      assert {:error, "expected_resource_ref"} = Validate.check_ref(event, %{"kind" => "*"})
    end

    test "fixture kinds accept good bodies and name what is wrong with bad ones", %{state: st} do
      cs = st.compiled

      art_base = %{
        "contentRef" => "bytes:sha256:" <> String.duplicate("b", 64),
        "mediaType" => "text/markdown",
        "size" => 42
      }

      ev = "event:sha256:" <> String.duplicate("c", 64)

      rs_ck = cs["harmony.r5e.io/v1/ReviewSynthesis"]

      assert Kind.conforms_to_paths(rs_ck) ==
               MapSet.new([
                 "core.r5e.io/v1/Artifact",
                 "harmony.r5e.io/v1/Synthesis",
                 "harmony.r5e.io/v1/ReviewSynthesis"
               ])

      good =
        Map.merge(art_base, %{
          "subjectRef" => ev,
          "reviewRefs" => [ev],
          "outcome" => "meets-spec",
          "disagreements" => []
        })

      assert :ok = Validate.validate(rs_ck.validator, good)

      assert {:error, [%{path: "$.reviewRefs", code: "empty_value"}]} =
               Validate.validate(rs_ck.validator, %{good | "reviewRefs" => []})

      # Every broken rule is reported, sorted by path then code.
      assert {:error,
              [
                %{path: "$.extra", code: "unexpected_property"},
                %{path: "$.mediaType", code: "missing_required"},
                %{path: "$.reviewRefs[1]", code: "expected_event_ref"},
                %{path: "$.size", code: "below_minimum"}
              ]} =
               Validate.validate(
                 rs_ck.validator,
                 good
                 |> Map.delete("mediaType")
                 |> Map.merge(%{"extra" => 1, "size" => -1, "reviewRefs" => [ev, "nope"]})
               )

      # Principal, Endorsement and Badge no longer bind fields to signing
      # keys; their shape is still checked.
      kid = "key:ed25519:sha256:" <> String.duplicate("d", 64)

      assert :ok =
               Validate.validate(cs["core.r5e.io/v1/Principal"].validator, %{
                 "key" => kid,
                 "kind" => "agent",
                 "custody" => "host"
               })

      badge_body = %{
        "subject" => kid,
        "subjectKey" => %{"algorithm" => "ed25519", "bytes" => "AAAA"},
        "subjectKind" => "agent",
        "kinds" => ["harmony.r5e.io/v1/WorkProduct"],
        "mayIssue" => false,
        "notBefore" => "2026-11-02T00:00:00Z",
        "notAfter" => "2026-11-02T04:00:00Z"
      }

      badge = cs["core.r5e.io/v1/Badge"].validator
      assert :ok = Validate.validate(badge, badge_body, envelope: %{})

      assert {:error, [%{path: "$", code: "envelope_required"}]} =
               Validate.validate(badge, badge_body)

      assert {:error, [%{path: "$", code: "out_of_order"}]} =
               Validate.validate(badge, %{badge_body | "notAfter" => "2026-11-01T00:00:00Z"},
                 envelope: %{}
               )

      assert {:error, [%{path: "$.notAfter", code: "invalid_timestamp"}]} =
               Validate.validate(badge, %{badge_body | "notAfter" => "2026-02-30T00:00:00Z"},
                 envelope: %{}
               )

      assert {:error, [%{path: "$.mayIssue", code: "wrong_type"}]} =
               Validate.validate(badge, %{badge_body | "mayIssue" => nil}, envelope: %{})

      assert {:error, [%{path: "$.subjectKey.bytes", code: "wrong_type"}]} =
               Validate.validate(
                 badge,
                 put_in(badge_body, ["subjectKey", "bytes"], 1.5),
                 envelope: %{}
               )

      assert {:error, [%{path: "$", code: "wrong_type"}]} = Validate.validate(badge, [])
    end

    test "every code is a documented fixed word" do
      for code <- Validate.codes() do
        assert code =~ ~r/\A[a-z_]+\z/
      end

      assert Validate.codes() == Enum.uniq(Validate.codes())
    end

    test "each object rule is reported under its own code" do
      schema = %{
        "type" => "object",
        "additionalProperties" => false,
        "properties" => %{
          "label" => %{"type" => "string"},
          "mode" => %{"type" => "string", "enum" => ["plain", "target"]},
          "start" => %{"type" => "integer"},
          "end" => %{"type" => "integer", "maximum" => 10},
          "target" => %{"type" => "integer"},
          "a" => %{"type" => "integer"},
          "b" => %{"type" => "integer"},
          "x" => %{"type" => "integer"},
          "y" => %{"type" => "integer"},
          "tags" => %{"type" => "object", "values" => %{"type" => ["string", "boolean"]}}
        },
        "required" => ["label"],
        "nonEmpty" => ["label"],
        "ordered" => [["start", "end"]],
        "requires" => [
          %{"when" => %{"field" => "mode", "equals" => "target"}, "then" => ["target"]}
        ],
        "exactlyOne" => [["a", "b"]],
        "atMostOne" => [["x", "y"]]
      }

      assert :ok = Schema.check_coherence(schema, "s")
      plan = Validate.prepare(schema)
      good = %{"label" => "ok", "start" => 1, "end" => 2, "a" => 1, "x" => 1}
      assert :ok = Validate.validate(plan, good)

      for {mutation, path, code} <- [
            {%{"label" => ""}, "$.label", "empty_value"},
            {%{"start" => 3}, "$", "out_of_order"},
            {%{"mode" => "target"}, "$.target", "missing_conditional"},
            {%{"mode" => "other"}, "$.mode", "enum_mismatch"},
            {%{"b" => 1}, "$", "not_exactly_one"},
            {%{"y" => 1}, "$", "more_than_one"},
            {%{"end" => 11}, "$.end", "above_maximum"},
            {%{"start" => -9_007_199_254_740_992}, "$.start", "integer_out_of_range"},
            {%{"tags" => %{"k" => 1}}, "$.tags.k", "wrong_type"},
            {%{"start" => true}, "$.start", "wrong_type"},
            {%{"extra" => 1}, "$.extra", "unexpected_property"}
          ] do
        assert {:error, [%{path: ^path, code: ^code}]} =
                 Validate.validate(plan, Map.merge(good, mutation)),
               inspect(mutation)
      end

      assert {:error,
              [
                %{path: "$", code: "not_exactly_one"},
                %{path: "$.label", code: "missing_required"}
              ]} =
               Validate.validate(plan, %{})
    end
  end

  describe "meta-kinds" do
    test "a definition is checked against its meta-kind's nested object rules, and relaxing one breaks conformance",
         %{base_pkgs: base} do
      int_props =
        Map.new(["start", "end", "target", "a", "b", "x", "y"], fn k ->
          {k, %{"type" => "integer"}}
        end)

      config = %{
        "type" => "object",
        "additionalProperties" => false,
        "properties" =>
          Map.merge(int_props, %{
            "label" => %{"type" => "string"},
            "mode" => %{"type" => "string"}
          }),
        "required" => ["label"],
        "nonEmpty" => ["label"],
        "ordered" => [["start", "end"]],
        "requires" => [
          %{"when" => %{"field" => "mode", "equals" => "target"}, "then" => ["target"]}
        ],
        "exactlyOne" => [["a", "b"]],
        "atMostOne" => [["x", "y"]]
      }

      good = %{"label" => "ok", "start" => 1, "end" => 2, "a" => 1, "x" => 1}

      for {rule, mutation, code} <- [
            {"nonEmpty", %{"label" => ""}, "empty_value"},
            {"ordered", %{"start" => 3}, "out_of_order"},
            {"requires", %{"mode" => "target"}, "missing_conditional"},
            {"exactlyOne", %{"b" => 1}, "not_exactly_one"},
            {"atMostOne", %{"y" => 1}, "more_than_one"}
          ] do
        ps =
          base
          |> put_kind(
            "r5e.examples",
            "ConstrainedDefinition",
            child(@root, %{
              "schema" => %{"required" => ["config"], "properties" => %{"config" => config}}
            })
          )
          |> put_kind("r5e.examples", "Value", %{
            "definedBy" => @ex <> "ConstrainedDefinition",
            "substrate" => "event",
            "description" => "Definition checked recursively",
            "schema" => %{"properties" => %{}},
            "config" => Map.merge(good, mutation)
          })

        assert {:error,
                {:definition_violates_meta_kind, @ex <> "Value", @ex <> "ConstrainedDefinition",
                 [%{code: ^code}]}} = Compiler.compile_packages(ps)

        relaxed = Map.delete(config, rule)

        ps_relaxed =
          ps
          |> put_kind(
            "r5e.examples",
            "RelaxedDefinition",
            child(@ex <> "ConstrainedDefinition", %{
              "overrides" => %{
                "reason" => "Relax one domain rule",
                "replace" => %{"config" => relaxed}
              }
            })
          )
          |> update_pkg(
            "r5e.examples",
            &put_in(&1, ["kinds", "Value", "definedBy"], @ex <> "RelaxedDefinition")
          )

        assert {:ok, %{compiled: cs_rel}} = Compiler.compile_packages(ps_relaxed)

        refute MapSet.member?(
                 Kind.conforms_to_paths(cs_rel[@ex <> "RelaxedDefinition"]),
                 @ex <> "ConstrainedDefinition"
               )
      end
    end

    test "meta-kind fields are inherited, and changing or leaving them breaks conformance", %{
      base_pkgs: base
    } do
      ex_pkg = Enum.find(base, &(&1["package"] == "r5e.examples"))
      original_metric = ex_pkg["kinds"]["DocDiscoveryMetric"]["metric"]

      ps_metric =
        base
        |> update_pkg("r5e.examples", fn pkg ->
          put_in(
            pkg,
            ["kinds", "StrictDocDiscoveryMetric", "metric"],
            Map.put(original_metric, "direction", "higher-is-better")
          )
        end)
        |> put_kind(
          "r5e.examples",
          "RestoredMetric",
          child(@ex <> "StrictDocDiscoveryMetric", %{"metric" => original_metric})
        )
        |> put_kind(
          "r5e.examples",
          "OrdinaryMetric",
          child(@ex <> "DocDiscoveryMetric", %{"definedBy" => @root})
        )

      assert {:ok, %{compiled: cs_m}} = Compiler.compile_packages(ps_metric)

      assert cs_m[@ex <> "StrictDocDiscoveryMetric"].published_spec["metric"]["direction"] ==
               "higher-is-better"

      for name <- ["StrictDocDiscoveryMetric", "RestoredMetric", "OrdinaryMetric"] do
        refute MapSet.member?(
                 Kind.conforms_to_paths(cs_m[@ex <> name]),
                 @ex <> "DocDiscoveryMetric"
               )
      end

      refute Map.has_key?(cs_m[@ex <> "OrdinaryMetric"].published_spec, "metric")
      refute Map.has_key?(cs_m[@ex <> "OrdinaryMetric"].published_spec["pins"], "definedByRef")
    end
  end
end
