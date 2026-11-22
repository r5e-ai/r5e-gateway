defmodule Recurse.Gateway.LlmProxy.CedarToolUseGateTest do
  @moduledoc """
  CT-001..CT-004 contract tests for `Recurse.Gateway.LlmProxy.CedarToolUseGate`
  (Spec 009 Phase 3 Sub-3.4 / T043).

  ## Test fixtures

  Cedar bundles are inlined as binaries — small enough to read inline
  and avoid filesystem coupling. Each test builds a `%PolicyBundleRef{}`
  directly without going through the BundleLoader (the bundle-snapshot
  semantic CT-003 simulates the loader by mutating the captured ref
  vs. the production-current ref independently).

  Per the orchestrator finding about Application.put_env races: this
  module does NOT use `Application.put_env` for any test-only seam. We
  pass per-test isolated DecisionCache instances via the `:cache` opt
  on `gate_context` (`name:` + `table_name:` per-test atoms) so async
  tests don't share cache state.
  """

  use ExUnit.Case, async: true

  alias Recurse.Cedar
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate.DecisionCache
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  @permissive_bundle "permit(principal, action, resource);\n"

  # Forbid invocation of the `shell` tool unconditionally — the simplest
  # rule that produces a `:deny`. We don't use schema-typed Cedar here;
  # the ToolUse type isn't in the F002 schema, but Cedar accepts
  # entity-name `ToolUse::"shell"` without strict-mode validation.
  # Permit anything by default; forbid the `shell` tool specifically.
  # Cedar's authorizer is "deny-by-default unless any permit applies, AND
  # no forbid applies" — so a bare `forbid` rule alone denies everything
  # because no permit ever fires. We pair the forbid with a baseline
  # permit so non-shell intents reach `:allow` cleanly.
  @forbid_shell_bundle ~S"""
  permit (principal, action, resource);

  forbid (
    principal,
    action == Action::"invoke_tool",
    resource == ToolUse::"shell"
  );
  """

  # Allow shell only for the `platform` group; deny for everyone else.
  # `principal` here is the User entity passed in via the entity store —
  # `principal.groups` resolves through the entity attrs.
  @group_gated_bundle ~S"""
  permit (
    principal,
    action == Action::"invoke_tool",
    resource
  );

  forbid (
    principal,
    action == Action::"invoke_tool",
    resource == ToolUse::"shell"
  ) when {
    !(principal.groups.contains("platform"))
  };
  """

  defp bundle_ref_for(source) do
    canonical_hash = Cedar.canonical_hash(source)

    %PolicyBundleRef{
      bundle_id: Base.encode16(canonical_hash, case: :lower),
      canonical_hash: canonical_hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: source,
      bundle_bytes: source
    }
  end

  defp build_intent(opts \\ []) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: Keyword.get(opts, :call_id, "call_test"),
        tool_name: Keyword.get(opts, :tool_name, "shell"),
        tool_args: Keyword.get(opts, :tool_args, %{"command" => "ls"}),
        provider_event_span: %{
          start_byte_offset: 0,
          end_byte_offset: 100,
          event_indices: [0]
        }
      })

    intent
  end

  defp gate_context(bundle, opts) do
    %{
      principal: %{
        id: Keyword.get(opts, :principal_id, "alice"),
        kind: :obo_human,
        chatgpt_account_id: nil,
        claims: %{"groups" => Keyword.get(opts, :groups, ["engineering"])}
      },
      model: Keyword.get(opts, :model, "gpt-5-codex"),
      tenant: "tenant-test",
      session_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ",
      prompt_hash: <<0::256>>,
      response_so_far_hash: <<0::256>>,
      estimated_completion_tokens: 100,
      parallel_tool_call_index: nil,
      cedar_bundle_hash: bundle.canonical_hash,
      upstream_domain: "chatgpt.com",
      transport: :wss,
      started_at: DateTime.utc_now(),
      bundle: bundle,
      args_inline_threshold_bytes:
        Keyword.get(opts, :threshold, CedarToolUseGate.default_args_inline_threshold_bytes()),
      cache: Keyword.get(opts, :cache, [])
    }
  end

  # Per-test isolated cache. The cache name + table name are derived from
  # the test name so async tests don't share state. Returns the cache
  # opts to thread into `gate_context.cache`.
  defp start_cache!(test_name) do
    name =
      String.to_atom(
        "Recurse.GW.LlmProxy.DecisionCache.#{test_name}.#{System.unique_integer([:positive])}"
      )

    table_name = DecisionCache.default_table_name(name)
    {:ok, _pid} = DecisionCache.start_link(name: name, table_name: table_name)
    on_exit_stop(name)
    [name: name, table_name: table_name]
  end

  defp on_exit_stop(name) do
    ExUnit.Callbacks.on_exit(fn ->
      with pid when is_pid(pid) <- Process.whereis(name),
           true <- Process.alive?(pid) do
        ref = Process.monitor(pid)

        try do
          GenServer.stop(pid, :normal, 500)
        catch
          :exit, _ -> :ok
        end

        receive do
          {:DOWN, ^ref, _, _, _} -> :ok
        after
          500 -> :ok
        end
      else
        _ -> :ok
      end
    end)
  end

  # ---------------------------------------------------------------------------
  # CT-001 — known fixture intent + known Cedar policy → expected decision
  # ---------------------------------------------------------------------------

  describe "CT-001 — fixture intent + fixture policy" do
    test "permissive bundle allows" do
      bundle = bundle_ref_for(@permissive_bundle)
      intent = build_intent(tool_name: "shell", tool_args: %{"command" => "ls"})
      cache = start_cache!("ct001-allow")
      ctx = gate_context(bundle, cache: cache)

      assert {:allow} = CedarToolUseGate.evaluate(intent, ctx)
    end

    test "forbid-shell bundle denies a shell intent" do
      bundle = bundle_ref_for(@forbid_shell_bundle)
      intent = build_intent(tool_name: "shell", tool_args: %{"command" => "ls"})
      cache = start_cache!("ct001-deny")
      ctx = gate_context(bundle, cache: cache)

      assert {:deny, %{rule_id: rule_id, reason: "denied_by_cedar_policy"}} =
               CedarToolUseGate.evaluate(intent, ctx)

      assert is_binary(rule_id)
    end

    test "forbid-shell bundle allows a non-shell intent" do
      bundle = bundle_ref_for(@forbid_shell_bundle)

      intent =
        build_intent(tool_name: "search", tool_args: %{"query" => "elixir"})

      cache = start_cache!("ct001-other")
      ctx = gate_context(bundle, cache: cache)

      assert {:allow} = CedarToolUseGate.evaluate(intent, ctx)
    end

    test "group-gated bundle denies non-platform principals on shell" do
      bundle = bundle_ref_for(@group_gated_bundle)
      intent = build_intent(tool_name: "shell")
      cache = start_cache!("ct001-group-deny")
      ctx = gate_context(bundle, cache: cache, groups: ["engineering"])

      assert {:deny, _} = CedarToolUseGate.evaluate(intent, ctx)
    end

    test "group-gated bundle allows platform principals on shell" do
      bundle = bundle_ref_for(@group_gated_bundle)
      intent = build_intent(tool_name: "shell")
      cache = start_cache!("ct001-group-allow")
      ctx = gate_context(bundle, cache: cache, groups: ["platform"])

      assert {:allow} = CedarToolUseGate.evaluate(intent, ctx)
    end
  end

  # ---------------------------------------------------------------------------
  # CT-002 — args-too-large → only hash provided
  # ---------------------------------------------------------------------------

  describe "CT-002 — args inlining threshold" do
    test "args under threshold are inlined in the Cedar context" do
      bundle = bundle_ref_for(@permissive_bundle)
      intent = build_intent(tool_args: %{"command" => "ls"})
      ctx = gate_context(bundle, threshold: 10_000)

      cedar_context = CedarToolUseGate.build_cedar_context(intent, ctx)

      assert Map.has_key?(cedar_context, "tool_args")
      assert cedar_context["tool_args"] == %{"command" => "ls"}
      assert Map.has_key?(cedar_context, "tool_args_hash")
    end

    test "args over threshold are NOT inlined; only hash is provided" do
      bundle = bundle_ref_for(@permissive_bundle)
      # 16-byte threshold; ls (~20 bytes encoded) exceeds it.
      big_args = %{"command" => String.duplicate("x", 1000)}
      intent = build_intent(tool_args: big_args)
      ctx = gate_context(bundle, threshold: 16)

      cedar_context = CedarToolUseGate.build_cedar_context(intent, ctx)

      refute Map.has_key?(cedar_context, "tool_args")
      assert Map.has_key?(cedar_context, "tool_args_hash")
      assert cedar_context["tool_args_size_bytes"] >= 16
    end

    test "permissive policy still reaches allow when args are too large" do
      bundle = bundle_ref_for(@permissive_bundle)
      big_args = %{"command" => String.duplicate("x", 1000)}
      intent = build_intent(tool_args: big_args)
      cache = start_cache!("ct002-allow-big")
      ctx = gate_context(bundle, threshold: 16, cache: cache)

      assert {:allow} = CedarToolUseGate.evaluate(intent, ctx)
    end

    test "resolve_args_inline_threshold/1 honours per-tenant override" do
      assert CedarToolUseGate.resolve_args_inline_threshold(%{
               "cedar_args_inline_threshold_bytes" => 200
             }) == 200
    end

    test "resolve_args_inline_threshold/1 falls back to default for invalid values" do
      assert CedarToolUseGate.resolve_args_inline_threshold(%{}) ==
               CedarToolUseGate.default_args_inline_threshold_bytes()

      assert CedarToolUseGate.resolve_args_inline_threshold(%{
               "cedar_args_inline_threshold_bytes" => "junk"
             }) == CedarToolUseGate.default_args_inline_threshold_bytes()

      assert CedarToolUseGate.resolve_args_inline_threshold(nil) ==
               CedarToolUseGate.default_args_inline_threshold_bytes()
    end
  end

  # ---------------------------------------------------------------------------
  # CT-003 — bundle snapshot semantic
  # ---------------------------------------------------------------------------

  describe "CT-003 — bundle snapshot at call-start" do
    test "evaluate/2 uses the snapshot in context.bundle even if a different bundle would be 'current' now" do
      # The whole test is independent of any global BundleLoader: the
      # gate's snapshot semantic is "use the bundle the caller passed
      # in via context.bundle". As long as that's preserved, the
      # snapshot semantic holds.
      original_bundle = bundle_ref_for(@permissive_bundle)
      _new_bundle = bundle_ref_for(@forbid_shell_bundle)

      intent = build_intent(tool_name: "shell")
      cache = start_cache!("ct003-snapshot")
      ctx_with_old = gate_context(original_bundle, cache: cache)

      # Even though a "newer" bundle now exists in our test harness,
      # evaluating against the snapshot the proxy captured at call
      # open MUST honor the snapshot.
      assert {:allow} = CedarToolUseGate.evaluate(intent, ctx_with_old)
    end

    test "snapshot_bundle/1 returns a stable %PolicyBundleRef{} from the configured Active module" do
      defmodule TestActive do
        @bundle %Recurse.Gateway.PolicyBundleRef{
          bundle_id: "deadbeef",
          canonical_hash: <<0::256>>,
          loaded_at: ~U[2026-05-07 00:00:00Z],
          evaluator_handle: "permit(principal, action, resource);",
          bundle_bytes: "permit(principal, action, resource);"
        }

        @envelope %Recurse.Gateway.Policy.Active{
          source: :filesystem,
          source_ref: "/tmp/test.cedar",
          loaded_at: ~U[2026-05-07 00:00:00Z],
          metadata: %{},
          bundle: @bundle
        }

        def current, do: {:ok, @envelope}
      end

      assert {:ok, %PolicyBundleRef{bundle_id: "deadbeef"}} =
               CedarToolUseGate.snapshot_bundle(active_module: TestActive)
    end
  end

  # ---------------------------------------------------------------------------
  # CT-004 — decision-cache hit returns same result as fresh eval
  # ---------------------------------------------------------------------------

  describe "CT-004 — decision cache hit-equals-miss" do
    test "two evaluations with identical inputs return identical results (cache hit)" do
      bundle = bundle_ref_for(@forbid_shell_bundle)
      intent = build_intent(tool_name: "shell")
      cache = start_cache!("ct004-cached")
      ctx = gate_context(bundle, cache: cache)

      decision1 = CedarToolUseGate.evaluate(intent, ctx)
      # Allow the GenServer cast to land before the second lookup.
      :ok = wait_for_cache_entry(cache, ctx, intent, bundle, 100)

      decision2 = CedarToolUseGate.evaluate(intent, ctx)

      assert decision1 == decision2
      assert match?({:deny, _}, decision1)
    end

    test "cache miss + cache hit produce identical decisions for an allow case" do
      bundle = bundle_ref_for(@permissive_bundle)
      intent = build_intent(tool_name: "any-tool")
      cache = start_cache!("ct004-allow")
      ctx = gate_context(bundle, cache: cache)

      d1 = CedarToolUseGate.evaluate(intent, ctx)
      :ok = wait_for_cache_entry(cache, ctx, intent, bundle, 100)
      d2 = CedarToolUseGate.evaluate(intent, ctx)

      assert d1 == d2
      assert d1 == {:allow}
    end

    test "different principals do NOT share cache entries" do
      bundle = bundle_ref_for(@group_gated_bundle)
      intent = build_intent(tool_name: "shell")
      cache = start_cache!("ct004-different")

      ctx_alice =
        gate_context(bundle, cache: cache, principal_id: "alice", groups: ["engineering"])

      ctx_bob = gate_context(bundle, cache: cache, principal_id: "bob", groups: ["platform"])

      assert {:deny, _} = CedarToolUseGate.evaluate(intent, ctx_alice)
      :ok = wait_for_cache_entry(cache, ctx_alice, intent, bundle, 100)
      # bob is in "platform" → allow, even though alice is cached as deny.
      assert {:allow} = CedarToolUseGate.evaluate(intent, ctx_bob)
    end
  end

  # ---------------------------------------------------------------------------
  # Wire-friendly accessors used by StreamingProxy + WebSocketBridge
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # Spec 012 S4 review — untrusted identifiers cannot become gate errors
  # ---------------------------------------------------------------------------

  describe "untrusted identifiers" do
    @bad_tool_names [
      ~s(x"y),
      "a\\b",
      "a\nb",
      "a\rb",
      String.duplicate("a", 300),
      "",
      "sp ace",
      ~s|Bash"; permit (principal, action, resource); //|,
      "ünïcode"
    ]

    test "tool names outside the safe charset are denied, never an error" do
      bundle = bundle_ref_for(@permissive_bundle)
      cache = start_cache!("bad_tool_names")

      for name <- @bad_tool_names do
        intent = build_intent(tool_name: name)

        assert {:deny, %{rule_id: "gateway.invalid_tool_name", reason: "invalid_tool_name"}} =
                 CedarToolUseGate.evaluate(intent, gate_context(bundle, cache: cache)),
               "expected deny for #{inspect(name)}"

        refute CedarToolUseGate.valid_tool_name?(name)
      end
    end

    test "tool names in the safe charset still evaluate" do
      bundle = bundle_ref_for(@forbid_shell_bundle)
      cache = start_cache!("good_tool_names")

      for name <- [
            "Bash",
            "mcp__linear__list_issues",
            "tool.v1:x-y_z",
            String.duplicate("a", 128)
          ] do
        assert CedarToolUseGate.valid_tool_name?(name)

        assert {:allow} =
                 CedarToolUseGate.evaluate(
                   build_intent(tool_name: name),
                   gate_context(bundle, cache: cache)
                 )
      end
    end

    test "a principal id with quotes, backslashes, newlines or control bytes cannot break the request" do
      bundle = bundle_ref_for(@forbid_shell_bundle)

      for id <- [
            ~s(x"y),
            "a\\b",
            "line\nbreak",
            "tab\tbed",
            <<1, 2, 3, 0x1F, 0x7F>>,
            ~s(claude-code:"),
            ~s(it's "quoted"),
            "ünïcode ❤",
            "user@example.com/path?x=1&y=2"
          ] do
        cache = start_cache!("principal_#{System.unique_integer([:positive])}")

        result =
          CedarToolUseGate.evaluate(
            build_intent(tool_name: "shell"),
            gate_context(bundle, principal_id: id, cache: cache)
          )

        assert match?({:deny, %{reason: "denied_by_cedar_policy"}}, result),
               "expected a Cedar deny (not an error) for #{inspect(id)}, got #{inspect(result)}"

        assert {:allow} =
                 CedarToolUseGate.evaluate(
                   build_intent(tool_name: "edit"),
                   gate_context(bundle, principal_id: id, cache: cache)
                 )
      end
    end

    test "a principal-keyed policy still matches an escaped id" do
      bundle =
        bundle_ref_for(~S"""
        permit (principal, action == Action::"invoke_tool", resource);

        forbid (
          principal == User::"eve\"quoted",
          action == Action::"invoke_tool",
          resource
        );
        """)

      cache = start_cache!("escaped_match")

      assert {:deny, _} =
               CedarToolUseGate.evaluate(
                 build_intent(),
                 gate_context(bundle, principal_id: ~s(eve"quoted), cache: cache)
               )

      assert {:allow} =
               CedarToolUseGate.evaluate(
                 build_intent(),
                 gate_context(bundle, principal_id: "eve", cache: cache)
               )
    end

    test "cedar_escape/1 escapes quotes, backslashes and control bytes; passes UTF-8 through" do
      assert CedarToolUseGate.cedar_escape(~s(a"b\\c\nd\re\tf)) == ~S(a\"b\\c\nd\re\tf)
      assert CedarToolUseGate.cedar_escape(~s(it's)) == ~S(it\'s)
      assert CedarToolUseGate.cedar_escape(<<1, 0x1F, 0x7F>>) == ~S(\u{1}\u{1f}\u{7f})
      assert CedarToolUseGate.cedar_escape("ünïcode") == "ünïcode"
      assert CedarToolUseGate.cedar_escape("") == ""
    end

    test "error decisions are not cached" do
      source = "this is not cedar {{{"

      bundle = %PolicyBundleRef{
        bundle_id: "broken",
        canonical_hash: :crypto.hash(:sha256, source),
        loaded_at: DateTime.utc_now(),
        evaluator_handle: source,
        bundle_bytes: source
      }

      cache = start_cache!("no_error_cache")
      intent = build_intent()

      assert {:error, :cedar_eval_error} =
               CedarToolUseGate.evaluate(intent, gate_context(bundle, cache: cache))

      key = {"alice", intent.tool_name, intent.tool_args_hash, bundle.canonical_hash}
      assert :miss = DecisionCache.get(key, cache)
    end
  end

  describe "build_gate_context_base/1 + gate_context_for_intent/2" do
    test "build + extract a per-intent context with parallel_tool_call_index" do
      bundle = bundle_ref_for(@permissive_bundle)

      base =
        CedarToolUseGate.build_gate_context_base(%{
          principal: %{id: "alice", kind: :obo_human, claims: %{}, chatgpt_account_id: nil},
          model: "gpt-5-codex",
          tenant: "t",
          session_id: "s",
          cedar_bundle_hash: bundle.canonical_hash,
          upstream_domain: "chatgpt.com",
          transport: :wss,
          started_at: DateTime.utc_now(),
          bundle: bundle
        })

      intent = build_intent()
      ctx = CedarToolUseGate.gate_context_for_intent(base, intent)

      assert Map.has_key?(ctx, :parallel_tool_call_index)
      assert Map.get(ctx, :estimated_completion_tokens) == 0
    end

    test "populate_estimated_tokens/2 wires TokenEstimator into the base" do
      bundle = bundle_ref_for(@permissive_bundle)

      base = %{
        principal: %{id: "alice", kind: :obo_human, claims: %{}, chatgpt_account_id: nil},
        model: "gpt-5-codex",
        tenant: "t",
        session_id: "s",
        cedar_bundle_hash: bundle.canonical_hash,
        upstream_domain: "chatgpt.com",
        transport: :wss,
        started_at: DateTime.utc_now(),
        bundle: bundle,
        prompt_hash: <<0::256>>,
        response_so_far_hash: <<0::256>>,
        parallel_tool_call_index: nil
      }

      enriched =
        CedarToolUseGate.populate_estimated_tokens(base, %{
          prompt_byte_size: 8000,
          request_params: %{}
        })

      assert enriched.estimated_completion_tokens == 2000
    end
  end

  # Spin-wait until the cache entry for `(intent,ctx,bundle)` is visible
  # via DecisionCache.get/2. Defensive: the put is GenServer.cast — there
  # is a small race where a hot-path lookup beats the cast. 100 iterations
  # at 1ms is plenty for tests.
  defp wait_for_cache_entry(cache, ctx, intent, bundle, attempts) when attempts > 0 do
    key =
      {ctx.principal.id, intent.tool_name, intent.tool_args_hash, bundle.canonical_hash}

    case DecisionCache.get(key, cache) do
      {:hit, _} ->
        :ok

      :miss ->
        Process.sleep(1)
        wait_for_cache_entry(cache, ctx, intent, bundle, attempts - 1)
    end
  end

  defp wait_for_cache_entry(_cache, _ctx, _intent, _bundle, 0), do: :ok
end
