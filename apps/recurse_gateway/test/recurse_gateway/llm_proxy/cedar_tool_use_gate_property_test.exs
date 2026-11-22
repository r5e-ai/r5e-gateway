defmodule Recurse.Gateway.LlmProxy.CedarToolUseGatePropertyTest do
  @moduledoc """
  PT-001 + PT-002 property tests for the Cedar tool-use gate (Spec 009
  Phase 3 Sub-3.4 / T044).

    * **PT-001 — Cedar evaluation determinism**: same input over many
      runs returns the same decision.
    * **PT-002 — Decision-cache correctness**: cache-hit return value
      matches the cache-miss return value.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Recurse.Cedar
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate
  alias Recurse.Gateway.LlmProxy.CedarToolUseGate.DecisionCache
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @permissive_bundle "permit(principal, action, resource);\n"
  @forbid_shell_bundle ~S"""
  permit (principal, action, resource);

  forbid (
    principal,
    action == Action::"invoke_tool",
    resource == ToolUse::"shell"
  );
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

  defp build_intent(tool_name, args) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: "call_test",
        tool_name: tool_name,
        tool_args: args,
        provider_event_span: %{
          start_byte_offset: 0,
          end_byte_offset: 100,
          event_indices: [0]
        }
      })

    intent
  end

  defp gate_context(bundle, principal_id, cache_opts) do
    %{
      principal: %{
        id: principal_id,
        kind: :obo_human,
        chatgpt_account_id: nil,
        claims: %{"groups" => ["engineering"]}
      },
      model: "gpt-5-codex",
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
      args_inline_threshold_bytes: 10_000,
      cache: cache_opts
    }
  end

  defp start_isolated_cache!(test_name) do
    name =
      String.to_atom(
        "Recurse.GW.PropCache.#{test_name}.#{System.unique_integer([:positive])}"
      )

    table_name = DecisionCache.default_table_name(name)
    {:ok, _pid} = DecisionCache.start_link(name: name, table_name: table_name)

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

    [name: name, table_name: table_name]
  end

  describe "PT-001 determinism" do
    property "same intent + context → same decision over many runs" do
      bundle = bundle_ref_for(@forbid_shell_bundle)
      cache = start_isolated_cache!("pt001-determinism")

      check all tool_name <- member_of(["shell", "search", "memory_lookup", "calc"]),
                args <-
                  fixed_map(%{
                    "command" => string(:alphanumeric, max_length: 20)
                  }),
                principal_id <-
                  member_of(["alice", "bob", "carol", "dave"]),
                max_runs: 200 do
        intent = build_intent(tool_name, args)
        ctx = gate_context(bundle, principal_id, cache)

        d1 = CedarToolUseGate.evaluate(intent, ctx)
        d2 = CedarToolUseGate.evaluate(intent, ctx)
        d3 = CedarToolUseGate.evaluate(intent, ctx)

        assert d1 == d2
        assert d2 == d3

        # Sanity check: shell denies, others allow under our test bundle.
        case tool_name do
          "shell" -> assert match?({:deny, _}, d1)
          _ -> assert d1 == {:allow}
        end
      end
    end

    property "permissive bundle always allows regardless of intent shape" do
      bundle = bundle_ref_for(@permissive_bundle)
      cache = start_isolated_cache!("pt001-permissive")

      check all tool_name <- string(:alphanumeric, min_length: 1, max_length: 30),
                args_keys <- list_of(string(:alphanumeric, min_length: 1, max_length: 10), max_length: 5),
                args_values <- list_of(string(:alphanumeric, max_length: 20), max_length: 5),
                principal_id <- string(:alphanumeric, min_length: 1, max_length: 30),
                max_runs: 100 do
        # Build a map from the two lists; use min-length to pair them.
        n = min(length(args_keys), length(args_values))

        args =
          args_keys
          |> Enum.take(n)
          |> Enum.zip(Enum.take(args_values, n))
          |> Map.new()

        intent = build_intent(tool_name, args)
        ctx = gate_context(bundle, principal_id, cache)

        assert {:allow} = CedarToolUseGate.evaluate(intent, ctx)
      end
    end
  end

  describe "PT-002 cache correctness" do
    property "cache-hit decision matches cache-miss decision for identical inputs" do
      bundle = bundle_ref_for(@forbid_shell_bundle)

      check all tool_name <- member_of(["shell", "search", "memory_lookup"]),
                principal_id <- member_of(["alice", "bob", "carol"]),
                max_runs: 100 do
        # Use a fresh cache per check-iteration so the first call is
        # always a miss and the second is always a hit.
        cache =
          start_isolated_cache!(
            "pt002-fresh-#{System.unique_integer([:positive])}"
          )

        intent = build_intent(tool_name, %{"x" => "y"})
        ctx = gate_context(bundle, principal_id, cache)

        # First call: cache miss → fresh evaluate.
        miss_decision = CedarToolUseGate.evaluate(intent, ctx)

        # Spin until the put cast lands so the second call deterministically
        # hits cache.
        :ok = wait_for_cache(cache, ctx, intent, bundle, 200)

        # Second call: cache hit (verified by the wait above).
        hit_decision = CedarToolUseGate.evaluate(intent, ctx)

        assert miss_decision == hit_decision
      end
    end

    property "different cache keys yield independent decisions" do
      bundle = bundle_ref_for(@forbid_shell_bundle)
      cache = start_isolated_cache!("pt002-independent")

      check all p1 <- member_of(["alice", "bob"]),
                p2 <- member_of(["carol", "dave"]),
                max_runs: 50 do
        intent_shell = build_intent("shell", %{"x" => "y"})
        intent_search = build_intent("search", %{"x" => "y"})

        # `shell` for p1 is cached as deny under group-gated would be —
        # but our test bundle is forbid_shell so shell is always deny.
        d_shell = CedarToolUseGate.evaluate(intent_shell, gate_context(bundle, p1, cache))
        d_search = CedarToolUseGate.evaluate(intent_search, gate_context(bundle, p2, cache))

        assert match?({:deny, _}, d_shell)
        assert d_search == {:allow}
      end
    end
  end

  defp wait_for_cache(cache, ctx, intent, bundle, attempts) when attempts > 0 do
    key =
      {ctx.principal.id, intent.tool_name, intent.tool_args_hash, bundle.canonical_hash}

    case DecisionCache.get(key, cache) do
      {:hit, _} ->
        :ok

      :miss ->
        Process.sleep(1)
        wait_for_cache(cache, ctx, intent, bundle, attempts - 1)
    end
  end

  defp wait_for_cache(_cache, _ctx, _intent, _bundle, 0), do: :ok
end
