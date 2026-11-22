defmodule Recurse.Provenance.EvidenceLabelsTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.Evidence

  test "a tool call says how policy decided and which tool" do
    assert %{"policyOutcome" => "allow", "target" => "Bash"} ==
             Evidence.labels(%{
               "body" => %{"tool" => "Bash", "policy" => %{"outcome" => "allow"}}
             })
  end

  test "a policy decision says how it decided and what it was about" do
    assert %{"policyOutcome" => "deny", "target" => "rm -rf /"} ==
             Evidence.labels(%{
               "body" => %{
                 "evaluation" => %{"outcome" => "deny"},
                 "details" => %{"target" => "rm -rf /"}
               }
             })
  end

  test "a model call is found by provider and model" do
    assert %{"target" => "anthropic/claude"} ==
             Evidence.labels(%{"body" => %{"provider" => "anthropic", "model" => "claude"}})

    assert %{"target" => "claude"} == Evidence.labels(%{"body" => %{"model" => "claude"}})
  end

  test "a record with neither has none" do
    assert %{} == Evidence.labels(%{"body" => %{"outcome" => "ok", "tool" => 7}})
    assert %{} == Evidence.labels(%{"body" => %{"policy" => %{"outcome" => ""}}})
    assert %{} == Evidence.labels(%{})
  end
end
