defmodule Recurse.Gateway.Provenance.ToolResultsTest do
  @moduledoc """
  Reading tool results out of a decoded request, and remembering which
  recorded tool call each one answers.
  """
  use ExUnit.Case, async: false

  alias Recurse.Gateway.Provenance.ToolResults

  describe "extract/2, Anthropic Messages" do
    test "takes the tool results of the last message when it is the user's" do
      request = %{
        "messages" => [
          %{"role" => "user", "content" => "list the files"},
          %{
            "role" => "assistant",
            "content" => [%{"type" => "tool_use", "id" => "toolu_1", "name" => "Bash"}]
          },
          %{
            "role" => "user",
            "content" => [
              %{"type" => "tool_result", "tool_use_id" => "toolu_1", "content" => "a.txt\n"},
              %{
                "type" => "tool_result",
                "tool_use_id" => "toolu_2",
                "is_error" => true,
                "content" => [%{"type" => "text", "text" => "no such file"}]
              },
              %{"type" => "text", "text" => "and then?"}
            ]
          }
        ]
      }

      assert [
               %{call_id: "toolu_1", content: "a.txt\n", media_type: "text/plain", error?: false},
               %{call_id: "toolu_2", content: json, media_type: "application/json", error?: true}
             ] = ToolResults.extract(:anthropic_messages, request)

      assert Jason.decode!(json) == [%{"type" => "text", "text" => "no such file"}]
    end

    test "results earlier in the history are not taken again" do
      request = %{
        "messages" => [
          %{
            "role" => "user",
            "content" => [
              %{"type" => "tool_result", "tool_use_id" => "toolu_1", "content" => "x"}
            ]
          },
          %{"role" => "assistant", "content" => "done"},
          %{"role" => "user", "content" => "thanks"}
        ]
      }

      assert [] = ToolResults.extract(:anthropic_messages, request)
    end

    test "a result with no usable call id is left out, and odd requests give nothing" do
      block = fn id -> %{"type" => "tool_result", "tool_use_id" => id, "content" => "x"} end

      request = %{
        "messages" => [
          %{
            "role" => "user",
            "content" => [block.(nil), block.(""), block.(String.duplicate("a", 257)), block.(7)]
          }
        ]
      }

      assert [] = ToolResults.extract(:anthropic_messages, request)
      assert [] = ToolResults.extract(:anthropic_messages, %{})
      assert [] = ToolResults.extract(:anthropic_messages, %{"messages" => "nope"})
      assert [] = ToolResults.extract(:anthropic_messages, %{"messages" => [%{"role" => "user"}]})
      assert [] = ToolResults.extract(:something_else, request)
    end

    test "no more than sixty-four from one request" do
      blocks =
        for n <- 1..70,
            do: %{"type" => "tool_result", "tool_use_id" => "t#{n}", "content" => "x"}

      request = %{"messages" => [%{"role" => "user", "content" => blocks}]}
      assert length(ToolResults.extract(:anthropic_messages, request)) == 64
    end
  end

  describe "extract/2, OpenAI Responses" do
    test "takes the function outputs the input ends with" do
      request = %{
        "input" => [
          %{"type" => "function_call_output", "call_id" => "old", "output" => "earlier"},
          %{"type" => "message", "role" => "assistant", "content" => "ok"},
          %{"type" => "function_call", "call_id" => "call_1", "name" => "shell"},
          %{"type" => "function_call_output", "call_id" => "call_1", "output" => "a.txt"},
          %{"type" => "function_call_output", "call_id" => "call_2", "output" => %{"k" => 1}}
        ]
      }

      assert [
               %{call_id: "call_1", content: "a.txt", media_type: "text/plain", error?: false},
               %{call_id: "call_2", content: ~s({"k":1}), media_type: "application/json"}
             ] = ToolResults.extract(:openai_responses, request)
    end

    test "custom tool outputs count, and a client's own trailing message does not hide them" do
      request = %{
        "input" => [
          %{"type" => "custom_tool_call", "call_id" => "call_p", "name" => "apply_patch"},
          %{"type" => "function_call", "call_id" => "call_s", "name" => "shell"},
          %{"type" => "custom_tool_call_output", "call_id" => "call_p", "output" => "patched"},
          %{"type" => "function_call_output", "call_id" => "call_s", "output" => "ok"},
          %{"type" => "message", "role" => "developer", "content" => "environment context"}
        ]
      }

      assert [%{call_id: "call_p", content: "patched"}, %{call_id: "call_s", content: "ok"}] =
               ToolResults.extract(:openai_responses, request)

      # Outputs before the model's last turn were recorded when they were new.
      earlier =
        update_in(request["input"], &(&1 ++ [%{"type" => "message", "role" => "assistant"}]))

      assert [] = ToolResults.extract(:openai_responses, earlier)
    end

    test "an input that is text gives nothing" do
      assert [] = ToolResults.extract(:openai_responses, %{"input" => "hello"})
    end
  end

  describe "remember/3 and take/2" do
    setup do
      ToolResults.init()
      actor = "urn:r5e:principal:test:#{System.unique_integer([:positive])}"
      %{owner: {actor, :crypto.hash(:sha256, "credential")}, actor: actor}
    end

    test "a call is found once, by the caller who made it with the same credential", ctx do
      ref = "evidence:sha256:" <> String.duplicate("a", 64)
      :ok = ToolResults.remember(ctx.owner, "toolu_1", ref)

      # The same name with another credential is someone else.
      assert :error = ToolResults.take({ctx.actor, :crypto.hash(:sha256, "other")}, "toolu_1")
      assert :error = ToolResults.take({ctx.actor <> "x", elem(ctx.owner, 1)}, "toolu_1")
      assert {:ok, ^ref} = ToolResults.take(ctx.owner, "toolu_1")
      assert :error = ToolResults.take(ctx.owner, "toolu_1")
    end

    test "with no credential, or no call id, nothing is remembered or found", ctx do
      assert :ok = ToolResults.remember(nil, "toolu_1", "evidence:sha256:x")
      assert :error = ToolResults.take(nil, "toolu_1")
      assert :ok = ToolResults.remember(ctx.owner, nil, "evidence:sha256:x")
      assert :error = ToolResults.take(ctx.owner, nil)
    end
  end
end
