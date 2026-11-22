defmodule Recurse.Gateway.Provenance.DisclosingTest do
  @moduledoc """
  Providing recorded evidence outside the deployment: what the scan
  withholds, what the record says, and what the public can then read.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Provenance.{Disclosing, Runtime, Secrets}
  alias Recurse.Provenance.{Body, Export, Key, Pipeline, Ref}
  alias Recurse.Providers.Impls.PostgresEvidenceStore, as: Store
  alias Recurse.Providers.Repo

  @base "provenance.r5e.io/v2"
  @operator "urn:r5e:principal:test:operator"

  describe "the scan" do
    test "flags the shapes it knows and says which" do
      assert :clean = Secrets.scan("total 0\ndrwxr-xr-x  2 thomas staff 64 Nov 15 10:00 src\n")

      for {text, rule} <- [
            {"-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "private-key"},
            {"export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuv", "anthropic-token"},
            {"token ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github-token"},
            {"AKIAIOSFODNN7EXAMPLE", "aws-access-key"},
            {"Authorization: Bearer abcdefghijklmnop0123456789", "authorization-header"},
            {"Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==", "authorization-header"},
            {~s("db_password": "correct horse battery"), "named-secret"},
            # JSON carried inside JSON, as a request body carries earlier tool output.
            {~S({"content":"{\"db_password\": \"correct horse battery\"}"}), "named-secret"},
            {~S("headers":"{\"Authorization\": \"Bearer abcdefghijklmnop0123456789\"}"),
             "authorization-header"},
            {"postgres://app:hunter2hunter2@db.internal:5432/prod", "credentials-in-address"}
          ] do
        assert {:flagged, names} = Secrets.scan(text)
        assert rule in names, "#{rule} did not flag #{inspect(text)}; got #{inspect(names)}"
      end
    end

    test "a long hostile input does not take long" do
      hostile = String.duplicate("secret_", 45_000)
      {micros, _} = :timer.tc(fn -> Secrets.scan(hostile) end)
      assert micros < 1_000_000, "took #{div(micros, 1000)} ms on #{byte_size(hostile)} bytes"
    end

    test "does not vouch for what it cannot read" do
      assert :not_scanned = Secrets.scan(<<0xFF, 0xFE, 0x00>>)
      assert :not_scanned = Secrets.scan(String.duplicate("a", 8_388_609))
    end
  end

  describe "providing records" do
    setup %{tmp_dir: tmp_dir} do
      :ok = Sandbox.checkout(Repo)
      Sandbox.mode(Repo, {:shared, self()})
      deployment = "test-#{System.unique_integer([:positive])}"

      start_supervised!(
        {Runtime,
         deployment: deployment,
         signer: Key.generate("es256"),
         dir: tmp_dir,
         partitions: 1,
         flush_interval_ms: 20}
      )

      on_exit(fn ->
        Application.delete_env(:recurse_gateway, :evidence_public_read?)
        :persistent_term.erase({Runtime, :info})
      end)

      %{deployment: deployment}
    end

    # A recorded tool result whose content is `output`.
    defp recorded(output) do
      session =
        "urn:r5e:session:test:#{String.duplicate("a", 16)}.s#{System.unique_integer([:positive])}"

      {:ok, call} =
        Pipeline.capture(Runtime.pipeline(), %{
          kind_path: @base <> "/ToolCall",
          actor: "urn:r5e:principal:test:alice",
          session: session,
          attachments: [%{name: "args", bytes: ~s({"command":"ls"})}],
          body:
            Body.tool_call(
              tool: "Bash",
              content_ref: "attachment:args",
              media_type: "application/json",
              size: 16
            )
        })

      {:ok, result} =
        Pipeline.capture(Runtime.pipeline(), %{
          kind_path: @base <> "/ToolResult",
          actor: "urn:r5e:principal:test:alice",
          session: session,
          attachments: [%{name: "output", bytes: output}],
          body:
            Body.response(
              outcome: "completed",
              content_ref: "attachment:output",
              media_type: "text/plain",
              size: byte_size(output),
              call: call.ref
            )
        })

      :ok = Runtime.flush()
      result.ref
    end

    test "a clean record is provided whole, and the record of it says so", ctx do
      ref = recorded("total 0\n")
      content = Ref.bytes("total 0\n")

      assert {:ok,
              %{
                "ref" => disclosure,
                "outcome" => "provided",
                "provided" => provided,
                "withheld" => [],
                "notProvided" => []
              }} =
               Disclosing.disclose(
                 %{"records" => [ref], "recipient" => Disclosing.public(), "reason" => "release"},
                 @operator
               )

      assert ref in provided and content in provided

      assert {:ok, %{evidence: evidence}} = Store.fetch(Repo, disclosure)
      assert evidence["stream"] == Disclosing.stream(ctx.deployment)
      assert evidence["onBehalfOf"] == @operator

      assert %{
               "requestedRefs" => [^ref],
               "recipient" => "urn:r5e:audience:public",
               "outcome" => "provided",
               "details" => %{"scan.pieces" => 1, "scan.withheld" => 0}
             } = evidence["body"]

      refute Map.has_key?(evidence["body"], "scope")
    end

    test "content that looks like a secret takes its record with it" do
      secret = "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuv\n"
      ref = recorded(secret)
      content = Ref.bytes(secret)

      # The record would show the content's hash and size. Neither the
      # record nor the content is provided, and the answer names the
      # record, not the content.
      assert {:ok, %{"outcome" => "denied", "provided" => [], "withheld" => [withheld]}} =
               Disclosing.disclose(
                 %{"records" => [ref], "recipient" => Disclosing.public()},
                 @operator
               )

      assert %{"ref" => ^ref, "reason" => "content-flagged:" <> _} = withheld
      refute Disclosing.public?(ref)
      refute Disclosing.public_with?(ref, content)
    end

    test "asking to withhold flagged content does not bring its record back" do
      secret = "ANTHROPIC_API_KEY=sk-ant-api03-zyxwvutsrqponmlkjihgfe\n"
      ref = recorded(secret)

      assert {:ok, %{"outcome" => "denied", "withheld" => [%{"ref" => ^ref}]}} =
               Disclosing.disclose(
                 %{
                   "records" => [ref],
                   "recipient" => Disclosing.public(),
                   "withhold" => [Ref.bytes(secret)]
                 },
                 @operator
               )

      refute Disclosing.public?(ref)
    end

    test "content that cannot be scanned keeps its record back unless it is named" do
      unreadable = <<0xFF, 0xFE>> <> "API_KEY=abc"
      ref = recorded(unreadable)
      content = Ref.bytes(unreadable)

      assert {:ok,
              %{
                "outcome" => "denied",
                "withheld" => [%{"ref" => ^ref, "reason" => "content-not-scanned"}]
              }} =
               Disclosing.disclose(
                 %{"records" => [ref], "recipient" => Disclosing.public()},
                 @operator
               )

      refute Disclosing.public?(ref)

      # Named in `withhold`, the asker has said they know that content.
      assert {:ok, %{"outcome" => "partial", "provided" => [^ref]}} =
               Disclosing.disclose(
                 %{
                   "records" => [ref],
                   "recipient" => Disclosing.public(),
                   "withhold" => [content]
                 },
                 @operator
               )

      assert Disclosing.public?(ref)
      refute Disclosing.public_with?(ref, content)
    end

    test "what is public is the same after a restart", %{deployment: deployment} do
      one = recorded("first output\n")
      two = recorded("second output\n")

      {:ok, _} =
        Disclosing.disclose(
          %{"records" => [one, two], "recipient" => Disclosing.public()},
          @operator
        )

      before =
        for ref <- [one, two],
            content <- [Ref.bytes("first output\n"), Ref.bytes("second output\n")],
            do: {Disclosing.public?(ref), Disclosing.public_with?(ref, content)}

      :ok = Runtime.flush()
      %{store: store} = Runtime.info()
      :ok = Disclosing.init(store, deployment)

      after_restart =
        for ref <- [one, two],
            content <- [Ref.bytes("first output\n"), Ref.bytes("second output\n")],
            do: {Disclosing.public?(ref), Disclosing.public_with?(ref, content)}

      assert before == after_restart
    end

    test "content public through one record is not public through another that withheld it" do
      # Two records with the same bytes as their content.
      first = recorded("shared output\n")
      second = recorded("shared output\n")
      shared = Ref.bytes("shared output\n")

      {:ok, _} =
        Disclosing.disclose(
          %{"records" => [first], "recipient" => Disclosing.public()},
          @operator
        )

      {:ok, %{"withheld" => [%{"ref" => ^shared, "reason" => "asked-to-withhold"}]}} =
        Disclosing.disclose(
          %{"records" => [second], "recipient" => Disclosing.public(), "withhold" => [shared]},
          @operator
        )

      assert Disclosing.public_with?(first, shared)
      refute Disclosing.public_with?(second, shared)

      Application.put_env(:recurse_gateway, :evidence_public_read?, true)
      {:ok, text} = Disclosing.public_bundle(second)
      refute shared in Enum.map(Jason.decode!(text)["blobs"], & &1["ref"])
    end

    test "only a record's own content goes with it, unless more is named" do
      policy = "permit(principal, action, resource);"

      {:ok, call} =
        Pipeline.capture(Runtime.pipeline(), %{
          kind_path: @base <> "/ToolCall",
          actor: "urn:r5e:principal:test:alice",
          session:
            "urn:r5e:session:test:#{String.duplicate("b", 16)}.p#{System.unique_integer([:positive])}",
          attachments: [%{name: "args", bytes: ~s({"command":"ls"})}],
          blobs: [policy],
          body:
            Body.tool_call(
              tool: "Bash",
              content_ref: "attachment:args",
              media_type: "application/json",
              size: 16,
              policy:
                Body.policy_evaluation(
                  policy_ref: Ref.bytes(policy),
                  outcome: "allow",
                  input_refs: []
                )
            )
        })

      :ok = Runtime.flush()

      {:ok, %{"provided" => provided}} =
        Disclosing.disclose(
          %{"records" => [call.ref], "recipient" => Disclosing.public()},
          @operator
        )

      assert Ref.bytes(~s({"command":"ls"})) in provided
      # The deployment's policy is named by the record and is not its content.
      refute Ref.bytes(policy) in provided

      Application.put_env(:recurse_gateway, :evidence_public_read?, true)
      {:ok, text} = Disclosing.public_bundle(call.ref)
      refute text =~ Base.encode64(policy)
    end

    test "a record whose own fields look like a secret is not provided at all" do
      {:ok, noted} =
        Pipeline.capture(Runtime.pipeline(), %{
          kind_path: @base <> "/ToolCall",
          actor: "urn:r5e:principal:test:alice",
          session:
            "urn:r5e:session:test:#{String.duplicate("c", 16)}.d#{System.unique_integer([:positive])}",
          attachments: [%{name: "args", bytes: ~s({"command":"ls"})}],
          body:
            Body.tool_call(
              tool: "Bash",
              content_ref: "attachment:args",
              media_type: "application/json",
              size: 16,
              details: %{"env" => "API_KEY=abcdefghijklmnop"}
            )
        })

      :ok = Runtime.flush()

      assert {:ok,
              %{
                "outcome" => "denied",
                "provided" => [],
                "withheld" => [%{"reason" => "record-flagged:" <> _}]
              }} =
               Disclosing.disclose(
                 %{"records" => [noted.ref], "recipient" => Disclosing.public()},
                 @operator
               )

      refute Disclosing.public?(noted.ref)
    end

    test "a second read is served from what was built, and too many builds at once are turned away" do
      ref = recorded("total 0\n")

      {:ok, _} =
        Disclosing.disclose(%{"records" => [ref], "recipient" => Disclosing.public()}, @operator)

      Application.put_env(:recurse_gateway, :evidence_public_read?, true)

      {:ok, first} = Disclosing.public_bundle(ref)
      assert [{_, ^first, _until}] = :ets.lookup(Disclosing, {:bundle, ref})
      assert {:ok, ^first} = Disclosing.public_bundle(ref)

      # With every building place taken, a record not yet built is asked to wait.
      other = recorded("other\n")

      {:ok, _} =
        Disclosing.disclose(
          %{"records" => [other], "recipient" => Disclosing.public()},
          @operator
        )

      :ets.insert(Disclosing, {:building, 4})
      assert {:error, :busy} = Disclosing.public_bundle(other)
      assert [{:building, 4}] = :ets.lookup(Disclosing, :building)
      # What is already built is still served.
      assert {:ok, ^first} = Disclosing.public_bundle(ref)
      :ets.insert(Disclosing, {:building, 0})
    end

    test "content can be withheld by name, and a record that does not exist is said not to",
         _ctx do
      ref = recorded("fine\n")
      content = Ref.bytes("fine\n")
      missing = "evidence:sha256:" <> String.duplicate("0", 64)

      assert {:ok,
              %{
                "outcome" => "partial",
                "notProvided" => [^missing],
                "withheld" => [%{"ref" => ^content, "reason" => "asked-to-withhold"}]
              }} =
               Disclosing.disclose(
                 %{
                   "records" => [ref, missing],
                   "recipient" => "urn:r5e:principal:test:auditor",
                   "withhold" => [content]
                 },
                 @operator
               )

      # Provided to one named reader is not provided to the public.
      refute Disclosing.public?(ref)
    end

    test "a malformed request records nothing", ctx do
      assert {:error, :malformed_request} = Disclosing.disclose(%{"records" => []}, @operator)

      assert {:error, :malformed_request} =
               Disclosing.disclose(%{"records" => ["nope"], "recipient" => "x:y"}, @operator)

      ref = recorded("x\n")

      assert {:error, :malformed_request} =
               Disclosing.disclose(%{"records" => [ref, ref], "recipient" => "x:y"}, @operator)

      assert {:error, :malformed_request} =
               Disclosing.disclose(
                 %{"records" => [ref], "recipient" => "not an identity"},
                 @operator
               )

      assert {:error, :malformed_request} =
               Disclosing.disclose(
                 %{"records" => [ref], "recipient" => "x:y", "withhold" => ["nope"]},
                 @operator
               )

      # Nothing was signed for any of these.
      assert {:ok, nil} = Store.head(Repo, Disclosing.stream(ctx.deployment))
    end

    test "the public reads what was provided, only when reading is switched on" do
      clean = recorded("total 0\n")
      secret_text = "password = hunter2hunter2\n"
      secret = recorded(secret_text)
      private = recorded("never disclosed\n")

      held_text = "kept back by the operator\n"
      held = recorded(held_text)

      {:ok, _} =
        Disclosing.disclose(
          %{
            "records" => [clean, secret, held],
            "recipient" => Disclosing.public(),
            "withhold" => [Ref.bytes(held_text)]
          },
          @operator
        )

      # Off by default: nothing is served, disclosed or not.
      assert {:error, :not_public} = Disclosing.public_bundle(clean)

      Application.put_env(:recurse_gateway, :evidence_public_read?, true)

      assert {:ok, text} = Disclosing.public_bundle(clean)
      bundle = Jason.decode!(text)
      assert clean in Enum.map(bundle["records"], & &1["ref"])
      assert Ref.bytes("total 0\n") in Enum.map(bundle["blobs"], & &1["ref"])
      # It verifies like any other bundle: nothing in it fails.
      assert %{failed: 0} = Export.verify(bundle, []).summary

      # A record served without content the operator held back lists it
      # as withheld.
      assert {:ok, text} = Disclosing.public_bundle(held)
      bundle = Jason.decode!(text)
      refute Ref.bytes(held_text) in Enum.map(bundle["blobs"], & &1["ref"])
      assert %{"ref" => Ref.bytes(held_text), "reason" => "withheld"} in bundle["omissions"]

      # A record whose content was flagged is not served at all, so the
      # hash of that content is not shown either.
      assert {:error, :not_public} = Disclosing.public_bundle(secret)
      refute text =~ String.replace_prefix(Ref.bytes(secret_text), "bytes:sha256:", "")

      # Never disclosed, and never existed, answer the same.
      assert {:error, :not_public} = Disclosing.public_bundle(private)

      assert {:error, :not_public} =
               Disclosing.public_bundle("evidence:sha256:" <> String.duplicate("0", 64))
    end

    test "what is public is found again after a restart", %{
      tmp_dir: tmp_dir,
      deployment: deployment
    } do
      ref = recorded("total 0\n")

      {:ok, _} =
        Disclosing.disclose(%{"records" => [ref], "recipient" => Disclosing.public()}, @operator)

      assert Disclosing.public?(ref)

      stop_supervised!(Runtime)
      Runtime.stop()
      refute Disclosing.public?(ref)

      start_supervised!(
        {Runtime,
         deployment: deployment,
         signer: Key.generate("es256"),
         dir: tmp_dir,
         partitions: 1,
         flush_interval_ms: 20}
      )

      assert Disclosing.public?(ref)
    end
  end
end
