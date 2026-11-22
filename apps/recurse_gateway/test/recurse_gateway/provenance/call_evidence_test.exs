defmodule Recurse.Gateway.Provenance.CallEvidenceTest do
  @moduledoc """
  A proxied call recorded as Provenance v2 evidence: what the emitter
  writes when capture is running, and that it writes nothing else.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.LlmProxy.AttestationEmitter
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Gateway.Provenance.{Runtime, Signer}
  alias Recurse.Provenance.{Envelope, Export, Key, Ref}
  alias Recurse.Providers.Impls.PostgresEvidenceStore, as: Store
  alias Recurse.Providers.Repo
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @policy "permit(principal, action, resource);"
  @base "provenance.r5e.io/v2"

  setup %{tmp_dir: tmp_dir} do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    signer = Key.generate("es256")
    deployment = "test-#{System.unique_integer([:positive])}"

    start_supervised!(
      {Runtime,
       deployment: deployment, signer: signer, dir: tmp_dir, partitions: 2, flush_interval_ms: 20}
    )

    on_exit(fn -> :persistent_term.erase({Runtime, :info}) end)

    %{signer: signer, info: Runtime.info()}
  end

  defp intent(call_id, tool, args) do
    {:ok, intent} =
      ToolUseIntent.new(%{
        call_id: call_id,
        tool_name: tool,
        tool_args: args,
        provider_event_span: %{start_byte_offset: 0, end_byte_offset: 100, event_indices: [0]}
      })

    intent
  end

  defp bundle do
    hash = :crypto.hash(:sha256, @policy)

    %PolicyBundleRef{
      bundle_id: Base.encode16(hash, case: :lower),
      canonical_hash: hash,
      loaded_at: DateTime.utc_now(),
      evaluator_handle: @policy,
      bundle_bytes: @policy
    }
  end

  defp call_state(intents, overrides \\ %{}) do
    Map.merge(
      %{
        tenant_id: "01TENANT",
        principal_id: "alice@example.test",
        principal_kind: "obo_human",
        principal_source: :jwt,
        session_id: "session-1",
        client_session_id: "client-session-1",
        started_at: ~U[2026-11-09 12:00:00.000000Z],
        completed_at: ~U[2026-11-09 12:00:01.500000Z],
        model: "claude-opus",
        provider: "anthropic",
        upstream_host: "api.anthropic.com",
        transport: :https_sse,
        api_format: :anthropic_messages,
        request_path: "/v1/messages",
        prompt_hash: :crypto.hash(:sha256, "the prompt"),
        response_hash: :crypto.hash(:sha256, "the response"),
        request_payload: {:ok, "the prompt"},
        response_payload: {:ok, "the response"},
        prompt_token_count: 100,
        completion_token_count: 20,
        reasoning_token_count: nil,
        cedar_bundle_hash: :crypto.hash(:sha256, @policy),
        policy_bundle: bundle(),
        upstream_status_code: 200,
        error_kind: nil,
        intents: intents,
        latency_ms: 1500,
        added_latency_ms: 12,
        correlation_id: nil,
        parser_failed?: false
      },
      overrides
    )
  end

  # Everything this gateway has recorded on its observation streams,
  # once shipped. Each test uses one session, so this is one chain.
  defp stream_records(info) do
    :ok = Runtime.flush()
    prefix = "urn:r5e:stream:#{info.deployment}:gateway:%"

    from(r in "evidence_records", where: like(r.stream, ^prefix), order_by: r.seq, select: r.ref)
    |> Repo.all()
    |> Enum.map(fn ref -> elem(Store.fetch(Repo, ref), 1) end)
  end

  test "an allowed and a denied tool call are each their own signed record", %{info: info} do
    allow = intent("call-1", "Read", %{"path" => "README.md"})
    deny = intent("call-2", "Bash", %{"command" => "rm -rf /"})

    denial = %{
      rule_id: "no-destructive-shell",
      reason: "destructive shell commands are not permitted",
      suggested_alternative: nil
    }

    assert {:ok, "evidence:sha256:" <> _ = call_ref} =
             AttestationEmitter.emit_call_attestation(
               call_state([{allow, {:allow}}, {deny, {:deny, denial}}])
             )

    [model_call, tool_a, tool_b, response] = stream_records(info)

    assert model_call.ref == call_ref
    assert model_call.kind_path == @base <> "/ModelCall"
    assert model_call.evidence["actor"] == "urn:r5e:principal:01TENANT:alice%40example.test"
    # The session's name carries a fingerprint of the caller.
    assert model_call.evidence["session"] ==
             Recurse.Gateway.Provenance.SessionName.for(
               "01TENANT",
               "urn:r5e:principal:01TENANT:alice%40example.test",
               "client-session-1"
             )

    assert %{"contentRef" => prompt_ref, "size" => 10, "mediaType" => "application/json"} =
             model_call.evidence["body"]

    assert prompt_ref == Ref.bytes("the prompt")
    assert model_call.evidence["body"]["details"]["principalSource"] == "jwt"
    refute Map.has_key?(model_call.evidence["body"], "policy")

    assert tool_a.kind_path == @base <> "/ToolCall"
    assert tool_a.evidence["causes"] == [call_ref]
    assert tool_a.evidence["body"]["tool"] == "Read"
    assert tool_a.evidence["body"]["policy"]["outcome"] == "allow"
    assert tool_a.evidence["body"]["policy"]["policyRef"] == Ref.bytes(@policy)
    # The model's id for the call is a field of the record, not a detail.
    assert tool_a.evidence["body"]["callId"] == "call-1"
    refute Map.has_key?(Map.get(tool_a.evidence["body"], "details", %{}), "callId")
    refute Map.has_key?(tool_a.evidence["body"], "result")

    assert tool_b.evidence["body"]["policy"]["outcome"] == "deny"
    assert tool_b.evidence["body"]["policy"]["reason"] =~ "destructive"
    assert tool_b.evidence["body"]["result"]["outcome"] == "denied"
    assert tool_b.evidence["body"]["details"]["ruleId"] == "no-destructive-shell"

    assert response.kind_path == @base <> "/ModelResponse"
    assert response.evidence["body"]["call"] == call_ref
    assert response.evidence["body"]["outcome"] == "completed"
    assert response.evidence["body"]["contentRef"] == Ref.bytes("the response")
    assert response.evidence["body"]["details"]["toolCalls"] == 2

    # One chain, in order.
    assert Enum.map([model_call, tool_a, tool_b, response], & &1.seq) == [1, 2, 3, 4]
    assert tool_a.evidence["previous"] == model_call.ref

    # The exact policy and the retained payloads are held under their hashes.
    assert {:ok, @policy} = Store.get_blob(Repo, Ref.bytes(@policy))
    assert {:ok, "the prompt"} = Store.get_blob(Repo, Ref.bytes("the prompt"))
  end

  test "details are flat named scalars: nested maps become dotted names", %{info: info} do
    {:ok, _} =
      AttestationEmitter.emit_call_attestation(
        call_state([], %{
          parser: %{name: :anthropic_messages, version: 3, stages: ["sse", "json"]},
          parse: %{complete: true, note: String.duplicate("x", 3000), ratio: 0.5}
        })
      )

    [_call, response] = stream_records(info)
    details = response.evidence["body"]["details"]

    assert %{
             "parser.name" => "anthropic_messages",
             "parser.version" => 3,
             "parser.stages" => "sse,json",
             "parse.complete" => true
           } = details

    # Too long for a detail, and a fraction: left out, not cut or rounded.
    refute Map.has_key?(details, "parse.note")
    refute Map.has_key?(details, "parse.ratio")
    assert Enum.all?(details, fn {_k, v} -> is_binary(v) or is_integer(v) or is_boolean(v) end)
  end

  describe "a tool's output, sent back in the next request" do
    @credential :crypto.hash(:sha256, "Bearer the-callers-token")

    defp results do
      [
        %{call_id: "toolu_read", content: "# r5e\n", media_type: "text/plain", error?: false},
        # Never proposed through this gateway: nothing to point at.
        %{call_id: "toolu_unknown", content: "x", media_type: "text/plain", error?: true}
      ]
    end

    defp tool_result_count(info) do
      info |> stream_records() |> Enum.count(&(&1.kind_path == @base <> "/ToolResult"))
    end

    test "is recorded against its call, once", %{info: info} do
      read = intent("toolu_read", "Read", %{"path" => "README.md"})

      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([{read, {:allow}}], %{credential: @credential})
        )

      {:ok, next_call} =
        AttestationEmitter.emit_call_attestation(
          call_state([], %{tool_results: results(), credential: @credential})
        )

      [_call, tool_call, _response, model_call, tool_result, _response_2] = stream_records(info)

      assert model_call.ref == next_call
      assert tool_result.kind_path == @base <> "/ToolResult"
      assert tool_result.evidence["causes"] == [next_call]

      assert %{
               "call" => call,
               "callId" => "toolu_read",
               "outcome" => "completed",
               "contentRef" => content,
               "mediaType" => "text/plain",
               "size" => 6
             } = tool_result.evidence["body"]

      assert call == tool_call.ref
      assert content == Ref.bytes("# r5e\n")
      assert {:ok, "# r5e\n"} = Store.get_blob(Repo, content)

      # The same request again records the call and not the result a second time.
      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([], %{tool_results: results(), credential: @credential})
        )

      assert tool_result_count(info) == 1
    end

    test "is not recorded for someone presenting another credential, or none", %{info: info} do
      read = intent("toolu_read", "Read", %{"path" => "README.md"})

      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([{read, {:allow}}], %{credential: @credential})
        )

      # The same stated name and session, a different credential.
      other = :crypto.hash(:sha256, "Bearer someone-elses-token")

      for credential <- [other, nil] do
        {:ok, _} =
          AttestationEmitter.emit_call_attestation(
            call_state([], %{tool_results: results(), credential: credential})
          )
      end

      assert tool_result_count(info) == 0

      # The rightful caller's result is still matched afterwards.
      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([], %{tool_results: results(), credential: @credential})
        )

      assert tool_result_count(info) == 1
    end

    test "is not recorded from a request the provider turned away", %{info: info} do
      read = intent("toolu_read", "Read", %{"path" => "README.md"})

      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([{read, {:allow}}], %{credential: @credential})
        )

      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([], %{
            tool_results: results(),
            credential: @credential,
            upstream_status_code: 401
          })
        )

      assert tool_result_count(info) == 0
    end

    test "has nothing to point at when the gate denied the call", %{info: info} do
      bash = intent("toolu_read", "Bash", %{"command" => "rm -rf /"})
      denial = %{rule_id: "no", reason: "not permitted", suggested_alternative: nil}

      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([{bash, {:deny, denial}}], %{credential: @credential})
        )

      {:ok, _} =
        AttestationEmitter.emit_call_attestation(
          call_state([], %{tool_results: results(), credential: @credential})
        )

      assert tool_result_count(info) == 0
    end
  end

  test "nothing is written in the older format while evidence capture is running" do
    {:ok, _} = AttestationEmitter.emit_call_attestation(call_state([]))

    assert Repo.aggregate(from(a in "attestations"), :count) == 0
    assert Repo.aggregate(from(r in "llm_call_records"), :count) == 0
  end

  test "with no policy loaded, a tool call is recorded without inventing an evaluation", %{
    info: info
  } do
    read = intent("call-1", "Read", %{"path" => "a"})

    {:ok, _} =
      AttestationEmitter.emit_call_attestation(
        call_state([{read, {:allow}}], %{policy_bundle: :no_bundle})
      )

    [_call, tool, _response] = stream_records(info)
    refute Map.has_key?(tool.evidence["body"], "policy")
  end

  test "a gate error is recorded as an evaluation error, and the call was withheld", %{info: info} do
    bash = intent("call-1", "Bash", %{"command" => "ls"})

    error = %{
      rule_id: "policy_evaluation_error",
      reason: "policy evaluation error: :timeout",
      suggested_alternative: nil
    }

    {:ok, _} =
      AttestationEmitter.emit_call_attestation(
        call_state([{bash, {:deny, error}}], %{error_kind: "policy_evaluation_failure"})
      )

    [_call, tool, response] = stream_records(info)
    assert tool.evidence["body"]["policy"]["outcome"] == "error"
    assert tool.evidence["body"]["result"]["outcome"] == "denied"
    assert response.evidence["body"]["reason"] == "policy_evaluation_failure"
  end

  test "a spooled body past its bound is dropped and reported truncated" do
    capture =
      [enabled?: true, spool?: true, spool_max_bytes: 10]
      |> Recurse.Gateway.LlmProxy.PayloadCapture.init()
      |> Recurse.Gateway.LlmProxy.PayloadCapture.append("12345678")

    assert %{spool: {path, _device}} = capture

    capture =
      capture
      |> Recurse.Gateway.LlmProxy.PayloadCapture.append("90123")
      |> Recurse.Gateway.LlmProxy.PayloadCapture.append("more")

    assert :truncated = Recurse.Gateway.LlmProxy.PayloadCapture.result(capture)
    refute File.exists?(path)
  end

  test "a body of any size is spooled to disk, recorded, held, and its temporary file removed", %{
    info: info
  } do
    alias Recurse.Gateway.LlmProxy.PayloadCapture

    # Larger than the old 8 MiB in-memory cap, fed in chunks as a stream would be.
    chunk = :binary.copy("r", 1024 * 1024)

    capture =
      Enum.reduce(1..10, PayloadCapture.init(), fn _, acc -> PayloadCapture.append(acc, chunk) end)

    assert {:file, path} = spooled = PayloadCapture.result(capture)
    assert File.stat!(path).size == 10 * 1024 * 1024

    response = :binary.copy(chunk, 10)

    {:ok, _} =
      AttestationEmitter.emit_call_attestation(
        call_state([], %{
          response_payload: spooled,
          response_hash: :crypto.hash(:sha256, response)
        })
      )

    [_call, record] = stream_records(info)
    refute Map.has_key?(record.evidence["body"]["details"], "contentHeld")
    assert record.evidence["body"]["contentRef"] == Ref.bytes(response)
    assert record.evidence["body"]["size"] == byte_size(response)
    assert {:ok, ^response} = Store.get_blob(Repo, Ref.bytes(response))
    refute File.exists?(path)
  end

  test "a capture that failed is recorded as not held, and counted", %{info: info} do
    test_pid = self()
    handler = "content-not-held-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:recurse, :provenance, :content_not_held],
      fn _event, _measure, meta, _ -> send(test_pid, {:not_held, meta.direction}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    {:ok, _} =
      AttestationEmitter.emit_call_attestation(call_state([], %{response_payload: :truncated}))

    [call, response] = stream_records(info)
    refute Map.has_key?(call.evidence["body"]["details"], "contentHeld")
    assert response.evidence["body"]["details"]["contentHeld"] == false
    assert response.evidence["body"]["contentRef"] == Ref.bytes("the response")
    assert :error = Store.get_blob(Repo, Ref.bytes("the response"))
    assert_received {:not_held, "response"}
  end

  test "a failed upstream is a failed response with its status", %{info: info} do
    {:ok, _} =
      AttestationEmitter.emit_call_attestation(
        call_state([], %{upstream_status_code: 529, error_kind: "upstream_5xx"})
      )

    [_call, response] = stream_records(info)
    assert response.evidence["body"]["outcome"] == "failed"
    assert response.evidence["body"]["details"]["upstreamStatus"] == 529
  end

  test "the recorded call seals, exports and verifies offline", %{info: info, signer: signer} do
    read = intent("call-1", "Read", %{"path" => "a"})
    {:ok, _} = AttestationEmitter.emit_call_attestation(call_state([{read, {:allow}}]))
    {:ok, [seal]} = Runtime.seal()

    entries = stream_records(info)
    {:ok, seal_entry} = Store.fetch(Repo, seal.ref)

    blob_refs = [
      info.profile_ref,
      seal_entry.evidence["body"]["manifestRef"],
      Ref.bytes(@policy),
      Ref.bytes("the prompt"),
      Ref.bytes("the response")
    ]

    blobs = for ref <- blob_refs, do: {elem(Store.get_blob(Repo, ref), 1), nil}
    args_ref = Enum.at(entries, 1).evidence["body"]["contentRef"]

    {:ok, bundle} =
      Export.build(
        records: Enum.map(entries ++ [seal_entry], & &1.envelope),
        blobs: blobs,
        keys: [%{key_id: signer.key_id, algorithm: "es256", public_key: signer.public_key}],
        seals: [seal.ref],
        omissions: [%{ref: args_ref, reason: "unavailable"}]
      )

    report =
      Export.verify(bundle |> Jason.encode!() |> Jason.decode!(),
        trusted_profiles: [info.profile_ref]
      )

    assert report.summary.failed == 0
    assert Enum.count(report.findings, &(&1.check == :signature and &1.result == :ok)) == 4
    assert Enum.any?(report.findings, &(&1.check == :epoch and &1.result == :ok))
    assert Enum.all?(report.findings, &(&1.check != :authority or &1.result == :ok))
  end

  test "a signer built from the secrets provider's key signs verifiable evidence" do
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)

    # SubjectPublicKeyInfo for a P-256 key: a fixed header, then the point.
    der = Base.decode16!("3059301306072A8648CE3D020106082A8648CE3D030107034200") <> public
    pem = :public_key.pem_encode([{:SubjectPublicKeyInfo, der, :not_encrypted}])

    defmodule FakeSecrets do
      def active_signing_key(_), do: {:ok, %{key_id: "local", key_version: 1}}
      def public_key(%{pem: pem}, _), do: {:ok, pem}

      def sign(%{private: private}, _, message),
        do: {:ok, :crypto.sign(:ecdsa, :sha256, message, [private, :secp256r1])}
    end

    assert {:ok, signer} = Signer.from_secrets(FakeSecrets, %{pem: pem, private: private})
    assert signer.algorithm == "es256"
    assert {:ok, signer.key_id} == Key.id("es256", public)

    {:ok, signature} = signer.sign.("message")
    assert Key.verify("es256", "message", signature, public)
    assert Envelope.payload_type() =~ "provenance-evidence"
  end
end
