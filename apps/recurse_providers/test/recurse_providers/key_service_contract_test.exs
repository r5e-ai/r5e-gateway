defmodule Recurse.Providers.LocalKeyServiceContractTest do
  @moduledoc """
  Contract and file-hygiene tests for `Recurse.Providers.Impls.LocalKeyService`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.LocalKeyService

  @moduletag :tmp_dir

  use Recurse.Providers.KeyServiceContractSuite, impl: LocalKeyService

  defp build_service(%{tmp_dir: tmp_dir}) do
    path = Path.join(tmp_dir, "master-#{System.unique_integer([:positive])}.key")
    :ok = LocalKeyService.generate(path)
    {:ok, state} = LocalKeyService.open(path)
    state
  end

  describe "LocalKeyService specifics" do
    test "generate/1 writes a 0600 key file and refuses to overwrite", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "content.key")
      assert :ok = LocalKeyService.generate(path)
      assert {:ok, %File.Stat{mode: mode}} = File.stat(path)
      assert Bitwise.band(mode, 0o777) == 0o600
      assert {:error, :eexist} = LocalKeyService.generate(path)
    end

    test "open/1 rejects missing or malformed key files", %{tmp_dir: tmp_dir} do
      missing = Path.join(tmp_dir, "missing.key")
      short = Path.join(tmp_dir, "short.key")
      File.write!(short, Base.encode64(:crypto.strong_rand_bytes(16)))

      assert {:error, :unreadable_content_key} = LocalKeyService.open(missing)
      assert {:error, :unreadable_content_key} = LocalKeyService.open(short)
    end

    test "inspect/1 redacts master key bytes", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "secret.key")
      raw_b64 = File.exists?(path) || (:ok = LocalKeyService.generate(path))
      _ = raw_b64
      key_text = path |> File.read!() |> String.trim()
      {:ok, state} = LocalKeyService.open(path)

      rendered = inspect(state)
      assert rendered =~ ~s(#LocalKeyService<name: "local file secret.key", key: "[REDACTED]">)
      refute String.contains?(rendered, key_text)
    end
  end
end

defmodule Recurse.Providers.FakeKeyServiceContractTest do
  @moduledoc """
  Contract, key rotation, backup kill-switch, and audit-log tests for
  `Recurse.Providers.Impls.FakeKeyService`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.FakeKeyService

  use Recurse.Providers.KeyServiceContractSuite, impl: FakeKeyService

  defp build_service(_context) do
    {:ok, state} = FakeKeyService.start_link(key_name: "test-fake-master")
    ExUnit.Callbacks.on_exit(fn -> FakeKeyService.stop(state) end)
    state
  end

  describe "FakeKeyService rotation, kill-switch, and audit log" do
    test "tracks v1 -> v2 rotation, min_decryption_version kill-switch, and exact audit entries",
         context do
      state = build_service(context)
      dek_v1 = :crypto.strong_rand_bytes(32)
      dek_v2 = :crypto.strong_rand_bytes(32)

      assert FakeKeyService.latest_version(state) == 1
      assert FakeKeyService.min_decryption_version(state) == 1

      assert {:ok, "fakekms:v1:" <> _ = wrapped_v1} =
               FakeKeyService.wrap(state, dek_v1, "session:s1")

      assert {:ok, ^dek_v1} = FakeKeyService.unwrap(state, wrapped_v1, "session:s1")
      assert {:error, :not_unwrappable} = FakeKeyService.unwrap(state, wrapped_v1, "session:s2")

      assert :ok = FakeKeyService.rotate(state)
      assert FakeKeyService.latest_version(state) == 2

      assert {:ok, "fakekms:v2:" <> _ = wrapped_v2} =
               FakeKeyService.wrap(state, dek_v2, "session:s2")

      # Before raising min_decryption_version, v1 ciphertexts remain readable.
      assert {:ok, ^dek_v1} = FakeKeyService.unwrap(state, wrapped_v1, "session:s1")

      # Backup kill-switch: retiring v1 immediately blocks old ciphertexts while v2 works.
      assert :ok = FakeKeyService.set_min_decryption_version(state, 2)
      assert FakeKeyService.min_decryption_version(state) == 2
      assert {:error, :not_unwrappable} = FakeKeyService.unwrap(state, wrapped_v1, "session:s1")
      assert {:ok, ^dek_v2} = FakeKeyService.unwrap(state, wrapped_v2, "session:s2")

      assert {:error, :invalid_min_decryption_version} =
               FakeKeyService.set_min_decryption_version(state, 3)

      assert [
               {:wrap, 1, "session:s1", :ok},
               {:unwrap, 1, "session:s1", :ok},
               {:unwrap, 1, "session:s2", {:error, :not_unwrappable}},
               {:wrap, 2, "session:s2", :ok},
               {:unwrap, 1, "session:s1", :ok},
               {:unwrap, 1, "session:s1", {:error, :not_unwrappable}},
               {:unwrap, 2, "session:s2", :ok}
             ] = FakeKeyService.audit_log(state)

      assert :ok = FakeKeyService.clear_audit_log(state)
      assert [] = FakeKeyService.audit_log(state)
    end

    test "simulates KMS outage cleanly and records availability failure in audit_log", context do
      state = build_service(context)
      dek = :crypto.strong_rand_bytes(32)
      assert {:ok, wrapped} = FakeKeyService.wrap(state, dek, "session:outage")
      assert :ok = FakeKeyService.clear_audit_log(state)

      assert :ok = FakeKeyService.set_available(state, false)

      assert {:error, {:key_service_unavailable, :simulated_outage}} =
               FakeKeyService.wrap(state, dek, "session:outage")

      assert {:error, {:key_service_unavailable, :simulated_outage}} =
               FakeKeyService.unwrap(state, wrapped, "session:outage")

      assert [
               {:wrap, 1, "session:outage",
                {:error, {:key_service_unavailable, :simulated_outage}}},
               {:unwrap, 1, "session:outage",
                {:error, {:key_service_unavailable, :simulated_outage}}}
             ] = FakeKeyService.audit_log(state)
    end

    test "inspect/1 shows key name and agent pid without secret material", context do
      raw_key = "0123456789abcdef0123456789abcdef"
      {:ok, state} = FakeKeyService.start_link(key_name: "inspect-check", initial_key: raw_key)
      on_exit(fn -> FakeKeyService.stop(state) end)
      _ = context

      rendered = inspect(state)
      assert rendered =~ "#FakeKeyService<key: \"inspect-check\", agent: #PID<"
      refute String.contains?(rendered, raw_key)
    end
  end
end

defmodule Recurse.Providers.OpenBaoTransitKeyServiceContractTest do
  @moduledoc """
  Live OpenBao Transit (`127.0.0.1:8200`) contract tests
  for `Recurse.Providers.Impls.OpenBaoTransitKeyService`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.OpenBaoTransitKeyService

  # Runs only against a real OpenBao or Vault, when the two variables
  # below say where it is and where its token file is. The token is read
  # by the adapter and never appears in the test.
  @moduletag :openbao

  use Recurse.Providers.KeyServiceContractSuite, impl: OpenBaoTransitKeyService

  defp build_service(_context) do
    key_name = "test-r5e-" <> Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    url = System.fetch_env!("R5E_OPENBAO_URL")
    token_path = System.fetch_env!("R5E_OPENBAO_TOKEN_PATH")

    {:ok, state} =
      OpenBaoTransitKeyService.new(
        url: url,
        mount: "transit",
        key_name: key_name,
        token_path: token_path
      )

    :ok = OpenBaoTransitKeyService.ensure_key(state)
    state
  end

  describe "OpenBaoTransitKeyService live Transit ceremonies & error classification" do
    test "supports live key rotation (v1 -> v2) and min_decryption_version=2 backup kill-switch",
         context do
      state = build_service(context)
      dek_v1 = :crypto.strong_rand_bytes(32)
      dek_v2 = :crypto.strong_rand_bytes(32)

      assert {:ok, "vault:v1:" <> _ = wrapped_v1} =
               OpenBaoTransitKeyService.wrap(state, dek_v1, "session:live-v1")

      assert :ok = OpenBaoTransitKeyService.rotate(state)

      assert {:ok, "vault:v2:" <> _ = wrapped_v2} =
               OpenBaoTransitKeyService.wrap(state, dek_v2, "session:live-v2")

      # Both v1 and v2 decrypt before raising min_decryption_version.
      assert {:ok, ^dek_v1} =
               OpenBaoTransitKeyService.unwrap(state, wrapped_v1, "session:live-v1")

      assert {:ok, ^dek_v2} =
               OpenBaoTransitKeyService.unwrap(state, wrapped_v2, "session:live-v2")

      # Raise min_decryption_version to 2: v1 backup ciphertexts immediately become unwrappable.
      assert :ok = OpenBaoTransitKeyService.set_min_decryption_version(state, 2)

      assert {:error, :not_unwrappable} =
               OpenBaoTransitKeyService.unwrap(state, wrapped_v1, "session:live-v1")

      assert {:ok, ^dek_v2} =
               OpenBaoTransitKeyService.unwrap(state, wrapped_v2, "session:live-v2")
    end
  end
end

defmodule Recurse.Providers.OpenBaoTransitKeyServiceFaultTest do
  @moduledoc """
  How `Recurse.Providers.Impls.OpenBaoTransitKeyService` tells an outage
  from a key that cannot be unwrapped, against a stand-in server. Needs
  no OpenBao.
  """

  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.OpenBaoTransitKeyService
  alias Recurse.Providers.Support.MockHttpUpstream

  describe "error classification and redaction" do
    test "returns {:error, {:key_service_unavailable, _}} on unreachable TCP port" do
      {:ok, listen_socket} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, closed_port} = :inet.port(listen_socket)
      :ok = :gen_tcp.close(listen_socket)

      {:ok, state} =
        OpenBaoTransitKeyService.new(
          url: "http://127.0.0.1:#{closed_port}",
          mount: "transit",
          key_name: "unreachable-key",
          token: "placeholder-token",
          connect_options: [timeout: 500],
          receive_timeout_ms: 500
        )

      dek = :crypto.strong_rand_bytes(32)

      assert {:error, {:key_service_unavailable, _reason}} =
               OpenBaoTransitKeyService.wrap(state, dek, "session:down")

      assert {:error, {:key_service_unavailable, _reason}} =
               OpenBaoTransitKeyService.unwrap(state, "vault:v1:AAAA", "session:down")
    end

    test "distinguishes HTTP 403/503 transient/auth errors from HTTP 400 :not_unwrappable" do
      {:ok, upstream} = MockHttpUpstream.start()
      on_exit(fn -> MockHttpUpstream.stop(upstream) end)

      {:ok, state} =
        OpenBaoTransitKeyService.new(
          url: MockHttpUpstream.url(upstream),
          mount: "transit",
          key_name: "mocked-key",
          token: "unit-test-token"
        )

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(503, ~s({"errors":["OpenBao is sealed"]}))
      end)

      assert {:error, {:key_service_unavailable, {:http_status, 503, %{"errors" => [_]}}}} =
               OpenBaoTransitKeyService.unwrap(state, "vault:v1:AAAA", "session:sealed")

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(403, ~s({"errors":["permission denied"]}))
      end)

      assert {:error, {:key_service_unavailable, {:http_status, 403, %{"errors" => [_]}}}} =
               OpenBaoTransitKeyService.unwrap(state, "vault:v1:AAAA", "session:denied")

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(400, ~s({"errors":["cipher: message authentication failed"]}))
      end)

      assert {:error, :not_unwrappable} =
               OpenBaoTransitKeyService.unwrap(state, "vault:v1:AAAA", "session:bad-aad")
    end

    test "inspect/1 redacts token strictly" do
      canary_secret = "canary-secret-value-never-inspect-me"

      {:ok, state} =
        OpenBaoTransitKeyService.new(
          url: "http://127.0.0.1:8200/",
          mount: "/transit/",
          key_name: "r5e-content-master",
          token: canary_secret
        )

      rendered = inspect(state)

      assert rendered ==
               ~s(#OpenBaoTransitKeyService<url: "http://127.0.0.1:8200", mount: "transit", key: "r5e-content-master", token: "[REDACTED]">)

      refute String.contains?(rendered, canary_secret)
    end
  end
end
