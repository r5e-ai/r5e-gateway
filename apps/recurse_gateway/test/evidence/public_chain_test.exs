defmodule Recurse.Gateway.Evidence.PublicChainTest do
  @moduledoc """
  End-to-end Router + CORS + Verifier tests for opt-in `R5E_EVIDENCE_PUBLIC_CHAIN`
  (`GET /v1/public/chain`, `OPTIONS /v1/public/*`, and full-chain lookup on
  `GET /v1/public/evidence/:ref`).
  """

  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  import Plug.Conn
  import Plug.Test

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Provenance.{Disclosing, Runtime}
  alias Recurse.Gateway.Router
  alias Recurse.Provenance.{Body, Export, Key, Pipeline, Ref}
  alias Recurse.Providers.Repo

  @base "provenance.r5e.io/v2"
  @router_opts Router.init([])

  setup %{tmp_dir: tmp_dir} do
    owner = Sandbox.start_owner!(Repo, shared: true)
    on_exit(fn -> Sandbox.stop_owner(owner) end)

    deployment = "pubchain-#{System.unique_integer([:positive])}"

    start_supervised!(
      {Runtime,
       deployment: deployment,
       signer: Key.generate("es256"),
       dir: tmp_dir,
       partitions: 1,
       flush_interval_ms: 20}
    )

    prev_read = Application.get_env(:recurse_gateway, :evidence_public_read?)
    prev_chain = Application.get_env(:recurse_gateway, :evidence_public_chain?)
    prev_cors = Application.get_env(:recurse_gateway, :app_cors_origins)

    Application.delete_env(:recurse_gateway, :evidence_public_read?)
    Application.delete_env(:recurse_gateway, :evidence_public_chain?)
    Application.delete_env(:recurse_gateway, :app_cors_origins)

    on_exit(fn ->
      restore_env(:evidence_public_read?, prev_read)
      restore_env(:evidence_public_chain?, prev_chain)
      restore_env(:app_cors_origins, prev_cors)
      :persistent_term.erase({Runtime, :info})
    end)

    {:ok, deployment: deployment}
  end

  test "defaults fail closed: 404 on /v1/public/chain, no CORS, and refuses non-disclosed /v1/public/evidence/:ref" do
    rec_ref = capture_tool_call("default-private-payload\n")

    # 1. Both flags unset/false -> 404 and zero CORS headers
    c1 = router_call(:get, "/v1/public/chain")
    assert c1.status == 404
    assert JSON.decode!(c1.resp_body) == %{"error" => "not_found"}
    assert get_resp_header(c1, "access-control-allow-origin") == []

    # 2. Public read enabled, but public chain still false -> 404 on /v1/public/chain
    #    and 404 on non-disclosed /v1/public/evidence/:ref
    Application.put_env(:recurse_gateway, :evidence_public_read?, true)
    Application.put_env(:recurse_gateway, :evidence_public_chain?, false)

    c2 = router_call(:get, "/v1/public/chain")
    assert c2.status == 404
    assert JSON.decode!(c2.resp_body) == %{"error" => "not_found"}

    c3 = router_call(:get, "/v1/public/evidence/#{rec_ref}")
    assert c3.status == 404
    assert JSON.decode!(c3.resp_body) == %{"error" => "not_found"}

    # 3. Public chain true, but public read false -> still 404 (requires BOTH)
    Application.put_env(:recurse_gateway, :evidence_public_read?, false)
    Application.put_env(:recurse_gateway, :evidence_public_chain?, true)

    c4 = router_call(:get, "/v1/public/chain")
    assert c4.status == 404
    assert get_resp_header(c4, "access-control-allow-origin") == []
  end

  test "enabled public chain serves verified JSON bundle, CORS GET/OPTIONS, full-chain ref lookup, cache, and 503 busy guard" do
    payload = "live-dev-chain-tool-output\n"
    rec_ref = capture_tool_call(payload)

    Application.put_env(:recurse_gateway, :evidence_public_read?, true)
    Application.put_env(:recurse_gateway, :evidence_public_chain?, true)

    # 1. Preflight OPTIONS on /v1/public/chain allows GET, OPTIONS with `*` and no credentials
    opt_ok =
      conn(:options, "/v1/public/chain")
      |> put_req_header("origin", "https://explorer.r5e.io")
      |> put_req_header("access-control-request-method", "GET")
      |> Router.call(@router_opts)

    assert opt_ok.status == 204
    assert get_resp_header(opt_ok, "access-control-allow-origin") == ["*"]
    assert get_resp_header(opt_ok, "access-control-allow-methods") == ["GET, OPTIONS"]
    assert get_resp_header(opt_ok, "access-control-allow-credentials") == []

    # Non-read-only preflight method (POST) is refused (no allow-origin header)
    opt_post =
      conn(:options, "/v1/public/chain")
      |> put_req_header("origin", "https://explorer.r5e.io")
      |> put_req_header("access-control-request-method", "POST")
      |> Router.call(@router_opts)

    assert opt_post.status == 204
    assert get_resp_header(opt_post, "access-control-allow-origin") == []

    # 2. GET /v1/public/chain returns 200 valid JSON bundle with CORS and 0 failed records
    c_chain =
      conn(:get, "/v1/public/chain?limit=50")
      |> put_req_header("origin", "https://explorer.r5e.io")
      |> Router.call(@router_opts)

    assert c_chain.status == 200
    assert get_resp_header(c_chain, "access-control-allow-origin") == ["*"]
    assert get_resp_header(c_chain, "access-control-allow-credentials") == []

    bundle = JSON.decode!(c_chain.resp_body)
    assert bundle["format"] == "r5e.provenance-export/v2"
    assert rec_ref in Enum.map(bundle["records"], & &1["ref"])
    assert Ref.bytes(payload) in Enum.map(bundle["blobs"], & &1["ref"])
    assert %{failed: 0} = Export.verify(bundle, []).summary

    # Second read hits the ETS cache
    assert [{_, cached, _until}] = :ets.lookup(Disclosing, {:chain, 50})
    assert cached == c_chain.resp_body

    # 3. GET /v1/public/evidence/:ref serves non-disclosed chain record when public chain is true
    c_ref =
      conn(:get, "/v1/public/evidence/#{rec_ref}")
      |> put_req_header("origin", "https://explorer.r5e.io")
      |> Router.call(@router_opts)

    assert c_ref.status == 200
    assert get_resp_header(c_ref, "access-control-allow-origin") == ["*"]
    ref_bundle = JSON.decode!(c_ref.resp_body)
    assert rec_ref in Enum.map(ref_bundle["records"], & &1["ref"])
    assert Ref.bytes(payload) in Enum.map(ref_bundle["blobs"], & &1["ref"])
    assert %{failed: 0} = Export.verify(ref_bundle, []).summary

    # 4. Concurrency guard returns 503 when all build slots are busy on an uncached limit
    :ets.insert(Disclosing, {:building, 4})

    try do
      c_busy = router_call(:get, "/v1/public/chain?limit=49")
      assert c_busy.status == 503
      assert JSON.decode!(c_busy.resp_body) == %{"error" => "busy"}
    after
      :ets.insert(Disclosing, {:building, 0})
    end
  end

  defp router_call(method, path) do
    method
    |> conn(path)
    |> Router.call(@router_opts)
  end

  defp capture_tool_call(output) do
    session =
      "urn:r5e:session:dev:#{String.duplicate("a", 16)}.s#{System.unique_integer([:positive])}"

    {:ok, call} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: @base <> "/ToolCall",
        actor: "urn:r5e:principal:dev:builder",
        session: session,
        attachments: [%{name: "args", bytes: ~s({"command":"mix test"})}],
        body:
          Body.tool_call(
            tool: "Bash",
            content_ref: "attachment:args",
            media_type: "application/json",
            size: 22
          )
      })

    {:ok, result} =
      Pipeline.capture(Runtime.pipeline(), %{
        kind_path: @base <> "/ToolResult",
        actor: "urn:r5e:principal:dev:builder",
        session: session,
        attachments: [%{name: "out", bytes: output}],
        body:
          Body.response(
            outcome: "completed",
            content_ref: "attachment:out",
            media_type: "text/plain",
            size: byte_size(output),
            call: call.ref
          )
      })

    :ok = Runtime.flush()
    result.ref
  end

  defp restore_env(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore_env(key, value), do: Application.put_env(:recurse_gateway, key, value)
end
