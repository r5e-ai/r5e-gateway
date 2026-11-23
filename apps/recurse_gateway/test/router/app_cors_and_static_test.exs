defmodule Recurse.Gateway.Router.AppCorsAndStaticTest do
  @moduledoc """
  Verifies unified `r5e App` CORS (`R5E_APP_CORS_ORIGINS` -> `:app_cors_origins`)
  on `/v1/*` routes and static SPA serving at `/app` beside `/admin`.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Recurse.Gateway.Plug.{AppCors, AppStatic}
  alias Recurse.Gateway.Router

  @router_opts Router.init([])

  setup do
    prev_origins = Application.get_env(:recurse_gateway, :app_cors_origins)
    prev_static_dir = Application.get_env(:recurse_gateway, :app_static_dir)

    on_exit(fn ->
      restore_env(:app_cors_origins, prev_origins)
      restore_env(:app_static_dir, prev_static_dir)
    end)

    Application.delete_env(:recurse_gateway, :app_cors_origins)
    Application.delete_env(:recurse_gateway, :app_static_dir)
    :ok
  end

  describe "R5E_APP_CORS_ORIGINS parsing" do
    test "defaults to empty and strips blanks and wildcards" do
      assert AppCors.parse_origins(nil) == []
      assert AppCors.parse_origins("") == []
      assert AppCors.parse_origins(" , * , ") == []

      assert AppCors.parse_origins(
               " tauri://localhost , http://localhost:5173, *, tauri://localhost "
             ) ==
               ["tauri://localhost", "http://localhost:5173"]
    end
  end

  describe "CORS on /v1/* routes" do
    test "disabled by default when :app_cors_origins is unset or empty" do
      conn =
        :get
        |> Plug.Test.conn("/v1/schemas/index.json")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Router.call(@router_opts)

      assert Plug.Conn.get_resp_header(conn, "access-control-allow-origin") == []
      assert Plug.Conn.get_resp_header(conn, "access-control-allow-credentials") == []

      preflight =
        :options
        |> Plug.Test.conn("/v1/evidence/records")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Plug.Conn.put_req_header("access-control-request-method", "GET")
        |> Router.call(@router_opts)

      assert preflight.status == 404
      assert Plug.Conn.get_resp_header(preflight, "access-control-allow-origin") == []
    end

    test "allows configured tauri://localhost and dev origins with credentials and OPTIONS preflight" do
      Application.put_env(:recurse_gateway, :app_cors_origins, [
        "tauri://localhost",
        "http://localhost:5173"
      ])

      # Preflight OPTIONS for Tauri origin on /v1/evidence/records
      preflight =
        :options
        |> Plug.Test.conn("/v1/evidence/records")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Plug.Conn.put_req_header("access-control-request-method", "GET")
        |> Plug.Conn.put_req_header(
          "access-control-request-headers",
          "authorization, content-type"
        )
        |> Router.call(@router_opts)

      assert preflight.status == 204

      assert Plug.Conn.get_resp_header(preflight, "access-control-allow-origin") == [
               "tauri://localhost"
             ]

      assert Plug.Conn.get_resp_header(preflight, "access-control-allow-credentials") == ["true"]
      assert Plug.Conn.get_resp_header(preflight, "vary") == ["origin"]

      [allow_headers] = Plug.Conn.get_resp_header(preflight, "access-control-allow-headers")
      assert allow_headers =~ "authorization"
      assert allow_headers =~ "content-type"

      # Preflight OPTIONS for dev origin on POST /v1/evidence/export
      dev_preflight =
        :options
        |> Plug.Test.conn("/v1/evidence/export")
        |> Plug.Conn.put_req_header("origin", "http://localhost:5173")
        |> Plug.Conn.put_req_header("access-control-request-method", "POST")
        |> Plug.Conn.put_req_header(
          "access-control-request-headers",
          "authorization, content-type"
        )
        |> Router.call(@router_opts)

      assert dev_preflight.status == 204

      assert Plug.Conn.get_resp_header(dev_preflight, "access-control-allow-origin") ==
               ["http://localhost:5173"]

      assert Plug.Conn.get_resp_header(dev_preflight, "access-control-allow-credentials") == [
               "true"
             ]

      # Actual request from allowed origin carries ACAO + credentials + expose headers
      actual =
        :get
        |> Plug.Test.conn("/v1/schemas/index.json")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Router.call(@router_opts)

      assert Plug.Conn.get_resp_header(actual, "access-control-allow-origin") == [
               "tauri://localhost"
             ]

      assert Plug.Conn.get_resp_header(actual, "access-control-allow-credentials") == ["true"]
      assert Plug.Conn.get_resp_header(actual, "vary") == ["origin"]
    end

    test "does not emit CORS headers for disallowed origins, wildcards, or non-/v1 paths" do
      Application.put_env(:recurse_gateway, :app_cors_origins, [
        "*",
        "tauri://localhost"
      ])

      disallowed_get =
        :get
        |> Plug.Test.conn("/v1/schemas/index.json")
        |> Plug.Conn.put_req_header("origin", "https://evil.example")
        |> Router.call(@router_opts)

      assert Plug.Conn.get_resp_header(disallowed_get, "access-control-allow-origin") == []
      assert Plug.Conn.get_resp_header(disallowed_get, "access-control-allow-credentials") == []

      disallowed_preflight =
        :options
        |> Plug.Test.conn("/v1/evidence/records")
        |> Plug.Conn.put_req_header("origin", "https://evil.example")
        |> Plug.Conn.put_req_header("access-control-request-method", "GET")
        |> Router.call(@router_opts)

      assert Plug.Conn.get_resp_header(disallowed_preflight, "access-control-allow-origin") == []

      assert Plug.Conn.get_resp_header(disallowed_preflight, "access-control-allow-credentials") ==
               []

      # Preflight from an allowed origin requesting a disallowed method or header is rejected
      bad_method =
        :options
        |> Plug.Test.conn("/v1/evidence/records")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Plug.Conn.put_req_header("access-control-request-method", "TRACE")
        |> Router.call(@router_opts)

      assert bad_method.status == 204
      assert Plug.Conn.get_resp_header(bad_method, "access-control-allow-origin") == []

      bad_header =
        :options
        |> Plug.Test.conn("/v1/evidence/records")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Plug.Conn.put_req_header("access-control-request-method", "GET")
        |> Plug.Conn.put_req_header("access-control-request-headers", "x-disallowed-header")
        |> Router.call(@router_opts)

      assert bad_header.status == 204
      assert Plug.Conn.get_resp_header(bad_header, "access-control-allow-origin") == []

      # Non-/v1 paths never emit CORS headers even for an allowed origin
      healthz =
        :get
        |> Plug.Test.conn("/healthz")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Router.call(@router_opts)

      assert Plug.Conn.get_resp_header(healthz, "access-control-allow-origin") == []

      admin =
        :get
        |> Plug.Test.conn("/admin")
        |> Plug.Conn.put_req_header("origin", "tauri://localhost")
        |> Router.call(@router_opts)

      assert admin.status == 302
      assert Plug.Conn.get_resp_header(admin, "access-control-allow-origin") == []
    end
  end

  describe "static /app serving" do
    test "init/1 defers priv_dir resolution to runtime so releases do not bake build-stage paths" do
      state = AppStatic.init([])

      assert state.root == nil
      assert %{from: {:recurse_gateway, "priv/static/app"}} = state.default_static_opts
    end

    test "returns clean 404 when priv/static/app/index.html is absent", %{tmp_dir: tmp_dir} do
      empty_dir = Path.join(tmp_dir, "missing-app")
      Application.put_env(:recurse_gateway, :app_static_dir, empty_dir)

      for path <- ["/app", "/app/", "/app/enterprise/activity", "/app/assets/main.js"] do
        conn =
          :get
          |> Plug.Test.conn(path)
          |> Router.call(@router_opts)

        assert conn.status == 404, "expected 404 for #{path}, got #{conn.status}"
        assert JSON.decode!(conn.resp_body) == %{"error" => "not_found"}
      end
    end

    test "serves index.html, SPA deep links, and static assets with security headers when present",
         %{tmp_dir: tmp_dir} do
      app_dir = Path.join(tmp_dir, "app")
      assets_dir = Path.join(app_dir, "assets")
      File.mkdir_p!(assets_dir)

      html = "<!doctype html><html><body>r5e-app</body></html>"
      js = "console.log('r5e-app');"
      File.write!(Path.join(app_dir, "index.html"), html)
      File.write!(Path.join(assets_dir, "main.js"), js)
      File.write!(Path.join(tmp_dir, "outside.txt"), "top-secret")

      Application.put_env(:recurse_gateway, :app_static_dir, app_dir)

      # Bare /app redirects to /app/ so relative ./assets/* URLs resolve under /app/
      bare =
        :get
        |> Plug.Test.conn("/app")
        |> Router.call(@router_opts)

      assert bare.status == 302
      assert Plug.Conn.get_resp_header(bare, "location") == ["/app/"]

      # /app/ and SPA deep links serve index.html with security headers
      for path <- ["/app/", "/app/space/education/safeguarding"] do
        conn =
          :get
          |> Plug.Test.conn(path)
          |> Router.call(@router_opts)

        assert conn.status == 200
        assert conn.resp_body == html
        assert [ct] = Plug.Conn.get_resp_header(conn, "content-type")
        assert ct =~ "text/html"
        assert [_] = Plug.Conn.get_resp_header(conn, "content-security-policy")
        assert Plug.Conn.get_resp_header(conn, "x-content-type-options") == ["nosniff"]
        assert Plug.Conn.get_resp_header(conn, "x-frame-options") == ["DENY"]
      end

      # Static JS asset is served directly
      asset =
        :get
        |> Plug.Test.conn("/app/assets/main.js")
        |> Router.call(@router_opts)

      assert asset.status == 200
      assert asset.resp_body == js
      assert Plug.Conn.get_resp_header(asset, "x-content-type-options") == ["nosniff"]

      # Missing asset under /app/assets/* returns clean 404 (not HTML)
      missing_asset =
        :get
        |> Plug.Test.conn("/app/assets/does-not-exist.js")
        |> Router.call(@router_opts)

      assert missing_asset.status == 404
      assert JSON.decode!(missing_asset.resp_body) == %{"error" => "not_found"}

      # Non-GET requests to /app return clean 404
      post_conn =
        :post
        |> Plug.Test.conn("/app")
        |> Router.call(@router_opts)

      assert post_conn.status == 404

      # Path traversal outside app_dir is rejected cleanly with 404
      traversal =
        :get
        |> Plug.Test.conn("/app/assets/../../outside.txt")
        |> Router.call(@router_opts)

      assert traversal.status == 404
      refute traversal.resp_body =~ "top-secret"
    end
  end

  defp restore_env(key, nil), do: Application.delete_env(:recurse_gateway, key)
  defp restore_env(key, value), do: Application.put_env(:recurse_gateway, key, value)
end
