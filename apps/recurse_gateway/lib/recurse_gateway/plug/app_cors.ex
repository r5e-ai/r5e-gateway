defmodule Recurse.Gateway.Plug.AppCors do
  @moduledoc """
  Opt-in CORS plug for the unified `r5e App` on `/v1/*` routes.

  Reads the exact-origin allowlist from `Application.get_env(:recurse_gateway,
  :app_cors_origins, [])` (populated at boot from `R5E_APP_CORS_ORIGINS`).

  ## Security posture

    * **Disabled by default.** When `:app_cors_origins` is empty (`[]`), this
      plug is a no-op: no CORS headers are emitted and `OPTIONS` preflight
      requests are not intercepted.
    * **Scoped to `/v1/*` only.** Admin/app HTML surfaces (`/admin/*`,
      `/app/*`) and observability endpoints never emit CORS headers.
    * **No wildcards with credentials.** Wildcard `"*"` entries are stripped so
      arbitrary origins are never reflected alongside
      `Access-Control-Allow-Credentials: true`.
    * **Exact origin matching.** Supports `tauri://localhost` and explicit dev
      or web origins (for example `http://localhost:5173`).

  ## Iron Law check

  Pure module plug with no process state. Executes synchronously on the
  request process using `Plug.Conn`.
  """

  @behaviour Plug

  alias Plug.Conn

  @allow_methods ~w(GET POST PUT PATCH DELETE OPTIONS HEAD)
  @allow_methods_header Enum.join(@allow_methods, ", ")
  @allow_headers ~w(authorization content-type accept x-correlation-id x-request-id x-r5e-session-id cache-control)
  @allow_headers_header Enum.join(@allow_headers, ", ")
  @expose_headers_header Enum.join(
                           ~w(x-recurse-correlation-id x-r5e-content-ref content-disposition),
                           ", "
                         )
  @max_age "600"

  @impl Plug
  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @impl Plug
  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(%Conn{request_path: path} = conn, _opts) do
    if String.starts_with?(path, "/v1/") do
      handle_cors(conn, allowed_origins())
    else
      conn
    end
  end

  @doc """
  Parse a comma-separated `R5E_APP_CORS_ORIGINS` string into a deduplicated
  list of exact origins, dropping blank values and `"*"` wildcards.
  """
  @spec parse_origins(String.t() | nil) :: [String.t()]
  def parse_origins(nil), do: []

  def parse_origins(raw) when is_binary(raw) do
    raw
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == "" or &1 == "*"))
    |> Enum.uniq()
  end

  @doc "Return the currently configured exact CORS origins (wildcards stripped)."
  @spec allowed_origins() :: [String.t()]
  def allowed_origins do
    :recurse_gateway
    |> Application.get_env(:app_cors_origins, [])
    |> List.wrap()
    |> Enum.filter(&(is_binary(&1) and String.trim(&1) not in ["", "*"]))
    |> Enum.map(&String.trim/1)
    |> Enum.uniq()
  end

  @doc false
  @spec origin_allowed?(Plug.Conn.t(), String.t()) :: boolean()
  def origin_allowed?(_conn, origin) when is_binary(origin) and origin != "*" do
    origin in allowed_origins()
  end

  def origin_allowed?(_conn, _origin), do: false

  defp handle_cors(conn, []), do: conn

  defp handle_cors(conn, origins) do
    case Conn.get_req_header(conn, "origin") do
      [origin] -> dispatch_origin(conn, origin, origin in origins)
      _ -> conn
    end
  end

  defp dispatch_origin(conn, origin, true) do
    conn = put_vary_origin(conn)

    case preflight_method(conn) do
      {:preflight, req_method} -> handle_preflight(conn, origin, req_method)
      :actual -> put_actual_headers(conn, origin)
    end
  end

  defp dispatch_origin(conn, _origin, false) do
    conn = put_vary_origin(conn)

    case preflight_method(conn) do
      {:preflight, _req_method} -> conn |> Conn.send_resp(204, "") |> Conn.halt()
      :actual -> conn
    end
  end

  defp preflight_method(%Conn{method: "OPTIONS"} = conn) do
    case Conn.get_req_header(conn, "access-control-request-method") do
      [method] when method != "" -> {:preflight, String.upcase(String.trim(method))}
      _ -> :actual
    end
  end

  defp preflight_method(_conn), do: :actual

  defp handle_preflight(conn, origin, req_method) do
    if req_method in @allow_methods and requested_headers_allowed?(conn) do
      conn
      |> Conn.put_resp_header("access-control-allow-origin", origin)
      |> Conn.put_resp_header("access-control-allow-credentials", "true")
      |> Conn.put_resp_header("access-control-allow-methods", @allow_methods_header)
      |> Conn.put_resp_header("access-control-allow-headers", @allow_headers_header)
      |> Conn.put_resp_header("access-control-max-age", @max_age)
      |> Conn.send_resp(204, "")
      |> Conn.halt()
    else
      conn
      |> Conn.send_resp(204, "")
      |> Conn.halt()
    end
  end

  defp put_actual_headers(conn, origin) do
    conn
    |> Conn.put_resp_header("access-control-allow-origin", origin)
    |> Conn.put_resp_header("access-control-allow-credentials", "true")
    |> Conn.put_resp_header("access-control-expose-headers", @expose_headers_header)
  end

  defp requested_headers_allowed?(conn) do
    conn
    |> Conn.get_req_header("access-control-request-headers")
    |> Enum.flat_map(&String.split(&1, ",", trim: true))
    |> Enum.map(&(&1 |> String.trim() |> String.downcase()))
    |> Enum.reject(&(&1 == ""))
    |> Enum.all?(&(&1 in @allow_headers))
  end

  defp put_vary_origin(conn) do
    existing =
      conn
      |> Conn.get_resp_header("vary")
      |> Enum.flat_map(&String.split(&1, ",", trim: true))
      |> Enum.map(&String.trim/1)

    if Enum.any?(existing, &(String.downcase(&1) == "origin")) do
      conn
    else
      value = Enum.join(existing ++ ["origin"], ", ")
      Conn.put_resp_header(conn, "vary", value)
    end
  end
end
