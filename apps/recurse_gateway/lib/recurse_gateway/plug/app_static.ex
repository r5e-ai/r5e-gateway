defmodule Recurse.Gateway.Plug.AppStatic do
  @moduledoc """
  Static-asset and SPA-fallback plug for the unified `r5e App` mounted at `/app`.

  Serves built frontend assets from `priv/static/app/` (or the path configured
  under `:recurse_gateway, :app_static_dir` in tests) when `index.html` exists.
  When `priv/static/app/index.html` is absent, returns a clean HTTP 404 JSON
  envelope instead of failing with a missing-file error.

  Sequence per request:

    1. Verify `index.html` exists in the static root (else 404).
    2. Refuse non-`GET`/non-`HEAD` methods with 404.
    3. Apply `Recurse.Gateway.Plug.SecurityHeaders`.
    4. Delegate to `Plug.Static` for real files under the static root.
    5. Return 404 for missing `/app/assets/*` files so broken asset requests
       never receive HTML.
    6. Serve `index.html` (`200 text/html`) as the client-side router fallback
       for `/app`, `/app/`, and SPA deep links.

  ## Iron Law check

  Pure module plug with no process state. Runs synchronously on the request
  process.
  """

  @behaviour Plug

  alias Recurse.Gateway.Plug.SecurityHeaders

  @impl Plug
  @spec init(keyword()) :: %{root: Path.t() | nil, default_static_opts: term()}
  def init(opts) when is_list(opts) do
    root = Keyword.get(opts, :root)

    from =
      if is_binary(root) and root != "", do: root, else: {:recurse_gateway, "priv/static/app"}

    %{
      root: root,
      default_static_opts: Plug.Static.init(at: "/", from: from, gzip: true)
    }
  end

  @impl Plug
  @spec call(Plug.Conn.t(), %{root: Path.t() | nil, default_static_opts: term()}) ::
          Plug.Conn.t()
  def call(%Plug.Conn{method: method} = conn, state) when method in ["GET", "HEAD"] do
    {root, static_opts} = resolve_root(state)
    index_path = Path.join(root, "index.html")

    if safe_path?(conn.path_info) and File.regular?(index_path) do
      if conn.request_path == "/app" do
        redirect_to_trailing_slash(conn)
      else
        serve(conn, static_opts, index_path)
      end
    else
      not_found(conn)
    end
  end

  def call(%Plug.Conn{} = conn, _state), do: not_found(conn)

  # Ensure relative asset URLs (`./assets/...`) inside `index.html` resolve
  # under `/app/` rather than `/`.
  defp redirect_to_trailing_slash(%Plug.Conn{query_string: ""} = conn) do
    conn
    |> Plug.Conn.put_resp_header("location", "/app/")
    |> Plug.Conn.send_resp(302, "")
  end

  defp redirect_to_trailing_slash(%Plug.Conn{query_string: qs} = conn) do
    conn
    |> Plug.Conn.put_resp_header("location", "/app/?" <> qs)
    |> Plug.Conn.send_resp(302, "")
  end

  defp safe_path?(segments) do
    not Enum.any?(segments, fn seg ->
      seg in ["..", "."] or String.contains?(seg, <<0>>) or String.contains?(seg, "\\")
    end)
  end

  defp serve(conn, static_opts, index_path) do
    conn =
      conn
      |> SecurityHeaders.call(SecurityHeaders.init([]))
      |> Plug.Static.call(static_opts)

    cond do
      conn.state in [:sent, :chunked, :file] ->
        conn

      match?(["assets" | _], conn.path_info) ->
        not_found(conn)

      true ->
        conn
        |> Plug.Conn.put_resp_content_type("text/html")
        |> Plug.Conn.send_file(200, index_path)
    end
  end

  defp resolve_root(%{root: explicit_root, default_static_opts: default_static_opts}) do
    case Application.get_env(:recurse_gateway, :app_static_dir) do
      dir when is_binary(dir) and dir != "" ->
        {dir, Plug.Static.init(at: "/", from: dir, gzip: true)}

      _ ->
        {runtime_root(explicit_root), default_static_opts}
    end
  end

  defp runtime_root(dir) when is_binary(dir) and dir != "", do: dir
  defp runtime_root(_), do: Application.app_dir(:recurse_gateway, "priv/static/app")

  defp not_found(conn) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(404, ~s({"error":"not_found"}))
  end
end
