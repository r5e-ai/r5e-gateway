defmodule Recurse.Gateway.Personal.Common do
  @moduledoc """
  Shared helpers for `/v1/personal/*` HTTP handlers: opt-in feature gate
  (`R5E_PERSONAL_ENABLED`), Cedar authz, strict household resolution bound to
  the authenticated principal, and JSON response formatting.
  """

  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.Personal.Policy
  alias Recurse.Providers.Personal, as: Store
  alias Recurse.Shared.IdentityContext

  @doc "Run `fun` only when `R5E_PERSONAL_ENABLED=true`; otherwise return 404."
  @spec require_enabled(Plug.Conn.t(), (Plug.Conn.t() -> Plug.Conn.t())) :: Plug.Conn.t()
  def require_enabled(conn, fun) do
    if Policy.enabled?() do
      fun.(conn)
    else
      json(conn, 404, %{"error" => "ERR_NOT_FOUND"})
    end
  end

  @doc "Gate a personal route with `R5E_PERSONAL_ENABLED` + Cedar `action`."
  @spec gate(Plug.Conn.t(), String.t(), String.t(), (Plug.Conn.t(), IdentityContext.t() ->
                                                       Plug.Conn.t())) :: Plug.Conn.t()
  def gate(conn, action, endpoint, fun) do
    require_enabled(conn, fn conn ->
      case Authz.gate(conn, action, resource(endpoint)) do
        {:ok, conn, %IdentityContext{} = ctx, _bundle_ref} -> fun.(conn, ctx)
        error -> Authz.dispatch_gate_error(conn, error)
      end
    end)
  end

  @doc "Gate a personal route against an ordered list of Cedar actions."
  @spec gate_any(
          Plug.Conn.t(),
          [String.t(), ...],
          String.t(),
          (Plug.Conn.t(), IdentityContext.t(), String.t() -> Plug.Conn.t())
        ) :: Plug.Conn.t()
  def gate_any(conn, actions, endpoint, fun) do
    require_enabled(conn, fn conn ->
      case Authz.gate_any(conn, actions, resource(endpoint)) do
        {:ok, conn, %IdentityContext{} = ctx, _bundle_ref, matched} -> fun.(conn, ctx, matched)
        error -> Authz.dispatch_gate_error(conn, error)
      end
    end)
  end

  @doc """
  Resolve the caller's household and member record strictly from the verified
  JWT `ctx` (plus optional `x-r5e-household-id` header verified against the
  caller's tenant and membership). Never returns another household's record.
  """
  @spec resolve_household_member(Plug.Conn.t(), IdentityContext.t()) ::
          {:ok, map(), map()} | {:error, :not_found}
  def resolve_household_member(conn, %IdentityContext{tenant_id: tenant_id} = ctx) do
    subject = subject_id(ctx)
    requested_hh = header(conn, "x-r5e-household-id")

    with {:ok, household} <- lookup_household(tenant_id, requested_hh),
         true <- household.tenant_id == tenant_id,
         {:ok, member} <- lookup_member(household.household_id, subject) do
      {:ok, household, member}
    else
      _ -> {:error, :not_found}
    end
  end

  defp lookup_household(_tenant_id, hh_id) when is_binary(hh_id) and hh_id != "" do
    Store.get_household(hh_id)
  end

  defp lookup_household(tenant_id, _nil) when is_binary(tenant_id) do
    Store.find_household_for_tenant(tenant_id)
  end

  defp lookup_household(_, _), do: :not_found

  defp lookup_member(household_id, subject) when is_binary(subject) and subject != "" do
    case Store.find_member_by_subject(household_id, subject) do
      {:ok, member} -> {:ok, member}
      :not_found -> Store.get_member(household_id, subject)
    end
  end

  defp lookup_member(_, _), do: :not_found

  @doc "Extract the verified subject identifier from `%IdentityContext{}`."
  @spec subject_id(IdentityContext.t()) :: String.t() | nil
  def subject_id(%IdentityContext{principal: principal}) when is_map(principal) do
    Map.get(principal, :subject) || Map.get(principal, :spiffe_id) ||
      Map.get(principal, :account_id)
  end

  def subject_id(_), do: nil

  @doc "Read a single request header value (lowercased key)."
  @spec header(Plug.Conn.t(), String.t()) :: String.t() | nil
  def header(conn, name) do
    case Plug.Conn.get_req_header(conn, name) do
      [value | _] when is_binary(value) and value != "" -> String.trim(value)
      _ -> nil
    end
  end

  @doc "Generate a prefixed random hex identifier."
  @spec random_id(String.t(), pos_integer()) :: String.t()
  def random_id(prefix, bytes \\ 16) do
    prefix <> Base.encode16(:crypto.strong_rand_bytes(bytes), case: :lower)
  end

  @doc "Build the standard AuditEndpoint Cedar resource map."
  @spec resource(String.t()) :: map()
  def resource(endpoint) do
    %{
      type: "Recurse::Resource::AuditEndpoint",
      id: endpoint |> String.trim_leading("/") |> String.replace("/", "_"),
      attrs: %{"endpoint" => endpoint}
    }
  end

  @doc "Send a JSON response."
  @spec json(Plug.Conn.t(), non_neg_integer(), map()) :: Plug.Conn.t()
  def json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  @doc "Send a standard 404 JSON response."
  @spec not_found(Plug.Conn.t()) :: Plug.Conn.t()
  def not_found(conn), do: json(conn, 404, %{"error" => "ERR_NOT_FOUND"})

  @doc "Send a standard 400 JSON response."
  @spec bad_request(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def bad_request(conn, message),
    do: json(conn, 400, %{"error" => "ERR_BAD_REQUEST", "message" => message})

  @doc "Send a 410 Gone tombstone response citing `erasureRef`."
  @spec gone(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def gone(conn, erasure_ref) do
    json(conn, 410, %{"error" => "ERR_CONTENT_DISPOSED", "erasureRef" => erasure_ref})
  end
end
