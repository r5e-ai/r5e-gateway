defmodule Recurse.Gateway.Personal.Common do
  @moduledoc """
  Shared helpers for `/v1/personal/*` HTTP handlers: opt-in feature gate
  (`R5E_PERSONAL_ENABLED`), Cedar authz, strict household and parent-role
  resolution bound to the authenticated principal, and JSON response formatting.
  """

  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.Personal.Policy
  alias Recurse.Gateway.Provenance.SessionName
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
  Resolve the caller's household and active member record strictly from the
  verified JWT `ctx` (plus `x-r5e-household-id` header when the caller belongs
  to multiple households).

  Never defaults to an arbitrary or newest household on the node:
    * Explicit `x-r5e-household-id` MUST exist in `ctx.tenant_id` and contain
      an active (non-revoked) member matching `auth_subject == subject_id(ctx)`.
    * Omitted `x-r5e-household-id` succeeds ONLY when `subject_id(ctx)` is an
      active member of exactly one household in `ctx.tenant_id`; returns
      `{:error, :ambiguous_household}` when multiple match and
      `{:error, :not_found}` when none match.
  """
  @spec resolve_household_member(Plug.Conn.t(), IdentityContext.t()) ::
          {:ok, map(), map()} | {:error, :not_found | :ambiguous_household}
  def resolve_household_member(conn, %IdentityContext{tenant_id: tenant_id} = ctx)
      when is_binary(tenant_id) and tenant_id != "" do
    subject = subject_id(ctx)
    requested_hh = header(conn, "x-r5e-household-id")

    if is_binary(subject) and subject != "" do
      resolve_for_subject(tenant_id, subject, requested_hh)
    else
      {:error, :not_found}
    end
  end

  def resolve_household_member(_conn, _ctx), do: {:error, :not_found}

  @doc """
  Resolve the caller's household and verify the caller holds a parent/owner
  role (`member.role in ["owner", "parent"]`), blocking `child` principals
  from mutating household settings, pairings, E2EE wraps/blobs, recovery, or
  erasures with `{:error, :parent_role_required}`.
  """
  @spec resolve_parent_member(Plug.Conn.t(), IdentityContext.t()) ::
          {:ok, map(), map()}
          | {:error, :not_found | :ambiguous_household | :parent_role_required}
  def resolve_parent_member(conn, ctx) do
    with {:ok, household, member} <- resolve_household_member(conn, ctx) do
      if member.role in ["owner", "parent"] do
        {:ok, household, member}
      else
        {:error, :parent_role_required}
      end
    end
  end

  defp resolve_for_subject(tenant_id, subject, hh_id) when is_binary(hh_id) and hh_id != "" do
    with {:ok, household} <- Store.get_household(hh_id),
         true <- household.tenant_id == tenant_id,
         {:ok, member} <- Store.find_member_by_subject(household.household_id, subject) do
      {:ok, household, member}
    else
      _ -> {:error, :not_found}
    end
  end

  defp resolve_for_subject(tenant_id, subject, _nil) do
    case Store.find_member_households(tenant_id, subject) do
      [{household, member}] -> {:ok, household, member}
      [_, _ | _] -> {:error, :ambiguous_household}
      [] -> {:error, :not_found}
    end
  end

  @doc "Extract the verified subject identifier from `%IdentityContext{}`."
  @spec subject_id(IdentityContext.t()) :: String.t() | nil
  def subject_id(%IdentityContext{principal: principal}) when is_map(principal) do
    Map.get(principal, :subject) || Map.get(principal, :spiffe_id) ||
      Map.get(principal, :account_id)
  end

  def subject_id(_), do: nil

  @doc "Canonical actor URN for evidence records captured on behalf of a caller."
  @spec actor_urn(IdentityContext.t(), map() | nil) :: String.t()
  def actor_urn(%IdentityContext{tenant_id: tenant} = ctx, member \\ nil) do
    encoded = SessionName.encode(tenant || "default")
    sub = subject_id(ctx) || (member && member.member_id) || "unknown"

    if String.contains?(sub, ":"),
      do: sub,
      else: "urn:r5e:principal:#{encoded}:" <> URI.encode(sub, &URI.char_unreserved?/1)
  end

  @doc "Send standard HTTP error responses for household/role/runtime errors."
  @spec send_common_error(Plug.Conn.t(), atom()) :: Plug.Conn.t()
  def send_common_error(conn, :not_found), do: not_found(conn)

  def send_common_error(conn, :ambiguous_household),
    do: json(conn, 400, %{"error" => "household_id_required"})

  def send_common_error(conn, :parent_role_required),
    do: json(conn, 403, %{"error" => "parent_role_required"})

  def send_common_error(conn, :evidence_runtime_unavailable),
    do: json(conn, 503, %{"error" => "evidence_runtime_unavailable"})

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
