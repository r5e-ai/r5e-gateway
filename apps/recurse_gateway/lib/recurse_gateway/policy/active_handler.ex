defmodule Recurse.Gateway.Policy.ActiveHandler do
  @moduledoc """
  `GET /v1/policies/active`: the policy this gateway is enforcing now.

  Answers the Cedar source, the reference call records name it by
  (`policyRef`), where it was loaded from and when. Someone reading a
  decision in the evidence can so check that the policy in force is the
  one the record names, and read what it says.

  It only reads. Changing the active policy is done where the policy is
  kept (a file, a registry), not here.

  Who may call: whoever may replay a decision (`PolicyReplay`), since
  replaying shows the same policy. 503 when no policy is loaded.
  """

  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.Policy.Active
  alias Recurse.Gateway.PolicyBundleRef
  alias Recurse.Provenance.Ref

  @action ~s(Recurse::Action::"PolicyReplay")
  @endpoint "/v1/policies/active"

  @doc "`GET /v1/policies/active`"
  @spec show(Plug.Conn.t()) :: Plug.Conn.t()
  def show(conn) do
    resource = %{
      type: "Recurse::Resource::AuditEndpoint",
      id: "v1_policies_active",
      attrs: %{"endpoint" => @endpoint}
    }

    case Authz.gate(conn, @action, resource) do
      {:ok, conn, _ctx, _bundle_ref} -> answer(conn, Active.current())
      error -> Authz.dispatch_gate_error(conn, error)
    end
  end

  defp answer(conn, {:ok, %Active{bundle: %PolicyBundleRef{bundle_bytes: source}} = active})
       when is_binary(source) do
    json(conn, 200, %{
      "bundleRef" => Ref.bytes(source),
      "source" => source,
      "sourceMode" => to_string(active.source),
      "sourceRef" => active.source_ref,
      "activatedAt" => DateTime.to_iso8601(active.loaded_at)
    })
  end

  defp answer(conn, _not_loaded), do: json(conn, 503, %{"error" => "ERR_POLICY_NOT_LOADED"})

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end
end
