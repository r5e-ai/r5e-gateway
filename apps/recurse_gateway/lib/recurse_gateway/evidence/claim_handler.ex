defmodule Recurse.Gateway.Evidence.ClaimHandler do
  @moduledoc """
  The HTTP side of claiming a deployment.

  Three routes, none of which uses a sign-in token, because before a
  deployment is claimed there is nobody to sign in:

    * `GET /v1/deployment` says whether the deployment has started and
      been claimed, and returns the records of its start, which are
      public by nature.
    * `POST /v1/deployment/claim/prepare` and `…/finalize` are the two
      steps of the claim, guarded by the one-time claim code.
    * `POST /v1/deployment/grants` takes the grants a root gives this
      gateway, or a workload badge chain a root minted offline. It needs
      no code: what is sent must stand under the roots the claim
      declared, or it is refused.

  The bodies of the two claim routes carry the claim code and are never
  logged.
  """

  alias Recurse.Gateway.Provenance.{Claim, Grants, OfflineBadges, Published, Roots, Runtime}
  alias Recurse.Provenance.Pipeline

  @doc "`GET /v1/deployment`"
  @spec describe(Plug.Conn.t()) :: Plug.Conn.t()
  def describe(conn), do: running(conn, fn -> json(conn, 200, Claim.describe()) end)

  @doc "`POST /v1/deployment/claim/prepare`"
  @spec prepare(Plug.Conn.t()) :: Plug.Conn.t()
  def prepare(%Plug.Conn{body_params: request} = conn) do
    running(conn, fn ->
      case Claim.prepare(request) do
        {:ok, body} -> json(conn, 200, body)
        {:error, reason} -> refuse(conn, reason)
      end
    end)
  end

  @doc "`POST /v1/deployment/claim/finalize`"
  @spec finalize(Plug.Conn.t()) :: Plug.Conn.t()
  def finalize(%Plug.Conn{body_params: request} = conn) do
    running(conn, fn ->
      case Claim.finalize(request) do
        {:ok, :created, body} -> json(conn, 201, body)
        {:ok, :already, body} -> json(conn, 200, body)
        {:error, reason} -> refuse(conn, reason)
      end
    end)
  end

  @doc "`POST /v1/deployment/grants`"
  @spec grants(Plug.Conn.t()) :: Plug.Conn.t()
  def grants(%Plug.Conn{body_params: set} = conn) do
    running(conn, fn ->
      if OfflineBadges.badge_set?(set) do
        case OfflineBadges.accept(set) do
          {:ok, :created, body} ->
            json(conn, 201, body)

          {:ok, :already, body} ->
            json(conn, 200, body)

          {:error, :badge_recorded_not_sealed} ->
            json(conn, 503, %{"error" => "badge_recorded_not_sealed"})

          {:error, reason}
          when reason in [
                 :stream_fork_refused,
                 :stream_prefix_taken,
                 :badge_taken_back,
                 :not_claimed
               ] ->
            json(conn, 409, %{"error" => Atom.to_string(reason)})

          {:error, :too_large} ->
            json(conn, 413, %{"error" => "too_large"})

          {:error, reason} ->
            json(conn, 422, %{"error" => Atom.to_string(reason)})
        end
      else
        case Grants.accept(set) do
          {:ok, refs} -> json(conn, 201, %{"recorded" => refs})
          {:error, :stream_fork_refused} -> json(conn, 409, %{"error" => "stream_fork_refused"})
          {:error, :not_claimed} -> json(conn, 409, %{"error" => "not_claimed"})
          {:error, :too_large} -> json(conn, 413, %{"error" => "too_large"})
          {:error, reason} -> json(conn, 422, %{"error" => Atom.to_string(reason)})
        end
      end
    end)
  end

  @doc """
  `GET /v1/deployment/definitions`: every definition a publisher has
  added to this deployment since it started, and whom the deployment
  believes about which domains.
  """
  @spec definitions(Plug.Conn.t()) :: Plug.Conn.t()
  def definitions(conn) do
    running(conn, fn ->
      json(conn, 200, %{
        "publishers" => Published.publishers(),
        "definitions" => Published.list()
      })
    end)
  end

  @doc """
  `POST /v1/deployment/definitions`: a publisher adds definitions. The
  body is a signed publication with the documents it names. It needs no
  login: it is taken on the strength of its signature, by a publisher the
  operator has said the deployment believes about those kinds.
  """
  @spec publish(Plug.Conn.t()) :: Plug.Conn.t()
  def publish(%Plug.Conn{body_params: set} = conn) do
    running(conn, fn ->
      case Published.admit(set) do
        {:ok, added} ->
          # Sealed at once when it can be: the seal is what shows the
          # definition was published before the records that cite it.
          best_effort_seal()
          json(conn, 201, %{"admitted" => added})

        {:error, :not_claimed} ->
          json(conn, 409, %{"error" => "not_claimed"})

        {:error, :stream_fork_refused} ->
          json(conn, 409, %{"error" => "stream_fork_refused"})

        {:error, :too_large} ->
          json(conn, 413, %{"error" => "too_large"})

        {:error, reason} when reason in [:no_publisher_configured, :publisher_not_believed] ->
          json(conn, 403, %{"error" => Atom.to_string(reason)})

        {:error, reason} ->
          json(conn, 422, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  @doc "`POST /v1/deployment/revocations`"
  @spec revocations(Plug.Conn.t()) :: Plug.Conn.t()
  def revocations(%Plug.Conn{body_params: set} = conn) do
    running(conn, fn ->
      _ = best_effort_seal()

      case Grants.revoke(set) do
        {:ok, refs} ->
          _ = best_effort_seal()
          json(conn, 201, %{"recorded" => refs})

        {:error, :stream_fork_refused} ->
          json(conn, 409, %{"error" => "stream_fork_refused"})

        {:error, :not_claimed} ->
          json(conn, 409, %{"error" => "not_claimed"})

        {:error, :too_large} ->
          json(conn, 413, %{"error" => "too_large"})

        {:error, reason} ->
          json(conn, 422, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  @doc "`POST /v1/deployment/roots`"
  @spec roots(Plug.Conn.t()) :: Plug.Conn.t()
  def roots(%Plug.Conn{body_params: sent} = conn) do
    running(conn, fn ->
      case Roots.accept(sent) do
        {:ok, body} ->
          json(conn, 201, body)

        {:error, {:change_not_in_order, code}} ->
          json(conn, 422, %{"error" => "change_not_in_order", "finding" => code})

        {:error, :stream_fork_refused} ->
          json(conn, 409, %{"error" => "stream_fork_refused"})

        {:error, :not_claimed} ->
          json(conn, 409, %{"error" => "not_claimed"})

        {:error, :too_large} ->
          json(conn, 413, %{"error" => "too_large"})

        {:error, reason} ->
          json(conn, 422, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  defp running(conn, respond) do
    if Runtime.running?(),
      do: respond.(),
      else: json(conn, 404, %{"error" => "evidence_not_recorded_here"})
  end

  defp best_effort_seal do
    Pipeline.flush(Runtime.pipeline())
    Runtime.seal()
  rescue
    _ -> :not_sealed
  catch
    :exit, _ -> :not_sealed
  end

  defp refuse(conn, :wrong_claim_code), do: json(conn, 403, %{"error" => "wrong_claim_code"})
  defp refuse(conn, :already_claimed), do: json(conn, 409, %{"error" => "already_claimed"})
  defp refuse(conn, :not_started), do: json(conn, 409, %{"error" => "not_started"})
  defp refuse(conn, :malformed_request), do: json(conn, 400, %{"error" => "malformed_request"})
  defp refuse(conn, reason), do: json(conn, 422, %{"error" => Atom.to_string(reason)})

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end
end
