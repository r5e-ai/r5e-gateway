defmodule Recurse.Gateway.LlmProxy.ZdrRoutes do
  @moduledoc """
  Structured, route-bound Zero-Data-Retention (ZDR) upstream route registry and
  selector (`R5E_UPSTREAM_ZDR_ROUTES`).

  Bare provider hostnames (such as `api.anthropic.com` or `api.openai.com`)
  cannot distinguish a contracted enterprise ZDR account from a consumer
  account sharing the same hostname. A route therefore evaluates to
  `upstream_zdr_pinned: true` **if and only if** the actual selected upstream
  route (primary OR fallback) carries:

    1. `zdrContracted: true`
    2. a non-empty `providerCredentialRef`
    3. a content-addressed `zdrEvidenceRef` (`bytes:sha256:<64 hex>`)

  When a primary route falls back to `fallbackRouteId`, ZDR pinning is
  recomputed strictly from the **selected fallback route**. If fallback lands
  on a non-ZDR route and `failClosedOnNonZdrFallback` is `true` (the default),
  selection fails closed with `{:error, :non_zdr_fallback_refused, details}`.
  """

  alias Recurse.Providers.Schemas.LlmProviderConfig

  @evidence_ref_re ~r/\Abytes:sha256:[0-9a-f]{64}\z/

  @type route :: %{
          route_id: String.t(),
          endpoint_url: String.t(),
          upstream_host: String.t(),
          provider_credential_ref: String.t() | nil,
          project_ref: String.t() | nil,
          zdr_contracted: boolean(),
          zdr_evidence_ref: String.t() | nil,
          fallback_route_id: String.t() | nil,
          fail_closed_on_non_zdr_fallback: boolean()
        }

  @type selection :: %{
          selected_route: route(),
          via_fallback?: boolean(),
          upstream_route_id: String.t(),
          upstream_zdr_pinned: boolean()
        }

  @doc """
  Parse raw `R5E_UPSTREAM_ZDR_ROUTES` JSON string or decoded structure into
  normalized route maps. Raises `ArgumentError` on malformed JSON or invalid
  route definitions so misconfigured ZDR routes never fail open at boot.
  """
  @spec parse_env!(String.t() | nil) :: [route()]
  def parse_env!(nil), do: []
  def parse_env!(""), do: []

  def parse_env!(raw) when is_binary(raw) do
    case String.trim(raw) do
      "" -> []
      trimmed -> decode_and_parse_routes!(trimmed)
    end
  end

  defp decode_and_parse_routes!(trimmed) do
    with {:json, {:ok, decoded}} <- {:json, JSON.decode(trimmed)},
         {:routes, {:ok, routes}} <- {:routes, parse_routes(decoded)} do
      routes
    else
      {:json, {:error, reason}} ->
        raise ArgumentError, "invalid R5E_UPSTREAM_ZDR_ROUTES JSON: #{inspect(reason)}"

      {:routes, {:error, reason}} ->
        raise ArgumentError, "invalid R5E_UPSTREAM_ZDR_ROUTES configuration: #{inspect(reason)}"
    end
  end

  @doc """
  Normalize a list of route maps or a `%{"routes" => [...]}` envelope into
  validated route structures.
  """
  @spec parse_routes(term()) :: {:ok, [route()]} | {:error, term()}
  def parse_routes(nil), do: {:ok, []}

  def parse_routes(%{"routes" => routes} = envelope) when is_list(routes) do
    default_fail_closed =
      case Map.get(envelope, "failClosedOnNonZdrFallback") do
        false -> false
        _ -> true
      end

    normalize_list(routes, default_fail_closed)
  end

  def parse_routes(routes) when is_list(routes), do: normalize_list(routes, true)
  def parse_routes(_other), do: {:error, :expected_routes_list_or_object}

  @doc """
  Return configured structured ZDR routes from `:recurse_gateway` application env.
  """
  @spec configured_routes() :: [route()]
  def configured_routes do
    case Application.get_env(:recurse_gateway, :upstream_zdr_routes, []) do
      routes when is_list(routes) ->
        case normalize_list(routes, true) do
          {:ok, normalized} -> normalized
          {:error, _} -> []
        end

      %{} = envelope ->
        case parse_routes(envelope) do
          {:ok, normalized} -> normalized
          {:error, _} -> []
        end

      _ ->
        []
    end
  end

  @doc """
  True if and only if `route` satisfies all three structured ZDR invariants:
  `zdr_contracted == true`, non-empty `provider_credential_ref`, and valid
  `bytes:sha256:...` `zdr_evidence_ref`.
  """
  @spec zdr_pinned?(route() | map() | nil) :: boolean()
  def zdr_pinned?(%{
        zdr_contracted: true,
        provider_credential_ref: cred_ref,
        zdr_evidence_ref: evidence_ref
      })
      when is_binary(cred_ref) and is_binary(evidence_ref) do
    String.trim(cred_ref) != "" and Regex.match?(@evidence_ref_re, evidence_ref)
  end

  def zdr_pinned?(_route), do: false

  @doc """
  Select an upstream route by `route_id`, applying fallback semantics when
  `primary_available?: false`.

  Options:
    * `:routes` — explicit route list (defaults to `configured_routes/0`)
    * `:primary_available?` — boolean (default `true`); when `false`, follows
      `primary.fallback_route_id` and re-evaluates ZDR pinning strictly on the
      selected fallback route, failing closed if the fallback is non-ZDR and
      `fail_closed_on_non_zdr_fallback` is `true`.
  """
  @spec select_route(String.t(), keyword()) :: {:ok, selection()} | {:error, atom(), map()}
  def select_route(route_id, opts \\ [])

  def select_route(route_id, opts) when is_binary(route_id) and route_id != "" do
    routes = Keyword.get(opts, :routes, configured_routes())
    primary_available? = Keyword.get(opts, :primary_available?, true)

    case find_by_id(routes, route_id) do
      nil ->
        {:error, :route_not_found, %{route_id: route_id, upstream_zdr_pinned: false}}

      primary ->
        if primary_available? do
          {:ok,
           %{
             selected_route: primary,
             via_fallback?: false,
             upstream_route_id: primary.route_id,
             upstream_zdr_pinned: zdr_pinned?(primary)
           }}
        else
          select_fallback(primary, routes)
        end
    end
  end

  def select_route(_route_id, _opts),
    do: {:error, :route_not_found, %{route_id: nil, upstream_zdr_pinned: false}}

  @doc """
  Derive Cedar route-bound ZDR context attributes (`:upstream_route_id` and
  `:upstream_zdr_pinned`) from an `%LlmProviderConfig{}` (or metadata map).

  Never trusts bare hostnames without a matching structured contracted route.
  """
  @spec cedar_context_for_config(LlmProviderConfig.t() | map() | nil, keyword()) ::
          {:ok, %{upstream_route_id: String.t(), upstream_zdr_pinned: boolean()}}
          | {:error, atom(), map()}
  def cedar_context_for_config(cfg, opts \\ [])

  def cedar_context_for_config(%LlmProviderConfig{metadata: metadata}, opts) do
    cedar_context_for_metadata(metadata || %{}, opts)
  end

  def cedar_context_for_config(%{metadata: metadata} = cfg, opts) when is_map(metadata) do
    merged = Map.merge(metadata, Map.delete(cfg, :metadata))
    cedar_context_for_metadata(merged, opts)
  end

  def cedar_context_for_config(metadata, opts) when is_map(metadata) do
    cedar_context_for_metadata(metadata, opts)
  end

  def cedar_context_for_config(_other, _opts) do
    {:ok, %{upstream_route_id: "", upstream_zdr_pinned: false}}
  end

  defp cedar_context_for_metadata(metadata, opts) do
    select_opts =
      Keyword.put_new(opts, :primary_available?, metadata_primary_available?(metadata))

    case extract_metadata_route_id(metadata, opts) do
      id when is_binary(id) and id != "" ->
        select_cedar_context(id, select_opts)

      _ ->
        {:ok, %{upstream_route_id: "", upstream_zdr_pinned: false}}
    end
  end

  defp extract_metadata_route_id(metadata, opts) do
    Keyword.get(opts, :route_id) ||
      Map.get(metadata, "upstream_route_id") ||
      Map.get(metadata, :upstream_route_id) ||
      Map.get(metadata, "zdr_route_id") ||
      Map.get(metadata, :zdr_route_id)
  end

  defp select_cedar_context(id, select_opts) do
    case select_route(id, select_opts) do
      {:ok, %{upstream_route_id: selected_id, upstream_zdr_pinned: pinned?}} ->
        {:ok, %{upstream_route_id: selected_id, upstream_zdr_pinned: pinned?}}

      {:error, :route_not_found, _} ->
        {:ok, %{upstream_route_id: id, upstream_zdr_pinned: false}}

      {:error, reason, details} ->
        {:error, reason, details}
    end
  end

  defp metadata_primary_available?(%{primary_available?: avail}) when is_boolean(avail),
    do: avail

  defp metadata_primary_available?(%{"primary_available" => avail}) when is_boolean(avail),
    do: avail

  defp metadata_primary_available?(_), do: true

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  defp select_fallback(%{fallback_route_id: nil} = primary, _routes) do
    {:error, :no_fallback_route,
     %{primary_route_id: primary.route_id, upstream_zdr_pinned: false}}
  end

  defp select_fallback(%{fallback_route_id: fallback_id} = primary, routes) do
    case find_by_id(routes, fallback_id) do
      nil ->
        {:error, :fallback_route_not_found,
         %{
           primary_route_id: primary.route_id,
           fallback_route_id: fallback_id,
           upstream_zdr_pinned: false
         }}

      fallback ->
        fallback_pinned? = zdr_pinned?(fallback)

        if not fallback_pinned? and primary.fail_closed_on_non_zdr_fallback do
          {:error, :non_zdr_fallback_refused,
           %{
             primary_route_id: primary.route_id,
             fallback_route_id: fallback.route_id,
             upstream_route_id: fallback.route_id,
             upstream_zdr_pinned: false
           }}
        else
          {:ok,
           %{
             selected_route: fallback,
             via_fallback?: true,
             upstream_route_id: fallback.route_id,
             upstream_zdr_pinned: fallback_pinned?
           }}
        end
    end
  end

  defp find_by_id(routes, id), do: Enum.find(routes, &(&1.route_id == id))

  defp normalize_list(routes, default_fail_closed) do
    Enum.reduce_while(routes, {:ok, []}, fn entry, {:ok, acc} ->
      case normalize_route(entry, default_fail_closed) do
        {:ok, route} -> {:cont, {:ok, [route | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp normalize_route(%{} = raw, default_fail_closed) do
    route_id = fetch_string(raw, ["routeId", "route_id", :route_id])
    endpoint_url = fetch_string(raw, ["endpointUrl", "endpoint_url", :endpoint_url])

    with true <- non_empty?(route_id) || {:error, :missing_route_id},
         {:ok, host} <- parse_endpoint_host(endpoint_url),
         {:ok, zdr_contracted} <-
           fetch_bool(raw, ["zdrContracted", "zdr_contracted", :zdr_contracted], false),
         {:ok, fail_closed} <-
           fetch_bool(
             raw,
             [
               "failClosedOnNonZdrFallback",
               "fail_closed_on_non_zdr_fallback",
               :fail_closed_on_non_zdr_fallback
             ],
             default_fail_closed
           ) do
      {:ok,
       %{
         route_id: route_id,
         endpoint_url: endpoint_url,
         upstream_host: host,
         provider_credential_ref:
           fetch_optional_string(raw, [
             "providerCredentialRef",
             "provider_credential_ref",
             :provider_credential_ref
           ]),
         project_ref: fetch_optional_string(raw, ["projectRef", "project_ref", :project_ref]),
         zdr_contracted: zdr_contracted,
         zdr_evidence_ref:
           fetch_optional_string(raw, ["zdrEvidenceRef", "zdr_evidence_ref", :zdr_evidence_ref]),
         fallback_route_id:
           fetch_optional_string(raw, [
             "fallbackRouteId",
             "fallback_route_id",
             :fallback_route_id
           ]),
         fail_closed_on_non_zdr_fallback: fail_closed
       }}
    end
  end

  defp normalize_route(_other, _default_fail_closed), do: {:error, :invalid_route_entry}

  defp parse_endpoint_host(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{scheme: scheme, host: host}
      when scheme in ["https", "http"] and is_binary(host) and host != "" ->
        {:ok, host}

      _ ->
        {:error, {:invalid_endpoint_url, url}}
    end
  end

  defp parse_endpoint_host(other), do: {:error, {:invalid_endpoint_url, other}}

  defp fetch_string(map, keys) do
    Enum.find_value(keys, fn key ->
      case Map.fetch(map, key) do
        {:ok, value} when is_binary(value) -> String.trim(value)
        _ -> nil
      end
    end)
  end

  defp fetch_optional_string(map, keys) do
    case fetch_string(map, keys) do
      nil -> nil
      "" -> nil
      value -> value
    end
  end

  defp fetch_bool(map, keys, default) do
    found =
      Enum.reduce_while(keys, :missing, fn key, _acc ->
        case Map.fetch(map, key) do
          {:ok, value} -> {:halt, {:ok, value}}
          :error -> {:cont, :missing}
        end
      end)

    case found do
      :missing -> {:ok, default}
      {:ok, nil} -> {:ok, default}
      {:ok, value} when is_boolean(value) -> {:ok, value}
      {:ok, invalid} -> {:error, {:invalid_boolean, invalid}}
    end
  end

  defp non_empty?(value), do: is_binary(value) and value != ""
end
