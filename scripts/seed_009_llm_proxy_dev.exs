# Spec 009 Phase 3 Sub-3.8 (T072) — dev seed for the LLM-proxy.
#
# Idempotent. Safe to re-run. Inserts:
#
#   * One dev `Tenant` row (`01TEN_DEV_009_LLM_PROXY`, tier:
#     `:standalone_gateway`) — reused if already present.
#   * Three `LlmProviderConfig` rows for `chatgpt.com`,
#     `auth.openai.com`, `api.openai.com` keyed by
#     `(tenant_id, provider, upstream_host)` per the unique constraint
#     in the table. Configured to point at the local BEAM (loopback
#     port 4000) so a dev-mode Codex CLI with /etc/hosts overrides
#     reaches the proxy without external network access.
#
# Run with:
#
#     mix run scripts/seed_009_llm_proxy_dev.exs
#
# The Cedar fixture bundle in
# `specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/bundle.cedar`
# is loaded via the operator's normal bundle-publish flow (see
# `specs/009-llm-api-proxy/dev-setup.md`); this script does NOT
# touch the bundle loader.
#
# Cross-references:
#   * specs/009-llm-api-proxy/data-model.md §LlmProviderConfig
#   * specs/009-llm-api-proxy/quickstart.md Flow 1
#   * apps/recurse_providers/lib/recurse_providers/schemas/llm_provider_config.ex

alias Recurse.Providers.Repo
alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
alias Recurse.Providers.Schemas.LlmProviderConfig

require Logger

dev_tenant_id = "01TEN_DEV_009_LLM_PROXY"

now = DateTime.utc_now()

tenant_attrs = %{
  tenant_id: dev_tenant_id,
  display_name: "Dev tenant — 009 LLM proxy smoke",
  tier: :standalone_gateway,
  created_at: now
}

case Repo.get(Tenant, dev_tenant_id) do
  nil ->
    Logger.info("seed_009_llm_proxy_dev: inserting dev tenant #{dev_tenant_id}")

    Repo.insert!(Tenant.changeset(%Tenant{}, tenant_attrs),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

  %Tenant{} ->
    Logger.info("seed_009_llm_proxy_dev: dev tenant #{dev_tenant_id} already present; reusing")
end

# Local BEAM listens on 127.0.0.1:4000 in dev. The DNS override
# (specs/009-llm-api-proxy/dev-setup.md §"/etc/hosts override")
# routes chatgpt.com / auth.openai.com / api.openai.com to 127.0.0.1
# so the proxy receives real Codex CLI traffic on its own port.
#
# `metadata.scheme = "http"` is the test-seam consumed by
# `StreamingProxy.upstream_scheme/1` and `WebSocketBridge.ws_schemes/1`
# — operators flip it to `"https"` (or omit to default to https) once
# they install the dev cert (T073).
local_beam_port = 4000

provider_configs = [
  %{
    tenant_id: dev_tenant_id,
    provider: "openai_chatgpt",
    upstream_host: "chatgpt.com",
    upstream_port: local_beam_port,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer_plus_chatgpt_account_id,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{"scheme" => "http", "smoke_seed_id" => "T072"}
  },
  %{
    tenant_id: dev_tenant_id,
    provider: "openai_auth",
    upstream_host: "auth.openai.com",
    upstream_port: local_beam_port,
    transport_modes: ["https-sse"],
    auth_mode: :internal_none,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{"scheme" => "http", "smoke_seed_id" => "T072", "passthrough" => true}
  },
  %{
    tenant_id: dev_tenant_id,
    provider: "openai_api",
    upstream_host: "api.openai.com",
    upstream_port: local_beam_port,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{"scheme" => "http", "smoke_seed_id" => "T072"}
  }
]

import Ecto.Query, only: [from: 2]

Enum.each(provider_configs, fn attrs ->
  query =
    from(c in LlmProviderConfig,
      where:
        c.tenant_id == ^attrs.tenant_id and
          c.provider == ^attrs.provider and
          c.upstream_host == ^attrs.upstream_host
    )

  case Repo.one(query) do
    nil ->
      Logger.info(
        "seed_009_llm_proxy_dev: inserting LlmProviderConfig host=#{attrs.upstream_host} provider=#{attrs.provider}"
      )

      Repo.insert!(LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs))

    %LlmProviderConfig{} = existing ->
      Logger.info(
        "seed_009_llm_proxy_dev: LlmProviderConfig host=#{attrs.upstream_host} already present; refreshing"
      )

      Repo.update!(LlmProviderConfig.changeset(existing, attrs))
  end
end)

Logger.info("seed_009_llm_proxy_dev: done.")
