# Spec 009 Phase 3 / Real-Codex demo seed (T076).
#
# Variant of `scripts/seed_009_llm_proxy_dev.exs` that points
# `LlmProviderConfig.upstream_host` at REAL OpenAI / ChatGPT endpoints.
# The proxy uses BypassDnsResolver to resolve those names against
# public DNS even when /etc/hosts maps the same names back to
# 127.0.0.1 (the customer-DNS-override primitive that's the
# sales wedge — see spec.md FR-007 / R-011).
#
# Idempotent. Safe to re-run.
#
# What this seeds:
#   * Dev tenant `01TEN_DEV_009_LLM_PROXY` (tier `:standalone_gateway`).
#   * 3 LlmProviderConfig rows pointing at real upstream:
#       - chatgpt.com:443  (Codex's WSS data plane)
#       - auth.openai.com:443  (OAuth login)
#       - api.openai.com:443  (Responses API HTTPS+SSE)
#     All three set metadata.scheme="https" so StreamingProxy +
#     WebSocketBridge negotiate TLS to real OpenAI.
#
# The Cedar fixture bundle is loaded separately by the operator
# (the BEAM startup wrapper copies
# `specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/bundle.cedar`
# into `apps/recurse_gateway/priv/cedar/active.cedar` before boot).
#
# Run with:
#
#     MIX_ENV=dev mix run scripts/seed_009_real_demo.exs

alias Recurse.Providers.Repo
alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
alias Recurse.Providers.Schemas.LlmProviderConfig

require Logger

dev_tenant_id = "01TEN_DEV_009_LLM_PROXY"

now = DateTime.utc_now()

tenant_attrs = %{
  tenant_id: dev_tenant_id,
  display_name: "Dev tenant — 009 LLM proxy real-OpenAI demo",
  tier: :standalone_gateway,
  created_at: now
}

case Repo.get(Tenant, dev_tenant_id) do
  nil ->
    Logger.info("seed_009_real_demo: inserting dev tenant #{dev_tenant_id}")

    Repo.insert!(Tenant.changeset(%Tenant{}, tenant_attrs),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

  %Tenant{} ->
    Logger.info("seed_009_real_demo: dev tenant #{dev_tenant_id} already present; reusing")
end

# Real OpenAI upstream (port 443, scheme https). The proxy's
# BypassDnsResolver resolves `chatgpt.com` etc. via public DNS
# (8.8.8.8 / 1.1.1.1) — bypassing the /etc/hosts override that
# directs Codex's connections at 127.0.0.1. This is the central
# trick that makes R-011 work end-to-end.
provider_configs = [
  %{
    tenant_id: dev_tenant_id,
    provider: "openai_chatgpt",
    upstream_host: "chatgpt.com",
    upstream_port: 443,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer_plus_chatgpt_account_id,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{
      "scheme" => "https",
      "smoke_seed_id" => "T076",
      "demo_target" => "real_openai"
    }
  },
  %{
    tenant_id: dev_tenant_id,
    provider: "openai_auth",
    upstream_host: "auth.openai.com",
    upstream_port: 443,
    transport_modes: ["https-sse"],
    auth_mode: :internal_none,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{
      "scheme" => "https",
      "smoke_seed_id" => "T076",
      "demo_target" => "real_openai",
      "passthrough" => true
    }
  },
  %{
    tenant_id: dev_tenant_id,
    provider: "openai_api",
    upstream_host: "api.openai.com",
    upstream_port: 443,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{
      "scheme" => "https",
      "smoke_seed_id" => "T076",
      "demo_target" => "real_openai"
    }
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
        "seed_009_real_demo: inserting LlmProviderConfig host=#{attrs.upstream_host} provider=#{attrs.provider}"
      )

      Repo.insert!(LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs))

    %LlmProviderConfig{} = existing ->
      Logger.info(
        "seed_009_real_demo: LlmProviderConfig host=#{attrs.upstream_host} already present; refreshing to real-OpenAI"
      )

      Repo.update!(LlmProviderConfig.changeset(existing, attrs))
  end
end)

Logger.info("seed_009_real_demo: done. proxy will route to real OpenAI on port 443 https.")
