# Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
# (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
# app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
#
# Seeds the LlmProviderConfig rows the LLM proxy needs to front REAL
# OpenAI for the local real-Codex demo, under the SAME tenant the
# audit console logs in as (`01TEN_FABLE_DEMO_LOCAL`).
#
# Why a variant of scripts/seed_009_real_demo.exs: that script seeds
# `01TEN_DEV_009_LLM_PROXY`, but FableDemo's ProviderRegistry install +
# the r5e_session cookie are both bound to `01TEN_FABLE_DEMO_LOCAL`.
# A tenant mismatch means real Codex traffic produces receipts the
# dashboard can't see. One tenant everywhere is what makes the
# end-to-end demo land.
#
# Idempotent. Run with:
#
#     MIX_ENV=dev mix run scripts/fable_demo/seed_real_upstreams.exs

import Ecto.Query, only: [from: 2]

alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Tenant
alias Recurse.Providers.Repo
alias Recurse.Providers.Schemas.LlmProviderConfig

require Logger

tenant_id = System.get_env("R5E_LLM_PROXY_DEFAULT_TENANT_ID", "01TEN_FABLE_DEMO_LOCAL")

case Repo.get(Tenant, tenant_id) do
  nil ->
    Logger.info("seed_real_upstreams: inserting tenant #{tenant_id}")

    Repo.insert!(
      Tenant.changeset(%Tenant{}, %{
        tenant_id: tenant_id,
        display_name: "Fable demo local tenant",
        tier: :standalone_gateway,
        created_at: DateTime.utc_now()
      }),
      on_conflict: :nothing,
      conflict_target: :tenant_id
    )

  %Tenant{} ->
    Logger.info("seed_real_upstreams: tenant #{tenant_id} already present; reusing")
end

# Real OpenAI upstreams. BypassDnsResolver resolves these against
# public DNS (8.8.8.8 / 1.1.1.1), so the /etc/hosts override that
# points Codex at 127.0.0.1 does NOT trap the gateway's own outbound
# connection. That asymmetry is the whole DNS-override primitive
# (spec 009 FR-007 / R-011).
provider_configs = [
  %{
    tenant_id: tenant_id,
    provider: "openai_chatgpt",
    upstream_host: "chatgpt.com",
    upstream_port: 443,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer_plus_chatgpt_account_id,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{
      "scheme" => "https",
      "demo_target" => "real_openai",
      "seed" => "fable_demo_real"
    }
  },
  %{
    tenant_id: tenant_id,
    provider: "openai_auth",
    upstream_host: "auth.openai.com",
    upstream_port: 443,
    transport_modes: ["https-sse"],
    auth_mode: :internal_none,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{
      "scheme" => "https",
      "demo_target" => "real_openai",
      "seed" => "fable_demo_real",
      "passthrough" => true
    }
  },
  %{
    tenant_id: tenant_id,
    provider: "openai_api",
    upstream_host: "api.openai.com",
    upstream_port: 443,
    transport_modes: ["wss", "https-sse"],
    auth_mode: :bearer,
    api_format: :openai_responses,
    enabled: true,
    metadata: %{
      "scheme" => "https",
      "demo_target" => "real_openai",
      "seed" => "fable_demo_real"
    }
  }
]

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
      Logger.info("seed_real_upstreams: inserting #{attrs.upstream_host} (#{attrs.provider})")
      Repo.insert!(LlmProviderConfig.changeset(%LlmProviderConfig{}, attrs))

    %LlmProviderConfig{} = existing ->
      Logger.info("seed_real_upstreams: refreshing #{attrs.upstream_host} (#{attrs.provider})")
      Repo.update!(LlmProviderConfig.changeset(existing, attrs))
  end
end)

Logger.info("seed_real_upstreams: done (tenant #{tenant_id}).")
