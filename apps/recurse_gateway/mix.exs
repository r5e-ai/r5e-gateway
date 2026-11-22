defmodule RecurseGateway.MixProject do
  @moduledoc """
  Data Plane + Control/Governance/Audit Plane HTTP surface (:recurse_gateway OTP app).

  Phase-1 scope: TLS termination + SPIFFE peer-cert verification at ingress (FR-025),
  Cedar policy evaluation (FR-039), attestation envelope construction (FR-021),
  RFC 8693 token exchange for downstream auth (FR-047), completeness-boundary
  netns egress filtering (FR-043), Standalone Identity Broker (FR-053),
  SIEM Log Forwarder (FR-048 surface 1).
  """
  use Mix.Project

  def project do
    [
      app: :recurse_gateway,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  # Test-support modules (JWT mint helper, ExUnit fixtures) live under
  # `test/support/`. Compile them only in :test env so production builds
  # stay lean and test-only deps (jose for mint helper) don't leak into
  # prod. Mirrors the pattern in `apps/recurse_providers/mix.exs`.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger, :ssl],
      mod: {RecurseGateway.Application, []}
    ]
  end

  defp deps do
    [
      {:recurse_shared, in_umbrella: true},
      {:recurse_provenance, in_umbrella: true},
      {:recurse_providers, in_umbrella: true},
      # HTTP server (Data Plane hot path; HTTP/1.1 + HTTP/2 + SSE).
      {:bandit, "~> 1.7"},
      {:plug, "~> 1.19"},
      # Hands a `Plug.Conn` over to a `WebSock` handler under Bandit, for
      # the evidence tail (`Recurse.Gateway.Evidence.TailSocket`).
      {:websock_adapter, "~> 0.5"},
      # 009 T001 — outbound WebSocket client for the LLM API proxy
      # (Sub-3.3). Used by `Recurse.Gateway.LlmProxy.WebSocketBridge` to
      # open `wss://chatgpt.com/backend-api/codex/responses` (and Anthropic
      # / Gemini WS variants in Phase 6). `mint_web_socket` is a transport
      # primitive built on top of `:mint` — NOT a vendor SDK — so it does
      # not violate Principle V's "front external deps with a Provider
      # Interface" rule. The LLMProvider PI continues to own the
      # high-level OpenAI/Anthropic/Bedrock client abstractions; the
      # proxy operates at the wire-transport layer below that abstraction.
      # See `specs/009-llm-api-proxy/contracts/streaming_proxy.md` and
      # `research.md` R-009.
      {:mint_web_socket, "~> 1.0"},
      # Telemetry + Prometheus exporter for FR-014 /metrics.
      #
      # `telemetry_metrics_prometheus` drags in `plug_cowboy` for its bundled
      # exposition endpoint; we don't want that coupling (Bandit owns our
      # ingress surface), so we expose `/metrics` ourselves via the router
      # and pull the core scraper directly. F002 T091 depends on the core
      # reporter's `scrape/1` entry point.
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_metrics_prometheus_core, "~> 1.2"},
      # Periodic gauge polling (FR-029 `recurse_outbox_depth`) — T091.
      {:telemetry_poller, "~> 1.0"},
      # In-memory token-bucket rate limiter for FR-030 — T092. Backend is
      # ETS-owned by Hammer; our Plug is stateless.
      {:hammer, "~> 7.1"},
      {:telemetry_metrics_prometheus, "~> 1.1"},
      # F004 T001 — background job runner for the audit console:
      #   * 3 retention purgers (PolicyDrafts, PolicySuggestions, ChatHistory)
      #   * SuggestionEngine.HeuristicRunner (hourly per FR-030)
      #   * SuggestionEngine.LlmRunner (daily per FR-030)
      #   * BrowserAuth.NoncePurger (5-min OIDC nonce TTL sweep)
      # Runs against the existing F002 Postgres instance — no new external
      # services per Constitution Principle I (Air-Gap Native).
      # Gateway is sole owner of console scheduled work; do NOT add to
      # other umbrella apps.
      {:oban, "~> 2.18"},
      # F004 T002 — CORS allowlist for the public schema-publication
      # endpoints (`/v1/schemas/*` and `/.well-known/r5e-audit.json`)
      # so third-party verifier tooling can fetch JSON Schemas
      # cross-origin. Same-origin SPA + API does NOT need CORS; this
      # dep is scoped to the schema-publication plug only.
      {:corsica, "~> 2.0"},
      # Note: outbound HTTP goes through recurse_providers' LLMProvider impls,
      # which own their `req` dependency directly. Gateway MUST NOT declare
      # req as a direct dep — doing so invites developers to bypass the
      # Provider Interface and violate Principle V (Provider-Interface Neutrality).
      # Test-only.
      {:stream_data, "~> 1.3", only: :test},
      {:mox, "~> 1.2", only: :test},
      # Sibling broker brought in for the F002 T089 end-to-end integration
      # test only. Prod releases of `:recurse_gateway` do NOT include the
      # broker — it ships as its own container per F002 docker-compose
      # topology. `only: :test` keeps the prod compile graph free of
      # broker code so Principle V (Provider-Interface Neutrality; no
      # hidden cross-app coupling) still holds at release time.
      {:recurse_broker, in_umbrella: true, only: :test}
      # NOTE: test-only cross-app dep — apps/recurse_gateway/test/integration/
      # us1_with_real_broker_test.exs and sc012_restore_drill_test.exs alias
      # RecurseBroker.Test.{MockOidcIssuer, SupervisorHelper} from the broker
      # app's test/support/ directory (see apps/recurse_broker/mix.exs
      # elixirc_paths). The in_umbrella dep above makes this resolution work.
      # See specs/002-standalone-gateway-vertical-slice/plan.md Post-Tasks
      # Recheck for the AD-001 c' / cross-app test-support rationale.
      #
      # Note: `plug_cowboy` is available for tests via transitive
      # inclusion from `telemetry_metrics_prometheus`. The in-tree
      # `MockHttpUpstream` at `test/support/mock_http_upstream.ex` uses
      # it for its Bypass-style mock server. If telemetry_metrics_prometheus
      # ever drops the dep, add `{:plug_cowboy, "~> 2.8", only: :test}`
      # here (the sibling `:recurse_providers` app does this). Adding
      # it with `only: :test` now conflicts with telemetry's prod-env
      # need; leaving it transitive is the zero-conflict posture.
    ]
  end
end
