defmodule Recurse.Gateway.Config.RuntimeExsParseTest do
  @moduledoc """
  Parse-level smoke test for `config/runtime.exs`.

  Caught by way of a multi-line `case ... end` in a keyword-list value
  position landed without parens — Elixir's parser silently splits the
  enclosing `config/3` call into 4 args around the case-end boundary,
  emitting `undefined function config/4` only at release boot. The
  pre-swap deploy script's boot check stopped the bad bytecode safely
  in prod, but `mix test` had no equivalent guard.

  This test reads `config/runtime.exs` and asserts it parses to a quoted
  AST. It does NOT evaluate the file (that needs prod-shape env vars +
  Config.Reader machinery; out of scope here). Evaluation errors are
  caught by the deploy boot check + ArgoCD `Healthy` gate post-cutover.
  """

  use ExUnit.Case, async: true

  @runtime_exs Path.expand("../../../../config/runtime.exs", __DIR__)

  test "config/runtime.exs parses to a quoted AST" do
    source = File.read!(@runtime_exs)

    # Code.string_to_quoted!/1 raises TokenMissingError or SyntaxError on
    # unparenthesized-case-in-keyword-list; if you see one of those at
    # boot in CI, this test now fails before the deploy attempts.
    quoted = Code.string_to_quoted!(source, file: @runtime_exs)

    assert match?({:__block__, _, _}, quoted) or is_tuple(quoted),
           "runtime.exs did not parse to a top-level expression block"
  end

  test "config/runtime.exs does not carry VM-shaped placeholder defaults" do
    source = File.read!(@runtime_exs)

    refute source =~ "gateway.example.com"
    refute source =~ "gateway.dogfood.recurse.local"
    refute source =~ "recurse-gateway-local"
    refute source =~ "localhost:4002"
    refute source =~ "/etc/recurse"
  end

  # Spec 012 S1 review — the two switches whose `false` side is the
  # insecure side must use the strict parser (raises on misspellings)
  # rather than `env_bool` (anything but "true" → false → fail-open).
  test "R5E_DATABASE_SSL and R5E_SECURE_COOKIE use the strict boolean parser" do
    source = File.read!(@runtime_exs)

    assert source =~ ~s|EnvFlags.strict_bool!("R5E_DATABASE_SSL", true)|
    assert source =~ ~s|EnvFlags.strict_bool!("R5E_SECURE_COOKIE", true)|
    refute source =~ ~s|env_bool.("R5E_DATABASE_SSL"|
    refute source =~ ~s|env_bool.("R5E_SECURE_COOKIE"|
  end

  # Spec 012 S2 review — release log level defaults to :info with Ecto
  # query logging off (INSERT params carry receipt tags + session ids);
  # the unknown-Host fallback is opt-in.
  test "LOGGER_LEVEL gates the release log level and Ecto query logging" do
    source = File.read!(@runtime_exs)

    assert source =~ ~s|env.("LOGGER_LEVEL")|
    assert source =~ "config :logger, level: log_level"
    assert source =~ "log: if(log_level == :debug, do: :debug, else: false)"
  end

  test "R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS is wired, default false" do
    source = File.read!(@runtime_exs)

    assert source =~
             ~s|llm_proxy_fallback_unknown_hosts: env_bool.("R5E_LLM_PROXY_FALLBACK_UNKNOWN_HOSTS", false)|
  end

  # Spec 012 S1 review — the collapsed-broker JWKS fallback for non-WorkOS
  # providers is gated on dev login; with it off, `jwks_url` stays unset
  # so application.ex's boot-time raise names BROWSER_OIDC_JWKS_URL.
  test "collapsed-broker JWKS fallback is gated on R5E_DEV_LOGIN_ENABLED" do
    source = File.read!(@runtime_exs)

    assert source =~ ~s|dev_login_enabled? = env.("R5E_DEV_LOGIN_ENABLED") == "true"|

    assert source =~
             ~s|env.("BROWSER_OIDC_JWKS_URL") \|\| (dev_login_enabled? and broker_jwks_url)|

    refute source =~ ~s|jwks_url: env.("BROWSER_OIDC_JWKS_URL") \|\| broker_jwks_url|
  end

  test "R5E_APP_CORS_ORIGINS is wired, defaults empty, and strips wildcards" do
    source = File.read!(@runtime_exs)

    assert source =~ ~s|env.("R5E_APP_CORS_ORIGINS")|
    assert source =~ ~s|config :recurse_gateway, app_cors_origins: app_cors_origins|
    assert source =~ ~s|&(&1 == "" or &1 == "*")|
  end

  test "R5E_EVIDENCE_AUTO_HOLD_KINDS is wired and defaults to empty list" do
    source = File.read!(@runtime_exs)

    assert source =~ ~s|env.("R5E_EVIDENCE_AUTO_HOLD_KINDS") \|\| ""|

    assert source =~
             ~s|config :recurse_gateway, evidence_auto_hold_kinds: evidence_auto_hold_kinds|
  end

  test "R5E_UPSTREAM_ZDR_ROUTES, R5E_CUSTODY_REQUIRE_RELEASE_GRANT, and R5E_PERSONAL_ENABLED are wired with safe defaults" do
    source = File.read!(@runtime_exs)

    assert source =~ ~s|env.("R5E_UPSTREAM_ZDR_ROUTES")|
    assert source =~ ~s|ZdrRoutes.parse_env!(raw)|
    assert source =~ ~s|config :recurse_gateway, upstream_zdr_routes: upstream_zdr_routes|

    assert source =~
             ~s|custody_require_release_grant?: env_bool.("R5E_CUSTODY_REQUIRE_RELEASE_GRANT", false)|

    assert source =~ ~s|personal_enabled?: env_bool.("R5E_PERSONAL_ENABLED", false)|

    assert source =~
             ~s|evidence_public_chain?: env_bool.("R5E_EVIDENCE_PUBLIC_CHAIN", false)|
  end
end
