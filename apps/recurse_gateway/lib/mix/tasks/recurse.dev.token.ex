defmodule Mix.Tasks.Recurse.Dev.Token do
  @shortdoc "Write a bearer token for a local or CI gateway to a file"
  @moduledoc """
  Mints a bearer token signed with the deployment's own broker key, for
  calling a gateway that has no identity provider behind it: a local
  run, or a test in CI.

      mix recurse.dev.token --subject dana@meridian.example --role caller --out /tmp/dana.token

  The token is written to `--out` with owner-only permissions and is
  never printed. It is what the development login would put in a cookie,
  as a bearer, so a client that sends `Authorization: Bearer` can be
  tried without a browser.

  It needs the same settings the gateway runs with
  (`BROKER_JWT_SIGNING_KEY_PATH`, `PORT` or `R5E_PUBLIC_HOSTNAME`,
  `R5E_TENANT_ID`), so that the issuer, audience and tenant match. It
  refuses to run in production.

  Options: `--subject` (required), `--role` (default `caller`),
  `--tenant` (default `R5E_TENANT_ID`), `--ttl` in seconds (default
  3600), `--out` (required).
  """
  use Mix.Task

  alias Recurse.Shared.Identity.JwtMinter

  @impl true
  def run(args) do
    if Mix.env() == :prod, do: Mix.raise("recurse.dev.token does not run in production")

    {opts, _} =
      OptionParser.parse!(args,
        strict: [subject: :string, role: :string, tenant: :string, ttl: :integer, out: :string]
      )

    subject = opts[:subject] || Mix.raise("--subject is required")
    out = opts[:out] || Mix.raise("--out is required")
    role = opts[:role] || "caller"

    Mix.Task.run("app.config")
    {:ok, _} = Application.ensure_all_started(:jose)

    cfg = Application.get_env(:recurse_gateway, :internal_jwt, [])
    path = cfg[:signing_key_path]
    tenant = opts[:tenant] || System.get_env("R5E_TENANT_ID")

    cond do
      is_nil(path) or not File.regular?(path) ->
        Mix.raise("BROKER_JWT_SIGNING_KEY_PATH is not set to a readable key file")

      is_nil(cfg[:audience]) or is_nil(cfg[:issuer]) ->
        Mix.raise("the gateway's token audience and issuer are not configured")

      is_nil(tenant) ->
        Mix.raise("--tenant or R5E_TENANT_ID is required")

      true ->
        :ok
    end

    {:ok, token} =
      JwtMinter.mint(
        subject: subject,
        issuer: cfg[:issuer],
        audience: cfg[:audience],
        principal: %{
          "kind" => "obo_human",
          "issuer" => "recurse://dev-token",
          "subject" => subject,
          "display_name" => subject,
          "groups" => [],
          "recurse_role" => role,
          "tenant_id" => tenant
        },
        jwk: JOSE.JWK.from_pem_file(path),
        kid: path |> Path.basename() |> Path.rootname(),
        ttl_seconds: opts[:ttl] || 3600
      )

    # Written beside the target under a name nobody could have planted,
    # owner-only before any token byte goes in, then moved into place: a
    # link left at `--out` is replaced, never followed.
    partial = out <> "." <> Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)
    {:ok, file} = :file.open(partial, [:write, :raw, :exclusive])
    :ok = :file.close(file)
    File.chmod!(partial, 0o600)
    File.write!(partial, token)
    File.rename!(partial, out)
    Mix.shell().info("wrote a token for #{subject} (#{role}) to #{out}")
  end
end
