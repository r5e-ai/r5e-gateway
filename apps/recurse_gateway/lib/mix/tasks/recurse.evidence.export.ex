defmodule Mix.Tasks.Recurse.Evidence.Export do
  @shortdoc "Export one session's Provenance v2 evidence as an offline bundle"
  @moduledoc """
  Writes the evidence of one session as an offline bundle.

      mix recurse.evidence.export SESSION --out FILE [--withhold-content]

  `SESSION` is the session's full id, as recorded
  (`urn:r5e:session:<tenant>:<id>`). The bundle carries the signed
  records, the profile and definitions they cite, the issuer's public
  key, the seals that cover the records, and the content they refer to.
  With `--withhold-content` the prompts, responses and tool arguments
  are left out and named as withheld; the records still verify.

  The task reads the index and the content store. It uses the same
  provider settings as the gateway (`R5E_PROVIDER_*`, `POSTGRES_*`,
  `R5E_EVIDENCE_DEPLOYMENT`) and does not need the gateway to be
  running. It starts no listener and records nothing.

  Check the result with `mix recurse.provenance.verify`.
  """
  use Mix.Task

  alias Recurse.Gateway.Provenance.Runtime
  alias Recurse.Provenance.Exporter

  @impl true
  def run(args) do
    {opts, positional} =
      OptionParser.parse!(args, strict: [out: :string, withhold_content: :boolean])

    session =
      case positional do
        [session] -> session
        _ -> Mix.raise("usage: mix recurse.evidence.export SESSION --out FILE")
      end

    out = opts[:out] || Mix.raise("--out FILE is required")

    # This process reads; it must not listen or capture.
    System.put_env("R5E_LLM_PROXY_ENABLED", "false")
    System.put_env("R5E_START_HTTP", "false")
    Mix.Task.run("app.config")
    Application.put_env(:recurse_gateway, :evidence_capture?, false)
    Mix.Task.run("app.start")

    deployment = Application.get_env(:recurse_gateway, :evidence_deployment, "default")

    case Exporter.session(Runtime.store(deployment), session,
           content: not Keyword.get(opts, :withhold_content, false)
         ) do
      {:ok, %{"records" => []}} ->
        Mix.raise("no evidence is recorded for session #{session}")

      {:ok, bundle} ->
        bundle = Recurse.Gateway.Provenance.Carried.carry(bundle)
        File.write!(out, Jason.encode_to_iodata!(bundle))

        Mix.shell().info(
          "wrote #{out}: #{length(bundle["records"])} records, #{length(bundle["blobs"])} blobs, " <>
            "#{length(bundle["seals"])} seals, #{length(bundle["omissions"])} omissions"
        )

      {:error, reason} ->
        Mix.raise("export failed: #{inspect(reason)}")
    end
  end
end
