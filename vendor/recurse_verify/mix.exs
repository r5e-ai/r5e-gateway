defmodule RecurseVerify.MixProject do
  use Mix.Project

  def project do
    [
      app: :recurse_verify,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: false,
      deps: [{:jason, "~> 1.4"}],
      escript: [main_module: RecurseVerify.CLI],
      aliases: aliases()
    ]
  end

  def application do
    [extra_applications: [:crypto]]
  end

  # `mix conformance` is this repository's CI target for the verifier:
  # build the escript and run it against every case in
  # `../conformance/cases`, comparing standard output byte for byte and
  # the exit status exactly (spec/07 §11). The reference must pass its
  # own kit, and a change that moves a byte of a report has to move the
  # recorded answers with it — deliberately, and in the same commit.
  defp aliases do
    [conformance: ["escript.build", &conformance/1]]
  end

  defp conformance(_args) do
    kit = Path.expand("../conformance", __DIR__)
    escript = Path.expand("recurse_verify", __DIR__)

    {output, status} =
      System.cmd(Path.join(kit, "run.sh"), [escript], cd: kit, stderr_to_stdout: true)

    IO.write(output)
    if status != 0, do: Mix.raise("conformance: #{status}")
  end
end
