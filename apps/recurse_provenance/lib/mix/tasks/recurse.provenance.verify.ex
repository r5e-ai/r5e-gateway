defmodule Mix.Tasks.Recurse.Provenance.Verify do
  @shortdoc "Verify a Provenance v2 export bundle offline"
  @moduledoc """
  Verifies an export bundle with nothing but the file.

      mix recurse.provenance.verify BUNDLE [--trust PROFILE_REF]... [--publisher KEY_ID]...
                                    [--root KEY_ID]... | [--chain REF [--min-start-seq N]]
                                    [--report FILE] [--allow-incomplete]

  `--trust` names a capture profile the reader accepts as in force
  (`bytes:sha256:…`); it may be given more than once. Without it, the
  authority of every record is reported as not established. A bundle
  cannot vouch for its own profile, so this is always the reader's
  statement and never taken from the file.

  `--publisher` names a key whose published definitions the reader
  accepts (`key:<alg>:sha256:…`); it may be given more than once.
  Without it, whose definition each record cites is reported as not
  established.

  `--root` names a key the reader trusts as a source of authority; it
  may be given more than once. With it, each record's authority is
  established by following endorsements and badges from those keys, and
  `--trust` no longer decides it.

  `--chain` names a deployment's chain, by the reference of its
  deployment record (`evidence:sha256:…`), in place of `--root`. The
  roots that chain declared at its start are then the ones trusted. Give
  one or the other. `--min-start-seq N` says how far the chain's start
  stream must reach in the file for the reader to accept it; a file can
  be cut short without breaking a signature, and this is how a reader
  who knows the roots were changed refuses an older view.

  Prints a summary and every check that failed or could not be
  performed. `--report FILE` writes the full report as canonical JSON.

  Exit status:

    * 0 — every check was performed and held
    * 1 — a check failed
    * 2 — the file could not be read
    * 3 — nothing failed, but some check could not be performed

  A check that could not be performed establishes nothing: a signature
  whose key was left out of the bundle is not a signature anyone has
  seen verify. `--allow-incomplete` turns status 3 into 0 for a reader
  who has looked at the list and accepts it.
  """
  use Mix.Task

  alias Recurse.Provenance.Export

  @impl true
  def run(args) do
    # Checking a P-256 or P-384 signature needs these, and a task is not
    # always run with the application started.
    {:ok, _} = Application.ensure_all_started(:crypto)
    {:ok, _} = Application.ensure_all_started(:public_key)

    {opts, positional} =
      OptionParser.parse!(args,
        strict: [
          trust: :keep,
          publisher: :keep,
          root: :keep,
          chain: :string,
          min_start_seq: :integer,
          report: :string,
          allow_incomplete: :boolean
        ]
      )

    path =
      case positional do
        [path] -> path
        _ -> Mix.raise("usage: mix recurse.provenance.verify BUNDLE [--trust PROFILE_REF]")
      end

    bundle =
      with {:ok, text} <- File.read(path),
           {:ok, bundle} when is_map(bundle) <- Jason.decode(text) do
        bundle
      else
        _ ->
          Mix.shell().error("#{path} is not a readable JSON object")
          exit({:shutdown, 2})
      end

    if opts[:root] && opts[:chain] do
      Mix.shell().error("give --root or --chain, not both")
      exit({:shutdown, 2})
    end

    result =
      Export.verify(bundle,
        trusted_profiles: Keyword.get_values(opts, :trust),
        trusted_publishers: Keyword.get_values(opts, :publisher),
        trusted_roots: if(opts[:root], do: Keyword.get_values(opts, :root)),
        trusted_chain: opts[:chain],
        min_start_seq: opts[:min_start_seq]
      )

    if start = result.start do
      Mix.shell().info(
        "start of #{start["deployment"]}: carried to position #{start["headSeq"]} " <>
          "(#{start["headCapturedAt"]}); chain #{start["chain"] || "not established"}"
      )
    end

    if file = opts[:report], do: File.write!(file, Export.report_json(result))

    %{ok: ok, failed: failed, incomplete: incomplete} = result.summary
    Mix.shell().info("#{ok} held, #{failed} failed, #{incomplete} could not be checked")

    for f <- result.findings, f.result != :ok do
      Mix.shell().info(
        "  #{f.result}  layer #{f.layer}  #{f.check}  #{f.code}  #{f.subject}" <>
          if(f.about, do: "  (#{f.about})", else: "")
      )
    end

    cond do
      failed > 0 -> exit({:shutdown, 1})
      incomplete > 0 and not Keyword.get(opts, :allow_incomplete, false) -> exit({:shutdown, 3})
      true -> :ok
    end
  end
end
