defmodule Mix.Tasks.Recurse.Provenance.Publish do
  @shortdoc "Sign a publication of the installed definitions"
  @moduledoc """
  Signs a statement that the installed definition documents are the
  publisher's, and writes it with everything needed to check it.

      mix recurse.provenance.publish --key PRIVATE_KEY.pem --out FILE [--name NAME]

  `--key` is the publisher's private key as a PEM file (Ed25519, P-256
  or P-384). It is read, used once and never written anywhere. Run this
  where that key lives, not on a serving machine.

  `--out` receives the carried set: the signed record, the publisher's
  public key, its profile and the definition documents. A gateway that
  is given this file adds it to what it exports, and a reader who trusts
  the publisher's key can then tell whose definitions the records cite.

  `--name` is the publisher's short name in its actor and stream
  (default `r5e`).

  Prints the publisher's key id, which is what a reader names as a
  trusted publisher.
  """
  use Mix.Task

  alias Recurse.Provenance.{Key, Publication}

  @impl true
  def run(args) do
    {opts, _} = OptionParser.parse!(args, strict: [key: :string, out: :string, name: :string])

    # Reading a key file needs OTP's key-handling code on the path, which a
    # bare task does not have until the project's applications are loaded.
    Mix.Task.run("app.config")

    key = opts[:key] || Mix.raise("--key PRIVATE_KEY.pem is required")
    out = opts[:out] || Mix.raise("--out FILE is required")

    signer =
      with {:ok, pem} <- File.read(key),
           {:ok, signer} <- Key.signer_from_pem(pem) do
        signer
      else
        _ -> Mix.raise("#{key} is not a readable Ed25519, P-256 or P-384 private key")
      end

    case Publication.issue(signer, Keyword.take(opts, [:name])) do
      {:ok, set} ->
        File.write!(out, Publication.encode(set))
        [%{"ref" => ref}] = set["records"]
        Mix.shell().info("published #{length(set["blobs"]) - 1} definitions as #{ref}")
        Mix.shell().info("publisher key: #{signer.key_id}")

      {:error, reason} ->
        Mix.raise("could not publish: #{inspect(reason)}")
    end
  end
end
