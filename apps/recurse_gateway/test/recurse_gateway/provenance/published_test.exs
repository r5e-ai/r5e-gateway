defmodule Recurse.Gateway.Provenance.PublishedTest do
  @moduledoc """
  A publisher adds a definition to a running deployment: who is believed,
  what is refused, and that what was admitted is on the chain, carried in
  exports and found again after a restart.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Provenance.{Carried, Published, Runtime}
  alias Recurse.Provenance.{Envelope, Evidence, Export, Key, Publication, Ref, Vectors}
  alias Recurse.Providers.Impls.PostgresEvidenceStore, as: Store
  alias Recurse.Providers.Repo

  setup %{tmp_dir: tmp_dir} do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    deployment = "test-#{System.unique_integer([:positive])}"
    publisher = Key.generate("ed25519")

    start = fn ->
      start_supervised!(
        {Runtime,
         deployment: deployment,
         signer: Key.generate("es256"),
         dir: tmp_dir,
         partitions: 1,
         flush_interval_ms: 20}
      )
    end

    believe(publisher.key_id <> "=acme.example")
    start.()

    on_exit(fn ->
      Application.delete_env(:recurse_gateway, :evidence_publishers)
      :persistent_term.erase({Runtime, :info})
      Published.unload()
    end)

    %{deployment: deployment, publisher: publisher, start: start, tmp_dir: tmp_dir}
  end

  # A bundle holding one record of `kind_path` citing `schema_ref`.
  defp bundle_citing(kind_path, schema_ref) do
    signer = Key.generate("ed25519")

    evidence =
      Evidence.new(
        kind_path: kind_path,
        schema_ref: schema_ref,
        profile_ref: Ref.bytes("a profile"),
        issuer: signer.key_id,
        actor: "urn:r5e:principal:test:someone",
        stream: "urn:r5e:stream:test:endpoint:one",
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{"verdict" => "pass"}
      )

    {:ok, signed} = Envelope.sign(evidence, signer)
    {:ok, bundle} = Export.build(records: [signed.envelope])
    bundle
  end

  defp believe(text), do: Application.put_env(:recurse_gateway, :evidence_publishers, text)

  # A publication of the extension kind, written for this deployment's chain.
  defp publication(signer, deployment, opts \\ []) do
    document = Vectors.extension_package()

    {:ok, set} =
      Publication.issue(
        signer,
        [
          name: "acme",
          package: "acme.reviews",
          documents: [document],
          stream_prefix: "urn:r5e:stream:#{deployment}:definitions:"
        ] ++ opts
      )

    {set, document}
  end

  test "a believed publisher's definition is admitted, recorded and in force", ctx do
    {set, document} = publication(ctx.publisher, ctx.deployment)
    refute Published.admitted?(document.kind_path, document.ref)

    assert {:ok, [%{"ref" => ref, "publisher" => publisher, "kinds" => [kind]}]} =
             Published.admit(set)

    assert publisher == ctx.publisher.key_id
    assert kind == document.kind_path
    assert Published.admitted?(document.kind_path, document.ref)

    # On this deployment's chain, at the first position of its own stream.
    assert {:ok, %{evidence: evidence}} = Store.fetch(Repo, ref)

    assert String.starts_with?(
             evidence["stream"],
             "urn:r5e:stream:#{ctx.deployment}:definitions:"
           )

    assert evidence["seq"] == 1

    # The document is held, and both go out with every export.
    assert {:ok, bytes} = Store.get_blob(Repo, document.ref)
    assert bytes == document.bytes

    # It goes out with an export whose records follow it, with its
    # document, and with no other export.
    citing = bundle_citing(document.kind_path, document.ref)
    assert %{"records" => [%{"ref" => ^ref}], "blobs" => blobs} = Published.carried_for(citing)
    assert document.ref in Enum.map(blobs, & &1["ref"])
    assert ref in Enum.map(Carried.carry(citing)["records"], & &1["ref"])

    base_only = bundle_citing("provenance.r5e.io/v2/ToolCall", document.ref)
    assert %{"records" => []} = Published.carried_for(base_only)
    refute ref in Enum.map(Carried.carry(base_only)["records"], & &1["ref"])

    assert [%{"kind" => ^kind, "publication" => ^ref, "inForce" => true}] = Published.list()

    # Sent again, it answers the same and adds nothing.
    assert {:ok, [%{"ref" => ^ref}]} = Published.admit(set)
    assert [_one] = Published.list()
  end

  test "nothing a caller attaches beyond what the record needs is kept", ctx do
    {set, _document} = publication(ctx.publisher, ctx.deployment)
    {:ok, _} = Published.admit(set)
    file = Published.file(ctx.tmp_dir)
    before = File.read!(file)

    # Anyone can send an admitted publication again. Extra keys and blobs
    # ride along and are well formed in themselves.
    junk = :crypto.strong_rand_bytes(4096)
    stray = Key.generate("ed25519")

    padded =
      set
      |> Map.update!(
        "blobs",
        &(&1 ++ [%{"ref" => Ref.bytes(junk), "base64" => Base.encode64(junk)}])
      )
      |> Map.update!(
        "keys",
        &(&1 ++
            [
              %{
                "keyid" => stray.key_id,
                "algorithm" => stray.algorithm,
                "bytes" => Base.encode64(stray.public_key)
              }
            ])
      )

    assert {:ok, [_same]} = Published.admit(padded)
    assert File.read!(file) == before
    refute File.read!(file) =~ Base.encode64(junk)
    assert [] = Path.wildcard(file <> ".*.partial")
  end

  test "what was admitted is in force again after a restart", ctx do
    {set, document} = publication(ctx.publisher, ctx.deployment)
    {:ok, _} = Published.admit(set)

    stop_supervised!(Runtime)
    Runtime.stop()
    refute Published.admitted?(document.kind_path, document.ref)

    ctx.start.()
    assert Published.admitted?(document.kind_path, document.ref)
  end

  test "a publisher is believed only about its own domains", ctx do
    {set, document} = publication(ctx.publisher, ctx.deployment)

    believe(ctx.publisher.key_id <> "=example.org")
    assert {:error, :publisher_not_believed} = Published.admit(set)

    # A name that merely ends the same way is another domain.
    believe(ctx.publisher.key_id <> "=notacme.example,cme.example")
    assert {:error, :publisher_not_believed} = Published.admit(set)

    stranger = Key.generate("ed25519")
    {theirs, _} = publication(stranger, ctx.deployment)
    believe(ctx.publisher.key_id <> "=acme.example")
    assert {:error, :publisher_not_believed} = Published.admit(theirs)

    refute Published.admitted?(document.kind_path, document.ref)
    assert [] = Published.list()
  end

  test "with no publisher named, or one named without a domain, nothing is admitted", ctx do
    {set, _document} = publication(ctx.publisher, ctx.deployment)

    Application.delete_env(:recurse_gateway, :evidence_publishers)
    assert {:error, :no_publisher_configured} = Published.admit(set)

    believe(ctx.publisher.key_id)
    assert %{} == Published.publishers()
    assert {:error, :no_publisher_configured} = Published.admit(set)
  end

  test "a publication is refused when it is not whole", ctx do
    {set, document} = publication(ctx.publisher, ctx.deployment)

    without_document =
      Map.update!(set, "blobs", &Enum.reject(&1, fn b -> b["ref"] == document.ref end))

    assert {:error, :definition_not_carried} = Published.admit(without_document)

    # Signed by someone else's key under the publisher's key id.
    forged =
      Map.update!(set, "records", fn [%{"envelope" => envelope} = record] ->
        [
          %{
            record
            | "envelope" =>
                put_in(
                  envelope,
                  ["signatures", Access.at(0), "sig"],
                  Base.encode64(:crypto.strong_rand_bytes(64))
                )
          }
        ]
      end)

    assert {:error, :not_a_verifiable_publication} = Published.admit(forged)

    # Written for somewhere other than this deployment's chain.
    {elsewhere, _} = publication(ctx.publisher, "another-deployment")
    assert {:error, :stream_not_admissible} = Published.admit(elsewhere)

    assert {:error, :not_a_verifiable_publication} = Published.admit(%{"records" => []})
    assert [] = Published.list()
  end

  test "a document listed under a kind it does not define is refused", ctx do
    document = Vectors.extension_package()
    wrong = %{document | kind_path: "acme.example/v1/SomethingElse"}

    {:ok, set} =
      Publication.issue(ctx.publisher,
        name: "acme",
        documents: [wrong],
        stream_prefix: "urn:r5e:stream:#{ctx.deployment}:definitions:"
      )

    assert {:error, :not_a_definition_of_that_kind} = Published.admit(set)
  end
end
