defmodule Recurse.Provenance.Capture do
  @moduledoc """
  The part of capturing a fact that needs no shared state.

  Everything here runs in the caller's own process, so it spreads across
  cores and never queues behind another caller: resolving named
  attachments to content references, placing their bytes in the local
  content directory, and checking the body against the definition the
  profile maps the kind to.

  What comes out is a prepared request. All that is left for the stream's
  owner is to give it a position, name its predecessor and sign it.
  """

  alias Recurse.Provenance.{Definitions, Evidence, Ref, Staging}
  alias RecurseVerify.Canonical

  @type attachment ::
          %{required(:name) => String.t(), required(:bytes) => binary()}
          | %{
              required(:name) => String.t(),
              required(:path) => Path.t(),
              optional(:sha256) => <<_::256>>
            }

  @type request :: %{
          required(:kind_path) => String.t(),
          required(:body) => map(),
          required(:actor) => String.t(),
          optional(:submission_id) => String.t(),
          optional(:attachments) => [attachment()],
          optional(:blobs) => [binary()],
          optional(:occurred_at) => DateTime.t(),
          optional(:session) => String.t(),
          optional(:subject) => String.t(),
          optional(:identity_ref) => String.t(),
          optional(:on_behalf_of) => String.t(),
          optional(:context_refs) => [String.t()],
          optional(:causes) => [String.t()]
        }

  @typedoc "A request with its content placed and its body checked."
  @type prepared :: %{
          request: request(),
          body: map(),
          schema_ref: Ref.t(),
          content: [Ref.t()],
          digest: String.t() | nil
        }

  @doc """
  Prepare a request for a stream that cites `profile`.

  `content_dir` is where content waits, under its hash, until it is
  shipped to the content store. `definitions` returns the bytes of an
  installed extension definition by its reference; the base definitions
  are always known.

  `opts`:

    * `:recorder?` — the recorder itself is asking (seals, checkpoints)
    * `:staging` — how content files are written and read
      (`Recurse.Provenance.Staging`); plain files by default
  """
  @spec prepare(request(), map(), Path.t(), (Ref.t() -> {:ok, binary()} | :error), keyword()) ::
          {:ok, prepared()} | {:error, term()}
  def prepare(request, profile, content_dir, definitions \\ fn _ -> :error end, opts \\ []) do
    staging = Keyword.get(opts, :staging) || Staging.plain()

    with :ok <- not_recorder_only(request.kind_path, Keyword.get(opts, :recorder?, false)),
         {:ok, schema_ref} <- schema_ref(profile, request.kind_path),
         {:ok, body, placed} <- place_attachments(request, content_dir, staging),
         :ok <- check_body(request.kind_path, schema_ref, body, definitions),
         {:ok, supplied} <- place_supplied(request, content_dir, staging) do
      {:ok,
       %{
         request: request,
         body: body,
         schema_ref: schema_ref,
         content: Enum.uniq(placed ++ supplied),
         digest: digest(request, body)
       }}
    end
  end

  @doc "The local path content with this reference waits at."
  @spec content_path(Path.t(), Ref.t()) :: Path.t()
  def content_path(content_dir, "bytes:sha256:" <> hex), do: Path.join(content_dir, hex)

  # Seals and checkpoints are issued by the recorder itself and cannot be
  # submitted as ordinary requests.
  defp not_recorder_only(_kind_path, true), do: :ok

  defp not_recorder_only(kind_path, false) do
    if Definitions.recorder_only?(kind_path), do: {:error, :recorder_only_kind}, else: :ok
  end

  defp schema_ref(profile, kind_path) do
    case Map.fetch(profile["schemas"], kind_path) do
      {:ok, ref} -> {:ok, ref}
      :error -> {:error, :kind_not_in_profile}
    end
  end

  # The body is checked here, against the exact definition the record
  # will cite. Position and predecessor are added by the stream's owner
  # and are right by construction.
  defp check_body(kind_path, schema_ref, body, definitions) do
    case Definitions.check(kind_path, schema_ref, body, definitions) do
      :ok ->
        :ok

      # A recorder signs only what it can check.
      :unavailable ->
        {:error, :definition_not_installed}

      {:error, :definition_is_for_another_kind} ->
        {:error, :definition_is_for_another_kind}

      {:error, violations} ->
        {:error,
         {:invalid_evidence,
          Enum.map(violations, &{"/body" <> String.trim_leading(&1.path, "$"), &1.code})}}
    end
  end

  # `attachment:<name>` tokens in the body become `bytes:` references to
  # the named content. The token never reaches signed evidence.
  defp place_attachments(request, content_dir, staging) do
    attachments = Map.get(request, :attachments, [])
    names = Enum.map(attachments, & &1.name)

    if names != Enum.uniq(names) do
      {:error, :duplicate_attachment_name}
    else
      try do
        by_name = Map.new(attachments, &{&1.name, place(&1, content_dir, staging)})
        {:ok, substitute(request.body, by_name), Map.values(by_name)}
      catch
        {:missing_attachment, name} -> {:error, {:missing_attachment, name}}
        {:attachment, name, reason} -> {:error, {:attachment, name, reason}}
      end
    end
  end

  # Content the host supplies alongside a request: the policy that was
  # evaluated, an extension definition.
  defp place_supplied(request, content_dir, staging) do
    Enum.reduce_while(Map.get(request, :blobs, []), {:ok, []}, fn bytes, {:ok, refs} ->
      ref = Ref.bytes(bytes)

      case Staging.write_bytes(staging, content_path(content_dir, ref), bytes) do
        :ok -> {:cont, {:ok, refs ++ [ref]}}
        {:error, reason} -> {:halt, {:error, {:content_not_held, reason}}}
      end
    end)
  end

  defp place(%{name: name, bytes: bytes}, content_dir, staging) do
    ref = Ref.bytes(bytes)

    case Staging.write_bytes(staging, content_path(content_dir, ref), bytes) do
      :ok -> ref
      {:error, reason} -> throw({:attachment, name, reason})
    end
  end

  # A file is hashed as a stream and moved into place; it is never read
  # whole into memory.
  defp place(%{name: name, path: path} = attachment, content_dir, staging) do
    digest =
      case Staging.hash_file(staging, path, attachment[:sha256]) do
        {:ok, digest} -> digest
        {:error, reason} -> throw({:attachment, name, reason})
      end

    case attachment[:sha256] do
      expected when is_binary(expected) and expected != digest ->
        throw({:attachment, name, :does_not_match_expected_hash})

      _ ->
        ref = "bytes:sha256:" <> Base.encode16(digest, case: :lower)

        case Staging.place_file(staging, path, content_path(content_dir, ref)) do
          :ok -> ref
          {:error, reason} -> throw({:attachment, name, reason})
        end
    end
  end

  defp substitute("attachment:" <> name, by_name) do
    case by_name do
      %{^name => ref} -> ref
      _ -> throw({:missing_attachment, name})
    end
  end

  defp substitute(list, by_name) when is_list(list), do: Enum.map(list, &substitute(&1, by_name))

  defp substitute(map, by_name) when is_map(map),
    do: Map.new(map, fn {k, v} -> {k, substitute(v, by_name)} end)

  defp substitute(other, _by_name), do: other

  # What a submission handle is bound to, so a retry can be told from a
  # different request reusing the handle.
  defp digest(request, body) do
    Canonical.hash(%{
      "kind" => request.kind_path,
      "body" => body,
      "actor" => request.actor,
      "session" => request[:session],
      "subject" => request[:subject],
      "causes" => request[:causes] || []
    })
  rescue
    ArgumentError -> nil
  end

  @doc "The evidence value for a prepared request at a given position."
  @spec evidence(prepared(), map()) :: Evidence.t()
  def evidence(%{request: request, body: body, schema_ref: schema_ref}, position) do
    Evidence.new(
      kind_path: request.kind_path,
      schema_ref: schema_ref,
      profile_ref: position.profile_ref,
      issuer: position.issuer,
      actor: request.actor,
      stream: position.stream,
      seq: position.seq,
      previous: position.previous,
      captured_at: position.captured_at,
      body: body,
      occurred_at: request[:occurred_at],
      session: request[:session],
      subject: request[:subject],
      identity_ref: request[:identity_ref],
      on_behalf_of: request[:on_behalf_of],
      context_refs: request[:context_refs],
      causes: request[:causes]
    )
  end
end
