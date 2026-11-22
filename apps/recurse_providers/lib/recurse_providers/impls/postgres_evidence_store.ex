defmodule Recurse.Providers.Impls.PostgresEvidenceStore do
  @moduledoc """
  `Recurse.Provenance.Store` on Postgres, with content in a storage
  provider.

  Postgres holds the signed records and, for each piece of content, its
  reference and where the bytes are. The bytes themselves go to the
  deployment's `StorageProvider` (S3, a filesystem). `append/2` first
  puts every blob into storage, then commits the record and the blob
  rows in one transaction; when it returns `:ok` the content is held and
  the record names it, which is the point at which a recorder may answer
  `durable`. A put that succeeds before a failed commit leaves an
  unreferenced object behind, which is harmless under content addressing.

  The unique index on `(stream, seq)` turns a second, different payload
  at an occupied position into `{:error, :conflict}`.

  The handle is either an Ecto repo module, in which case content is
  held inline in Postgres (tests, a single-box trial), or

      %{repo: Repo, content: {StorageProviderModule, state, identity_context}}
  """
  @behaviour Recurse.Provenance.Store

  import Ecto.Query

  alias Recurse.Provenance.{Envelope, Ref}
  alias Recurse.Providers.ContentCipher

  @seal "provenance.r5e.io/v2/EpochSeal"

  @impl true
  def head(handle, stream) do
    query =
      from(r in "evidence_records",
        where: r.stream == ^stream,
        order_by: [desc: r.seq],
        limit: 1,
        select: {r.seq, r.ref}
      )

    {:ok, repo(handle).one(query)}
  rescue
    error -> {:error, error}
  end

  @impl true
  def append(handle, %{ref: ref, stream: stream, seq: seq} = entry) do
    repo = repo(handle)
    row = row(entry)

    with {:ok, blob_rows} <- hold_all(handle, Map.get(entry, :blobs, [])) do
      repo.transaction(fn ->
        if blob_rows != [],
          do: repo.insert_all("evidence_blobs", blob_rows, on_conflict: :nothing)

        result =
          case repo.insert_all("evidence_records", [row], on_conflict: :nothing) do
            {1, _} -> :ok
            {0, _} -> existing(repo, stream, seq, ref)
          end

        with {:error, reason} <- result, do: repo.rollback(reason)
      end)
      |> case do
        {:ok, :ok} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def append_many(_handle, []), do: :ok

  def append_many(handle, entries) do
    # Positions are unique per stream, so a replayed batch inserts nothing
    # for the records already present.
    entries
    |> Enum.map(&row/1)
    |> Enum.chunk_every(1_000)
    |> Enum.each(&repo(handle).insert_all("evidence_records", &1, on_conflict: :nothing))

    :ok
  rescue
    error -> {:error, error}
  end

  defp row(%{evidence: evidence} = entry) do
    sealed = if entry.kind_path == @seal, do: evidence["body"], else: %{}
    {:ok, captured_at, 0} = DateTime.from_iso8601(evidence["capturedAt"])

    %{
      ref: entry.ref,
      stream: entry.stream,
      seq: entry.seq,
      kind_path: entry.kind_path,
      envelope: entry.envelope,
      issuer: evidence["issuer"],
      actor: evidence["actor"],
      session: evidence["session"],
      on_behalf_of: evidence["onBehalfOf"],
      captured_at: captured_at,
      submission_id: entry[:submission_id],
      submission_digest: entry[:submission_digest],
      sealed_stream: sealed["stream"],
      sealed_from: sealed["firstSeq"],
      sealed_through: sealed["lastSeq"]
    }
  end

  # Nothing was inserted: the same record again is fine, anything else at
  # this position (or this submission handle) is a conflict.
  defp existing(repo, stream, seq, ref) do
    query =
      from(r in "evidence_records", where: r.stream == ^stream and r.seq == ^seq, select: r.ref)

    case repo.one(query) do
      ^ref -> :ok
      _other -> {:error, :conflict}
    end
  end

  @impl true
  def fetch(handle, ref) do
    from(r in "evidence_records", where: r.ref == ^ref, select: ^fields())
    |> repo(handle).one()
    |> entry()
  end

  @impl true
  def by_submission(handle, stream, submission_id) do
    from(r in "evidence_records",
      where: r.stream == ^stream and r.submission_id == ^submission_id,
      select: ^fields()
    )
    |> repo(handle).one()
    |> entry()
  end

  @impl true
  def range(handle, stream, first, last) do
    rows =
      from(r in "evidence_records",
        where: r.stream == ^stream and r.seq >= ^first and r.seq <= ^last,
        order_by: [asc: r.seq],
        select: ^fields()
      )
      |> repo(handle).all()

    if length(rows) == last - first + 1,
      do: {:ok, Enum.map(rows, &elem(entry(&1), 1))},
      else: {:error, :gap}
  rescue
    error -> {:error, error}
  end

  @impl true
  def last_seal(handle, stream) do
    query =
      from(r in "evidence_records",
        where: r.sealed_stream == ^stream,
        order_by: [desc: r.sealed_through],
        limit: 1,
        select: {r.ref, r.sealed_through}
      )

    {:ok, repo(handle).one(query)}
  rescue
    error -> {:error, error}
  end

  @impl true
  def unsealed_firsts(handle, prefix) do
    # LIKE treats \, % and _ specially; a stream name may hold any of them.
    pattern = String.replace(prefix, ["\\", "%", "_"], &("\\" <> &1)) <> "%"

    # Streams are found by their first record, which a partial index
    # covers; each is then compared with its own last record and last seal.
    query =
      from(r in "evidence_records",
        as: :first,
        where: r.seq == 1 and like(r.stream, ^pattern),
        where:
          fragment(
            "(SELECT max(l.seq) FROM evidence_records l WHERE l.stream = ?) > coalesce((SELECT max(s.sealed_through) FROM evidence_records s WHERE s.sealed_stream = ?), 0)",
            r.stream,
            r.stream
          ),
        order_by: r.stream,
        select: r.stream
      )

    {:ok, repo(handle).all(query)}
  rescue
    error -> {:error, error}
  end

  @impl true
  def by_session(handle, session) do
    rows =
      from(r in "evidence_records",
        where: r.session == ^session,
        order_by: [asc: r.stream, asc: r.seq],
        select: ^fields()
      )
      |> repo(handle).all()

    {:ok, Enum.map(rows, &elem(entry(&1), 1))}
  rescue
    error -> {:error, error}
  end

  @impl true
  def list(handle, %{stream_prefix: prefix, limit: limit} = asked) do
    rows =
      from(r in "evidence_records",
        where: fragment("starts_with(?, ?)", r.stream, ^prefix),
        order_by: [desc: r.captured_at, desc: r.ref],
        limit: ^limit,
        select: ^fields()
      )
      |> narrowed(asked)
      |> repo(handle).all()

    {:ok, Enum.map(rows, &elem(entry(&1), 1))}
  rescue
    error -> {:error, error}
  end

  defp narrowed(query, asked) do
    Enum.reduce(asked, query, fn
      {:kind_path, kind}, query ->
        where(query, [r], r.kind_path == ^kind)

      {:session, session}, query ->
        where(query, [r], r.session == ^session)

      {:actor, actor}, query ->
        where(query, [r], r.actor == ^actor)

      {:since, since}, query ->
        where(query, [r], r.captured_at >= type(^since, :utc_datetime_usec))

      {:until, until}, query ->
        where(query, [r], r.captured_at < type(^until, :utc_datetime_usec))

      # One comparison over the pair, so the index that orders the
      # listing also finds where to resume it.
      {:before, {at, ref}}, query ->
        where(
          query,
          [r],
          fragment(
            "(?, ?) < (?, ?)",
            r.captured_at,
            r.ref,
            type(^at, :utc_datetime_usec),
            ^ref
          )
        )

      {_, _}, query ->
        query
    end)
  end

  @impl true
  def by_kind(handle, kind_path, stream_prefix) do
    rows =
      from(r in "evidence_records",
        where:
          r.kind_path == ^kind_path and fragment("starts_with(?, ?)", r.stream, ^stream_prefix),
        order_by: [asc: r.stream, asc: r.seq],
        select: ^fields()
      )
      |> repo(handle).all()

    {:ok, Enum.map(rows, &elem(entry(&1), 1))}
  rescue
    error -> {:error, error}
  end

  @impl true
  def seal_covering(handle, stream, seq) do
    from(r in "evidence_records",
      where: r.sealed_stream == ^stream and r.sealed_from <= ^seq and r.sealed_through >= ^seq,
      order_by: [asc: r.sealed_through],
      limit: 1,
      select: ^fields()
    )
    |> repo(handle).one()
    |> entry()
  end

  @impl true
  def put_key(handle, %{key_id: key_id, algorithm: algorithm, public_key: public_key}) do
    repo(handle).insert_all(
      "evidence_keys",
      [%{key_id: key_id, algorithm: algorithm, public_key: public_key}],
      on_conflict: :nothing
    )

    :ok
  rescue
    error -> {:error, error}
  end

  @impl true
  def get_key(handle, key_id) do
    query =
      from(k in "evidence_keys",
        where: k.key_id == ^key_id,
        select: %{key_id: k.key_id, algorithm: k.algorithm, public_key: k.public_key}
      )

    case repo(handle).one(query) do
      nil -> :error
      key -> {:ok, key}
    end
  end

  @impl true
  def put_blob(handle, ref, content) do
    with {:ok, rows} <- hold_all(handle, [{ref, content}]) do
      if rows != [], do: repo(handle).insert_all("evidence_blobs", rows, on_conflict: :nothing)
      :ok
    end
  rescue
    error -> {:error, error}
  end

  @impl true
  def get_blob(handle, ref) do
    query =
      from(b in "evidence_blobs",
        where: b.ref == ^ref and b.copy == "",
        select: {b.uri, b.bytes}
      )

    case repo(handle).one(query) do
      nil -> :error
      {uri, bytes} -> stored(handle, uri, bytes)
    end
  end

  @impl true
  def get_content(handle, ref, scope) do
    with :error <- get_blob(handle, ref),
         true <- is_binary(scope),
         {copy, content_key} when is_binary(copy) <- opened_by(handle, ref, scope),
         {uri, bytes} <-
           repo(handle).one(
             from(b in "evidence_blobs",
               where: b.ref == ^ref and b.copy == ^copy,
               select: {b.uri, b.bytes}
             )
           ),
         {:ok, stored} <- stored(handle, uri, bytes),
         {:ok, plain} <- ContentCipher.decrypt(stored, content_key, ref),
         # What is handed back is always the bytes the reference names.
         true <- Ref.bytes(plain) == ref do
      {:ok, plain}
    else
      {:ok, bytes} -> {:ok, bytes}
      {:error, :key_service_unavailable} -> {:error, :key_service_unavailable}
      _ -> :error
    end
  end

  # The key to a reference's content through the scope's own locks. A
  # scope can have had several keys; a lock under one that the key service
  # will no longer open does not stand in the way of one it will.
  defp opened_by(handle, ref, scope) do
    locks =
      repo(handle).all(
        from(l in live_locks(ref),
          where: ^of_scope(:lock, scope),
          select: {l.copy, l.locked, l.scope}
        )
      )

    # A lock that could not be tried because the key service did not
    # answer is not the same as one that will never open: the first is
    # worth asking again, and is said only when no other lock opened.
    Enum.reduce_while(locks, nil, fn {copy, locked, under}, outcome ->
      with {:ok, scope_key} <- existing_scope_key(handle, under),
           {:ok, content_key} <- ContentCipher.unlock(locked, scope_key, ref) do
        {:halt, {copy, content_key}}
      else
        {:error, {:key_service_unavailable, _}} -> {:cont, {:error, :key_service_unavailable}}
        _ -> {:cont, outcome}
      end
    end)
  end

  # A scope's key can be destroyed and the scope written to again
  # afterwards: a session whose content was disposed of may still record
  # more. What arrives then is kept under a new key for the same scope,
  # stored under the scope's name followed by a space, `#` and a number.
  # A scope is an identity URI or a stream name and can contain no space,
  # so no scope's name can be mistaken for another's later key.
  @later " #"
  @subject "subject:"

  defp of_scope(:lock, scope),
    do:
      dynamic(
        [l],
        l.scope == ^scope or fragment("starts_with(?, ?)", l.scope, ^(scope <> @later))
      )

  # The keys locked under an owner's key, whichever of the owner's keys.
  defp of_scope(:under, owner) do
    name = @subject <> owner
    dynamic([k], k.under == ^name or fragment("starts_with(?, ?)", k.under, ^(name <> @later)))
  end

  defp of_scope(:key, scope),
    do:
      dynamic(
        [k],
        k.scope == ^scope or fragment("starts_with(?, ?)", k.scope, ^(scope <> @later))
      )

  # The name content recorded under a scope is stored under now: the
  # scope's key that still exists, or the scope itself if it never had
  # one, or the next name if every key it had has been destroyed.
  defp writing_scope(handle, scope) do
    keys = scope_keys(handle, scope)

    case keys |> Enum.filter(fn {_name, wrapped} -> not is_nil(wrapped) end) |> List.last() do
      {name, _wrapped} -> name
      nil when keys == [] -> scope
      nil -> next_scope(scope, keys)
    end
  end

  # A scope's keys, oldest first.
  defp scope_keys(handle, scope) do
    repo(handle).all(
      from(k in "evidence_content_keys",
        where: ^of_scope(:key, scope),
        select: {k.scope, k.wrapped}
      )
    )
    |> Enum.sort_by(fn {name, _wrapped} ->
      case String.split(name, @later) do
        [_bare] -> 0
        parts -> parts |> List.last() |> String.to_integer()
      end
    end)
  end

  defp next_scope(scope, keys), do: scope <> @later <> Integer.to_string(length(keys))

  # The key to write a scope's content under. If the key service will no
  # longer open the scope's present key (the customer retired the version
  # that locked it), the scope moves on to a new key and goes on
  # recording. What was written under the old one stays as it is:
  # unreadable, and not said to have been disposed of, because nothing on
  # the record disposed of it.
  defp writing_key(handle, scope, subject) do
    under = writing_scope(handle, scope)

    case scope_key(handle, under, subject) do
      {:ok, key} ->
        {:ok, under, key}

      {:error, :not_unwrappable} ->
        moved = next_scope(scope, scope_keys(handle, scope))
        with {:ok, key} <- scope_key(handle, moved, subject), do: {:ok, moved, key}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def put_content(handle, ref, content, {scope, subject}) when is_binary(scope),
    do: keep_content(handle, ref, content, scope, subject_named(handle, subject))

  def put_content(handle, ref, content, scope), do: keep_content(handle, ref, content, scope, nil)

  # Whose key a new session key is locked by. Only a deployment that says
  # what its subjects look like has any: a session whose owner does not
  # fit (a service, an operator) is locked by the key service as before.
  # A name with a space could be taken for another scope's later key.
  # An owner's key is kept under a name no session, stream or hold can
  # have, so an owner is never mistaken for one of those, and an owner's
  # key is always locked by the key service, never by another owner's.
  defp subject_named(%{subjects: %Regex{} = pattern}, subject) when is_binary(subject) do
    if Regex.match?(pattern, subject) and not String.contains?(subject, " "),
      do: @subject <> subject
  end

  defp subject_named(_handle, _subject), do: nil

  defp keep_content(%{keys: {_module, _state}} = handle, ref, content, scope, subject)
       when is_binary(scope) do
    copies =
      repo(handle).all(from(b in "evidence_blobs", where: b.ref == ^ref, select: b.copy))

    with {:ok, under, scope_key} <- writing_key(handle, scope, subject) do
      cond do
        # Held unencrypted already (structure, or from before encryption).
        "" in copies and content != :own ->
          :ok

        # Held for this scope already. A hold on the scope may not have
        # reached it, if it could not be applied when it was placed.
        locked?(handle, ref, under) ->
          hold_arriving(handle, ref, scope)

        # Asked only whether this scope holds it. Another scope's copy is
        # not shared on the strength of knowing its reference.
        content == :own ->
          {:error, :not_held}

        true ->
          with :ok <- share_or_hold(handle, ref, content, under, scope_key),
               do: hold_arriving(handle, ref, scope)
      end
    end
  rescue
    error -> {:error, error}
  end

  # With no key service nothing says which scope content belongs to, so
  # a scope cannot be shown to hold it already.
  defp keep_content(_handle, _ref, :own, _scope, _subject), do: {:error, :not_held}

  # Structure, or a store with no key service: held as it is.
  defp keep_content(handle, ref, :held, _scope, _subject),
    do: if(match?({:ok, _}, get_blob(handle, ref)), do: :ok, else: {:error, :not_held})

  # Content that waited encrypted on the gateway's disk is only ever read
  # back to be encrypted again; a store with no key service would have to
  # keep it in the clear, which is the one thing it waited encrypted for.
  # Structure (a seal's manifest: references, never content) has no scope
  # and is kept as it is, as it always was; it is small and read whole.
  defp keep_content(%{keys: {_module, _state}} = handle, ref, {:reader, _path, open}, nil, _) do
    with {:ok, bytes} <- read_whole(open) do
      if Ref.bytes(bytes) == ref,
        do: put_blob(handle, ref, bytes),
        else: {:error, {:staged_content_unreadable, :does_not_match_ref}}
    end
  end

  defp keep_content(_handle, _ref, {:reader, _path, _open}, _scope, _subject),
    do: {:error, :reader_requires_key_service}

  defp keep_content(handle, ref, content, _scope, _subject), do: put_blob(handle, ref, content)

  @hold_scope "urn:r5e:hold:"

  @doc """
  Dispose of a scope's content, by destroying its key, under a disposal
  record that has already been recorded.

  This is the only way a scope's content key is destroyed, and it is
  refused unless every record made under the scope allows it: each
  record's own profile must say content may be disposed of, and the
  period it says content is kept for must have run by the time the
  disposal states. A scope whose records were made under different
  profiles is held to the strictest of them. A profile that says nothing
  about retention means never.

  Content under a hold is not lost: the hold has its own lock on it,
  which this does not touch.

  `disposal` is `%{ref: <the PayloadDisposition's reference>, at:
  <its capturedAt>}`. Returns `:already` when the key was destroyed
  before and `:none` when the scope never had one.
  """
  @spec dispose_content(term(), String.t(), %{ref: String.t(), at: DateTime.t()}) ::
          :ok
          | :already
          | :none
          | {:error, {:never_disposed_of | :kept_until | :profile_not_held, String.t()} | term()}
  def dispose_content(handle, scope, %{ref: ref, at: %DateTime{} = at})
      when is_binary(scope) and is_binary(ref) do
    if String.starts_with?(scope, @hold_scope) do
      {:error, :a_hold_is_released_not_disposed_of}
    else
      # Judged and destroyed in one transaction that holds the owner's
      # key rows. A session's first key takes a shared lock on the same
      # rows, so no session can appear under the owner between being
      # judged and being destroyed.
      {:ok, outcome} =
        repo(handle).transaction(fn ->
          repo(handle).all(
            from(k in "evidence_content_keys",
              where: ^of_scope(:key, @subject <> scope),
              lock: "FOR UPDATE",
              select: k.scope
            )
          )

          with :ok <- all_allow(handle, scope, at), do: destroy_key(handle, scope, ref, at)
        end)

      outcome
    end
  rescue
    error -> {:error, error}
  end

  @doc """
  Which of these scopes a disposal dated `at` would make something
  unreadable for: a scope with a key of its own that has not been
  destroyed, or an owner with such a session made by then. An owner's
  own key locks no content, so it alone does not count.
  """
  @spec live_scopes(term(), [String.t()], DateTime.t() | nil) :: [String.t()]
  def live_scopes(handle, scopes, at \\ nil) do
    Enum.filter(scopes, fn scope ->
      repo(handle).exists?(from(k in disposable(scope, at), where: not is_nil(k.wrapped)))
    end)
  rescue
    _ -> []
  end

  # The key rows a disposal of `scope` dated `at` destroys: the scope's
  # own, and those of the owner's sessions that existed by then. A
  # session that began later was not judged by that disposal and is left.
  defp disposable(scope, at) do
    own = of_scope(:key, scope)
    under = of_scope(:under, scope)

    under =
      if at, do: dynamic([k], ^under and k.created_at <= ^at), else: under

    from(k in "evidence_content_keys", where: ^dynamic(^own or ^under))
  end

  @doc """
  The recorded names of the sessions, under `prefix`, whose name ends
  with a sixteen-character owner fingerprint, a dot and `id`. More than
  one when different people used the same id.
  """
  @spec sessions_named(term(), String.t(), String.t()) :: [String.t()]
  def sessions_named(handle, prefix, id) when is_binary(prefix) and is_binary(id) do
    tail = "." <> id
    whole = String.length(prefix) + 16 + String.length(tail)

    repo(handle).all(
      from(r in "evidence_records",
        where: fragment("starts_with(?, ?)", r.session, ^prefix),
        where: fragment("right(?, ?) = ?", r.session, ^String.length(tail), ^tail),
        where: fragment("char_length(?) = ?", r.session, ^whole),
        distinct: true,
        order_by: r.session,
        select: r.session
      )
    )
  rescue
    _ -> []
  end

  @doc """
  Note that an authority record stands behind a signing key: its badge,
  or a revocation of that badge. Exports of the key's records carry them.
  """
  @spec note_authority(term(), String.t(), [String.t()]) :: :ok
  def note_authority(handle, issuer, refs) when is_binary(issuer) do
    repo(handle).insert_all(
      "evidence_issuer_authority",
      for(ref <- refs, do: %{issuer: issuer, ref: ref}),
      on_conflict: :nothing
    )

    :ok
  end

  @doc "The references noted for each of these signing keys, oldest first."
  @spec authority_of(term(), [String.t()]) :: [{String.t(), String.t()}]
  def authority_of(_handle, []), do: []

  def authority_of(handle, issuers) do
    repo(handle).all(
      from(a in "evidence_issuer_authority",
        where: a.issuer in ^issuers,
        order_by: [a.noted_at, a.ref],
        select: {a.issuer, a.ref}
      )
    )
  end

  @doc "The signing keys a reference has been noted for."
  @spec issuers_noting(term(), String.t()) :: [String.t()]
  def issuers_noting(handle, ref) when is_binary(ref) do
    repo(handle).all(
      from(a in "evidence_issuer_authority",
        where: a.ref == ^ref,
        distinct: true,
        select: a.issuer
      )
    )
  end

  @doc "The subject keys of any stored `Badge` whose `streamPrefixes` include `prefix`."
  @spec badge_subjects_for_prefix(term(), String.t()) :: [String.t()]
  def badge_subjects_for_prefix(handle, prefix) when is_binary(prefix) do
    from(r in "evidence_records",
      where: r.kind_path == "provenance.r5e.io/v2/Badge",
      select: ^fields()
    )
    |> repo(handle).all()
    |> Enum.flat_map(fn row ->
      case entry(row) do
        {:ok, %{evidence: %{"body" => %{"subject" => subject, "streamPrefixes" => prefixes}}}}
        when is_binary(subject) and is_list(prefixes) ->
          if prefix in prefixes, do: [subject], else: []

        _ ->
          []
      end
    end)
    |> Enum.uniq()
  end

  @doc """
  Every `Revocation` held whose target is one of `refs`. Revocations are
  few (each takes back one grant or badge), so they are read and matched
  here rather than indexed by target.
  """
  @spec revocations_of(term(), [String.t()]) :: [map()]
  def revocations_of(_handle, []), do: []

  def revocations_of(handle, refs) do
    targets = MapSet.new(refs)

    from(r in "evidence_records",
      where: r.kind_path == "provenance.r5e.io/v2/Revocation",
      select: ^fields()
    )
    |> repo(handle).all()
    |> Enum.flat_map(fn row ->
      case entry(row) do
        {:ok, %{evidence: %{"body" => %{"target" => target}}} = e} ->
          if MapSet.member?(targets, target), do: [e], else: []

        _ ->
          []
      end
    end)
  end

  @doc """
  Whether this content, as this scope held it, was disposed of: the key
  that locked the scope's own lock on it was destroyed on the record.
  Content the scope never held, or holds under a later key, was not.
  """
  @spec content_disposed?(term(), String.t(), String.t()) :: boolean()
  def content_disposed?(handle, ref, scope) when is_binary(ref) and is_binary(scope) do
    repo(handle).exists?(
      from(l in "evidence_content_locks",
        join: k in "evidence_content_keys",
        on: k.scope == l.scope,
        where: l.ref == ^ref,
        where: ^of_scope(:lock, scope),
        where: not is_nil(k.destroyed_reason)
      )
    )
  rescue
    _ -> false
  end

  @doc """
  Whether one of a scope's keys was destroyed under this disposal record.
  """
  @spec disposed_by?(term(), String.t(), String.t()) :: boolean()
  def disposed_by?(handle, scope, ref) do
    repo(handle).exists?(
      from(k in "evidence_content_keys",
        where: ^of_scope(:key, scope),
        where: k.destroyed_reason == ^ref
      )
    )
  rescue
    _ -> false
  end

  @doc """
  Whether a scope's content could be disposed of at `at`, by the rule
  `dispose_content/3` applies. Whoever records a disposal asks this
  first, so that no disposal is ever recorded that then cannot be
  carried out.
  """
  @spec disposal_allowed(term(), String.t(), DateTime.t()) ::
          :ok
          | {:error, {:never_disposed_of | :kept_until | :profile_not_held, String.t()} | term()}
  def disposal_allowed(handle, scope, %DateTime{} = at) when is_binary(scope) do
    if String.starts_with?(scope, @hold_scope),
      do: {:error, :a_hold_is_released_not_disposed_of},
      else: all_allow(handle, scope, at)
  rescue
    error -> {:error, error}
  end

  @doc """
  The sessions whose keys are locked under this owner's key. Disposing
  of the owner disposes of them, so whoever judges a disposal judges
  each of them as well. It raises when the store cannot be asked: an
  answer of "none" must never be a failure to look.
  """
  @spec scopes_under(term(), String.t()) :: [String.t()]
  def scopes_under(handle, scope) when is_binary(scope) do
    repo(handle).all(
      from(k in "evidence_content_keys", where: ^of_scope(:under, scope), select: k.scope)
    )
    |> bare()
  end

  @doc """
  The owners whose keys lock this session's key. A hold on an owner
  stands in the way of disposing of one of their sessions. Raises as
  `scopes_under/2` does.
  """
  @spec owners_of(term(), String.t()) :: [String.t()]
  def owners_of(handle, scope) when is_binary(scope) do
    repo(handle).all(
      from(k in "evidence_content_keys",
        where: ^of_scope(:key, scope),
        where: not is_nil(k.under),
        select: k.under
      )
    )
    |> bare()
    |> Enum.map(&String.replace_prefix(&1, @subject, ""))
  end

  defp bare(names), do: names |> Enum.map(&(&1 |> String.split(@later) |> hd())) |> Enum.uniq()

  # The scope, and every session of the owner's that existed by `at`,
  # must allow the disposal. And every session recorded for the owner
  # must be one the disposal reaches: a session keyed on its own (before
  # the deployment named its subjects, or because its first content came
  # with no owner) would stay readable behind a record saying otherwise.
  defp all_allow(handle, scope, at) do
    children =
      repo(handle).all(
        from(k in "evidence_content_keys",
          where: ^of_scope(:under, scope),
          where: k.created_at <= ^at,
          select: k.scope
        )
      )
      |> bare()

    with :ok <- none_astray(handle, scope) do
      Enum.reduce_while([scope | children], :ok, fn each, :ok ->
        case records_allow(handle, each, at) do
          :ok -> {:cont, :ok}
          refused -> {:halt, refused}
        end
      end)
    end
  end

  defp none_astray(handle, owner) do
    sessions =
      repo(handle).all(
        from(r in "evidence_records",
          where: r.on_behalf_of == ^owner and not is_nil(r.session),
          distinct: true,
          select: r.session
        )
      )

    astray =
      Enum.find(sessions, fn session ->
        repo(handle).exists?(
          from(k in "evidence_content_keys",
            where: ^of_scope(:key, session),
            where: not is_nil(k.wrapped),
            where: ^dynamic([k], is_nil(k.under) or not (^of_scope(:under, owner)))
          )
        )
      end)

    if astray, do: {:error, {:session_not_under_owner, astray}}, else: :ok
  end

  # Every record made under the scope, each judged by the profile it cites.
  defp records_allow(handle, scope, at) do
    where =
      case scope do
        "stream:" <> stream -> dynamic([r], r.stream == ^stream and is_nil(r.session))
        session -> dynamic([r], r.session == ^session)
      end

    rows =
      repo(handle).all(
        from(r in "evidence_records", where: ^where, select: {r.ref, r.envelope, r.inserted_at})
      )

    Enum.reduce_while(rows, :ok, fn {ref, envelope, arrived}, :ok ->
      {:ok, %{evidence: evidence}} = Envelope.open(envelope)
      # The time the record itself states, which is what a reader
      # compares, or the time it arrived here if that is later. A record
      # signed elsewhere states its own time, and one dated early would
      # otherwise have its content disposable sooner than it should be.
      # Judging by the later of the two is never looser than a reader.
      {:ok, stated, _} = DateTime.from_iso8601(evidence["capturedAt"])
      captured_at = Enum.max([stated, arrival(arrived) || stated], DateTime)

      # A seal, a checkpoint and the retention records themselves have no
      # content of their own under any scope, so their profiles have no say.
      rule =
        if Recurse.Provenance.Evidence.content_scope(evidence),
          do: retention(handle, evidence["profileRef"]),
          else: {:keep_for, 0}

      case rule do
        {:keep_for, seconds} ->
          if DateTime.compare(DateTime.add(captured_at, seconds, :second), at) == :gt,
            do: {:halt, {:error, {:kept_until, ref}}},
            else: {:cont, :ok}

        :never ->
          {:halt, {:error, {:never_disposed_of, ref}}}

        :unknown ->
          {:halt, {:error, {:profile_not_held, ref}}}
      end
    end)
  end

  defp arrival(%NaiveDateTime{} = at), do: DateTime.from_naive!(at, "Etc/UTC")
  defp arrival(%DateTime{} = at), do: at
  defp arrival(_none), do: nil

  defp retention(handle, profile_ref) do
    with {:ok, bytes} <- get_blob(handle, profile_ref),
         {:ok, %{} = profile} <- Jason.decode(bytes) do
      case profile["retention"] do
        %{"disposal" => "by-record", "keepContentForSeconds" => seconds} -> {:keep_for, seconds}
        _never_or_unsaid -> :never
      end
    else
      _ -> :unknown
    end
  end

  # A scope's key goes together with every key locked under it. Those
  # could be opened by nothing once it is gone; marking them destroyed
  # in the same statement keeps "is this content gone" a question about
  # one row.
  defp destroy_key(handle, scope, reason, at \\ nil) do
    gone = [wrapped: nil, destroyed_at: DateTime.utc_now(), destroyed_reason: reason]
    of_scope = disposable(scope, at)
    live = from(k in of_scope, where: not is_nil(k.wrapped))
    {destroyed, _} = repo(handle).update_all(live, set: gone)

    # The owner's own key goes once no session is left under it. While a
    # later session is, it stays: that session's content is not this
    # disposal's to take.
    owner = from(k in "evidence_content_keys", where: ^of_scope(:key, @subject <> scope))
    under = from(k in "evidence_content_keys", where: ^of_scope(:under, scope))

    unless repo(handle).exists?(from(k in under, where: not is_nil(k.wrapped))) do
      repo(handle).update_all(from(k in owner, where: not is_nil(k.wrapped)), set: gone)
    end

    cond do
      destroyed > 0 -> :ok
      repo(handle).exists?(of_scope) -> :already
      true -> :none
    end
  end

  @doc """
  Place a hold on content: give each piece one more lock, under the hold.

  `what` is `{:scope, scope}` for everything recorded under a scope, now
  and from now on, or `{:content, refs}` for named pieces of content.
  Held content stays readable, to someone reading under the hold, when
  the scope it was recorded under is disposed of.

  Content that can no longer be opened cannot be held; its references
  are returned as `:lost` so that the caller can say so on the record.
  """
  @spec hold_content(term(), String.t(), {:scope, String.t()} | {:content, [String.t()]}) ::
          {:ok, %{held: non_neg_integer(), lost: [String.t()]}} | {:error, term()}
  def hold_content(%{keys: _} = handle, hold_ref, what) when is_binary(hold_ref) do
    hold_scope = @hold_scope <> hold_ref

    refs =
      case what do
        {:scope, scope} ->
          repo(handle).insert_all("evidence_scope_holds", [%{scope: scope, hold: hold_ref}],
            on_conflict: :nothing
          )

          repo(handle).all(
            from(l in "evidence_content_locks", where: ^of_scope(:lock, scope), select: l.ref)
          )

        {:content, refs} ->
          refs
      end

    with {:ok, hold_key} <- scope_key(handle, hold_scope) do
      {held, lost} =
        Enum.reduce(Enum.uniq(refs), {0, []}, fn ref, {held, lost} ->
          case lock_under(handle, ref, hold_scope, hold_key) do
            :ok -> {held + 1, lost}
            :lost -> {held, [ref | lost]}
            # Not lost: it could not be asked. The hold is not applied in
            # part and reported as whole; the caller is told and asks again.
            {:error, reason} -> throw({:not_applied, reason})
          end
        end)

      {:ok, %{held: held, lost: Enum.reverse(lost)}}
    end
  rescue
    error -> {:error, error}
  catch
    {:not_applied, reason} -> {:error, reason}
  end

  def hold_content(_no_key_service, _hold_ref, _what), do: {:error, :no_key_service}

  @doc """
  Release a hold: its lock on everything it held is destroyed, and
  content recorded from now on is no longer given one. Content whose own
  scope has already been disposed of is gone with this.
  """
  @spec release_hold(term(), String.t(), String.t()) :: :ok | :already | :none | {:error, term()}
  def release_hold(handle, hold_ref, release_ref) when is_binary(hold_ref) do
    repo(handle).update_all(
      from(h in "evidence_scope_holds", where: h.hold == ^hold_ref and is_nil(h.released_at)),
      set: [released_at: DateTime.utc_now()]
    )

    destroy_key(handle, @hold_scope <> hold_ref, release_ref)
  rescue
    error -> {:error, error}
  end

  # One more lock on a piece of content, under `scope`, through any lock
  # that can still open it.
  defp lock_under(handle, ref, scope, scope_key) do
    copies = repo(handle).all(from(l in live_locks(ref), distinct: true, select: l.copy))

    found =
      Enum.reduce_while(copies, :lost, fn copy, outcome ->
        case content_key(handle, ref, copy) do
          {:ok, content_key} -> {:halt, {copy, content_key}}
          {:error, {:key_service_unavailable, _} = reason} -> {:cont, {:error, reason}}
          _ -> {:cont, outcome}
        end
      end)

    case found do
      {copy, content_key} -> lock(handle, ref, copy, scope, scope_key, content_key)
      other -> other
    end
  end

  # Content recorded under a scope that is under a hold is held as it arrives.
  defp hold_arriving(handle, ref, scope) do
    holds =
      repo(handle).all(
        from(h in "evidence_scope_holds",
          where: h.scope == ^scope and is_nil(h.released_at),
          select: h.hold
        )
      )

    # Content is not taken as stored until every hold on its scope has
    # its lock on it. If the key service cannot be asked, the caller is
    # told and stores it again later.
    Enum.reduce_while(holds, :ok, fn hold, :ok ->
      with {:ok, hold_key} <- scope_key(handle, @hold_scope <> hold),
           outcome when outcome in [:ok, :lost] <-
             lock_under(handle, ref, @hold_scope <> hold, hold_key) do
        {:cont, :ok}
      else
        {:error, {:key_service_unavailable, _} = reason} -> {:halt, {:error, reason}}
        # The hold's own key is gone: it was released. Nothing to add.
        _ -> {:cont, :ok}
      end
    end)
  end

  @doc """
  Why content cannot be read: `:held` when it can, `:erased` when every
  copy's key has been destroyed, `:absent` when it was never held.
  """
  @spec content_state(term(), String.t()) :: :held | :erased | :absent
  def content_state(handle, ref) do
    copies = repo(handle).all(from(b in "evidence_blobs", where: b.ref == ^ref, select: b.copy))

    cond do
      copies == [] -> :absent
      "" in copies -> :held
      repo(handle).exists?(live_locks(ref)) -> :held
      true -> :erased
    end
  end

  # -- content -----------------------------------------------------------

  # Put each blob where content lives and return the rows that record it.
  # Content already held under a reference is not put again.
  defp hold_all(handle, blobs) do
    refs = Enum.map(blobs, &elem(&1, 0))

    held =
      MapSet.new(
        repo(handle).all(
          from(b in "evidence_blobs", where: b.ref in ^refs and b.copy == "", select: b.ref)
        )
      )

    blobs
    |> Enum.uniq_by(&elem(&1, 0))
    |> Enum.reject(fn {ref, _} -> MapSet.member?(held, ref) end)
    |> Enum.reduce_while({:ok, []}, fn {ref, content}, {:ok, rows} ->
      case hold(handle, ref, content) do
        {:ok, row} -> {:cont, {:ok, [row | rows]}}
        {:error, reason} -> {:halt, {:error, {:content_not_held, ref, reason}}}
      end
    end)
  end

  defp hold(%{content: {module, state, ctx}}, ref, content) do
    with {:ok, %{uri: uri}} <- put(module, state, ctx, content) do
      {:ok, %{ref: ref, size: size(content), uri: uri, bytes: nil}}
    end
  end

  defp hold(_repo_only, ref, content) do
    bytes = read(content)
    {:ok, %{ref: ref, size: byte_size(bytes), uri: nil, bytes: bytes}}
  end

  defp put(module, state, ctx, {:file, path}) do
    if function_exported?(module, :put_payload_file, 3),
      do: module.put_payload_file(state, path, ctx),
      else: put(module, state, ctx, File.read!(path))
  end

  # Every piece of content is written through the same identity, so it
  # must be stored under a name of its own. A provider that names by the
  # caller says how to name by content instead.
  defp put(module, state, ctx, bytes) when is_binary(bytes) do
    if function_exported?(module, :put_content, 3),
      do: module.put_content(state, bytes, ctx),
      else: module.put_payload(state, bytes, ctx)
  end

  defp stored(_handle, nil, bytes), do: {:ok, bytes}
  defp stored(handle, uri, nil), do: from_storage(handle, uri)

  # The locks on a reference's content whose scope key still exists.
  defp live_locks(ref) do
    from(l in "evidence_content_locks",
      join: k in "evidence_content_keys",
      on: k.scope == l.scope,
      where: l.ref == ^ref and not is_nil(k.wrapped)
    )
  end

  defp locked?(handle, ref, scope) do
    repo(handle).exists?(
      from(l in "evidence_content_locks", where: l.ref == ^ref and l.scope == ^scope)
    )
  end

  # The key a stored copy was encrypted under, through any scope whose
  # own key still exists.
  defp content_key(handle, ref, copy) do
    locks =
      repo(handle).all(
        from(l in live_locks(ref), where: l.copy == ^copy, select: {l.scope, l.locked})
      )

    # A key service that cannot be reached is not a key that is gone.
    # If no lock opens and any failed for that reason, say so, so that a
    # caller never takes an outage for content that was disposed of.
    Enum.reduce_while(locks, {:error, :erased}, fn {scope, locked}, outcome ->
      with {:ok, scope_key} <- existing_scope_key(handle, scope),
           {:ok, content_key} <- ContentCipher.unlock(locked, scope_key, ref) do
        {:halt, {:ok, content_key}}
      else
        {:error, {:key_service_unavailable, _} = reason} -> {:cont, {:error, reason}}
        _ -> {:cont, outcome}
      end
    end)
  end

  # This scope refers to content. If a copy is already stored that some
  # scope can still open, this scope is given its own lock on that copy's
  # key and nothing is stored twice. Otherwise the content is encrypted
  # under a new key and stored.
  defp share_or_hold(handle, ref, content, scope, scope_key) do
    copies =
      repo(handle).all(from(l in live_locks(ref), distinct: true, select: l.copy))

    shared =
      Enum.reduce_while(copies, nil, fn copy, outcome ->
        case content_key(handle, ref, copy) do
          {:ok, content_key} -> {:halt, {copy, content_key}}
          {:error, {:key_service_unavailable, _} = reason} -> {:cont, {:error, reason}}
          _ -> {:cont, outcome}
        end
      end)

    case {shared, content} do
      # Whether a copy is already held could not be asked. Storing another,
      # or saying it is not held, would both be guesses; the caller retries.
      {{:error, reason}, _content} ->
        {:error, reason}

      {{copy, content_key}, _content} ->
        lock(handle, ref, copy, scope, scope_key, content_key)

      {nil, :held} ->
        {:error, :not_held}

      {nil, content} ->
        content_key = :crypto.strong_rand_bytes(32)
        copy = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)

        # The stored copy and the first lock on it appear together, so
        # nobody ever sees a copy that no scope can open.
        with {:ok, row} <- hold_encrypted(handle, ref, content, content_key),
             {:ok, :ok} <-
               repo(handle).transaction(fn ->
                 repo(handle).insert_all("evidence_blobs", [Map.put(row, :copy, copy)])
                 lock(handle, ref, copy, scope, scope_key, content_key)
               end) do
          :ok
        end
    end
  end

  defp lock(handle, ref, copy, scope, scope_key, content_key) do
    repo(handle).insert_all(
      "evidence_content_locks",
      [
        %{
          ref: ref,
          copy: copy,
          scope: scope,
          locked: ContentCipher.lock(content_key, scope_key, ref)
        }
      ],
      on_conflict: :nothing
    )

    :ok
  end

  # The scope's key, made and locked on first use: by the subject's key
  # when the scope is a session that belongs to a subject, and otherwise
  # by the key service. Who locks a key is fixed when the key is made.
  defp scope_key(handle, scope, subject \\ nil) do
    case existing_scope_key(handle, scope) do
      {:ok, key} -> {:ok, key}
      {:error, :destroyed} -> {:error, :content_key_destroyed}
      {:error, :none} -> new_scope_key(handle, scope, subject)
      {:error, reason} -> {:error, reason}
    end
  end

  defp existing_scope_key(%{keys: {module, state}} = handle, scope) do
    query =
      from(k in "evidence_content_keys",
        where: k.scope == ^scope,
        select: {k.wrapped, k.destroyed_at, k.under}
      )

    case repo(handle).one(query) do
      nil -> {:error, :none}
      {nil, _destroyed_at, _under} -> {:error, :destroyed}
      {wrapped, nil, nil} -> module.unwrap(state, wrapped, scope)
      {wrapped, nil, under} -> opened_under(handle, wrapped, scope, under)
    end
  end

  defp existing_scope_key(_no_key_service, _scope), do: {:error, :no_key_service}

  # A key locked by another row's key. When that key is gone, so is this
  # one: nothing else can open it.
  defp opened_under(handle, wrapped, scope, under) do
    with {:ok, subject_key} <- existing_scope_key(handle, under) do
      case ContentCipher.unlock(wrapped, subject_key, scope) do
        {:ok, key} -> {:ok, key}
        {:error, :not_decryptable} -> {:error, :not_unwrappable}
      end
    else
      {:error, :none} -> {:error, :destroyed}
      other -> other
    end
  end

  defp new_scope_key(%{keys: {module, state}} = handle, scope, subject) do
    key = :crypto.strong_rand_bytes(32)

    row = fn wrapped, under ->
      %{scope: scope, wrapped: wrapped, key_service: module.describe(state), under: under}
    end

    with {:ok, wrapped, under} <- locked(handle, key, scope, subject),
         :ok <- insert_key(handle, row.(wrapped, under)) do
      # Another writer may have made this scope's key first; theirs stands.
      existing_scope_key(handle, scope)
    end
  end

  defp insert_key(handle, %{under: nil} = row) do
    repo(handle).insert_all("evidence_content_keys", [row], on_conflict: :nothing)
    :ok
  end

  # A key under an owner's is added only while the owner's key exists,
  # and holds that row against a disposal until it is in: a disposal of
  # the owner either sees this session and judges it, or has finished,
  # and then the session is not put under a key that is gone.
  defp insert_key(handle, %{under: under} = row) do
    {:ok, outcome} =
      repo(handle).transaction(fn ->
        parent =
          from(k in "evidence_content_keys",
            where: k.scope == ^under and not is_nil(k.wrapped),
            lock: "FOR SHARE",
            select: true
          )

        if repo(handle).one(parent) do
          repo(handle).insert_all("evidence_content_keys", [row], on_conflict: :nothing)
          :ok
        else
          {:error, :owner_key_destroyed}
        end
      end)

    outcome
  end

  defp locked(%{keys: {module, state}}, key, scope, nil) do
    with {:ok, wrapped} <- module.wrap(state, key, scope), do: {:ok, wrapped, nil}
  end

  # The subject's own key is locked by the key service, and is replaced
  # like any scope's when it has been destroyed or can no longer be opened.
  defp locked(handle, key, scope, subject) do
    with {:ok, under, subject_key} <- writing_key(handle, subject, nil),
         do: {:ok, ContentCipher.lock(key, subject_key, scope), under}
  end

  defp hold_encrypted(handle, ref, {:file, path}, content_key) do
    sealed = path <> ".sealed-" <> Integer.to_string(System.unique_integer([:positive]))

    try do
      with :ok <- ContentCipher.encrypt_file(path, sealed, content_key, ref),
           {:ok, row} <- hold(handle, ref, {:file, sealed}) do
        {:ok, %{row | size: File.stat!(path).size}}
      end
    after
      File.rm(sealed)
    end
  end

  # Read from the waiting file a piece at a time, decrypted only in
  # memory, and encrypted under the content key into a file beside it.
  # The reader checks the content against its reference before it says
  # it has ended, and nothing is stored until it has: content that fails
  # that check is never held under the reference.
  defp hold_encrypted(handle, ref, {:reader, path, open}, content_key) do
    sealed = path <> ".sealed-" <> Integer.to_string(System.unique_integer([:positive]))

    try do
      with {:ok, size} <- ContentCipher.encrypt_reader(open, sealed, content_key, ref),
           {:ok, row} <- hold(handle, ref, {:file, sealed}) do
        {:ok, %{row | size: size}}
      end
    after
      File.rm(sealed)
    end
  end

  defp hold_encrypted(handle, ref, plain, content_key) when is_binary(plain) do
    with {:ok, row} <- hold(handle, ref, ContentCipher.encrypt(plain, content_key, ref)) do
      {:ok, %{row | size: byte_size(plain)}}
    end
  end

  defp from_storage(%{content: {module, state, ctx}}, uri) do
    case module.get_payload(state, uri, ctx) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, _reason} -> :error
    end
  end

  defp from_storage(_repo_only, _uri), do: :error

  defp size({:file, path}), do: File.stat!(path).size
  defp size(bytes) when is_binary(bytes), do: byte_size(bytes)

  defp read({:file, path}), do: File.read!(path)
  defp read(bytes) when is_binary(bytes), do: bytes

  defp read_whole(open) do
    with {:ok, source, read, close} <- open.() do
      try do
        read_whole(read, source, [])
      after
        close.()
      end
    end
  end

  defp read_whole(read, source, acc) do
    case read.(source) do
      {:ok, piece, source} -> read_whole(read, source, [acc, piece])
      :eof -> {:ok, IO.iodata_to_binary(acc)}
      {:error, _} = error -> error
    end
  end

  defp repo(%{repo: repo}), do: repo
  defp repo(repo) when is_atom(repo), do: repo

  defp fields,
    do: [:ref, :stream, :seq, :kind_path, :envelope, :submission_id, :submission_digest]

  defp entry(nil), do: :error

  # The envelope is the record; the evidence map is read back out of it
  # rather than stored a second time.
  defp entry(row) do
    {:ok, %{evidence: evidence}} = Envelope.open(row.envelope)
    {:ok, Map.put(row, :evidence, evidence)}
  end
end
