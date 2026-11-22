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
            {1, _} -> label(repo, [entry])
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

    label(repo(handle), entries)
  rescue
    error -> {:error, error}
  end

  # What each record can be searched and counted by, kept beside the
  # records. Derived from them, so a replayed batch changes nothing.
  defp label(repo, entries) do
    for %{evidence: evidence} = entry <- entries,
        {:ok, captured_at, 0} <- [DateTime.from_iso8601(evidence["capturedAt"])],
        {name, value} <- Recurse.Provenance.Evidence.labels(evidence) do
      %{ref: entry.ref, name: name, value: value, stream: entry.stream, captured_at: captured_at}
    end
    |> Enum.chunk_every(1_000)
    |> Enum.each(&repo.insert_all("evidence_record_labels", &1, on_conflict: :nothing))

    :ok
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
  def list(handle, %{stream_prefix: _, limit: limit} = asked) do
    rows =
      from(r in matching(asked),
        order_by: [desc: r.captured_at, desc: r.ref],
        limit: ^limit,
        select: ^fields()
      )
      |> repo(handle).all()

    {:ok, Enum.map(rows, &elem(entry(&1), 1))}
  rescue
    error -> {:error, error}
  end

  @doc """
  How many records match, and how they divide by kind, by how policy
  decided, and by what was called (the twenty most frequent). `asked`
  narrows as it does for `list/2`; its limit and position are ignored.
  The counts are of every matching record, not of a page of them.

  Each division is counted without the reader's own choice within it:
  having chosen "deny", a reader still sees how many were allowed, and
  can compare or switch. The total is of what every choice together
  leaves.
  """
  @spec facets(term(), map()) ::
          {:ok,
           %{total: non_neg_integer(), facets: %{String.t() => [{String.t(), pos_integer()}]}}}
          | {:error, term()}
  def facets(handle, %{stream_prefix: _} = asked) do
    asked = Map.drop(asked, [:before, :limit])
    found = matching(asked)
    repo = repo(handle)

    kinds =
      repo.all(
        from(r in matching(Map.delete(asked, :kind_path)),
          group_by: r.kind_path,
          order_by: [desc: count(r.ref), asc: r.kind_path],
          select: {r.kind_path, count(r.ref)}
        )
      )

    labelled = fn name, own, limit ->
      repo.all(
        from(r in matching(Map.delete(asked, own)),
          join: l in "evidence_record_labels",
          on: l.ref == r.ref and l.name == ^name,
          group_by: l.value,
          order_by: [desc: count(r.ref), asc: l.value],
          limit: ^limit,
          select: {l.value, count(r.ref)}
        )
      )
    end

    {:ok,
     %{
       total: repo.aggregate(found, :count),
       facets: %{
         "kind" => kinds,
         "policyOutcome" => labelled.("policyOutcome", :policy_outcome, 50),
         "target" => labelled.("target", :target, 20)
       }
     }}
  rescue
    error -> {:error, error}
  end

  @doc """
  Matching records counted over time: `buckets` equal spans from `since`
  to `until`, each with its count and how those divide by how policy
  decided. Spans with nothing in them are given, with a count of zero.
  """
  @spec histogram(term(), map(), pos_integer()) ::
          {:ok, %{bucket_seconds: number(), buckets: [map()]}} | {:error, term()}
  def histogram(
        handle,
        %{since: %DateTime{} = since, until: %DateTime{} = until} = asked,
        buckets
      )
      when is_integer(buckets) and buckets > 0 do
    width = max(DateTime.diff(until, since, :microsecond) / buckets / 1_000_000, 0.000001)
    found = matching(Map.drop(asked, [:before, :limit]))

    counted =
      repo(handle).all(
        from(r in found,
          left_join: l in "evidence_record_labels",
          on: l.ref == r.ref and l.name == "policyOutcome",
          group_by: [1, l.value],
          select: {
            fragment(
              "floor(extract(epoch from (? - ?)) / ?)::bigint",
              r.captured_at,
              type(^since, :utc_datetime_usec),
              ^width
            ),
            l.value,
            count(r.ref)
          }
        )
      )

    by_bucket = Enum.group_by(counted, &elem(&1, 0), fn {_, outcome, n} -> {outcome, n} end)

    spans =
      for index <- 0..(buckets - 1) do
        within = Map.get(by_bucket, index, [])

        %{
          start: DateTime.add(since, round(index * width * 1_000_000), :microsecond),
          count: within |> Enum.map(&elem(&1, 1)) |> Enum.sum(),
          by_outcome: for({outcome, n} <- within, is_binary(outcome), into: %{}, do: {outcome, n})
        }
      end

    {:ok, %{bucket_seconds: width, buckets: spans}}
  rescue
    error -> {:error, error}
  end

  # The records of a deployment's streams that `asked` narrows to.
  defp matching(%{stream_prefix: prefix} = asked) do
    from(r in "evidence_records",
      as: :record,
      where: fragment("starts_with(?, ?)", r.stream, ^prefix)
    )
    |> narrowed(asked)
  end

  defp labelled(query, name, value) do
    where(
      query,
      [],
      exists(
        from(l in "evidence_record_labels",
          where: l.ref == parent_as(:record).ref and l.name == ^name and l.value == ^value,
          select: 1
        )
      )
    )
  end

  defp narrowed(query, asked) do
    Enum.reduce(asked, query, fn
      {:kind_path, kind}, query ->
        where(query, [r], r.kind_path == ^kind)

      {:session, session}, query ->
        where(query, [r], r.session == ^session)

      {:actor, actor}, query ->
        where(query, [r], r.actor == ^actor)

      {:policy_outcome, outcome}, query ->
        labelled(query, "policyOutcome", outcome)

      {:target, target}, query ->
        labelled(query, "target", target)

      # Anywhere in who acted, the session, the kind or what was called.
      # The reader's text is matched as it is, never as a pattern.
      {:q, text}, query ->
        like = "%" <> String.replace(text, ["\\", "%", "_"], &("\\" <> &1)) <> "%"

        where(
          query,
          [r],
          ilike(r.actor, ^like) or ilike(r.session, ^like) or ilike(r.kind_path, ^like) or
            exists(
              from(l in "evidence_record_labels",
                where:
                  l.ref == parent_as(:record).ref and l.name == "target" and ilike(l.value, ^like),
                select: 1
              )
            )
        )

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

  defp of_scope(:lock, scope),
    do:
      dynamic(
        [l],
        l.scope == ^scope or fragment("starts_with(?, ?)", l.scope, ^(scope <> @later))
      )

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
  defp writing_key(handle, scope) do
    under = writing_scope(handle, scope)

    case scope_key(handle, under) do
      {:ok, key} ->
        {:ok, under, key}

      {:error, :not_unwrappable} ->
        moved = next_scope(scope, scope_keys(handle, scope))
        with {:ok, key} <- scope_key(handle, moved), do: {:ok, moved, key}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def put_content(handle, ref, content, scope)

  def put_content(%{keys: {_module, _state}} = handle, ref, content, scope)
      when is_binary(scope) do
    copies =
      repo(handle).all(from(b in "evidence_blobs", where: b.ref == ^ref, select: b.copy))

    with {:ok, under, scope_key} <- writing_key(handle, scope) do
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
  def put_content(_handle, _ref, :own, _scope), do: {:error, :not_held}

  # Structure, or a store with no key service: held as it is.
  def put_content(handle, ref, :held, _scope),
    do: if(match?({:ok, _}, get_blob(handle, ref)), do: :ok, else: {:error, :not_held})

  # Content that waited encrypted on the gateway's disk is only ever read
  # back to be encrypted again; a store with no key service would have to
  # keep it in the clear, which is the one thing it waited encrypted for.
  # Structure (a seal's manifest: references, never content) has no scope
  # and is kept as it is, as it always was; it is small and read whole.
  def put_content(%{keys: {_module, _state}} = handle, ref, {:reader, _path, open}, nil) do
    with {:ok, bytes} <- read_whole(open) do
      if Ref.bytes(bytes) == ref,
        do: put_blob(handle, ref, bytes),
        else: {:error, {:staged_content_unreadable, :does_not_match_ref}}
    end
  end

  def put_content(_handle, _ref, {:reader, _path, _open}, _scope),
    do: {:error, :reader_requires_key_service}

  def put_content(handle, ref, content, _scope), do: put_blob(handle, ref, content)

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
    cond do
      String.starts_with?(scope, @hold_scope) -> {:error, :a_hold_is_released_not_disposed_of}
      true -> with :ok <- all_allow(handle, scope, at), do: destroy_key(handle, scope, ref)
    end
  rescue
    error -> {:error, error}
  end

  @doc """
  Which of these scopes still have a key that has not been destroyed.
  """
  @spec live_scopes(term(), [String.t()]) :: [String.t()]
  def live_scopes(handle, scopes) do
    Enum.filter(scopes, fn scope ->
      repo(handle).exists?(
        from(k in "evidence_content_keys",
          where: ^of_scope(:key, scope),
          where: not is_nil(k.wrapped)
        )
      )
    end)
  rescue
    _ -> []
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
  The recorded names of every session whose name begins with `prefix`:
  with a tenant and an owner's fingerprint, every session of that
  owner's. It raises when the store cannot be asked, because whoever
  disposes of a person's sessions must never take a failure to look for
  "there are none".
  """
  @spec sessions_owned(term(), String.t()) :: [String.t()]
  def sessions_owned(handle, prefix) when is_binary(prefix) do
    repo(handle).all(
      from(r in "evidence_records",
        where: fragment("starts_with(?, ?)", r.session, ^prefix),
        distinct: true,
        order_by: r.session,
        select: r.session
      )
    )
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

  # Every record made under the scope, each judged by the profile it cites.
  defp all_allow(handle, scope, at) do
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

  defp destroy_key(handle, scope, reason) do
    of_scope = from(k in "evidence_content_keys", where: ^of_scope(:key, scope))
    live = from(k in of_scope, where: not is_nil(k.wrapped))

    case repo(handle).update_all(live,
           set: [wrapped: nil, destroyed_at: DateTime.utc_now(), destroyed_reason: reason]
         ) do
      {0, _} -> if repo(handle).exists?(of_scope), do: :already, else: :none
      {_some, _} -> :ok
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

  # The scope's key, made and locked by the key service on first use.
  defp scope_key(handle, scope) do
    case existing_scope_key(handle, scope) do
      {:ok, key} -> {:ok, key}
      {:error, :destroyed} -> {:error, :content_key_destroyed}
      {:error, :none} -> new_scope_key(handle, scope)
      {:error, reason} -> {:error, reason}
    end
  end

  defp existing_scope_key(%{keys: {module, state}} = handle, scope) do
    query =
      from(k in "evidence_content_keys",
        where: k.scope == ^scope,
        select: {k.wrapped, k.destroyed_at}
      )

    case repo(handle).one(query) do
      nil -> {:error, :none}
      {nil, _destroyed_at} -> {:error, :destroyed}
      {wrapped, nil} -> module.unwrap(state, wrapped, scope)
    end
  end

  defp existing_scope_key(_no_key_service, _scope), do: {:error, :no_key_service}

  defp new_scope_key(%{keys: {module, state}} = handle, scope) do
    key = :crypto.strong_rand_bytes(32)

    with {:ok, wrapped} <- module.wrap(state, key, scope) do
      repo(handle).insert_all(
        "evidence_content_keys",
        [%{scope: scope, wrapped: wrapped, key_service: module.describe(state)}],
        on_conflict: :nothing
      )

      # Another writer may have made this scope's key first; theirs stands.
      existing_scope_key(handle, scope)
    end
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
