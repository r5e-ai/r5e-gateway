defmodule Recurse.Provenance.Store do
  @moduledoc """
  Durable storage behind a recorder (contract §5).

  The recorder process owns a stream's live head; the store is where a
  record must land before a receipt may say `durable`. `append/2` is the
  durability boundary: when it returns `:ok`, the signed envelope and
  every blob passed with it are retained together.

  Each stream position holds one immutable payload. Writing different
  bytes to an occupied position is `{:error, :conflict}`, never an
  overwrite; writing the same record again is `:ok`.
  """

  alias Recurse.Provenance.Ref

  @type handle :: term()
  @type entry :: %{
          required(:ref) => Ref.t(),
          required(:stream) => String.t(),
          required(:seq) => pos_integer(),
          required(:kind_path) => String.t(),
          required(:envelope) => map(),
          required(:evidence) => map(),
          optional(:submission_id) => String.t() | nil,
          optional(:submission_digest) => String.t() | nil,
          optional(:blobs) => [{Ref.t(), content()}]
        }

  @typedoc """
  Content to retain: the bytes themselves, a file that holds them, or a
  reader over a file that holds them in some other form (encrypted
  while it waited on disk). A file or a reader lets a large body go from
  the wire to storage without ever being held whole in memory.

  A reader is `{:reader, path, open}`: `open.()` answers
  `{:ok, source, read, close}`, where `read.(source)` answers
  `{:ok, piece, source}`, `:eof` or `{:error, reason}`, and `close.()`
  releases it. `path` is the waiting file, beside which a store may put
  files of its own. A reader answers `:eof` only once everything it gave
  is known to be the content the reference names; a store keeps nothing
  from a reader that ended in an error.
  """
  @type content ::
          binary()
          | {:file, Path.t()}
          | {:reader, Path.t(), (-> {:ok, term(), reader(), (-> any())} | {:error, term()})}

  @typedoc "One step of a content reader: see `t:content/0`."
  @type reader :: (term() -> {:ok, binary(), term()} | :eof | {:error, term()})

  @doc "The last position of a stream and its record reference, or nil when empty."
  @callback head(handle(), stream :: String.t()) ::
              {:ok, {pos_integer(), Ref.t()} | nil} | {:error, term()}

  @doc "Retain one signed record and its blobs, atomically."
  @callback append(handle(), entry()) :: :ok | {:error, :conflict | term()}

  @doc """
  Retain a batch of signed records in one step. Records already present
  are left as they are, so replaying a batch is harmless.
  """
  @callback append_many(handle(), [entry()]) :: :ok | {:error, term()}

  @doc "A retained record by reference."
  @callback fetch(handle(), Ref.t()) :: {:ok, entry()} | :error

  @doc "The record a submission handle produced on a stream, if any."
  @callback by_submission(handle(), stream :: String.t(), submission_id :: String.t()) ::
              {:ok, entry()} | :error

  @doc "Records of a stream at positions `first..last`, in order."
  @callback range(handle(), stream :: String.t(), first :: pos_integer(), last :: pos_integer()) ::
              {:ok, [entry()]} | {:error, term()}

  @doc "The latest seal covering a stream: its reference and last covered position."
  @callback last_seal(handle(), stream :: String.t()) ::
              {:ok, {Ref.t(), pos_integer()} | nil} | {:error, term()}

  @doc """
  Every record of a session, across streams, ordered by stream and
  position.
  """
  @callback by_session(handle(), session :: String.t()) :: {:ok, [entry()]} | {:error, term()}

  @typedoc """
  What a listing asks for. `stream_prefix` and `limit` are always given:
  a deployment's streams share a prefix, and a listing is never
  unbounded. The rest narrow it: one kind (its full path), one session,
  one actor, records captured at or after `since`, records captured
  before `until`. `before` continues an earlier listing from the
  capture time and reference of the last record it returned.
  """
  @type listing :: %{
          required(:stream_prefix) => String.t(),
          required(:limit) => pos_integer(),
          optional(:kind_path) => String.t(),
          optional(:session) => String.t(),
          optional(:actor) => String.t(),
          optional(:own_principal) => {String.t(), String.t()},
          optional(:since) => DateTime.t(),
          optional(:until) => DateTime.t(),
          optional(:before) => {DateTime.t(), Ref.t()}
        }

  @doc """
  Records newest first: by the time each says it was captured, then by
  reference so that records sharing a time keep one order. At most
  `limit` are returned. To read on, pass the last record's capture time
  and reference as `before`; a record arriving meanwhile is never
  repeated or skipped past, because the position is a record and not a
  count.
  """
  @callback list(handle(), listing()) :: {:ok, [entry()]} | {:error, term()}

  @doc """
  Every record of one kind on streams beginning with `stream_prefix`,
  ordered by stream and position. A deployment's streams share a prefix,
  so this is "all the session closings of this deployment" or "every
  definition a publisher added to it": what a node reads once as it
  starts, to rebuild what it otherwise keeps in memory.
  """
  @callback by_kind(handle(), kind_path :: String.t(), stream_prefix :: String.t()) ::
              {:ok, [entry()]} | {:error, term()}

  @doc """
  The streams beginning with `prefix` that hold a record no seal covers
  yet: the stream's last record is beyond its last seal. This is how
  records admitted whole, on streams no writer owns, are found for
  sealing without anyone remembering them in memory, so a restart loses
  none.
  """
  @callback unsealed_firsts(handle(), prefix :: String.t()) ::
              {:ok, [String.t()]} | {:error, term()}

  @doc "The earliest seal that covers a position of a stream."
  @callback seal_covering(handle(), stream :: String.t(), seq :: pos_integer()) ::
              {:ok, entry()} | :error

  @doc """
  Keep a public key under its key id. Keys are kept for good: a record
  must stay checkable long after the key that signed it has been retired.
  """
  @callback put_key(handle(), %{key_id: String.t(), algorithm: String.t(), public_key: binary()}) ::
              :ok | {:error, term()}

  @doc "A public key by key id."
  @callback get_key(handle(), key_id :: String.t()) ::
              {:ok, %{key_id: String.t(), algorithm: String.t(), public_key: binary()}} | :error

  @doc "Retain content under its `bytes:` reference."
  @callback put_blob(handle(), Ref.t(), content()) :: :ok | {:error, term()}

  @doc """
  Hold content that belongs to a scope (in practice a session), so that
  the scope's content can later be erased together and nothing else is.
  A store that encrypts keeps a separate copy per scope under that
  scope's key. `:held` in place of the content means "this scope also
  refers to content already held for another", and gives this scope the
  means to read it: only the deployment's own recorder may say it, about
  content it captured itself. `:own` means "this scope already holds
  this", and is refused with `:not_held` when it does not, or when the
  store cannot tell scopes apart. It is what to pass when the reference
  came from outside and its bytes did not: knowing a reference is not a
  right to the content. A `nil` scope is structure (a profile, a
  definition, a seal's manifest) and is held as it is.
  """
  @callback put_content(
              handle(),
              Ref.t(),
              content() | :held | :own,
              scope :: String.t() | nil
            ) ::
              :ok | {:error, term()}

  @doc """
  Content bytes by reference, as the given scope may read them. A store
  that encrypts opens the content only through that scope's own key, so
  one session's content is never read by way of another's, and content
  whose scope's key is gone is not returned even if the same bytes
  survive elsewhere. `{:error, :key_service_unavailable}` when the
  content may well be readable but the key service did not answer, so
  that a caller about to record a lasting conclusion can stop instead.
  """
  @callback get_content(handle(), Ref.t(), scope :: String.t() | nil) ::
              {:ok, binary()} | :error | {:error, :key_service_unavailable}

  @doc """
  Bytes held as they are, by reference: profiles, definitions and seal
  manifests. A store that encrypts does not return encrypted content
  here; that is read with `get_content/3`.
  """
  @callback get_blob(handle(), Ref.t()) :: {:ok, binary()} | :error
end
