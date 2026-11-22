defmodule Recurse.Provenance.Staging do
  @moduledoc """
  How content waits on the local disk between capture and the content
  store.

  Capture places the bytes behind every content reference in the
  pipeline's content directory, named by the reference, and the shipper
  later hands them to the content store and removes them. How those
  files are written and read back is up to the host: `Plain` keeps them
  as they are, and a host that must not leave recorded content readable
  on its disk supplies an implementation that encrypts them.

  Nothing here knows about keys or ciphers. An implementation is given
  as `{module, state}`; the module implements these callbacks.

  Whatever the format, a file is always named by the reference of the
  bytes it holds, and every callback that places a file leaves either
  the complete file or nothing at the target.
  """

  alias Recurse.Provenance.Store

  @type t :: {module(), term()}

  @doc """
  Place `bytes` at `target`, unless a file is there already (content is
  addressed by its hash, so an existing file holds the same bytes). An
  existing file is marked as wanted again, so that a sweep for files no
  record refers to does not take it.
  """
  @callback write_bytes(state :: term(), target :: Path.t(), bytes :: binary()) ::
              :ok | {:error, term()}

  @doc """
  The SHA-256 of the content a file at `path` holds, read as a stream.
  The file may be one this implementation wrote or a plain file.

  `expected` is the hash the caller took of the same bytes as they were
  written, or nil. An implementation whose shipping reader checks every
  byte against the reference anyway may answer with `expected` without
  reading the file again.
  """
  @callback hash_file(state :: term(), path :: Path.t(), expected :: <<_::256>> | nil) ::
              {:ok, <<_::256>>} | {:error, term()}

  @doc """
  Move the file at `source` to `target` in this implementation's format,
  unless a file is there already, in which case it is marked as wanted
  again and `source` is left for its owner to remove.
  """
  @callback place_file(state :: term(), source :: Path.t(), target :: Path.t()) ::
              :ok | {:error, term()}

  @doc """
  What to hand the content store for the file at `path`.

  `{:error, :staged_content_lost}` says the file can never be read again
  (its key no longer exists); the shipper then records without it rather
  than wait for ever. A reader that finds a file it cannot read (altered,
  cut short, not the content its name says) answers
  `{:error, {:staged_content_unreadable, why}}`, having already moved the
  file aside, and the shipper does the same. Any other error is retried.
  """
  @callback content(state :: term(), path :: Path.t()) ::
              {:ok, Store.content()} | {:error, term()}

  @doc "The default: files hold the content as it is."
  @spec plain() :: t()
  def plain, do: {__MODULE__.Plain, nil}

  @doc false
  def write_bytes({module, state}, target, bytes), do: module.write_bytes(state, target, bytes)
  @doc false
  def hash_file({module, state}, path, expected), do: module.hash_file(state, path, expected)
  @doc false
  def place_file({module, state}, source, target), do: module.place_file(state, source, target)
  @doc false
  def content({module, state}, path), do: module.content(state, path)

  defmodule Plain do
    @moduledoc "Content waits on disk as it is. For hosts with no key service, and tests."
    @behaviour Recurse.Provenance.Staging

    @impl true
    def write_bytes(_state, target, bytes) do
      unless File.exists?(target) do
        partial = target <> ".partial-" <> Integer.to_string(System.unique_integer([:positive]))
        File.write!(partial, bytes)
        File.rename!(partial, target)
      end

      :ok
    rescue
      error in [File.Error] -> {:error, error.reason}
    end

    # Plain files are always read: nothing else checks them before they
    # are shipped.
    @impl true
    def hash_file(_state, path, _expected) do
      {:ok,
       path
       |> File.stream!(64 * 1024)
       |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))
       |> :crypto.hash_final()}
    rescue
      error in [File.Error] -> {:error, error.reason}
    end

    # Rename when the spool is on the same filesystem; copy otherwise.
    @impl true
    def place_file(_state, source, target) do
      unless File.exists?(target) do
        with {:error, _} <- File.rename(source, target) do
          partial = target <> ".partial-" <> Integer.to_string(System.unique_integer([:positive]))
          File.cp!(source, partial)
          File.rename!(partial, target)
        end
      end

      :ok
    rescue
      error in [File.Error] -> {:error, error.reason}
    end

    @impl true
    def content(_state, path), do: {:ok, {:file, path}}
  end
end
