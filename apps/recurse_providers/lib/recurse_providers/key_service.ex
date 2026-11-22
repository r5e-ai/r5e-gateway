defmodule Recurse.Providers.KeyService do
  @moduledoc """
  The customer's key service, as far as content encryption needs it.

  Content is encrypted under per-session keys this product makes. Those
  keys are never stored as they are: each is locked ("wrapped") by a key
  that lives in the customer's own key service and never leaves it, and
  only the locked form is kept. Reading content means asking the key
  service to unlock the session's key, so the customer's key service
  decides, and can log, every read; and whoever holds a copy of the
  database and the stored content, without the key service, holds
  nothing readable.

  An implementation wraps and unwraps 32-byte keys. `context` names what
  the key is for and is bound into the wrapping, so a locked key moved
  to another session does not unlock.
  """

  @type state :: term()

  @doc "Lock a key under the customer's key."
  @callback wrap(state(), key :: <<_::256>>, context :: String.t()) ::
              {:ok, binary()} | {:error, term()}

  @doc "Unlock a key locked by `wrap/3` with the same context."
  @callback unwrap(state(), wrapped :: binary(), context :: String.t()) ::
              {:ok, <<_::256>>} | {:error, term()}

  @doc "A name for the customer's key, to show an operator which key holds their content."
  @callback describe(state()) :: String.t()
end
