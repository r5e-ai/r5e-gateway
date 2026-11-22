defmodule Recurse.Providers.StorageProvider do
  @moduledoc """
  Provider Interface — StorageProvider.

  Spec source: FR-003. Stores **detached payloads** per Constitution Principle IV
  (the ledger NEVER stores payloads; this interface does). Customer-controlled
  storage — S3, Splunk HEC, MinIO, or equivalent — so payloads can be deleted
  (GDPR Article 17 / DSA Right-to-be-Forgotten) without breaking the ledger's
  audit chain.

  Reference implementations (Feature 002+ per task T064):

  - `S3Storage` — AWS S3 (Managed SaaS reference per `gtm_sequencing.md`)
  - `SplunkHECStorage` — Splunk HTTP Event Collector
  - `MinIOStorage` — on-prem S3-compatible object store (Air-Gapped Appliance
    reference)
  """

  @type config :: map()
  @type state :: term()

  @typedoc "Opaque URI the Audit Payload Broker uses to retrieve a payload."
  @type payload_uri :: String.t()

  @typedoc "SHA-256 hash of the payload bytes; populates `payload_hash` in FR-021."
  @type payload_hash :: binary()

  @typedoc """
  Optional-feature capability flags an implementation declares via `capabilities/1`.
  """
  @type capability :: :put | :get | :delete | :streaming | :versioned

  @doc """
  Initialize the provider with deployment-time configuration.
  """
  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Store a detached payload.

  Returns a URI that the Audit Payload Broker (FR-030) uses to retrieve the
  payload, and the SHA-256 hash that goes into the attestation envelope's
  `payload_hash` field (FR-021).

  The `Recurse.Shared.IdentityContext.t()` is used for tenancy scoping at
  storage time.
  """
  @callback put_payload(
              state,
              payload :: binary(),
              Recurse.Shared.IdentityContext.t()
            ) :: {:ok, %{uri: payload_uri, hash: payload_hash}} | {:error, term()}

  @doc """
  Retrieve a detached payload by URI. Used by the Audit Payload Broker (FR-030).

  The `Recurse.Shared.IdentityContext.t()` represents the auditor's identity;
  the broker authorizes via Cedar before invoking this, so impls MAY skip
  auth checks (defense-in-depth is recommended but not required).
  """
  @callback get_payload(
              state,
              payload_uri,
              Recurse.Shared.IdentityContext.t()
            ) :: {:ok, binary()} | {:error, term()}

  @doc """
  Delete a payload. Supports GDPR Article 17 / DSA Right-to-be-Forgotten.

  Constitutional contract: deletion MUST NOT break the ledger or other receipts.
  The ledger holds only the hash; deleting the payload makes future
  hash-comparison impossible for THIS payload but does not invalidate the
  receipt's signature or inclusion proofs.
  """
  @callback delete_payload(
              state,
              payload_uri,
              Recurse.Shared.IdentityContext.t()
            ) :: :ok | {:error, term()}

  @doc """
  Optional-feature capability flags. See `t:capability/0` for allowed values.
  """
  @callback capabilities(state) :: [capability]

  @doc """
  Store a detached payload held in a file, without reading it whole
  into memory. Optional: a caller falls back to `put_payload/3` on the
  file's contents when a provider does not implement it.
  """
  @callback put_payload_file(
              state,
              path :: Path.t(),
              Recurse.Shared.IdentityContext.t()
            ) :: {:ok, %{uri: payload_uri, hash: payload_hash}} | {:error, term()}

  @doc """
  Store bytes at a place named by the bytes themselves: the same bytes
  always land in the same place, and different bytes never share one.
  The evidence store keeps every piece of recorded content this way,
  through one long-lived identity, so a provider whose `put_payload/3`
  names objects after the caller (a run, a day) must implement this or
  each write would replace the one before. Optional: a provider whose
  `put_payload/3` already names by content need not.
  """
  @callback put_content(
              state,
              payload :: binary(),
              Recurse.Shared.IdentityContext.t()
            ) :: {:ok, %{uri: payload_uri, hash: payload_hash}} | {:error, term()}

  @optional_callbacks put_payload_file: 3, put_content: 3

  @doc """
  Healthcheck for `/healthz` aggregation (FR-014).
  """
  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @doc """
  Graceful shutdown — flush buffered writes, close backend connections.
  """
  @callback terminate(state, reason :: term()) :: :ok
end
