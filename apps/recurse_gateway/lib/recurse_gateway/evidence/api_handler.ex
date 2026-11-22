defmodule Recurse.Gateway.Evidence.ApiHandler do
  @moduledoc """
  Provenance v2 evidence over HTTP.

    * `GET  /v1/evidence/records/:ref` — one signed record by its
      `evidence:sha256:…` reference.
    * `GET  /v1/evidence/records` — records newest first, a page at a
      time. Query: `kind` (a kind's full path), `session`, `actor`,
      `since` and `until` (RFC 3339; `since` is included, `until` is
      not), `limit` (1 to 200, 50 when absent) and `cursor`. Answers
      `{"records": […], "cursor": "…" | null}`; pass the cursor back to
      read on. A parameter this route does not know is refused, so that
      a filter that was not applied is never mistaken for one that
      matched nothing.
    * `GET  /v1/evidence/tail` — records as they arrive, over a
      WebSocket (`Recurse.Gateway.Evidence.TailSocket`). Query: `kind`,
      `session` and `actor`, as on the list. 426 for a request that is
      not a WebSocket handshake, 503 when this node is not capturing.
    * `GET  /v1/evidence/records/:ref/content/:bytes_ref` — one piece
      of content a record names, as a download. 404 when the record does
      not name it or it is not held, 410 when the record's content was
      disposed of, 503 when the key service did not answer.
    * `GET  /v1/evidence/sessions/:session_id` — a session's records in
      stream order. `:session_id` is the session's recorded name, or
      the part after the tenant, or the client's id alone; an id that
      different people used answers 409 with the names to choose from.
    * `POST /v1/evidence/export` — a session as an offline bundle.
      Body: `{"session": "<id>", "content": true | false}`. Content is
      withheld unless asked for.
    * `POST /v1/evidence/verify` — check a submitted bundle and return
      the report. Body: `{"bundle": {…}, "trustedProfiles": ["bytes:…"],
      "trustedPublishers": ["key:…"], "trustedRoots": ["key:…"]}`.
      With `trustedRoots`, authority is established by following
      endorsements and badges from those keys; without it, from the
      trusted profiles.

    * `POST /v1/authority/badges/prepare` and `…/finalize` — give a
      workload a badge, in two steps
      (`Recurse.Gateway.Provenance.Enrolment`). `prepare` takes
      `{"subjectKey": {"algorithm", "bytes"}, "holder", "workload",
      "requestedKinds", "requestedActorPrefixes", "requestedTtlSeconds"}`
      and returns `{"payloadType", "payload", "ticket"}`. `finalize`
      takes `{"payload", "ticket", "subjectSignature": {"keyid", "sig"}}`
      and returns the badge with the chain, keys and profile the
      workload needs to produce evidence that verifies offline.

    * `GET  /v1/evidence/retention` — the holds and disposals recorded.
    * `POST /v1/evidence/retention/holds` — place a hold. Body:
      `{"reason", "scope" | "targets", "until"?}`.
    * `POST /v1/evidence/retention/holds/release/prepare` and
      `…/finalize` — release a hold, in two steps, because the person
      releasing signs the record too. `prepare` takes `{"hold",
      "reason", "releasedBy": {"algorithm", "bytes"}}` and returns
      `{"payloadType", "payload", "ticket"}`. `finalize` takes
      `{"payload", "ticket", "signature": {"keyid", "sig"},
      "releasedBy", "authority"?}`.
    * `POST /v1/evidence/retention/disposals` — dispose of a scope's
      content. Body: `{"scope", "reason", "action"?}`. 409 when the
      scope has no content key left to destroy.
      (`Recurse.Gateway.Provenance.Retention`.)

    * `POST /v1/evidence/sessions` — open a session for the caller and
      return its recorded name. Body: `{}` for a new id the gateway
      makes, or `{"clientSessionId": "<id>"}` for the id the caller's
      own client uses on its model calls, which answers with the same
      session whether or not it was already open.
    * `POST /v1/evidence/records` — hand over records a workload signed
      itself, with its badge (`Recurse.Gateway.Provenance.Admission`).
    * `POST /v1/authority/badges/revoke` — take back a badge this
      gateway issued. Body: `{"badge", "reason"}`.

  The read routes read the index and the content store directly, so they answer
  whether or not this node is capturing.

  ## Who may call

  Cookie or bearer, then the policy bundle: `ReadReceipts` to read
  records and to verify, `ExportEvidence` to export, `ReadPayload`
  as well when an export asks for content or content is read directly, `EnrolWorkload` to be
  given a badge, and `ManageRetention` to place or release a hold or to
  dispose of content. `SubmitEvidence` to open a session or hand over
  a workload's records. A badge is taken back by the person it acts for
  (`EnrolWorkload`) or by an operator (`RevokeBadge`).

  A deployment records for one tenant, and a record does not carry a
  tenant of its own. So a caller is served only when their tenant is the
  deployment's; anyone else gets 404, the same answer as for a record
  that does not exist. A session is looked up under the caller's own
  tenant, so a session id from another tenant can never match.

  ## What is not here

  Reading and exporting are not yet recorded as evidence themselves, and
  a session's records are returned whole, without paging. A listing
  cannot be narrowed by anything inside a record's body, such as a
  policy outcome or a tool's name.
  """

  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.Evidence.TailSocket
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Provenance.{Admission, Carried, Disclosing, Enrolment, Retention, Runtime}
  alias Recurse.Gateway.Provenance.SessionName
  alias Recurse.Provenance.{Evidence, Export, Exporter, Key, Pipeline, Ref}
  alias Recurse.Shared.IdentityContext

  @read ~s(Recurse::Action::"ReadReceipts")
  @export ~s(Recurse::Action::"ExportEvidence")
  @payload ~s(Recurse::Action::"ReadPayload")
  @enrol ~s(Recurse::Action::"EnrolWorkload")
  @retention ~s(Recurse::Action::"ManageRetention")
  @disclose ~s(Recurse::Action::"DiscloseEvidence")
  @submit ~s(Recurse::Action::"SubmitEvidence")
  @revoke_badge ~s(Recurse::Action::"RevokeBadge")
  @payload_type "application/vnd.r5e.provenance-evidence+json;v=2"

  @default_limit 50
  @max_limit 200
  @listing_params ~w(kind session actor since until limit cursor)
  @tail_params ~w(kind session actor)

  @doc "`GET /v1/evidence/records`"
  @spec records(Plug.Conn.t()) :: Plug.Conn.t()
  def records(conn) do
    %Plug.Conn{query_params: params} = conn = Plug.Conn.fetch_query_params(conn)

    gated(conn, @read, "/v1/evidence/records", fn conn, ctx, index ->
      case page(params, ctx, index) do
        {:ok, page} -> json(conn, 200, page)
        :none -> json(conn, 200, %{"records" => [], "cursor" => nil})
        {:many, sessions} -> several(conn, sessions)
        {:bad, message} -> bad_request(conn, message)
        {:error, _} -> json(conn, 503, %{"error" => "ERR_UNAVAILABLE"})
      end
    end)
  end

  defp page(params, ctx, {module, handle} = index) do
    with {:ok, asked} <- listing(params),
         {:ok, asked} <- of_session(asked, params["session"], ctx, index),
         # One more than asked for says whether there is more to read.
         {:ok, entries} <- module.list(handle, %{asked | limit: asked.limit + 1}) do
      {page, rest} = Enum.split(entries, asked.limit)
      cursor = if rest == [], do: nil, else: cursor(List.last(page))
      {:ok, %{"records" => Enum.map(page, &render/1), "cursor" => cursor}}
    end
  end

  @doc "`GET /v1/evidence/tail`"
  @spec tail(Plug.Conn.t()) :: Plug.Conn.t()
  def tail(conn) do
    %Plug.Conn{query_params: params} = conn = Plug.Conn.fetch_query_params(conn)

    gated(conn, @read, "/v1/evidence/tail", fn conn, ctx, index ->
      case watching(params, ctx, index) do
        {:ok, opening} -> TailSocket.upgrade(conn, opening)
        :none -> not_found(conn)
        {:many, sessions} -> several(conn, sessions)
        {:bad, message} -> bad_request(conn, message)
        :not_capturing -> json(conn, 503, %{"error" => "ERR_NOT_CAPTURING"})
        {:error, _} -> json(conn, 503, %{"error" => "ERR_UNAVAILABLE"})
      end
    end)
  end

  # What a tail connection is opened with, or why it cannot be.
  defp watching(params, ctx, index) do
    with [] <- Map.keys(params) -- @tail_params,
         true <- Runtime.running?() || :not_capturing,
         {:ok, asked} <- Enum.reduce_while(params, {:ok, %{}}, &asked/2),
         {:ok, filter} <- of_session(asked, params["session"], ctx, index) do
      {:ok,
       %{
         store: index,
         signals: Pipeline.signals(Runtime.pipeline()),
         stream_prefix: "urn:r5e:stream:#{deployment()}:",
         filter: filter
       }}
    else
      [unknown | _] -> {:bad, "unknown parameter #{unknown}"}
      other -> other
    end
  end

  # What the query asks for, or why it cannot be answered as asked.
  defp listing(params) do
    start = %{stream_prefix: "urn:r5e:stream:#{deployment()}:", limit: @default_limit}

    case Map.keys(params) -- @listing_params do
      [] -> Enum.reduce_while(params, {:ok, start}, &asked/2)
      [unknown | _] -> {:bad, "unknown parameter #{unknown}"}
    end
  end

  defp asked({"kind", kind}, {:ok, acc}) when kind != "",
    do: {:cont, {:ok, Map.put(acc, :kind_path, kind)}}

  defp asked({"actor", actor}, {:ok, acc}) when actor != "",
    do: {:cont, {:ok, Map.put(acc, :actor, actor)}}

  # Resolved against the caller's tenant afterwards: see `of_session/4`.
  defp asked({"session", session}, acc) when session != "", do: {:cont, acc}

  defp asked({name, stated}, {:ok, acc}) when name in ["since", "until"] do
    case DateTime.from_iso8601(stated) do
      {:ok, at, _offset} -> {:cont, {:ok, Map.put(acc, String.to_existing_atom(name), at)}}
      _ -> {:halt, {:bad, "#{name} is not an RFC 3339 time"}}
    end
  end

  defp asked({"limit", stated}, {:ok, acc}) do
    case Integer.parse(stated) do
      {limit, ""} when limit in 1..@max_limit -> {:cont, {:ok, %{acc | limit: limit}}}
      _ -> {:halt, {:bad, "limit is a whole number from 1 to #{@max_limit}"}}
    end
  end

  defp asked({"cursor", cursor}, {:ok, acc}) do
    with {:ok, plain} <- Base.url_decode64(cursor, padding: false),
         [stated, ref] <- String.split(plain, " ", parts: 2),
         {:ok, at, 0} <- DateTime.from_iso8601(stated),
         true <- Ref.valid?(ref, :evidence) do
      {:cont, {:ok, Map.put(acc, :before, {at, ref})}}
    else
      _ -> {:halt, {:bad, "cursor is not one this route gave"}}
    end
  end

  defp asked({name, _}, _acc), do: {:halt, {:bad, "#{name} is empty"}}

  # The deployment whose records these are: the one this node captures
  # for, or the configured one when it only reads.
  defp deployment do
    case Runtime.info() do
      %{deployment: deployment} -> deployment
      _ -> Application.get_env(:recurse_gateway, :evidence_deployment, "default")
    end
  end

  # A session is only ever looked for among the caller's tenant's own.
  defp of_session(asked, nil, _ctx, _index), do: {:ok, asked}

  defp of_session(asked, id, ctx, index) do
    case named(ctx, id, index) do
      {:ok, session} -> {:ok, Map.put(asked, :session, session)}
      other -> other
    end
  end

  # Where a listing left off: the last record's place in the order.
  defp cursor(entry),
    do: Base.url_encode64(entry.evidence["capturedAt"] <> " " <> entry.ref, padding: false)

  @doc "`GET /v1/evidence/records/:ref`"
  @spec record(Plug.Conn.t()) :: Plug.Conn.t()
  def record(%Plug.Conn{path_params: %{"ref" => ref}} = conn) do
    gated(conn, @read, "/v1/evidence/records", fn conn, _ctx, {module, handle} ->
      with true <- Ref.valid?(ref, :evidence),
           {:ok, entry} <- module.fetch(handle, ref) do
        json(conn, 200, render(entry))
      else
        _ -> not_found(conn)
      end
    end)
  end

  @disposition "provenance.r5e.io/v2/PayloadDisposition"

  @doc """
  `GET /v1/evidence/records/:ref/content/:bytes_ref`

  Content is reached through a record that names it, never by its
  reference alone: the record says which session's key opens it, and
  knowing a reference is not a right to the bytes. It is always sent as
  a download of unstated type. What was captured may be anything, and it
  must never be shown as a page on this origin.
  """
  @spec content(Plug.Conn.t()) :: Plug.Conn.t()
  def content(%Plug.Conn{path_params: %{"ref" => ref, "bytes_ref" => bytes_ref}} = conn) do
    endpoint = "/v1/evidence/records/content"

    gated(conn, @read, endpoint, fn conn, _ctx, index ->
      case content_allowed(conn, true, endpoint) do
        :ok -> held(conn, index, ref, bytes_ref)
        {:forbidden, error} -> Authz.dispatch_gate_error(conn, error)
      end
    end)
  end

  defp held(conn, {module, handle} = index, ref, bytes_ref) do
    with true <- Ref.valid?(ref, :evidence) and Ref.valid?(bytes_ref, :bytes),
         {:ok, entry} <- module.fetch(handle, ref),
         true <- bytes_ref in Exporter.content_refs([entry]),
         scope = Evidence.content_scope(entry.evidence),
         {:ok, bytes} <- readable(index, bytes_ref, scope) do
      download(conn, bytes_ref, bytes)
    else
      {:error, :key_service_unavailable} -> json(conn, 503, %{"error" => "ERR_UNAVAILABLE"})
      {:unreadable, scope} -> if disposed?(index, scope), do: gone(conn), else: not_found(conn)
      _ -> not_found(conn)
    end
  end

  defp readable({module, handle}, bytes_ref, scope) do
    case module.get_content(handle, bytes_ref, scope) do
      :error -> {:unreadable, scope}
      other -> other
    end
  end

  defp download(conn, bytes_ref, bytes) do
    conn
    |> Plug.Conn.put_resp_content_type("application/octet-stream", nil)
    |> Plug.Conn.put_resp_header("content-disposition", "attachment")
    |> Plug.Conn.put_resp_header("x-content-type-options", "nosniff")
    |> Plug.Conn.put_resp_header("cache-control", "no-store, private")
    |> Plug.Conn.put_resp_header("x-r5e-content-ref", bytes_ref)
    |> Plug.Conn.send_resp(200, bytes)
  end

  # Whether a disposal of this scope's content is on record. Asked only
  # once the content has turned out not to be readable.
  defp disposed?(_index, nil), do: false

  defp disposed?({module, handle}, scope) do
    case module.by_kind(handle, @disposition, "urn:r5e:stream:#{deployment()}:") do
      {:ok, entries} ->
        Enum.any?(entries, &(&1.evidence["body"]["scope"] == scope)) or
          Enum.any?(entries, &under?(module, handle, scope, &1.ref))

      _ ->
        false
    end
  end

  # A disposal of whoever the session belongs to names that person, not
  # the session, and destroys the session's key all the same.
  defp under?(module, handle, scope, disposal) do
    function_exported?(module, :disposed_by?, 3) and module.disposed_by?(handle, scope, disposal)
  end

  defp gone(conn), do: json(conn, 410, %{"error" => "ERR_CONTENT_DISPOSED"})

  @doc "`GET /v1/evidence/sessions/:session_id`"
  @spec session(Plug.Conn.t()) :: Plug.Conn.t()
  def session(%Plug.Conn{path_params: %{"session_id" => id}} = conn) do
    gated(conn, @read, "/v1/evidence/sessions", fn conn, ctx, {module, handle} ->
      with {:ok, session} <- named(ctx, id, {module, handle}),
           {:ok, [_ | _] = entries} <- module.by_session(handle, session) do
        json(conn, 200, %{"session" => session, "records" => Enum.map(entries, &render/1)})
      else
        {:many, sessions} -> several(conn, sessions)
        _ -> not_found(conn)
      end
    end)
  end

  @doc "`POST /v1/evidence/export`"
  @spec export(Plug.Conn.t()) :: Plug.Conn.t()
  def export(%Plug.Conn{body_params: %{"session" => id} = body} = conn) when is_binary(id) do
    content? = body["content"] == true

    gated(conn, @export, "/v1/evidence/export", fn conn, ctx, index ->
      with :ok <- content_allowed(conn, content?, "/v1/evidence/export"),
           {:ok, session} <- named(ctx, id, index),
           {:ok, %{"records" => [_ | _]} = bundle} <-
             Exporter.session(index, session, content: content?) do
        json(conn, 200, Carried.carry(bundle))
      else
        {:forbidden, error} -> Authz.dispatch_gate_error(conn, error)
        {:many, sessions} -> several(conn, sessions)
        _ -> not_found(conn)
      end
    end)
  end

  def export(conn), do: bad_request(conn, ~s(expected {"session": "<id>"}))

  @doc "`POST /v1/evidence/verify`"
  @spec verify(Plug.Conn.t()) :: Plug.Conn.t()
  def verify(%Plug.Conn{body_params: %{"bundle" => bundle} = body} = conn) when is_map(bundle) do
    trusted = body["trustedProfiles"] || []
    publishers = body["trustedPublishers"] || []
    roots = body["trustedRoots"]
    chain = body["trustedChain"]
    minimum = body["minStartSeq"]

    key_ids? = fn list ->
      is_list(list) and Enum.all?(list, &match?({:ok, _}, Key.algorithm_of(&1)))
    end

    # A publisher is a key id, or a key id believed about named domains
    # only: `key:…=r5e.io,acme.example`.
    publishers? = fn list ->
      is_list(list) and
        Enum.all?(list, fn
          entry when is_binary(entry) ->
            case String.split(entry, "=", parts: 2) do
              [key] ->
                match?({:ok, _}, Key.algorithm_of(key))

              [key, domains] ->
                match?({:ok, _}, Key.algorithm_of(key)) and
                  Regex.match?(
                    ~r/\A[a-z0-9-]+(\.[a-z0-9-]+)*(,[a-z0-9-]+(\.[a-z0-9-]+)*)*\z/,
                    domains
                  )
            end

          _ ->
            false
        end)
    end

    if is_list(trusted) and Enum.all?(trusted, &Ref.valid?(&1, :bytes)) and
         publishers?.(publishers) and (is_nil(roots) or key_ids?.(roots)) and
         (is_nil(chain) or Ref.valid?(chain, :evidence)) and not (roots != nil and chain != nil) and
         (is_nil(minimum) or (is_integer(minimum) and minimum >= 2)) do
      # Verification reads nothing of this deployment's, so the tenant
      # rule does not apply; the caller only has to be allowed to read.
      case Authz.gate(conn, @read, resource("/v1/evidence/verify")) do
        {:ok, conn, _ctx, _bundle_ref} ->
          json(
            conn,
            200,
            Export.report(
              Export.verify(bundle,
                trusted_profiles: trusted,
                trusted_publishers: publishers,
                trusted_roots: roots,
                trusted_chain: chain,
                min_start_seq: minimum
              )
            )
          )

        error ->
          Authz.dispatch_gate_error(conn, error)
      end
    else
      bad_request(
        conn,
        "trustedProfiles must be bytes: references; trustedPublishers and trustedRoots key ids; " <>
          "trustedChain an evidence: reference, given instead of trustedRoots; minStartSeq 2 or more"
      )
    end
  end

  def verify(conn), do: bad_request(conn, ~s(expected {"bundle": {…}}))

  @doc "`POST /v1/authority/badges/prepare`"
  @spec badge_prepare(Plug.Conn.t()) :: Plug.Conn.t()
  def badge_prepare(%Plug.Conn{body_params: %{"subjectKey" => _} = request} = conn) do
    gated(conn, @enrol, "/v1/authority/badges", fn conn, ctx, _index ->
      case Enrolment.prepare(request, acts_for(ctx)) do
        {:ok, %{payload: payload, ticket: ticket}} ->
          json(conn, 200, %{
            "payloadType" => @payload_type,
            "payload" => Base.encode64(payload),
            "ticket" => ticket
          })

        {:error, reason} ->
          enrolment_error(conn, reason)
      end
    end)
  end

  def badge_prepare(conn), do: bad_request(conn, ~s(expected {"subjectKey": {…}, …}))

  @doc "`POST /v1/authority/badges/finalize`"
  @spec badge_finalize(Plug.Conn.t()) :: Plug.Conn.t()
  def badge_finalize(%Plug.Conn{body_params: request} = conn) do
    gated(conn, @enrol, "/v1/authority/badges", fn conn, ctx, _index ->
      case Enrolment.finalize(request, acts_for(ctx)) do
        {:ok, body} -> json(conn, 201, body)
        {:error, reason} -> enrolment_error(conn, reason)
      end
    end)
  end

  @doc "`POST /v1/evidence/sessions`"
  @spec open_session(Plug.Conn.t()) :: Plug.Conn.t()
  def open_session(%Plug.Conn{body_params: request} = conn) do
    serving(conn, @submit, "/v1/evidence/sessions", fn conn, ctx ->
      case Admission.open_session(request, caller(ctx)) do
        {:ok, :opened, body} -> json(conn, 201, body)
        {:ok, :already, body} -> json(conn, 200, body)
        {:error, reason} -> json(conn, 422, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  @doc "`POST /v1/evidence/records`"
  @spec submit(Plug.Conn.t()) :: Plug.Conn.t()
  def submit(%Plug.Conn{body_params: request} = conn) do
    serving(conn, @submit, "/v1/evidence/records", fn conn, ctx ->
      case Admission.submit(request, caller(ctx)) do
        {:ok, admitted} ->
          status =
            if Enum.all?(admitted, &(&1["status"] == "already_admitted")), do: 200, else: 201

          json(conn, status, %{"admitted" => admitted})

        {:error, :malformed_request} ->
          bad_request(conn, ~s(expected {"records": [{"envelope": {…}}], …}, 1 to 64 records))

        {:error, {reason, about}} when is_atom(reason) and is_map(about) ->
          json(conn, 409, Map.put(about, "error", Atom.to_string(reason)))

        {:error, reason}
        when reason in [:not_next_in_stream, :stream_fork_refused, :gateway_has_no_endorsement] ->
          json(conn, 409, %{"error" => Atom.to_string(reason)})

        {:error, reason} when is_atom(reason) ->
          json(conn, 422, %{"error" => Atom.to_string(reason)})

        {:error, _other} ->
          json(conn, 422, %{"error" => "not_recorded"})
      end
    end)
  end

  @doc "`POST /v1/authority/badges/revoke`"
  @spec badge_revoke(Plug.Conn.t()) :: Plug.Conn.t()
  def badge_revoke(%Plug.Conn{body_params: %{"badge" => ref, "reason" => reason}} = conn) do
    serving(conn, @enrol, "/v1/authority/badges", fn conn, ctx ->
      with {:ok, body} <- Admission.badge(ref),
           :ok <- may_revoke(conn, ctx, body),
           {:ok, done} <- Admission.revoke_badge(ref, reason) do
        json(conn, 201, done)
      else
        :error -> not_found(conn)
        {:forbidden, error} -> Authz.dispatch_gate_error(conn, error)
        {:error, reason} -> json(conn, 422, %{"error" => Atom.to_string(reason)})
      end
    end)
  end

  def badge_revoke(conn), do: bad_request(conn, ~s(expected {"badge": "evidence:…", "reason"}))

  # One's own badge, or any badge for an operator.
  defp may_revoke(conn, ctx, %{"actsFor" => acts_for}) do
    if is_binary(acts_for) and acts_for == acts_for(ctx) do
      :ok
    else
      case Authz.gate(conn, @revoke_badge, resource("/v1/authority/badges")) do
        {:ok, _conn, _ctx, _bundle_ref} -> :ok
        error -> {:forbidden, error}
      end
    end
  end

  defp may_revoke(conn, ctx, body), do: may_revoke(conn, ctx, Map.put(body, "actsFor", nil))

  # These routes write, so they answer only on a node that is capturing,
  # and, where a deployment begins its own chain, only once it is claimed.
  defp serving(conn, action, endpoint, fun) do
    gated(conn, action, endpoint, fn conn, ctx, _index ->
      cond do
        not Runtime.running?() -> not_found(conn)
        not Runtime.serving?() -> json(conn, 503, %{"error" => "deployment_not_claimed"})
        true -> fun.(conn, ctx)
      end
    end)
  end

  # Who is calling, named the way the gateway names the same caller on a
  # proxied call. Never taken from the request.
  defp caller(%IdentityContext{tenant_id: tenant, principal: principal} = ctx) do
    encoded = URI.encode(to_string(tenant), &URI.char_unreserved?/1)

    named =
      case acts_for(ctx) do
        nil ->
          id =
            Map.get(principal, :spiffe_id) || Map.get(principal, :subject) ||
              Map.get(principal, :account_id) || "unknown"

          if String.starts_with?(to_string(id), "spiffe://"),
            do: id,
            else:
              "urn:r5e:principal:#{encoded}:" <>
                URI.encode(to_string(id), &URI.char_unreserved?/1)

        person ->
          person
      end

    %{tenant: encoded, principal: named}
  end

  @doc "`GET /v1/evidence/retention`"
  @spec retention(Plug.Conn.t()) :: Plug.Conn.t()
  def retention(conn) do
    capturing(conn, @read, fn conn, _ctx -> json(conn, 200, Retention.list()) end)
  end

  @doc "`POST /v1/evidence/retention/holds`"
  @spec hold(Plug.Conn.t()) :: Plug.Conn.t()
  def hold(%Plug.Conn{body_params: request} = conn) do
    capturing(conn, @retention, fn conn, ctx ->
      retention_answer(conn, 201, Retention.hold(request, acts_for(ctx)))
    end)
  end

  @doc """
  `POST /v1/evidence/disclosures`: provide named records to someone
  outside the deployment. Who may is policy: the caller needs
  `DiscloseEvidence`, and `ReadPayload` as well, since what is provided
  is content. Neither is limited to the caller's own records; a
  deployment that lets people publish needs to decide whose.
  """
  @spec disclose(Plug.Conn.t()) :: Plug.Conn.t()
  def disclose(%Plug.Conn{body_params: request} = conn) do
    gated(conn, @disclose, "/v1/evidence/disclosures", fn conn, ctx, _index ->
      with true <- Runtime.running?() || :not_running,
           :ok <- content_allowed(conn, true, "/v1/evidence/export") do
        # Whoever asked is on the record, person or service.
        case Disclosing.disclose(request, caller(ctx).principal) do
          {:ok, body} ->
            json(conn, 201, body)

          {:error, reason} when reason in [:stream_fork_refused, :gateway_may_not_record_this] ->
            json(conn, 409, %{"error" => Atom.to_string(reason)})

          # Nothing was recorded; the same request can be sent again.
          {:error, :key_service_unavailable} ->
            json(conn, 503, %{"error" => "key_service_unavailable"})

          {:error, reason} ->
            json(conn, 422, %{"error" => Atom.to_string(reason)})
        end
      else
        :not_running -> not_found(conn)
        {:forbidden, error} -> Authz.dispatch_gate_error(conn, error)
      end
    end)
  end

  @doc """
  `GET /v1/public/evidence/:ref`: a record that was provided to the
  public, with no login. Answers 404 for anything else, and for
  everything when the deployment has not switched public reading on, so
  the route never says whether a record exists. 503 when too many are
  being put together at once.
  """
  @spec public(Plug.Conn.t()) :: Plug.Conn.t()
  def public(%Plug.Conn{path_params: %{"ref" => ref}} = conn) do
    case Disclosing.public_bundle(ref) do
      {:ok, text} ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.put_resp_header("cache-control", "public, max-age=300")
        |> Plug.Conn.send_resp(200, text)

      {:error, :busy} ->
        conn
        |> Plug.Conn.put_resp_header("retry-after", "2")
        |> json(503, %{"error" => "busy"})

      {:error, :not_public} ->
        json(conn, 404, %{"error" => "not_found"})
    end
  end

  @doc "`POST /v1/evidence/retention/holds/release/prepare`"
  @spec release_prepare(Plug.Conn.t()) :: Plug.Conn.t()
  def release_prepare(%Plug.Conn{body_params: request} = conn) do
    capturing(conn, @retention, fn conn, ctx ->
      case Retention.release_prepare(request, acts_for(ctx)) do
        {:ok, %{payload: payload, ticket: ticket}} ->
          json(conn, 200, %{
            "payloadType" => @payload_type,
            "payload" => Base.encode64(payload),
            "ticket" => ticket
          })

        error ->
          retention_answer(conn, 200, error)
      end
    end)
  end

  @doc "`POST /v1/evidence/retention/holds/release/finalize`"
  @spec release_finalize(Plug.Conn.t()) :: Plug.Conn.t()
  def release_finalize(%Plug.Conn{body_params: request} = conn) do
    capturing(conn, @retention, fn conn, _ctx ->
      retention_answer(conn, 201, Retention.release_finalize(request))
    end)
  end

  @doc "`POST /v1/evidence/retention/disposals`"
  @spec dispose(Plug.Conn.t()) :: Plug.Conn.t()
  def dispose(%Plug.Conn{body_params: request} = conn) do
    capturing(conn, @retention, fn conn, ctx ->
      retention_answer(conn, 201, Retention.dispose(request, acts_for(ctx)))
    end)
  end

  # Retention records are written by the capturing gateway, so these
  # routes answer only on a node that is capturing.
  defp capturing(conn, action, fun) do
    gated(conn, action, "/v1/evidence/retention", fn conn, ctx, _index ->
      if Runtime.running?(), do: fun.(conn, ctx), else: not_found(conn)
    end)
  end

  defp retention_answer(conn, status, {:ok, body}), do: json(conn, status, body)

  defp retention_answer(conn, _status, {:error, :malformed_request}),
    do: bad_request(conn, "the request does not describe a hold, a release or a disposal")

  defp retention_answer(conn, _status, {:error, :nothing_to_dispose}),
    do:
      json(conn, 409, %{
        "error" => "ERR_NOTHING_TO_DISPOSE",
        "message" =>
          "No content key is held for this scope, so nothing would be made unreadable: " <>
            "its content was never encrypted, or was disposed of before. Nothing was recorded."
      })

  # Another request took the next position on the stream; ask again.
  defp retention_answer(conn, _status, {:error, reason})
       when reason in [:stream_fork_refused, :not_next_in_stream],
       do: json(conn, 409, %{"error" => "retention_stream_moved"})

  # On the record, and its locks not yet added because the key service
  # could not be reached.
  defp retention_answer(conn, _status, {:error, {:hold_recorded_not_applied, ref}}),
    do:
      json(conn, 503, %{
        "error" => "hold_recorded_not_applied",
        "hold" => ref,
        "message" =>
          "The hold is recorded and no disposal will be made over it. The key service " <>
            "could not be reached, so its locks on the content are added when the gateway next starts."
      })

  defp retention_answer(conn, _status, {:error, {reason, ref}}) when is_atom(reason),
    do: json(conn, 409, %{"error" => Atom.to_string(reason), "about" => ref})

  defp retention_answer(conn, _status, {:error, reason}) when is_atom(reason),
    do: json(conn, 422, %{"error" => Atom.to_string(reason)})

  defp retention_answer(conn, _status, {:error, _other}),
    do: json(conn, 422, %{"error" => "not_recorded"})

  # A person's badge acts for that person; a service's acts for nobody
  # but itself. Never taken from the request.
  defp acts_for(%IdentityContext{
         tenant_id: tenant,
         principal: %{kind: :obo_human, subject: subject}
       })
       when is_binary(subject),
       do: "urn:r5e:principal:#{SessionName.encode(tenant)}:" <> SessionName.encode(subject)

  defp acts_for(_ctx), do: nil

  defp enrolment_error(conn, :gateway_has_no_endorsement),
    do: json(conn, 409, %{"error" => "gateway_has_no_endorsement"})

  defp enrolment_error(conn, reason), do: json(conn, 422, %{"error" => Atom.to_string(reason)})

  # -- shared ------------------------------------------------------------

  defp gated(conn, action, endpoint, fun) do
    case Authz.gate(conn, action, resource(endpoint)) do
      {:ok, conn, %IdentityContext{} = ctx, _bundle_ref} ->
        case index_for(ctx) do
          {:ok, index} -> fun.(conn, ctx, index)
          :error -> not_found(conn)
        end

      error ->
        Authz.dispatch_gate_error(conn, error)
    end
  end

  # Asking for content needs the right to read payloads too.
  defp content_allowed(_conn, false, _endpoint), do: :ok

  defp content_allowed(conn, true, endpoint) do
    case Authz.gate(conn, @payload, resource(endpoint)) do
      {:ok, _conn, _ctx, _bundle_ref} -> :ok
      error -> {:forbidden, error}
    end
  end

  # The deployment's store, when the caller belongs to the deployment's tenant.
  defp index_for(%IdentityContext{tenant_id: tenant}) do
    case ProviderRegistry.fetch() do
      {:ok, %{tenant_id: ^tenant}} when is_binary(tenant) ->
        deployment = Application.get_env(:recurse_gateway, :evidence_deployment, "default")
        {:ok, Runtime.store(deployment)}

      _ ->
        :error
    end
  end

  # The recorded name of the session a reader asked for. A recorded
  # name carries its owner's fingerprint, which a reader looking for
  # "session abc" does not know, so three forms are taken: the whole
  # recorded name, the part after the tenant (`<fingerprint>.<id>`), or
  # the id alone. An id alone is looked up among the caller's tenant's
  # sessions; when different people used the same id the reader is given
  # the names to choose from. Nothing outside the caller's tenant is ever
  # matched.
  defp named(%IdentityContext{tenant_id: tenant}, asked, {module, handle}) do
    prefix = "urn:r5e:session:" <> SessionName.encode(tenant) <> ":"

    cond do
      String.starts_with?(asked, "urn:r5e:session:") ->
        if String.starts_with?(asked, prefix) and match?({:ok, _}, SessionName.parts(asked)),
          do: {:ok, asked},
          else: :none

      match?({:ok, _}, SessionName.parts(prefix <> asked)) and
          match?({:ok, [_ | _]}, module.by_session(handle, prefix <> asked)) ->
        {:ok, prefix <> asked}

      true ->
        case module.sessions_named(handle, prefix, SessionName.encode(asked)) do
          [session] -> {:ok, session}
          [_, _ | _] = sessions -> {:many, sessions}
          [] -> :none
        end
    end
  end

  defp several(conn, sessions),
    do: json(conn, 409, %{"error" => "more_than_one_session_has_this_id", "sessions" => sessions})

  defp resource(endpoint) do
    %{
      type: "Recurse::Resource::AuditEndpoint",
      id: endpoint |> String.trim_leading("/") |> String.replace("/", "_"),
      attrs: %{"endpoint" => endpoint}
    }
  end

  defp render(entry), do: TailSocket.row(entry)

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  defp not_found(conn), do: json(conn, 404, %{"error" => "ERR_NOT_FOUND"})

  defp bad_request(conn, message),
    do: json(conn, 400, %{"error" => "ERR_BAD_REQUEST", "message" => message})
end
