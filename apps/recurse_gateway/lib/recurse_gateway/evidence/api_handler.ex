defmodule Recurse.Gateway.Evidence.ApiHandler do
  @moduledoc """
  Provenance v2 evidence over HTTP.

    * `GET  /v1/evidence/records/:ref` — one signed record by its
      `evidence:sha256:…` reference.
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
      content. Body: `{"scope", "reason", "action"?}`.
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
  as well when an export asks for content, `EnrolWorkload` to be
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
  a session's records are returned whole, without paging.
  """

  alias Recurse.Gateway.AuditPlane.Authz
  alias Recurse.Gateway.ProviderRegistry
  alias Recurse.Gateway.Provenance.{Admission, Carried, Disclosing, Enrolment, Retention, Runtime}
  alias Recurse.Gateway.Provenance.SessionName
  alias Recurse.Provenance.{Export, Exporter, Key, Ref}
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
      with :ok <- content_allowed(conn, content?),
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
           :ok <- content_allowed(conn, true) do
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
  defp content_allowed(_conn, false), do: :ok

  defp content_allowed(conn, true) do
    case Authz.gate(conn, @payload, resource("/v1/evidence/export")) do
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

  defp render(entry) do
    %{
      "ref" => entry.ref,
      "stream" => entry.stream,
      "seq" => entry.seq,
      "kind" => entry.kind_path,
      "capturedAt" => entry.evidence["capturedAt"],
      "envelope" => entry.envelope
    }
  end

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, JSON.encode!(body))
  end

  defp not_found(conn), do: json(conn, 404, %{"error" => "ERR_NOT_FOUND"})

  defp bad_request(conn, message),
    do: json(conn, 400, %{"error" => "ERR_BAD_REQUEST", "message" => message})
end
