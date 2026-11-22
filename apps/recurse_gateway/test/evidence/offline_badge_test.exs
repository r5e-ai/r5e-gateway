defmodule Recurse.Gateway.Evidence.OfflineBadgeTest do
  @moduledoc """
  A workload badge a root gave offline (A5/A8): handed over on
  `POST /v1/deployment/grants`, held to the same bounds as an enrolled
  badge, sealed before anything is taken under it, bound to the person
  it acts for, and ended by a root's, issuer's, or subject's revocation
  of it or of anything above it.

  `async: false` because evidence capture is node-wide.
  """
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  alias Ecto.Adapters.SQL.Sandbox
  alias Recurse.Gateway.Evidence.ClaimHandler

  alias Recurse.Gateway.Provenance.{
    Admission,
    Carried,
    Claim,
    Grants,
    OfflineBadges,
    Roots,
    Runtime
  }

  alias Recurse.Provenance.{Body, Definitions, Envelope, Evidence, Export, Exporter, Key}
  alias Recurse.Provenance.{Profile, Publication, Ref}
  alias Recurse.Providers.Impls.{LocalKeyService, PostgresEvidenceStore}
  alias Recurse.Providers.Repo

  @base "provenance.r5e.io/v2/"
  @args ~s({"command":"ls"})
  @dana "urn:r5e:principal:test:dana"
  @eve "urn:r5e:principal:test:eve"
  @custodian_id "mailto:lena@example.com"

  setup %{tmp_dir: dir} do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    key_file = Path.join(dir, "content.key")
    :ok = LocalKeyService.generate(key_file)
    {:ok, keys} = LocalKeyService.open(key_file)
    store = {PostgresEvidenceStore, %{repo: Repo, keys: {LocalKeyService, keys}}}

    publisher = Key.generate("ed25519")
    {:ok, published} = Publication.issue(publisher, name: "test-steward")
    deployment = "offline-#{System.unique_integer([:positive])}"
    gateway_signer = Key.generate("ed25519")
    evidence_dir = Path.join(dir, "evidence")

    runtime_opts = [
      deployment: deployment,
      signer: gateway_signer,
      store: store,
      dir: evidence_dir,
      partitions: 1,
      flush_interval_ms: 20,
      start_chain?: true,
      retention: {:keep_for_seconds, 0},
      publications: [published]
    ]

    start_supervised!({Runtime, runtime_opts})

    on_exit(fn -> :persistent_term.erase({Runtime, :info}) end)

    eventually(fn ->
      with %{"state" => "unclaimed"} = found <- Claim.describe(), do: found, else: (_ -> nil)
    end)

    root = Key.generate("ed25519")
    root2 = Key.generate("ed25519")
    custodian = Key.generate("ed25519")
    chain = claim(evidence_dir, [root, root2], custodian)

    # The gateway's own grant, so that it can seal and open sessions.
    {:ok, [gateway_grant]} =
      Grants.accept(
        grant(root, deployment, Runtime.info().key_id, ~w[EpochSeal SessionOpened Revocation])
      )

    %{
      store: store,
      deployment: deployment,
      evidence_dir: evidence_dir,
      runtime_opts: runtime_opts,
      publisher: publisher,
      root: root,
      root2: root2,
      custodian: custodian,
      gateway_grant: gateway_grant,
      chain: chain,
      issuer: Key.generate("ed25519"),
      helper: Key.generate("ed25519")
    }
  end

  # -- building what a root ceremony makes --------------------------------------

  defp eventually(check, tries \\ 100) do
    case check.() do
      nil when tries > 0 ->
        Process.sleep(20)
        eventually(check, tries - 1)

      found ->
        found
    end
  end

  defp ensure_sandbox_shared do
    case Sandbox.checkout(Repo) do
      :ok -> :ok
      {:already, _} -> :ok
    end

    Sandbox.mode(Repo, {:shared, self()})
  end

  defp restart_runtime(runtime_opts) do
    stop_supervised!(Runtime)
    :persistent_term.erase({Runtime, :info})
    ensure_sandbox_shared()
    start_supervised!({Runtime, runtime_opts})

    eventually(fn ->
      if Runtime.running?(), do: :ok, else: nil
    end)
  end

  defp wire_key(signer),
    do: %{
      "keyid" => signer.key_id,
      "algorithm" => signer.algorithm,
      "bytes" => Base.encode64(signer.public_key)
    }

  defp public_key(signer),
    do: %{"algorithm" => signer.algorithm, "bytes" => Base.encode64(signer.public_key)}

  defp hex(signer), do: signer.key_id |> String.split(":") |> List.last()
  defp token(n), do: :crypto.strong_rand_bytes(n) |> Base.encode16(case: :lower)

  defp iso(seconds),
    do:
      DateTime.utc_now()
      |> DateTime.add(seconds)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

  defp profile(stream_prefix, issuer, retention \\ nil, policy_required_kinds \\ []) do
    {:ok, profile} =
      Profile.new(
        bindings: [
          %{
            stream_prefix: stream_prefix,
            actor_prefixes: ["urn:r5e:"],
            issuer_keys: [issuer.key_id],
            sealer_keys: []
          }
        ],
        failure_domain: "made offline",
        deployment_policy_ref: Ref.bytes("root"),
        policy_required_kinds: policy_required_kinds,
        retention: retention
      )

    profile
  end

  defp blob(profile) do
    encoded = Profile.encode(profile)
    %{"ref" => Ref.bytes(encoded), "base64" => Base.encode64(encoded)}
  end

  defp schema(kind), do: elem(Definitions.fetch(@base <> kind), 1).ref

  defp grant(root, deployment, subject, kinds) do
    stream =
      "urn:r5e:stream:#{deployment}:authority:root:#{hex(root)}:grant:#{token(8)}"

    profile = profile("urn:r5e:stream:#{deployment}:authority:root:#{hex(root)}", root)

    evidence =
      Evidence.new(
        kind_path: @base <> "Endorsement",
        schema_ref: schema("Endorsement"),
        profile_ref: Profile.ref(profile),
        issuer: root.key_id,
        actor: "urn:r5e:operator:root",
        stream: stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{
          "subject" => subject,
          "kinds" => Enum.map(kinds, &(@base <> &1)),
          "streamPrefixes" => ["urn:r5e:stream:#{deployment}:"],
          "mayEndorse" => false,
          "notBefore" => iso(-60),
          "notAfter" => iso(86_400)
        }
      )

    {:ok, signed} = Envelope.sign(evidence, root)

    %{
      "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
      "keys" => [wire_key(root)],
      "blobs" => [blob(profile)]
    }
  end

  defp claim(dir, roots, custodian) do
    code = dir |> Path.join("claim.code") |> File.read!()
    [primary | _] = roots

    root_entries =
      for r <- roots do
        %{
          "publicKey" => public_key(r),
          "holder" => "person",
          "custody" => "hardware"
        }
      end

    {:ok, %{"payload" => payload, "ticket" => ticket}} =
      Claim.prepare(%{
        "code" => code,
        "claimedBy" => primary.key_id,
        "roots" => root_entries,
        "threshold" => 1,
        "custodians" => [%{"identity" => @custodian_id, "key" => custodian.key_id}]
      })

    {:ok, signature} = primary.sign.(Envelope.message(Base.decode64!(payload)))

    {:ok, :created, %{"chain" => chain}} =
      Claim.finalize(%{
        "code" => code,
        "payload" => payload,
        "ticket" => ticket,
        "rootSignature" => %{"keyid" => primary.key_id, "sig" => Base.encode64(signature)}
      })

    chain
  end

  # A root endorses an issuing key, which gives the workload its badge.
  # `e` and `b` override the endorsement's and the badge's bodies.
  defp offline(ctx, opts \\ []) do
    %{deployment: dep, root: root, issuer: issuer, helper: helper} = ctx
    prefix = Keyword.get(opts, :prefix, "urn:r5e:stream:#{dep}:endpoint:offline-#{token(12)}:")
    top = Keyword.get(opts, :top, root)

    e_stream =
      Keyword.get(
        opts,
        :e_stream,
        "urn:r5e:stream:#{dep}:authority:root:#{hex(top)}:grant:#{token(8)}"
      )

    e_profile = profile("urn:r5e:stream:#{dep}:authority:root:#{hex(top)}", top)

    endorsement =
      Keyword.get_lazy(opts, :endorsement, fn ->
        evidence =
          Evidence.new(
            kind_path: @base <> "Endorsement",
            schema_ref: schema("Endorsement"),
            profile_ref: Profile.ref(e_profile),
            issuer: top.key_id,
            actor: "urn:r5e:operator:root",
            stream: e_stream,
            seq: 1,
            previous: nil,
            captured_at: DateTime.utc_now(),
            body:
              Map.merge(
                %{
                  "subject" => issuer.key_id,
                  "kinds" => [@base <> "ToolCall"],
                  "streamPrefixes" => [prefix],
                  "actorPrefixes" => ["urn:r5e:agent:"],
                  "actsFor" => @dana,
                  "mayEndorse" => true,
                  "notBefore" => iso(-60),
                  "notAfter" => iso(7200)
                },
                Keyword.get(opts, :e, %{})
              )
          )

        {:ok, signed} = Envelope.sign(evidence, top)
        signed
      end)

    b_stream =
      Keyword.get(opts, :b_stream, "urn:r5e:stream:#{dep}:authority:badge:offline-#{token(12)}")

    b_profile = profile("urn:r5e:stream:#{dep}:authority:badge:", issuer)

    evidence =
      Evidence.new(
        kind_path: @base <> "Badge",
        schema_ref: schema("Badge"),
        profile_ref: Profile.ref(b_profile),
        issuer: issuer.key_id,
        actor: "urn:r5e:operator:root",
        stream: b_stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body:
          Map.merge(
            %{
              "subject" => helper.key_id,
              "subjectKey" => public_key(helper),
              "holder" => "endpoint-helper",
              "kinds" => [@base <> "ToolCall"],
              "streamPrefixes" => [prefix],
              "actorPrefixes" => ["urn:r5e:agent:"],
              "actsFor" => @dana,
              "parent" => endorsement.ref,
              "notBefore" => iso(-30),
              "notAfter" => iso(3600)
            },
            Keyword.get(opts, :b, %{})
          )
          |> Map.reject(fn {_k, v} -> v == :drop end)
      )

    {:ok, payload} = Evidence.encode(evidence)
    message = Envelope.message(payload)
    {:ok, by_issuer} = issuer.sign.(message)
    {:ok, by_helper} = helper.sign.(message)

    envelope =
      Envelope.assemble(payload, [{issuer.key_id, by_issuer}, {helper.key_id, by_helper}])

    {:ok, %{ref: badge_ref}} = Envelope.open(envelope)

    set = %{
      "records" => [
        %{"ref" => endorsement.ref, "envelope" => endorsement.envelope},
        %{"ref" => badge_ref, "envelope" => envelope}
      ],
      "keys" => Enum.uniq_by([wire_key(top), wire_key(issuer), wire_key(helper)], & &1["keyid"]),
      "blobs" => [blob(e_profile), blob(b_profile)]
    }

    %{
      set: set,
      badge: badge_ref,
      endorsement: endorsement.ref,
      prefix: prefix,
      b_stream: b_stream,
      e_profile_ref: Profile.ref(e_profile),
      b_profile_ref: Profile.ref(b_profile)
    }
  end

  defp record(ctx, prefix, session, {seq, previous}, about \\ @dana, opts \\ []) do
    retention = Keyword.get(opts, :retention, {:keep_for_seconds, 0})
    policy_required_kinds = Keyword.get(opts, :policy_required_kinds, [])
    policy_eval = Keyword.get(opts, :policy, nil)
    rec_profile = profile(prefix, ctx.helper, retention, policy_required_kinds)

    evidence =
      Evidence.new(
        kind_path: @base <> "ToolCall",
        schema_ref: schema("ToolCall"),
        profile_ref: Profile.ref(rec_profile),
        issuer: ctx.helper.key_id,
        actor: "urn:r5e:agent:claude-code",
        stream: prefix <> "s",
        seq: seq,
        previous: previous,
        captured_at: DateTime.utc_now(),
        session: session,
        on_behalf_of: about,
        body:
          Body.tool_call(
            tool: "Bash",
            content_ref: Ref.bytes(@args),
            media_type: "application/json",
            size: byte_size(@args),
            policy: policy_eval
          )
      )

    {:ok, signed} = Envelope.sign(evidence, ctx.helper)

    batch = %{
      "records" => [%{"envelope" => signed.envelope}],
      "keys" => [wire_key(ctx.helper)],
      "blobs" => [
        blob(rec_profile),
        %{"ref" => Ref.bytes(@args), "base64" => Base.encode64(@args)}
      ]
    }

    {signed, batch}
  end

  defp session(principal) do
    {:ok, :opened, %{"session" => session}} =
      Admission.open_session(%{}, %{tenant: "test", principal: principal})

    session
  end

  defp revocation(signer, deployment, target, captured_at \\ DateTime.utc_now()) do
    stream =
      "urn:r5e:stream:#{deployment}:authority:revocation:#{System.unique_integer([:positive])}"

    rev_profile = profile(stream, signer)

    evidence =
      Evidence.new(
        kind_path: @base <> "Revocation",
        schema_ref: schema("Revocation"),
        profile_ref: Profile.ref(rev_profile),
        issuer: signer.key_id,
        actor: "urn:r5e:operator:root",
        stream: stream,
        seq: 1,
        previous: nil,
        captured_at: captured_at,
        body: %{"target" => target, "reason" => "the laptop was lost"}
      )

    {:ok, signed} = Envelope.sign(evidence, signer)

    %{
      "records" => [%{"ref" => signed.ref, "envelope" => signed.envelope}],
      "keys" => [wire_key(signer)],
      "blobs" => [blob(rev_profile)]
    }
  end

  # -- the route and its rules ---------------------------------------------------

  test "a root's offline badge is taken and sealed; records under it are admitted and export with full chain, profiles, and keys",
       ctx do
    %{
      set: set,
      badge: badge,
      endorsement: endorsement,
      prefix: prefix,
      e_profile_ref: e_profile_ref,
      b_profile_ref: b_profile_ref
    } = offline(ctx)

    assert OfflineBadges.badge_set?(set)

    assert {:ok, :created,
            %{"badge" => ^badge, "sealed" => true, "recorded" => [^endorsement, ^badge]}} =
             OfflineBadges.accept(set)

    # Offered again: the same answer, nothing new.
    assert {:ok, :already, %{"badge" => ^badge, "sealed" => true}} = OfflineBadges.accept(set)

    # Not among the grants the gateway acts under itself (`grants.json`).
    refute Enum.any?(Grants.list(), &(&1["ref"] == badge))
    grants_json = File.read!(Path.join(Runtime.info().dir, "grants.json"))
    refute grants_json =~ badge
    refute grants_json =~ endorsement

    session = session(@dana)
    {first, batch} = record(ctx, prefix, session, {1, nil})

    assert {:ok, [%{"status" => "admitted", "contentHeld" => [_]}]} =
             Admission.submit(batch, %{tenant: "test", principal: @dana})

    assert {:ok, [_ | _]} = Runtime.seal()
    {:ok, raw_bundle} = Exporter.session(ctx.store, session, content: true)
    carried = Carried.carry(raw_bundle)
    report = Export.verify(carried, trusted_chain: ctx.chain)
    assert [] == Enum.reject(report.findings, &(&1.result == :ok or &1.check == :publication))

    assert [%{result: :ok}] =
             Enum.filter(report.findings, &(&1.subject == first.ref and &1.check == :authority))

    # The export carries E, Badge, both CaptureProfile blobs, and K's, root's, and W's keys.
    record_refs = MapSet.new(carried["records"], & &1["ref"])
    assert MapSet.member?(record_refs, endorsement)
    assert MapSet.member?(record_refs, badge)

    blob_refs = MapSet.new(carried["blobs"], & &1["ref"])
    assert MapSet.member?(blob_refs, e_profile_ref)
    assert MapSet.member?(blob_refs, b_profile_ref)

    key_ids = MapSet.new(carried["keys"], & &1["keyid"])
    assert MapSet.member?(key_ids, ctx.root.key_id)
    assert MapSet.member?(key_ids, ctx.issuer.key_id)
    assert MapSet.member?(key_ids, ctx.helper.key_id)
  end

  test "the route dispatches offline badge sets and preserves non-badge Grants.accept unchanged",
       ctx do
    %{set: set} = offline(ctx)

    conn = fn body ->
      ClaimHandler.grants(%{
        Plug.Test.conn(:post, "/v1/deployment/grants", "")
        | body_params: body
      })
    end

    assert %{status: 201} = conn.(set)
    assert %{status: 200} = conn.(set)

    %{set: bad} = offline(ctx, b: %{"actsFor" => :drop}, e: %{"actsFor" => nil})
    assert %{status: 422, resp_body: body} = conn.(bad)
    assert body =~ "badge_must_act_for_someone"

    # Non-badge gateway grant still dispatches to `Grants.accept`, and a non-badge
    # endorsement naming another key still returns `no_grant_names_this_gateway`.
    gw_grant = grant(ctx.root2, ctx.deployment, Runtime.info().key_id, ~w[EpochSeal])
    refute OfflineBadges.badge_set?(gw_grant)
    assert %{status: 201, resp_body: gw_body} = conn.(gw_grant)
    assert gw_body =~ "recorded"

    other_grant = grant(ctx.root2, ctx.deployment, ctx.helper.key_id, ~w[ToolCall])
    refute OfflineBadges.badge_set?(other_grant)
    assert %{status: 422, resp_body: other_body} = conn.(other_grant)
    assert other_body =~ "no_grant_names_this_gateway"
  end

  test "held to the bounds of an enrolled badge, no wider above it, and stream forks never half-record",
       ctx do
    dep = ctx.deployment
    wide = "urn:r5e:stream:#{dep}:"

    ten_years =
      DateTime.utc_now()
      |> DateTime.add(10 * 365 * 86_400)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

    cases = [
      {[b: %{"actsFor" => :drop}], :badge_must_act_for_someone},
      {[prefix: "urn:r5e:stream:#{dep}:endpoint:abcdefghijklmnop:"],
       :badge_streams_not_offline_endpoint},
      {[prefix: "urn:r5e:stream:other:endpoint:offline-#{token(12)}:"],
       :badge_streams_not_offline_endpoint},
      {[e: %{"streamPrefixes" => [wide]}], :endorsement_wider_than_badge},
      {[e: %{"actsFor" => @eve}], :endorsement_wider_than_badge},
      {[e: %{"kinds" => [@base <> "ToolCall", @base <> "EpochSeal"]}],
       :kind_not_admissible_from_workload},
      {[
         e: %{"kinds" => [@base <> "ToolCall", @base <> "Badge"]},
         b: %{"kinds" => [@base <> "Badge"]}
       ], :kind_not_admissible_from_workload},
      {[e: %{"notAfter" => ten_years}, b: %{"notAfter" => ten_years}], :window_too_long},
      {[e: %{"notAfter" => ten_years}], :window_too_long},
      {[
         e: %{"notBefore" => iso(-3600), "notAfter" => iso(-60)},
         b: %{"notBefore" => iso(-1800), "notAfter" => iso(-60)}
       ], :not_in_force},
      {[top: ctx.helper], :grant_not_from_a_current_root}
    ]

    for {opts, error} <- cases do
      %{set: set} = offline(ctx, opts)
      assert {:error, ^error} = OfflineBadges.accept(set), inspect({opts, error})
    end

    # A set that is not exactly one chain.
    %{set: one} = offline(ctx)
    %{set: two} = offline(ctx)
    extra = %{one | "records" => one["records"] ++ [hd(two["records"])]}
    assert {:error, :set_is_not_one_chain} = OfflineBadges.accept(extra)
    lone = %{one | "records" => tl(one["records"])}
    assert {:error, :set_is_not_one_chain} = OfflineBadges.accept(lone)

    # Signatures and bodies are read as any reader would.
    [e, b] = one["records"]
    forged = put_in(b, ["envelope", "signatures"], Enum.reverse(b["envelope"]["signatures"]))
    assert {:error, _} = OfflineBadges.accept(%{one | "records" => [e, forged]})

    # Nothing refused was recorded.
    {module, handle} = ctx.store
    assert :error = module.fetch(handle, b["ref"])

    # A stream collision on `Badge` refuses the whole set without recording `E`.
    %{set: accepted, b_stream: taken_b_stream} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(accepted)

    other_ctx = %{ctx | helper: Key.generate("ed25519")}
    %{set: colliding, endorsement: colliding_e} = offline(other_ctx, b_stream: taken_b_stream)
    assert {:error, :stream_fork_refused} = OfflineBadges.accept(colliding)
    assert :error = module.fetch(handle, colliding_e)
  end

  test "a stream prefix belongs to the first key a badge gave it to, survives missing local state, and supports renewal",
       ctx do
    %{set: set, badge: first_badge, prefix: prefix} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set)

    other = %{ctx | helper: Key.generate("ed25519")}
    %{set: again} = offline(other, prefix: prefix)
    assert {:error, :stream_prefix_taken} = OfflineBadges.accept(again)

    taken_conn =
      ClaimHandler.grants(%{
        Plug.Test.conn(:post, "/v1/deployment/grants", "")
        | body_params: again
      })

    assert taken_conn.status == 409
    assert %{"error" => "stream_prefix_taken"} = JSON.decode!(taken_conn.resp_body)

    # Even if `offline-badges.json` is deleted, the DB index still protects the prefix.
    File.rm!(Path.join(Runtime.info().dir, "offline-badges.json"))
    assert {:error, :stream_prefix_taken} = OfflineBadges.accept(again)

    # Revoke the first badge, then renew the SAME workload key on the SAME stream prefix:
    # registration succeeds AND new records are admitted under the renewed badge.
    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)
    {r1, batch1} = record(ctx, prefix, session, {1, nil})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch1, caller)

    assert {:ok, [_]} = Grants.revoke(revocation(ctx.root, ctx.deployment, first_badge))
    {_r2_refused, batch2} = record(ctx, prefix, session, {2, r1.ref})
    assert {:error, :authority_ended} = Admission.submit(batch2, caller)

    %{set: renewed} = offline(ctx, prefix: prefix)
    assert {:ok, :created, _} = OfflineBadges.accept(renewed)
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch2, caller)
  end

  test "records under the badge must be about, and submitted by, the person it acts for", ctx do
    %{set: set, prefix: prefix} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set)

    eves = session(@eve)
    {_r, batch} = record(ctx, prefix, eves, {1, nil}, @eve)

    assert {:error, :badge_does_not_act_for_caller} =
             Admission.submit(batch, %{tenant: "test", principal: @eve})

    danas = session(@dana)
    {_r, batch} = record(ctx, prefix, danas, {1, nil}, @dana)

    assert {:error, :record_is_not_about_the_caller} =
             Admission.submit(batch, %{tenant: "test", principal: @eve})
  end

  test "a root takes the badge back, or the endorsement above it; nothing more is taken and it is not taken again",
       ctx do
    %{set: set, badge: badge, prefix: prefix} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set)
    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)

    {first, batch} = record(ctx, prefix, session, {1, nil})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch, caller)

    # The gateway did not issue it and cannot take it back.
    assert {:error, :no_such_badge} = Admission.revoke_badge(badge, "not ours")

    assert {:ok, [_]} = Grants.revoke(revocation(ctx.root, ctx.deployment, badge))
    {_second, batch} = record(ctx, prefix, session, {2, first.ref})
    assert {:error, :authority_ended} = Admission.submit(batch, caller)
    assert {:error, :badge_taken_back} = OfflineBadges.accept(set)

    # A new badge for another workload under a new endorsement; the root
    # takes back the endorsement, which ends the badge below it.
    other = %{ctx | helper: Key.generate("ed25519")}
    %{set: set2, endorsement: e2, prefix: prefix2} = offline(other)
    assert {:ok, :created, _} = OfflineBadges.accept(set2)
    {r1, batch} = record(other, prefix2, session, {1, nil})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch, caller)

    assert {:ok, [_]} = Grants.revoke(revocation(ctx.root, ctx.deployment, e2))
    {_r2, batch} = record(other, prefix2, session, {2, r1.ref})
    assert {:error, :authority_ended} = Admission.submit(batch, caller)

    # And a further badge under the endorsement that was taken back is refused.
    third = %{ctx | helper: Key.generate("ed25519")}
    [e2_record | _] = set2["records"]
    {:ok, %{evidence: e2_evidence}} = Envelope.open(e2_record["envelope"])
    endorsement = %{ref: e2, envelope: e2_record["envelope"]}

    %{set: set3} =
      offline(third, endorsement: endorsement, prefix: hd(e2_evidence["body"]["streamPrefixes"]))

    assert {:error, error} = OfflineBadges.accept(set3)
    assert error in [:badge_taken_back, :stream_prefix_taken]
  end

  test "chained multi-root and multi-link delegation (`R1 -> R2 -> D -> W`) matching r5e-endpoint-helper streams",
       ctx do
    dep = ctx.deployment
    tok24 = token(12)
    prefix = "urn:r5e:stream:#{dep}:endpoint:offline-#{tok24}:"
    delegator = Key.generate("ed25519")
    helper = Key.generate("ed25519")

    e0_stream = "urn:r5e:stream:#{dep}:authority:root:#{hex(ctx.root)}:grant:#{token(8)}"
    e0_prof = profile(e0_stream, ctx.root)

    {:ok, e0} =
      Evidence.new(
        kind_path: @base <> "Endorsement",
        schema_ref: schema("Endorsement"),
        profile_ref: Profile.ref(e0_prof),
        issuer: ctx.root.key_id,
        actor: "urn:r5e:operator:root",
        stream: e0_stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{
          "subject" => ctx.root2.key_id,
          "kinds" => [@base <> "ToolCall"],
          "streamPrefixes" => [prefix],
          "actorPrefixes" => ["urn:r5e:agent:"],
          "actsFor" => @dana,
          "mayEndorse" => true,
          "notBefore" => iso(-60),
          "notAfter" => iso(3600)
        }
      )
      |> Envelope.sign(ctx.root)

    # Second root signs intermediate Endorsement on `authority:delegation:<16hex>`
    # (exact stream emitted by `r5e-endpoint-helper` for `idx > 0`).
    e1_stream = "urn:r5e:stream:#{dep}:authority:delegation:#{token(8)}"
    e1_prof = profile(e1_stream, ctx.root2)

    {:ok, e1} =
      Evidence.new(
        kind_path: @base <> "Endorsement",
        schema_ref: schema("Endorsement"),
        profile_ref: Profile.ref(e1_prof),
        issuer: ctx.root2.key_id,
        actor: "urn:r5e:operator:root",
        stream: e1_stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{
          "parent" => e0.ref,
          "subject" => delegator.key_id,
          "kinds" => [@base <> "ToolCall"],
          "streamPrefixes" => [prefix],
          "actorPrefixes" => ["urn:r5e:agent:"],
          "actsFor" => @dana,
          "mayEndorse" => true,
          "notBefore" => iso(-60),
          "notAfter" => iso(3600)
        }
      )
      |> Envelope.sign(ctx.root2)

    b_stream = "urn:r5e:stream:#{dep}:authority:badge:offline-#{tok24}"
    b_prof = profile(b_stream, delegator)

    b_ev =
      Evidence.new(
        kind_path: @base <> "Badge",
        schema_ref: schema("Badge"),
        profile_ref: Profile.ref(b_prof),
        issuer: delegator.key_id,
        actor: "urn:r5e:operator:root",
        stream: b_stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{
          "parent" => e1.ref,
          "subject" => helper.key_id,
          "subjectKey" => public_key(helper),
          "holder" => "endpoint-helper",
          "kinds" => [@base <> "ToolCall"],
          "streamPrefixes" => [prefix],
          "actorPrefixes" => ["urn:r5e:agent:"],
          "actsFor" => @dana,
          "notBefore" => iso(-30),
          "notAfter" => iso(3600)
        }
      )

    {:ok, b_payload} = Evidence.encode(b_ev)
    b_msg = Envelope.message(b_payload)
    {:ok, sig1} = delegator.sign.(b_msg)
    {:ok, sig2} = helper.sign.(b_msg)

    b_env =
      Envelope.assemble(b_payload, [{delegator.key_id, sig1}, {helper.key_id, sig2}])

    {:ok, %{ref: b_ref}} = Envelope.open(b_env)

    set = %{
      "records" => [
        %{"ref" => e0.ref, "envelope" => e0.envelope},
        %{"ref" => e1.ref, "envelope" => e1.envelope},
        %{"ref" => b_ref, "envelope" => b_env}
      ],
      "keys" => Enum.map([ctx.root, ctx.root2, delegator, helper], &wire_key/1),
      "blobs" => Enum.map([e0_prof, e1_prof, b_prof], &blob/1)
    }

    conn =
      ClaimHandler.grants(%{
        Plug.Test.conn(:post, "/v1/deployment/grants", "")
        | body_params: set
      })

    assert conn.status == 201

    session = session(@dana)
    {_call, batch} = record(%{ctx | helper: helper}, prefix, session, {1, nil})

    assert {:ok, [%{"status" => "admitted"}]} =
             Admission.submit(batch, %{tenant: "test", principal: @dana})

    assert {:ok, [_ | _]} = Runtime.seal()
    {:ok, bundle} = Exporter.session(ctx.store, session, content: true)
    report = Export.verify(Carried.carry(bundle), trusted_chain: ctx.chain)
    assert [] == Enum.reject(report.findings, &(&1.result == :ok or &1.check == :publication))
  end

  test "unregistered badge in `/v1/evidence/records` is refused, and unsealed badge returns 503 and blocks admission until sealed",
       ctx do
    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)

    # 1. Passing an unregistered offline badge inline in `authority` on `/v1/evidence/records`
    # without first registering and sealing on `/v1/deployment/grants` is refused.
    %{set: unreg_set, prefix: unreg_prefix} = offline(ctx)
    {_r, unreg_batch} = record(ctx, unreg_prefix, session, {1, nil})

    assert {:error, :no_standing} =
             Admission.submit(Map.put(unreg_batch, "authority", unreg_set), caller)

    # 2. Revoke the gateway's own grant so sealing cannot happen yet; registering an offline
    # badge records it and returns 503 `badge_recorded_not_sealed`, and Admission refuses
    # records under it with `:badge_not_sealed` until a seal covers the chain.
    assert {:ok, [_]} = Grants.revoke(revocation(ctx.root, ctx.deployment, ctx.gateway_grant))
    assert Runtime.info().authority == nil

    other = %{ctx | helper: Key.generate("ed25519")}
    %{set: set2, prefix: prefix2} = offline(other)

    conn =
      ClaimHandler.grants(%{
        Plug.Test.conn(:post, "/v1/deployment/grants", "")
        | body_params: set2
      })

    assert conn.status == 503
    assert conn.resp_body =~ "badge_recorded_not_sealed"

    {_r2, batch2} = record(other, prefix2, session, {1, nil})
    assert {:error, :badge_not_sealed} = Admission.submit(batch2, caller)

    # Restore a sealing grant to the gateway: Admission seals the waiting chain first and admits.
    assert {:ok, [_]} =
             Grants.accept(
               grant(
                 ctx.root2,
                 ctx.deployment,
                 Runtime.info().key_id,
                 ~w[EpochSeal SessionOpened Revocation]
               )
             )

    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch2, caller)
  end

  test "revocation by ceremony issuer K, by workload W, by stranger (refused), and future-dated revocation (R10); unrelated exports stay clean",
       ctx do
    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)
    stranger = Key.generate("ed25519")

    # 1. Stranger is refused; ceremony issuer K is entitled to revoke Badge.
    %{set: set1, badge: badge1, prefix: prefix1} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set1)
    assert {:error, :not_entitled} = Grants.revoke(revocation(stranger, ctx.deployment, badge1))
    assert {:ok, [_]} = Grants.revoke(revocation(ctx.issuer, ctx.deployment, badge1))
    {_r1, batch1} = record(ctx, prefix1, session, {1, nil})
    assert {:error, :authority_ended} = Admission.submit(batch1, caller)

    # 2. Workload W self-revokes its own Badge after a sealed record; W's session export
    # carries the revocation cleanly AND unrelated exports are not polluted by `grants.json`.
    ctx2 = %{ctx | helper: Key.generate("ed25519")}
    %{set: set2, badge: badge2, prefix: prefix2} = offline(ctx2)
    assert {:ok, :created, _} = OfflineBadges.accept(set2)

    {admitted_call, batch2_first} = record(ctx2, prefix2, session, {1, nil})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch2_first, caller)
    assert {:ok, [_ | _]} = Runtime.seal()
    Process.sleep(10)

    rev_conn =
      ClaimHandler.revocations(%{
        Plug.Test.conn(:post, "/v1/deployment/revocations", "")
        | body_params: revocation(ctx2.helper, ctx.deployment, badge2)
      })

    assert rev_conn.status == 201
    assert %{"recorded" => [rev_ref]} = JSON.decode!(rev_conn.resp_body)
    {_r2_next, batch2_second} = record(ctx2, prefix2, session, {2, admitted_call.ref})
    assert {:error, :authority_ended} = Admission.submit(batch2_second, caller)

    {:ok, w2_bundle} = Exporter.session(ctx.store, session, content: true)
    w2_carried = Carried.carry(w2_bundle)
    assert rev_ref in Enum.map(w2_carried["records"], & &1["ref"])
    w2_report = Export.verify(w2_carried, trusted_chain: ctx.chain)
    assert [] == Enum.reject(w2_report.findings, &(&1.result == :ok or &1.check == :publication))

    {:ok, empty_bundle} = Export.build(records: [])

    unrelated_report =
      Export.verify(Carried.carry(empty_bundle),
        trusted_chain: ctx.chain,
        trusted_publishers: [ctx.publisher.key_id]
      )

    assert [] == Enum.reject(unrelated_report.findings, &(&1.result == :ok))

    # 3. Future-dated Revocation (`capturedAt = now + 3600s`) immediately blocks new admissions (R10).
    ctx3 = %{ctx | helper: Key.generate("ed25519")}
    %{set: set3, badge: badge3, prefix: prefix3} = offline(ctx3)
    assert {:ok, :created, _} = OfflineBadges.accept(set3)

    future = DateTime.add(DateTime.utc_now(), 3600, :second)
    assert {:ok, [_]} = Grants.revoke(revocation(ctx.root, ctx.deployment, badge3, future))
    {_r3, batch3} = record(ctx3, prefix3, session, {1, nil})
    assert {:error, :authority_ended} = Admission.submit(batch3, caller)
    assert {:error, :badge_taken_back} = OfflineBadges.accept(set3)
  end

  test "full Runtime stop and restart preserves standing, carried exports, and revocations (R9)",
       ctx do
    %{set: set, badge: badge, prefix: prefix} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set)

    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)
    {first, batch1} = record(ctx, prefix, session, {1, nil})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch1, caller)

    # Stop and restart the full Runtime supervisor against the same store and directory.
    :ok = restart_runtime(ctx.runtime_opts)

    {second, batch2} = record(ctx, prefix, session, {2, first.ref})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch2, caller)
    assert {:ok, [_ | _]} = Runtime.seal()

    {:ok, bundle} = Exporter.session(ctx.store, session, content: true)
    report = Export.verify(Carried.carry(bundle), trusted_chain: ctx.chain)
    assert [] == Enum.reject(report.findings, &(&1.result == :ok or &1.check == :publication))

    # Revoke, then stop and restart Runtime again: revocation still holds across restart.
    assert {:ok, [_]} = Grants.revoke(revocation(ctx.root, ctx.deployment, badge))
    :ok = restart_runtime(ctx.runtime_opts)

    {_third, batch3} = record(ctx, prefix, session, {3, second.ref})
    assert {:error, :authority_ended} = Admission.submit(batch3, caller)
    assert {:error, :badge_taken_back} = OfflineBadges.accept(set)
  end

  test "retention parity and policy-required kinds (CaptureProfile bounds) are enforced identically to gateway-issued badges",
       ctx do
    %{set: set, prefix: prefix} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set)
    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)

    # Deployment has `retention: {:keep_for_seconds, 0}`, so `retention: nil` (`:never`) is refused.
    {_bad_ret, bad_ret_batch} = record(ctx, prefix, session, {1, nil}, @dana, retention: nil)
    assert {:error, :profile_retention_mismatch} = Admission.submit(bad_ret_batch, caller)

    # Workload profile requiring policy on `ToolCall` refuses a call with no inline
    # policy evaluation, and admits one carrying a `Body.policy_evaluation`.
    {_no_pol, no_pol_batch} =
      record(ctx, prefix, session, {1, nil}, @dana,
        policy_required_kinds: [@base <> "ToolCall"],
        policy: nil
      )

    assert {:error, :profile_bounds_not_satisfied} = Admission.submit(no_pol_batch, caller)

    {_with_pol, with_pol_batch} =
      record(ctx, prefix, session, {1, nil}, @dana,
        policy_required_kinds: [@base <> "ToolCall"],
        policy:
          Body.policy_evaluation(
            policy_ref: Ref.bytes("root"),
            outcome: "allow",
            input_refs: [Ref.bytes(@args)]
          )
      )

    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(with_pol_batch, caller)
  end

  test "root rotation (RootsChanged): retiring the root that issued E ends new admissions while preserving sealed history and allowing the new root to revoke",
       ctx do
    %{set: set, badge: badge, prefix: prefix} = offline(ctx)
    assert {:ok, :created, _} = OfflineBadges.accept(set)
    caller = %{tenant: "test", principal: @dana}
    session = session(@dana)

    {first, batch1} = record(ctx, prefix, session, {1, nil})
    assert {:ok, [%{"status" => "admitted"}]} = Admission.submit(batch1, caller)
    assert {:ok, [_ | _]} = Runtime.seal()
    Process.sleep(10)

    # Rotate roots to `[new_root]`, retiring both `ctx.root` and `ctx.root2`.
    new_root = Key.generate("ed25519")
    described = Claim.describe()
    start_stream = Claim.stream(ctx.deployment)
    change_prof = profile(start_stream, ctx.root)

    {:ok, proposed} =
      Evidence.new(
        kind_path: @base <> "RootsChanged",
        schema_ref: schema("RootsChanged"),
        profile_ref: Profile.ref(change_prof),
        issuer: ctx.root.key_id,
        actor: "urn:r5e:root-ceremony",
        stream: start_stream,
        seq: described["startHead"] + 1,
        previous: described["chain"],
        captured_at: DateTime.utc_now(),
        body: %{
          "chain" => described["chain"],
          "replaces" => described["chain"],
          "authorization" => "quorum",
          "signer" => ctx.root.key_id,
          "signerKey" => public_key(ctx.root),
          "roots" => [%{"key" => new_root.key_id, "publicKey" => public_key(new_root)}],
          "threshold" => 1,
          "reason" => "retiring initial ceremony roots"
        }
      )
      |> Envelope.sign(ctx.root)

    approval_stream =
      "urn:r5e:stream:#{ctx.deployment}:authority:approval:#{System.unique_integer([:positive])}"

    approval_prof = profile(approval_stream, ctx.root)

    {:ok, approval} =
      Evidence.new(
        kind_path: @base <> "RootChangeApproval",
        schema_ref: schema("RootChangeApproval"),
        profile_ref: Profile.ref(approval_prof),
        issuer: ctx.root.key_id,
        actor: "urn:r5e:root-ceremony",
        stream: approval_stream,
        seq: 1,
        previous: nil,
        captured_at: DateTime.utc_now(),
        body: %{
          "change" => proposed.ref,
          "root" => ctx.root.key_id,
          "custodian" => @custodian_id,
          "custodianKey" => ctx.custodian.key_id,
          "custodianPublicKey" => public_key(ctx.custodian)
        }
      )
      |> Envelope.sign([ctx.root, ctx.custodian])

    assert {:ok, _} =
             Roots.accept(%{
               "change" => %{"ref" => proposed.ref, "envelope" => proposed.envelope},
               "approvals" => [%{"ref" => approval.ref, "envelope" => approval.envelope}],
               "keys" => Enum.map([ctx.root, ctx.custodian, new_root], &wire_key/1),
               "blobs" => [blob(change_prof), blob(approval_prof)]
             })

    assert {:ok, [_]} =
             Grants.accept(
               grant(
                 new_root,
                 ctx.deployment,
                 Runtime.info().key_id,
                 ~w[EpochSeal SessionOpened Revocation]
               )
             )

    assert {:ok, [_ | _]} = Runtime.seal()

    # Retiring `ctx.root` stops new workload records under `ctx.root`'s offline badge.
    {_second, batch2} = record(ctx, prefix, session, {2, first.ref})
    assert {:error, :authority_ended} = Admission.submit(batch2, caller)

    # Sealed historical record from before root rotation still verifies cleanly (`0` failed/incomplete).
    {:ok, bundle} = Exporter.session(ctx.store, session, content: true)
    report = Export.verify(Carried.carry(bundle), trusted_chain: ctx.chain)
    assert [] == Enum.reject(report.findings, &(&1.result == :ok or &1.check == :publication))

    # And `new_root` can still revoke the old offline badge (because seals over `E` are carried).
    assert {:ok, [_]} = Grants.revoke(revocation(new_root, ctx.deployment, badge))
  end
end
