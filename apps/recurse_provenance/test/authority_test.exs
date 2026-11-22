defmodule Recurse.Provenance.AuthorityTest do
  use ExUnit.Case, async: true

  alias Recurse.Provenance.Authority

  @api "provenance.r5e.io/v2"
  @tool @api <> "/ToolCall"
  @seal_kind @api <> "/EpochSeal"
  @stream "urn:r5e:stream:meridian:routing:1"

  # Keys are just names here; signatures were checked by an earlier layer.
  defp key(name), do: "key:ed25519:sha256:" <> hex(name)
  defp ref(name), do: "evidence:sha256:" <> hex(name)
  defp hex(name), do: Base.encode16(:crypto.hash(:sha256, name), case: :lower)

  defp day(n), do: "2026-06-#{String.pad_leading(Integer.to_string(n), 2, "0")}T00:00:00Z"

  defp record(name, kind, issuer, at, body, extra \\ %{}) do
    evidence =
      Map.merge(
        %{
          "apiVersion" => @api,
          "kind" => kind,
          "issuer" => key(issuer),
          "actor" => "urn:meridian:agent:router",
          "stream" => @stream,
          "capturedAt" => day(at),
          "body" => body
        },
        extra
      )

    {ref(name),
     %{ref: ref(name), evidence: evidence, signed?: true, body_ok?: true, broken?: false}}
  end

  defp endorsement(name, issuer, subject, at, opts \\ []) do
    body =
      %{
        "subject" => key(subject),
        "kinds" => Keyword.get(opts, :kinds, [@tool, @seal_kind]),
        "mayEndorse" => Keyword.get(opts, :may_endorse, true),
        "notBefore" => day(Keyword.get(opts, :from, 1)),
        "notAfter" => day(Keyword.get(opts, :to, 28))
      }
      |> put(opts, :parent, "parent", &ref/1)
      |> put(opts, :streams, "streamPrefixes", & &1)
      |> put(opts, :actors, "actorPrefixes", & &1)
      |> put(opts, :acts_for, "actsFor", & &1)

    record(name, "Endorsement", issuer, at, body)
  end

  defp badge(name, issuer, subject, at, parent, opts \\ []) do
    body =
      %{
        "subject" => key(subject),
        "kinds" => Keyword.get(opts, :kinds, [@tool]),
        "notBefore" => day(Keyword.get(opts, :from, 1)),
        "notAfter" => day(Keyword.get(opts, :to, 28)),
        "parent" => ref(parent)
      }
      |> put(opts, :actors, "actorPrefixes", & &1)

    record(name, "Badge", issuer, at, body)
  end

  defp put(body, opts, key, field, fun) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> Map.put(body, field, fun.(value))
      :error -> body
    end
  end

  defp tool(name, issuer, at, extra \\ %{}), do: record(name, "ToolCall", issuer, at, %{}, extra)

  defp revocation(name, issuer, target, at),
    do: record(name, "Revocation", issuer, at, %{"target" => ref(target)})

  defp succession(name, from, to, at),
    do:
      record(name, "Succession", from, at, %{"predecessor" => key(from), "successor" => key(to)})

  defp seal(name, issuer, at),
    do:
      record(name, "EpochSeal", issuer, at, %{"stream" => @stream}, %{
        "stream" => "urn:r5e:control"
      })

  defp outcome(records, name, opts \\ []) do
    cover =
      for {seal, covered} <- Keyword.get(opts, :sealed, []), into: %{} do
        {ref(seal), MapSet.new(covered, &ref/1)}
      end

    roots = opts |> Keyword.get(:roots, ["root"]) |> Enum.map(&key/1)
    Authority.outcomes(Map.new(records), roots, cover)[ref(name)]
  end

  # root -> gateway (may endorse) -> worker badge
  defp company do
    [
      endorsement("e-gateway", "root", "gateway", 1),
      badge("b-worker", "gateway", "worker", 2, "e-gateway")
    ]
  end

  describe "a chain from a trusted root" do
    test "covers a record under an endorsement and under a badge beneath it" do
      records = company() ++ [tool("by-gateway", "gateway", 3), tool("by-worker", "worker", 3)]

      assert outcome(records, "by-gateway") == {:ok, "ok", ref("e-gateway")}
      assert outcome(records, "by-worker") == {:ok, "ok", ref("b-worker")}
      assert outcome(records, "e-gateway") == {:ok, "ok", key("root")}
      assert outcome(records, "b-worker") == {:ok, "ok", ref("e-gateway")}
    end

    test "principals and successions have no outcome; nobody's permission is needed" do
      records = [record("p", "Principal", "root", 1, %{}), succession("s", "root", "root2", 1)]
      assert Authority.outcomes(Map.new(records), [key("root")], %{}) == %{}
    end

    test "a key no link names has no standing, and a root that is not trusted is not a root" do
      records = company() ++ [tool("stranger", "mallory", 3)]

      assert outcome(records, "stranger") == {:failed, "no_standing", key("mallory")}

      assert outcome(records, "e-gateway", roots: ["other"]) ==
               {:failed, "no_standing", key("root")}

      assert outcome(records ++ [tool("w", "worker", 3)], "w", roots: ["other"]) ==
               {:failed, "not_covered", nil}
    end

    test "a parentless endorsement by a key that is not a root gives nothing" do
      records =
        company() ++ [endorsement("e-rogue", "gateway", "friend", 3), tool("t", "friend", 4)]

      assert outcome(records, "e-rogue") == {:failed, "no_standing", key("gateway")}
      assert outcome(records, "t") == {:failed, "not_covered", nil}
    end

    test "an endorsement of oneself is ignored" do
      records = [endorsement("self", "root", "root", 1), tool("t", "root", 2)]
      assert outcome(records, "self") == {:failed, "not_covered", nil}
      assert outcome(records, "t") == {:failed, "not_covered", nil}
    end

    test "an unsigned or malformed grant states nothing" do
      [{r, gateway}, badge] = company()
      # Could not be checked (a key was missing): it may yet be valid.
      records = [{r, %{gateway | signed?: false}}, badge, tool("t", "worker", 3)]
      assert outcome(records, "t") == {:incomplete, "chain_not_carried", r}

      # Checked and failed: a forged parent is not a missing one.
      records = [{r, %{gateway | signed?: false, broken?: true}}, badge, tool("t", "worker", 3)]
      assert outcome(records, "t") == {:failed, "not_covered", nil}
    end
  end

  describe "what a link covers" do
    test "kind, stream, actor, on-behalf-of and window" do
      records = [
        endorsement("e", "root", "gateway", 1,
          kinds: [@tool],
          streams: ["urn:r5e:stream:meridian:"],
          actors: ["urn:meridian:agent:"],
          acts_for: "urn:meridian:user:dana",
          from: 2,
          to: 10
        )
      ]

      dana = %{"onBehalfOf" => "urn:meridian:user:dana"}
      check = fn at, extra -> outcome(records ++ [tool("t", "gateway", at, extra)], "t") end

      assert check.(3, dana) == {:ok, "ok", ref("e")}
      assert check.(3, %{}) == {:failed, "not_covered", nil}

      assert check.(3, %{"onBehalfOf" => "urn:meridian:user:lena"}) ==
               {:failed, "not_covered", nil}

      assert check.(1, dana) == {:failed, "not_covered", nil}
      assert check.(11, dana) == {:failed, "not_covered", nil}

      assert check.(3, Map.put(dana, "actor", "urn:meridian:user:lena")) ==
               {:failed, "not_covered", nil}

      assert check.(3, Map.put(dana, "stream", "urn:r5e:stream:harbor:1")) ==
               {:failed, "not_covered", nil}

      model = record("m", "ModelCall", "gateway", 3, %{}, dana)
      assert outcome(records ++ [model], "m") == {:failed, "not_covered", nil}
    end

    test "a seal is tested on the stream it seals" do
      grant = fn streams -> endorsement("e", "root", "sealer", 1, streams: streams) end

      assert outcome([grant.(["urn:r5e:stream:meridian:"]), seal("s", "sealer", 3)], "s") ==
               {:ok, "ok", ref("e")}

      assert outcome([grant.(["urn:r5e:control"]), seal("s", "sealer", 3)], "s") ==
               {:failed, "not_covered", nil}
    end
  end

  describe "a link never grants more than its parent" do
    defp under(parent_opts, child_opts) do
      records = [
        endorsement("p", "root", "gateway", 1, parent_opts),
        endorsement("c", "gateway", "team", 2, [parent: "p"] ++ child_opts)
      ]

      outcome(records, "c")
    end

    test "kinds, window, prefixes and on-behalf-of" do
      ok = {:ok, "ok", ref("p")}
      no = {:failed, "not_covered", nil}

      assert under([], []) == ok
      assert under([kinds: [@tool]], kinds: [@tool, @seal_kind]) == no
      assert under([to: 10], to: 11) == no
      assert under([from: 1], from: 1, to: 5) == ok
      assert under([streams: ["urn:a:"]], []) == no
      assert under([streams: ["urn:a:"]], streams: ["urn:a:b", "urn:c"]) == no
      assert under([streams: ["urn:a:"]], streams: ["urn:a:b"]) == ok
      assert under([actors: ["urn:m:"]], actors: ["urn:x:"]) == no
      assert under([acts_for: "urn:u:dana"], []) == no
      assert under([acts_for: "urn:u:dana"], acts_for: "urn:u:dana") == ok
      assert under([may_endorse: false], []) == no
    end

    test "a badge is only ever the last link, and its issuer must hold the parent" do
      records = company() ++ [badge("b2", "worker", "helper", 3, "b-worker")]
      assert outcome(records, "b2") == {:failed, "not_covered", nil}

      records = company() ++ [badge("b3", "mallory", "helper", 3, "e-gateway")]
      assert outcome(records, "b3") == {:failed, "not_covered", nil}
    end

    test "a link issued outside its parent's window does not count" do
      records = [
        endorsement("p", "root", "gateway", 1, from: 5, to: 10),
        endorsement("c", "gateway", "team", 2, parent: "p", from: 5, to: 10)
      ]

      assert outcome(records, "c") == {:failed, "not_covered", nil}
    end
  end

  describe "a parent that is not carried" do
    test "is reported as such when the carried links hold" do
      [_gateway, worker] = company()
      records = [worker, tool("t", "worker", 3)]

      assert outcome(records, "t") == {:incomplete, "chain_not_carried", ref("e-gateway")}
      assert outcome(records, "b-worker") == {:incomplete, "chain_not_carried", ref("e-gateway")}
    end

    test "cannot turn a record the carried links already fail into an open question" do
      [_gateway, worker] = company()
      model = record("m", "ModelCall", "worker", 3, %{})
      assert outcome([worker, model], "m") == {:failed, "not_covered", nil}
    end
  end

  describe "revocation" do
    test "by the issuer, an ancestor or the subject is honoured; by a stranger it is not" do
      for {who, entitled?} <- [
            {"gateway", true},
            {"root", true},
            {"worker", true},
            {"mallory", false}
          ] do
        records = company() ++ [revocation("rv", who, "b-worker", 5), tool("t", "worker", 6)]

        if entitled? do
          assert outcome(records, "rv") == {:ok, "ok", ref("b-worker")}
          assert outcome(records, "t") == {:failed, "ended", ref("rv")}
        else
          assert outcome(records, "rv") == {:failed, "no_standing", key(who)}
          assert outcome(records, "t") == {:ok, "ok", ref("b-worker")}
        end
      end
    end

    test "ending a link ends everything beneath it" do
      records = company() ++ [revocation("rv", "root", "e-gateway", 5), tool("t", "worker", 6)]
      assert outcome(records, "t") == {:failed, "ended", ref("rv")}
    end

    test "a target that is not carried, or is not a grant" do
      records = company() ++ [tool("t", "worker", 3)]

      assert outcome(records ++ [revocation("rv", "root", "elsewhere", 5)], "rv") ==
               {:incomplete, "chain_not_carried", ref("elsewhere")}

      assert outcome(records ++ [revocation("rv", "root", "t", 5)], "rv") ==
               {:failed, "not_covered", nil}
    end

    test "a record dated before it is believed only when someone else sealed it first" do
      records =
        company() ++
          [
            endorsement("e-sealer", "root", "sealer", 1),
            tool("t", "worker", 3),
            seal("s", "sealer", 4),
            revocation("rv", "gateway", "b-worker", 5)
          ]

      assert outcome(records, "t") == {:incomplete, "time_rests_on_the_signer", ref("rv")}
      assert outcome(records, "t", sealed: [{"s", ["t"]}]) == {:ok, "ok", ref("b-worker")}

      # A seal dated after the revocation shows nothing about before it.
      late = Enum.reject(records, fn {r, _} -> r == ref("s") end) ++ [seal("s", "sealer", 6)]

      assert outcome(late, "t", sealed: [{"s", ["t"]}]) ==
               {:incomplete, "time_rests_on_the_signer", ref("rv")}
    end

    test "a link minted under a grant after the grant was taken back fails, whatever the record's date" do
      records = [
        endorsement("e-gateway", "root", "gateway", 1),
        revocation("rv", "root", "e-gateway", 5),
        badge("late", "gateway", "worker", 6, "e-gateway"),
        tool("t", "worker", 3)
      ]

      assert outcome(records, "t") == {:failed, "ended", ref("rv")}
      assert outcome(records, "late") == {:failed, "ended", ref("rv")}
    end

    test "a sealer still vouches after the root that endorsed it hands over, not after its own end" do
      records =
        company() ++
          [
            endorsement("e-sealer", "root", "sealer", 1),
            tool("t", "worker", 3),
            seal("s", "sealer", 4),
            revocation("rv", "gateway", "b-worker", 5),
            succession("s-root", "root", "root2", 20)
          ]

      assert outcome(records, "t", sealed: [{"s", ["t"]}]) == {:ok, "ok", ref("b-worker")}

      ended = records ++ [revocation("rv-s", "root", "e-sealer", 8)]

      assert outcome(ended, "t", sealed: [{"s", ["t"]}]) ==
               {:incomplete, "time_rests_on_the_signer", ref("rv")}
    end

    test "a seal by a key with no standing shows nothing" do
      records =
        company() ++
          [
            tool("t", "worker", 3),
            seal("s", "nobody", 4),
            revocation("rv", "gateway", "b-worker", 5)
          ]

      assert outcome(records, "t", sealed: [{"s", ["t"]}]) ==
               {:incomplete, "time_rests_on_the_signer", ref("rv")}
    end
  end

  describe "succession" do
    test "the new key stands in for the old as an endorsed subject, and never as a root" do
      records =
        company() ++
          [
            succession("s-root", "root", "root2", 10),
            succession("s-gw", "gateway", "gateway2", 10),
            endorsement("e-new", "root2", "auditor", 11, kinds: [@tool]),
            tool("by-new", "gateway2", 11),
            tool("by-old", "gateway", 11),
            badge("b-late", "gateway2", "helper", 11, "e-gateway")
          ]

      # A root's place does not pass by hand-over: only a change of roots
      # on the deployment's start stream makes another key a root.
      assert outcome(records, "e-new") == {:failed, "no_standing", key("root2")}
      assert outcome(records, "by-new") == {:ok, "ok", ref("e-gateway")}
      assert outcome(records, "by-old") == {:failed, "ended", ref("s-gw")}
      assert outcome(records, "b-late") == {:ok, "ok", ref("e-gateway")}
    end

    test "the new key does not act before the hand-over, and a badge does not pass on" do
      records =
        company() ++
          [
            succession("s-gw", "gateway", "gateway2", 10),
            tool("early", "gateway2", 9),
            succession("s-w", "worker", "worker2", 10),
            tool("w2", "worker2", 11)
          ]

      assert outcome(records, "early") == {:failed, "no_standing", key("gateway2")}
      assert outcome(records, "w2") == {:failed, "no_standing", key("worker2")}
    end

    test "two successors for one key: neither stands in, and the key is ended" do
      records =
        company() ++
          [
            succession("s1", "gateway", "a", 10),
            succession("s2", "gateway", "b", 12),
            tool("ta", "a", 13),
            tool("old", "gateway", 13)
          ]

      assert outcome(records, "ta") == {:failed, "no_standing", key("a")}
      assert {:failed, "ended", _} = outcome(records, "old")
    end

    test "a loop of successions stands in for nobody" do
      records =
        company() ++
          [
            succession("s1", "gateway", "a", 10),
            succession("s2", "a", "gateway", 11),
            tool("ta", "a", 12)
          ]

      assert outcome(records, "ta") == {:failed, "no_standing", key("a")}
    end

    test "an old key's own hand-over cannot undo history someone else sealed before its date" do
      base =
        company() ++
          [
            endorsement("e-sealer", "root", "sealer", 1),
            tool("t", "gateway", 3),
            seal("s", "sealer", 4)
          ]

      # Honest: sealed on day 4, handed over on day 10.
      honest = base ++ [succession("h", "gateway", "gateway2", 10)]
      assert outcome(honest, "t", sealed: [{"s", ["t"]}]) == {:ok, "ok", ref("e-gateway")}
      assert outcome(honest, "t") == {:incomplete, "time_rests_on_the_signer", ref("h")}

      # A hand-over claiming day 2, never sealed: the same dates as an
      # honest hand-over followed by misuse. Neither can be shown.
      backdated = base ++ [succession("h", "gateway", "thief", 2)]

      assert outcome(backdated, "t", sealed: [{"s", ["t"]}]) ==
               {:incomplete, "time_rests_on_the_signer", ref("h")}

      # The hand-over was itself sealed before the record was: it applies.
      early_seal = seal("s0", "sealer", 2)

      assert outcome(backdated ++ [early_seal], "t", sealed: [{"s", ["t"]}, {"s0", ["h"]}]) ==
               {:failed, "ended", ref("h")}

      # Nothing sealed at all, and dated after the hand-over.
      assert outcome(backdated, "t") == {:failed, "ended", ref("h")}
    end
  end
end
