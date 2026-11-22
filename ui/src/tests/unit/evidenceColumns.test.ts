import { describe, expect, it } from "vitest";

import {
  defaultColumnPrefs,
  reorderColumnIds,
} from "~/lib/evidenceColumns";
import {
  formatActorShort,
  reasonOf,
  targetDetailOf,
  type EvidenceEnvelopePayload,
} from "~/lib/evidenceTypes";

describe("evidenceColumns & targetDetailOf", () => {
  it("reorders column IDs cleanly", () => {
    const prefs = defaultColumnPrefs();
    expect(prefs.visible.reason).toBe(true);
    const reordered = reorderColumnIds(prefs.order, "actor", "kind");
    expect(reordered.indexOf("actor")).toBe(reordered.indexOf("kind") - 1);
  });

  it("extracts canonical target and reason separately and decodes actor identity", () => {
    const payload: EvidenceEnvelopePayload = {
      apiVersion: "provenance.r5e.io/v2",
      kind: "PolicyDecision",
      schemaRef: "bytes:sha256:" + "1".repeat(64),
      profileRef: "bytes:sha256:" + "2".repeat(64),
      issuer: "key:ed25519:sha256:" + "3".repeat(64),
      actor: "urn:r5e:workload:r5e-dev:tutor-agent",
      stream: "urn:r5e:stream:s1",
      seq: 2,
      previous: null,
      capturedAt: "2026-11-22T07:00:00Z",
      body: {
        subject: "bytes:sha256:" + "a".repeat(64),
        evaluation: {
          outcome: "deny",
          policyRef: "bytes:sha256:" + "4".repeat(64),
          inputRefs: [],
          reason: "Blocked shell command",
        },
        details: {
          target: "ExecCommand",
        },
      },
    };
    const detail = targetDetailOf(payload);
    expect(detail.primary).toBe("ExecCommand");
    expect(reasonOf(payload)).toBe("Blocked shell command");
    expect(formatActorShort(payload.actor)).toBe("tutor-agent");
  });
});
