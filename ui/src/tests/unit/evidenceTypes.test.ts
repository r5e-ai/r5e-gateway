import { describe, expect, it } from "vitest";

import {
  DEFAULT_TRUSTED_CHAIN,
  contentRefOf,
  decodeEvidencePayload,
  policyEvaluationOf,
  shortKindName,
  truncateRef,
  type SignedEvidenceEnvelope,
} from "~/lib/evidenceTypes";

function makeEnvelope(payloadObj: Record<string, unknown>): SignedEvidenceEnvelope {
  const b64 = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64");
  return {
    payloadType: "application/vnd.r5e.provenance-evidence+json;v=2",
    payload: b64,
    signatures: [{ keyid: "key:ed25519:sha256:" + "a".repeat(64), sig: "AAAA" }],
  };
}

describe("evidenceTypes helpers", () => {
  it("decodes ToolCall inline .policy and contentRef cleanly", () => {
    const env = makeEnvelope({
      apiVersion: "provenance.r5e.io/v2",
      kind: "ToolCall",
      schemaRef: "bytes:sha256:" + "1".repeat(64),
      profileRef: "bytes:sha256:" + "2".repeat(64),
      issuer: "key:ed25519:sha256:" + "a".repeat(64),
      actor: "urn:r5e:user:alice",
      stream: "urn:r5e:stream:s1",
      seq: 3,
      previous: null,
      capturedAt: "2026-11-22T07:00:00Z",
      body: {
        tool: "shell",
        contentRef: "bytes:sha256:" + "3".repeat(64),
        policy: {
          outcome: "deny",
          policyRef: "bytes:sha256:" + "4".repeat(64),
          inputRefs: ["bytes:sha256:" + "3".repeat(64)],
          reason: "blocked",
        },
      },
    });
    const decoded = decodeEvidencePayload(env);
    expect(decoded?.kind).toBe("ToolCall");
    expect(policyEvaluationOf(decoded)?.outcome).toBe("deny");
    expect(contentRefOf(decoded)).toBe("bytes:sha256:" + "3".repeat(64));
  });

  it("supports open-string custom kind paths and pins r5e-dev trusted chain", () => {
    expect(shortKindName("edtech.r5e.io/v1/GuardianConsent")).toBe("GuardianConsent");
    expect(shortKindName("provenance.r5e.io/v2/PolicyDecision")).toBe("PolicyDecision");
    expect(DEFAULT_TRUSTED_CHAIN).toMatch(/^evidence:sha256:[0-9a-f]{64}$/);
    expect(truncateRef(DEFAULT_TRUSTED_CHAIN, 8)).toContain("evidence:sha256:b1c6b5aa");
  });
});
