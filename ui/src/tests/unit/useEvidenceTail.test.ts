import { describe, expect, it } from "vitest";

import { mergeEvidenceRows } from "~/hooks/useEvidenceTail";
import { apiPaths } from "~/lib/apiPaths";
import type { EvidenceRecordEntry } from "~/lib/evidenceTypes";

function stubRow(ref: string, seq: number): EvidenceRecordEntry {
  return {
    ref,
    stream: "urn:r5e:stream:s1",
    seq,
    kind: "provenance.r5e.io/v2/ToolCall",
    capturedAt: "2026-11-22T07:00:00Z",
    actor: "urn:r5e:user:alice",
    session: "urn:r5e:session:r5e-dev:0123456789abcdef.s1",
    envelope: {
      payloadType: "application/vnd.r5e.provenance-evidence+json;v=2",
      payload: "",
      signatures: [],
    },
  };
}

describe("apiPaths.liveTail & mergeEvidenceRows", () => {
  it("builds /v1/evidence/tail with optional kind, session, and actor filters", () => {
    expect(apiPaths.liveTail()).toBe("/v1/evidence/tail");
    expect(
      apiPaths.liveTail({
        kind: "provenance.r5e.io/v2/ToolCall",
        session: "urn:r5e:session:r5e-dev:abc.1",
        actor: "urn:r5e:user:alice",
      }),
    ).toBe(
      "/v1/evidence/tail?kind=provenance.r5e.io%2Fv2%2FToolCall&session=urn%3Ar5e%3Asession%3Ar5e-dev%3Aabc.1&actor=urn%3Ar5e%3Auser%3Aalice",
    );
  });

  it("deduplicates live-tail records against fetched list rows by ref", () => {
    const r3 = stubRow("evidence:sha256:" + "3".repeat(64), 3);
    const r2 = stubRow("evidence:sha256:" + "2".repeat(64), 2);
    const r1 = stubRow("evidence:sha256:" + "1".repeat(64), 1);

    const merged = mergeEvidenceRows([r3, r2], [r2, r1]);
    expect(merged.map((r) => r.ref)).toEqual([r3.ref, r2.ref, r1.ref]);
  });
});
