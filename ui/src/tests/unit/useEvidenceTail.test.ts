import { describe, expect, it } from "vitest";

import {
  classifyTailProbeResponse,
  mergeEvidenceRows,
  nextBackoffDelayMs,
} from "~/hooks/useEvidenceTail";
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

describe("apiPaths.liveTail, backoff, probe classification & mergeEvidenceRows", () => {
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

  it("treats HTTP 426 probe as transient Connection lost with reconnect enabled", () => {
    const res = classifyTailProbeResponse(426);
    expect(res.detail).toContain("Connection lost");
    expect(res.detail).not.toContain("WebSocket upgrade required");
    expect(res.shouldReconnect).toBe(true);
  });

  it("stops reconnecting on terminal 401/403/404/503/400 responses", () => {
    expect(classifyTailProbeResponse(401).shouldReconnect).toBe(false);
    expect(classifyTailProbeResponse(403).shouldReconnect).toBe(false);
    expect(classifyTailProbeResponse(404).shouldReconnect).toBe(false);
    expect(classifyTailProbeResponse(503, { error: "ERR_NOT_CAPTURING" })).toMatchObject({
      status: "not_capturing",
      shouldReconnect: false,
    });
    expect(classifyTailProbeResponse(400).shouldReconnect).toBe(false);
  });

  it("computes bounded exponential backoff 1s -> 2s -> 4s -> 8s capped", () => {
    expect(nextBackoffDelayMs(0)).toBe(1_000);
    expect(nextBackoffDelayMs(1)).toBe(2_000);
    expect(nextBackoffDelayMs(2)).toBe(4_000);
    expect(nextBackoffDelayMs(3)).toBe(8_000);
    expect(nextBackoffDelayMs(4)).toBe(8_000);
    expect(nextBackoffDelayMs(10)).toBe(8_000);
  });

  it("deduplicates live-tail records against fetched list rows by ref", () => {
    const r3 = stubRow("evidence:sha256:" + "3".repeat(64), 3);
    const r2 = stubRow("evidence:sha256:" + "2".repeat(64), 2);
    const r1 = stubRow("evidence:sha256:" + "1".repeat(64), 1);

    const merged = mergeEvidenceRows([r3, r2], [r2, r1]);
    expect(merged.map((r) => r.ref)).toEqual([r3.ref, r2.ref, r1.ref]);
  });
});
