import { describe, expect, it } from "vitest";

import {
  buildBucketsFromRows,
  normalizeServerHistogram,
} from "~/components/evidence/EvidenceHistogram";

describe("EvidenceHistogram helpers", () => {
  it("normalizes server histogram buckets including empty buckets", () => {
    const buckets = normalizeServerHistogram({
      since: "2026-11-22T00:00:00Z",
      until: "2026-11-22T02:00:00Z",
      bucketSeconds: 3600,
      buckets: [
        {
          start: "2026-11-22T00:00:00Z",
          count: 10,
          byOutcome: { allow: 6, deny: 3 },
        },
        {
          start: "2026-11-22T01:00:00Z",
          count: 0,
          byOutcome: {},
        },
      ],
    });
    expect(buckets).toHaveLength(2);
    expect(buckets[0]).toMatchObject({
      allow: 6,
      deny: 3,
      other: 1,
      total: 10,
    });
    expect(buckets[1]).toMatchObject({
      allow: 0,
      deny: 0,
      other: 0,
      total: 0,
      end: "2026-11-22T02:00:00Z",
    });
  });

  it("uses next bucket start and response until for fractional bucketSeconds", () => {
    const buckets = normalizeServerHistogram({
      since: "2026-11-22T07:55:50.000Z",
      until: "2026-11-22T07:55:51.000Z",
      bucketSeconds: 0.5,
      buckets: [
        { start: "2026-11-22T07:55:50.000Z", count: 2, byOutcome: { allow: 1 } },
        { start: "2026-11-22T07:55:50.500Z", count: 3, byOutcome: { deny: 1, error: 1 } },
      ],
    });
    expect(buckets[0]!.end).toBe("2026-11-22T07:55:50.500Z");
    expect(buckets[1]!.end).toBe("2026-11-22T07:55:51.000Z");
    expect(buckets[1]!.deny).toBe(2);
    expect(buckets[1]!.other).toBe(1);
  });

  it("builds fallback buckets from loaded rows", () => {
    const buckets = buildBucketsFromRows(
      [
        { capturedAt: "2026-11-22T07:00:00Z", outcome: "allow" },
        { capturedAt: "2026-11-22T07:05:00Z", outcome: "deny" },
        { capturedAt: "2026-11-22T07:10:00Z", outcome: null },
      ],
      6,
    );
    expect(buckets).toHaveLength(6);
    const total = buckets.reduce((sum, b) => sum + b.total, 0);
    expect(total).toBe(3);
  });
});
