import { describe, expect, it } from "vitest";

import {
  extractInlineToolArgs,
  formatToolArgsPreview,
  parseContentBlobArgs,
  toolCallPreviewOf,
} from "~/lib/toolArgs";
import type { EvidenceEnvelopePayload } from "~/lib/evidenceTypes";

function makeToolCallPayload(body: Record<string, unknown>): EvidenceEnvelopePayload {
  return {
    apiVersion: "provenance.r5e.io/v2",
    kind: "ToolCall",
    schemaRef: "bytes:sha256:" + "1".repeat(64),
    profileRef: "bytes:sha256:" + "2".repeat(64),
    issuer: "key:ed25519:sha256:" + "a".repeat(64),
    actor: "urn:r5e:workload:r5e-dev:edtech-tutor",
    stream: "urn:r5e:stream:s1",
    seq: 2,
    previous: null,
    capturedAt: "2026-11-22T07:55:52Z",
    body,
  };
}

describe("toolArgs helpers", () => {
  it("extracts inline body.args and formats a concise one-line preview", () => {
    const payload = makeToolCallPayload({
      tool: "math_hint_generator",
      args: { mode: "socratic", topic: "fractions", grade: 6 },
    });
    const parsed = extractInlineToolArgs(payload);
    expect(parsed.source).toBe("inline");
    expect(parsed.entries.map((e) => e.key)).toEqual(["topic", "mode", "grade"]);
    expect(formatToolArgsPreview(parsed)).toBe(
      'topic="fractions", mode="socratic", grade=6',
    );
    expect(
      toolCallPreviewOf("provenance.r5e.io/v2/ToolCall", payload, "math_hint_generator"),
    ).toBe('topic="fractions", mode="socratic", grade=6');
  });

  it("extracts inline body.details metadata and omits redundant program name in preview", () => {
    const payload = makeToolCallPayload({
      tool: "python3",
      details: { program: "python3", argc: 3 },
    });
    const parsed = extractInlineToolArgs(payload);
    expect(parsed.source).toBe("details");
    expect(toolCallPreviewOf("provenance.r5e.io/v2/ToolCall", payload, "python3")).toBe(
      "argc=3",
    );
  });

  it("parses JSON contentRef blob with preferred key ordering", () => {
    const raw = JSON.stringify({
      program: "python3",
      argv: ["python3", "mock_tools/socratic_hint.py", "bytes:sha256:efb7"],
      commandLine: "python3 mock_tools/socratic_hint.py bytes:sha256:efb7",
    });
    const parsed = parseContentBlobArgs(raw, "application/json");
    expect(parsed.source).toBe("content");
    expect(parsed.nonJsonNote).toBeNull();
    expect(parsed.entries.map((e) => e.key)).toEqual([
      "commandLine",
      "argv",
      "program",
    ]);
    expect(parsed.rawJson).toContain('"commandLine"');
  });

  it("handles plain text and binary blobs gracefully", () => {
    const plain = parseContentBlobArgs("git status --short", "text/plain");
    expect(plain.entries).toHaveLength(0);
    expect(plain.rawText).toBe("git status --short");
    expect(plain.nonJsonNote).toContain("plain text");

    const bin = parseContentBlobArgs("\x00\x01\x02\x03\x04", "application/octet-stream");
    expect(bin.entries).toHaveLength(0);
    expect(bin.rawText).toBeNull();
    expect(bin.nonJsonNote).toContain("Binary");
  });

  it("returns null preview for non-ToolCall kinds", () => {
    const payload = makeToolCallPayload({ tool: "bash", command: "ls" });
    expect(
      toolCallPreviewOf("provenance.r5e.io/v2/PolicyDecision", payload, "bash"),
    ).toBeNull();
  });
});
