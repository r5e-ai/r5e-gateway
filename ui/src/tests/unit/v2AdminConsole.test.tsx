import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { apiPaths } from "~/lib/apiPaths";
import Dashboard from "~/pages/Dashboard";
import RecordDetail from "~/pages/RecordDetail";

const SAMPLE_REF =
  "evidence:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SAMPLE_BLOB_REF =
  "bytes:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function makeRecord() {
  const payload = {
    apiVersion: "provenance.r5e.io/v2",
    kind: "ToolCall",
    schemaRef: "bytes:sha256:" + "1".repeat(64),
    profileRef: "bytes:sha256:" + "2".repeat(64),
    issuer: "key:ed25519:sha256:" + "3".repeat(64),
    actor: "urn:r5e:user:alice@r5e.dev",
    session: "urn:r5e:session:r5e-dev:0123456789abcdef.s1",
    stream: "urn:r5e:stream:r5e-dev:s1",
    seq: 2,
    previous: null,
    capturedAt: "2026-11-22T07:00:00Z",
    body: {
      tool: "shell",
      contentRef: SAMPLE_BLOB_REF,
      policy: {
        outcome: "deny",
        policyRef: "bytes:sha256:" + "4".repeat(64),
        inputRefs: [SAMPLE_BLOB_REF],
        reason: "Blocked destructive command",
      },
    },
  };
  return {
    ref: SAMPLE_REF,
    stream: payload.stream,
    seq: 2,
    kind: "provenance.r5e.io/v2/ToolCall",
    capturedAt: payload.capturedAt,
    actor: payload.actor,
    session: payload.session,
    envelope: {
      payloadType: "application/vnd.r5e.provenance-evidence+json;v=2",
      payload: Buffer.from(JSON.stringify(payload), "utf8").toString("base64"),
      signatures: [{ keyid: payload.issuer, sig: "AAAA" }],
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("v2 Admin Console Dashboard & RecordDetail", () => {
  it("loads Provenance v2 records from /v1/evidence/records, fetches content via /content/:bytes_ref, and verifies via /v1/evidence/verify", async () => {
    const rec = makeRecord();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url === apiPaths.auth.me) {
        return new Response(
          JSON.stringify({
            principal_subject: "operator@r5e.dev",
            recurse_role: "platform_operator",
            tenant_id: "r5e-dev",
            browser_session_id: "s1",
            session_expires_at: "2026-11-23T00:00:00Z",
            session_idle_timeout_at: "2026-11-22T09:00:00Z",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url === apiPaths.deployment) {
        return new Response(
          JSON.stringify({
            chain:
              "evidence:sha256:b1c6b5aa26e4205c79a3e44fd2e899e49c1920e4e37422166f739cf040fcdb20",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url.startsWith(apiPaths.evidence.records + "?")) {
        return new Response(JSON.stringify({ records: [rec], cursor: null }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url === apiPaths.evidence.recordDetail(SAMPLE_REF)) {
        return new Response(JSON.stringify(rec), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url === apiPaths.evidence.recordContent(SAMPLE_REF, SAMPLE_BLOB_REF)) {
        return new Response(JSON.stringify({ command: "rm -rf /tmp" }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
          },
        });
      }
      if (url === apiPaths.evidence.export) {
        return new Response(
          JSON.stringify({
            format: "r5e.provenance-export/v2",
            scope: { query: {}, at: [] },
            records: [{ ref: rec.ref, envelope: rec.envelope }],
            blobs: [],
            keys: [],
            seals: [],
            checkpoints: [],
            proofs: [],
            publicationProofs: [],
            omissions: [],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url === apiPaths.evidence.verify) {
        return new Response(
          JSON.stringify({
            format: "r5e.provenance-verify-report/v2",
            summary: { ok: 155, failed: 0, incomplete: 15 },
            findings: [
              {
                layer: 1,
                subject: rec.ref,
                check: "signature",
                result: "ok",
                code: "ok",
                about: rec.envelope.signatures[0]?.keyid ?? null,
              },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response("Not Found", { status: 404 });
    });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/dashboard"]}>
          <Routes>
            <Route path="/dashboard" element={<Dashboard />}>
              <Route path="records/:ref" element={<RecordDetail />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const row = await screen.findByTestId("evidence-row-ToolCall");
    expect(row).toHaveTextContent("shell");
    expect(row).toHaveTextContent("deny");

    fireEvent.click(row);
    await screen.findByTestId("record-detail-drawer");

    fireEvent.click(screen.getByTestId("detail-tab-content"));
    fireEvent.click(screen.getByTestId("fetch-content-btn"));
    await screen.findByTestId("content-blob-json");

    fireEvent.click(screen.getByTestId("detail-tab-verify"));
    fireEvent.click(screen.getByTestId("run-verify-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("verify-ok-count")).toHaveTextContent("ok: 155");
    });

    const calledUrls = fetchSpy.mock.calls.map((c) => String(c[0]));
    expect(
      calledUrls.every(
        (u) =>
          u.startsWith("/v1/auth/") ||
          u.startsWith("/v1/deployment") ||
          u.startsWith("/v1/evidence/"),
      ),
    ).toBe(true);
    expect(calledUrls.some((u) => u.includes("/content/"))).toBe(true);
    expect(calledUrls.some((u) => u.includes("/v1/evidence/verify"))).toBe(true);
  });
});
