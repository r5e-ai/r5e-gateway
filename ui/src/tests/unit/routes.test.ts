import { describe, expect, it } from "vitest";

import {
  ADMIN_BASE,
  mcpRegistryDetailPath,
  policySimulatorRecordDetailPath,
  recordDetailPath,
  routes,
  stripBasename,
  timelinePath,
  timelineRecordDetailPath,
} from "~/lib/routes";

describe("stripBasename", () => {
  it("strips /admin prefix cleanly", () => {
    expect(stripBasename(routes.dashboard)).toBe("/dashboard");
    expect(stripBasename(routes.policySimulator)).toBe("/policy-simulator");
    expect(stripBasename("/admin")).toBe("/");
  });
});

describe("recordDetailPath", () => {
  it("encodes evidence:sha256:... refs under /dashboard/records/", () => {
    const ref = "evidence:sha256:b1c6b5aa26e4205c79a3e44fd2e899e49c1920e4e37422166f739cf040fcdb20";
    expect(recordDetailPath(ref)).toBe(`/dashboard/records/${encodeURIComponent(ref)}`);
    expect(`${ADMIN_BASE}${recordDetailPath(ref)}`).toBe(
      `/admin/dashboard/records/${encodeURIComponent(ref)}`,
    );
  });

  it("supports timeline and policy simulator nested record detail paths", () => {
    expect(timelineRecordDetailPath("evidence:sha256:aaa")).toBe(
      "/timeline/records/evidence%3Asha256%3Aaaa",
    );
    expect(policySimulatorRecordDetailPath("evidence:sha256:bbb")).toBe(
      "/policy-simulator/records/evidence%3Asha256%3Abbb",
    );
  });
});

describe("timelinePath & mcpRegistryDetailPath", () => {
  it("builds session-scoped timeline URLs", () => {
    expect(timelinePath({ session: "urn:r5e:session:dev:1" })).toBe(
      "/timeline?session=urn%3Ar5e%3Asession%3Adev%3A1",
    );
    expect(mcpRegistryDetailPath("srv-1")).toBe("/mcp-registry/srv-1");
  });
});
