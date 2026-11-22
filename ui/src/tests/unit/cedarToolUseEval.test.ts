// @vitest-environment node
import { describe, expect, it } from "vitest";

import {
  DEFAULT_ARGS_INLINE_THRESHOLD_BYTES,
  evaluateToolUseCedar,
} from "../../../vite-plugins/cedar-tool-use-eval";

const SAMPLE_POLICY = `
@id("allow-all")
permit(
  principal,
  action == Action::"invoke_tool",
  resource
);

@id("block-rm-rf")
@reason("Destructive rm -rf is forbidden")
@suggested_alternative("Remove specific files without -rf")
forbid(
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  context has tool_args &&
  context.tool_args has command &&
  context.tool_args.command like "*rm -rf*"
};
`;

describe("evaluateToolUseCedar (real Cedar 4.9.1 WASM)", () => {
  it("enforces forbid-wins with @id/@reason/@suggested_alternative annotations", () => {
    const res = evaluateToolUseCedar({
      cedarSource: SAMPLE_POLICY,
      principal: { id: "alice@r5e.dev", kind: "obo_human", groups: ["eng"] },
      resource: { tool: "shell" },
      context: { toolArgs: { command: "rm -rf /tmp/cache" } },
    });
    expect(res.ok).toBe(true);
    expect(res.decision).toBe("deny");
    expect(res.ruleId).toBe("block-rm-rf");
    expect(res.reason).toBe("Destructive rm -rf is forbidden");
    expect(res.suggestedAlternative).toBe("Remove specific files without -rf");
    expect(res.toolArgsInlined).toBe(true);
  });

  it("allows benign tool calls matching permit", () => {
    const res = evaluateToolUseCedar({
      cedarSource: SAMPLE_POLICY,
      principal: { id: "alice@r5e.dev", kind: "obo_human", groups: ["eng"] },
      resource: { tool: "read_file" },
      context: { toolArgs: { path: "Makefile" } },
    });
    expect(res.ok).toBe(true);
    expect(res.decision).toBe("allow");
    expect(res.ruleId).toBe("allow-all");
  });

  it("enforces default-deny when no permit matches", () => {
    const res = evaluateToolUseCedar({
      cedarSource: `forbid(principal, action == Action::"invoke_tool", resource == ToolUse::"shell");`,
      principal: { id: "alice@r5e.dev", kind: "obo_human", groups: [] },
      resource: { tool: "read_file" },
      context: {},
    });
    expect(res.ok).toBe(true);
    expect(res.decision).toBe("deny");
  });

  it("omits context.tool_args when payload exceeds argsInlineThresholdBytes", () => {
    const huge = "x".repeat(DEFAULT_ARGS_INLINE_THRESHOLD_BYTES + 200);
    const res = evaluateToolUseCedar({
      cedarSource: `
        permit(principal, action == Action::"invoke_tool", resource)
        when { context has tool_args };
      `,
      principal: { id: "alice@r5e.dev", kind: "obo_human", groups: [] },
      resource: { tool: "shell" },
      context: { toolArgs: { command: huge } },
    });
    expect(res.ok).toBe(true);
    expect(res.toolArgsInlined).toBe(false);
    expect(res.toolArgsSizeBytes).toBeGreaterThan(DEFAULT_ARGS_INLINE_THRESHOLD_BYTES);
    expect(res.decision).toBe("deny");
  });

  it("rejects invalid tool names before invoking Cedar", () => {
    const res = evaluateToolUseCedar({
      cedarSource: SAMPLE_POLICY,
      principal: { id: "alice@r5e.dev", kind: "obo_human", groups: [] },
      resource: { tool: 'bad"tool\nname' },
      context: {},
    });
    expect(res.decision).toBe("deny");
    expect(res.reason).toBe("invalid_tool_name");
  });

  it("surfaces real Cedar 4.9.1 syntax errors on invalid policies", () => {
    const res = evaluateToolUseCedar({
      cedarSource: "permit(principal, action === broken);",
      principal: { id: "alice@r5e.dev", kind: "obo_human", groups: [] },
      resource: { tool: "read_file" },
      context: {},
    });
    expect(res.ok).toBe(false);
    expect(res.decision).toBe("error");
    expect(res.parseError).toContain("cedar parse error");
  });
});
