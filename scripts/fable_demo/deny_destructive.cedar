// Local demo scripts, ported from the r5e-enterprise.fable-demo workspace
// (2026-07-27 / 2026-08-25 runs). Dev-only: nothing here is loaded by the
// app, and boot.sh/boot-real.sh are meant to be run by hand from a checkout.
//
// Deny-destructive Cedar bundle for the local demo (step d).
// Baseline permit + forbids for destructive tool invocations. Cedar is
// deny-by-default, so the bare permit is required for the allow path to
// fire at all; the forbids then override it for matching requests.
//
// Shapes covered (mirrors specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke):
//   * legacy codex `shell` tool, `command` arg — rm -rf and DROP DATABASE
//   * codex 0.125+ `exec_command` tool, `cmd` arg — rm -rf and DROP DATABASE

permit (
  principal,
  action,
  resource
);

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"shell"
) when {
  context has tool_args
  && context.tool_args has "command"
  && (context.tool_args.command like "*rm -rf*"
      || context.tool_args.command like "*DROP DATABASE*")
};

forbid (
  principal,
  action == Action::"invoke_tool",
  resource == ToolUse::"exec_command"
) when {
  context has tool_args
  && context.tool_args has "cmd"
  && (context.tool_args.cmd like "*rm -rf*"
      || context.tool_args.cmd like "*DROP DATABASE*")
};
