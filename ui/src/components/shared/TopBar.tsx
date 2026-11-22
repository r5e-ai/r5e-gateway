// TopBar — global page-context strip rendered above every authenticated route.
//
// Per `design/r5e-enterprise-audit-ui.pen` Dashboard topbar (`happW`) +
// Policy Simulator topbar (`81OUt`) + the surface-gap brief.
//
// Layout:
//   - 56px tall, full width inside the shell's main column.
//   - Left slot (`pageContent`): page-supplied breadcrumb / page title / mode
//     tabs entrypoint. Pages pass this via the prop; default is empty.
//   - Right slot (`actions`): page-supplied action buttons (e.g. Suggestions
//     link on PolicySimulator, Refresh on PolicySimulatorSuggestions).
//   - Far-right (always rendered): role pill, principal subject, sign-out.
//
// The role pill + principal + sign-out used to live inline at the top of
// `Dashboard.tsx`. They moved here so every page renders identical user-state
// chrome. Constitution Principle VII: extract on the second consumer, before
// the third copy can land.
//
// Sign-out semantics match the previous Dashboard implementation:
//   1. POST /admin/logout (best-effort; ignore network errors — cookie may
//      already be invalid).
//   2. Full-page navigate to /admin/login (NOT to /admin/login/start, which
//      would re-trigger SSO immediately because the IdP session is alive —
//      see issue #20).

import type { ReactNode } from "react";

import { useAuth } from "~/hooks/useAuth";
import { logoutEndpoint, routes } from "~/lib/auth";

interface TopBarProps {
  /**
   * Left-side page context — typically a breadcrumb / page title /
   * back-link composition. Optional; default is empty.
   */
  pageContent?: ReactNode;
  /**
   * Right-side page-specific action buttons rendered immediately to the LEFT
   * of the global user/role/sign-out cluster. Optional.
   */
  actions?: ReactNode;
}

export function TopBar({ pageContent, actions }: TopBarProps = {}): JSX.Element {
  const auth = useAuth();
  const role = auth.status === "authenticated" ? auth.role : null;
  const principal = auth.status === "authenticated" ? auth.principal : "";

  return (
    <header
      data-testid="global-topbar"
      className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-r5e-border bg-r5e-bg px-5 font-sans"
    >
      <div
        data-testid="topbar-page-content"
        className="flex min-w-0 flex-1 items-center gap-3 overflow-hidden"
      >
        {pageContent}
      </div>

      <div className="flex shrink-0 items-center gap-2.5">
        {actions && (
          <div data-testid="topbar-actions" className="flex shrink-0 items-center gap-2">
            {actions}
          </div>
        )}
        {role && (
          <span
            data-testid="topbar-role-pill"
            className="shrink-0 whitespace-nowrap rounded-full bg-r5e-accent/25 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-r5e-text"
          >
            {role.replace("_", " ")}
          </span>
        )}
        {principal && (
          <span
            data-testid="topbar-principal"
            title={principal}
            className="max-w-[180px] truncate font-mono text-xs text-r5e-text/85"
          >
            {principal}
          </span>
        )}
        <button
          type="button"
          data-testid="topbar-signout"
          onClick={handleSignOut}
          className="shrink-0 whitespace-nowrap rounded px-2 py-1 text-xs font-medium text-r5e-text/85 hover:bg-r5e-surface hover:text-r5e-text"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}

/**
 * Sign-out side-effect. POST is fire-and-forget; even if the request fails
 * the user is still navigated to /admin/login (the cookie may already be
 * invalid). Tests exercise this via simulated click on the sign-out button.
 */
async function handleSignOut(): Promise<void> {
  try {
    await fetch(logoutEndpoint, { method: "POST", credentials: "include" });
  } catch {
    // Best-effort — fall through to the redirect regardless.
  }
  window.location.assign(routes.login);
}
