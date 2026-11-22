import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { Sidebar } from "~/components/shared/Sidebar";
import { ADMIN_BASE } from "~/lib/routes";

function renderAt(path: string) {
  return render(
    <MemoryRouter basename={ADMIN_BASE} initialEntries={[path]}>
      <Sidebar />
    </MemoryRouter>,
  );
}

describe("Sidebar", () => {
  it("renders the four top-level v2 nav links (Evidence, Timeline, Policy Simulator, MCP Registry)", () => {
    renderAt("/admin/dashboard");
    const nav = screen.getByTestId("sidebar-nav");
    expect(within(nav).getByRole("link", { name: /evidence/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /timeline/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /policy simulator/i })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: /mcp registry/i })).toBeInTheDocument();
  });

  it("highlights the Evidence link on /admin/dashboard and nested /admin/dashboard/records/:ref", () => {
    renderAt("/admin/dashboard/records/evidence%3Asha256%3Aabc");
    const link = screen.getByTestId("sidebar-link-evidence");
    expect(link.className).toContain("bg-r5e-accent");
  });

  it("prefixes hrefs with /admin once (no double /admin/admin)", () => {
    renderAt("/admin/dashboard");
    expect(screen.getByTestId("sidebar-link-evidence")).toHaveAttribute(
      "href",
      "/admin/dashboard",
    );
    expect(screen.getByTestId("sidebar-link-policy-simulator")).toHaveAttribute(
      "href",
      "/admin/policy-simulator",
    );
  });
});
