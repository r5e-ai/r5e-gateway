// Sidebar — global left-rail navigation for the v2 Admin Console SPA.

import { Activity, Inbox, Package, Shield } from "lucide-react";
import type { ComponentType, SVGProps } from "react";
import { NavLink } from "react-router-dom";

import { Wordmark } from "~/components/shared/Wordmark";
import { routes, stripBasename } from "~/lib/routes";
import { slug } from "~/lib/strings";

type IconProps = SVGProps<SVGSVGElement>;

interface NavItem {
  label: string;
  to: string;
  icon: ComponentType<IconProps>;
}

const NAV_ITEMS: ReadonlyArray<NavItem> = [
  { label: "Evidence", to: routes.dashboard, icon: Inbox },
  { label: "Timeline", to: routes.timeline, icon: Activity },
  { label: "Policy Simulator", to: routes.policySimulator, icon: Shield },
  { label: "MCP Registry", to: routes.mcpRegistry, icon: Package },
];

export function Sidebar(): JSX.Element {
  return (
    <aside
      data-testid="global-sidebar"
      aria-label="Primary navigation"
      className="flex h-screen w-[220px] shrink-0 flex-col border-r border-r5e-border bg-r5e-surface px-4 py-4 font-sans"
    >
      <div className="flex flex-col gap-1 pb-4" data-testid="sidebar-workspace">
        <Wordmark size="sm" />
        <span className="text-[12px] text-r5e-muted">/ provenance v2</span>
      </div>

      <div className="h-px w-full bg-r5e-border" aria-hidden="true" />

      <nav className="flex flex-col gap-0.5 pt-4" data-testid="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <SidebarLink key={item.to} item={item} />
        ))}
      </nav>
    </aside>
  );
}

function SidebarLink({ item }: { item: NavItem }): JSX.Element {
  const Icon = item.icon;
  return (
    <NavLink
      to={stripBasename(item.to)}
      data-testid={`sidebar-link-${slug(item.label)}`}
      end={false}
      className={({ isActive }) =>
        [
          "flex h-9 items-center gap-2 rounded-md px-3 text-[13px] transition-colors",
          isActive
            ? "bg-r5e-accent/15 text-r5e-text"
            : "text-r5e-muted hover:bg-r5e-bg hover:text-r5e-text",
        ].join(" ")
      }
    >
      <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{item.label}</span>
    </NavLink>
  );
}
