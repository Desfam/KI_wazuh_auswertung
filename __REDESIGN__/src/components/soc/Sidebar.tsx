import { Link, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard,
  ShieldAlert,
  Server,
  Search,
  ScanLine,
  GitCompareArrows,
  Activity,
} from "lucide-react";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert, badge: 4 },
  { to: "/hosts", label: "Hosts", icon: Server },
  { to: "/investigation", label: "Investigation", icon: Search },
  { to: "/full-scan", label: "Full Scan", icon: ScanLine },
  { to: "/baseline", label: "Baseline", icon: GitCompareArrows },
] as const;

export function SocSidebar() {
  const path = useRouterState({ select: (s) => s.location.pathname });

  return (
    <aside className="w-[200px] shrink-0 border-r border-border bg-[var(--sidebar)] flex flex-col">
      <div className="h-10 px-3 flex items-center gap-2 border-b border-border">
        <div className="h-5 w-5 rounded-sm bg-primary/20 border border-primary/40 grid place-items-center">
          <Activity className="h-3 w-3 text-primary" />
        </div>
        <div className="text-[12px] font-semibold tracking-wide">SENTINEL/OPS</div>
      </div>

      <nav className="flex-1 py-2">
        {nav.map((n) => {
          const active = path === n.to;
          const Icon = n.icon;
          return (
            <Link
              key={n.to}
              to={n.to}
              className={[
                "flex items-center gap-2 px-3 h-8 mx-1 rounded-sm text-[12.5px]",
                "text-[var(--sidebar-foreground)] hover:bg-[var(--sidebar-accent)]",
                active
                  ? "bg-[var(--sidebar-accent)] text-foreground border-l-2 border-primary -ml-px pl-[11px]"
                  : "border-l-2 border-transparent -ml-px pl-[11px]",
              ].join(" ")}
            >
              <Icon className="h-3.5 w-3.5" />
              <span className="flex-1 truncate">{n.label}</span>
              {"badge" in n && n.badge ? (
                <span className="text-[10px] font-mono px-1 rounded-sm bg-critical text-critical-foreground">
                  {n.badge}
                </span>
              ) : null}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border p-2 text-[10.5px] font-mono text-muted-foreground space-y-0.5">
        <div className="flex justify-between"><span>fleet</span><span>412 hosts</span></div>
        <div className="flex justify-between"><span>agents</span><span className="text-success">408 ok</span></div>
        <div className="flex justify-between"><span>rules</span><span>1,247</span></div>
        <div className="flex justify-between"><span>build</span><span>v2.14.3</span></div>
      </div>
    </aside>
  );
}
