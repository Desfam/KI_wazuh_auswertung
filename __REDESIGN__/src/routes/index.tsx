import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { SocLayout } from "@/components/soc/SocLayout";
import { IncidentCard } from "@/components/soc/IncidentCard";
import { ContextPanel } from "@/components/soc/ContextPanel";
import { SeverityBadge, Tag } from "@/components/soc/Badges";
import { incidents, topHosts, recentActivity } from "@/components/soc/data";
import { ShieldAlert, Activity, Server, Filter, ArrowUpRight } from "lucide-react";

export const Route = createFileRoute("/")({
  component: Dashboard,
  head: () => ({
    meta: [
      { title: "SOC Dashboard · Sentinel/Ops" },
      { name: "description", content: "Security Operations Center — incident queue, host risk and live detections." },
    ],
  }),
});

function Dashboard() {
  const [selectedId, setSelectedId] = useState<string>(incidents[0].id);
  const selected = incidents.find((i) => i.id === selectedId) ?? null;

  const counts = {
    crit: incidents.filter((i) => i.severity === "CRITICAL" && i.status !== "CLOSED").length,
    high: incidents.filter((i) => i.severity === "HIGH" && i.status !== "CLOSED").length,
    med: incidents.filter((i) => i.severity === "MEDIUM" && i.status !== "CLOSED").length,
    open: incidents.filter((i) => i.status !== "CLOSED").length,
  };

  return (
    <SocLayout title="DASHBOARD" sub="// realtime · last 1h">
      <div className="h-full grid grid-cols-[1fr_360px] min-h-0">
        {/* Main column */}
        <div className="flex flex-col min-h-0 border-r border-border">
          {/* KPI strip */}
          <div className="grid grid-cols-5 border-b border-border bg-[var(--panel)]">
            <Kpi label="THREAT LEVEL" value="ELEVATED" tone="warning" sub="↑ from NORMAL · 14m ago" />
            <Kpi label="ACTIVE INCIDENTS" value={String(counts.open)} sub={`${counts.crit} crit · ${counts.high} high`} />
            <Kpi label="MTTD" value="42s" sub="-18% vs 24h" tone="success" />
            <Kpi label="MTTR" value="6m 11s" sub="+1m vs 24h" tone="warning" />
            <Kpi label="AGENTS" value="408 / 412" sub="4 stale" tone="info" last />
          </div>

          {/* Incident queue header */}
          <div className="h-9 px-3 flex items-center gap-2 border-b border-border bg-[var(--panel)]">
            <ShieldAlert className="h-3.5 w-3.5 text-critical" />
            <span className="text-[12px] font-semibold tracking-wide">INCIDENT QUEUE</span>
            <span className="text-[11px] font-mono text-muted-foreground">/ {incidents.length} total</span>

            <div className="ml-auto flex items-center gap-1">
              <FilterBtn active>Open</FilterBtn>
              <FilterBtn>Mine</FilterBtn>
              <FilterBtn>Crit+High</FilterBtn>
              <FilterBtn>Last 1h</FilterBtn>
              <button className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
                <Filter className="h-3 w-3" /> filter
              </button>
              <Link
                to="/incidents"
                className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1"
              >
                all <ArrowUpRight className="h-3 w-3" />
              </Link>
            </div>
          </div>

          {/* Queue */}
          <div className="flex-1 overflow-y-auto divide-y divide-border">
            {incidents.map((inc) => (
              <IncidentCard
                key={inc.id}
                incident={inc}
                selected={inc.id === selectedId}
                onSelect={() => setSelectedId(inc.id)}
              />
            ))}
          </div>

          {/* Bottom strip: hosts + activity */}
          <div className="grid grid-cols-2 border-t border-border bg-[var(--panel)] max-h-[200px]">
            <div className="border-r border-border flex flex-col min-h-0">
              <div className="h-7 px-3 flex items-center gap-2 border-b border-border">
                <Server className="h-3.5 w-3.5 text-info" />
                <span className="text-[11.5px] font-semibold tracking-wide">TOP HOSTS BY RISK</span>
              </div>
              <div className="flex-1 overflow-y-auto">
                {topHosts.map((h) => (
                  <div
                    key={h.host}
                    className="grid grid-cols-[1fr_60px_64px] gap-2 px-3 py-1.5 text-[11.5px] font-mono hover:bg-[var(--row-hover)] border-b border-border/60 last:border-0"
                  >
                    <span className="truncate">{h.host}</span>
                    <span className="text-right text-muted-foreground">{h.alerts} alr</span>
                    <span className="text-right">
                      <span
                        className={
                          h.risk >= 80 ? "text-critical" : h.risk >= 60 ? "text-warning" : "text-muted-foreground"
                        }
                      >
                        risk {h.risk}
                      </span>
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex flex-col min-h-0">
              <div className="h-7 px-3 flex items-center gap-2 border-b border-border">
                <Activity className="h-3.5 w-3.5 text-success" />
                <span className="text-[11.5px] font-semibold tracking-wide">RECENT ACTIVITY</span>
              </div>
              <div className="flex-1 overflow-y-auto">
                {recentActivity.map((a, i) => (
                  <div
                    key={i}
                    className="grid grid-cols-[44px_1fr_70px] gap-2 px-3 py-1.5 text-[11.5px] font-mono hover:bg-[var(--row-hover)] border-b border-border/60 last:border-0"
                  >
                    <span className="text-muted-foreground">{a.ts}</span>
                    <span className="truncate">{a.text}</span>
                    <span className="text-right">
                      <Tag>{a.kind}</Tag>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right context panel */}
        <aside className="bg-[var(--panel)] flex flex-col min-h-0">
          <div className="h-9 px-3 flex items-center border-b border-border">
            <span className="text-[12px] font-semibold tracking-wide">CONTEXT</span>
            {selected && (
              <span className="ml-2 text-[10.5px] font-mono text-muted-foreground">
                {selected.id}
              </span>
            )}
            <span className="ml-auto flex items-center gap-1">
              <SeverityBadge level={selected?.severity ?? "INFO"} />
            </span>
          </div>
          <ContextPanel incident={selected} />
        </aside>
      </div>
    </SocLayout>
  );
}

function Kpi({
  label,
  value,
  sub,
  tone = "default",
  last,
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "default" | "critical" | "warning" | "success" | "info";
  last?: boolean;
}) {
  const toneCls =
    tone === "critical"
      ? "text-critical"
      : tone === "warning"
        ? "text-warning"
        : tone === "success"
          ? "text-success"
          : tone === "info"
            ? "text-info"
            : "text-foreground";
  return (
    <div className={`px-3 py-2 ${last ? "" : "border-r border-border"}`}>
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`mt-0.5 text-[16px] font-mono font-semibold ${toneCls}`}>{value}</div>
      {sub && <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5">{sub}</div>}
    </div>
  );
}

function FilterBtn({ children, active }: { children: React.ReactNode; active?: boolean }) {
  return (
    <button
      className={
        "h-6 px-2 rounded-sm text-[11px] font-mono border " +
        (active
          ? "bg-accent border-border text-foreground"
          : "border-border text-muted-foreground hover:text-foreground hover:bg-accent")
      }
    >
      {children}
    </button>
  );
}
