import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Search,
  Cpu,
  Network,
  KeyRound,
  Wrench,
  FileText,
  Database,
  Plus,
  Play,
  Download,
  GitBranch,
} from "lucide-react";
import { SocLayout } from "@/components/soc/SocLayout";
import { SeverityBadge } from "@/components/soc/Badges";
import { investigationEvents, type InvEvent, type EventType } from "@/components/soc/extra-data";

export const Route = createFileRoute("/investigation")({
  component: InvestigationView,
  head: () => ({
    meta: [
      { title: "Investigation · Sentinel/Ops" },
      { name: "description", content: "Pivot, correlate and analyze security events." },
    ],
  }),
});

const TYPES: { id: EventType | "all"; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "all", label: "all", icon: FileText },
  { id: "process", label: "process", icon: Cpu },
  { id: "network", label: "network", icon: Network },
  { id: "auth", label: "auth", icon: KeyRound },
  { id: "service", label: "service", icon: Wrench },
  { id: "file", label: "file", icon: FileText },
  { id: "registry", label: "registry", icon: Database },
];

function InvestigationView() {
  const [query, setQuery] = useState("host:BANK_12_01");
  const [type, setType] = useState<EventType | "all">("all");
  const [selectedTs, setSelectedTs] = useState<string>(investigationEvents[1].ts);

  const filtered = useMemo(() => {
    return investigationEvents.filter((e) => {
      if (type !== "all" && e.type !== type) return false;
      if (!query) return true;
      const q = query.toLowerCase();
      // pivot syntax
      const pairs = q.split(/\s+/).filter((x) => x.includes(":"));
      if (pairs.length === 0) {
        return (e.text + e.host + (e.user || "") + e.eid).toLowerCase().includes(q);
      }
      return pairs.every((p) => {
        const [k, v] = p.split(":");
        if (!v) return true;
        switch (k) {
          case "host":
            return e.host.toLowerCase().includes(v);
          case "user":
            return (e.user || "").toLowerCase().includes(v);
          case "eid":
            return e.eid === v;
          case "process":
            return (e.process || "").toLowerCase().includes(v);
          default:
            return true;
        }
      });
    });
  }, [query, type]);

  const selected = investigationEvents.find((e) => e.ts === selectedTs) ?? filtered[0] ?? null;

  return (
    <SocLayout title="INVESTIGATION" sub={`// ${filtered.length} events · pivot mode`}>
      <div className="h-full grid grid-cols-[180px_1fr_360px] min-h-0">
        {/* Left filters */}
        <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0 overflow-y-auto">
          <FSec title="Type">
            {TYPES.map((t) => {
              const active = type === t.id;
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  onClick={() => setType(t.id)}
                  className={
                    "w-full flex items-center gap-2 h-6 px-2 rounded-sm text-[11.5px] font-mono " +
                    (active
                      ? "bg-accent text-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground")
                  }
                >
                  <Icon className="h-3 w-3" />
                  {t.label}
                </button>
              );
            })}
          </FSec>
          <FSec title="Time Range">
            {["last 15m", "last 1h", "last 24h", "last 7d", "custom…"].map((r, i) => (
              <button
                key={r}
                className={
                  "w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono " +
                  (i === 1
                    ? "bg-accent text-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground")
                }
              >
                {r}
              </button>
            ))}
          </FSec>
          <FSec title="Top Hosts">
            {["BANK_12_01", "RZ_MANU2", "DC01", "WS-FIN-204"].map((h) => (
              <button
                key={h}
                onClick={() => setQuery(`host:${h}`)}
                className="w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono text-muted-foreground hover:bg-accent hover:text-foreground truncate"
              >
                → {h}
              </button>
            ))}
          </FSec>
          <FSec title="Top Users">
            {["SYSTEM", "j.weber", "admin.svc", "m.koehler"].map((u) => (
              <button
                key={u}
                onClick={() => setQuery(`user:${u}`)}
                className="w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono text-muted-foreground hover:bg-accent hover:text-foreground truncate"
              >
                → {u}
              </button>
            ))}
          </FSec>
        </aside>

        {/* Center timeline */}
        <div className="flex flex-col min-h-0 border-r border-border">
          <div className="border-b border-border bg-[var(--panel)] px-3 py-2 flex items-center gap-2">
            <div className="flex items-center gap-2 h-7 flex-1 px-2 rounded-sm bg-input border border-border">
              <Search className="h-3.5 w-3.5 text-muted-foreground" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="host: user: eid: process: hash:"
                className="bg-transparent flex-1 outline-none text-[12px] font-mono placeholder:text-muted-foreground"
              />
              <span className="text-[10px] font-mono text-muted-foreground">{filtered.length} hits</span>
            </div>
            <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
              <Play className="h-3 w-3" /> Run
            </button>
            <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
              <Plus className="h-3 w-3" /> Add to Incident
            </button>
            <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
              <Download className="h-3 w-3" /> Export
            </button>
          </div>

          {/* Histogram strip */}
          <div
            className="px-3 py-2 border-b border-border bg-[var(--panel)] grid gap-[2px] h-12"
            style={{ gridTemplateColumns: "repeat(30, minmax(0, 1fr))" }}
          >
            {Array.from({ length: 30 }).map((_, i) => {
              const v = (Math.sin(i * 0.7) + 1) * 0.5 * 100;
              const sev = i === 22 ? "bg-critical" : i === 18 ? "bg-high" : v > 60 ? "bg-warning/60" : "bg-info/40";
              return (
                <div key={i} className="flex items-end">
                  <div className={"w-full rounded-sm " + sev} style={{ height: `${Math.max(10, v)}%` }} />
                </div>
              );
            })}
          </div>

          {/* Timeline list */}
          <div className="flex-1 overflow-y-auto">
            {filtered.map((e) => {
              const sel = e.ts === selectedTs;
              const Icon =
                e.type === "process"
                  ? Cpu
                  : e.type === "network"
                    ? Network
                    : e.type === "auth"
                      ? KeyRound
                      : e.type === "service"
                        ? Wrench
                        : FileText;
              return (
                <button
                  key={e.ts + e.eid}
                  onClick={() => setSelectedTs(e.ts)}
                  className={
                    "w-full text-left grid grid-cols-[60px_22px_60px_70px_1fr_120px] gap-2 px-3 py-1.5 border-b border-border/60 hover:bg-[var(--row-hover)] " +
                    (sel ? "bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[11px]" : "")
                  }
                >
                  <span className="text-[11px] font-mono text-muted-foreground">{e.ts}</span>
                  <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                  <SeverityBadge level={e.severity} />
                  <span className="text-[11px] font-mono text-info">[{e.eid}]</span>
                  <span className="text-[12px] truncate">{e.text}</span>
                  <span className="text-[11px] font-mono text-muted-foreground truncate text-right">
                    {e.host}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Process tree mini */}
          <div className="border-t border-border bg-[var(--panel)] px-3 py-2">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5 flex items-center gap-1">
              <GitBranch className="h-3 w-3" /> Process Tree
            </div>
            <pre className="text-[11px] font-mono leading-snug text-muted-foreground">
{`services.exe (664)
└─ svchost.exe (1024)
   └─ powershell.exe (4812)   ◀ HIGH  -nop -w hidden -enc ...
      └─ svc_upd.exe (5102)   ◀ CRIT  unsigned · ProgramData`}
            </pre>
          </div>
        </div>

        {/* Right detail */}
        <aside className="bg-[var(--panel)] flex flex-col min-h-0">
          <div className="h-9 px-3 flex items-center border-b border-border">
            <span className="text-[12px] font-semibold tracking-wide">EVENT</span>
            {selected && (
              <span className="ml-2 text-[10.5px] font-mono text-muted-foreground">
                [{selected.eid}] · {selected.ts}
              </span>
            )}
            {selected && (
              <span className="ml-auto">
                <SeverityBadge level={selected.severity} />
              </span>
            )}
          </div>

          {selected ? (
            <div className="flex-1 overflow-y-auto">
              <Sec title="Summary">
                <div className="text-[12px] leading-snug">{selected.text}</div>
                <div className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono">
                  <KV k="host" v={selected.host} />
                  <KV k="type" v={selected.type} />
                  {selected.user && <KV k="user" v={selected.user} />}
                  {selected.process && <KV k="proc" v={selected.process} />}
                </div>
              </Sec>
              <Sec title="Raw Data">
                <pre className="text-[11px] font-mono whitespace-pre-wrap leading-snug">
{Object.entries(selected.data)
  .map(([k, v]) => `${k.padEnd(16)} ${v}`)
  .join("\n")}
                </pre>
              </Sec>
              <Sec title="Quick Pivots">
                <div className="grid grid-cols-2 gap-1">
                  {[
                    `host:${selected.host}`,
                    `eid:${selected.eid}`,
                    selected.user && `user:${selected.user}`,
                    selected.process && `proc:${selected.process}`,
                  ]
                    .filter(Boolean)
                    .map((p) => (
                      <button
                        key={p as string}
                        onClick={() => setQuery(p as string)}
                        className="text-left h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono truncate"
                      >
                        → {p}
                      </button>
                    ))}
                </div>
              </Sec>
              <Sec title="Related Events">
                {investigationEvents
                  .filter((e) => e.host === selected.host && e.ts !== selected.ts)
                  .slice(0, 4)
                  .map((e) => (
                    <div
                      key={e.ts + e.eid}
                      className="grid grid-cols-[60px_44px_1fr] gap-2 text-[11px] font-mono py-1 border-b border-border/60 last:border-0"
                    >
                      <span className="text-muted-foreground">{e.ts}</span>
                      <span className="text-info">[{e.eid}]</span>
                      <span className="truncate">{e.text}</span>
                    </div>
                  ))}
              </Sec>
            </div>
          ) : (
            <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
              select event →
            </div>
          )}
        </aside>
      </div>
    </SocLayout>
  );
}

function FSec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-border p-2">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1 px-1">
        {title}
      </div>
      <div className="space-y-[1px]">{children}</div>
    </div>
  );
}
function Sec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-border">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
        {title}
      </div>
      {children}
    </div>
  );
}
function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2 min-w-0">
      <span className="text-muted-foreground w-12 shrink-0">{k}</span>
      <span className="truncate">{v}</span>
    </div>
  );
}
