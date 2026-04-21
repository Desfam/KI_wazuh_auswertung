import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { ShieldAlert, Filter, Search } from "lucide-react";
import { SocLayout } from "@/components/soc/SocLayout";
import { IncidentCard } from "@/components/soc/IncidentCard";
import { ContextPanel } from "@/components/soc/ContextPanel";
import { SeverityBadge } from "@/components/soc/Badges";
import { incidents, type Severity } from "@/components/soc/data";

export const Route = createFileRoute("/incidents")({
  component: IncidentsView,
  head: () => ({
    meta: [
      { title: "Incidents · Sentinel/Ops" },
      { name: "description", content: "Triage queue for active security incidents." },
    ],
  }),
});

const SEVS: (Severity | "ALL")[] = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function IncidentsView() {
  const [sev, setSev] = useState<Severity | "ALL">("ALL");
  const [q, setQ] = useState("");
  const [selectedId, setSelectedId] = useState<string>(incidents[0].id);

  const filtered = useMemo(
    () =>
      incidents.filter(
        (i) =>
          (sev === "ALL" || i.severity === sev) &&
          (q === "" ||
            (i.title + i.host + i.id + i.tags.join(",")).toLowerCase().includes(q.toLowerCase())),
      ),
    [sev, q],
  );

  const selected = incidents.find((i) => i.id === selectedId) ?? null;

  return (
    <SocLayout title="INCIDENTS" sub={`// queue · ${filtered.length}/${incidents.length}`}>
      <div className="h-full grid grid-cols-[1fr_360px] min-h-0">
        <div className="flex flex-col min-h-0 border-r border-border">
          {/* Filter bar */}
          <div className="border-b border-border bg-[var(--panel)] px-3 py-2 flex flex-wrap items-center gap-2">
            <ShieldAlert className="h-3.5 w-3.5 text-critical" />
            <span className="text-[12px] font-semibold tracking-wide">TRIAGE QUEUE</span>

            <div className="ml-2 flex items-center gap-1">
              {SEVS.map((s) => (
                <button
                  key={s}
                  onClick={() => setSev(s)}
                  className={
                    "h-6 px-2 rounded-sm text-[11px] font-mono border " +
                    (sev === s
                      ? "bg-accent border-border text-foreground"
                      : "border-border text-muted-foreground hover:text-foreground hover:bg-accent")
                  }
                >
                  {s}
                </button>
              ))}
            </div>

            <div className="ml-2 flex items-center gap-1">
              {["Open", "Investigating", "Mine", "Last 24h"].map((c) => (
                <button
                  key={c}
                  className="h-6 px-2 rounded-sm text-[11px] font-mono border border-border text-muted-foreground hover:text-foreground hover:bg-accent"
                >
                  {c}
                </button>
              ))}
            </div>

            <div className="ml-auto flex items-center gap-2 h-6 w-[260px] px-2 rounded-sm bg-input border border-border">
              <Search className="h-3 w-3 text-muted-foreground" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="title, host, tag…"
                className="bg-transparent flex-1 outline-none text-[11.5px] font-mono placeholder:text-muted-foreground"
              />
            </div>
            <button className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
              <Filter className="h-3 w-3" /> more
            </button>
          </div>

          {/* List */}
          <div className="flex-1 overflow-y-auto divide-y divide-border">
            {filtered.length === 0 ? (
              <div className="p-6 text-center text-[12px] font-mono text-muted-foreground">
                — no incidents match —
              </div>
            ) : (
              filtered.map((inc) => (
                <IncidentCard
                  key={inc.id}
                  incident={inc}
                  selected={inc.id === selectedId}
                  onSelect={() => setSelectedId(inc.id)}
                />
              ))
            )}
          </div>
        </div>

        <aside className="bg-[var(--panel)] flex flex-col min-h-0">
          <div className="h-9 px-3 flex items-center border-b border-border">
            <span className="text-[12px] font-semibold tracking-wide">CONTEXT</span>
            {selected && (
              <span className="ml-2 text-[10.5px] font-mono text-muted-foreground">{selected.id}</span>
            )}
            <span className="ml-auto">
              <SeverityBadge level={selected?.severity ?? "INFO"} />
            </span>
          </div>
          <ContextPanel incident={selected} />
        </aside>
      </div>
    </SocLayout>
  );
}
