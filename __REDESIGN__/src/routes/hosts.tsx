import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Server, Search } from "lucide-react";
import { SocLayout } from "@/components/soc/SocLayout";
import { Tag } from "@/components/soc/Badges";
import { hosts, type Host, type HostStatus } from "@/components/soc/extra-data";

export const Route = createFileRoute("/hosts")({
  component: HostsView,
  head: () => ({
    meta: [
      { title: "Hosts · Sentinel/Ops" },
      { name: "description", content: "Fleet overview, risk score and host status." },
    ],
  }),
});

const STATUSES: (HostStatus | "ALL")[] = ["ALL", "ONLINE", "OFFLINE", "ISOLATED", "STALE"];

function HostsView() {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<HostStatus | "ALL">("ALL");
  const [selected, setSelected] = useState<Host>(hosts[0]);

  const filtered = useMemo(
    () =>
      hosts.filter(
        (h) =>
          (status === "ALL" || h.status === status) &&
          (q === "" || (h.name + h.ip + h.tags.join(",")).toLowerCase().includes(q.toLowerCase())),
      ),
    [q, status],
  );

  return (
    <SocLayout title="HOSTS" sub={`// fleet · ${hosts.length} agents`}>
      <div className="h-full flex flex-col min-h-0">
        {/* Toolbar */}
        <div className="border-b border-border bg-[var(--panel)] px-3 py-2 flex flex-wrap items-center gap-2">
            <Server className="h-3.5 w-3.5 text-info" />
            <span className="text-[12px] font-semibold tracking-wide">FLEET</span>

            <div className="ml-2 flex items-center gap-1">
              {STATUSES.map((s) => (
                <button
                  key={s}
                  onClick={() => setStatus(s)}
                  className={
                    "h-6 px-2 rounded-sm text-[11px] font-mono border " +
                    (status === s
                      ? "bg-accent border-border text-foreground"
                      : "border-border text-muted-foreground hover:text-foreground hover:bg-accent")
                  }
                >
                  {s}
                </button>
              ))}
            </div>

            <div className="ml-auto flex items-center gap-2 h-6 w-[320px] px-2 rounded-sm bg-input border border-border">
              <Search className="h-3 w-3 text-muted-foreground" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="host, ip, tag, profile…"
                className="bg-transparent flex-1 outline-none text-[11.5px] font-mono placeholder:text-muted-foreground"
              />
            </div>
          </div>

          {/* Table */}
          <div className="flex-1 overflow-auto">
            <table className="w-full text-[11.5px] font-mono">
              <thead className="sticky top-0 bg-[var(--panel)] border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <Th>Hostname</Th>
                  <Th align="right">Risk</Th>
                  <Th>Status</Th>
                  <Th>Last Seen</Th>
                  <Th align="right">Alerts</Th>
                  <Th>Profile</Th>
                  <Th>OS</Th>
                  <Th>IP</Th>
                  <Th>Tags</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((h) => {
                  const isSel = h.name === selected.name;
                  return (
                    <tr
                      key={h.name}
                      onClick={() => setSelected(h)}
                      className={
                        "cursor-pointer border-b border-border/60 hover:bg-[var(--row-hover)] " +
                        (isSel ? "bg-[var(--row-hover)]" : "")
                      }
                    >
                      <Td>
                        <span
                          className={
                            "border-l-2 pl-2 -ml-2 inline-block " +
                            (h.risk >= 80
                              ? "border-l-critical"
                              : h.risk >= 60
                                ? "border-l-high"
                                : h.risk >= 40
                                  ? "border-l-warning"
                                  : "border-l-success/50")
                          }
                        >
                          {h.name}
                        </span>
                      </Td>
                      <Td align="right">
                        <RiskCell risk={h.risk} />
                      </Td>
                      <Td>
                        <StatusDot status={h.status} />
                      </Td>
                      <Td className="text-muted-foreground">{h.lastSeen}</Td>
                      <Td align="right">{h.alerts}</Td>
                      <Td className="text-muted-foreground">{h.profile}</Td>
                      <Td className="text-muted-foreground">{h.os}</Td>
                      <Td className="text-muted-foreground">{h.ip}</Td>
                      <Td>
                        <span className="flex flex-wrap gap-1">
                          {h.tags.map((t) => (
                            <Tag key={t}>#{t}</Tag>
                          ))}
                        </span>
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </SocLayout>
  );
}

function Th({ children, align }: { children: React.ReactNode; align?: "right" }) {
  return (
    <th className={"px-3 py-2 font-medium " + (align === "right" ? "text-right" : "text-left")}>
      {children}
    </th>
  );
}
function Td({
  children,
  align,
  className = "",
}: {
  children: React.ReactNode;
  align?: "right";
  className?: string;
}) {
  return (
    <td className={"px-3 py-1.5 " + (align === "right" ? "text-right " : "") + className}>
      {children}
    </td>
  );
}

function riskColor(r: number) {
  return r >= 80 ? "text-critical" : r >= 60 ? "text-high" : r >= 40 ? "text-warning" : "text-success";
}
function riskBg(r: number) {
  return r >= 80 ? "bg-critical" : r >= 60 ? "bg-high" : r >= 40 ? "bg-warning" : "bg-success";
}

function RiskCell({ risk }: { risk: number }) {
  return (
    <span className={"font-semibold " + riskColor(risk)}>{risk}</span>
  );
}

function StatusDot({ status }: { status: HostStatus }) {
  const map: Record<HostStatus, { c: string; t: string }> = {
    ONLINE: { c: "bg-success", t: "online" },
    OFFLINE: { c: "bg-muted-foreground", t: "offline" },
    ISOLATED: { c: "bg-critical", t: "isolated" },
    STALE: { c: "bg-warning", t: "stale" },
  };
  const m = map[status];
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-mono">
      <span className={"h-1.5 w-1.5 rounded-full " + m.c} />
      {m.t}
    </span>
  );
}
